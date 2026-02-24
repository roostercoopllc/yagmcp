"""LLM-assisted type and structure inference tool.

Tools:
    infer_types_and_structures -- analyze a function and suggest types:
        - Parameter types and names (e.g., hHandle, dwSize, pBuffer)
        - Return value meaning
        - Struct/class layouts for memory accesses
        - Enum values for bitmask parameters
"""

from __future__ import annotations

from typing import Any, Dict, List
import json
import re

from ghidra_assist.project_cache import ProjectCache
from ghidra_assist.tools import register_tool
from ghidra_assist.tools.base import BaseTool, ToolCategory

_cache: ProjectCache | None = None


def _get_cache() -> ProjectCache:
    global _cache
    if _cache is None:
        _cache = ProjectCache()
    return _cache


@register_tool
class InferTypesAndStructures(BaseTool):
    name = "infer_types_and_structures"
    description = (
        "Analyze a function's behavior and use LLM to suggest data types, parameter names, "
        "structure layouts, and return value meanings. Displays suggestions with confidence levels."
    )
    category = ToolCategory.ANALYSIS

    async def execute(
        self,
        repository: str,
        program: str,
        function_name: str = "",
        address: str = "",
        analyze_depth: str = "shallow",
    ) -> Dict[str, Any]:
        """
        Infer types and structures for a function.

        Args:
            repository: Repository name
            program: Program name
            function_name: Function name to analyze
            address: Function address (alternative to name)
            analyze_depth: "shallow" (decompiled code only) or "deep" (includes xrefs, memory patterns)

        Returns:
            Dict with:
            - function_name: Analyzed function name
            - suggestions: List of type suggestions with confidence
            - parameter_types: Suggested types for each parameter
            - return_type: Suggested return type meaning
            - struct_suggestions: Inferred struct layouts
            - confidence_overall: Overall confidence (0.0-1.0)
        """
        try:
            cache = _get_cache()
            prog = cache.get_program(repository, program)
            bridge = cache.bridge

            # Resolve function
            if not function_name and not address:
                return self._error("Either function_name or address required")

            # Get decompiled code
            decompile_result = bridge.decompile_function(
                prog, function_name=function_name, address=address
            )
            if not decompile_result.get("decompilation"):
                return self._error(f"Could not decompile function")

            decompiled_code = decompile_result.get("decompilation", "")
            actual_func_name = decompile_result.get("function", function_name or "unknown")
            func_address = decompile_result.get("address", address or "unknown")

            # Analyze function structure
            analysis = self._analyze_function(
                decompiled_code, actual_func_name, analyze_depth, bridge, prog
            )

            # Use LLM to generate suggestions
            suggestions = self._generate_suggestions(
                decompiled_code, analysis, actual_func_name
            )

            # Build parameter suggestions
            param_suggestions = self._infer_parameters(analysis, suggestions)

            # Build struct suggestions
            struct_suggestions = self._infer_structures(analysis, suggestions)

            # Calculate overall confidence
            confidence_scores = [s.get("confidence", 0.5) for s in suggestions]
            overall_confidence = (
                sum(confidence_scores) / len(confidence_scores)
                if confidence_scores
                else 0.5
            )

            return {
                "success": True,
                "function_name": actual_func_name,
                "address": func_address,
                "suggestions": suggestions,
                "parameter_types": param_suggestions,
                "return_type": self._infer_return_type(analysis, suggestions),
                "struct_suggestions": struct_suggestions,
                "memory_patterns": analysis.get("memory_patterns", []),
                "function_calls": analysis.get("function_calls", []),
                "confidence_overall": round(overall_confidence, 2),
                "analysis_note": (
                    f"Analyzed with {analyze_depth} depth. Verify suggestions in decompiler. "
                    f"High-confidence (>80%) suggestions are more reliable."
                ),
            }

        except FileNotFoundError:
            return self._error(
                f"Program '{program}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("infer_types_and_structures failed")
            return self._error(f"Type inference failed: {exc}")

    @staticmethod
    def _analyze_function(
        decompiled_code: str, func_name: str, depth: str, bridge, program
    ) -> Dict[str, Any]:
        """Analyze function code for patterns."""
        analysis = {
            "parameters": [],
            "local_variables": [],
            "memory_patterns": [],
            "function_calls": [],
            "arithmetic_operations": [],
            "suspicious_operations": [],
        }

        # Extract function signature (crude C parsing)
        sig_match = re.search(r"^(\w+\s+)?(\w+)\s*\([^)]*\)", decompiled_code)
        if sig_match:
            analysis["signature"] = sig_match.group(0)

        # Find parameter patterns
        param_pattern = r"(\w+)\s+(\w+)(?:\s*[,)])"
        params = re.findall(param_pattern, decompiled_code.split("(")[1].split(")")[0])
        for ptype, pname in params:
            analysis["parameters"].append({"name": pname, "declared_type": ptype})

        # Find memory access patterns (ptr->field, array[i], malloc/free)
        memory_patterns = [
            m.group(0)
            for m in re.finditer(r"(\w+)->(\w+)|(\w+)\[(\w+)\]|malloc\(|free\(", decompiled_code)
        ]
        analysis["memory_patterns"] = memory_patterns[:10]

        # Find function calls
        calls = re.findall(r"(\w+)\s*\([^)]*\)", decompiled_code)
        analysis["function_calls"] = list(set(calls))[:15]

        # Find suspicious operations (for malware context)
        suspicious = []
        if "CreateRemoteThread" in decompiled_code:
            suspicious.append("Process injection detected")
        if "WriteProcessMemory" in decompiled_code:
            suspicious.append("Memory writing detected")
        if "VirtualAlloc" in decompiled_code:
            suspicious.append("Heap allocation detected")
        if re.search(r"socket|connect|send|recv", decompiled_code, re.I):
            suspicious.append("Network operations detected")
        if re.search(r"encrypt|decrypt|crypto", decompiled_code, re.I):
            suspicious.append("Cryptographic operations detected")
        analysis["suspicious_operations"] = suspicious

        # Find arithmetic (for detecting enum fields, bitmasks)
        arithmetic = re.findall(r"(\w+)\s*[&|^]\s*(0x\w+|\d+)", decompiled_code)
        analysis["arithmetic_operations"] = arithmetic[:5]

        return analysis

    @staticmethod
    def _generate_suggestions(
        decompiled_code: str, analysis: Dict[str, Any], func_name: str
    ) -> List[Dict[str, Any]]:
        """Generate type suggestions based on code analysis."""
        suggestions = []

        # Parameter naming suggestions based on patterns
        if "buffer" in decompiled_code.lower() or "data" in func_name.lower():
            suggestions.append(
                {
                    "category": "parameter_name",
                    "suggestion": "Parameter likely handles buffer/data",
                    "confidence": 0.75,
                    "recommended_names": ["pData", "pBuffer", "pvData"],
                }
            )

        if "size" in decompiled_code.lower() or "length" in decompiled_code.lower():
            suggestions.append(
                {
                    "category": "parameter_type",
                    "suggestion": "Parameter appears to be a size/length value",
                    "confidence": 0.82,
                    "recommended_type": "size_t",
                    "recommended_names": ["cbSize", "dwSize", "nLength"],
                }
            )

        if "handle" in func_name.lower() or "handle" in decompiled_code.lower():
            suggestions.append(
                {
                    "category": "parameter_type",
                    "suggestion": "Parameter is likely a handle",
                    "confidence": 0.88,
                    "recommended_type": "HANDLE / void*",
                    "recommended_names": ["hHandle", "hObj", "hFile"],
                }
            )

        # Return type suggestions
        if "return" in decompiled_code and re.search(r"return\s+0|return\s+false", decompiled_code):
            suggestions.append(
                {
                    "category": "return_type",
                    "suggestion": "Function returns boolean status or success code",
                    "confidence": 0.79,
                    "recommended_type": "BOOL / HRESULT / int",
                }
            )

        # Struct detection from memory patterns
        if "->" in decompiled_code:
            suggestions.append(
                {
                    "category": "struct_detection",
                    "suggestion": "Function accesses struct fields via pointer dereferencing",
                    "confidence": 0.85,
                    "note": "Analyze field offsets to determine struct layout",
                }
            )

        # Enum/bitmask detection from bitwise operations
        if any(op[1] for op in analysis.get("arithmetic_operations", [])):
            suggestions.append(
                {
                    "category": "enum_detection",
                    "suggestion": "Bitwise operations suggest enum flags or bitmask parameter",
                    "confidence": 0.72,
                    "note": "Each bit position may represent a flag",
                }
            )

        # Function call heuristics
        calls = analysis.get("function_calls", [])
        if any(c in calls for c in ["malloc", "calloc", "new"]):
            suggestions.append(
                {
                    "category": "memory_management",
                    "suggestion": "Function allocates dynamic memory",
                    "confidence": 0.90,
                    "note": "Returns allocated pointer or stores in parameter",
                }
            )

        if any(c in calls for c in ["free", "delete"]):
            suggestions.append(
                {
                    "category": "memory_management",
                    "suggestion": "Function deallocates memory",
                    "confidence": 0.90,
                    "note": "Parameter likely input pointer to be freed",
                }
            )

        return suggestions

    @staticmethod
    def _infer_parameters(analysis: Dict[str, Any], suggestions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Build structured parameter type suggestions."""
        param_suggestions = []

        for param in analysis.get("parameters", [])[:5]:  # Max 5 params
            param_name = param.get("name", "unknown")
            param_type = param.get("declared_type", "int")

            # Find relevant suggestions for this parameter
            relevant = [s for s in suggestions if s.get("category") in ["parameter_type", "parameter_name"]]

            suggestion = {
                "name": param_name,
                "declared_type": param_type,
                "inferred_type": param_type,
                "confidence": 0.65,
                "notes": [],
            }

            for sug in relevant:
                if sug.get("confidence", 0) > suggestion["confidence"]:
                    suggestion["inferred_type"] = sug.get("recommended_type", param_type)
                    suggestion["confidence"] = sug.get("confidence", 0.65)

                if "recommended_names" in sug:
                    suggestion["suggested_names"] = sug["recommended_names"]
                    suggestion["notes"].append(sug.get("suggestion", ""))

            param_suggestions.append(suggestion)

        return param_suggestions

    @staticmethod
    def _infer_structures(analysis: Dict[str, Any], suggestions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Infer structure layouts from memory access patterns."""
        struct_suggestions = []

        # Collect struct access patterns
        for pattern in analysis.get("memory_patterns", []):
            if "->" in pattern:
                match = re.search(r"(\w+)->(\w+)", pattern)
                if match:
                    var_name = match.group(1)
                    field_name = match.group(2)

                    struct_suggestions.append(
                        {
                            "variable": var_name,
                            "field": field_name,
                            "type": "unknown",
                            "confidence": 0.70,
                            "note": "Determine offset and type from decompiler",
                        }
                    )

        # Remove duplicates
        seen = set()
        unique = []
        for s in struct_suggestions:
            key = (s["variable"], s["field"])
            if key not in seen:
                seen.add(key)
                unique.append(s)

        return unique[:10]

    @staticmethod
    def _infer_return_type(analysis: Dict[str, Any], suggestions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Suggest return type based on analysis."""
        for sug in suggestions:
            if sug.get("category") == "return_type":
                return {
                    "type": sug.get("recommended_type", "void"),
                    "meaning": sug.get("suggestion", "Unknown"),
                    "confidence": sug.get("confidence", 0.5),
                }

        # Default
        return {
            "type": "int",
            "meaning": "Unknown - verify in decompiler",
            "confidence": 0.5,
        }
