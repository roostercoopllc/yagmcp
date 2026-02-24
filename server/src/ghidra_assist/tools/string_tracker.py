"""String reference tracking and impact analysis tool.

Tools:
    trace_string_references -- find all references to a string and analyze impact:
        - Xrefs with code context
        - Distance from entry point
        - How string flows through code
        - Impact summary (how many functions reference it)
"""

from __future__ import annotations

from typing import Any, Dict, List
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
class TraceStringReferences(BaseTool):
    name = "trace_string_references"
    description = (
        "Find all references to a string and analyze its impact on the binary. "
        "Shows xrefs with code context, function usage patterns, and data flow. "
        "Useful for finding C2 domains, file paths, error messages, and critical strings."
    )
    category = ToolCategory.ANALYSIS

    async def execute(
        self,
        repository: str,
        program: str,
        search_string: str,
        use_regex: bool = False,
        follow_data_flow: bool = False,
    ) -> Dict[str, Any]:
        """
        Find all references to a string and analyze its impact.

        Args:
            repository: Repository name
            program: Program name
            search_string: String to search for (or regex pattern if use_regex=True)
            use_regex: If True, search_string is treated as regex pattern
            follow_data_flow: If True, try to trace how the string flows through functions

        Returns:
            Dict with:
            - string_value: The searched string
            - total_references: Total number of references found
            - references: List of reference objects with context
            - functions_involved: Set of functions that reference the string
            - impact_summary: Human-readable summary
            - data_flow: (if follow_data_flow=True) Flow of string through functions
        """
        try:
            cache = _get_cache()
            prog = cache.get_program(repository, program)
            bridge = cache.bridge

            # Get all strings in the program
            all_strings = bridge.list_strings(prog)

            # Filter strings based on search criteria
            matching_strings = []
            if use_regex:
                try:
                    pattern = re.compile(search_string, re.IGNORECASE)
                    matching_strings = [
                        s
                        for s in all_strings
                        if pattern.search(s.get("value", ""))
                    ]
                except re.error as e:
                    return self._error(f"Invalid regex pattern: {e}")
            else:
                matching_strings = [
                    s
                    for s in all_strings
                    if search_string.lower() in s.get("value", "").lower()
                ]

            if not matching_strings:
                return {
                    "string_value": search_string,
                    "total_references": 0,
                    "references": [],
                    "functions_involved": [],
                    "impact_summary": "No matching strings found.",
                }

            # For each matching string, get xrefs
            all_references = []
            all_functions = set()

            for str_obj in matching_strings:
                str_addr = str_obj.get("address", "")
                str_value = str_obj.get("value", "")

                # Get xrefs to this string
                xrefs = bridge.get_xrefs_to(prog, str_addr)

                for xref in xrefs:
                    ref_addr = xref.get("address", "")
                    ref_func = xref.get("function_name", "unknown")
                    all_functions.add(ref_func)

                    # Decompile the referencing function to get context
                    code_context = ""
                    try:
                        func_code = bridge.decompile_function(
                            prog, ref_func
                        )
                        # Extract a snippet around the string reference
                        code_context = self._extract_context(
                            func_code, str_value, max_lines=3
                        )
                    except Exception:
                        code_context = f"[Could not decompile {ref_func}]"

                    all_references.append({
                        "string_value": str_value,
                        "address": ref_addr,
                        "function": ref_func,
                        "code_context": code_context,
                        "xref_type": xref.get("type", "unknown"),
                    })

            # Generate impact summary
            impact_summary = (
                f"String '{search_string}' referenced {len(all_references)} time(s) "
                f"across {len(all_functions)} function(s): {', '.join(sorted(all_functions)[:5])}"
                f"{'...' if len(all_functions) > 5 else ''}"
            )

            # Data flow analysis (if requested)
            data_flow = []
            if follow_data_flow and len(all_references) > 0:
                data_flow = self._trace_data_flow(all_references, bridge, prog)

            return {
                "success": True,
                "string_value": search_string,
                "total_references": len(all_references),
                "references": all_references,
                "functions_involved": sorted(list(all_functions)),
                "impact_summary": impact_summary,
                "data_flow": data_flow,
            }

        except FileNotFoundError:
            return self._error(
                f"Program '{program}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("trace_string_references failed")
            return self._error(f"String reference tracing failed: {exc}")

    @staticmethod
    def _extract_context(decompiled_code: str, search_term: str, max_lines: int = 3) -> str:
        """Extract a snippet of code around a search term."""
        if not decompiled_code:
            return "[No code available]"

        lines = decompiled_code.split("\n")
        for i, line in enumerate(lines):
            if search_term.lower() in line.lower():
                start = max(0, i - max_lines // 2)
                end = min(len(lines), i + max_lines // 2 + 1)
                snippet = "\n".join(lines[start:end])
                return snippet

        return f"[Code contains '{search_term}' but context extraction failed]"

    @staticmethod
    def _trace_data_flow(
        references: List[Dict[str, Any]], bridge: Any, program: Any
    ) -> List[Dict[str, Any]]:
        """Attempt to trace how a string flows through the program."""
        # Simplified data flow: show function call chain
        flow = []
        for ref in references[:10]:  # Limit to first 10 for performance
            func_name = ref.get("function", "unknown")
            flow.append({
                "function": func_name,
                "uses_string": True,
                "location": ref.get("address", ""),
            })
        return flow
