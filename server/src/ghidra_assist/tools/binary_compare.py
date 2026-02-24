"""Comparative binary analysis tool for variant detection.

Tools:
    compare_binaries -- compare two binaries to identify changes:
        - Function-level similarity matching
        - Diff of matched function pairs
        - Identify added, removed, and modified functions
        - Suggest function mapping between variants
"""

from __future__ import annotations

from typing import Any, Dict, List
import re
from difflib import SequenceMatcher

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
class CompareBinaries(BaseTool):
    name = "compare_binaries"
    description = (
        "Compare two binary programs to identify variant differences. "
        "Matches functions by similarity, highlights modifications, "
        "and suggests variant patches or new functionality."
    )
    category = ToolCategory.ANALYSIS

    async def execute(
        self,
        repository1: str,
        program1: str,
        repository2: str,
        program2: str,
        similarity_threshold: float = 0.70,
    ) -> Dict[str, Any]:
        """
        Compare two binaries for variant analysis.

        Args:
            repository1: Repository name for first binary
            program1: Program name for first binary (base/original)
            repository2: Repository name for second binary
            program2: Program name for second binary (variant)
            similarity_threshold: Minimum similarity (0.0-1.0) to match functions

        Returns:
            Dict with:
            - program1, program2: Names of compared programs
            - summary: Overall comparison statistics
            - unchanged_functions: Functions that appear identical
            - modified_functions: Functions with changes
            - added_functions: Functions only in program2
            - removed_functions: Functions only in program1
            - function_mapping: Suggested matching between programs
            - patch_analysis: Suspected security patches or bug fixes
        """
        try:
            cache = _get_cache()
            prog1 = cache.get_program(repository1, program1)
            prog2 = cache.get_program(repository2, program2)
            bridge = cache.bridge

            # Get function lists from both programs
            funcs1 = self._get_functions(bridge, prog1)
            funcs2 = self._get_functions(bridge, prog2)

            if not funcs1 or not funcs2:
                return self._error("Could not retrieve functions from one or both programs")

            # Match functions between programs
            matches = self._match_functions(
                funcs1, funcs2, bridge, prog1, prog2, similarity_threshold
            )

            # Categorize functions
            matched_names1 = {m["func1_name"] for m in matches}
            matched_names2 = {m["func2_name"] for m in matches}

            unchanged = [m for m in matches if m["similarity"] >= 0.95]
            modified = [m for m in matches if m["similarity"] < 0.95]
            removed = [f for f in funcs1 if f["name"] not in matched_names1]
            added = [f for f in funcs2 if f["name"] not in matched_names2]

            # Analyze patches (likely bug fixes)
            patch_analysis = self._analyze_patches(modified, bridge, prog1, prog2)

            # Build comparison summary
            summary = {
                "total_functions_prog1": len(funcs1),
                "total_functions_prog2": len(funcs2),
                "unchanged_count": len(unchanged),
                "modified_count": len(modified),
                "added_count": len(added),
                "removed_count": len(removed),
                "match_rate": round(
                    len(unchanged) / len(funcs1) if funcs1 else 0, 2
                ),
            }

            # Identify likely patches
            likely_patches = [p for p in patch_analysis if p.get("likely_patch", False)]

            return {
                "success": True,
                "program1": program1,
                "program2": program2,
                "summary": summary,
                "unchanged_functions": [
                    {
                        "name": u["func1_name"],
                        "address1": u["func1_addr"],
                        "address2": u["func2_addr"],
                        "similarity": u["similarity"],
                    }
                    for u in unchanged
                ],
                "modified_functions": [
                    {
                        "name": m["func1_name"],
                        "matched_to": m["func2_name"],
                        "address1": m["func1_addr"],
                        "address2": m["func2_addr"],
                        "similarity": m["similarity"],
                        "diff_summary": m.get("diff_summary", ""),
                    }
                    for m in modified[:10]  # Limit output
                ],
                "added_functions": [
                    {
                        "name": f["name"],
                        "address": f["address"],
                        "estimated_size": f["size"],
                    }
                    for f in added
                ],
                "removed_functions": [
                    {
                        "name": f["name"],
                        "address": f["address"],
                        "estimated_size": f["size"],
                    }
                    for f in removed
                ],
                "likely_patches": likely_patches[:5],
                "patch_analysis": {
                    "suspected_security_fixes": len([p for p in patch_analysis if "security" in p.get("reason", "").lower()]),
                    "performance_optimizations": len([p for p in patch_analysis if "optimization" in p.get("reason", "").lower()]),
                    "feature_changes": len([p for p in patch_analysis if "feature" in p.get("reason", "").lower()]),
                },
                "analysis_note": (
                    f"Compared {len(funcs1)} functions from {program1} with "
                    f"{len(funcs2)} functions from {program2}. "
                    f"Similarity threshold: {similarity_threshold * 100:.0f}%. "
                    f"Verify analysis in decompiler."
                ),
            }

        except FileNotFoundError as e:
            return self._error(f"Program not found: {e}")
        except Exception as exc:
            self.logger.exception("compare_binaries failed")
            return self._error(f"Binary comparison failed: {exc}")

    @staticmethod
    def _get_functions(bridge, program) -> List[Dict[str, Any]]:
        """Get all functions from a program."""
        try:
            functions = bridge.list_functions(program)
            return [
                {
                    "name": f.get("name", f.get("address", "unknown")),
                    "address": f.get("address", "unknown"),
                    "size": f.get("size", 0),
                }
                for f in functions
            ]
        except Exception:
            return []

    @staticmethod
    def _match_functions(
        funcs1: List[Dict[str, Any]],
        funcs2: List[Dict[str, Any]],
        bridge,
        prog1,
        prog2,
        threshold: float,
    ) -> List[Dict[str, Any]]:
        """Match functions between two programs by similarity."""
        matches = []

        for f1 in funcs1[:50]:  # Limit to first 50 functions for performance
            best_match = None
            best_similarity = 0.0

            for f2 in funcs2:
                # Calculate similarity based on:
                # 1. Function name similarity
                # 2. Function size similarity (if decompilation not available)
                name_sim = CompareBinaries._string_similarity(
                    f1["name"], f2["name"]
                )
                size_ratio = 1.0
                if f1["size"] > 0 and f2["size"] > 0:
                    size_ratio = min(f1["size"], f2["size"]) / max(
                        f1["size"], f2["size"]
                    )

                # Weighted combination
                combined_sim = name_sim * 0.6 + size_ratio * 0.4

                if combined_sim > best_similarity:
                    best_similarity = combined_sim
                    best_match = f2

            if best_similarity >= threshold and best_match:
                # Try to decompile for better diff
                try:
                    decomp1 = bridge.decompile_function(
                        prog1, function_name=f1["name"]
                    )
                    decomp2 = bridge.decompile_function(
                        prog2, function_name=best_match["name"]
                    )

                    code1 = decomp1.get("decompilation", "")
                    code2 = decomp2.get("decompilation", "")

                    # Recalculate similarity using decompiled code
                    if code1 and code2:
                        code_similarity = SequenceMatcher(
                            None, code1, code2
                        ).ratio()
                        diff_summary = CompareBinaries._summarize_diff(code1, code2)
                    else:
                        code_similarity = best_similarity
                        diff_summary = ""
                except Exception:
                    code_similarity = best_similarity
                    diff_summary = ""

                matches.append(
                    {
                        "func1_name": f1["name"],
                        "func1_addr": f1["address"],
                        "func2_name": best_match["name"],
                        "func2_addr": best_match["address"],
                        "similarity": round(code_similarity, 2),
                        "diff_summary": diff_summary,
                    }
                )

        return matches

    @staticmethod
    def _string_similarity(s1: str, s2: str) -> float:
        """Calculate string similarity (0.0 to 1.0)."""
        return SequenceMatcher(None, s1.lower(), s2.lower()).ratio()

    @staticmethod
    def _summarize_diff(code1: str, code2: str) -> str:
        """Summarize differences between two decompiled code samples."""
        lines1 = set(code1.split("\n"))
        lines2 = set(code2.split("\n"))

        added = lines2 - lines1
        removed = lines1 - lines2

        summary_parts = []
        if added:
            summary_parts.append(f"+{len(added)} lines")
        if removed:
            summary_parts.append(f"-{len(removed)} lines")

        if summary_parts:
            return ", ".join(summary_parts)
        return "Minor changes"

    @staticmethod
    def _analyze_patches(
        modified: List[Dict[str, Any]], bridge, prog1, prog2
    ) -> List[Dict[str, Any]]:
        """Analyze modified functions to identify likely patches."""
        patches = []

        for mod in modified[:5]:  # Analyze first 5 modified functions
            reason = ""
            likely_patch = False

            # Check for security-related changes
            try:
                decomp1 = bridge.decompile_function(
                    prog1, function_name=mod["func1_name"]
                )
                decomp2 = bridge.decompile_function(
                    prog2, function_name=mod["func2_name"]
                )

                code1 = decomp1.get("decompilation", "")
                code2 = decomp2.get("decompilation", "")

                # Detect security patterns
                if (
                    "strlen" in code1
                    and "memcpy" in code1
                    and "strlen" not in code2
                ):
                    reason = "Buffer overflow protection removed"
                    likely_patch = True

                if (
                    "if (size" in code2
                    and "if (size" not in code1
                ):
                    reason = "Size validation added (security patch)"
                    likely_patch = True

                if "strcpy" in code1 and "strncpy" in code2:
                    reason = "Unsafe string function replaced (security patch)"
                    likely_patch = True

                # Detect optimization patterns
                if len(code2) < len(code1) * 0.8:
                    reason = "Code optimized/simplified"
                    likely_patch = False

                # Detect new features
                new_calls = CompareBinaries._extract_calls(
                    code2
                ) - CompareBinaries._extract_calls(code1)
                if len(new_calls) > 3:
                    reason = f"New API calls: {', '.join(list(new_calls)[:3])}"
                    likely_patch = False

            except Exception:
                pass

            if reason:
                patches.append(
                    {
                        "function": mod["func1_name"],
                        "reason": reason,
                        "likely_patch": likely_patch,
                        "similarity": mod["similarity"],
                    }
                )

        return patches

    @staticmethod
    def _extract_calls(code: str) -> set:
        """Extract function call names from decompiled code."""
        return set(re.findall(r"(\w+)\s*\(", code))
