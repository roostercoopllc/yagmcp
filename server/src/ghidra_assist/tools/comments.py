"""Comment retrieval and search tools.

Tools:
    get_comments    — all comment types for a function or address
    search_comments — regex search across all comments in a program
"""

from __future__ import annotations

import re
from typing import Any, Dict

from ghidra_assist.project_cache import ProjectCache
from ghidra_assist.tools import register_tool
from ghidra_assist.tools.base import BaseTool

_cache: ProjectCache | None = None


def _get_cache() -> ProjectCache:
    global _cache
    if _cache is None:
        _cache = ProjectCache()
    return _cache


# ---------------------------------------------------------------------- #
# get_comments
# ---------------------------------------------------------------------- #


@register_tool
class GetComments(BaseTool):
    name = "get_comments"
    description = (
        "Get comments (plate, pre, post, EOL, repeatable) for a function "
        "or at a specific address."
    )

    async def execute(self, **kwargs: Any) -> Dict[str, Any]:
        err = self._require_params(kwargs, "repository", "program")
        if err:
            return err

        repository: str = kwargs["repository"]
        program_name: str = kwargs["program"]
        function_name: str | None = kwargs.get("function_name")
        address: str | None = kwargs.get("address")

        if not function_name and not address:
            return self._error(
                "At least one of 'function_name' or 'address' must be provided"
            )

        try:
            cache = _get_cache()
            program = cache.get_program(repository, program_name)
            bridge = cache.bridge

            raw_comments = bridge.get_comments(
                program, function_name=function_name, address=address
            )

            return {
                "comments": [
                    {
                        "address": c.get("address", ""),
                        "type": c.get("type", ""),
                        "text": c.get("text", ""),
                    }
                    for c in raw_comments
                ]
            }

        except FileNotFoundError:
            return self._error(
                f"Program '{program_name}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("get_comments failed")
            return self._error(f"Failed to get comments: {exc}")


# ---------------------------------------------------------------------- #
# search_comments
# ---------------------------------------------------------------------- #


@register_tool
class SearchComments(BaseTool):
    name = "search_comments"
    description = "Search all comments in a program by text pattern (regex)."

    async def execute(self, **kwargs: Any) -> Dict[str, Any]:
        err = self._require_params(kwargs, "repository", "program", "pattern")
        if err:
            return err

        repository: str = kwargs["repository"]
        program_name: str = kwargs["program"]
        pattern: str = kwargs["pattern"]
        limit: int = int(kwargs.get("limit", 50))

        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as e:
            return self._error(f"Invalid regex pattern: {e}")

        try:
            cache = _get_cache()
            program = cache.get_program(repository, program_name)
            bridge = cache.bridge

            # Get all comments via bridge (returns flat list)
            all_comments = bridge.get_comments(program)

            matches = []
            for c in all_comments:
                text = c.get("text", "")
                if regex.search(text):
                    matches.append({
                        "address": c.get("address", ""),
                        "function_name": c.get("function_name", ""),
                        "type": c.get("type", ""),
                        "text": text,
                        "match_context": text[:200],
                    })
                    if len(matches) >= limit:
                        break

            return {"matches": matches}

        except FileNotFoundError:
            return self._error(
                f"Program '{program_name}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("search_comments failed")
            return self._error(f"Failed to search comments: {exc}")
