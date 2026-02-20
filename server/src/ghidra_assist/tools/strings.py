"""String, import, and export listing tools.

Tools:
    list_strings  — defined strings with optional regex filter
    list_imports  — imported symbols with library names
    list_exports  — exported symbols
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
# list_strings
# ---------------------------------------------------------------------- #


@register_tool
class ListStrings(BaseTool):
    name = "list_strings"
    description = (
        "List defined strings in a program. Supports regex filtering "
        "and minimum length. Returns paginated results."
    )

    async def execute(self, **kwargs: Any) -> Dict[str, Any]:
        err = self._require_params(kwargs, "repository", "program")
        if err:
            return err

        repository: str = kwargs["repository"]
        program_name: str = kwargs["program"]
        pattern: str = kwargs.get("filter", "")
        min_length: int = int(kwargs.get("min_length", 4))
        offset: int = int(kwargs.get("offset", 0))
        limit: int = int(kwargs.get("limit", 100))

        try:
            cache = _get_cache()
            program = cache.get_program(repository, program_name)
            bridge = cache.bridge

            raw_strings = bridge.list_strings(program)

            # Apply minimum length filter
            filtered = [s for s in raw_strings if s.get("length", 0) >= min_length]

            # Apply regex filter
            if pattern:
                try:
                    regex = re.compile(pattern, re.IGNORECASE)
                    filtered = [s for s in filtered if regex.search(s.get("value", ""))]
                except re.error as e:
                    return self._error(f"Invalid regex pattern: {e}")

            total = len(filtered)
            page = filtered[offset : offset + limit]

            return {
                "strings": [
                    {
                        "value": s.get("value", ""),
                        "address": s.get("address", ""),
                        "length": s.get("length", 0),
                        "type": s.get("type", "string"),
                    }
                    for s in page
                ],
                "total": total,
            }

        except FileNotFoundError:
            return self._error(
                f"Program '{program_name}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("list_strings failed")
            return self._error(f"Failed to list strings: {exc}")


# ---------------------------------------------------------------------- #
# list_imports
# ---------------------------------------------------------------------- #


@register_tool
class ListImports(BaseTool):
    name = "list_imports"
    description = "List imported functions with library names."

    async def execute(self, **kwargs: Any) -> Dict[str, Any]:
        err = self._require_params(kwargs, "repository", "program")
        if err:
            return err

        repository: str = kwargs["repository"]
        program_name: str = kwargs["program"]
        pattern: str = kwargs.get("filter", "")

        try:
            cache = _get_cache()
            program = cache.get_program(repository, program_name)
            bridge = cache.bridge

            raw_imports = bridge.list_imports(program)

            if pattern:
                try:
                    regex = re.compile(pattern, re.IGNORECASE)
                    raw_imports = [
                        i for i in raw_imports if regex.search(i.get("name", ""))
                    ]
                except re.error as e:
                    return self._error(f"Invalid regex pattern: {e}")

            return {
                "imports": [
                    {
                        "name": i.get("name", ""),
                        "address": i.get("address", ""),
                        "library": i.get("library", ""),
                    }
                    for i in raw_imports
                ]
            }

        except FileNotFoundError:
            return self._error(
                f"Program '{program_name}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("list_imports failed")
            return self._error(f"Failed to list imports: {exc}")


# ---------------------------------------------------------------------- #
# list_exports
# ---------------------------------------------------------------------- #


@register_tool
class ListExports(BaseTool):
    name = "list_exports"
    description = "List exported symbols from a program."

    async def execute(self, **kwargs: Any) -> Dict[str, Any]:
        err = self._require_params(kwargs, "repository", "program")
        if err:
            return err

        repository: str = kwargs["repository"]
        program_name: str = kwargs["program"]

        try:
            cache = _get_cache()
            program = cache.get_program(repository, program_name)
            bridge = cache.bridge

            raw_exports = bridge.list_exports(program)

            return {
                "exports": [
                    {
                        "name": e.get("name", ""),
                        "address": e.get("address", ""),
                        "ordinal": e.get("ordinal", -1),
                    }
                    for e in raw_exports
                ]
            }

        except FileNotFoundError:
            return self._error(
                f"Program '{program_name}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("list_exports failed")
            return self._error(f"Failed to list exports: {exc}")
