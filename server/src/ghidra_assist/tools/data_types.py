"""Data type, memory map, and byte reading tools.

Tools:
    list_data_types — structs, enums, typedefs
    get_memory_map  — memory segments with permissions
    read_bytes      — raw hex dump at an address
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
# list_data_types
# ---------------------------------------------------------------------- #


@register_tool
class ListDataTypes(BaseTool):
    name = "list_data_types"
    description = "List defined data types (structs, enums, typedefs) in a program."

    async def execute(self, **kwargs: Any) -> Dict[str, Any]:
        err = self._require_params(kwargs, "repository", "program")
        if err:
            return err

        repository: str = kwargs["repository"]
        program_name: str = kwargs["program"]
        pattern: str = kwargs.get("filter", "")
        category: str = kwargs.get("category", "")

        try:
            cache = _get_cache()
            program = cache.get_program(repository, program_name)
            bridge = cache.bridge

            raw_types = bridge.list_data_types(program)

            # Apply category filter
            if category:
                raw_types = [
                    t for t in raw_types
                    if category.lower() in t.get("category", "").lower()
                ]

            # Apply name regex filter
            if pattern:
                try:
                    regex = re.compile(pattern, re.IGNORECASE)
                    raw_types = [
                        t for t in raw_types if regex.search(t.get("name", ""))
                    ]
                except re.error as e:
                    return self._error(f"Invalid regex pattern: {e}")

            return {
                "data_types": [
                    {
                        "name": t.get("name", ""),
                        "category": t.get("category", ""),
                        "size": t.get("size", -1),
                        "kind": t.get("kind", "unknown"),
                    }
                    for t in raw_types
                ]
            }

        except FileNotFoundError:
            return self._error(
                f"Program '{program_name}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("list_data_types failed")
            return self._error(f"Failed to list data types: {exc}")


# ---------------------------------------------------------------------- #
# get_memory_map
# ---------------------------------------------------------------------- #


@register_tool
class GetMemoryMap(BaseTool):
    name = "get_memory_map"
    description = "Get the program's memory segments with read/write/execute permissions."

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

            raw_blocks = bridge.get_memory_map(program)

            return {
                "memory_blocks": [
                    {
                        "name": b.get("name", ""),
                        "start": b.get("start", ""),
                        "end": b.get("end", ""),
                        "size": b.get("size", 0),
                        "read": b.get("read", False),
                        "write": b.get("write", False),
                        "execute": b.get("execute", False),
                        "initialized": b.get("initialized", False),
                        "source": b.get("source", ""),
                    }
                    for b in raw_blocks
                ]
            }

        except FileNotFoundError:
            return self._error(
                f"Program '{program_name}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("get_memory_map failed")
            return self._error(f"Failed to get memory map: {exc}")


# ---------------------------------------------------------------------- #
# read_bytes
# ---------------------------------------------------------------------- #


@register_tool
class ReadBytes(BaseTool):
    name = "read_bytes"
    description = (
        "Read raw bytes at an address. Returns hex dump and ASCII representation. "
        "Maximum 1024 bytes per request."
    )

    async def execute(self, **kwargs: Any) -> Dict[str, Any]:
        err = self._require_params(kwargs, "repository", "program", "address")
        if err:
            return err

        repository: str = kwargs["repository"]
        program_name: str = kwargs["program"]
        address: str = kwargs["address"]
        length: int = min(int(kwargs.get("length", 64)), 1024)

        try:
            cache = _get_cache()
            program = cache.get_program(repository, program_name)
            bridge = cache.bridge

            result = bridge.read_bytes(program, address, length)

            if result is None:
                return self._error(f"Failed to read bytes at {address}")

            return {
                "address": result.get("address", address),
                "length": result.get("length", 0),
                "hex_dump": result.get("hex", ""),
                "ascii": result.get("ascii", ""),
            }

        except FileNotFoundError:
            return self._error(
                f"Program '{program_name}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("read_bytes failed")
            return self._error(f"Failed to read bytes: {exc}")
