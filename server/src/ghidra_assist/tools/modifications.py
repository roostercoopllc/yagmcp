"""Program modification tools.

Tools:
    rename_function   -- rename a function by name or address
    rename_variable   -- rename a local variable or parameter
    set_comment       -- add or update a comment at an address
    patch_bytes       -- write bytes at an address
    rename_label      -- rename or create a label at an address
"""

from __future__ import annotations

from typing import Any, Dict

from ghidra_assist.project_cache import ProjectCache
from ghidra_assist.tools import register_tool
from ghidra_assist.tools.base import BaseTool, ToolCategory

_cache: ProjectCache | None = None


def _get_cache() -> ProjectCache:
    global _cache
    if _cache is None:
        _cache = ProjectCache()
    return _cache


def _normalize_address(addr: str | None) -> str | None:
    """Strip the '0x' prefix so Ghidra's AddressFactory can parse it."""
    if addr is None:
        return None
    addr = addr.strip()
    if addr.lower().startswith("0x"):
        addr = addr[2:]
    return addr


# ---------------------------------------------------------------------- #
# rename_function
# ---------------------------------------------------------------------- #


@register_tool
class RenameFunction(BaseTool):
    name = "rename_function"
    description = (
        "Rename a function by name or address. "
        "Provide either function_name or address to identify the function."
    )
    category = ToolCategory.MODIFICATION

    async def execute(self, repository: str, program: str, new_name: str, function_name: str = "", address: str = "") -> Dict[str, Any]:
        program_name: str = program

        if not function_name and not address:
            return self._error(
                "At least one of 'function_name' or 'address' must be provided."
            )

        try:
            cache = _get_cache()
            program = cache.get_program(repository, program_name)
            bridge = cache.bridge

            target = _normalize_address(address) if address else function_name
            result = bridge.rename_function(program, target, new_name)

            if not result.get("success"):
                return self._error(result.get("error", "Rename failed"))

            return {
                "success": True,
                "old_name": result["old_name"],
                "new_name": result["new_name"],
                "address": result["address"],
            }

        except FileNotFoundError:
            return self._error(
                f"Program '{program_name}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("rename_function failed")
            return self._error(f"Rename failed: {exc}")


# ---------------------------------------------------------------------- #
# rename_variable
# ---------------------------------------------------------------------- #


@register_tool
class RenameVariable(BaseTool):
    name = "rename_variable"
    description = (
        "Rename a local variable or parameter within a function. "
        "Requires decompilation to resolve the variable."
    )
    category = ToolCategory.MODIFICATION

    async def execute(self, repository: str, program: str, old_name: str, new_name: str, function_name: str = "", address: str = "") -> Dict[str, Any]:
        program_name: str = program

        if not function_name and not address:
            return self._error(
                "At least one of 'function_name' or 'address' must be provided "
                "to identify the containing function."
            )

        try:
            cache = _get_cache()
            program = cache.get_program(repository, program_name)
            bridge = cache.bridge

            func_target = _normalize_address(address) if address else function_name
            result = bridge.rename_variable(program, func_target, old_name, new_name)

            if not result.get("success"):
                return self._error(result.get("error", "Rename failed"))

            return {
                "success": True,
                "old_name": result["old_name"],
                "new_name": result["new_name"],
                "function": result["function"],
                "kind": result.get("kind", "variable"),
            }

        except FileNotFoundError:
            return self._error(
                f"Program '{program_name}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("rename_variable failed")
            return self._error(f"Variable rename failed: {exc}")


# ---------------------------------------------------------------------- #
# set_comment
# ---------------------------------------------------------------------- #


@register_tool
class SetComment(BaseTool):
    name = "set_comment"
    description = (
        "Add or update a comment at a given address. "
        "Supported types: eol, pre, post, plate, repeatable."
    )
    category = ToolCategory.MODIFICATION

    async def execute(self, repository: str, program: str, address: str, comment: str, comment_type: str = "eol") -> Dict[str, Any]:
        program_name: str = program

        try:
            cache = _get_cache()
            program = cache.get_program(repository, program_name)
            bridge = cache.bridge

            norm_addr = _normalize_address(address)
            result = bridge.set_comment(program, norm_addr, comment, comment_type)

            if not result.get("success"):
                return self._error(result.get("error", "Set comment failed"))

            return {
                "success": True,
                "address": result["address"],
                "comment_type": result["comment_type"],
                "old_comment": result.get("old_comment", ""),
                "new_comment": result["new_comment"],
            }

        except FileNotFoundError:
            return self._error(
                f"Program '{program_name}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("set_comment failed")
            return self._error(f"Set comment failed: {exc}")


# ---------------------------------------------------------------------- #
# patch_bytes
# ---------------------------------------------------------------------- #


@register_tool
class PatchBytes(BaseTool):
    name = "patch_bytes"
    description = (
        "Write bytes at a given address to patch instructions or data. "
        "Accepts hex string (e.g. '90 90' or '9090'). Max 1024 bytes."
    )
    category = ToolCategory.MODIFICATION

    async def execute(self, repository: str, program: str, address: str, hex_bytes: str) -> Dict[str, Any]:
        program_name: str = program

        try:
            cache = _get_cache()
            program = cache.get_program(repository, program_name)
            bridge = cache.bridge

            norm_addr = _normalize_address(address)
            result = bridge.patch_bytes(program, norm_addr, hex_bytes)

            if not result.get("success"):
                return self._error(result.get("error", "Patch failed"))

            return {
                "success": True,
                "address": result["address"],
                "length": result["length"],
                "old_bytes": result["old_bytes"],
                "new_bytes": result["new_bytes"],
            }

        except FileNotFoundError:
            return self._error(
                f"Program '{program_name}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("patch_bytes failed")
            return self._error(f"Patch failed: {exc}")


# ---------------------------------------------------------------------- #
# rename_label
# ---------------------------------------------------------------------- #


@register_tool
class RenameLabel(BaseTool):
    name = "rename_label"
    description = (
        "Rename or create a label/symbol at a given address."
    )
    category = ToolCategory.MODIFICATION

    async def execute(self, repository: str, program: str, address: str, new_name: str) -> Dict[str, Any]:
        program_name: str = program

        try:
            cache = _get_cache()
            program = cache.get_program(repository, program_name)
            bridge = cache.bridge

            norm_addr = _normalize_address(address)
            result = bridge.rename_label(program, norm_addr, new_name)

            if not result.get("success"):
                return self._error(result.get("error", "Rename label failed"))

            return {
                "success": True,
                "address": result["address"],
                "old_name": result.get("old_name", ""),
                "new_name": result["new_name"],
            }

        except FileNotFoundError:
            return self._error(
                f"Program '{program_name}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("rename_label failed")
            return self._error(f"Rename label failed: {exc}")
