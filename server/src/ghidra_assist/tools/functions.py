"""Function analysis tools.

Tools:
    list_functions       — paginated listing of all functions
    decompile_function   — decompile a single function to C
    get_function_signature — retrieve a function's full signature
    get_disassembly      — disassemble instructions at an address
    search_functions     — regex search over function names or decompiled code
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


def _normalize_address(addr: str | None) -> str | None:
    """Strip the '0x' prefix so Ghidra's AddressFactory can parse it."""
    if addr is None:
        return None
    addr = addr.strip()
    if addr.lower().startswith("0x"):
        addr = addr[2:]
    return addr


# ---------------------------------------------------------------------- #
# list_functions
# ---------------------------------------------------------------------- #


@register_tool
class ListFunctions(BaseTool):
    name = "list_functions"
    description = "List functions in a program with optional regex filter and pagination."

    async def execute(self, repository: str, program: str, filter: str = "", offset: int = 0, limit: int = 100) -> Dict[str, Any]:
        program_name: str = program
        name_filter: str | None = filter

        try:
            cache = _get_cache()
            program = cache.get_program(repository, program_name)
            bridge = cache.bridge
            all_funcs = bridge.list_functions(program)

            # Apply regex filter
            if name_filter:
                try:
                    pattern = re.compile(name_filter, re.IGNORECASE)
                except re.error as exc:
                    return self._error(f"Invalid regex filter: {exc}")
                all_funcs = [f for f in all_funcs if pattern.search(f["name"])]

            total = len(all_funcs)
            page = all_funcs[offset : offset + limit]

            functions = []
            for f in page:
                functions.append({
                    "name": f["name"],
                    "address": f["entry"],
                    "size": f["body_size"],
                    "calling_convention": f["calling_convention"],
                    "return_type": f["return_type"],
                    "param_count": f["parameter_count"],
                })

            return {
                "functions": functions,
                "total": total,
                "offset": offset,
                "limit": limit,
            }

        except FileNotFoundError:
            return self._error(
                f"Program '{program_name}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("list_functions failed")
            return self._error(f"Failed to list functions: {exc}")


# ---------------------------------------------------------------------- #
# decompile_function
# ---------------------------------------------------------------------- #


@register_tool
class DecompileFunction(BaseTool):
    name = "decompile_function"
    description = "Decompile a function to C pseudocode by name or address."

    async def execute(self, repository: str, program: str, function_name: str = "", address: str = "") -> Dict[str, Any]:
        program_name: str = program

        if not function_name and not address:
            return self._error(
                "At least one of 'function_name' or 'address' must be provided."
            )

        try:
            cache = _get_cache()
            program = cache.get_program(repository, program_name)
            bridge = cache.bridge

            # Resolve what to decompile
            target = address
            if function_name and not address:
                # Find address by name
                target = self._find_function_entry(bridge, program, function_name)
                if target is None:
                    return self._error(
                        f"Function '{function_name}' not found in program."
                    )
            else:
                target = _normalize_address(address)

            result = bridge.decompile(program, target)

            if not result.get("success", False):
                return self._error(
                    result.get("error", "Decompilation failed for unknown reason.")
                )

            return {
                "function_name": result["name"],
                "address": result["entry"],
                "decompiled_c": result["decompiled_c"],
                "signature": result["signature"],
            }

        except FileNotFoundError:
            return self._error(
                f"Program '{program_name}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("decompile_function failed")
            return self._error(f"Decompilation failed: {exc}")

    @staticmethod
    def _find_function_entry(bridge, program, name: str) -> str | None:
        """Search for a function by name and return its entry address string."""
        funcs = bridge.list_functions(program)
        for f in funcs:
            if f["name"] == name:
                return f["entry"]
        return None


# ---------------------------------------------------------------------- #
# get_function_signature
# ---------------------------------------------------------------------- #


@register_tool
class GetFunctionSignature(BaseTool):
    name = "get_function_signature"
    description = "Retrieve the full type signature of a function."

    async def execute(self, repository: str, program: str, function_name: str = "", address: str = "") -> Dict[str, Any]:
        program_name: str = program

        if not function_name and not address:
            return self._error(
                "At least one of 'function_name' or 'address' must be provided."
            )

        try:
            cache = _get_cache()
            program = cache.get_program(repository, program_name)
            bridge = cache.bridge

            # Resolve to address
            addr = _normalize_address(address) if address else None
            if function_name and not addr:
                funcs = bridge.list_functions(program)
                for f in funcs:
                    if f["name"] == function_name:
                        addr = f["entry"]
                        break
                if addr is None:
                    return self._error(
                        f"Function '{function_name}' not found in program."
                    )

            func_info = bridge.get_function_at(program, addr)
            if func_info is None:
                return self._error(f"No function found at address '{addr}'.")

            # Get detailed parameter info from the Ghidra Program object
            func_obj = program.getFunctionManager().getFunctionAt(
                program.getAddressFactory().getAddress(addr)
            )

            parameters = []
            if func_obj is not None:
                for param in func_obj.getParameters():
                    parameters.append({
                        "name": param.getName(),
                        "type": param.getDataType().getName(),
                        "ordinal": param.getOrdinal(),
                    })

            return {
                "name": func_info["name"],
                "address": func_info["entry"],
                "return_type": func_info["return_type"],
                "calling_convention": func_info["calling_convention"],
                "parameters": parameters,
            }

        except FileNotFoundError:
            return self._error(
                f"Program '{program_name}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("get_function_signature failed")
            return self._error(f"Failed to get function signature: {exc}")


# ---------------------------------------------------------------------- #
# get_disassembly
# ---------------------------------------------------------------------- #


@register_tool
class GetDisassembly(BaseTool):
    name = "get_disassembly"
    description = "Disassemble instructions at a given address."

    async def execute(self, repository: str, program: str, address: str, count: int = 20) -> Dict[str, Any]:
        program_name: str = program

        if count < 1:
            return self._error("count must be at least 1.")
        count = min(count, 500)

        try:
            cache = _get_cache()
            program = cache.get_program(repository, program_name)
            bridge = cache.bridge

            norm_addr = _normalize_address(address)
            instructions = bridge.get_disassembly(program, norm_addr, count)

            if not instructions:
                return self._error(
                    f"No instructions found at address '{address}'. "
                    "The address may be invalid or not in an executable segment."
                )

            return {
                "address": address,
                "instructions": [
                    {
                        "address": i["address"],
                        "mnemonic": i["mnemonic"],
                        "operands": i["operands"],
                        "bytes": i["bytes"],
                    }
                    for i in instructions
                ],
            }

        except FileNotFoundError:
            return self._error(
                f"Program '{program_name}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("get_disassembly failed")
            return self._error(f"Failed to get disassembly: {exc}")


# ---------------------------------------------------------------------- #
# search_functions
# ---------------------------------------------------------------------- #


@register_tool
class SearchFunctions(BaseTool):
    name = "search_functions"
    description = (
        "Search functions by regex pattern in function names or decompiled output."
    )

    async def execute(self, repository: str, program: str, pattern: str, search_in: str = "name", limit: int = 50) -> Dict[str, Any]:
        program_name: str = program
        pattern_str: str = pattern

        if search_in not in ("name", "decompiled"):
            return self._error(
                f"Invalid search_in value '{search_in}'. Must be 'name' or 'decompiled'."
            )

        try:
            regex = re.compile(pattern_str, re.IGNORECASE)
        except re.error as exc:
            return self._error(f"Invalid regex pattern: {exc}")

        try:
            cache = _get_cache()
            program = cache.get_program(repository, program_name)
            bridge = cache.bridge
            all_funcs = bridge.list_functions(program)

            matches = []

            if search_in == "name":
                for f in all_funcs:
                    m = regex.search(f["name"])
                    if m:
                        matches.append({
                            "name": f["name"],
                            "address": f["entry"],
                            "match_context": f["name"],
                        })
                        if len(matches) >= limit:
                            break

            else:  # search_in == "decompiled"
                for f in all_funcs:
                    if len(matches) >= limit:
                        break
                    try:
                        decomp = bridge.decompile(program, f["entry"])
                        if not decomp.get("success"):
                            continue
                        c_code = decomp.get("decompiled_c", "")
                        m = regex.search(c_code)
                        if m:
                            # Extract a context window around the match
                            start = max(0, m.start() - 60)
                            end = min(len(c_code), m.end() + 60)
                            context = c_code[start:end].replace("\n", " ")
                            matches.append({
                                "name": f["name"],
                                "address": f["entry"],
                                "match_context": context,
                            })
                    except Exception:
                        # Skip functions that fail to decompile
                        continue

            return {"matches": matches}

        except FileNotFoundError:
            return self._error(
                f"Program '{program_name}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("search_functions failed")
            return self._error(f"Function search failed: {exc}")
