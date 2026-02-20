"""Cross-reference and call-graph tools.

Tools:
    get_xrefs_to  — references that point *to* an address
    get_xrefs_from — references that originate *from* a function/address
    get_call_graph — recursive caller/callee graph around a function
"""

from __future__ import annotations

from typing import Any, Dict, List, Set

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
# get_xrefs_to
# ---------------------------------------------------------------------- #


@register_tool
class GetXrefsTo(BaseTool):
    name = "get_xrefs_to"
    description = "Get all cross-references pointing to a given address."

    async def execute(self, **kwargs: Any) -> Dict[str, Any]:
        err = self._require_params(kwargs, "repository", "program", "address")
        if err:
            return err

        repository: str = kwargs["repository"]
        program_name: str = kwargs["program"]
        address: str = kwargs["address"]

        try:
            cache = _get_cache()
            program = cache.get_program(repository, program_name)
            bridge = cache.bridge

            norm_addr = _normalize_address(address)
            refs = bridge.get_xrefs_to(program, norm_addr)

            xrefs = []
            func_mgr = program.getFunctionManager()
            for r in refs:
                # Resolve the function containing the from-address
                from_func_name = ""
                from_addr_obj = program.getAddressFactory().getAddress(r["from_addr"])
                if from_addr_obj is not None:
                    containing = func_mgr.getFunctionContaining(from_addr_obj)
                    if containing is not None:
                        from_func_name = containing.getName()

                xrefs.append({
                    "from_address": r["from_addr"],
                    "from_function": from_func_name,
                    "ref_type": r["ref_type"],
                })

            return {
                "address": address,
                "xrefs": xrefs,
            }

        except FileNotFoundError:
            return self._error(
                f"Program '{program_name}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("get_xrefs_to failed")
            return self._error(f"Failed to get cross-references to {address}: {exc}")


# ---------------------------------------------------------------------- #
# get_xrefs_from
# ---------------------------------------------------------------------- #


@register_tool
class GetXrefsFrom(BaseTool):
    name = "get_xrefs_from"
    description = "Get all cross-references originating from a function or address."

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
                "At least one of 'function_name' or 'address' must be provided."
            )

        try:
            cache = _get_cache()
            program = cache.get_program(repository, program_name)
            bridge = cache.bridge

            # Resolve function entry address
            resolved_addr = _normalize_address(address)
            resolved_name = function_name or ""
            if function_name and not resolved_addr:
                funcs = bridge.list_functions(program)
                for f in funcs:
                    if f["name"] == function_name:
                        resolved_addr = f["entry"]
                        break
                if resolved_addr is None:
                    return self._error(
                        f"Function '{function_name}' not found in program."
                    )

            # For a function, iterate through all addresses in the body and
            # collect outgoing references.
            func_mgr = program.getFunctionManager()
            addr_obj = program.getAddressFactory().getAddress(resolved_addr)

            xrefs: List[Dict[str, Any]] = []

            if addr_obj is not None:
                func_obj = func_mgr.getFunctionAt(addr_obj)
                if func_obj is not None:
                    resolved_name = func_obj.getName()
                    # Iterate over the function body
                    body = func_obj.getBody()
                    ref_mgr = program.getReferenceManager()
                    addr_iter = body.getAddresses(True)
                    while addr_iter.hasNext():
                        cur_addr = addr_iter.next()
                        refs = ref_mgr.getReferencesFrom(cur_addr)
                        for ref in refs:
                            to_addr = ref.getToAddress()
                            to_func_name = ""
                            to_func = func_mgr.getFunctionAt(to_addr)
                            if to_func is not None:
                                to_func_name = to_func.getName()
                            elif func_mgr.getFunctionContaining(to_addr) is not None:
                                to_func_name = func_mgr.getFunctionContaining(
                                    to_addr
                                ).getName()

                            xrefs.append({
                                "to_address": to_addr.toString(),
                                "to_function": to_func_name,
                                "ref_type": ref.getReferenceType().getName(),
                            })
                else:
                    # No function at address — just get refs from that single address
                    refs = bridge.get_xrefs_from(program, resolved_addr)
                    for r in refs:
                        to_func_name = ""
                        to_addr_obj = program.getAddressFactory().getAddress(
                            r["to_addr"]
                        )
                        if to_addr_obj is not None:
                            to_func = func_mgr.getFunctionAt(to_addr_obj)
                            if to_func is not None:
                                to_func_name = to_func.getName()
                        xrefs.append({
                            "to_address": r["to_addr"],
                            "to_function": to_func_name,
                            "ref_type": r["ref_type"],
                        })

            return {
                "function_name": resolved_name,
                "address": resolved_addr,
                "xrefs": xrefs,
            }

        except FileNotFoundError:
            return self._error(
                f"Program '{program_name}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("get_xrefs_from failed")
            return self._error(f"Failed to get cross-references from: {exc}")


# ---------------------------------------------------------------------- #
# get_call_graph
# ---------------------------------------------------------------------- #


@register_tool
class GetCallGraph(BaseTool):
    name = "get_call_graph"
    description = (
        "Build a call graph (callees and callers) around a function up to a "
        "specified depth."
    )

    async def execute(self, **kwargs: Any) -> Dict[str, Any]:
        err = self._require_params(kwargs, "repository", "program")
        if err:
            return err

        repository: str = kwargs["repository"]
        program_name: str = kwargs["program"]
        function_name: str | None = kwargs.get("function_name")
        address: str | None = kwargs.get("address")
        depth: int = int(kwargs.get("depth", 2))

        if not function_name and not address:
            return self._error(
                "At least one of 'function_name' or 'address' must be provided."
            )

        depth = max(1, min(depth, 10))  # clamp to reasonable range

        try:
            cache = _get_cache()
            program = cache.get_program(repository, program_name)
            bridge = cache.bridge

            # Resolve root function
            resolved_addr = _normalize_address(address)
            if function_name and not resolved_addr:
                funcs = bridge.list_functions(program)
                for f in funcs:
                    if f["name"] == function_name:
                        resolved_addr = f["entry"]
                        break
                if resolved_addr is None:
                    return self._error(
                        f"Function '{function_name}' not found in program."
                    )

            func_mgr = program.getFunctionManager()
            addr_obj = program.getAddressFactory().getAddress(resolved_addr)
            root_func = func_mgr.getFunctionAt(addr_obj) if addr_obj else None

            if root_func is None:
                return self._error(f"No function found at address '{resolved_addr}'.")

            # Build callee tree (recursive down)
            callees = self._build_callee_tree(program, root_func, depth, set())

            # Build caller list (one level — callers of root)
            callers = self._get_callers(program, root_func)

            return {
                "root": {
                    "name": root_func.getName(),
                    "address": root_func.getEntryPoint().toString(),
                    "callees": callees,
                    "callers": callers,
                }
            }

        except FileNotFoundError:
            return self._error(
                f"Program '{program_name}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("get_call_graph failed")
            return self._error(f"Failed to build call graph: {exc}")

    # ------------------------------------------------------------------ #
    # Internal graph-building helpers
    # ------------------------------------------------------------------ #

    def _build_callee_tree(
        self,
        program: Any,
        func: Any,
        depth: int,
        visited: Set[str],
    ) -> List[Dict[str, Any]]:
        """Recursively build a callee tree down to *depth* levels."""
        if depth <= 0:
            return []

        entry = func.getEntryPoint().toString()
        if entry in visited:
            return []
        visited.add(entry)

        callees: List[Dict[str, Any]] = []
        called = func.getCalledFunctions(None)  # TaskMonitor=None => ConsoleTaskMonitor fallback
        if called is None:
            return callees

        for callee_func in called:
            subtree = self._build_callee_tree(
                program, callee_func, depth - 1, visited
            )
            callees.append({
                "name": callee_func.getName(),
                "address": callee_func.getEntryPoint().toString(),
                "callees": subtree,
            })

        return callees

    @staticmethod
    def _get_callers(program: Any, func: Any) -> List[Dict[str, Any]]:
        """Return the immediate callers of *func*."""
        callers: List[Dict[str, Any]] = []
        calling = func.getCallingFunctions(None)
        if calling is None:
            return callers

        for caller_func in calling:
            callers.append({
                "name": caller_func.getName(),
                "address": caller_func.getEntryPoint().toString(),
            })

        return callers
