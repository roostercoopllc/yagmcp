"""Program and repository listing tools.

Tools:
    list_repositories — enumerate repository directories under /repos
    list_programs     — enumerate programs within a repository
    get_program_info  — detailed metadata for a single program
"""

from __future__ import annotations

from typing import Any, Dict

from ghidra_assist.project_cache import ProjectCache
from ghidra_assist.tools import register_tool
from ghidra_assist.tools.base import BaseTool

# Module-level singleton (created lazily on first use)
_cache: ProjectCache | None = None


def _get_cache() -> ProjectCache:
    global _cache
    if _cache is None:
        _cache = ProjectCache()
    return _cache


# ---------------------------------------------------------------------- #
# list_repositories
# ---------------------------------------------------------------------- #


@register_tool
class ListRepositories(BaseTool):
    name = "list_repositories"
    description = "List all Ghidra repository directories available on the server."

    async def execute(self, **kwargs: Any) -> Dict[str, Any]:
        try:
            cache = _get_cache()
            repos = cache.list_repos()

            result = []
            for repo_name in repos:
                try:
                    programs = cache.list_programs(repo_name)
                    program_count = len(programs)
                except FileNotFoundError:
                    program_count = 0

                result.append({
                    "name": repo_name,
                    "path": str(cache._repos_dir / repo_name)
                    if hasattr(cache, "_repos_dir")
                    else f"/repos/{repo_name}",
                    "program_count": program_count,
                })

            return {"repositories": result}

        except Exception as exc:
            self.logger.exception("list_repositories failed")
            return self._error(f"Failed to list repositories: {exc}")


# ---------------------------------------------------------------------- #
# list_programs
# ---------------------------------------------------------------------- #


@register_tool
class ListPrograms(BaseTool):
    name = "list_programs"
    description = "List all programs in a Ghidra repository with metadata."

    async def execute(self, **kwargs: Any) -> Dict[str, Any]:
        err = self._require_params(kwargs, "repository")
        if err:
            return err

        repository: str = kwargs["repository"]

        try:
            cache = _get_cache()
            raw_programs = cache.list_programs(repository)

            programs = []
            for p in raw_programs:
                programs.append({
                    "name": p.get("name", ""),
                    "language": p.get("language", "unknown"),
                    "compiler": p.get("compiler", "unknown"),
                    "size": p.get("size_bytes", 0),
                    "created": p.get("created", ""),
                    "modified": p.get("modified", ""),
                })

            return {"programs": programs}

        except FileNotFoundError:
            return self._error(f"Repository not found: {repository}")
        except Exception as exc:
            self.logger.exception("list_programs failed for %s", repository)
            return self._error(f"Failed to list programs: {exc}")


# ---------------------------------------------------------------------- #
# get_program_info
# ---------------------------------------------------------------------- #


@register_tool
class GetProgramInfo(BaseTool):
    name = "get_program_info"
    description = (
        "Get detailed metadata for a specific program including "
        "language, compiler, entry point, and memory layout."
    )

    async def execute(self, **kwargs: Any) -> Dict[str, Any]:
        err = self._require_params(kwargs, "repository", "program")
        if err:
            return err

        repository: str = kwargs["repository"]
        program_name: str = kwargs["program"]

        try:
            cache = _get_cache()
            program = cache.get_program(repository, program_name)

            # Language / compiler
            language = program.getLanguage()
            compiler_spec = program.getCompilerSpec()

            # Address space info
            addr_factory = program.getAddressFactory()
            default_space = addr_factory.getDefaultAddressSpace()

            # Function count
            func_mgr = program.getFunctionManager()
            num_functions = func_mgr.getFunctionCount()

            # Data type count
            dtm = program.getDataTypeManager()
            num_data_types = dtm.getDataTypeCount(True)

            # Memory blocks
            memory = program.getMemory()
            blocks_raw = memory.getBlocks()
            memory_blocks = []
            for block in blocks_raw:
                perms = ""
                if block.isRead():
                    perms += "r"
                if block.isWrite():
                    perms += "w"
                if block.isExecute():
                    perms += "x"

                memory_blocks.append({
                    "name": block.getName(),
                    "start": block.getStart().toString(),
                    "end": block.getEnd().toString(),
                    "size": block.getSize(),
                    "permissions": perms,
                })

            # Entry point — first entry if there is one
            sym_table = program.getSymbolTable()
            entry_points = sym_table.getExternalEntryPointIterator()
            entry_point = ""
            if entry_points.hasNext():
                entry_point = entry_points.next().toString()

            return {
                "name": program.getName(),
                "language": language.getLanguageID().toString(),
                "compiler": compiler_spec.getCompilerSpecID().toString(),
                "address_size": default_space.getSize(),
                "entry_point": entry_point,
                "min_address": memory.getMinAddress().toString()
                if memory.getMinAddress()
                else "",
                "max_address": memory.getMaxAddress().toString()
                if memory.getMaxAddress()
                else "",
                "num_functions": num_functions,
                "num_data_types": num_data_types,
                "memory_blocks": memory_blocks,
            }

        except FileNotFoundError:
            return self._error(
                f"Program '{program_name}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception(
                "get_program_info failed for %s/%s", repository, program_name
            )
            return self._error(f"Failed to get program info: {exc}")
