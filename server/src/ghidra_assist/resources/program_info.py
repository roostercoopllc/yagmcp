"""MCP resource: program_info

Exposes metadata about a Ghidra program at:
    ghidra://program/{repository}/{name}/info

Returns information such as language, compiler, address ranges, number of
functions, and analysis status.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict

from ghidra_assist.resources import register_resource

logger = logging.getLogger(__name__)


@dataclass
class ProgramInfoResource:
    """MCP resource that returns metadata for a Ghidra program."""

    uri_template: str = "ghidra://program/{repository}/{name}/info"
    name: str = "program_info"
    description: str = (
        "Metadata about a Ghidra program — language, compiler, address "
        "ranges, function count, and analysis status."
    )

    async def read(
        self,
        repository: str,
        name: str,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Read program metadata from the Ghidra bridge.

        Args:
            repository: Repository name containing the program.
            name: Program (binary) name within the repository.

        Returns:
            Dict with program metadata, or an error dict on failure.
        """
        try:
            # Import here to avoid circular imports and allow graceful
            # degradation when pyghidra is not available.
            from ghidra_assist.core.ghidra_bridge import get_bridge

            bridge = get_bridge()
            program = await bridge.open_program(repository, name)

            if program is None:
                return {
                    "error": f"Program '{name}' not found in repository '{repository}'",
                }

            # Collect metadata from the Ghidra program object
            info: Dict[str, Any] = {
                "repository": repository,
                "name": name,
                "language": str(getattr(program, "languageID", "unknown")),
                "compiler": str(getattr(program, "compilerSpecID", "unknown")),
                "executable_format": str(
                    getattr(program, "executableFormat", "unknown")
                ),
                "image_base": str(getattr(program, "imageBase", "unknown")),
                "address_size": getattr(program, "defaultPointerSize", 0) * 8,
            }

            # Function count
            func_mgr = getattr(program, "functionManager", None)
            if func_mgr is not None:
                info["function_count"] = func_mgr.getFunctionCount()
            else:
                info["function_count"] = -1

            # Memory blocks
            memory = getattr(program, "memory", None)
            if memory is not None:
                blocks = []
                for block in memory.getBlocks():
                    blocks.append(
                        {
                            "name": block.getName(),
                            "start": str(block.getStart()),
                            "end": str(block.getEnd()),
                            "size": block.getSize(),
                            "permissions": {
                                "read": block.isRead(),
                                "write": block.isWrite(),
                                "execute": block.isExecute(),
                            },
                        }
                    )
                info["memory_blocks"] = blocks

            # Analysis status
            options = getattr(program, "options", None)
            if options is not None:
                try:
                    analysis_opts = options.getOptions("Analyzers")
                    info["analysis_completed"] = True
                except Exception:
                    info["analysis_completed"] = False
            else:
                info["analysis_completed"] = False

            return info

        except ImportError:
            return {
                "error": (
                    "Ghidra bridge not available. Ensure pyghidra is installed "
                    "and GHIDRA_INSTALL_DIR is set."
                ),
            }
        except Exception as exc:
            logger.exception(
                "Error reading program info for %s/%s", repository, name
            )
            return {"error": f"Failed to read program info: {exc}"}


# Register the resource at import time
RESOURCE = register_resource(ProgramInfoResource())
