"""Abstract base class and common Pydantic models for Ghidra-Assist MCP tools.

All tools inherit from BaseTool and implement the execute() method with
explicit typed parameters.  Return types are Pydantic models so FastMCP
can auto-generate JSON schemas for clients.
"""

from __future__ import annotations

import abc
import logging
from datetime import datetime
from enum import Enum
from typing import Any, Dict

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Tool categories
# ---------------------------------------------------------------------------

class ToolCategory(str, Enum):
    """Categories for organising Ghidra-Assist tools."""

    ANALYSIS = "analysis"
    NAVIGATION = "navigation"
    DATA = "data"
    CHAT = "chat"
    MODIFICATION = "modification"


# ---------------------------------------------------------------------------
# Common return-type models
# ---------------------------------------------------------------------------

class ToolResult(BaseModel):
    """Generic wrapper returned by every tool."""

    success: bool
    message: str
    data: dict | list | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    duration_ms: float | None = None


class FunctionInfo(BaseModel):
    """Describes a single function."""

    name: str
    entry: str = Field(description="Hex entry-point address")
    body_size: int = Field(0, description="Number of addresses in the function body")
    parameter_count: int = 0
    return_type: str = ""
    calling_convention: str = ""
    signature: str = ""
    is_thunk: bool = False


class DecompilationResult(BaseModel):
    """Result of decompiling a function."""

    success: bool
    name: str = ""
    entry: str = ""
    signature: str = ""
    decompiled_c: str = ""
    error: str | None = None


class XRefInfo(BaseModel):
    """A single cross-reference."""

    from_addr: str
    to_addr: str
    ref_type: str
    is_call: bool = False


class StringInfo(BaseModel):
    """A defined string in the binary."""

    address: str
    value: str
    length: int
    data_type: str = "string"


class ImportInfo(BaseModel):
    """An imported symbol."""

    name: str
    address: str
    source: str = ""
    namespace: str = ""


class ExportInfo(BaseModel):
    """An exported symbol."""

    name: str
    address: str
    source: str = ""


class MemoryBlockInfo(BaseModel):
    """A memory block/segment."""

    name: str
    start: str
    end: str
    size: int
    permissions: str = ""
    type: str = "unknown"
    initialized: bool = False


class BytesResult(BaseModel):
    """Raw bytes read from memory."""

    success: bool
    address: str = ""
    hex: str = ""
    length: int = 0
    ascii: str = ""
    error: str | None = None


class DataTypeInfo(BaseModel):
    """A data type from the program's type manager."""

    name: str
    category: str = ""
    length: int = -1
    description: str = ""


class CommentInfo(BaseModel):
    """All comment types at an address."""

    address: str
    eol: str | None = None
    pre: str | None = None
    post: str | None = None
    plate: str | None = None
    repeatable: str | None = None


class DisassemblyLine(BaseModel):
    """A single disassembled instruction."""

    address: str
    mnemonic: str
    operands: str = ""
    bytes: str = ""


class ProgramSummary(BaseModel):
    """High-level program metadata."""

    repo: str
    program: str
    language: str = ""
    compiler: str = ""
    address_size: int = 0
    num_functions: int = 0
    num_symbols: int = 0
    image_base: str = ""
    executable_format: str = ""
    memory_blocks: int = 0


class ModificationResult(BaseModel):
    """Result of a program modification (rename, patch, comment)."""

    success: bool
    message: str
    tool: str = ""
    target: str = ""
    old_value: str = ""
    new_value: str = ""


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class BaseTool(abc.ABC):
    """Abstract base for all Ghidra-Assist MCP tools.

    Subclasses must set class-level ``name``, ``description``, and
    ``category`` attributes, and implement ``execute()`` with explicit
    typed parameters (not ``**kwargs``).

    Example::

        class ListFunctionsTool(BaseTool):
            name = "list_functions"
            description = "List all functions in a program"
            category = ToolCategory.NAVIGATION

            async def execute(self, repo: str, program: str) -> ToolResult:
                ...
    """

    name: str
    description: str
    category: ToolCategory

    def __init__(self) -> None:
        self.logger = logging.getLogger(f"ghidra_assist.tools.{self.name}")

    @abc.abstractmethod
    async def execute(self) -> ToolResult | BaseModel | Dict[str, Any]:
        """Execute the tool and return a typed result.

        Concrete implementations should declare explicit typed parameters
        so FastMCP can introspect the signature for JSON-schema generation.
        Implementations must never raise -- return an error ToolResult
        instead so the MCP layer always gets a clean response.
        """
        ...

    # ------------------------------------------------------------------ #
    # Helpers available to every tool
    # ------------------------------------------------------------------ #

    @staticmethod
    def _require_params(kwargs: dict, *names: str) -> ToolResult | None:
        """Return an error ToolResult if any of *names* are missing from kwargs."""
        missing = [n for n in names if not kwargs.get(n)]
        if missing:
            return ToolResult(
                success=False,
                message=f"Missing required parameter(s): {', '.join(missing)}",
            )
        return None

    @staticmethod
    def _error(message: str) -> ToolResult:
        """Convenience wrapper for error responses."""
        return ToolResult(success=False, message=message)

    @staticmethod
    def _ok(message: str, data: dict | list | None = None) -> ToolResult:
        """Convenience wrapper for success responses."""
        return ToolResult(success=True, message=message, data=data)
