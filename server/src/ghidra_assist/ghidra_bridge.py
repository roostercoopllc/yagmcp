"""Ghidra Bridge — Python wrappers around the Ghidra Java API via pyghidra.

This module lazily initializes pyghidra (which embeds the Ghidra JVM via JPype)
and exposes common Ghidra operations as Python functions returning structured
data (dicts and lists).

Usage:
    from ghidra_assist.ghidra_bridge import GhidraBridge

    bridge = GhidraBridge()
    program = bridge.open_program("/repos/my_repo", "firmware.bin")
    funcs = bridge.list_functions(program)
    decomp = bridge.decompile(program, funcs[0]["entry"])
"""

import logging
import os
import threading
from pathlib import Path

from .config import settings

logger = logging.getLogger(__name__)

# Sentinel for "JVM not yet started"
_NOT_INITIALIZED = object()


class GhidraBridge:
    """Lazy-initializing wrapper around pyghidra and the Ghidra Java API.

    The JVM is started on the first call that requires it.  All public
    methods return plain Python dicts/lists so callers never need to
    interact with Java objects directly.
    """

    def __init__(self, ghidra_install: str | None = None):
        self._ghidra_install = ghidra_install or os.environ.get(
            "GHIDRA_INSTALL_DIR", "/opt/ghidra"
        )
        self._lock = threading.Lock()
        self._pyghidra = _NOT_INITIALIZED
        self._java_ready = False

    # ------------------------------------------------------------------
    # JVM lifecycle
    # ------------------------------------------------------------------

    @property
    def is_ready(self) -> bool:
        """Return True if pyghidra has been imported and the JVM is running."""
        return self._java_ready

    def _ensure_jvm(self) -> None:
        """Start the Ghidra/JPype JVM if it has not been started yet.

        Thread-safe: only the first caller pays the startup cost.
        """
        if self._java_ready:
            return

        with self._lock:
            # Double-check inside the lock
            if self._java_ready:
                return

            logger.info(
                "Initializing pyghidra JVM (GHIDRA_INSTALL_DIR=%s)",
                self._ghidra_install,
            )
            try:
                import pyghidra  # type: ignore[import-untyped]

                pyghidra.start(install_dir=self._ghidra_install)
                self._pyghidra = pyghidra
                self._java_ready = True
                logger.info("pyghidra JVM started successfully")
            except Exception:
                logger.exception("Failed to start pyghidra JVM")
                raise

    # ------------------------------------------------------------------
    # Project / Program helpers
    # ------------------------------------------------------------------

    def open_program(self, repo_path: str, program_name: str):
        """Open a Ghidra program from a server repository directory.

        Args:
            repo_path: Absolute path to the repository directory under repos_dir.
            program_name: Name of the program file inside the repository.

        Returns:
            A Ghidra ``Program`` Java object (via JPype proxy).

        Raises:
            FileNotFoundError: If the repo or program file does not exist.
            RuntimeError: If pyghidra cannot open the program.
        """
        self._ensure_jvm()

        repo_dir = Path(repo_path)
        if not repo_dir.is_dir():
            raise FileNotFoundError(f"Repository directory not found: {repo_dir}")

        program_file = repo_dir / program_name
        if not program_file.exists():
            # Ghidra projects store data in .rep directories; try common patterns
            candidates = list(repo_dir.glob(f"**/{program_name}*"))
            if not candidates:
                raise FileNotFoundError(
                    f"Program '{program_name}' not found in {repo_dir}"
                )
            program_file = candidates[0]

        logger.info("Opening program: %s", program_file)
        try:
            program = self._pyghidra.open_program(str(program_file))
            return program
        except Exception:
            logger.exception("Failed to open program: %s", program_file)
            raise RuntimeError(f"Could not open program: {program_file}")

    # ------------------------------------------------------------------
    # Decompiler
    # ------------------------------------------------------------------

    def decompile(self, program, function_or_address) -> dict:
        """Decompile a function and return its C representation.

        Args:
            program: Ghidra Program object.
            function_or_address: A Ghidra ``Function`` object **or** an
                address string (hex).  If a string is given the function
                at that address is resolved first.

        Returns:
            dict with keys: name, entry, decompiled_c, signature, success.
        """
        self._ensure_jvm()

        from ghidra.app.decompiler import DecompInterface  # type: ignore[import-untyped]
        from ghidra.util.task import ConsoleTaskMonitor  # type: ignore[import-untyped]

        func = self._resolve_function(program, function_or_address)
        if func is None:
            return {
                "success": False,
                "error": f"No function found at {function_or_address}",
                "decompiled_c": "",
                "name": "",
                "entry": str(function_or_address),
                "signature": "",
            }

        decomp = DecompInterface()
        try:
            decomp.openProgram(program)
            monitor = ConsoleTaskMonitor()
            result = decomp.decompileFunction(func, 60, monitor)

            if result.decompileCompleted():
                c_code = result.getDecompiledFunction().getC()
                return {
                    "success": True,
                    "name": func.getName(),
                    "entry": func.getEntryPoint().toString(),
                    "signature": func.getSignature().getPrototypeString(),
                    "decompiled_c": c_code,
                }
            return {
                "success": False,
                "error": "Decompilation did not complete",
                "name": func.getName(),
                "entry": func.getEntryPoint().toString(),
                "signature": "",
                "decompiled_c": "",
            }
        finally:
            decomp.dispose()

    # ------------------------------------------------------------------
    # Function queries
    # ------------------------------------------------------------------

    def get_function_at(self, program, address: str) -> dict | None:
        """Return function info at the given address, or None.

        Args:
            program: Ghidra Program object.
            address: Hex address string (e.g. "00401000").

        Returns:
            dict with name, entry, body_size, parameter_count, return_type or None.
        """
        self._ensure_jvm()
        func = self._resolve_function(program, address)
        if func is None:
            return None
        return self._func_to_dict(func)

    def list_functions(self, program) -> list[dict]:
        """List all functions in the program.

        Returns:
            List of dicts with name, entry, body_size, parameter_count, return_type.
        """
        self._ensure_jvm()
        listing = program.getFunctionManager()
        functions = listing.getFunctions(True)  # forward iterator
        result = []
        for func in functions:
            result.append(self._func_to_dict(func))
        return result

    # ------------------------------------------------------------------
    # Cross-references
    # ------------------------------------------------------------------

    def get_xrefs_to(self, program, address: str) -> list[dict]:
        """Get cross-references *to* the given address.

        Returns:
            List of dicts with from_addr, to_addr, ref_type, is_call.
        """
        self._ensure_jvm()
        from ghidra.program.model.symbol import ReferenceManager  # noqa: F811 # type: ignore[import-untyped]

        addr = self._parse_address(program, address)
        if addr is None:
            return []

        ref_mgr = program.getReferenceManager()
        refs = ref_mgr.getReferencesTo(addr)
        return [self._ref_to_dict(r) for r in refs]

    def get_xrefs_from(self, program, address: str) -> list[dict]:
        """Get cross-references *from* the given address.

        Returns:
            List of dicts with from_addr, to_addr, ref_type, is_call.
        """
        self._ensure_jvm()
        addr = self._parse_address(program, address)
        if addr is None:
            return []

        ref_mgr = program.getReferenceManager()
        refs = ref_mgr.getReferencesFrom(addr)
        return [self._ref_to_dict(r) for r in refs]

    # ------------------------------------------------------------------
    # Strings
    # ------------------------------------------------------------------

    def list_strings(self, program) -> list[dict]:
        """List defined string data items in the program.

        Returns:
            List of dicts with address, value, length, data_type.
        """
        self._ensure_jvm()
        from ghidra.program.util import DefinedDataIterator  # type: ignore[import-untyped]

        results = []
        for data in DefinedDataIterator.definedStrings(program):
            value = data.getValue()
            if value is None:
                continue
            results.append(
                {
                    "address": data.getAddress().toString(),
                    "value": str(value),
                    "length": data.getLength(),
                    "data_type": data.getDataType().getName(),
                }
            )
        return results

    # ------------------------------------------------------------------
    # Imports / Exports
    # ------------------------------------------------------------------

    def list_imports(self, program) -> list[dict]:
        """List imported symbols.

        Returns:
            List of dicts with name, address, source, namespace.
        """
        self._ensure_jvm()
        from ghidra.program.model.symbol import SourceType  # type: ignore[import-untyped]

        sym_table = program.getSymbolTable()
        ext_symbols = sym_table.getExternalSymbols()
        results = []
        for sym in ext_symbols:
            results.append(
                {
                    "name": sym.getName(),
                    "address": sym.getAddress().toString(),
                    "source": sym.getSource().toString(),
                    "namespace": sym.getParentNamespace().getName(),
                }
            )
        return results

    def list_exports(self, program) -> list[dict]:
        """List exported symbols.

        Returns:
            List of dicts with name, address, source.
        """
        self._ensure_jvm()
        from ghidra.program.model.symbol import SourceType  # type: ignore[import-untyped]

        sym_table = program.getSymbolTable()
        results = []
        sym_iter = sym_table.getAllSymbols(True)
        for sym in sym_iter:
            if sym.isExternalEntryPoint():
                results.append(
                    {
                        "name": sym.getName(),
                        "address": sym.getAddress().toString(),
                        "source": sym.getSource().toString(),
                    }
                )
        return results

    # ------------------------------------------------------------------
    # Memory
    # ------------------------------------------------------------------

    def get_memory_map(self, program) -> list[dict]:
        """Return the program's memory map as a list of segment descriptors.

        Returns:
            List of dicts with name, start, end, size, permissions, type.
        """
        self._ensure_jvm()
        memory = program.getMemory()
        blocks = memory.getBlocks()
        results = []
        for block in blocks:
            perms = ""
            if block.isRead():
                perms += "r"
            if block.isWrite():
                perms += "w"
            if block.isExecute():
                perms += "x"

            results.append(
                {
                    "name": block.getName(),
                    "start": block.getStart().toString(),
                    "end": block.getEnd().toString(),
                    "size": block.getSize(),
                    "permissions": perms,
                    "type": block.getType().toString() if block.getType() else "unknown",
                    "initialized": block.isInitialized(),
                }
            )
        return results

    def read_bytes(self, program, address: str, length: int) -> dict:
        """Read raw bytes from program memory.

        Args:
            program: Ghidra Program object.
            address: Hex address string.
            length: Number of bytes to read (capped at 4096).

        Returns:
            dict with address, hex, length, ascii.
        """
        self._ensure_jvm()

        length = min(length, 4096)
        addr = self._parse_address(program, address)
        if addr is None:
            return {
                "success": False,
                "error": f"Invalid address: {address}",
                "hex": "",
                "ascii": "",
            }

        memory = program.getMemory()
        buf = bytearray(length)
        try:
            bytes_read = memory.getBytes(addr, buf)
        except Exception:
            bytes_read = 0
            logger.debug("read_bytes failed at %s", address)

        raw = bytes(buf[:bytes_read]) if bytes_read > 0 else bytes(buf)
        hex_str = raw.hex(" ")
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)

        return {
            "success": True,
            "address": address,
            "hex": hex_str,
            "length": len(raw),
            "ascii": ascii_str,
        }

    # ------------------------------------------------------------------
    # Data types
    # ------------------------------------------------------------------

    def list_data_types(self, program) -> list[dict]:
        """List data types defined in the program's data type manager.

        Returns:
            List of dicts with name, category, length, description.
        """
        self._ensure_jvm()
        dtm = program.getDataTypeManager()
        results = []
        dt_iter = dtm.getAllDataTypes()
        while dt_iter.hasNext():
            dt = dt_iter.next()
            results.append(
                {
                    "name": dt.getName(),
                    "category": dt.getCategoryPath().toString() if dt.getCategoryPath() else "",
                    "length": dt.getLength(),
                    "description": dt.getDescription() or "",
                }
            )
        return results

    # ------------------------------------------------------------------
    # Comments
    # ------------------------------------------------------------------

    def get_comments(self, program, address: str) -> dict:
        """Get all comment types at the given address.

        Returns:
            dict with address, eol, pre, post, plate, repeatable.
        """
        self._ensure_jvm()
        from ghidra.program.model.listing import CodeUnit  # type: ignore[import-untyped]

        addr = self._parse_address(program, address)
        if addr is None:
            return {"error": f"Invalid address: {address}"}

        listing = program.getListing()
        cu = listing.getCodeUnitAt(addr)
        if cu is None:
            return {
                "address": address,
                "eol": None,
                "pre": None,
                "post": None,
                "plate": None,
                "repeatable": None,
            }

        return {
            "address": address,
            "eol": cu.getComment(CodeUnit.EOL_COMMENT),
            "pre": cu.getComment(CodeUnit.PRE_COMMENT),
            "post": cu.getComment(CodeUnit.POST_COMMENT),
            "plate": cu.getComment(CodeUnit.PLATE_COMMENT),
            "repeatable": cu.getComment(CodeUnit.REPEATABLE_COMMENT),
        }

    # ------------------------------------------------------------------
    # Disassembly
    # ------------------------------------------------------------------

    def get_disassembly(self, program, address: str, count: int = 20) -> list[dict]:
        """Disassemble *count* instructions starting at *address*.

        Args:
            program: Ghidra Program object.
            address: Hex start address.
            count: Number of instructions to return (capped at 500).

        Returns:
            List of dicts with address, mnemonic, operands, bytes.
        """
        self._ensure_jvm()

        count = min(count, 500)
        addr = self._parse_address(program, address)
        if addr is None:
            return []

        listing = program.getListing()
        instructions = listing.getInstructions(addr, True)  # forward
        results = []
        for i, instr in enumerate(instructions):
            if i >= count:
                break
            raw = instr.getBytes()
            hex_bytes = " ".join(f"{b & 0xFF:02x}" for b in raw)

            operands = []
            for op_idx in range(instr.getNumOperands()):
                operands.append(instr.getDefaultOperandRepresentation(op_idx))

            results.append(
                {
                    "address": instr.getAddress().toString(),
                    "mnemonic": instr.getMnemonicString(),
                    "operands": ", ".join(operands),
                    "bytes": hex_bytes,
                }
            )
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_address(self, program, address: str):
        """Parse a hex address string into a Ghidra Address object.

        Returns None on failure.
        """
        try:
            addr_factory = program.getAddressFactory()
            return addr_factory.getAddress(address)
        except Exception:
            logger.debug("Cannot parse address: %s", address)
            return None

    def _resolve_function(self, program, function_or_address):
        """Resolve a function from either a Function object or address string.

        Returns a Ghidra Function or None.
        """
        if isinstance(function_or_address, str):
            addr = self._parse_address(program, function_or_address)
            if addr is None:
                return None
            return program.getFunctionManager().getFunctionAt(addr)
        # Assume it is already a Function object
        return function_or_address

    @staticmethod
    def _func_to_dict(func) -> dict:
        """Convert a Ghidra Function object to a plain dict."""
        params = func.getParameters()
        return {
            "name": func.getName(),
            "entry": func.getEntryPoint().toString(),
            "body_size": func.getBody().getNumAddresses(),
            "parameter_count": len(params),
            "return_type": func.getReturnType().getName(),
            "calling_convention": func.getCallingConventionName(),
            "signature": func.getSignature().getPrototypeString(),
            "is_thunk": func.isThunk(),
        }

    @staticmethod
    def _ref_to_dict(ref) -> dict:
        """Convert a Ghidra Reference object to a plain dict."""
        return {
            "from_addr": ref.getFromAddress().toString(),
            "to_addr": ref.getToAddress().toString(),
            "ref_type": ref.getReferenceType().getName(),
            "is_call": ref.getReferenceType().isCall(),
        }
