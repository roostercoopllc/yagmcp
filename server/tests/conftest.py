"""Pytest configuration and fixtures for YAGMCP tests.

This module provides fixtures for:
- Mocking Ghidra objects
- Creating test programs
- Setting up tool instances
"""

import pytest
from unittest.mock import MagicMock, AsyncMock
from typing import Any, Dict


@pytest.fixture
def mock_program():
    """Mock Ghidra Program object for testing."""
    program = MagicMock()
    program.getName.return_value = "test_binary"

    # Mock language chain: getLanguage() -> getLanguageDescription() -> getProcessor() -> toString()
    language_desc = MagicMock()
    processor = MagicMock()
    processor.toString.return_value = "x86_64"
    processor.getName.return_value = "x86"
    language_desc.getProcessor.return_value = processor
    language_desc.getSize.return_value = 64
    language = MagicMock()
    language.getLanguageDescription.return_value = language_desc
    program.getLanguage.return_value = language

    # Mock compiler spec chain
    compiler_spec_desc = MagicMock()
    compiler_spec_desc.getCompilerSpecName.return_value = "Visual Studio"
    compiler_spec = MagicMock()
    compiler_spec.getCompilerSpecDescription.return_value = compiler_spec_desc
    program.getCompilerSpec.return_value = compiler_spec

    # Mock other required methods
    program.getExecutableFormat.return_value = "PE"
    image_base = MagicMock()
    image_base.toString.return_value = "0x400000"
    program.getImageBase.return_value = image_base

    # Mock function manager
    func_manager = MagicMock()
    func_manager.getFunctionCount.return_value = 100
    program.getFunctionManager.return_value = func_manager

    # Mock symbol table
    sym_table = MagicMock()
    sym_table.getNumSymbols.return_value = 50
    program.getSymbolTable.return_value = sym_table

    program.getMemory.return_value = MagicMock()
    program.getListing.return_value = MagicMock()
    program.startTransaction.return_value = 1
    program.endTransaction.return_value = None
    program.save.return_value = None
    return program


@pytest.fixture
def mock_function():
    """Mock Ghidra Function object for testing."""
    function = MagicMock()
    function.getName.return_value = "test_function"
    function.getEntryPoint.return_value.toString.return_value = "0x401000"
    function.getParameters.return_value = []
    function.getBody.return_value = MagicMock()
    return function


@pytest.fixture
def mock_address():
    """Mock Ghidra Address object for testing."""
    address = MagicMock()
    address.toString.return_value = "0x401000"
    address.getOffset.return_value = 0x1000
    return address


@pytest.fixture
def mock_cache(mock_program):
    """Mock ProjectCache for testing tools."""
    from ghidra_assist.tools.base import BaseTool

    cache = MagicMock()
    cache.get_program.return_value = mock_program

    # Mock bridge methods for malware analysis tools
    bridge = MagicMock()

    # Default bridge method returns
    bridge.get_section_entropy.return_value = [
        {"name": ".text", "entropy": 5.2, "size": 4096, "initialized": True},
        {"name": ".data", "entropy": 2.1, "size": 2048, "initialized": True},
    ]
    bridge.list_imports.return_value = [
        {"name": "kernel32.dll", "address": "0x400000"},
        {"name": "ntdll.dll", "address": "0x400010"},
    ]
    bridge.list_strings.return_value = [
        {"value": "cmd.exe", "address": "0x405000"},
        {"value": "powershell", "address": "0x405010"},
    ]
    bridge.get_entry_point_bytes.return_value = {
        "address": "0x401000",
        "hex": "55 48 89 E5",
    }
    bridge.triage_binary.return_value = {
        "architecture": "x86_64",
        "compiler": "Visual Studio",
        "executable_format": "PE",
        "entry_point": "0x401000",
        "packing": {"likely_packed": False},
        "sections": [],
        "suspicious_imports": [],
        "suspicious_strings": [],
        "function_count": 100,
        "string_count": 500,
    }
    bridge.extract_iocs.return_value = {
        "iocs": {
            "ipv4": [],
            "urls": [],
            "domains": [],
            "registry_keys": [],
            "file_paths": [],
        },
        "total_count": 0,
    }
    bridge.detect_anti_analysis.return_value = {
        "techniques": [],
        "summary": {},
    }
    bridge.generate_yara.return_value = {
        "rule": "rule test { strings: $s1 = \"test\" condition: $s1 }",
        "indicators_used": {},
        "confidence": "low",
    }
    bridge.decompile_function.return_value = {
        "decompilation": "void test_func() { int x = 0; }",
        "function": "test_func",
        "address": "0x401000",
    }
    bridge.get_xrefs_to.return_value = []
    bridge.get_xrefs_from.return_value = []
    bridge.list_functions.return_value = [
        {"name": "main", "address": "0x401000", "size": 256},
        {"name": "helper", "address": "0x401100", "size": 128},
    ]

    cache.bridge = bridge
    return cache


@pytest.fixture(autouse=True)
def mock_get_cache(mock_cache, monkeypatch):
    """Auto-patch _get_cache() in all tool modules to use mock_cache."""
    import ghidra_assist.tools.programs
    import ghidra_assist.tools.functions
    import ghidra_assist.tools.xrefs
    import ghidra_assist.tools.strings
    import ghidra_assist.tools.data_types
    import ghidra_assist.tools.modifications
    import ghidra_assist.tools.comments
    import ghidra_assist.tools.triage
    import ghidra_assist.tools.ioc_extract
    import ghidra_assist.tools.anti_analysis
    import ghidra_assist.tools.yara_gen
    import ghidra_assist.tools.string_tracker
    import ghidra_assist.tools.pattern_detector
    import ghidra_assist.tools.type_inference
    import ghidra_assist.tools.binary_compare
    import ghidra_assist.tools.call_graph

    for module in [
        ghidra_assist.tools.programs,
        ghidra_assist.tools.functions,
        ghidra_assist.tools.xrefs,
        ghidra_assist.tools.strings,
        ghidra_assist.tools.data_types,
        ghidra_assist.tools.modifications,
        ghidra_assist.tools.comments,
        ghidra_assist.tools.triage,
        ghidra_assist.tools.ioc_extract,
        ghidra_assist.tools.anti_analysis,
        ghidra_assist.tools.yara_gen,
        ghidra_assist.tools.string_tracker,
        ghidra_assist.tools.pattern_detector,
        ghidra_assist.tools.type_inference,
        ghidra_assist.tools.binary_compare,
        ghidra_assist.tools.call_graph,
    ]:
        monkeypatch.setattr(module, "_get_cache", lambda: mock_cache)


class TestToolTemplate:
    """Base class for tool tests with common assertions."""

    @staticmethod
    def assert_success(result: Dict[str, Any]) -> None:
        """Assert that a tool result indicates success."""
        assert isinstance(result, dict), "Tool must return a dict"
        assert result.get("success") != False, f"Tool returned error: {result.get('error', 'Unknown error')}"

    @staticmethod
    def assert_error(result: Dict[str, Any], error_substring: str = "") -> None:
        """Assert that a tool result indicates an error."""
        assert isinstance(result, dict), "Tool must return a dict"
        assert result.get("success") == False or "error" in result, "Tool should indicate error"
        if error_substring and "error" in result:
            assert error_substring.lower() in result["error"].lower(), \
                f"Expected error to contain '{error_substring}', got: {result['error']}"


__all__ = ["TestToolTemplate", "mock_program", "mock_function", "mock_address", "mock_cache"]
