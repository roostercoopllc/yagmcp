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
    program.getLanguage.return_value.getProcessor.return_value.getName.return_value = "x86"
    program.getMemory.return_value = MagicMock()
    program.getListing.return_value = MagicMock()
    program.getSymbolTable.return_value = MagicMock()
    program.getFunctionManager.return_value = MagicMock()
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
    cache.bridge = MagicMock()
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

    for module in [
        ghidra_assist.tools.programs,
        ghidra_assist.tools.functions,
        ghidra_assist.tools.xrefs,
        ghidra_assist.tools.strings,
        ghidra_assist.tools.data_types,
        ghidra_assist.tools.modifications,
        ghidra_assist.tools.comments,
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
