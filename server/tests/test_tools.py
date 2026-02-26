"""Tests for MCP tool registration and basic validation.

These tests verify:
- All tools register correctly in the TOOL_REGISTRY
- Tool names are unique
- Tools have required attributes (name, description)
- Error handling for missing parameters
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


class TestToolRegistry:
    """Test that tools register correctly."""

    def test_tool_modules_import(self):
        """All tool modules should import without error."""
        # Patch pyghidra to avoid JVM initialization
        with patch.dict("sys.modules", {"pyghidra": MagicMock()}):
            from ghidra_assist.tools import get_all_tools

            tools = get_all_tools()
            assert len(tools) > 0, "No tools registered"

    def test_all_tools_have_name(self):
        """Every registered tool must have a name attribute."""
        with patch.dict("sys.modules", {"pyghidra": MagicMock()}):
            from ghidra_assist.tools import get_all_tools

            for tool_cls in get_all_tools():
                assert hasattr(tool_cls, "name"), (
                    f"{tool_cls.__qualname__} missing 'name'"
                )
                assert isinstance(tool_cls.name, str)
                assert len(tool_cls.name) > 0

    def test_all_tools_have_description(self):
        """Every registered tool must have a description attribute."""
        with patch.dict("sys.modules", {"pyghidra": MagicMock()}):
            from ghidra_assist.tools import get_all_tools

            for tool_cls in get_all_tools():
                assert hasattr(tool_cls, "description"), (
                    f"{tool_cls.__qualname__} missing 'description'"
                )
                assert isinstance(tool_cls.description, str)
                assert len(tool_cls.description) > 0

    def test_no_duplicate_tool_names(self):
        """Tool names must be unique across all modules."""
        with patch.dict("sys.modules", {"pyghidra": MagicMock()}):
            from ghidra_assist.tools import get_all_tools

            names = [t.name for t in get_all_tools()]
            assert len(names) == len(set(names)), (
                f"Duplicate tool names: {[n for n in names if names.count(n) > 1]}"
            )

    def test_expected_tool_count(self):
        """We expect 33+ tools total (13 core + 20 utilities)."""
        with patch.dict("sys.modules", {"pyghidra": MagicMock()}):
            from ghidra_assist.tools import get_all_tools

            tools = get_all_tools()
            assert len(tools) >= 33, (
                f"Expected 33+ tools, got {len(tools)}: "
                f"{[t.name for t in tools]}"
            )


class TestToolErrorHandling:
    """Test that tools handle missing parameters gracefully."""

    @pytest.mark.asyncio
    async def test_list_programs_requires_repository(self):
        """list_programs should error when repository is missing."""
        with patch.dict("sys.modules", {"pyghidra": MagicMock()}):
            from ghidra_assist.tools.programs import ListPrograms

            tool = ListPrograms()
            try:
                result = await tool.execute()
                # If no exception, check that result indicates failure
                assert result.success is False, "Expected tool to fail with missing repository"
            except TypeError:
                # Expected: missing required positional argument 'repository'
                pass

    @pytest.mark.asyncio
    async def test_decompile_requires_function_or_address(self):
        """decompile_function should error without function_name or address."""
        with patch.dict("sys.modules", {"pyghidra": MagicMock()}):
            from ghidra_assist.tools.functions import DecompileFunction

            tool = DecompileFunction()
            result = await tool.execute(repository="test", program="test.exe")
            # Should have failed due to missing function_name/address
            assert result.success is False, "Expected tool to fail without function_name or address"
            assert "function_name" in result.message.lower() or "address" in result.message.lower()
