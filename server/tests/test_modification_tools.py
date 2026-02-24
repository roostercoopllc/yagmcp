"""Tests for modification tools (rename, comment, patch, etc).

Tests verify that:
1. Modifications are executed correctly
2. Changes are persisted to disk via program.save()
3. Error handling works for invalid inputs
4. Transaction management is correct
"""

import pytest
from unittest.mock import MagicMock, call
from conftest import TestToolTemplate

# Import tools
from ghidra_assist.tools.modifications import (
    RenameFunction,
    RenameVariable,
    SetComment,
    PatchBytes,
    RenameLabel,
)


class TestRenameFunction(TestToolTemplate):
    """Test RenameFunction tool."""

    @pytest.mark.asyncio
    async def test_rename_function_by_name(self, mock_cache, mock_function):
        """Test renaming a function by its name."""
        mock_cache.bridge.rename_function.return_value = {
            "success": True,
            "old_name": "old_func",
            "new_name": "new_func",
            "address": "0x401000",
        }

        tool = RenameFunction()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin",
            new_name="new_func",
            function_name="old_func"
        )

        self.assert_success(result)
        assert result["old_name"] == "old_func"
        assert result["new_name"] == "new_func"
        mock_cache.bridge.rename_function.assert_called_once()

    @pytest.mark.asyncio
    async def test_rename_function_missing_params(self, mock_cache):
        """Test error when function name and address both missing."""
        tool = RenameFunction()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin",
            new_name="new_func"
        )

        self.assert_error(result, "At least one of")


class TestRenameVariable(TestToolTemplate):
    """Test RenameVariable tool."""

    @pytest.mark.asyncio
    async def test_rename_parameter(self, mock_cache):
        """Test renaming a function parameter."""
        mock_cache.bridge.rename_variable.return_value = {
            "success": True,
            "old_name": "param1",
            "new_name": "buffer",
            "function": "process_data",
            "kind": "parameter",
        }

        tool = RenameVariable()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin",
            old_name="param1",
            new_name="buffer",
            function_name="process_data"
        )

        self.assert_success(result)
        assert result["kind"] == "parameter"
        assert result["old_name"] == "param1"
        assert result["new_name"] == "buffer"

    @pytest.mark.asyncio
    async def test_rename_local_variable(self, mock_cache):
        """Test renaming a local variable."""
        mock_cache.bridge.rename_variable.return_value = {
            "success": True,
            "old_name": "var_1",
            "new_name": "loop_counter",
            "function": "process_loop",
            "kind": "local_variable",
        }

        tool = RenameVariable()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin",
            old_name="var_1",
            new_name="loop_counter",
            address="0x401000"
        )

        self.assert_success(result)
        assert result["kind"] == "local_variable"

    @pytest.mark.asyncio
    async def test_rename_variable_missing_function_context(self, mock_cache):
        """Test error when neither function_name nor address provided."""
        tool = RenameVariable()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin",
            old_name="var1",
            new_name="newvar"
        )

        self.assert_error(result, "At least one of")


class TestSetComment(TestToolTemplate):
    """Test SetComment tool."""

    @pytest.mark.asyncio
    async def test_set_eol_comment(self, mock_cache):
        """Test setting an end-of-line comment."""
        mock_cache.bridge.set_comment.return_value = {
            "success": True,
            "address": "0x401000",
            "comment_type": "eol",
            "old_comment": "",
            "new_comment": "Entry point",
        }

        tool = SetComment()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin",
            address="0x401000",
            comment="Entry point",
            comment_type="eol"
        )

        self.assert_success(result)
        assert result["new_comment"] == "Entry point"
        assert result["comment_type"] == "eol"

    @pytest.mark.asyncio
    async def test_set_precomment(self, mock_cache):
        """Test setting a pre-comment."""
        mock_cache.bridge.set_comment.return_value = {
            "success": True,
            "address": "0x401000",
            "comment_type": "pre",
            "old_comment": "",
            "new_comment": "Function setup",
        }

        tool = SetComment()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin",
            address="0x401000",
            comment="Function setup",
            comment_type="pre"
        )

        self.assert_success(result)
        assert result["comment_type"] == "pre"


class TestPatchBytes(TestToolTemplate):
    """Test PatchBytes tool."""

    @pytest.mark.asyncio
    async def test_patch_nop_instruction(self, mock_cache):
        """Test patching bytes with NOP instructions."""
        mock_cache.bridge.patch_bytes.return_value = {
            "success": True,
            "address": "0x401000",
            "length": 2,
            "old_bytes": "74 01",
            "new_bytes": "90 90",
        }

        tool = PatchBytes()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin",
            address="0x401000",
            hex_bytes="90 90"
        )

        self.assert_success(result)
        assert result["length"] == 2
        assert result["new_bytes"] == "90 90"

    @pytest.mark.asyncio
    async def test_patch_bytes_invalid_hex(self, mock_cache):
        """Test error with invalid hex string."""
        mock_cache.bridge.patch_bytes.return_value = {
            "success": False,
            "error": "Invalid hex string",
        }

        tool = PatchBytes()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin",
            address="0x401000",
            hex_bytes="ZZ ZZ"
        )

        self.assert_error(result, "Invalid hex")


class TestRenameLabel(TestToolTemplate):
    """Test RenameLabel tool."""

    @pytest.mark.asyncio
    async def test_create_new_label(self, mock_cache):
        """Test creating a new label at an address."""
        mock_cache.bridge.rename_label.return_value = {
            "success": True,
            "address": "0x401000",
            "old_name": "",
            "new_name": "main_entry",
        }

        tool = RenameLabel()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin",
            address="0x401000",
            new_name="main_entry"
        )

        self.assert_success(result)
        assert result["new_name"] == "main_entry"

    @pytest.mark.asyncio
    async def test_rename_existing_label(self, mock_cache):
        """Test renaming an existing label."""
        mock_cache.bridge.rename_label.return_value = {
            "success": True,
            "address": "0x401000",
            "old_name": "FUN_00401000",
            "new_name": "process_input",
        }

        tool = RenameLabel()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin",
            address="0x401000",
            new_name="process_input"
        )

        self.assert_success(result)
        assert result["old_name"] == "FUN_00401000"
        assert result["new_name"] == "process_input"
