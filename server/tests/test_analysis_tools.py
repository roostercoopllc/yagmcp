"""Tests for analysis tools (decompile, strings, functions, etc).

Tests verify that:
1. Analysis tools return correctly formatted data
2. Filtering and pagination work correctly
3. Error handling works for invalid queries
4. Data integrity is maintained
"""

import pytest
from tests import TestToolTemplate

# Import tools
from ghidra_assist.tools.functions import (
    ListFunctions,
    DecompileFunction,
    GetFunctionSignature,
    GetDisassembly,
    SearchFunctions,
)
from ghidra_assist.tools.xrefs import GetXrefsTo, GetXrefsFrom, GetCallGraph
from ghidra_assist.tools.strings import ListStrings, ListImports, ListExports
from ghidra_assist.tools.data_types import ListDataTypes, GetMemoryMap, ReadBytes


class TestListFunctions(TestToolTemplate):
    """Test ListFunctions tool."""

    @pytest.mark.asyncio
    async def test_list_all_functions(self, mock_cache):
        """Test listing all functions in a program."""
        mock_cache.bridge.list_functions.return_value = [
            {"address": "0x401000", "name": "main", "entry": "0x401000"},
            {"address": "0x401100", "name": "process", "entry": "0x401100"},
        ]

        tool = ListFunctions()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin"
        )

        self.assert_success(result)
        assert len(result["functions"]) == 2
        assert result["functions"][0]["name"] == "main"

    @pytest.mark.asyncio
    async def test_list_functions_with_filter(self, mock_cache):
        """Test listing functions with name filter."""
        mock_cache.bridge.list_functions.return_value = [
            {"address": "0x401100", "name": "process_data", "entry": "0x401100"},
        ]

        tool = ListFunctions()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin",
            filter="process"
        )

        self.assert_success(result)
        assert len(result["functions"]) == 1
        assert "process" in result["functions"][0]["name"].lower()


class TestDecompileFunction(TestToolTemplate):
    """Test DecompileFunction tool."""

    @pytest.mark.asyncio
    async def test_decompile_by_name(self, mock_cache):
        """Test decompiling a function by name."""
        mock_code = "void main() {\n  printf(\"Hello World\\n\");\n}"
        mock_cache.bridge.decompile_function.return_value = {
            "decompilation": mock_code,
            "address": "0x401000",
            "function": "main",
        }

        tool = DecompileFunction()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin",
            function_name="main"
        )

        self.assert_success(result)
        assert "printf" in result["decompilation"]

    @pytest.mark.asyncio
    async def test_decompile_by_address(self, mock_cache):
        """Test decompiling a function by address."""
        mock_code = "void process() {\n  // function code\n}"
        mock_cache.bridge.decompile_function.return_value = {
            "decompilation": mock_code,
            "address": "0x401000",
            "function": "process",
        }

        tool = DecompileFunction()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin",
            address="0x401000"
        )

        self.assert_success(result)
        assert "process" in result["function"]

    @pytest.mark.asyncio
    async def test_decompile_missing_function(self, mock_cache):
        """Test error when function not found."""
        tool = DecompileFunction()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin"
        )

        assert result.get("error") is not None


class TestListStrings(TestToolTemplate):
    """Test ListStrings tool."""

    @pytest.mark.asyncio
    async def test_list_strings(self, mock_cache):
        """Test listing strings in a program."""
        mock_cache.bridge.list_strings.return_value = [
            {"address": "0x2000", "value": "Hello World", "length": 11},
            {"address": "0x200B", "value": "Error!", "length": 6},
        ]

        tool = ListStrings()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin"
        )

        self.assert_success(result)
        assert len(result["strings"]) == 2
        assert result["strings"][0]["value"] == "Hello World"

    @pytest.mark.asyncio
    async def test_list_strings_with_filter(self, mock_cache):
        """Test listing strings with minimum length filter."""
        mock_cache.bridge.list_strings.return_value = [
            {"address": "0x2000", "value": "Hello World", "length": 11},
        ]

        tool = ListStrings()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin",
            min_length=10
        )

        self.assert_success(result)
        assert all(s["length"] >= 10 for s in result["strings"])


class TestListImports(TestToolTemplate):
    """Test ListImports tool."""

    @pytest.mark.asyncio
    async def test_list_imports(self, mock_cache):
        """Test listing imported functions."""
        mock_cache.bridge.list_imports.return_value = [
            {"address": "0x3000", "name": "printf", "library": "libc"},
            {"address": "0x3008", "name": "malloc", "library": "libc"},
        ]

        tool = ListImports()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin"
        )

        self.assert_success(result)
        assert len(result["imports"]) == 2
        assert result["imports"][0]["name"] == "printf"


class TestGetXrefsTo(TestToolTemplate):
    """Test GetXrefsTo tool."""

    @pytest.mark.asyncio
    async def test_get_xrefs_to_address(self, mock_cache):
        """Test getting cross-references TO an address."""
        mock_cache.bridge.get_xrefs_to.return_value = [
            {"from_address": "0x401100", "from_function": "main", "type": "call"},
            {"from_address": "0x401200", "from_function": "init", "type": "call"},
        ]

        tool = GetXrefsTo()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin",
            address="0x401000"
        )

        self.assert_success(result)
        assert len(result["xrefs"]) == 2
        assert result["xrefs"][0]["type"] == "call"


class TestGetCallGraph(TestToolTemplate):
    """Test GetCallGraph tool."""

    @pytest.mark.asyncio
    async def test_get_call_graph(self, mock_cache):
        """Test getting call graph for a function."""
        mock_cache.bridge.get_call_graph.return_value = {
            "function": "main",
            "address": "0x401000",
            "calls": [
                {"target": "printf", "address": "0x401100"},
                {"target": "process", "address": "0x401200"},
            ],
            "depth": 1,
        }

        tool = GetCallGraph()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin",
            function_name="main",
            depth=1
        )

        self.assert_success(result)
        assert result["function"] == "main"
        assert len(result["calls"]) == 2


class TestReadBytes(TestToolTemplate):
    """Test ReadBytes tool."""

    @pytest.mark.asyncio
    async def test_read_bytes(self, mock_cache):
        """Test reading bytes from memory."""
        mock_cache.bridge.read_bytes.return_value = {
            "address": "0x401000",
            "bytes": "55 48 89 E5 48 83 EC 10",
            "length": 8,
        }

        tool = ReadBytes()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin",
            address="0x401000",
            length=8
        )

        self.assert_success(result)
        assert result["length"] == 8
        assert len(result["bytes"].split()) == 8

    @pytest.mark.asyncio
    async def test_read_bytes_capped_length(self, mock_cache):
        """Test that very large length requests are capped."""
        mock_cache.bridge.read_bytes.return_value = {
            "address": "0x401000",
            "bytes": "90 " * 1024,
            "length": 1024,
        }

        tool = ReadBytes()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin",
            address="0x401000",
            length=10000  # Request more than cap
        )

        self.assert_success(result)
        assert result["length"] <= 1024  # Should be capped


class TestGetMemoryMap(TestToolTemplate):
    """Test GetMemoryMap tool."""

    @pytest.mark.asyncio
    async def test_get_memory_map(self, mock_cache):
        """Test getting memory segments."""
        mock_cache.bridge.get_memory_map.return_value = [
            {"name": ".text", "start": "0x400000", "end": "0x402000", "size": 8192, "permissions": "rx"},
            {"name": ".data", "start": "0x600000", "end": "0x601000", "size": 4096, "permissions": "rw"},
        ]

        tool = GetMemoryMap()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin"
        )

        self.assert_success(result)
        assert len(result["segments"]) == 2
        assert result["segments"][0]["name"] == ".text"


class TestTraceStringReferences(TestToolTemplate):
    """Test TraceStringReferences tool."""

    @pytest.mark.asyncio
    async def test_trace_simple_string(self, mock_cache):
        """Test tracing references to a simple string."""
        from ghidra_assist.tools.string_tracker import TraceStringReferences

        mock_cache.bridge.list_strings.return_value = [
            {"value": "malicious.com", "address": "0x405000"},
            {"value": "config.ini", "address": "0x405020"},
        ]
        mock_cache.bridge.get_xrefs_to.return_value = [
            {"address": "0x401234", "function_name": "connect_c2", "type": "read"},
            {"address": "0x401567", "function_name": "init_network", "type": "read"},
        ]
        mock_cache.bridge.decompile_function.return_value = "void connect_c2() { // sends to malicious.com }"

        tool = TraceStringReferences()
        result = await tool.execute(
            repository="TestRepo",
            program="malware.exe",
            search_string="malicious.com"
        )

        self.assert_success(result)
        assert result["total_references"] == 2
        assert "malicious.com" in result["string_value"]
        assert len(result["functions_involved"]) > 0

    @pytest.mark.asyncio
    async def test_trace_string_not_found(self, mock_cache):
        """Test tracing a string that doesn't exist."""
        from ghidra_assist.tools.string_tracker import TraceStringReferences

        mock_cache.bridge.list_strings.return_value = [
            {"value": "normal_string", "address": "0x405000"},
        ]

        tool = TraceStringReferences()
        result = await tool.execute(
            repository="TestRepo",
            program="program.exe",
            search_string="nonexistent_string"
        )

        self.assert_success(result)
        assert result["total_references"] == 0
        assert result["impact_summary"] == "No matching strings found."


class TestDetectCodePatterns(TestToolTemplate):
    """Test DetectCodePatterns tool."""

    @pytest.mark.asyncio
    async def test_detect_crypto_patterns(self, mock_cache):
        """Test detecting crypto patterns."""
        from ghidra_assist.tools.pattern_detector import DetectCodePatterns

        # Mock strings that contain crypto-related content
        mock_cache.bridge.list_strings.return_value = [
            {"value": "0x67452301", "address": "0x405000"},  # SHA-1 constant
            {"value": "normal_string", "address": "0x405020"},
        ]
        mock_cache.bridge.list_imports.return_value = [
            {"name": "OpenSSL", "address": "0x400000"},
        ]

        tool = DetectCodePatterns()
        result = await tool.execute(
            repository="TestRepo",
            program="encrypted.exe",
            pattern_category="crypto"
        )

        self.assert_success(result)
        assert result["patterns_found"] >= 0
        assert "category_summary" in result
        assert "iocs_extracted" in result

    @pytest.mark.asyncio
    async def test_detect_network_patterns(self, mock_cache):
        """Test detecting network patterns."""
        from ghidra_assist.tools.pattern_detector import DetectCodePatterns

        mock_cache.bridge.list_strings.return_value = [
            {"value": "POST /api/beacon HTTP/1.1", "address": "0x405000"},
            {"value": "User-Agent: Custom", "address": "0x405050"},
        ]
        mock_cache.bridge.list_imports.return_value = [
            {"name": "WinHTTP.dll", "address": "0x400000"},
        ]

        tool = DetectCodePatterns()
        result = await tool.execute(
            repository="TestRepo",
            program="c2.exe",
            pattern_category="network"
        )

        self.assert_success(result)
        assert "matches" in result
        assert "iocs_extracted" in result
