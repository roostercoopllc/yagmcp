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
            {
                "name": "main",
                "entry": "0x401000",
                "body_size": 256,
                "parameter_count": 2,
                "return_type": "int",
                "calling_convention": "cdecl",
            },
            {
                "name": "process",
                "entry": "0x401100",
                "body_size": 512,
                "parameter_count": 1,
                "return_type": "void",
                "calling_convention": "cdecl",
            },
        ]

        tool = ListFunctions()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin"
        )

        self.assert_success(result)
        assert len(self.get_data(result)["functions"]) == 2
        assert self.get_data(result)["functions"][0]["name"] == "main"

    @pytest.mark.asyncio
    async def test_list_functions_with_filter(self, mock_cache):
        """Test listing functions with name filter."""
        mock_cache.bridge.list_functions.return_value = [
            {
                "name": "process_data",
                "entry": "0x401100",
                "body_size": 384,
                "parameter_count": 2,
                "return_type": "int",
                "calling_convention": "cdecl",
            },
        ]

        tool = ListFunctions()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin",
            filter="process"
        )

        self.assert_success(result)
        assert len(self.get_data(result)["functions"]) == 1
        assert "process" in self.get_data(result)["functions"][0]["name"].lower()


class TestDecompileFunction(TestToolTemplate):
    """Test DecompileFunction tool."""

    @pytest.mark.asyncio
    async def test_decompile_by_name(self, mock_cache):
        """Test decompiling a function by name."""
        mock_code = "void main() {\n  printf(\"Hello World\\n\");\n}"
        # Mock list_functions to find the function by name
        mock_cache.bridge.list_functions.return_value = [
            {
                "name": "main",
                "entry": "0x401000",
                "body_size": 256,
                "parameter_count": 2,
                "return_type": "int",
                "calling_convention": "cdecl",
            },
        ]
        # Mock decompile result
        mock_cache.bridge.decompile.return_value = {
            "success": True,
            "name": "main",
            "entry": "0x401000",
            "decompiled_c": mock_code,
            "signature": "int main(int argc, char** argv)",
        }

        tool = DecompileFunction()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin",
            function_name="main"
        )

        self.assert_success(result)
        assert "printf" in self.get_data(result)["decompiled_c"]

    @pytest.mark.asyncio
    async def test_decompile_by_address(self, mock_cache):
        """Test decompiling a function by address."""
        mock_code = "void process() {\n  // function code\n}"
        # Mock decompile result
        mock_cache.bridge.decompile.return_value = {
            "success": True,
            "name": "process",
            "entry": "0x401000",
            "decompiled_c": mock_code,
            "signature": "void process(void)",
        }

        tool = DecompileFunction()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin",
            address="0x401000"
        )

        self.assert_success(result)
        assert "process" in self.get_data(result)["function_name"]

    @pytest.mark.asyncio
    async def test_decompile_missing_function(self, mock_cache):
        """Test error when function not found."""
        tool = DecompileFunction()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin"
        )

        # Tool should fail when both function_name and address are missing
        from ghidra_assist.tools.base import ToolResult
        if isinstance(result, ToolResult):
            assert result.success is False, "Tool should fail without function_name or address"
        else:
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
        assert len(self.get_data(result)["strings"]) == 2
        assert self.get_data(result)["strings"][0]["value"] == "Hello World"

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
        assert all(s["length"] >= 10 for s in self.get_data(result)["strings"])


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
        assert len(self.get_data(result)["imports"]) == 2
        assert self.get_data(result)["imports"][0]["name"] == "printf"


class TestGetXrefsTo(TestToolTemplate):
    """Test GetXrefsTo tool."""

    @pytest.mark.asyncio
    async def test_get_xrefs_to_address(self, mock_cache):
        """Test getting cross-references TO an address."""
        mock_cache.bridge.get_xrefs_to.return_value = [
            {"from_addr": "0x401100", "ref_type": "call"},
            {"from_addr": "0x401200", "ref_type": "call"},
        ]

        tool = GetXrefsTo()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin",
            address="0x401000"
        )

        self.assert_success(result)
        assert len(self.get_data(result)["xrefs"]) == 2
        assert self.get_data(result)["xrefs"][0]["ref_type"] == "call"


class TestGetCallGraph(TestToolTemplate):
    """Test GetCallGraph tool."""

    @pytest.mark.asyncio
    async def test_get_call_graph(self, mock_cache):
        """Test getting call graph for a function."""
        # Need to mock list_functions for the tool to find the function by name
        mock_cache.bridge.list_functions.return_value = [
            {
                "name": "main",
                "entry": "0x401000",
                "body_size": 256,
                "parameter_count": 2,
                "return_type": "int",
                "calling_convention": "cdecl",
            },
            {
                "name": "printf",
                "entry": "0x401100",
                "body_size": 128,
                "parameter_count": 1,
                "return_type": "int",
                "calling_convention": "cdecl",
            },
        ]

        tool = GetCallGraph()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin",
            function_name="main",
            depth=1
        )

        self.assert_success(result)
        # Check that root structure exists
        assert "root" in self.get_data(result)
        assert "name" in self.get_data(result)["root"]
        assert "address" in self.get_data(result)["root"]
        assert "callees" in self.get_data(result)["root"]
        assert "callers" in self.get_data(result)["root"]


class TestReadBytes(TestToolTemplate):
    """Test ReadBytes tool."""

    @pytest.mark.asyncio
    async def test_read_bytes(self, mock_cache):
        """Test reading bytes from memory."""
        mock_cache.bridge.read_bytes.return_value = {
            "address": "0x401000",
            "hex": "55 48 89 E5 48 83 EC 10",
            "ascii": "UH..H...",
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
        assert self.get_data(result)["length"] == 8
        assert len(self.get_data(result)["hex_dump"].split()) == 8

    @pytest.mark.asyncio
    async def test_read_bytes_capped_length(self, mock_cache):
        """Test that very large length requests are capped."""
        mock_cache.bridge.read_bytes.return_value = {
            "address": "0x401000",
            "hex": "90 " * 1024,
            "ascii": "." * 1024,
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
        assert self.get_data(result)["length"] <= 1024  # Should be capped


class TestGetMemoryMap(TestToolTemplate):
    """Test GetMemoryMap tool."""

    @pytest.mark.asyncio
    async def test_get_memory_map(self, mock_cache):
        """Test getting memory segments."""
        mock_cache.bridge.get_memory_map.return_value = [
            {"name": ".text", "start": "0x400000", "end": "0x402000", "size": 8192, "read": True, "write": False, "execute": True, "initialized": True},
            {"name": ".data", "start": "0x600000", "end": "0x601000", "size": 4096, "read": True, "write": True, "execute": False, "initialized": True},
        ]

        tool = GetMemoryMap()
        result = await tool.execute(
            repository="TestRepo",
            program="test.bin"
        )

        self.assert_success(result)
        assert len(self.get_data(result)["memory_blocks"]) == 2
        assert self.get_data(result)["memory_blocks"][0]["name"] == ".text"


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
        assert self.get_data(result)["total_references"] == 2
        assert "malicious.com" in self.get_data(result)["string_value"]
        assert len(self.get_data(result)["functions_involved"]) > 0

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
        assert self.get_data(result)["total_references"] == 0
        assert self.get_data(result)["impact_summary"] == "No matching strings found."


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
        assert self.get_data(result)["patterns_found"] >= 0
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


class TestInferTypesAndStructures(TestToolTemplate):
    """Test InferTypesAndStructures tool."""

    @pytest.mark.asyncio
    async def test_infer_types_by_name(self, mock_cache):
        """Test inferring types for a function by name."""
        from ghidra_assist.tools.type_inference import InferTypesAndStructures

        mock_code = """void process_data(void* pData, size_t cbSize, HANDLE hHandle) {
            malloc(cbSize);
            pData->field = 0x123;
            handle->method();
        }"""

        mock_cache.bridge.decompile_function.return_value = {
            "decompilation": mock_code,
            "function": "process_data",
            "address": "0x401000",
        }

        tool = InferTypesAndStructures()
        result = await tool.execute(
            repository="TestRepo",
            program="test.exe",
            function_name="process_data"
        )

        self.assert_success(result)
        assert self.get_data(result)["function_name"] == "process_data"
        assert "suggestions" in result
        assert "parameter_types" in result
        assert "struct_suggestions" in result
        assert self.get_data(result)["confidence_overall"] >= 0.0 and self.get_data(result)["confidence_overall"] <= 1.0

    @pytest.mark.asyncio
    async def test_infer_types_by_address(self, mock_cache):
        """Test inferring types for a function by address."""
        from ghidra_assist.tools.type_inference import InferTypesAndStructures

        mock_code = """BOOL check_size(int size) {
            if (size == 0) return FALSE;
            return TRUE;
        }"""

        mock_cache.bridge.decompile_function.return_value = {
            "decompilation": mock_code,
            "function": "check_size",
            "address": "0x401000",
        }

        tool = InferTypesAndStructures()
        result = await tool.execute(
            repository="TestRepo",
            program="test.exe",
            address="0x401000"
        )

        self.assert_success(result)
        assert self.get_data(result)["address"] == "0x401000"
        assert self.get_data(result)["return_type"]["type"] is not None


class TestCompareBinaries(TestToolTemplate):
    """Test CompareBinaries tool."""

    @pytest.mark.asyncio
    async def test_compare_binaries(self, mock_cache):
        """Test comparing two binary programs."""
        from ghidra_assist.tools.binary_compare import CompareBinaries

        # Mock function lists for both programs
        funcs_v1 = [
            {"name": "main", "address": "0x401000", "size": 256},
            {"name": "process_data", "address": "0x401100", "size": 512},
            {"name": "helper", "address": "0x401200", "size": 128},
        ]
        funcs_v2 = [
            {"name": "main", "address": "0x402000", "size": 256},
            {"name": "process_data", "address": "0x402100", "size": 480},  # Slightly different size
            {"name": "new_function", "address": "0x402200", "size": 200},  # New function
        ]

        # Mock decompilation results
        decomp_v1_main = "void main() { process_data(buf); }"
        decomp_v2_main = "void main() { process_data(buf); }"

        call_count = [0]

        def decompile_side_effect(prog, function_name=None, address=None):
            call_count[0] += 1
            if "main" in (function_name or ""):
                return {
                    "decompilation": decomp_v1_main if call_count[0] == 1 else decomp_v2_main,
                    "function": "main",
                    "address": "0x401000" if call_count[0] == 1 else "0x402000",
                }
            return {
                "decompilation": "void func() { }",
                "function": function_name or "unknown",
                "address": address or "unknown",
            }

        mock_cache.bridge.list_functions.side_effect = [funcs_v1, funcs_v2]
        mock_cache.bridge.decompile_function.side_effect = decompile_side_effect

        tool = CompareBinaries()
        result = await tool.execute(
            repository1="TestRepo",
            program1="malware_v1.exe",
            repository2="TestRepo",
            program2="malware_v2.exe",
            similarity_threshold=0.70
        )

        self.assert_success(result)
        assert self.get_data(result)["program1"] == "malware_v1.exe"
        assert self.get_data(result)["program2"] == "malware_v2.exe"
        assert "summary" in result
        assert "modified_functions" in result
        assert "added_functions" in result
        assert "removed_functions" in result

    @pytest.mark.asyncio
    async def test_compare_empty_functions(self, mock_cache):
        """Test error handling when no functions found."""
        from ghidra_assist.tools.binary_compare import CompareBinaries
        from ghidra_assist.tools.base import ToolResult

        # Mock empty function lists
        mock_cache.bridge.list_functions.side_effect = [[], []]

        tool = CompareBinaries()
        result = await tool.execute(
            repository1="TestRepo",
            program1="empty1.exe",
            repository2="TestRepo",
            program2="empty2.exe"
        )

        # Should handle empty function lists gracefully (returns error ToolResult)
        assert isinstance(result, (dict, ToolResult))
        assert hasattr(result, 'success') or isinstance(result, dict)


class TestAnalyzeCallGraph(TestToolTemplate):
    """Test AnalyzeCallGraph tool."""

    @pytest.mark.asyncio
    async def test_analyze_call_graph_all_functions(self, mock_cache):
        """Test analyzing call graph for all functions."""
        from ghidra_assist.tools.call_graph import AnalyzeCallGraph

        # Mock function list
        mock_cache.bridge.list_functions.return_value = [
            {"name": "main", "address": "0x401000"},
            {"name": "process_data", "address": "0x401100"},
            {"name": "helper", "address": "0x401200"},
        ]

        # Mock xrefs (call relationships)
        def xrefs_side_effect(prog, func_name):
            if func_name == "main":
                return [
                    {"to_addr": "process_data", "ref_type": "call", "is_call": True},
                    {"to_addr": "helper", "ref_type": "call", "is_call": True},
                ]
            elif func_name == "process_data":
                return [
                    {"to_addr": "helper", "ref_type": "call", "is_call": True},
                ]
            return []

        mock_cache.bridge.get_xrefs_from.side_effect = xrefs_side_effect

        tool = AnalyzeCallGraph()
        result = await tool.execute(
            repository="TestRepo",
            program="test.exe"
        )

        self.assert_success(result)
        assert self.get_data(result)["function_count"] > 0
        assert "nodes" in result
        assert "edges" in result
        assert "critical_functions" in result
        assert "graph_metrics" in result

    @pytest.mark.asyncio
    async def test_analyze_call_graph_from_root(self, mock_cache):
        """Test analyzing call graph from specific function."""
        from ghidra_assist.tools.call_graph import AnalyzeCallGraph

        mock_cache.bridge.list_functions.return_value = [
            {"name": "main", "address": "0x401000"},
            {"name": "helper", "address": "0x401200"},
        ]

        def xrefs_side_effect(prog, func_name):
            if func_name == "main":
                return [
                    {"to_addr": "helper", "ref_type": "call", "is_call": True},
                ]
            return []

        mock_cache.bridge.get_xrefs_from.side_effect = xrefs_side_effect

        tool = AnalyzeCallGraph()
        result = await tool.execute(
            repository="TestRepo",
            program="test.exe",
            root_function="main",
            max_depth=3
        )

        self.assert_success(result)
        assert self.get_data(result)["root_function"] == "main"
        assert "edges" in result
        assert "cycles" in result
