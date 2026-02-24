# YAGMCP Test Suite

Comprehensive automated tests for all YAGMCP tools (analysis, modification, malware analysis).

## Overview

The test suite consists of three main categories:

### 1. **Modification Tools** (`test_modification_tools.py`)
Tests for tools that modify Ghidra programs:
- `RenameFunction` — verify function renaming and persistence
- `RenameVariable` — verify parameter and local variable renaming
- `SetComment` — verify comment creation/updates
- `PatchBytes` — verify hex patching with validation
- `RenameLabel` — verify label creation and renaming

**Key focus**: Verify that `program.save()` is called to persist changes to disk.

### 2. **Analysis Tools** (`test_analysis_tools.py`)
Tests for read-only analysis tools:
- `ListFunctions` — function listing and filtering
- `DecompileFunction` — C pseudocode generation
- `GetDisassembly` — assembly listing
- `ListStrings` — string enumeration
- `ListImports` / `ListExports` — symbol management
- `GetXrefsTo` / `GetXrefsFrom` — cross-reference analysis
- `GetCallGraph` — call tree visualization
- `ReadBytes` — memory reading with bounds checking
- `GetMemoryMap` — segment listing

**Key focus**: Verify correct data formatting and filtering logic.

### 3. **Malware Analysis Tools** (`test_malware_tools.py`)
Tests for binary analysis and detection tools:
- `TriageBinary` — automated binary triage (architecture, packing, suspicious imports)
- `ExtractIOCs` — indicator of compromise extraction (IPs, URLs, domains, registry keys)
- `DetectAntiAnalysis` — anti-debug, anti-VM, sandbox evasion detection
- `GenerateYara` — YARA rule synthesis from indicators

**Key focus**: Verify detection accuracy and rule quality.

## Running Tests

### Install test dependencies:
```bash
uv sync --all-groups  # From server/ directory (uses uv.lock for reproducible builds)
```

### Run all tests:
```bash
pytest
```

### Run tests by category:
```bash
# Modification tools only
pytest tests/test_modification_tools.py

# Analysis tools only
pytest tests/test_analysis_tools.py

# Malware analysis tools only
pytest tests/test_malware_tools.py
```

### Run specific test:
```bash
pytest tests/test_modification_tools.py::TestRenameFunction::test_rename_function_by_name
```

### Run with verbose output:
```bash
pytest -v
```

### Run with logging:
```bash
pytest -v --log-cli-level=DEBUG
```

### Run and stop on first failure:
```bash
pytest -x
```

## Test Structure

Each test file follows this pattern:

```python
class TestToolName(TestToolTemplate):
    @pytest.mark.asyncio
    async def test_basic_functionality(self, mock_cache):
        """Test the basic happy path."""
        # Setup mock bridge return value
        mock_cache.bridge.tool_method.return_value = {...}

        # Instantiate tool
        tool = ToolName()

        # Execute
        result = await tool.execute(...)

        # Assert
        self.assert_success(result)
        assert result["expected_field"] == "expected_value"

    @pytest.mark.asyncio
    async def test_error_condition(self, mock_cache):
        """Test error handling."""
        # ... setup ...
        result = await tool.execute(...)
        self.assert_error(result, "expected_error_substring")
```

## Key Testing Principles

### 1. **Mock Ghidra Objects**
All tests use `mock_cache` and `mock_program` fixtures to avoid requiring a full Ghidra installation:
- `mock_cache` — mocks ProjectCache and GhidraBridge
- `mock_program` — mocks Ghidra Program object
- `mock_function` — mocks Ghidra Function object
- `mock_address` — mocks Ghidra Address object

### 2. **Test Assertions**
Use `TestToolTemplate` helper methods:
```python
self.assert_success(result)        # Verify successful execution
self.assert_error(result, "foo")   # Verify error with message
```

### 3. **Tool Execution Format**
All tool tests follow:
```python
tool = ToolClass()
result = await tool.execute(
    repository="TestRepo",
    program="test.bin",
    param1="value1",
    ...
)
```

### 4. **Expected Return Format**
All tools return dicts:
```python
# Success
{
    "success": True,
    "field1": "value1",
    ...
}

# Error
{
    "success": False,
    "error": "Error message"
}
```

## Verification Checklist

Before committing tool changes, verify:

- [ ] `pytest` runs all tests without errors
- [ ] All modification tools include `program.save()` calls
- [ ] Tools validate parameters and return appropriate errors
- [ ] Analysis tools filter and paginate data correctly
- [ ] Malware analysis tools detect expected indicators
- [ ] Tool responses follow the standard dict format
- [ ] Tool names and descriptions are accurate

## Continuous Integration

Run tests automatically before deployment:

```bash
cd server/
uv sync --all-groups
pytest --tb=short && echo "✓ All tests passed"
```

Failures should block deployment until resolved.

## Adding New Tests

When adding new tools:

1. **Create test class** in appropriate file:
   ```python
   class TestNewTool(TestToolTemplate):
       @pytest.mark.asyncio
       async def test_happy_path(self, mock_cache):
           ...
   ```

2. **Mock the bridge method**:
   ```python
   mock_cache.bridge.new_tool_method.return_value = {...}
   ```

3. **Test success and error cases**:
   ```python
   test_basic_functionality()
   test_error_condition()
   test_edge_case()
   ```

4. **Verify tool saves data** (if modification):
   ```python
   mock_cache.bridge.new_method.return_value = {
       "success": True,
       ...
   }
   ```

## Troubleshooting

### Tests fail with "Tool must return a dict"
- Ensure tool's `execute()` method returns a dict, not a Pydantic model

### Mock bridge methods not called
- Check that `_get_cache()` is patched in conftest.py for the module
- Verify mock call: `mock_cache.bridge.method_name.assert_called_once()`

### Async tests fail with "RuntimeError: no running event loop"
- Ensure `@pytest.mark.asyncio` decorator is present
- Verify `asyncio_mode = auto` in pytest.ini

### Import errors for tools
- Ensure tool is exported from `__init__.py`
- Check that all dependencies are installed: `uv sync --all-groups`
