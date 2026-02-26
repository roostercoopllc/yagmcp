"""YAGMCP test suite."""

from typing import Any, Dict, Union

from ghidra_assist.tools.base import ToolResult


class TestToolTemplate:
    """Base class for tool tests with common assertions.

    Handles both ToolResult objects (new API) and dict responses (legacy).
    """

    @staticmethod
    def assert_success(result: Union[ToolResult, Dict[str, Any]]) -> None:
        """Assert that a tool result indicates success."""
        if isinstance(result, ToolResult):
            assert result.success, f"Tool returned error: {result.message}"
        else:
            assert isinstance(result, dict), "Tool must return a dict or ToolResult"
            assert result.get("success") != False, f"Tool returned error: {result.get('error', 'Unknown error')}"

    @staticmethod
    def assert_error(result: Union[ToolResult, Dict[str, Any]], error_substring: str = "") -> None:
        """Assert that a tool result indicates an error."""
        if isinstance(result, ToolResult):
            assert not result.success, "Tool should indicate error"
            if error_substring:
                assert error_substring.lower() in result.message.lower(), \
                    f"Expected error to contain '{error_substring}', got: {result.message}"
        else:
            assert isinstance(result, dict), "Tool must return a dict or ToolResult"
            assert result.get("success") == False or "error" in result, "Tool should indicate error"
            if error_substring and "error" in result:
                assert error_substring.lower() in result["error"].lower(), \
                    f"Expected error to contain '{error_substring}', got: {result['error']}"

    @staticmethod
    def get_data(result: Union[ToolResult, Dict[str, Any]]) -> Dict[str, Any]:
        """Extract data from a tool result.

        Handles both ToolResult objects (new API) and dict responses (legacy).
        """
        if isinstance(result, ToolResult):
            return result.data if result.data is not None else {}
        else:
            # For dict responses, return the dict itself (without success/error keys)
            data = dict(result)
            data.pop("success", None)
            data.pop("error", None)
            data.pop("message", None)
            return data


__all__ = ["TestToolTemplate"]
