"""YAGMCP test suite."""

from typing import Any, Dict


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


__all__ = ["TestToolTemplate"]
