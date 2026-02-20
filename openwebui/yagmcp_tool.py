"""
YAGMCP Tool for Open WebUI.

Wraps the YAGMCP REST API so that Open WebUI can call Ghidra analysis
functions as tool calls within any chat model.

Install:
  1. Open WebUI > Workspace > Tools > "+" (Create Tool)
  2. Paste this entire file
  3. Configure the Valve: yagmcp_url = http://<server-ip>:8889
  4. Enable the tool in your model settings
"""

from typing import Optional

import httpx
from pydantic import BaseModel, Field


class Tools:
    """YAGMCP — Ghidra reverse-engineering assistant tools."""

    class Valves(BaseModel):
        """User-configurable settings exposed in the Open WebUI UI."""

        yagmcp_url: str = Field(
            default="http://192.168.0.167:8889",
            description="Base URL of the YAGMCP server (no trailing slash)",
        )
        request_timeout: int = Field(
            default=120,
            description="HTTP request timeout in seconds",
        )

    def __init__(self):
        self.valves = self.Valves()

    # --------------------------------------------------------------------- #
    # Internal helpers
    # --------------------------------------------------------------------- #

    def _url(self, path: str) -> str:
        """Build a full URL from a relative API path."""
        return f"{self.valves.yagmcp_url.rstrip('/')}{path}"

    async def _get(self, path: str, params: Optional[dict] = None) -> dict:
        """Perform an async GET request to the YAGMCP server."""
        async with httpx.AsyncClient(timeout=self.valves.request_timeout) as client:
            resp = await client.get(self._url(path), params=params)
            resp.raise_for_status()
            return resp.json()

    async def _post(self, path: str, payload: dict) -> dict:
        """Perform an async POST request to the YAGMCP server."""
        async with httpx.AsyncClient(timeout=self.valves.request_timeout) as client:
            resp = await client.post(self._url(path), json=payload)
            resp.raise_for_status()
            return resp.json()

    # --------------------------------------------------------------------- #
    # Tool: decompile_function
    # --------------------------------------------------------------------- #

    async def decompile_function(
        self,
        repository: str,
        program: str,
        function_name: str,
    ) -> str:
        """
        Decompile a function from a Ghidra program and return pseudo-C source.

        :param repository: Name of the Ghidra shared repository.
        :param program: Name of the program/binary within the repository.
        :param function_name: Exact name of the function to decompile.
        :return: Decompiled C-like source code of the function.
        """
        try:
            data = await self._get(
                f"/api/repositories/{repository}/programs/{program}"
                f"/functions/{function_name}/decompile"
            )
            return data.get("decompilation", data.get("error", "No output"))
        except httpx.HTTPStatusError as exc:
            return f"HTTP error {exc.response.status_code}: {exc.response.text}"
        except Exception as exc:
            return f"Error decompiling function: {exc}"

    # --------------------------------------------------------------------- #
    # Tool: list_functions
    # --------------------------------------------------------------------- #

    async def list_functions(
        self,
        repository: str,
        program: str,
        filter: str = "",
    ) -> str:
        """
        List functions in a Ghidra program, optionally filtered by name substring.

        :param repository: Name of the Ghidra shared repository.
        :param program: Name of the program/binary within the repository.
        :param filter: Optional substring to filter function names (case-insensitive).
        :return: Newline-separated list of matching function names and addresses.
        """
        try:
            params = {}
            if filter:
                params["filter"] = filter
            data = await self._get(
                f"/api/repositories/{repository}/programs/{program}/functions",
                params=params,
            )
            functions = data.get("functions", [])
            if not functions:
                return "No functions found."
            lines = []
            for fn in functions:
                addr = fn.get("address", "???")
                name = fn.get("name", "???")
                lines.append(f"  {addr}  {name}")
            return f"Found {len(functions)} function(s):\n" + "\n".join(lines)
        except httpx.HTTPStatusError as exc:
            return f"HTTP error {exc.response.status_code}: {exc.response.text}"
        except Exception as exc:
            return f"Error listing functions: {exc}"

    # --------------------------------------------------------------------- #
    # Tool: analyze_function
    # --------------------------------------------------------------------- #

    async def analyze_function(
        self,
        message: str,
        repository: str,
        program: str,
        function_name: str,
    ) -> str:
        """
        Decompile a function, then ask the LLM to analyze it with a custom prompt.

        :param message: Analysis prompt/question (e.g., "What does this function do?").
        :param repository: Name of the Ghidra shared repository.
        :param program: Name of the program/binary within the repository.
        :param function_name: Exact name of the function to analyze.
        :return: LLM-generated analysis of the decompiled function.
        """
        try:
            data = await self._post(
                "/api/chat",
                {
                    "message": message,
                    "repository": repository,
                    "program": program,
                    "function_name": function_name,
                },
            )
            return data.get("response", data.get("error", "No response"))
        except httpx.HTTPStatusError as exc:
            return f"HTTP error {exc.response.status_code}: {exc.response.text}"
        except Exception as exc:
            return f"Error analyzing function: {exc}"

    # --------------------------------------------------------------------- #
    # Tool: list_repositories
    # --------------------------------------------------------------------- #

    async def list_repositories(self) -> str:
        """
        List all available Ghidra repositories on the server.

        :return: Newline-separated list of repository names.
        """
        try:
            data = await self._get("/api/repositories")
            repos = data.get("repositories", [])
            if not repos:
                return "No repositories found."
            lines = [f"  - {r}" for r in repos]
            return f"Found {len(repos)} repository(ies):\n" + "\n".join(lines)
        except httpx.HTTPStatusError as exc:
            return f"HTTP error {exc.response.status_code}: {exc.response.text}"
        except Exception as exc:
            return f"Error listing repositories: {exc}"

    # --------------------------------------------------------------------- #
    # Tool: list_programs
    # --------------------------------------------------------------------- #

    async def list_programs(self, repository: str) -> str:
        """
        List all programs/binaries in a Ghidra repository.

        :param repository: Name of the Ghidra shared repository.
        :return: Newline-separated list of program names.
        """
        try:
            data = await self._get(f"/api/repositories/{repository}/programs")
            programs = data.get("programs", [])
            if not programs:
                return f"No programs found in repository '{repository}'."
            lines = [f"  - {p}" for p in programs]
            return f"Found {len(programs)} program(s):\n" + "\n".join(lines)
        except httpx.HTTPStatusError as exc:
            return f"HTTP error {exc.response.status_code}: {exc.response.text}"
        except Exception as exc:
            return f"Error listing programs: {exc}"
