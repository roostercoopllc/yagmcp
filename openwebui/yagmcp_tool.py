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
            default="http://localhost:8889",
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

    # --------------------------------------------------------------------- #
    # Tool: get_xrefs_to
    # --------------------------------------------------------------------- #

    async def get_xrefs_to(
        self,
        repository: str,
        program: str,
        address: str,
    ) -> str:
        """
        Get all cross-references pointing to a given address.

        :param repository: Name of the Ghidra shared repository.
        :param program: Name of the program/binary within the repository.
        :param address: Address to analyze (hex format, with or without 0x prefix).
        :return: List of references pointing to this address.
        """
        try:
            data = await self._post(
                "/api/tools/get_xrefs_to",
                {
                    "repository": repository,
                    "program": program,
                    "address": address,
                },
            )
            xrefs = data.get("xrefs", [])
            if not xrefs:
                return f"No references found pointing to {address}."
            lines = [f"  {x.get('from_addr', '???')} -> {x.get('type', '???')}" for x in xrefs]
            return f"Found {len(xrefs)} reference(s):\n" + "\n".join(lines)
        except httpx.HTTPStatusError as exc:
            return f"HTTP error {exc.response.status_code}: {exc.response.text}"
        except Exception as exc:
            return f"Error getting xrefs: {exc}"

    # --------------------------------------------------------------------- #
    # Tool: get_xrefs_from
    # --------------------------------------------------------------------- #

    async def get_xrefs_from(
        self,
        repository: str,
        program: str,
        address: str,
    ) -> str:
        """
        Get all cross-references originating from a given address or function.

        :param repository: Name of the Ghidra shared repository.
        :param program: Name of the program/binary within the repository.
        :param address: Address or function name to analyze.
        :return: List of references originating from this address/function.
        """
        try:
            data = await self._post(
                "/api/tools/get_xrefs_from",
                {
                    "repository": repository,
                    "program": program,
                    "address": address,
                },
            )
            xrefs = data.get("xrefs", [])
            if not xrefs:
                return f"No references found from {address}."
            lines = [f"  {x.get('from_addr', '???')} -> {x.get('to_addr', '???')}" for x in xrefs]
            return f"Found {len(xrefs)} reference(s):\n" + "\n".join(lines)
        except httpx.HTTPStatusError as exc:
            return f"HTTP error {exc.response.status_code}: {exc.response.text}"
        except Exception as exc:
            return f"Error getting xrefs: {exc}"

    # --------------------------------------------------------------------- #
    # Tool: get_call_graph
    # --------------------------------------------------------------------- #

    async def get_call_graph(
        self,
        repository: str,
        program: str,
        function_name: str,
        depth: int = 2,
    ) -> str:
        """
        Get the call graph (callers and callees) of a function.

        :param repository: Name of the Ghidra shared repository.
        :param program: Name of the program/binary within the repository.
        :param function_name: Name of the function to analyze.
        :param depth: Recursion depth for the call graph (default: 2).
        :return: Call graph structure showing callers and callees.
        """
        try:
            data = await self._post(
                "/api/tools/get_call_graph",
                {
                    "repository": repository,
                    "program": program,
                    "function_name": function_name,
                    "depth": depth,
                },
            )
            result = data.get("call_graph", {})
            return str(result) if result else f"No call graph found for {function_name}."
        except httpx.HTTPStatusError as exc:
            return f"HTTP error {exc.response.status_code}: {exc.response.text}"
        except Exception as exc:
            return f"Error getting call graph: {exc}"

    # --------------------------------------------------------------------- #
    # Tool: get_disassembly
    # --------------------------------------------------------------------- #

    async def get_disassembly(
        self,
        repository: str,
        program: str,
        address: str,
        num_instructions: int = 10,
    ) -> str:
        """
        Get assembly/disassembly at a given address.

        :param repository: Name of the Ghidra shared repository.
        :param program: Name of the program/binary within the repository.
        :param address: Address to disassemble (hex format, with or without 0x prefix).
        :param num_instructions: Number of instructions to return (default: 10).
        :return: Disassembly listing.
        """
        try:
            data = await self._post(
                "/api/tools/get_disassembly",
                {
                    "repository": repository,
                    "program": program,
                    "address": address,
                    "num_instructions": num_instructions,
                },
            )
            disasm = data.get("disassembly", [])
            if not disasm:
                return f"No disassembly found at {address}."
            lines = [f"  {d}" for d in disasm]
            return "Disassembly:\n" + "\n".join(lines)
        except httpx.HTTPStatusError as exc:
            return f"HTTP error {exc.response.status_code}: {exc.response.text}"
        except Exception as exc:
            return f"Error getting disassembly: {exc}"

    # --------------------------------------------------------------------- #
    # Tool: triage_binary
    # --------------------------------------------------------------------- #

    async def triage_binary(
        self,
        repository: str,
        program: str,
    ) -> str:
        """
        Perform automated binary triage: detect strings, imports, anti-analysis.

        :param repository: Name of the Ghidra shared repository.
        :param program: Name of the program/binary within the repository.
        :return: Triage report with key findings.
        """
        try:
            data = await self._post(
                "/api/tools/triage_binary",
                {
                    "repository": repository,
                    "program": program,
                },
            )
            triage = data.get("triage", {})
            return str(triage) if triage else f"No triage data found for {program}."
        except httpx.HTTPStatusError as exc:
            return f"HTTP error {exc.response.status_code}: {exc.response.text}"
        except Exception as exc:
            return f"Error triaging binary: {exc}"

    # --------------------------------------------------------------------- #
    # Tool: extract_iocs
    # --------------------------------------------------------------------- #

    async def extract_iocs(
        self,
        repository: str,
        program: str,
    ) -> str:
        """
        Extract Indicators of Compromise (IOCs) from a binary.

        :param repository: Name of the Ghidra shared repository.
        :param program: Name of the program/binary within the repository.
        :return: List of IOCs (IPs, domains, hashes, etc.).
        """
        try:
            data = await self._post(
                "/api/tools/extract_iocs",
                {
                    "repository": repository,
                    "program": program,
                },
            )
            iocs = data.get("iocs", [])
            if not iocs:
                return f"No IOCs found in {program}."
            lines = [f"  - {ioc}" for ioc in iocs]
            return f"Found {len(iocs)} IOC(s):\n" + "\n".join(lines)
        except httpx.HTTPStatusError as exc:
            return f"HTTP error {exc.response.status_code}: {exc.response.text}"
        except Exception as exc:
            return f"Error extracting IOCs: {exc}"

    # --------------------------------------------------------------------- #
    # Tool: detect_anti_analysis
    # --------------------------------------------------------------------- #

    async def detect_anti_analysis(
        self,
        repository: str,
        program: str,
    ) -> str:
        """
        Detect anti-analysis techniques (anti-debug, anti-VM, packers, etc.).

        :param repository: Name of the Ghidra shared repository.
        :param program: Name of the program/binary within the repository.
        :return: List of detected anti-analysis techniques.
        """
        try:
            data = await self._post(
                "/api/tools/detect_anti_analysis",
                {
                    "repository": repository,
                    "program": program,
                },
            )
            detections = data.get("detections", [])
            if not detections:
                return f"No anti-analysis techniques detected in {program}."
            lines = [f"  - {d}" for d in detections]
            return f"Found {len(detections)} detection(s):\n" + "\n".join(lines)
        except httpx.HTTPStatusError as exc:
            return f"HTTP error {exc.response.status_code}: {exc.response.text}"
        except Exception as exc:
            return f"Error detecting anti-analysis: {exc}"

    # --------------------------------------------------------------------- #
    # Tool: generate_yara
    # --------------------------------------------------------------------- #

    async def generate_yara(
        self,
        repository: str,
        program: str,
        function_name: str,
    ) -> str:
        """
        Generate YARA rules for a function's signature.

        :param repository: Name of the Ghidra shared repository.
        :param program: Name of the program/binary within the repository.
        :param function_name: Name of the function to generate rules for.
        :return: YARA rule(s) for matching this function in other binaries.
        """
        try:
            data = await self._post(
                "/api/tools/generate_yara",
                {
                    "repository": repository,
                    "program": program,
                    "function_name": function_name,
                },
            )
            rule = data.get("rule", data.get("error", "No rule generated"))
            return rule
        except httpx.HTTPStatusError as exc:
            return f"HTTP error {exc.response.status_code}: {exc.response.text}"
        except Exception as exc:
            return f"Error generating YARA rule: {exc}"
