"""YARA rule generation tool.

Tools:
    generate_yara -- gather indicators from a binary (strings, imports,
        byte patterns) and use Ollama to synthesize a YARA detection rule.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict

import httpx

from ghidra_assist.config import settings
from ghidra_assist.project_cache import ProjectCache
from ghidra_assist.tools import register_tool
from ghidra_assist.tools.base import BaseTool, ToolCategory

logger = logging.getLogger(__name__)

_cache: ProjectCache | None = None


def _get_cache() -> ProjectCache:
    global _cache
    if _cache is None:
        _cache = ProjectCache()
    return _cache


# Common strings to exclude (too generic, would cause false positives)
_GENERIC_STRINGS = {
    "This program cannot be run in DOS mode",
    ".text", ".data", ".rdata", ".bss", ".rsrc", ".reloc",
    "Rich", "PE", "MZ",
    "KERNEL32.dll", "ntdll.dll", "USER32.dll", "ADVAPI32.dll",
    "msvcrt.dll", "GDI32.dll",
    "GetProcAddress", "LoadLibrary", "GetModuleHandle",
    "ExitProcess", "GetLastError", "SetLastError",
}


def _is_generic_string(s: str) -> bool:
    """Return True if the string is too generic for YARA rules."""
    if len(s) < 6:
        return True
    if s in _GENERIC_STRINGS:
        return True
    # Pure whitespace or control chars
    if not s.strip():
        return True
    return False


# ---------------------------------------------------------------------- #
# generate_yara
# ---------------------------------------------------------------------- #


@register_tool
class GenerateYara(BaseTool):
    name = "generate_yara"
    description = (
        "Generate a YARA detection rule for a binary by gathering indicators "
        "(strings, imports, byte patterns) and using Ollama to synthesize "
        "the rule."
    )
    category = ToolCategory.ANALYSIS

    async def execute(self, **kwargs: Any) -> Dict[str, Any]:
        err = self._require_params(kwargs, "repository", "program")
        if err:
            return err

        repository: str = kwargs["repository"]
        program_name: str = kwargs["program"]
        rule_name: str = kwargs.get("rule_name", "")
        focus: str = kwargs.get("focus", "all")  # strings, imports, bytes, all
        max_strings: int = int(kwargs.get("max_strings", 10))

        try:
            cache = _get_cache()
            program = cache.get_program(repository, program_name)
            bridge = cache.bridge

            indicators: dict[str, Any] = {
                "strings": [],
                "imports": [],
                "hex_patterns": [],
            }

            # ---- Gather string indicators --------------------------------
            if focus in ("strings", "all"):
                raw_strings = bridge.list_strings(program)
                unique_strings: list[str] = []
                seen: set[str] = set()

                for s in raw_strings:
                    val = s.get("value", "")
                    if val not in seen and not _is_generic_string(val):
                        seen.add(val)
                        unique_strings.append(val)

                # Sort by length descending — longer strings are more specific
                unique_strings.sort(key=len, reverse=True)
                indicators["strings"] = unique_strings[:max_strings]

            # ---- Gather import indicators --------------------------------
            if focus in ("imports", "all"):
                raw_imports = bridge.list_imports(program)
                # Keep imports that suggest malicious behaviour
                suspicious_import_names = [
                    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                    "NtCreateThreadEx", "QueueUserAPC", "NtMapViewOfSection",
                    "IsDebuggerPresent", "NtQueryInformationProcess",
                    "InternetOpen", "HttpSendRequest", "URLDownloadToFile",
                    "WinHttpOpen", "WinHttpSendRequest",
                    "CryptEncrypt", "CryptDecrypt", "BCryptEncrypt",
                    "RegSetValueEx", "CreateService", "ShellExecute",
                    "WinExec", "CreateProcess",
                ]
                suspicious_set = {n.lower() for n in suspicious_import_names}

                for imp in raw_imports:
                    name = imp.get("name", "")
                    if name.lower().rstrip("aw") in suspicious_set or name.lower() in suspicious_set:
                        indicators["imports"].append(name)

                indicators["imports"] = indicators["imports"][:15]

            # ---- Gather byte pattern indicators --------------------------
            if focus in ("bytes", "all"):
                entry_info = bridge.get_entry_point_bytes(program, 32)
                if entry_info.get("success") and entry_info.get("hex"):
                    # Use first 16 bytes of entry point as signature
                    hex_str = entry_info["hex"].replace(" ", "")
                    if len(hex_str) >= 32:
                        indicators["hex_patterns"].append({
                            "description": "Entry point bytes",
                            "hex": hex_str[:32],
                            "address": entry_info.get("address", ""),
                        })

            # ---- Generate rule name if not provided ----------------------
            if not rule_name:
                safe_name = "".join(
                    c if c.isalnum() or c == "_" else "_"
                    for c in program_name
                )
                rule_name = f"Mal_{safe_name}_Gen"

            # ---- Build LLM prompt ----------------------------------------
            llm_prompt = self._build_yara_prompt(
                rule_name, program_name, indicators
            )

            # ---- Call Ollama to generate the rule ------------------------
            model = kwargs.get("model") or settings.ollama_model
            rule_text = ""
            llm_error = ""

            try:
                async with httpx.AsyncClient(timeout=120.0) as client:
                    resp = await client.post(
                        f"{settings.ollama_url}/api/generate",
                        json={
                            "model": model,
                            "prompt": llm_prompt,
                            "stream": False,
                        },
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    rule_text = data.get("response", "").strip()
            except httpx.HTTPError as e:
                llm_error = f"Ollama request failed: {e}"
                logger.error("YARA generation LLM call failed: %s", e)

            # Extract just the YARA rule if the LLM wrapped it in markdown
            if rule_text:
                rule_text = self._extract_yara_block(rule_text)

            result: Dict[str, Any] = {
                "rule": rule_text,
                "rule_name": rule_name,
                "indicators_used": {
                    "strings": len(indicators["strings"]),
                    "imports": len(indicators["imports"]),
                    "hex_patterns": len(indicators["hex_patterns"]),
                },
            }
            if llm_error:
                result["error"] = llm_error
            return result

        except FileNotFoundError:
            return self._error(
                f"Program '{program_name}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("generate_yara failed")
            return self._error(f"YARA generation failed: {exc}")

    @staticmethod
    def _build_yara_prompt(
        rule_name: str,
        program_name: str,
        indicators: dict[str, Any],
    ) -> str:
        """Build the LLM prompt for YARA rule generation."""
        parts = [
            "Generate a valid YARA rule based on the following indicators "
            f"extracted from the binary \"{program_name}\".\n",
            f"Rule name: {rule_name}\n",
        ]

        if indicators["strings"]:
            parts.append("Unique strings found in the binary:")
            for i, s in enumerate(indicators["strings"], 1):
                parts.append(f"  {i}. \"{s}\"")
            parts.append("")

        if indicators["imports"]:
            parts.append("Suspicious imports:")
            for imp in indicators["imports"]:
                parts.append(f"  - {imp}")
            parts.append("")

        if indicators["hex_patterns"]:
            parts.append("Byte patterns:")
            for hp in indicators["hex_patterns"]:
                parts.append(f"  - {hp['description']}: {{ {hp['hex']} }}")
            parts.append("")

        parts.append(
            "Instructions:\n"
            "- Output ONLY the YARA rule, no explanation before or after.\n"
            "- Include a meta section with: description, author=\"YAGMCP\", "
            "date (today), reference to the binary name.\n"
            "- Use $s1, $s2 etc. for string indicators.\n"
            "- Use $h1, $h2 etc. for hex patterns.\n"
            "- Set a reasonable condition (e.g., 3 of ($s*) and 1 of ($h*), "
            "or uint16(0) == 0x5A4D for PE files).\n"
            "- If import indicators are provided, add pe.imports() conditions.\n"
            "- Do NOT include overly generic strings that would cause "
            "false positives.\n"
            "- The rule must be syntactically valid YARA."
        )

        return "\n".join(parts)

    @staticmethod
    def _extract_yara_block(text: str) -> str:
        """Extract YARA rule from LLM output, stripping markdown fences."""
        # Try to find a fenced code block
        if "```" in text:
            lines = text.split("\n")
            inside = False
            rule_lines: list[str] = []
            for line in lines:
                if line.strip().startswith("```") and not inside:
                    inside = True
                    continue
                elif line.strip().startswith("```") and inside:
                    break
                elif inside:
                    rule_lines.append(line)
            if rule_lines:
                return "\n".join(rule_lines).strip()

        # If no fenced block, try to find "rule ... { ... }"
        import re
        match = re.search(
            r"(rule\s+\w+[\s\S]*?\{[\s\S]*?\})",
            text,
        )
        if match:
            return match.group(1).strip()

        return text
