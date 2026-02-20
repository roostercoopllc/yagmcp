"""Binary triage tool.

Tools:
    triage_binary -- automated first-contact analysis of a binary:
        architecture, packing detection, section entropy, suspicious
        imports/strings, and triage notes.
"""

from __future__ import annotations

from typing import Any, Dict

from ghidra_assist.project_cache import ProjectCache
from ghidra_assist.tools import register_tool
from ghidra_assist.tools.base import BaseTool, ToolCategory

_cache: ProjectCache | None = None


def _get_cache() -> ProjectCache:
    global _cache
    if _cache is None:
        _cache = ProjectCache()
    return _cache


# ---------------------------------------------------------------------- #
# Suspicious-import categories
# ---------------------------------------------------------------------- #

_SUSPICIOUS_IMPORTS: dict[str, list[str]] = {
    "process_injection": [
        "VirtualAllocEx", "VirtualAlloc", "WriteProcessMemory",
        "CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC",
        "NtMapViewOfSection", "RtlCreateUserThread",
    ],
    "evasion": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "OutputDebugString",
        "GetTickCount", "QueryPerformanceCounter",
        "NtQuerySystemInformation", "NtSetInformationThread",
    ],
    "persistence": [
        "RegSetValueEx", "RegSetValueExA", "RegSetValueExW",
        "CreateService", "CreateServiceA", "CreateServiceW",
    ],
    "network": [
        "InternetOpen", "InternetOpenA", "InternetOpenW",
        "InternetOpenUrl", "InternetOpenUrlA", "InternetOpenUrlW",
        "HttpSendRequest", "HttpSendRequestA", "HttpSendRequestW",
        "WSAStartup", "connect", "send", "recv", "socket",
        "URLDownloadToFile", "URLDownloadToFileA", "URLDownloadToFileW",
        "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
    ],
    "crypto": [
        "CryptEncrypt", "CryptDecrypt", "CryptHashData",
        "CryptCreateHash", "CryptDeriveKey",
        "BCryptEncrypt", "BCryptDecrypt",
    ],
    "process_creation": [
        "CreateProcess", "CreateProcessA", "CreateProcessW",
        "ShellExecute", "ShellExecuteA", "ShellExecuteW",
        "WinExec", "system",
    ],
    "file_operations": [
        "CreateFile", "CreateFileA", "CreateFileW",
        "WriteFile", "DeleteFile", "DeleteFileA", "DeleteFileW",
        "MoveFile", "MoveFileA", "MoveFileW",
        "CopyFile", "CopyFileA", "CopyFileW",
    ],
}

# Flatten for quick lookup: import_name -> category
_IMPORT_LOOKUP: dict[str, str] = {}
for _cat, _names in _SUSPICIOUS_IMPORTS.items():
    for _name in _names:
        _IMPORT_LOOKUP[_name] = _cat

# Strings that suggest packing or suspicious behaviour
_SUSPICIOUS_STRING_PATTERNS = [
    "cmd.exe", "powershell", "cmd /c", "cmd.exe /c",
    "/bin/sh", "/bin/bash",
    "HKLM\\", "HKCU\\", "HKEY_",
    "Mozilla/", "User-Agent:",
    "password", "passwd",
    "rundll32", "regsvr32",
    "schtasks", "sc create",
]

_PACKER_SECTION_NAMES = {
    "UPX0", "UPX1", "UPX2", ".aspack", ".adata",
    ".nsp0", ".nsp1", ".nsp2",
    ".packed", ".Themida", ".vmp0", ".vmp1",
}

# Entropy threshold for packing detection
_HIGH_ENTROPY_THRESHOLD = 7.0


# ---------------------------------------------------------------------- #
# triage_binary
# ---------------------------------------------------------------------- #


@register_tool
class TriageBinary(BaseTool):
    name = "triage_binary"
    description = (
        "Automated first-contact triage of a binary: architecture, packing "
        "detection, section entropy, suspicious imports and strings, and triage notes."
    )
    category = ToolCategory.ANALYSIS

    async def execute(self, **kwargs: Any) -> Dict[str, Any]:
        err = self._require_params(kwargs, "repository", "program")
        if err:
            return err

        repository: str = kwargs["repository"]
        program_name: str = kwargs["program"]

        try:
            cache = _get_cache()
            program = cache.get_program(repository, program_name)
            bridge = cache.bridge

            # ---- Program metadata ----------------------------------------
            lang = program.getLanguage()
            compiler_spec = program.getCompilerSpec()

            architecture = lang.getLanguageDescription().getProcessor().toString()
            address_size = lang.getLanguageDescription().getSize()
            compiler_name = compiler_spec.getCompilerSpecDescription().getCompilerSpecName()
            exec_format = program.getExecutableFormat() or ""
            image_base = program.getImageBase().toString()

            func_count = program.getFunctionManager().getFunctionCount()
            sym_count = program.getSymbolTable().getNumSymbols()

            # ---- Section entropy -----------------------------------------
            sections = bridge.get_section_entropy(program)

            # ---- Packing detection ---------------------------------------
            triage_notes: list[str] = []
            high_entropy_sections = [
                s for s in sections
                if s["initialized"] and s["entropy"] >= _HIGH_ENTROPY_THRESHOLD
            ]

            packer_sections = [
                s["name"] for s in sections
                if s["name"] in _PACKER_SECTION_NAMES
            ]

            likely_packed = bool(high_entropy_sections) or bool(packer_sections)
            packing_reasons: list[str] = []
            if high_entropy_sections:
                names = ", ".join(
                    f"{s['name']} ({s['entropy']:.1f})"
                    for s in high_entropy_sections
                )
                packing_reasons.append(f"High entropy in: {names}")
            if packer_sections:
                packing_reasons.append(
                    f"Packer section names detected: {', '.join(packer_sections)}"
                )

            if likely_packed:
                triage_notes.append("Binary appears packed or encrypted")

            # ---- Imports -------------------------------------------------
            raw_imports = bridge.list_imports(program)
            import_count = len(raw_imports)
            suspicious_imports: list[dict] = []

            for imp in raw_imports:
                imp_name = imp.get("name", "")
                if imp_name in _IMPORT_LOOKUP:
                    suspicious_imports.append({
                        "name": imp_name,
                        "category": _IMPORT_LOOKUP[imp_name],
                        "address": imp.get("address", ""),
                    })

            if not raw_imports and func_count > 10:
                triage_notes.append(
                    "No imports found — possible static linking or import obfuscation"
                )

            # ---- Strings -------------------------------------------------
            raw_strings = bridge.list_strings(program)
            string_count = len(raw_strings)
            suspicious_strings: list[dict] = []

            for s in raw_strings:
                val = s.get("value", "")
                val_lower = val.lower()
                for pattern in _SUSPICIOUS_STRING_PATTERNS:
                    if pattern.lower() in val_lower:
                        suspicious_strings.append({
                            "value": val,
                            "address": s.get("address", ""),
                            "matched_pattern": pattern,
                        })
                        break  # one match per string is enough

            # ---- Entry point bytes ---------------------------------------
            entry_info = bridge.get_entry_point_bytes(program, 32)

            return {
                "architecture": architecture,
                "address_size": address_size,
                "compiler": compiler_name,
                "executable_format": exec_format,
                "image_base": image_base,
                "entry_point": entry_info.get("address", ""),
                "entry_bytes": entry_info.get("hex", ""),
                "packing": {
                    "likely_packed": likely_packed,
                    "reasons": packing_reasons,
                },
                "sections": sections,
                "function_count": func_count,
                "symbol_count": sym_count,
                "import_count": import_count,
                "string_count": string_count,
                "suspicious_imports": suspicious_imports,
                "suspicious_strings": suspicious_strings[:50],
                "triage_notes": triage_notes,
            }

        except FileNotFoundError:
            return self._error(
                f"Program '{program_name}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("triage_binary failed")
            return self._error(f"Triage failed: {exc}")
