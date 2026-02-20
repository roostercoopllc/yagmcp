"""Anti-analysis detection tool.

Tools:
    detect_anti_analysis -- scan for anti-debug, anti-VM, and sandbox
        evasion techniques in imports, strings, and cross-references,
        with suggested bypass patches.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

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


# ---------------------------------------------------------------------- #
# Known anti-analysis imports
# ---------------------------------------------------------------------- #

_ANTI_DEBUG_IMPORTS: dict[str, str] = {
    "IsDebuggerPresent": "PEB.BeingDebugged check",
    "CheckRemoteDebuggerPresent": "Remote debugger check via NtQueryInformationProcess",
    "NtQueryInformationProcess": "ProcessDebugPort / ProcessDebugFlags query",
    "OutputDebugString": "SEH-based anti-debug (OutputDebugString + GetLastError)",
    "NtSetInformationThread": "ThreadHideFromDebugger to detach debugger",
    "DebugActiveProcess": "Self-debugging anti-debug technique",
    "CloseHandle": "CloseHandle with invalid handle + SEH anti-debug",
}

_TIMING_IMPORTS: dict[str, str] = {
    "GetTickCount": "Timing check to detect single-stepping",
    "GetTickCount64": "64-bit timing check",
    "QueryPerformanceCounter": "High-resolution timing anti-debug",
    "QueryPerformanceFrequency": "Used with QueryPerformanceCounter for timing",
    "timeGetTime": "Multimedia timer timing check",
}

_ANTI_VM_IMPORTS: dict[str, str] = {
    "NtQuerySystemInformation": "SystemFirmwareTableInformation for VM detection",
    "EnumSystemFirmwareTable": "SMBIOS/ACPI table enumeration for VM detection",
    "GetSystemFirmwareTable": "Direct firmware table read for VM detection",
}

_ANTI_SANDBOX_IMPORTS: dict[str, str] = {
    "GetCursorPos": "Mouse movement check (sandbox mice don't move)",
    "GetForegroundWindow": "Active window check (sandboxes may have no GUI)",
    "GetLastInputInfo": "User activity check (sandboxes have no input)",
    "GetSystemMetrics": "Screen resolution check (sandboxes use low res)",
    "GlobalMemoryStatusEx": "RAM size check (sandboxes allocate minimal RAM)",
    "GetDiskFreeSpaceEx": "Disk size check (sandbox disks are small)",
    "GetAdaptersInfo": "MAC address check for VM vendor prefixes",
    "EnumProcesses": "Process enumeration (looking for analysis tools)",
    "CreateToolhelp32Snapshot": "Process/module snapshot for analysis tool detection",
}

# VM vendor strings in binary
_VM_STRINGS = [
    "VMware", "vmware", "VBox", "vbox", "VBOX",
    "VirtualBox", "QEMU", "qemu", "Xen", "xen",
    "Hyper-V", "hyper-v", "Virtual", "virtual",
    "innotek", "BOCHS", "bochs", "Microsoft Hv",
    "VMW", "KVMKVMKVM",
]

# Sandbox artefact strings
_SANDBOX_STRINGS = [
    "sbiedll.dll", "SbieDll.dll",
    "cuckoomon", "cuckoo",
    "dbghelp.dll",
    "wireshark", "Wireshark",
    "procmon", "Procmon",
    "fiddler", "Fiddler",
    "idaq", "IDA",
    "ollydbg", "OllyDbg",
    "x64dbg", "x32dbg",
    "VBoxService", "VBoxTray",
    "vmtoolsd", "vmwaretray",
]

# Known analysis-tool process names
_ANALYSIS_PROCESS_NAMES = [
    "ollydbg.exe", "x64dbg.exe", "x32dbg.exe",
    "idaq.exe", "idaq64.exe", "ida.exe", "ida64.exe",
    "windbg.exe", "procmon.exe", "procexp.exe",
    "wireshark.exe", "fiddler.exe", "tcpdump",
    "processhacker.exe", "pestudio.exe",
    "regmon.exe", "filemon.exe",
]


# ---------------------------------------------------------------------- #
# detect_anti_analysis
# ---------------------------------------------------------------------- #


@register_tool
class DetectAntiAnalysis(BaseTool):
    name = "detect_anti_analysis"
    description = (
        "Detect anti-debug, anti-VM, and sandbox evasion techniques "
        "by scanning imports, strings, and cross-references. "
        "Returns findings with bypass suggestions."
    )
    category = ToolCategory.ANALYSIS

    async def execute(self, **kwargs: Any) -> Dict[str, Any]:
        err = self._require_params(kwargs, "repository", "program")
        if err:
            return err

        repository: str = kwargs["repository"]
        program_name: str = kwargs["program"]
        include_xrefs: bool = kwargs.get("include_xrefs", True)

        try:
            cache = _get_cache()
            program = cache.get_program(repository, program_name)
            bridge = cache.bridge

            techniques: list[dict] = []
            summary = {
                "anti_debug": 0,
                "anti_vm": 0,
                "anti_sandbox": 0,
                "timing_checks": 0,
            }

            # ---- Phase 1: Import scan ------------------------------------
            raw_imports = bridge.list_imports(program)
            import_names = {imp.get("name", ""): imp for imp in raw_imports}

            # Check anti-debug imports
            for imp_name, description in _ANTI_DEBUG_IMPORTS.items():
                if imp_name in import_names:
                    imp = import_names[imp_name]
                    technique = {
                        "category": "anti_debug",
                        "technique": f"{imp_name}: {description}",
                        "import_address": imp.get("address", ""),
                        "severity": "high",
                        "locations": [],
                        "bypass_suggestion": "",
                    }

                    if imp_name == "IsDebuggerPresent":
                        technique["bypass_suggestion"] = (
                            "Patch to return 0: replace function prologue with "
                            "'xor eax,eax; ret' (31 C0 C3) or NOP the conditional "
                            "jump after the call"
                        )
                    elif imp_name == "NtSetInformationThread":
                        technique["bypass_suggestion"] = (
                            "Patch the ThreadHideFromDebugger call to NOP, "
                            "or hook NtSetInformationThread to ignore class 0x11"
                        )
                    else:
                        technique["bypass_suggestion"] = (
                            f"NOP the call to {imp_name} or patch the "
                            "conditional branch that uses its return value"
                        )

                    # Get xrefs to find where it's called
                    if include_xrefs:
                        try:
                            addr = imp.get("address", "")
                            if addr:
                                xrefs = bridge.get_xrefs_to(program, addr)
                                for xref in xrefs[:5]:
                                    technique["locations"].append({
                                        "address": xref.get("from_addr", ""),
                                        "ref_type": xref.get("ref_type", ""),
                                    })
                        except Exception:
                            pass

                    techniques.append(technique)
                    summary["anti_debug"] += 1

            # Check timing imports
            for imp_name, description in _TIMING_IMPORTS.items():
                if imp_name in import_names:
                    imp = import_names[imp_name]
                    technique = {
                        "category": "timing_check",
                        "technique": f"{imp_name}: {description}",
                        "import_address": imp.get("address", ""),
                        "severity": "medium",
                        "locations": [],
                        "bypass_suggestion": (
                            f"Patch {imp_name} calls to return consistent values, "
                            "or NOP the delta-time comparison"
                        ),
                    }

                    if include_xrefs:
                        try:
                            addr = imp.get("address", "")
                            if addr:
                                xrefs = bridge.get_xrefs_to(program, addr)
                                for xref in xrefs[:5]:
                                    technique["locations"].append({
                                        "address": xref.get("from_addr", ""),
                                        "ref_type": xref.get("ref_type", ""),
                                    })
                        except Exception:
                            pass

                    techniques.append(technique)
                    summary["timing_checks"] += 1

            # Check anti-VM imports
            for imp_name, description in _ANTI_VM_IMPORTS.items():
                if imp_name in import_names:
                    imp = import_names[imp_name]
                    techniques.append({
                        "category": "anti_vm",
                        "technique": f"{imp_name}: {description}",
                        "import_address": imp.get("address", ""),
                        "severity": "medium",
                        "locations": [],
                        "bypass_suggestion": (
                            f"Hook {imp_name} to return sanitized data, "
                            "or patch the VM-detection branch"
                        ),
                    })
                    summary["anti_vm"] += 1

            # Check anti-sandbox imports
            for imp_name, description in _ANTI_SANDBOX_IMPORTS.items():
                if imp_name in import_names:
                    imp = import_names[imp_name]
                    techniques.append({
                        "category": "anti_sandbox",
                        "technique": f"{imp_name}: {description}",
                        "import_address": imp.get("address", ""),
                        "severity": "low",
                        "locations": [],
                        "bypass_suggestion": (
                            f"Hook {imp_name} to return realistic values "
                            "(high RAM, large disk, real resolution)"
                        ),
                    })
                    summary["anti_sandbox"] += 1

            # ---- Phase 2: String scan ------------------------------------
            raw_strings = bridge.list_strings(program)

            for s in raw_strings:
                val = s.get("value", "")

                # VM vendor strings
                for vm_str in _VM_STRINGS:
                    if vm_str in val:
                        techniques.append({
                            "category": "anti_vm",
                            "technique": f"VM vendor string: \"{val[:80]}\"",
                            "import_address": "",
                            "severity": "medium",
                            "locations": [{"address": s.get("address", ""), "ref_type": "string"}],
                            "bypass_suggestion": (
                                "Patch or zero out the VM detection string, "
                                "or NOP the comparison that references it"
                            ),
                        })
                        summary["anti_vm"] += 1
                        break

                # Sandbox artefact strings
                for sb_str in _SANDBOX_STRINGS:
                    if sb_str in val:
                        techniques.append({
                            "category": "anti_sandbox",
                            "technique": f"Sandbox/analysis artefact string: \"{val[:80]}\"",
                            "import_address": "",
                            "severity": "medium",
                            "locations": [{"address": s.get("address", ""), "ref_type": "string"}],
                            "bypass_suggestion": (
                                "Patch the string comparison or rename "
                                "analysis tools to avoid detection"
                            ),
                        })
                        summary["anti_sandbox"] += 1
                        break

                # Analysis tool process names
                val_lower = val.lower()
                for proc_name in _ANALYSIS_PROCESS_NAMES:
                    if proc_name in val_lower:
                        techniques.append({
                            "category": "anti_sandbox",
                            "technique": f"Analysis tool process name: \"{val[:80]}\"",
                            "import_address": "",
                            "severity": "medium",
                            "locations": [{"address": s.get("address", ""), "ref_type": "string"}],
                            "bypass_suggestion": (
                                "Rename analysis tools or patch the process "
                                "enumeration check"
                            ),
                        })
                        summary["anti_sandbox"] += 1
                        break

            return {
                "techniques": techniques,
                "summary": summary,
                "total_detections": len(techniques),
            }

        except FileNotFoundError:
            return self._error(
                f"Program '{program_name}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("detect_anti_analysis failed")
            return self._error(f"Anti-analysis detection failed: {exc}")
