"""IOC extraction tool.

Tools:
    extract_iocs -- scan binary strings for indicators of compromise:
        IPv4/IPv6 addresses, URLs, domains, email addresses,
        registry keys, file paths, and mutex names.
"""

from __future__ import annotations

import re
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
# IOC regex patterns
# ---------------------------------------------------------------------- #

_IOC_PATTERNS: dict[str, re.Pattern] = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "ipv6": re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
        r"|"
        r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
        r"|"
        r"\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b"
    ),
    "url": re.compile(
        r"https?://[^\s\"'<>]{4,256}"
    ),
    "domain": re.compile(
        r"\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
        r"\.(?:com|net|org|info|biz|ru|cn|xyz|top|tk|ml|ga|cf|gq|"
        r"io|co|me|pw|cc|ws|su|onion|bit)\b",
        re.IGNORECASE,
    ),
    "email": re.compile(
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
    ),
    "registry_key": re.compile(
        r"(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|"
        r"HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)"
        r"\\[^\s\"']{2,256}",
        re.IGNORECASE,
    ),
    "file_path_windows": re.compile(
        r"[A-Za-z]:\\(?:[^\s\"'<>|:*?\\]+\\)*[^\s\"'<>|:*?\\]+",
    ),
    "file_path_unix": re.compile(
        r"(?:/(?:tmp|var|usr|etc|opt|home|root|bin|sbin|dev|proc)"
        r"/[^\s\"']{2,256})",
    ),
}

# Common false-positive IPs to filter
_FP_IPS = {
    "0.0.0.0", "127.0.0.1", "255.255.255.255",
    "255.255.255.0", "0.0.0.1",
}

# Common false-positive domains
_FP_DOMAINS = {
    "example.com", "example.net", "example.org",
    "localhost.com",
}


# ---------------------------------------------------------------------- #
# extract_iocs
# ---------------------------------------------------------------------- #


@register_tool
class ExtractIOCs(BaseTool):
    name = "extract_iocs"
    description = (
        "Extract indicators of compromise (IOCs) from binary strings: "
        "IPs, URLs, domains, emails, registry keys, file paths."
    )
    category = ToolCategory.ANALYSIS

    async def execute(self, **kwargs: Any) -> Dict[str, Any]:
        err = self._require_params(kwargs, "repository", "program")
        if err:
            return err

        repository: str = kwargs["repository"]
        program_name: str = kwargs["program"]
        min_length: int = int(kwargs.get("min_length", 4))

        try:
            cache = _get_cache()
            program = cache.get_program(repository, program_name)
            bridge = cache.bridge

            raw_strings = bridge.list_strings(program)
            filtered = [
                s for s in raw_strings if s.get("length", 0) >= min_length
            ]

            iocs: dict[str, list[dict]] = {
                "ipv4": [],
                "ipv6": [],
                "urls": [],
                "domains": [],
                "emails": [],
                "registry_keys": [],
                "file_paths": [],
            }

            seen: dict[str, set] = {k: set() for k in iocs}

            for s in filtered:
                value = s.get("value", "")
                address = s.get("address", "")

                for ioc_type, pattern in _IOC_PATTERNS.items():
                    for match in pattern.finditer(value):
                        matched = match.group(0)

                        # Map to output category
                        if ioc_type in ("file_path_windows", "file_path_unix"):
                            out_key = "file_paths"
                        elif ioc_type == "url":
                            out_key = "urls"
                        elif ioc_type == "domain":
                            out_key = "domains"
                        elif ioc_type == "email":
                            out_key = "emails"
                        elif ioc_type == "registry_key":
                            out_key = "registry_keys"
                        else:
                            out_key = ioc_type

                        # Filter false positives
                        if out_key == "ipv4" and matched in _FP_IPS:
                            continue
                        if out_key == "domains" and matched.lower() in _FP_DOMAINS:
                            continue

                        if matched not in seen[out_key]:
                            seen[out_key].add(matched)
                            iocs[out_key].append({
                                "value": matched,
                                "address": address,
                                "context": f"in string at {address}",
                            })

            total = sum(len(v) for v in iocs.values())

            return {
                "iocs": iocs,
                "total_count": total,
                "strings_scanned": len(filtered),
                "source": "strings",
            }

        except FileNotFoundError:
            return self._error(
                f"Program '{program_name}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("extract_iocs failed")
            return self._error(f"IOC extraction failed: {exc}")
