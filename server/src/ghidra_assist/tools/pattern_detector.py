"""Pattern matching and detection database tool.

Tools:
    detect_code_patterns -- scan binary for known code patterns:
        - Crypto (AES, RC4, DES, SHA, MD5)
        - Compression (zlib, LZMA, RLE)
        - Encoding (Base64, XOR, Caesar)
        - PE operations (PE parsing, IAT walking)
        - File I/O and Network operations
"""

from __future__ import annotations

from typing import Any, Dict, List
import re

from ghidra_assist.project_cache import ProjectCache
from ghidra_assist.tools import register_tool
from ghidra_assist.tools.base import BaseTool, ToolCategory

_cache: ProjectCache | None = None


def _get_cache() -> ProjectCache:
    global _cache
    if _cache is None:
        _cache = ProjectCache()
    return _cache


# Pattern database: recognized code patterns with signatures
_PATTERN_DATABASE = {
    "RC4_KSA": {
        "name": "RC4 Key Scheduling Algorithm",
        "category": "crypto",
        "confidence": 0.95,
        "signatures": [
            "for.*256",  # KSA typically loops 256 times
            "S\\[.*\\].*S\\[.*\\]",  # KSA swaps S[i] and S[j]
        ],
        "keywords": ["rc4", "ksa", "256", "swap"],
        "library": "OpenSSL RC4 / mbedTLS",
    },
    "AES_SBOX": {
        "name": "AES S-Box Initialization",
        "category": "crypto",
        "confidence": 0.92,
        "signatures": [
            "0x63.*0x7c.*0x77.*0x7b",  # AES S-box first bytes
        ],
        "keywords": ["aes", "sbox", "rijndael"],
        "library": "OpenSSL AES / mbedTLS / libgcrypt",
    },
    "SHA1_INIT": {
        "name": "SHA-1 Initialization",
        "category": "crypto",
        "confidence": 0.88,
        "signatures": [
            "0x67452301",  # SHA-1 initial A value
        ],
        "keywords": ["sha1", "sha", "hash"],
        "library": "OpenSSL SHA / mbedTLS",
    },
    "MD5_INIT": {
        "name": "MD5 Initialization",
        "category": "crypto",
        "confidence": 0.85,
        "signatures": [
            "0x67452301.*0xefcdab89",  # MD5 initial state
        ],
        "keywords": ["md5", "hash"],
        "library": "OpenSSL MD5 / libgcrypt",
    },
    "BASE64_TABLE": {
        "name": "Base64 Encoding Table",
        "category": "encoding",
        "confidence": 0.90,
        "signatures": [
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        ],
        "keywords": ["base64", "encoding"],
        "library": "Custom or standard base64",
    },
    "ZLIB_MAGIC": {
        "name": "zlib Decompression",
        "category": "compression",
        "confidence": 0.88,
        "signatures": [
            "0x78.*0x9c",  # zlib header (78 9c = default compression)
            "inflate",
            "uncompress",
        ],
        "keywords": ["zlib", "deflate", "uncompress"],
        "library": "zlib / libz",
    },
    "PE_HEADER": {
        "name": "PE File Parsing",
        "category": "pe_operations",
        "confidence": 0.92,
        "signatures": [
            "0x5a4d",  # PE magic "MZ"
            "GetProcAddress",
            "LoadLibrary",
        ],
        "keywords": ["pe", "portable executable", "image base"],
        "library": "Windows PE loader",
    },
    "XOR_CIPHER": {
        "name": "XOR Cipher Loop",
        "category": "encoding",
        "confidence": 0.75,
        "signatures": [
            "for.*xor",
            "\\^=",  # XOR assignment in decompiled code
        ],
        "keywords": ["xor", "cipher", "encrypt"],
        "library": "Custom XOR encryption",
    },
    "SOCKET_INIT": {
        "name": "Socket Network Operations",
        "category": "network",
        "confidence": 0.90,
        "signatures": [
            "socket",
            "connect",
            "WSAStartup",
            "inet_addr",
        ],
        "keywords": ["socket", "network", "connect", "bind"],
        "library": "Winsock / BSD Sockets",
    },
    "HTTP_REQUEST": {
        "name": "HTTP Request Construction",
        "category": "network",
        "confidence": 0.88,
        "signatures": [
            "GET|POST|PUT|DELETE|HEAD|OPTIONS",
            "User-Agent",
            "Content-Length",
            "Host:",
        ],
        "keywords": ["http", "request", "user-agent"],
        "library": "Custom or libcurl / WinHTTP",
    },
}


@register_tool
class DetectCodePatterns(BaseTool):
    name = "detect_code_patterns"
    description = (
        "Scan a binary for recognized code patterns: crypto algorithms, compression, "
        "encoding schemes, PE operations, file I/O, and network functionality. "
        "Returns matched patterns with confidence levels and suggested libraries."
    )
    category = ToolCategory.ANALYSIS

    async def execute(
        self,
        repository: str,
        program: str,
        pattern_category: str = "all",
        min_confidence: float = 0.80,
    ) -> Dict[str, Any]:
        """
        Detect code patterns in a binary.

        Args:
            repository: Repository name
            program: Program name
            pattern_category: Filter by category: "all", "crypto", "encoding",
                            "compression", "network", "pe_operations"
            min_confidence: Minimum confidence threshold (0.0-1.0)

        Returns:
            Dict with:
            - patterns_found: Number of patterns detected
            - matches: List of matched patterns with details
            - category_summary: Count by category
            - iocs_extracted: Potential indicators of compromise found
        """
        try:
            cache = _get_cache()
            prog = cache.get_program(repository, program)
            bridge = cache.bridge

            matches = []
            iocs = []

            # Get strings and disassembly for pattern matching
            strings = bridge.list_strings(prog)
            imports = bridge.list_imports(prog)

            # String-based pattern detection
            for pattern_id, pattern_info in _PATTERN_DATABASE.items():
                if (
                    pattern_category != "all"
                    and pattern_info.get("category") != pattern_category
                ):
                    continue

                if pattern_info.get("confidence", 0.0) < min_confidence:
                    continue

                # Check strings for pattern signatures
                for signature in pattern_info.get("signatures", []):
                    for string_obj in strings:
                        str_value = string_obj.get("value", "")
                        if self._matches_signature(str_value, signature):
                            match = {
                                "pattern_id": pattern_id,
                                "pattern_name": pattern_info.get("name"),
                                "category": pattern_info.get("category"),
                                "confidence": pattern_info.get("confidence"),
                                "library": pattern_info.get("library"),
                                "location": string_obj.get("address"),
                                "evidence": str_value[:100],
                            }
                            matches.append(match)

                            # Extract IOCs
                            if pattern_info.get("category") == "network":
                                iocs.append({
                                    "type": "network_string",
                                    "value": str_value,
                                    "pattern": pattern_id,
                                })

            # Import-based pattern detection
            for pattern_id, pattern_info in _PATTERN_DATABASE.items():
                if (
                    pattern_category != "all"
                    and pattern_info.get("category") != pattern_category
                ):
                    continue

                for imp in imports:
                    imp_name = imp.get("name", "")
                    for keyword in pattern_info.get("keywords", []):
                        if keyword.lower() in imp_name.lower():
                            if not any(
                                m.get("pattern_id") == pattern_id
                                for m in matches
                            ):
                                match = {
                                    "pattern_id": pattern_id,
                                    "pattern_name": pattern_info.get("name"),
                                    "category": pattern_info.get("category"),
                                    "confidence": pattern_info.get("confidence")
                                    * 0.8,  # Lower confidence for import matches
                                    "library": pattern_info.get("library"),
                                    "location": "import",
                                    "evidence": f"Import: {imp_name}",
                                }
                                matches.append(match)

            # Remove duplicates and sort by confidence
            seen = set()
            unique_matches = []
            for m in sorted(
                matches, key=lambda x: x.get("confidence", 0), reverse=True
            ):
                key = (m.get("pattern_id"), m.get("location"))
                if key not in seen:
                    seen.add(key)
                    unique_matches.append(m)

            # Category summary
            category_summary = {}
            for match in unique_matches:
                cat = match.get("category", "unknown")
                category_summary[cat] = category_summary.get(cat, 0) + 1

            return {
                "success": True,
                "patterns_found": len(unique_matches),
                "matches": unique_matches,
                "category_summary": category_summary,
                "iocs_extracted": iocs,
                "total_iocs": len(iocs),
                "analysis_note": (
                    f"Found {len(unique_matches)} pattern(s) "
                    f"in {len(category_summary)} categor(ies). "
                    "Patterns marked as 'import' have lower confidence. "
                    "Verify high-confidence matches in decompiler."
                ),
            }

        except FileNotFoundError:
            return self._error(
                f"Program '{program}' not found in repository '{repository}'"
            )
        except Exception as exc:
            self.logger.exception("detect_code_patterns failed")
            return self._error(f"Pattern detection failed: {exc}")

    @staticmethod
    def _matches_signature(text: str, signature: str) -> bool:
        """Check if text matches a signature (literal string or hex pattern)."""
        try:
            # Try as regex
            return bool(re.search(signature, text, re.IGNORECASE))
        except re.error:
            # Fall back to literal string match
            return signature.lower() in text.lower()
