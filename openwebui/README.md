# YAGMCP Open WebUI Tool

This directory contains a custom Tool function for [Open WebUI](https://github.com/open-webui/open-webui) that connects to the YAGMCP server, allowing any chat model to call Ghidra reverse-engineering functions.

## Prerequisites

- A running YAGMCP server (see `deploy/` for Docker setup)
- Open WebUI instance with Tool support enabled

## Installation

1. Open your Open WebUI instance in a browser.
2. Navigate to **Workspace > Tools**.
3. Click the **"+"** button to create a new tool.
4. Paste the entire contents of `yagmcp_tool.py` into the editor.
5. Save the tool.

## Configuration

After creating the tool, configure the **Valves** (settings):

| Valve | Default | Description |
|---|---|---|
| `yagmcp_url` | `http://localhost:8889` | Base URL of your YAGMCP server |
| `request_timeout` | `120` | HTTP timeout in seconds (increase for large binaries) |

Update `yagmcp_url` to match your server's address. If running Open WebUI and YAGMCP on the same Docker network, use the container name (e.g., `http://yagmcp-server:8889`).

## Available Tools

| Tool | Description |
|---|---|
| **Program Management** | |
| `list_repositories` | List all Ghidra repositories on the server |
| `list_programs` | List all programs in a repository |
| **Function Analysis** | |
| `decompile_function` | Decompile a function and return pseudo-C source |
| `list_functions` | List functions in a program (with optional name filter) |
| `analyze_function` | Decompile + LLM analysis with a custom prompt |
| `get_disassembly` | Get assembly/disassembly at a given address |
| **Cross-Reference Analysis** | |
| `get_xrefs_to` | Get all cross-references pointing to an address |
| `get_xrefs_from` | Get all cross-references originating from an address |
| `get_call_graph` | Get the call graph (callers/callees) of a function |
| **Malware Analysis** | |
| `triage_binary` | Perform automated binary triage with key findings |
| `extract_iocs` | Extract IOCs (IPs, domains, hashes, etc.) from a binary |
| `detect_anti_analysis` | Detect anti-debug, anti-VM, packers, and other anti-analysis techniques |
| `generate_yara` | Generate YARA rules for a function's signature |

## Usage

Once the tool is installed and enabled on a model:

1. Open a chat with the model.
2. Ask questions like:
   - "List the repositories available on the Ghidra server."
   - "Show me the functions in the `firmware.bin` program in the `IoT` repository."
   - "Decompile the `main` function from `firmware.bin` in the `IoT` repository."
   - "Analyze the `handle_auth` function — is there a buffer overflow?"

The model will automatically invoke the appropriate tool and incorporate the Ghidra output into its response.

## Troubleshooting

- **Connection refused**: Verify the YAGMCP server is running and reachable from the Open WebUI container.
- **Timeout errors**: Increase `request_timeout` in the Valves, especially for large binaries that take time to analyze.
- **Tool not appearing**: Make sure the tool is enabled for the model you are chatting with (Model Settings > Tools).
