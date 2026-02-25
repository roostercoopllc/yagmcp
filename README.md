# YAGMCP — Yet Another Ghidra MCP

LLM-assisted reverse engineering with headless Ghidra analysis, MCP protocol, and an embedded chat panel.

Open a binary in Ghidra, click on a function, and ask "Does this function look right?" — the system knows what you're looking at and can decompile, trace cross-references, and search through the program autonomously.

## Architecture

```
  ANALYST'S DESKTOP                          SERVER
  +-----------------------+    HTTP    +---------------------------+
  | Ghidra 12.0.3         |---------->| yagmcp-server (:8889)     |
  |  + YAGMCP Chat Panel  |           |  FastMCP 2.0 + pyghidra   |
  |  + Context Tracker    |           |  20 MCP analysis tools     |
  +-----------------------+           |  Chat Agent --> Ollama     |
                                      +---------------------------+
  Claude Desktop ---MCP--->                    |
  Open WebUI -----REST--->            ghidra-server (:13100)
                                       shared repos (NAS)
```

**Server** reads Ghidra repos via shared volume (read-only), runs headless analysis via pyghidra (JDK 21 + Ghidra 12.0.3), exposes 20 MCP tools, and routes chat to Ollama.

**Plugin** tracks your cursor (function, address, selection) and sends context with each chat message. No analysis logic client-side.

## Three Ways to Use

| Interface | Protocol | Best For |
|-----------|----------|----------|
| **Ghidra Chat Panel** | REST | Primary workflow — context-aware chat |
| **Claude Desktop** | MCP | Advanced agentic analysis |
| **Open WebUI** | REST/OpenAPI | Web-based team access |

## Quick Start

### 1. Build and Deploy Server

```bash
# Build Docker image (~2-3 GB, includes JDK + Ghidra)
./scripts/build-server.sh

# Deploy (with home-automation integration)
cp deploy/.env.template /opt/home-automation/docker/ghidra-assist/.env
# Edit .env: set OLLAMA_URL and OLLAMA_MODEL
homectl ghidra-assist deploy
```

### 2. Build and Install Plugin

```bash
# Build (requires Ghidra 12.0.3 + JDK 21)
./scripts/build-plugin.sh /path/to/ghidra_12.0.3

# Install
./scripts/install-plugin.sh /path/to/ghidra_12.0.3
# Restart Ghidra, enable via File > Configure > GhidraAssistPlugin
```

### 3. Chat

Open a program in Ghidra. The YAGMCP panel appears on the right. Click on a function, type your question, press Enter.

## MCP Tools (20)

| Category | Tools |
|----------|-------|
| **Programs** | `list_repositories`, `list_programs`, `get_program_info` |
| **Functions** | `list_functions`, `decompile_function`, `get_function_signature`, `get_disassembly`, `search_functions` |
| **Cross-Refs** | `get_xrefs_to`, `get_xrefs_from`, `get_call_graph` |
| **Data** | `list_strings`, `list_imports`, `list_exports` |
| **Memory** | `list_data_types`, `get_memory_map`, `read_bytes` |
| **Comments** | `get_comments`, `search_comments` |
| **Agent** | `ghidra_chat` |

## API Endpoints

```
POST /api/chat                  # Chat with context (plugin endpoint)
POST /api/tools/{tool_name}     # Direct tool invocation
GET  /api/projects              # List repositories
GET  /api/projects/{repo}       # List programs
GET  /api/health                # Health check
GET  /openapi.json              # OpenAPI spec (Open WebUI)
GET  /mcp | POST /mcp           # MCP Streamable HTTP (Claude Desktop)
```

## Configuration

### Server (.env)

```bash
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5-coder:7b
REPOS_DIR=/repos
MAX_CACHED_PROGRAMS=5
GHIDRA_ASSIST_PORT=8889
```

### Plugin (Edit > Tool Options > YAGMCP)

- Server URL: `http://localhost:8889`
- Model: `qwen2.5-coder:7b`
- Context mode: function / selection / both / none
- Auto-include context: on/off

## Project Structure

```
yagmcp/
  server/                    # Python FastMCP + pyghidra
    src/ghidra_assist/
      main.py                # FastMCP app
      ghidra_bridge.py       # pyghidra JVM wrapper
      project_cache.py       # LRU program cache
      chat_agent.py          # Ollama agent loop
      tools/                 # 20 MCP tools (7 modules)
      prompts/               # MCP prompt templates
      resources/             # MCP resources
    Dockerfile
    pyproject.toml
  plugin/                    # Java Ghidra extension
    src/main/java/ghidraassist/
      GhidraAssistPlugin.java
      ui/ChatPanel.java
      ...
    build.gradle
  deploy/                    # Docker Compose configs
  openwebui/                 # Open WebUI tool function
  scripts/                   # Build and helper scripts
```

## Requirements

| Component | Version |
|-----------|---------|
| Ghidra | 12.0.3 (server and client must match) |
| JDK | 21 (Eclipse Temurin) |
| Python | 3.12+ |
| Docker | 20.10+ |
| Ollama | Any version with tool-calling support |

## Documentation

Full documentation: [Wiki](https://github.com/roostercoopllc/yagmcp/wiki)

- [Server Setup](https://github.com/roostercoopllc/yagmcp/wiki/Server-Setup)
- [Plugin Installation](https://github.com/roostercoopllc/yagmcp/wiki/Plugin-Installation)
- [API Reference](https://github.com/roostercoopllc/yagmcp/wiki/API-Reference)
- [Chat Interface Guide](https://github.com/roostercoopllc/yagmcp/wiki/Chat-Interface-Guide)
- [Troubleshooting](https://github.com/roostercoopllc/yagmcp/wiki/Troubleshooting)
- [Architecture Deep Dive](https://github.com/roostercoopllc/yagmcp/wiki/Architecture-Deep-Dive)

## License

MIT
