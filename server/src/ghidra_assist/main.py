"""FastMCP server entry point for YAGMCP (Yet Another Ghidra MCP).

Creates and runs the MCP server with:
- Ghidra analysis tools exposed via the MCP protocol
- REST API endpoints for the Ghidra-Assist web UI and direct integration
- Ollama-powered chat agent for LLM-assisted reverse engineering
- CORS enabled for LAN use

Usage:
    python -m ghidra_assist.main
"""

from __future__ import annotations

import inspect
import json
import logging
from functools import wraps
from typing import Any

from fastmcp import FastMCP

from . import __version__
from .config import settings
from .project_cache import ProjectCache
from .tools import TOOL_REGISTRY, get_all_tools

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Lightweight instrument_tool (no external telemetry dependency)
# ---------------------------------------------------------------------------

def instrument_tool(tool_name: str):
    """Decorator that wraps a tool's execute method for logging/metrics.

    Uses ``@wraps`` so that ``inspect.signature()`` follows ``__wrapped__``
    and FastMCP sees the real typed parameter signature.
    """

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            logger.debug("Tool invoked: %s", tool_name)
            try:
                return await func(*args, **kwargs)
            except Exception:
                logger.exception("Tool %s failed", tool_name)
                raise

        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

# Module-level cache shared between MCP tools and REST handlers
_cache: ProjectCache | None = None


def get_cache() -> ProjectCache:
    """Return the shared ProjectCache singleton."""
    global _cache
    if _cache is None:
        _cache = ProjectCache()
    return _cache


def create_app() -> FastMCP:
    """Create and configure the FastMCP application.

    Returns:
        Configured FastMCP instance.
    """
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    logger.info("Starting YAGMCP server v%s", __version__)

    mcp = FastMCP(
        name="yagmcp",
        instructions=(
            "This MCP server exposes Ghidra reverse-engineering analysis and modification tools.\n\n"
            "Available capabilities:\n"
            "- List repositories and programs (list_repos, get_program_info)\n"
            "- List and search functions (list_functions, get_function)\n"
            "- Decompile functions to C (decompile)\n"
            "- Disassemble instructions (disassemble)\n"
            "- Cross-reference queries (xrefs_to, xrefs_from)\n"
            "- String listing (list_strings)\n"
            "- Import/export listing (list_imports, list_exports)\n"
            "- Memory map and raw byte reading (memory_map, read_bytes)\n"
            "- Data type listing (list_data_types)\n"
            "- Comment retrieval and creation (get_comments, set_comment)\n"
            "- Rename functions, variables, and labels (rename_function, rename_variable, rename_label)\n"
            "- Patch bytes in memory (patch_bytes)\n"
            "- LLM-assisted chat (chat_with_ollama)\n"
        ),
    )

    # ------------------------------------------------------------------
    # Register MCP tools
    # ------------------------------------------------------------------
    logger.info("Registering tools...")
    for tool_cls in get_all_tools():
        tool = tool_cls()

        # Apply instrumentation directly to the execute method.
        # @wraps inside instrument_tool sets __wrapped__ = tool.execute.
        # inspect.signature() follows __wrapped__ by default, so FastMCP
        # sees the real typed parameter signature rather than **kwargs.
        instrumented = instrument_tool(tool.name)(tool.execute)

        mcp.tool(
            name=tool.name,
            description=tool.description,
        )(instrumented)
        logger.info("  Registered tool: %s", tool.name)

    # ------------------------------------------------------------------
    # Register resources (from resources/ package, if any)
    # ------------------------------------------------------------------
    logger.info("Registering resources...")
    try:
        from .resources import get_all_resources  # type: ignore[import-untyped]

        for resource_cls in get_all_resources():
            resource = resource_cls()
            import re

            pattern = resource.uri_pattern
            path_params = re.findall(r"\{(\w+)\}", pattern)

            if not path_params:
                async def _static_getter(_r=resource, _p=pattern):
                    return await _r.get(_p)

                _static_getter.__name__ = f"resource_{resource.name}"
                _static_getter.__signature__ = inspect.Signature([])
                mcp.resource(pattern)(_static_getter)
            else:
                async def _template_getter(_r=resource, _p=pattern, **kwargs):
                    uri = _p
                    for k, v in kwargs.items():
                        uri = uri.replace(f"{{{k}}}", str(v))
                    return await _r.get(uri)

                _template_getter.__name__ = f"resource_{resource.name}"
                _template_getter.__annotations__ = {p: str for p in path_params}
                _template_getter.__signature__ = inspect.Signature(
                    [
                        inspect.Parameter(
                            p, inspect.Parameter.POSITIONAL_OR_KEYWORD, annotation=str
                        )
                        for p in path_params
                    ]
                )
                mcp.resource(pattern)(_template_getter)

            logger.info("  Registered resource: %s", resource.name)
    except (ImportError, AttributeError):
        logger.debug("No resources package found -- skipping resource registration")

    # ------------------------------------------------------------------
    # Register prompts (from prompts/ package, if any)
    # ------------------------------------------------------------------
    logger.info("Registering prompts...")
    try:
        from .prompts import get_all_prompts  # type: ignore[import-untyped]

        for prompt_cls in get_all_prompts():
            prompt = prompt_cls()

            async def _prompt_renderer(_p=prompt, **kwargs):
                result = await _p.render(**kwargs)
                return result.messages

            _prompt_renderer.__name__ = f"prompt_{prompt.name}"
            render_sig = inspect.signature(prompt.render)
            _prompt_renderer.__annotations__ = {
                name: (
                    param.annotation
                    if param.annotation is not inspect.Parameter.empty
                    else str
                )
                for name, param in render_sig.parameters.items()
            }
            _prompt_renderer.__signature__ = render_sig

            mcp.prompt(name=prompt.name, description=prompt.description)(
                _prompt_renderer
            )
            logger.info("  Registered prompt: %s", prompt.name)
    except (ImportError, AttributeError):
        logger.debug("No prompts package found -- skipping prompt registration")

    # ------------------------------------------------------------------
    # Health-check tool (always present)
    # ------------------------------------------------------------------
    @mcp.tool(name="health", description="Health check for the YAGMCP server")
    async def health_check() -> dict:
        cache = get_cache()
        return {
            "status": "ok",
            "version": __version__,
            "ghidra_ready": cache.bridge.is_ready,
        }

    logger.info("MCP server configured successfully")
    return mcp


# ---------------------------------------------------------------------------
# REST API layer (Starlette routes mounted on the FastMCP HTTP app)
# ---------------------------------------------------------------------------

def main() -> None:
    """Entry point: create FastMCP app, attach REST routes, run uvicorn."""
    import uvicorn
    from starlette.middleware.cors import CORSMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    mcp = create_app()
    app = mcp.http_app()

    cache = get_cache()

    # Instantiate tools once for REST reuse
    _tool_instances: dict[str, Any] = {}
    for tool_name, tool_cls in TOOL_REGISTRY.items():
        _tool_instances[tool_name] = tool_cls()

    # ---- REST handlers ------------------------------------------------

    async def rest_health(request: Request) -> JSONResponse:
        """GET /api/health"""
        return JSONResponse(
            {
                "status": "ok",
                "version": __version__,
                "ghidra_ready": cache.bridge.is_ready,
            }
        )

    async def rest_list_projects(request: Request) -> JSONResponse:
        """GET /api/projects -- list repositories."""
        try:
            repos = cache.list_repos()
            return JSONResponse({"repos": repos})
        except Exception as e:
            logger.exception("Failed to list repos")
            return JSONResponse({"error": str(e)}, status_code=500)

    async def rest_list_programs(request: Request) -> JSONResponse:
        """GET /api/projects/{repo} -- list programs in a repo."""
        repo = request.path_params["repo"]
        try:
            programs = cache.list_programs(repo)
            return JSONResponse({"repo": repo, "programs": programs})
        except FileNotFoundError:
            return JSONResponse({"error": f"Repository not found: {repo}"}, status_code=404)
        except Exception as e:
            logger.exception("Failed to list programs for %s", repo)
            return JSONResponse({"error": str(e)}, status_code=500)

    async def rest_tool_handler(request: Request) -> JSONResponse:
        """POST /api/tools/{tool_name} -- direct tool invocation."""
        tool_name = request.path_params["tool_name"]
        tool = _tool_instances.get(tool_name)
        if tool is None:
            return JSONResponse({"error": f"Unknown tool: {tool_name}"}, status_code=404)
        try:
            body = await request.json() if await request.body() else {}
            result = await tool.execute(**body)
            data = result.model_dump(mode="json") if hasattr(result, "model_dump") else result
            return JSONResponse(data)
        except TypeError as e:
            return JSONResponse({"error": f"Invalid arguments: {e}"}, status_code=422)
        except Exception as e:
            logger.exception("Tool %s failed", tool_name)
            return JSONResponse({"error": str(e)}, status_code=500)

    async def rest_chat(request: Request) -> JSONResponse:
        """POST /api/chat -- Ollama chat agent."""
        from .chat_agent import chat

        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

        message = body.get("message")
        if not message:
            return JSONResponse({"error": "\"message\" field is required"}, status_code=400)

        context = body.get("context", {})
        conversation_id = body.get("conversation_id")
        model = body.get("model")

        try:
            result = await chat(
                message=message,
                context=context,
                conversation_id=conversation_id,
                model=model,
            )
            return JSONResponse(result)
        except Exception as e:
            logger.exception("Chat agent error")
            return JSONResponse({"error": str(e)}, status_code=500)

    async def rest_openapi(request: Request) -> JSONResponse:
        """GET /openapi.json -- dynamically generated OpenAPI spec."""
        spec = _build_openapi_spec()
        return JSONResponse(spec)

    # ---- Mount routes -------------------------------------------------

    app.routes.extend(
        [
            Route("/api/health", rest_health, methods=["GET"]),
            Route("/api/projects", rest_list_projects, methods=["GET"]),
            Route("/api/projects/{repo}", rest_list_programs, methods=["GET"]),
            Route("/api/tools/{tool_name}", rest_tool_handler, methods=["POST"]),
            Route("/api/chat", rest_chat, methods=["POST"]),
            Route("/openapi.json", rest_openapi, methods=["GET"]),
        ]
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    logger.info("Starting server on 0.0.0.0:%d", settings.ghidra_assist_port)
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=settings.ghidra_assist_port,
        log_level=settings.log_level.lower(),
    )


# ---------------------------------------------------------------------------
# OpenAPI spec builder
# ---------------------------------------------------------------------------

def _build_openapi_spec() -> dict:
    """Generate a minimal OpenAPI 3.1 spec from the tool registry."""
    paths: dict[str, Any] = {
        "/api/health": {
            "get": {
                "summary": "Health check",
                "operationId": "health",
                "responses": {
                    "200": {
                        "description": "Server health status",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "status": {"type": "string"},
                                        "version": {"type": "string"},
                                        "ghidra_ready": {"type": "boolean"},
                                    },
                                }
                            }
                        },
                    }
                },
            }
        },
        "/api/projects": {
            "get": {
                "summary": "List repositories",
                "operationId": "list_projects",
                "responses": {
                    "200": {
                        "description": "List of repository names",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "repos": {
                                            "type": "array",
                                            "items": {"type": "string"},
                                        }
                                    },
                                }
                            }
                        },
                    }
                },
            }
        },
        "/api/projects/{repo}": {
            "get": {
                "summary": "List programs in a repository",
                "operationId": "list_programs",
                "parameters": [
                    {
                        "name": "repo",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Programs in the repository",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "repo": {"type": "string"},
                                        "programs": {
                                            "type": "array",
                                            "items": {"type": "object"},
                                        },
                                    },
                                }
                            }
                        },
                    }
                },
            }
        },
        "/api/chat": {
            "post": {
                "summary": "Chat with Ollama reverse-engineering assistant",
                "operationId": "chat",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["message"],
                                "properties": {
                                    "message": {
                                        "type": "string",
                                        "description": "User question or instruction",
                                    },
                                    "context": {
                                        "type": "object",
                                        "description": "Optional repo/program/function context",
                                    },
                                    "conversation_id": {
                                        "type": "string",
                                        "description": "ID for multi-turn threading",
                                    },
                                    "model": {
                                        "type": "string",
                                        "description": "Ollama model override",
                                    },
                                },
                            }
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Chat response",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "response": {"type": "string"},
                                        "tools_called": {
                                            "type": "array",
                                            "items": {"type": "string"},
                                        },
                                        "conversation_id": {"type": "string"},
                                        "turns_used": {"type": "integer"},
                                        "duration_ms": {"type": "number"},
                                    },
                                }
                            }
                        },
                    }
                },
            }
        },
    }

    # Add a POST path for each registered tool
    for name, tool_cls in TOOL_REGISTRY.items():
        tool = tool_cls()
        sig = inspect.signature(tool.execute)
        properties: dict[str, dict] = {}
        required: list[str] = []

        for pname, param in sig.parameters.items():
            if pname == "self":
                continue
            annotation = param.annotation
            json_type = "string"
            if annotation is int:
                json_type = "integer"
            elif annotation is float:
                json_type = "number"
            elif annotation is bool:
                json_type = "boolean"

            properties[pname] = {"type": json_type}
            if param.default is inspect.Parameter.empty:
                required.append(pname)

        paths[f"/api/tools/{name}"] = {
            "post": {
                "summary": tool.description,
                "operationId": f"tool_{name}",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": properties,
                                "required": required,
                            }
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Tool result",
                        "content": {
                            "application/json": {"schema": {"type": "object"}}
                        },
                    }
                },
            }
        }

    return {
        "openapi": "3.1.0",
        "info": {
            "title": "YAGMCP — Ghidra Assist",
            "version": __version__,
            "description": (
                "REST API for Ghidra reverse-engineering analysis and "
                "Ollama-powered chat assistant."
            ),
        },
        "servers": [
            {"url": f"http://localhost:{settings.ghidra_assist_port}"}
        ],
        "paths": paths,
    }


if __name__ == "__main__":
    main()
