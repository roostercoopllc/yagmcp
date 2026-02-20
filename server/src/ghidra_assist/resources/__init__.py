"""Resource registry for YAGMCP.

MCP resources expose read-only data at well-known URIs.  Each resource
module exposes a ``RESOURCE`` instance implementing the ``BaseResource``
protocol.

After all resource modules are imported the ``RESOURCE_REGISTRY`` dict
maps resource URI template -> instance.
"""

from __future__ import annotations

import importlib
import logging
from typing import Any, Dict, Protocol

logger = logging.getLogger(__name__)


class BaseResource(Protocol):
    """Minimal interface every resource must satisfy."""

    uri_template: str
    name: str
    description: str

    async def read(self, **kwargs: Any) -> Dict[str, Any]:
        """Return the resource data as a JSON-serialisable dict."""
        ...


RESOURCE_REGISTRY: Dict[str, BaseResource] = {}

_RESOURCE_MODULES = [
    "ghidra_assist.resources.program_info",
]


def register_resource(resource: BaseResource) -> BaseResource:
    """Add *resource* to the global registry.

    Raises ``ValueError`` on duplicate URI templates so mis-configuration
    is caught at import time.
    """
    uri = resource.uri_template
    if uri in RESOURCE_REGISTRY:
        raise ValueError(
            f"Duplicate resource URI '{uri}': "
            f"{RESOURCE_REGISTRY[uri]!r} and {resource!r}"
        )
    RESOURCE_REGISTRY[uri] = resource
    logger.debug("Registered resource: %s -> %s", uri, resource.name)
    return resource


def discover_resources() -> Dict[str, BaseResource]:
    """Import every resource module so registrations fire.

    Returns the populated ``RESOURCE_REGISTRY``.  Safe to call multiple times.
    """
    for mod in _RESOURCE_MODULES:
        try:
            importlib.import_module(mod)
        except Exception:
            logger.exception("Failed to import resource module %s", mod)
    return RESOURCE_REGISTRY
