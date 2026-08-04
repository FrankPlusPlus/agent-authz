"""Small adapters for popular Agent runtimes.

The adapters intentionally do not import LangGraph, LangChain, or Agno. They
wrap ordinary Python callables, which keeps the SDK lightweight and resilient
to framework version changes.
"""

from authz_sdk.integrations.agno import AgnoAuthz
from authz_sdk.integrations.common import CallInput, protect_tool, record_tool_inventory
from authz_sdk.integrations.fastapi import (
    FastAPIAuthz,
    FastAPIRouteInventory,
    discover_fastapi_routes,
    record_fastapi_inventory,
)
from authz_sdk.integrations.langgraph import LangGraphAuthz
from authz_sdk.integrations.mcp import MCPAuthz

__all__ = [
    "AgnoAuthz",
    "CallInput",
    "FastAPIAuthz",
    "FastAPIRouteInventory",
    "LangGraphAuthz",
    "MCPAuthz",
    "discover_fastapi_routes",
    "protect_tool",
    "record_tool_inventory",
    "record_fastapi_inventory",
]
