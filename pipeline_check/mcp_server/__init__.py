"""MCP (Model Context Protocol) server for pipeline-check.

Wraps the existing scanner and rule / chain / standards registries
as a locally-running MCP server an AI agent can introspect. The
package layout splits the *tool functions* (pure, return dicts,
unit-testable without an MCP loop) from the *server harness* that
binds them to MCP types and runs an asyncio event loop.

The package's public API is exactly the two entrypoints below;
everything else under ``pipeline_check.mcp_server.*`` is internal.
"""
from __future__ import annotations

from .server import run_stdio, server_app

__all__ = ["run_stdio", "server_app"]
