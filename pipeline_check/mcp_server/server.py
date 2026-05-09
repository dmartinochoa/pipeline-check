"""MCP server harness.

Binds the pure tool functions in ``tools.py`` to the MCP protocol's
typed handler shape and runs an asyncio event loop on stdio. The
harness is deliberately thin: every piece of business logic lives
in ``tools.py`` so the unit tests don't touch async code.

Why stdio? It's the transport every MCP-aware desktop client
(Claude Desktop, Claude Code, Cursor, Continue, Zed) speaks
natively. HTTP+SSE support can come later as a second entry
point without changing any tool signatures.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

from .. import __version__
from . import tools as _tools


def _build_server() -> Any:
    """Construct the MCP ``Server`` instance and register handlers.

    Imported lazily inside the function so a bare ``import
    pipeline_check.mcp_server`` doesn't pay the SDK cost when
    ``--serve`` isn't being used.
    """
    from mcp import types
    from mcp.server import Server

    server = Server("pipeline-check", version=__version__)

    @server.list_tools()  # type: ignore[no-untyped-call,untyped-decorator]
    async def _list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name=spec["name"],
                description=spec["description"],
                inputSchema=spec["input_schema"],
            )
            for spec in _tools.TOOL_SPECS
        ]

    @server.call_tool(validate_input=True)  # type: ignore[untyped-decorator]
    async def _call_tool(
        name: str, arguments: dict[str, Any] | None,
    ) -> list[types.TextContent]:
        kwargs = arguments or {}
        try:
            fn = _tools.get_tool_fn(name)
            # Tool functions are sync; run them on the default
            # executor so a long scan doesn't block the event
            # loop's other handlers.
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None, lambda: fn(**kwargs)
            )
        except (KeyError, ValueError) as exc:
            # Surface a structured error the MCP client can
            # display without a stack trace. The MCP SDK's call_tool
            # wrapper turns a raised exception into an isError result
            # automatically; we deliberately pre-shape the message
            # into JSON so the agent can parse it programmatically
            # if needed.
            return [
                types.TextContent(
                    type="text",
                    text=json.dumps({"error": str(exc)}),
                ),
            ]
        return [
            types.TextContent(
                type="text",
                text=json.dumps(result, indent=2, default=str),
            ),
        ]

    return server


# Public re-export for tests / programmatic use. The lazy import
# means this binds at first access, not at module import.
def server_app() -> Any:
    """Return the constructed MCP server instance.

    Test code uses this to call handlers directly without going
    through stdio framing. Production code goes through
    :func:`run_stdio` instead.
    """
    return _build_server()


def run_stdio() -> None:
    """Run the MCP server on stdio until the client disconnects.

    This is the entry point ``pipeline_check --serve`` invokes.
    Blocks until stdin closes; clean shutdown on Ctrl-C raises
    ``KeyboardInterrupt`` which the CLI converts to exit code 0.
    """
    if not _tools.mcp_available():
        raise RuntimeError(
            "the ``mcp`` package is not installed. Install with "
            "``pip install 'pipeline-check[mcp]'``."
        )

    async def _main() -> None:
        from mcp.server.stdio import stdio_server

        server = _build_server()
        async with stdio_server() as (read, write):
            await server.run(
                read,
                write,
                server.create_initialization_options(),
            )

    asyncio.run(_main())
