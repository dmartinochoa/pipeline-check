"""DEV-007, a committed MCP config auto-launches a local command server.

Model Context Protocol (MCP) configs map server names to specs. A
``command``-bearing spec is a *stdio* server: when a developer opens the
project in Claude Code (``.mcp.json``), Cursor (``.cursor/mcp.json``), or
VS Code (``.vscode/mcp.json``), the agent / editor launches that command
as a local child process with the developer's privileges, and the agent
can then call its tools. A committed config therefore auto-runs code on
project open, the same trust boundary the VS Code / devcontainer auto-run
rules (DEV-001 / DEV-002) cover, extended to the agent-tooling surface.

The sharpest case is a server whose command fetches an unpinned remote
package (``npx -y <pkg>``, ``uvx <pkg>``, ``pnpm dlx`` …): the tool server
is whatever that registry serves at open time, so a compromised or
typosquatted package is code execution plus a persistent tool the agent
trusts. A first-party local server (``node ./scripts/server.js``) is the
benign case the recommendation calls out.
"""
from __future__ import annotations

import re

from ...base import Finding, Severity, summarize_offenders
from ...rule import Rule
from ..base import KIND_MCP_CONFIG, WorkspaceFile, location_for, mcp_command_servers

RULE = Rule(
    id="DEV-007",
    title="Committed MCP config auto-launches a local command server",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-829", "CWE-94"),
    recommendation=(
        "Treat a committed MCP server config as code that runs on project "
        "open. Prefer a first-party server invoked from a checked-in, "
        "reviewed script over a ``npx -y`` / ``uvx`` runner that pulls an "
        "unpinned remote package; if a remote package is required, pin it "
        "to an exact version (and ideally an integrity hash). Keep "
        "developer-specific or untrusted MCP servers in user-level config "
        "(``~/.cursor`` / user settings) rather than committing them to the "
        "repository where they auto-launch for every contributor."
    ),
    docs_note=(
        "Fires when a committed MCP config (``.mcp.json``, "
        "``.cursor/mcp.json``, ``.vscode/mcp.json``) defines a server with "
        "a ``command`` (a stdio server the editor / agent launches as a "
        "local process on project open). Both the ``mcpServers`` "
        "(Claude / Cursor) and ``servers`` (VS Code) block names are read. "
        "``url``-only servers (``type: http`` / ``sse``) don't spawn a "
        "local process and don't fire. Commands that fetch an unpinned "
        "remote package (``npx -y`` / ``uvx`` / ``pnpm dlx`` / ``bunx`` / "
        "``pipx run``) are called out as the sharpest case."
    ),
    known_fp=(
        "A first-party MCP server invoked from a checked-in, reviewed "
        "script (``node ./tools/mcp-server.js``) is intentional. The "
        "finding still flags that the config auto-launches a process on "
        "open; suppress on the file with a rationale naming the server.",
    ),
)

# Package runners that fetch-and-execute a (possibly unpinned, remote)
# package rather than running a checked-in local entry point.
_REMOTE_RUNNER_RE = re.compile(
    r"\b(?:npx|bunx|(?:pnpm|yarn)\s+dlx|uvx|uv\s+tool\s+run|pipx\s+run)\b",
    re.IGNORECASE,
)


def check(path: str, wf: WorkspaceFile) -> Finding:
    if wf.kind != KIND_MCP_CONFIG:
        return RULE.finding(
            path, "Not an MCP server config.", passed=True,
        )
    servers = mcp_command_servers(wf.data)
    passed = not servers
    if passed:
        return RULE.finding(
            path, "No MCP server launches a local command on project open.",
            passed=True,
        )
    labels = [f"{name} ({cmd})" for name, cmd in servers]
    remote = [name for name, cmd in servers if _REMOTE_RUNNER_RE.search(cmd)]
    remote_note = (
        f" {len(remote)} fetch an unpinned remote package "
        f"({', '.join(sorted(remote))})." if remote else ""
    )
    desc = (
        f"{len(servers)} MCP server(s) launch a local command on project "
        f"open: {summarize_offenders(labels, limit=3)}.{remote_note} The "
        "agent / editor runs these with the developer's privileges the "
        "moment the repo is opened."
    )
    first_cmd = servers[0][1]
    return RULE.finding(
        path, desc, passed=False,
        locations=location_for(path, wf.raw, first_cmd.split()[0]),
    )
