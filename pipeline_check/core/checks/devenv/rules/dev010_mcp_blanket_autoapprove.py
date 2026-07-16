"""DEV-010, a committed MCP config blanket-auto-approves a server's tools.

MCP clients gate tool calls behind a human confirmation by default: the
agent asks before it runs a tool. A server spec can opt out of that gate
(``autoApprove: true`` / ``["*"]`` in Cursor / VS Code, ``alwaysAllow:
["*"]`` in Cline), and when the opt-out is *blanket* the agent runs every
tool that server exposes with no prompt.

Committed to the repo, a blanket auto-approve is the second half of the
DEV-007 problem: DEV-007's server auto-launches on project open, and this
removes the last confirmation step, so a poisoned or rug-pulled tool
executes silently for every contributor. A grant scoped to specific named
tools (``alwaysAllow: ["read_file"]``) is an intentional, bounded choice
and is not flagged.
"""
from __future__ import annotations

from ...base import Finding, Severity, summarize_offenders
from ...rule import Rule
from ..base import MCP_KINDS, WorkspaceFile, location_for, mcp_blanket_auto_approvals

RULE = Rule(
    id="DEV-010",
    title="Committed MCP config blanket-auto-approves a server's tools",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-284", "CWE-269"),
    recommendation=(
        "Don't commit a blanket tool auto-approval. Remove "
        "``autoApprove: true`` / ``[\"*\"]`` (and Cline's "
        "``alwaysAllow: [\"*\"]``) so tool calls keep their human "
        "confirmation, or scope the grant to the specific low-risk tools "
        "you trust (``alwaysAllow: [\"read_file\"]``). Combined with an "
        "auto-launched server (DEV-007), a blanket grant means a poisoned "
        "tool runs with no prompt for every contributor who opens the repo."
    ),
    docs_note=(
        "Fires when a committed MCP config (``.mcp.json``, "
        "``.cursor/mcp.json``, ``.vscode/mcp.json``, Zed's "
        "``.zed/settings.json``, or Continue's ``.continue/config.yaml`` / "
        "``.continue/mcpServers/*.yaml``) sets a *blanket* tool "
        "auto-approval on a server: ``autoApprove: true`` / ``[\"*\"]`` or "
        "``alwaysAllow`` containing ``\"*\"``. A grant scoped to specific "
        "named tools is a bounded choice and passes."
    ),
    known_fp=(
        "A blanket grant on a first-party, fully trusted local server may "
        "be intentional. Prefer a named-tool allow-list; if the blanket "
        "grant is deliberate, suppress on the file with a rationale naming "
        "the server.",
    ),
)


def check(path: str, wf: WorkspaceFile) -> Finding:
    if wf.kind not in MCP_KINDS:
        return RULE.finding(path, "Not an MCP server config.", passed=True)
    offenders = mcp_blanket_auto_approvals(wf.data)
    passed = not offenders
    if passed:
        return RULE.finding(
            path,
            "No MCP server blanket-auto-approves its tools.",
            passed=True,
        )
    labels = [f"{name} ({key})" for name, key in offenders]
    desc = (
        f"{len(offenders)} MCP server(s) blanket-auto-approve every tool "
        f"they expose: {summarize_offenders(labels, limit=3)}. The agent "
        "runs those tools with no confirmation, so a poisoned or "
        "rug-pulled tool executes silently on every contributor's machine."
    )
    return RULE.finding(
        path, desc, passed=False,
        locations=location_for(path, wf.raw, offenders[0][1]),
    )
