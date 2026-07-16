"""DEV-009, a committed MCP config talks to a remote server over plaintext.

DEV-007 covers *stdio* MCP servers (a committed ``command`` the editor
launches locally). The other half of the surface is a *remote* server:
a spec with a ``url`` (``type: http`` / ``sse``) that the agent connects
to over the network. DEV-007 deliberately passes on those; this rule
inspects their transport.

When that URL is plaintext ``http://`` to a non-loopback host, the tool
stream (the tools the agent may call, their descriptions, and every
request / response) crosses the network unauthenticated and in the
clear. An on-path attacker can read it or, worse, rewrite it: inject a
tool result that steers the agent, or swap the advertised tool set for a
poisoned one. It is the MCP equivalent of fetching a dependency over
``http://``. A loopback URL (``http://localhost`` / ``127.0.0.1``) is a
local dev server and is not flagged; an ``https://`` endpoint is not
flagged.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from ...base import Finding, Severity, summarize_offenders
from ...rule import Rule
from ..base import MCP_KINDS, WorkspaceFile, location_for, mcp_remote_servers

RULE = Rule(
    id="DEV-009",
    title="Committed MCP config uses a remote server over plaintext HTTP",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-319", "CWE-829"),
    recommendation=(
        "Point the MCP server at an ``https://`` endpoint so the tool "
        "stream is authenticated and encrypted. A plaintext ``http://`` "
        "transport to a remote host lets an on-path attacker read or "
        "rewrite the tools the agent is offered and the data it exchanges. "
        "If the server genuinely runs locally, bind it to loopback "
        "(``http://localhost`` / ``127.0.0.1``), which is not flagged."
    ),
    docs_note=(
        "Fires when a committed MCP config (``.mcp.json``, "
        "``.cursor/mcp.json``, ``.vscode/mcp.json``, Zed's "
        "``.zed/settings.json``, or Continue's ``.continue/config.yaml`` / "
        "``.continue/mcpServers/*.yaml``) defines a remote server whose "
        "``url`` is plaintext ``http://`` to a non-loopback host (any "
        "``sse`` / ``streamable-http`` transport included). Loopback URLs "
        "(``localhost`` / ``127.0.0.0/8`` / ``::1``) and ``https://`` "
        "endpoints pass. Stdio (``command``) servers are DEV-007's "
        "concern, not this rule's."
    ),
    known_fp=(
        "A remote server reached over plaintext inside a trusted, isolated "
        "network segment may be intentional. Prefer TLS regardless; if the "
        "plaintext hop is truly contained, suppress on the file with a "
        "rationale naming the server and the network boundary.",
    ),
)

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})


def _is_plaintext_remote(url: str) -> bool:
    """True when *url* is ``http://`` to a resolvable non-loopback host."""
    parts = urlsplit(url)
    if parts.scheme.lower() != "http":
        return False
    host = (parts.hostname or "").lower()
    if not host:
        return False
    if host in _LOOPBACK_HOSTS or host.startswith("127."):
        return False
    return True


def check(path: str, wf: WorkspaceFile) -> Finding:
    if wf.kind not in MCP_KINDS:
        return RULE.finding(path, "Not an MCP server config.", passed=True)
    offenders = [
        (name, url)
        for name, url in mcp_remote_servers(wf.data)
        if _is_plaintext_remote(url)
    ]
    passed = not offenders
    if passed:
        return RULE.finding(
            path,
            "No remote MCP server is reached over plaintext HTTP.",
            passed=True,
        )
    labels = [f"{name} ({url})" for name, url in offenders]
    desc = (
        f"{len(offenders)} remote MCP server(s) are reached over plaintext "
        f"HTTP: {summarize_offenders(labels, limit=3)}. The tool stream "
        "crosses the network unauthenticated and in the clear, so an on-path "
        "attacker can read or rewrite the tools the agent is offered."
    )
    return RULE.finding(
        path, desc, passed=False,
        locations=location_for(path, wf.raw, offenders[0][1]),
    )
