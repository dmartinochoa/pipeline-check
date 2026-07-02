"""DEV-008, credential-shaped literal committed in a dev-environment config.

The developer-environment provider (the devenv `*-008`) of the
cross-provider literal-secret family. Editor / agent / container configs
routinely carry credentials: an MCP server's ``env`` block (a
``GITHUB_TOKEN`` / API key passed to the tool server), a devcontainer
``remoteEnv`` / ``containerEnv``, a VS Code setting, or a Claude Code
hook. When that value is committed as a literal it is exposed to everyone
with repo access and shows up in clone / fork history.

Scans every string in the parsed config against the shared
credential-shape catalog (the same detector set GHA-008 / GL-008 use), so
it catches a token pasted anywhere in the document, not just under a
known key.
"""
from __future__ import annotations

from ..._secrets import find_secret_values
from ...base import Finding, Severity, summarize_offenders
from ...rule import Rule
from ..base import WorkspaceFile

RULE = Rule(
    id="DEV-008",
    title="Credential-shaped literal in a developer-environment config",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798",),
    recommendation=(
        "Rotate the exposed credential immediately, it is in the repo's "
        "history. Don't commit secrets to editor / agent / container "
        "config: pass them through the environment at run time (an MCP "
        "server reads ``${env:GITHUB_TOKEN}`` from the developer's shell, "
        "a devcontainer reads a host env var) or a local, git-ignored "
        "config rather than a committed literal."
    ),
    docs_note=(
        "Scans every string in a developer-environment config "
        "(``.vscode/`` tasks / settings, ``.devcontainer``, "
        "``.claude/settings.json``, and MCP configs ``.mcp.json`` / "
        "``.cursor/mcp.json`` / ``.vscode/mcp.json`` / Zed's "
        "``.zed/settings.json`` / Continue's ``.continue/`` YAML) against "
        "the cross-provider credential-shape catalog. The common hit is a "
        "token in an MCP server's ``env`` block or a devcontainer "
        "``remoteEnv`` / ``containerEnv``."
    ),
    known_fp=(
        "Documentation / example configs sometimes embed credential-shaped "
        "strings (a sample ``ghp_`` token, a JWT). Well-known vendor "
        "example tokens are suppressed by the shared catalog; suppress a "
        "genuine fixture per-resource with a rationale.",
    ),
)


def check(path: str, wf: WorkspaceFile) -> Finding:
    hits = find_secret_values(wf.data)
    passed = not hits
    if passed:
        desc = (
            "No string in this developer-environment config matches a "
            "known credential pattern."
        )
    else:
        desc = (
            f"{len(hits)} literal value(s) in this developer-environment "
            f"config match known credential patterns: "
            f"{summarize_offenders(hits, limit=5)}. A committed credential "
            "is exposed to everyone with repo access and lives in git "
            "history."
        )
    return RULE.finding(path, desc, passed=passed)
