"""GHA-008 — workflow must not contain credential-shaped literals."""
from __future__ import annotations

from typing import Any

from ..._secrets import find_secret_values
from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="GHA-008",
    title="Credential-shaped literal in workflow body",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798",),
    recommendation=(
        "Rotate the exposed credential immediately. Move the value to "
        "an encrypted repository or environment secret and reference "
        "it via `${{ secrets.NAME }}`. For cloud access, prefer OIDC "
        "federation over long-lived keys."
    ),
    docs_note=(
        "Every string in the workflow is scanned against a set of "
        "credential patterns (AWS access keys, GitHub tokens, Slack "
        "tokens, JWTs, Stripe, Google, Anthropic, etc. — see "
        "`--man secrets` for the full catalogue). A match means a "
        "secret was pasted into YAML — the value is visible in every "
        "fork and every build log and must be treated as compromised."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    hits = find_secret_values(doc)
    passed = not hits
    desc = (
        "No string in the workflow matches a known credential pattern."
        if passed else
        f"Workflow contains {len(hits)} literal value(s) matching known "
        f"credential patterns (AWS keys, GitHub tokens, Slack tokens, "
        f"JWTs): {', '.join(hits[:5])}{'…' if len(hits) > 5 else ''}. "
        f"Secrets committed to YAML are visible in every fork and in "
        f"every build log, and must be considered compromised."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
