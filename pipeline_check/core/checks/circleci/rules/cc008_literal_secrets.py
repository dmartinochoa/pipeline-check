"""CC-008 — Config must not contain credential-shaped literals."""
from __future__ import annotations

from typing import Any

from ..._secrets import find_secret_values
from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="CC-008",
    title="Credential-shaped literal in config body",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798",),
    recommendation=(
        "Rotate the exposed credential immediately. Move the value to "
        "a CircleCI project environment variable or a context and "
        "reference it via the variable name. For cloud access, prefer "
        "OIDC federation over long-lived keys."
    ),
    docs_note=(
        "Every string in the config is scanned against a set of "
        "credential patterns (AWS access keys, GitHub tokens, Slack "
        "tokens, JWTs, Stripe, Google, Anthropic, etc.). A match means "
        "a secret was pasted into YAML — the value is visible in every "
        "fork and every build log and must be treated as compromised."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    hits = find_secret_values(doc)
    passed = not hits
    desc = (
        "No string in the config matches a known credential pattern."
        if passed else
        f"Config contains {len(hits)} literal value(s) matching known "
        f"credential patterns (AWS keys, GitHub tokens, Slack tokens, "
        f"JWTs): {', '.join(hits[:5])}{'...' if len(hits) > 5 else ''}. "
        f"Secrets committed to YAML are visible in every fork and in "
        f"every build log, and must be considered compromised."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
