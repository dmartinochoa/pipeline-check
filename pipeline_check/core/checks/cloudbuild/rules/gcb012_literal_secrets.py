"""GCB-012 — credential-shaped literal in pipeline body.

Scans every string scalar in the document against the cross-provider
credential-pattern catalogue (AWS keys, GitHub tokens, Slack tokens,
PEM blocks, JWTs, …). Complements GCB-003 (secrets consumed inline
via ``gcloud secrets versions access``) — GCB-003 catches *fetches*,
this catches *pastes*.

Mirrors GHA-008 / GL-008 / BB-008 / ADO-008 / CC-008 / JF-008.
"""
from __future__ import annotations

from typing import Any

from ..._secrets import find_secret_values
from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="GCB-012",
    title="Credential-shaped literal in pipeline body",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798",),
    recommendation=(
        "Rotate the exposed credential immediately. Move the value to "
        "``availableSecrets.secretManager`` and reference it via "
        "``secretEnv:`` so the plaintext never lands in the YAML or "
        "the build logs. For cloud access prefer workload-identity "
        "federation over long-lived keys."
    ),
    docs_note=(
        "Complements GCB-003 (inline ``gcloud secrets versions access``) "
        "and GCB-007 (``/versions/latest`` alias). This rule runs the "
        "shared credential-shape catalogue against every string in the "
        "YAML — AWS keys, GitHub PATs, Slack webhooks, JWTs, PEM private "
        "key blocks, and any user-registered ``--secret-pattern`` regex. "
        "Known placeholders like ``EXAMPLE``/``CHANGEME`` are already "
        "filtered upstream so fixtures and docs don't false-match."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    hits = find_secret_values(doc)
    passed = not hits
    desc = (
        "No string in the pipeline matches a known credential pattern."
        if passed else
        f"Pipeline contains {len(hits)} literal value(s) matching known "
        f"credential patterns (AWS keys, GitHub tokens, Slack tokens, "
        f"JWTs, PEM blocks): {', '.join(hits[:5])}"
        f"{'…' if len(hits) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
