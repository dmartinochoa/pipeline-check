"""GCB-003 — Secrets passed via step args instead of ``secretEnv``.

Cloud Build supports two patterns for consuming Secret Manager
secrets:

1. **Correct:** Map the secret once via ``availableSecrets.secret
   Manager[*].env`` and reference the env var from a step's
   ``secretEnv:`` list. The value never appears in the step's
   ``args`` or logs.
2. **Dangerous:** Pass the secret's plaintext (or its resource URI
   via ``$(gcloud secrets versions access ...)``) inline in
   ``args`` or ``entrypoint``. The value is captured in Cloud Build
   logs, stored in build history, and may echo into stdout of the
   builder container — visible to anyone with ``roles/cloudbuild.
   builds.viewer``.

This rule fires on step bodies (``args``, ``entrypoint``) that
contain literal Secret Manager references or shell expansions that
fetch a secret at runtime. It does *not* fire on the official
``secretEnv:`` pattern.
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_steps, step_name, step_strings

RULE = Rule(
    id="GCB-003",
    title="Secret Manager value referenced in step args",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-532",),
    recommendation=(
        "Map the secret under ``availableSecrets.secretManager[]`` "
        "with an ``env:`` alias, then reference it from each step "
        "via ``secretEnv: [ALIAS]``. Avoid inline ``gcloud secrets "
        "versions access`` in ``args`` — the resolved plaintext "
        "lands in build logs."
    ),
    docs_note=(
        "Detection patterns: literal ``projects/<n>/secrets/<name>"
        "/versions/...`` URIs, ``gcloud secrets versions access`` "
        "shell invocations, and ``$(gcloud secrets …)`` command "
        "substitutions in step args or entrypoint."
    ),
)

# Literal Secret Manager resource URI (also used by gcloud output).
_SECRET_URI_RE = re.compile(
    r"projects/[^/\s]+/secrets/[^/\s]+/versions/[^\s)]+"
)

# ``gcloud secrets versions access`` + ``gcloud secrets access`` idioms,
# whether bare or inside a ``$(...)`` command substitution.
_GCLOUD_SECRETS_RE = re.compile(
    r"gcloud\s+(?:secrets\s+(?:versions\s+)?access|beta\s+secrets\s+versions\s+access)"
)


def _step_uses_secret_in_args(step: dict[str, Any]) -> list[str]:
    """Return the list of offending evidence strings for one step."""
    offenders: list[str] = []
    for blob in step_strings(step):
        if _SECRET_URI_RE.search(blob):
            offenders.append(f"secret URI: {blob[:80]}")
            continue
        if _GCLOUD_SECRETS_RE.search(blob):
            offenders.append(f"gcloud fetch: {blob[:80]}")
    return offenders


def check(path: str, doc: dict[str, Any]) -> Finding:
    findings_per_step: list[str] = []
    for idx, step in iter_steps(doc):
        offenders = _step_uses_secret_in_args(step)
        if offenders:
            findings_per_step.append(
                f"{step_name(step, idx)}: {'; '.join(offenders[:2])}"
            )
    passed = not findings_per_step
    desc = (
        "No step references a Secret Manager value inline in args."
        if passed else
        f"{len(findings_per_step)} step(s) fetch or embed Secret Manager "
        f"values inline: {', '.join(findings_per_step[:5])}"
        f"{'…' if len(findings_per_step) > 5 else ''}. Move the secret "
        f"to availableSecrets.secretManager[] and reference via "
        f"secretEnv so the plaintext doesn't land in build logs."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
