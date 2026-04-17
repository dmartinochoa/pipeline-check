"""GCB-007 — ``availableSecrets`` references a rolling ``versions/latest``.

Secret Manager secret versions are immutable once created, but the
``versions/latest`` alias rolls to whatever version is newest at the
time the build executes. A build that references
``projects/.../secrets/<name>/versions/latest`` therefore pulls a
different value any time a new version is published — and a
compromised principal with ``roles/secretmanager.admin`` on that
project can publish a new version that the next build will transparently
consume.

The correct shape is a pinned version number:

    availableSecrets:
      secretManager:
        - versionName: projects/p/secrets/api-token/versions/7
          env: API_TOKEN

(``gcloud secrets versions add`` returns the version number, which can
be substituted in via a user substitution if the pipeline needs to
refresh on a controlled cadence.)
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="GCB-007",
    title="availableSecrets references ``versions/latest``",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS", "ESF-S-PIN-DEPS"),
    cwe=("CWE-353",),
    recommendation=(
        "Pin each ``availableSecrets.secretManager[].versionName`` to "
        "a specific version number (``.../versions/7``) rather than "
        "``latest``. Rotate by updating the number when a new version "
        "is promoted, not by silently publishing a new version that "
        "the next build pulls."
    ),
    docs_note=(
        "``versions/latest`` is documented as a rolling alias. A build "
        "run on Monday and a re-run on Tuesday can consume different "
        "secret bodies without any change to ``cloudbuild.yaml`` — "
        "breaking the reproducibility invariant that pinning protects."
    ),
)


def _iter_available_secrets(doc: dict[str, Any]):
    avail = doc.get("availableSecrets")
    if not isinstance(avail, dict):
        return
    entries = avail.get("secretManager")
    if not isinstance(entries, list):
        return
    for idx, entry in enumerate(entries):
        if isinstance(entry, dict):
            yield idx, entry


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    any_entries = False
    for idx, entry in _iter_available_secrets(doc):
        any_entries = True
        version = entry.get("versionName")
        if not isinstance(version, str):
            continue
        if version.rstrip("/").endswith("/versions/latest"):
            env = entry.get("env") or f"secretManager[{idx}]"
            offenders.append(f"{env}: {version}")
    if not any_entries:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="No ``availableSecrets.secretManager`` entries declared.",
            recommendation=RULE.recommendation, passed=True,
        )
    passed = not offenders
    desc = (
        "Every ``availableSecrets`` entry pins a specific version."
        if passed else
        f"{len(offenders)} secret reference(s) use the rolling "
        f"``versions/latest`` alias: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
