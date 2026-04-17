"""GCB-002 — Cloud Build runs with the default service account.

When ``serviceAccount:`` is unset, Cloud Build uses the project's
default Cloud Build service account (``<project-number>@cloudbuild.
gserviceaccount.com``) or, in projects created after April 2024, a
new default that still has broader-than-needed roles. Either default
grants more GCP APIs than a typical build needs, and a compromised
step (or a vulnerable builder image) can reuse those credentials.

Binding a dedicated, least-privilege service account is the single
highest-leverage Cloud Build hardening step and the only durable
way to scope the blast radius of a compromised build step.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="GCB-002",
    title="Cloud Build uses the default service account",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    esf=("ESF-D-IDENTITY", "ESF-D-LEAST-PRIV"),
    cwe=("CWE-250",),
    recommendation=(
        "Create a dedicated service account for the build, grant it "
        "only the roles the pipeline actually needs (``roles/"
        "artifactregistry.writer``, ``roles/storage.objectCreator`` "
        "for artifact upload, etc.), and set ``serviceAccount: "
        "projects/<PROJECT>/serviceAccounts/<NAME>@...``. Leaving it "
        "unset falls back to the default Cloud Build SA, which "
        "accumulates roles over a project's lifetime and is routinely "
        "granted ``roles/editor``."
    ),
    docs_note=(
        "The default Cloud Build service account historically held "
        "``roles/cloudbuild.builds.builder`` plus project-level editor "
        "in many organisations. Even under the GCP April-2024 default-"
        "identity change, the default SA is still broader than what "
        "a single pipeline needs. Explicit ``serviceAccount:`` is "
        "required to pass."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    sa = doc.get("serviceAccount")
    if isinstance(sa, str) and sa.strip():
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=f"Explicit serviceAccount set: {sa}.",
            recommendation=RULE.recommendation, passed=True,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path,
        description=(
            "``serviceAccount:`` is not set. The build runs as the "
            "project's default Cloud Build SA, which typically carries "
            "roles well beyond what this pipeline needs."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
