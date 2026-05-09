"""GCB-020. Explicit ``serviceAccount:`` still points at the default Cloud Build SA."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="GCB-020",
    title="serviceAccount points at the default Cloud Build service account",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    esf=("ESF-D-IDENTITY", "ESF-D-LEAST-PRIV"),
    cwe=("CWE-250",),
    recommendation=(
        "Don't bind the build to ``<project-number>@cloudbuild."
        "gserviceaccount.com``. The default Cloud Build SA accumulates "
        "roles over a project's lifetime (commonly ``roles/editor`` "
        "or broad Artifact Registry / Secret Manager access). Create "
        "a dedicated SA per pipeline, grant only the roles the build "
        "actually needs, and reference it by its bespoke email "
        "(``<name>@<project>.iam.gserviceaccount.com``). Revoking a "
        "compromised pipeline then doesn't unbind every other build "
        "in the project."
    ),
    docs_note=(
        "Complements GCB-002, which only fires when ``serviceAccount:`` "
        "is unset. This rule fires when an explicit value is set but "
        "still resolves to the project default, typically the email "
        "shape ``<digits>@cloudbuild.gserviceaccount.com``, optionally "
        "wrapped in the ``projects/<id>/serviceAccounts/...`` URI form. "
        "The April-2024 GCP default-identity change kept the same SA "
        "shape; the broad-permissions concern remains."
    ),
    known_fp=(
        "Single-pipeline GCP projects where the default SA's roles are "
        "actively scoped down. Rare in practice; create a named SA "
        "anyway so the audit log stays unambiguous about which "
        "pipeline made each API call.",
    ),
)

# Match the default Cloud Build SA email shape, in either bare-email
# form or the ``projects/<id>/serviceAccounts/<email>`` URI form. The
# default SA always has the project-number prefix on the local part.
_DEFAULT_SA_RE = re.compile(
    r"\b\d+@cloudbuild\.gserviceaccount\.com\b",
    re.IGNORECASE,
)


def _references_default_sa(value: str) -> bool:
    return bool(_DEFAULT_SA_RE.search(value))


def check(path: str, doc: dict[str, Any]) -> Finding:
    sa = doc.get("serviceAccount")
    if not isinstance(sa, str) or not sa.strip():
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "``serviceAccount:`` is unset (covered separately by "
                "GCB-002). This rule short-circuits to passing, set "
                "an explicit, dedicated SA email to satisfy both."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    if _references_default_sa(sa):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                f"``serviceAccount: {sa}`` resolves to the project "
                "default Cloud Build SA. Even with an explicit value "
                "the build inherits the default SA's broad role set."
            ),
            recommendation=RULE.recommendation, passed=False,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path,
        description=f"``serviceAccount: {sa}`` is a dedicated SA email.",
        recommendation=RULE.recommendation, passed=True,
    )
