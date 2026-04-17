"""BB-010 — deploy steps must verify ingested PR artifacts."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_steps

RULE = Rule(
    id="BB-010",
    title="Deploy step ingests pull-request artifact unverified",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-494",),
    recommendation=(
        "Add a verification step before the deploy step consumes "
        "the artifact: `sha256sum -c artifact.sha256` against a "
        "manifest the producer signed, or `cosign verify` over the "
        "artifact directly. Alternatively, restrict the artifact-"
        "producing step to non-PR pipelines via ``branches:`` or "
        "``custom:`` triggers."
    ),
    docs_note=(
        "Bitbucket steps declare artifacts on the producer and "
        "downstream steps implicitly receive them. When an "
        "unprivileged step produces an artifact and a later "
        "`deployment:` step consumes it without verification, "
        "attacker-controlled output flows into the privileged stage."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    produces = False
    deploys = False
    verified = False
    for _, step in iter_steps(doc):
        arts = step.get("artifacts")
        if (isinstance(arts, list) and arts) or (isinstance(arts, dict) and arts):
            produces = True
        if step.get("deployment"):
            deploys = True
        for line in step.get("script", []) or []:
            if not isinstance(line, str):
                continue
            low = line.lower()
            if (
                "cosign verify" in low
                or "sha256sum --check" in low
                or "sha256sum -c" in low
                or "gpg --verify" in low
            ):
                verified = True
    if not (produces and deploys):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "Pipeline does not pair an artifact-producing step "
                "with a deploy step."
            ),
            recommendation="No action required.", passed=True,
        )
    passed = verified
    desc = (
        "Deploy step is paired with an artifact verification step."
        if passed else
        "Pipeline produces an artifact in one step and consumes it "
        "in a `deployment:` step without any verification (cosign, "
        "sha256sum -c, gpg --verify)."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
