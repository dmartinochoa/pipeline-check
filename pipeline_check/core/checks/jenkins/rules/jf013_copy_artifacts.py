"""JF-013 — copyArtifacts must be paired with a verification step."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile
from ._helpers import COPY_ARTIFACTS_RE, VERIFY_RE

RULE = Rule(
    id="JF-013",
    title="copyArtifacts ingests another job's output unverified",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-494",),
    recommendation=(
        "Add a verification step before consuming the artifact: "
        "`sh 'sha256sum -c manifest.sha256'` against a manifest the "
        "producer signed, or `cosign verify` over the artifact "
        "directly. Restrict the upstream job to non-PR builds via "
        "branch protection if verification isn't feasible."
    ),
    docs_note=(
        "Recognises both `copyArtifacts(projectName: ...)` and the "
        "older `step([$class: 'CopyArtifact', ...])` form. If the "
        "upstream job accepts multibranch or PR builds, the "
        "artifact may have been produced by attacker-controlled code."
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    ingests = bool(COPY_ARTIFACTS_RE.search(jf.text))
    if not ingests:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=jf.path,
            description="Pipeline does not use copyArtifacts.",
            recommendation="No action required.", passed=True,
        )
    passed = bool(VERIFY_RE.search(jf.text))
    desc = (
        "copyArtifacts is paired with a verification step."
        if passed else
        "Pipeline pulls artifacts from another Jenkins job via "
        "`copyArtifacts` but no signature/checksum verification "
        "step is present."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
