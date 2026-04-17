"""JF-027 — ``archiveArtifacts`` should record a fingerprint for provenance."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile
from ._helpers import ARCHIVE_ARTIFACTS_RE, FINGERPRINT_TRUE_RE

RULE = Rule(
    id="JF-027",
    title="`archiveArtifacts` does not record a fingerprint",
    severity=Severity.LOW,
    owasp=("CICD-SEC-9",),
    esf=("ESF-D-TAMPER",),
    cwe=("CWE-345",),
    recommendation=(
        "Set ``fingerprint: true`` on every ``archiveArtifacts`` call "
        "(or use ``archiveArtifacts artifacts: '...', fingerprint: "
        "true``). Without it, Jenkins can't link the artifact to the "
        "build that produced it; ``copyArtifacts`` consumers downstream "
        "then have no provenance to verify against."
    ),
    docs_note=(
        "Fingerprinting hashes the artifact on archive so Jenkins can "
        "trace its flow between jobs — the same mechanism JF-013 "
        "relies on for verification-step pairing. It's cheap and "
        "retroactive: enabling it on the producer job unlocks a "
        "build-traceability audit for every downstream consumer."
    ),
)


def check(jf: Jenkinsfile) -> Finding:
    # Use the comment-stripped text so a TODO comment like
    # ``// add fingerprint: true`` doesn't satisfy the check.
    text = jf.text_no_comments or jf.text
    if not ARCHIVE_ARTIFACTS_RE.search(text):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=jf.path,
            description="Pipeline does not archive any artifacts.",
            recommendation="No action required.", passed=True,
        )
    passed = bool(FINGERPRINT_TRUE_RE.search(text))
    desc = (
        "``archiveArtifacts`` is paired with ``fingerprint: true``."
        if passed else
        "Pipeline archives artifacts but never sets ``fingerprint: "
        "true`` — downstream jobs can't verify the artifact's origin."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
