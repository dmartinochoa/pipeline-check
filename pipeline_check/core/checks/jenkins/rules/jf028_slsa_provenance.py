"""JF-028 — Jenkinsfile must emit SLSA provenance attestation."""
from __future__ import annotations

from ...base import PROVENANCE_TOKENS, Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile

RULE = Rule(
    id="JF-028",
    title="No SLSA provenance attestation produced",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    esf=("ESF-S-PROVENANCE",),
    cwe=("CWE-345",),
    recommendation=(
        "Add a ``sh 'cosign attest --predicate=provenance.intoto.jsonl …'`` "
        "step after the build, or integrate the TestifySec ``witness run`` "
        "attestor. JF-006 covers signing; this rule covers the build-"
        "provenance statement SLSA Build L3 requires."
    ),
    docs_note=(
        "``cosign sign`` signs the artifact bytes. ``cosign attest`` "
        "signs an in-toto statement describing how the build ran — "
        "builder, source commit, input parameters. SLSA L3 verifiers "
        "check the latter so consumers can enforce policy on where "
        "and how artifacts were produced."
    ),
)

# Artifact-production tokens in Groovy/shell — mirrors the heuristic
# in checks/base.py but narrowed to what appears in Jenkinsfiles so
# lint/test-only pipelines don't trip this check.
_ARTIFACT_HINTS = (
    "archiveartifacts", "docker push", "docker build",
    "publish", "deploy", "release",
    "aws s3 cp", "aws s3 sync",
    "twine upload", "npm publish", "yarn publish",
    "cargo publish", "gem push",
    "kubectl apply", "helm upgrade", "helm install",
)


def check(jf: Jenkinsfile) -> Finding:
    # Comment-stripped text so a ``// TODO: add cosign attest``
    # comment doesn't satisfy the check.
    text = (jf.text_no_comments or jf.text).lower()
    if not any(tok in text for tok in _ARTIFACT_HINTS):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=jf.path,
            description="Pipeline does not produce deployable artifacts.",
            recommendation="No action required.", passed=True,
        )
    passed = any(tok in text for tok in PROVENANCE_TOKENS)
    desc = (
        "SLSA provenance attestation step detected."
        if passed else
        "Pipeline publishes artifacts but does not emit a SLSA provenance "
        "attestation (``cosign attest`` / ``witness run``)."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
