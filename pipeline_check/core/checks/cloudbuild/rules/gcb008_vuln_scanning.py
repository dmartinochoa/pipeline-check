"""GCB-008. No vulnerability scanning step anywhere in the pipeline.

Reuses the cross-provider ``has_vuln_scanning`` helper so the
scanner-name catalog (trivy / grype / snyk / osv-scanner / pip-audit
/ npm audit / govulncheck) stays in sync across GHA-020 / GL-019 /
BB-019 / ADO-019 / CC-020 / JF-020.

Cloud Build pipelines can invoke a scanner solely through the step
``name:`` field (the container image), with scanner args passed via
``args:`` or ``entrypoint:``. In that pattern the tool name never
appears as a bare token in the blob (e.g. ``name: aquasec/trivy``
with ``args: [image, ...]`` has no ``trivy `` substring). The shared
``has_vuln_scanning`` helper uses trailing-space tokens to avoid
substring FPs; that approach cannot match image refs. This rule adds
a Cloud Build-specific step-image check against known scanner images
so both invocation patterns are recognized.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity, has_vuln_scanning
from ...rule import Rule

# Binary/repo segments of well-known scanner images used as Cloud Build
# step ``name:`` values. Matched as substrings of the lowercased name
# so both ``aquasec/trivy`` and ``gcr.io/aquasec/trivy`` match.
# Keep this list narrow: only scanner-specific images, not base images
# that happen to include a scanner as one of many tools.
_SCANNER_STEP_IMAGES = (
    "aquasec/trivy",
    "anchore/grype",
    "snyk/snyk",
    "goodwithtech/dockle",
    "opensecurity/clair-scanner",
)


def _has_scanner_step_image(doc: dict[str, Any]) -> bool:
    """Return True if any Cloud Build step ``name:`` refers to a known scanner image."""
    steps = doc.get("steps")
    if not isinstance(steps, list):
        return False
    for step in steps:
        if not isinstance(step, dict):
            continue
        name = step.get("name")
        if not isinstance(name, str):
            continue
        name_lower = name.lower()
        if any(img in name_lower for img in _SCANNER_STEP_IMAGES):
            return True
    return False


RULE = Rule(
    id="GCB-008",
    title="No vulnerability scanning step in Cloud Build pipeline",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-VULN-SCAN",),
    cwe=("CWE-1104",),
    recommendation=(
        "Add a step that runs a vulnerability scanner, trivy, grype, "
        "snyk test, npm audit, pip-audit, osv-scanner, or govulncheck. "
        "In Cloud Build this typically looks like a step with "
        "``name: aquasec/trivy`` or an ``entrypoint: bash`` step that "
        "invokes ``trivy image`` / ``grype <ref>`` on the built image."
    ),
    docs_note=(
        "The detector matches tool names anywhere in the document, "
        "step images, ``args``, or ``entrypoint`` strings. Container "
        "Analysis API scanning configured at the project level counts "
        "as compensating control but is out of scope for this YAML-only "
        "check; if you rely on it, suppress this rule via ``--checks``."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    passed = has_vuln_scanning(doc) or _has_scanner_step_image(doc)
    desc = (
        "Pipeline invokes a vulnerability scanner (trivy / grype / "
        "snyk / pip-audit / osv-scanner)."
        if passed else
        "No vulnerability scanner (trivy / grype / snyk / npm audit / "
        "pip-audit / osv-scanner / govulncheck) is invoked by any step."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
