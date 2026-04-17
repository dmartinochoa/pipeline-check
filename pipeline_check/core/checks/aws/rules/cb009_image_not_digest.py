"""CB-009 — CodeBuild environment image is tag-pinned, not digest-pinned."""
from __future__ import annotations

from ..._primitives.container_image import classify
from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CB-009",
    title="CodeBuild image not pinned by digest",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3",),
    cwe=("CWE-494", "CWE-829"),
    recommendation=(
        "Pin custom CodeBuild images by ``@sha256:<digest>``. Tag-based "
        "references (``:latest``, ``:1.2.3``) can be silently overwritten "
        "to point at a malicious layer that is pulled on the next build."
    ),
    docs_note=(
        "CodeBuild pulls the environment image on every build. A tag pointer "
        "can be moved by whoever controls the registry; a digest cannot. "
        "AWS-managed ``aws/codebuild/...`` images are exempt — those are "
        "covered by CB-005 and are not part of the tag-mutation threat model."
    ),
)

def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for project in catalog.codebuild_projects():
        name = project.get("name", "<unnamed>")
        image = (project.get("environment") or {}).get("image", "") or ""
        info = classify(image)
        if not image or info.aws_managed:
            passed = True
            desc = (
                f"CodeBuild project '{name}' uses an AWS-managed image "
                f"({image or '<unset>'}); digest pinning is managed by AWS."
            )
        elif info.digest:
            passed = True
            desc = f"CodeBuild project '{name}' pins its image by sha256 digest."
        else:
            passed = False
            desc = (
                f"CodeBuild project '{name}' uses image {image!r}, which is "
                "tag-pinned. A malicious push to that tag would be pulled on "
                "the next build."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
