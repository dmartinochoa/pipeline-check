"""CB-005. CodeBuild project uses an outdated AWS-managed standard image."""
from __future__ import annotations

from ..._patterns import LATEST_STANDARD_VERSION, MANAGED_IMAGE_RE
from ...base import Confidence, Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CB-005",
    title="Outdated managed build image",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    cwe=("CWE-1104",),
    recommendation=(
        f"Update the CodeBuild environment image to "
        f"aws/codebuild/standard:{LATEST_STANDARD_VERSION}.0 or later "
        f"to ensure the build environment receives the latest security patches."
    ),
    docs_note=(
        "Only AWS-managed ``aws/codebuild/standard:N.0`` images are "
        "version-checked. Custom or third-party images pass here, "
        "CB-009 handles the separate concern of tag vs digest pinning "
        "for custom images."
    ),
    known_fp=(
        "One version behind the current "
        "``aws/codebuild/standard`` is a hygiene warning, not a "
        "production issue, and defaults to MEDIUM confidence. "
        "The rule emits HIGH only when the project is two or "
        "more versions behind. Custom or third-party images are "
        "not version-checked here; CB-009 handles tag-vs-digest "
        "pinning for those.",
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for project in catalog.codebuild_projects():
        name = project.get("name", "<unnamed>")
        image = project.get("environment", {}).get("image", "")
        match = MANAGED_IMAGE_RE.search(image)
        confidence_locked = False
        if match:
            version = int(match.group(1))
            passed = version >= LATEST_STANDARD_VERSION
            if passed:
                desc = (
                    f"Project uses the current managed image "
                    f"(aws/codebuild/standard:{version}.0)."
                )
            else:
                desc = (
                    f"Project uses aws/codebuild/standard:{version}.0, which is "
                    f"outdated (latest: {LATEST_STANDARD_VERSION}.0). Older images "
                    f"may contain unpatched OS packages, runtimes, or tools that "
                    f"introduce supply-chain risk."
                )
                # Two-or-more versions behind is an unambiguous staleness
                # signal: lock HIGH so the scanner's blanket MEDIUM demotion
                # (which targets the one-behind hygiene case) does not apply.
                if version <= LATEST_STANDARD_VERSION - 2:
                    confidence_locked = True
        else:
            passed = True
            desc = (
                f"Project uses a non-standard image ({image!r}); "
                f"automated version check skipped. Ensure this image is regularly "
                f"updated and sourced from a trusted registry."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
            confidence=Confidence.HIGH, confidence_locked=confidence_locked,
        ))
    return findings
