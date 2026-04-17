"""CB-008 — CodeBuild buildspec is declared inline rather than sourced from the repo."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CB-008",
    title="CodeBuild buildspec is inline (not sourced from a protected repo)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    cwe=("CWE-829",),
    recommendation=(
        "Remove the inline buildspec and store buildspec.yml in the source "
        "repository under branch protection. Anyone with codebuild:UpdateProject "
        "can silently rewrite an inline buildspec; repository-sourced buildspecs "
        "inherit the repo's review and protection controls."
    ),
    docs_note=(
        "An inline buildspec (source.buildspec set to YAML text, or a S3 URL) "
        "bypasses the protections that cover your source code. A user with "
        "``codebuild:UpdateProject`` can rewrite the build commands without "
        "touching the repository — no PR review, no branch protection, no audit "
        "of what changed. Store buildspec.yml in the repo instead."
    ),
)


def _is_inline(buildspec: str) -> bool:
    """Return True when *buildspec* is inline YAML rather than a repo path.

    CodeBuild accepts three shapes:
    - Empty / missing  -> buildspec.yml from the source root (safe)
    - ``path/to/file`` -> relative path in the source repo (safe)
    - Multi-line YAML  -> inline (unsafe)
    - ``arn:aws:s3:::`` -> inline from S3 (unsafe, external to repo)
    """
    if not buildspec:
        return False
    text = buildspec.strip()
    if text.startswith("arn:aws:s3:::") or text.startswith("s3://"):
        return True
    # A single-line relative path never contains a newline, colon, or
    # pipe. Anything multi-line or containing a YAML block marker is
    # inline content.
    if "\n" in text or text.startswith(("version:", "phases:", "|", ">")):
        return True
    return False


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for project in catalog.codebuild_projects():
        name = project.get("name", "<unnamed>")
        source = project.get("source") or {}
        buildspec = source.get("buildspec") or ""
        inline = _is_inline(buildspec)
        if inline:
            location = "S3" if buildspec.strip().startswith(("arn:aws:s3:::", "s3://")) else "inline YAML"
            desc = (
                f"CodeBuild project '{name}' uses a buildspec stored as "
                f"{location}, not in the source repository. Build commands "
                "can be rewritten without any source-repo review."
            )
        else:
            desc = (
                f"CodeBuild project '{name}' sources its buildspec from the repository."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=not inline,
        ))
    return findings
