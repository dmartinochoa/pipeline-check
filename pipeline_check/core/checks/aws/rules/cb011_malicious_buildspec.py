"""CB-011 — CodeBuild buildspec contains indicators of malicious activity."""
from __future__ import annotations

from ..._malicious import find_malicious_patterns
from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CB-011",
    title="CodeBuild buildspec contains indicators of malicious activity",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4", "CICD-SEC-7"),
    cwe=("CWE-506", "CWE-913"),
    recommendation=(
        "Treat as a potential compromise. Identify which principal or "
        "pipeline ran the CodeBuild project recently, rotate its "
        "service role's credentials, audit CloudTrail for outbound "
        "activity to the matched hosts, and — if an inline buildspec "
        "is in use (CB-008) — enforce repo-sourced buildspecs under "
        "branch protection so the next malicious edit requires a PR."
    ),
    docs_note=(
        "Scans the ``source.buildspec`` text on every CodeBuild "
        "project for concrete attack indicators: reverse shells, "
        "base64-decoded execution, miner binaries/pools, Discord/"
        "Telegram webhooks, credential-dump pipes, audit-erasure "
        "commands. CB-011 is CRITICAL by design — a true positive is "
        "evidence of compromise, not a hygiene improvement. Repo-"
        "sourced buildspecs (not inlined) return ``NOT APPLICABLE`` "
        "because the text isn't visible to the scanner; CB-008 "
        "already flags the inline form as a governance gap."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for project in catalog.codebuild_projects():
        name = project.get("name", "<unnamed>")
        source = project.get("source") or {}
        buildspec = source.get("buildspec") or ""
        if not isinstance(buildspec, str) or not buildspec.strip():
            continue
        # Only inline buildspecs have text to scan; a path like
        # ``ci/build.yml`` is a file reference the scanner can't read.
        if "\n" not in buildspec and not buildspec.startswith(("version:", "phases:")):
            continue
        hits = find_malicious_patterns(buildspec.lower())
        if not hits:
            findings.append(Finding(
                check_id=RULE.id, title=RULE.title, severity=RULE.severity,
                resource=name,
                description=(
                    f"Inline buildspec on project '{name}' has no "
                    "detected indicators of malicious activity."
                ),
                recommendation=RULE.recommendation, passed=True,
            ))
            continue
        categories = sorted({c for c, _n, _e in hits})
        summary = "; ".join(
            f"{n} ({e!r})" for _c, n, e in hits[:3]
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name,
            description=(
                f"Inline buildspec on project '{name}' contains "
                f"{len(hits)} indicator(s) of malicious activity "
                f"({', '.join(categories)}). Examples: {summary}"
                f"{'...' if len(hits) > 3 else ''}."
            ),
            recommendation=RULE.recommendation, passed=False,
        ))
    return findings
