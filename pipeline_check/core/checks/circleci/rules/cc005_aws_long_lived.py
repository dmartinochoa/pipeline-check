"""CC-005. Jobs should not declare long-lived AWS access keys in environment blocks."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs
from ._helpers import AWS_KEY_RE

RULE = Rule(
    id="CC-005",
    title="AWS auth uses long-lived access keys in environment block",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-TOKEN-HYGIENE",),
    cwe=("CWE-522",),
    recommendation=(
        "Remove AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from the "
        "job `environment:` block. Use CircleCI's OIDC token with "
        "`aws-cli/setup` orb's role-based auth, or store credentials "
        "in a context with security group restrictions."
    ),
    docs_note=(
        "Long-lived AWS access keys declared directly in a job's "
        "`environment:` block are visible to anyone who can read the "
        "config. They cannot be rotated automatically and remain valid "
        "until manually revoked. OIDC-based federation yields short-lived "
        "credentials per build."
    ),
    exploit_example=(
        "# Vulnerable: long-lived AWS keys in a job environment: block.\n"
        "jobs:\n"
        "  deploy:\n"
        "    docker:\n"
        "      - image: cimg/base:current\n"
        "    environment:\n"
        "      AWS_ACCESS_KEY_ID: AKIA…\n"
        "      AWS_SECRET_ACCESS_KEY: …\n"
        "    steps:\n"
        "      - run: aws s3 sync ./dist s3://prod-site\n"
        "\n"
        "# Attack: the keys sit in the checked-in config, readable by\n"
        "# anyone with repo access, and land in every step's\n"
        "# environment. A leaked build log or a malicious dependency\n"
        "# exfiltrates them, and because they're long-lived IAM user\n"
        "# keys the attacker keeps AWS access until they're rotated by\n"
        "# hand.\n"
        "\n"
        "# Safe: OIDC via the aws-cli orb's role-based auth (short-lived\n"
        "# credentials per build), or a restricted context.\n"
        "jobs:\n"
        "  deploy:\n"
        "    steps:\n"
        "      - aws-cli/setup:\n"
        "          role_arn: arn:aws:iam::123456789012:role/ci-deploy"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offending_jobs: list[str] = []
    for job_id, job in iter_jobs(doc):
        env = job.get("environment")
        if not isinstance(env, dict):
            continue
        for var_name in env:
            if isinstance(var_name, str) and AWS_KEY_RE.search(var_name):
                offending_jobs.append(job_id)
                break
    passed = not offending_jobs
    desc = (
        "No job declares AWS access keys in `environment:` blocks."
        if passed else
        f"{len(offending_jobs)} job(s) declare AWS_ACCESS_KEY_ID or "
        f"AWS_SECRET_ACCESS_KEY in `environment:` blocks: "
        f"{', '.join(offending_jobs)}. Long-lived keys in config are "
        f"visible in the repository and cannot be auto-rotated."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
