"""ECR-003 — ECR repository policy allows wildcard / public principal."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="ECR-003",
    title="Repository policy allows public access",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-8",),
    cwe=("CWE-732",),
    recommendation=(
        "Remove wildcard principals from the repository policy. Grant access "
        "only to specific AWS account IDs or IAM principals that require it."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    client = catalog.client("ecr")
    for repo in catalog.ecr_repositories():
        name = repo.get("repositoryName", "<unnamed>")
        try:
            resp = client.get_repository_policy(repositoryName=name)
            policy = json.loads(resp.get("policyText", "{}"))
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "")
            if error_code == "RepositoryPolicyNotFoundException":
                findings.append(Finding(
                    check_id=RULE.id, title=RULE.title, severity=RULE.severity,
                    resource=name,
                    description="No resource-based policy is attached; repository is private.",
                    recommendation=(
                        "Keep the repository private. If cross-account access is "
                        "needed, restrict the policy to specific account principals."
                    ),
                    passed=True,
                ))
                continue
            findings.append(Finding(
                check_id=RULE.id, title=RULE.title, severity=RULE.severity,
                resource=name,
                description=f"Could not retrieve repository policy: {exc}",
                recommendation="Verify IAM permissions include ecr:GetRepositoryPolicy.",
                passed=False,
            ))
            continue

        public_statements = [
            s for s in policy.get("Statement", [])
            if s.get("Effect") == "Allow"
            and (
                s.get("Principal") == "*"
                or s.get("Principal", {}).get("AWS") == "*"
                or s.get("Principal", {}).get("Service") == "*"
            )
        ]
        passed = not public_statements
        if passed:
            desc = "Repository policy does not grant public access."
        else:
            desc = (
                "The repository policy contains statements that allow unauthenticated "
                "or public access (Principal: '*'). This could expose proprietary "
                "images or allow unauthorised parties to push images."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
