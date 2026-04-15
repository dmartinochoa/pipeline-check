"""Terraform ECR checks (ECR-001 … ECR-004).

Primary resource: ``aws_ecr_repository``.
ECR-003 joins against ``aws_ecr_repository_policy`` by repository name.
ECR-004 joins against ``aws_ecr_lifecycle_policy`` by repository name.
"""
from __future__ import annotations

import json

from .base import TerraformBaseCheck
from ..base import Finding, Severity


def _first(block_list: list | None) -> dict:
    if not block_list:
        return {}
    return block_list[0] or {}


class ECRChecks(TerraformBaseCheck):

    def run(self) -> list[Finding]:
        # Index ancillary resources by repository name.
        policies: dict[str, str] = {}
        for r in self.ctx.resources("aws_ecr_repository_policy"):
            repo = r.values.get("repository")
            if repo:
                policies[repo] = r.values.get("policy", "") or ""

        lifecycles: set[str] = set()
        for r in self.ctx.resources("aws_ecr_lifecycle_policy"):
            repo = r.values.get("repository")
            if repo:
                lifecycles.add(repo)

        findings: list[Finding] = []
        for r in self.ctx.resources("aws_ecr_repository"):
            name = r.values.get("name") or r.name
            findings.append(_ecr001_scan_on_push(r.values, name))
            findings.append(_ecr002_tag_mutability(r.values, name))
            findings.append(_ecr003_public_policy(policies.get(name), name))
            findings.append(_ecr004_lifecycle_policy(name in lifecycles, name))
        return findings


def _ecr001_scan_on_push(values: dict, name: str) -> Finding:
    scan_cfg = _first(values.get("image_scanning_configuration"))
    enabled = bool(scan_cfg.get("scan_on_push", False))
    desc = (
        "Image scanning on push is enabled."
        if enabled else
        "Image scanning on push is disabled. Vulnerabilities in base images "
        "or dependencies will not be detected when images are pushed."
    )
    return Finding(
        check_id="ECR-001",
        title="Image scanning on push not enabled",
        severity=Severity.HIGH,
        resource=name,
        description=desc,
        recommendation=(
            "Set image_scanning_configuration { scan_on_push = true } on the "
            "repository."
        ),
        passed=enabled,
    )


def _ecr002_tag_mutability(values: dict, name: str) -> Finding:
    mutability = values.get("image_tag_mutability") or "MUTABLE"
    passed = mutability == "IMMUTABLE"
    desc = (
        "Image tags are immutable — pushed tags cannot be overwritten."
        if passed else
        "Image tag mutability is MUTABLE. Any principal with ecr:PutImage can "
        "silently overwrite a tag, allowing a malicious or accidental image "
        "swap to affect deployments that pull by tag."
    )
    return Finding(
        check_id="ECR-002",
        title="Image tags are mutable",
        severity=Severity.HIGH,
        resource=name,
        description=desc,
        recommendation=(
            "Set image_tag_mutability = \"IMMUTABLE\" on the repository."
        ),
        passed=passed,
    )


def _ecr003_public_policy(policy_text: str | None, name: str) -> Finding:
    if not policy_text:
        return Finding(
            check_id="ECR-003",
            title="Repository policy allows public access",
            severity=Severity.CRITICAL,
            resource=name,
            description="No resource-based policy is attached; repository is private.",
            recommendation=(
                "Keep the repository private. If cross-account access is needed, "
                "restrict the policy to specific account principals."
            ),
            passed=True,
        )

    try:
        policy = json.loads(policy_text)
    except (TypeError, json.JSONDecodeError):
        return Finding(
            check_id="ECR-003",
            title="Repository policy allows public access",
            severity=Severity.CRITICAL,
            resource=name,
            description="Could not parse repository policy JSON.",
            recommendation="Verify the policy document is valid JSON.",
            passed=False,
        )

    public = [
        s for s in policy.get("Statement", [])
        if s.get("Effect") == "Allow"
        and (
            s.get("Principal") == "*"
            or (isinstance(s.get("Principal"), dict) and (
                s["Principal"].get("AWS") == "*"
                or s["Principal"].get("Service") == "*"
            ))
        )
    ]
    passed = not public
    desc = (
        "Repository policy does not grant public access."
        if passed else
        "The repository policy contains statements that allow unauthenticated "
        "or public access (Principal: '*')."
    )
    return Finding(
        check_id="ECR-003",
        title="Repository policy allows public access",
        severity=Severity.CRITICAL,
        resource=name,
        description=desc,
        recommendation=(
            "Remove wildcard principals from the repository policy. Grant "
            "access only to specific AWS account IDs or IAM principals."
        ),
        passed=passed,
    )


def _ecr004_lifecycle_policy(has_policy: bool, name: str) -> Finding:
    desc = (
        "A lifecycle policy is configured on the repository."
        if has_policy else
        "No lifecycle policy is configured. Without automated cleanup, old "
        "and potentially vulnerable images accumulate indefinitely."
    )
    return Finding(
        check_id="ECR-004",
        title="No lifecycle policy configured",
        severity=Severity.LOW,
        resource=name,
        description=desc,
        recommendation=(
            "Add an aws_ecr_lifecycle_policy resource that expires untagged "
            "images and caps retained tagged images."
        ),
        passed=has_policy,
    )
