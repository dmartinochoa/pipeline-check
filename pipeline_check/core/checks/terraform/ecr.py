"""Terraform ECR checks.

ECR-001  Image scanning on push not enabled            HIGH      CICD-SEC-3
ECR-002  Image tags are mutable                        HIGH      CICD-SEC-9
ECR-003  Repository policy allows public access        CRITICAL  CICD-SEC-8
ECR-004  No lifecycle policy configured                LOW       CICD-SEC-7
ECR-005  Repository encrypted with AES256 not KMS CMK  MEDIUM    CICD-SEC-9
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
            findings.append(_ecr005_kms_encryption(r.values, name))
        return findings


def _ecr001_scan_on_push(values: dict, name: str) -> Finding:
    scan_cfg = _first(values.get("image_scanning_configuration"))
    enabled = bool(scan_cfg.get("scan_on_push", False))
    desc = (
        "Image scanning on push is enabled."
        if enabled else
        "Image scanning on push is disabled."
    )
    return Finding(
        check_id="ECR-001",
        title="Image scanning on push not enabled",
        severity=Severity.HIGH,
        resource=name,
        description=desc,
        recommendation="Set image_scanning_configuration { scan_on_push = true }.",
        passed=enabled,
    )


def _ecr002_tag_mutability(values: dict, name: str) -> Finding:
    mutability = values.get("image_tag_mutability") or "MUTABLE"
    passed = mutability == "IMMUTABLE"
    desc = (
        "Image tags are immutable."
        if passed else
        "Image tag mutability is MUTABLE."
    )
    return Finding(
        check_id="ECR-002",
        title="Image tags are mutable",
        severity=Severity.HIGH,
        resource=name,
        description=desc,
        recommendation="Set image_tag_mutability = \"IMMUTABLE\".",
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
                "Keep the repository private, restricting to specific principals "
                "if cross-account access is required."
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
            recommendation="Verify the policy is valid JSON.",
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
        "The repository policy contains statements that allow public access "
        "(Principal: '*')."
    )
    return Finding(
        check_id="ECR-003",
        title="Repository policy allows public access",
        severity=Severity.CRITICAL,
        resource=name,
        description=desc,
        recommendation="Remove wildcard principals from the repository policy.",
        passed=passed,
    )


def _ecr004_lifecycle_policy(has_policy: bool, name: str) -> Finding:
    desc = (
        "A lifecycle policy is configured on the repository."
        if has_policy else
        "No lifecycle policy is configured."
    )
    return Finding(
        check_id="ECR-004",
        title="No lifecycle policy configured",
        severity=Severity.LOW,
        resource=name,
        description=desc,
        recommendation=(
            "Add an aws_ecr_lifecycle_policy that expires untagged images."
        ),
        passed=has_policy,
    )


def _ecr005_kms_encryption(values: dict, name: str) -> Finding:
    enc = _first(values.get("encryption_configuration"))
    enc_type = (enc.get("encryption_type") or "AES256")
    kms_key = enc.get("kms_key")
    passed = enc_type == "KMS" and bool(kms_key)

    if passed:
        desc = f"Repository uses KMS encryption with key {kms_key}."
    else:
        desc = (
            f"Repository encryption_type is {enc_type!r} and kms_key="
            f"{kms_key!r}. AES256 uses an AWS-managed key, which cannot be "
            f"audited or restricted via key policies."
        )
    return Finding(
        check_id="ECR-005",
        title="Repository encrypted with AES256 rather than KMS CMK",
        severity=Severity.MEDIUM,
        resource=name,
        description=desc,
        recommendation=(
            "Set encryption_configuration { encryption_type = \"KMS\" "
            "kms_key = aws_kms_key.ecr.arn } using a customer-managed key "
            "with a restrictive key policy."
        ),
        passed=passed,
    )
