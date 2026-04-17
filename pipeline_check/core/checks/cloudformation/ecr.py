"""CloudFormation ECR checks — ECR-001..005.

Resource policies and lifecycle policies are inline on AWS::ECR::Repository
(``RepositoryPolicyText`` and ``LifecyclePolicy.LifecyclePolicyText``) —
there are no separate CFN resources for them.
"""
from __future__ import annotations

import json

from ..base import Finding, Severity
from .base import CloudFormationBaseCheck, as_str, is_true


class ECRChecks(CloudFormationBaseCheck):

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for r in self.ctx.resources("AWS::ECR::Repository"):
            name = as_str(r.properties.get("RepositoryName")) or r.logical_id
            findings.append(_ecr001_scan_on_push(r.properties, name))
            findings.append(_ecr002_tag_mutability(r.properties, name))
            findings.append(_ecr003_public_policy(r.properties, name))
            findings.append(_ecr004_lifecycle_policy(r.properties, name))
            findings.append(_ecr005_kms_encryption(r.properties, name))
        return findings


def _ecr001_scan_on_push(properties: dict, name: str) -> Finding:
    scan_cfg = properties.get("ImageScanningConfiguration") or {}
    enabled = is_true(scan_cfg.get("ScanOnPush"))
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
        recommendation="Set ImageScanningConfiguration.ScanOnPush: true.",
        passed=enabled,
    )


def _ecr002_tag_mutability(properties: dict, name: str) -> Finding:
    mutability = as_str(properties.get("ImageTagMutability")) or "MUTABLE"
    passed = mutability == "IMMUTABLE"
    desc = "Image tags are immutable." if passed else "Image tag mutability is MUTABLE."
    return Finding(
        check_id="ECR-002",
        title="Image tags are mutable",
        severity=Severity.HIGH,
        resource=name,
        description=desc,
        recommendation='Set ImageTagMutability: "IMMUTABLE".',
        passed=passed,
    )


def _ecr003_public_policy(properties: dict, name: str) -> Finding:
    policy_text = properties.get("RepositoryPolicyText")
    if not policy_text:
        return Finding(
            check_id="ECR-003",
            title="Repository policy allows public access",
            severity=Severity.CRITICAL,
            resource=name,
            description="No RepositoryPolicyText is attached; repository is private.",
            recommendation="Keep the repository private, or restrict to specific principals.",
            passed=True,
        )
    # CFN allows the policy as an inline dict (recommended) or a JSON string.
    if isinstance(policy_text, str):
        try:
            policy = json.loads(policy_text)
        except (TypeError, json.JSONDecodeError):
            return Finding(
                check_id="ECR-003",
                title="Repository policy allows public access",
                severity=Severity.CRITICAL,
                resource=name,
                description="Could not parse RepositoryPolicyText as JSON.",
                recommendation="Verify the policy document is valid JSON.",
                passed=False,
            )
    elif isinstance(policy_text, dict):
        policy = policy_text
    else:
        policy = {}
    public = [
        s for s in policy.get("Statement", [])
        if isinstance(s, dict)
        and s.get("Effect") == "Allow"
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
        "RepositoryPolicyText contains statements that allow public access "
        "(Principal: '*')."
    )
    return Finding(
        check_id="ECR-003",
        title="Repository policy allows public access",
        severity=Severity.CRITICAL,
        resource=name,
        description=desc,
        recommendation="Remove wildcard principals from RepositoryPolicyText.",
        passed=passed,
    )


def _ecr004_lifecycle_policy(properties: dict, name: str) -> Finding:
    lifecycle = properties.get("LifecyclePolicy") or {}
    has_policy = bool(lifecycle.get("LifecyclePolicyText"))
    desc = (
        "A LifecyclePolicy is configured on the repository."
        if has_policy else
        "No LifecyclePolicy is configured."
    )
    return Finding(
        check_id="ECR-004",
        title="No lifecycle policy configured",
        severity=Severity.LOW,
        resource=name,
        description=desc,
        recommendation="Add LifecyclePolicy.LifecyclePolicyText that expires untagged images.",
        passed=has_policy,
    )


def _ecr005_kms_encryption(properties: dict, name: str) -> Finding:
    enc = properties.get("EncryptionConfiguration") or {}
    enc_type = as_str(enc.get("EncryptionType")) or "AES256"
    kms_key = enc.get("KmsKey")
    passed = enc_type == "KMS" and bool(kms_key)
    if passed:
        desc = f"Repository uses KMS encryption with key {kms_key}."
    else:
        desc = (
            f"Repository EncryptionType is {enc_type!r} and KmsKey={kms_key!r}. "
            "AES256 uses an AWS-managed key, which cannot be audited via key policies."
        )
    return Finding(
        check_id="ECR-005",
        title="Repository encrypted with AES256 rather than KMS CMK",
        severity=Severity.MEDIUM,
        resource=name,
        description=desc,
        recommendation=(
            "Set EncryptionConfiguration.EncryptionType: KMS with a customer-managed KmsKey."
        ),
        passed=passed,
    )
