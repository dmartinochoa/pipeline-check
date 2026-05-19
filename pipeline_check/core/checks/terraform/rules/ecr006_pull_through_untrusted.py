"""ECR-006 (Terraform). ECR pull-through cache uses untrusted upstream."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import TerraformContext
from ..phase3 import _ecr006

RULE = Rule(
    id="ECR-006",
    title="ECR pull-through cache rule uses an untrusted upstream",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    cwe=("CWE-829",),
    recommendation=(
        "Either scope ``upstream_registry_url`` to a trusted registry "
        "(``public.ecr.aws``, ``registry.k8s.io``, ``ghcr.io``, "
        "``gcr.io``) or set ``credential_arn`` so the upstream "
        "registry authenticates the pull."
    ),
    docs_note=(
        "Reads "
        "``aws_ecr_pull_through_cache_rule.{upstream_registry_url,"
        "credential_arn}``. Fires when the upstream is not on the "
        "trusted allow-list AND no credential ARN is configured — "
        "the cache then proxies any image from an attacker-controlled "
        "domain into your registry."
    ),
)


def check(ctx: TerraformContext) -> list[Finding]:
    return _ecr006(ctx)
