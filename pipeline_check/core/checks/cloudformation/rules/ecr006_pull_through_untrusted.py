"""ECR-006 (CloudFormation). ECR pull-through cache uses untrusted upstream."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..phase3 import _ecr006

RULE = Rule(
    id="ECR-006",
    title="ECR pull-through cache rule uses an untrusted upstream",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    cwe=("CWE-829",),
    recommendation=(
        "Either scope ``UpstreamRegistryUrl`` to a trusted registry "
        "(``public.ecr.aws``, ``registry.k8s.io``, ``ghcr.io``, "
        "``gcr.io``) or set ``CredentialArn`` so the upstream "
        "authenticates the pull."
    ),
    docs_note=(
        "Reads ``AWS::ECR::PullThroughCacheRule."
        "Properties.{UpstreamRegistryUrl,CredentialArn}``. Fires "
        "when the upstream is not on the trusted allow-list AND no "
        "credential ARN is configured."
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return _ecr006(ctx)
