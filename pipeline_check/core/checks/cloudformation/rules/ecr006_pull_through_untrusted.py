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
    exploit_example=(
        "# Vulnerable: pull-through cache rule against an\n"
        "# untrusted upstream. A compromise of the upstream\n"
        "# lands bytes in your registry and ships to every\n"
        "# consumer.\n"
        "Resources:\n"
        "  Cache:\n"
        "    Type: AWS::ECR::PullThroughCacheRule\n"
        "    Properties:\n"
        "      EcrRepositoryPrefix: internal-mirror\n"
        "      UpstreamRegistryUrl: https://rando-mirror.example.com\n"
        "\n"
        "# Safe: pull-through caches only against well-known\n"
        "# upstreams (Docker Hub Verified, ECR Public, Quay,\n"
        "# k8s.io).\n"
        "Resources:\n"
        "  Cache:\n"
        "    Type: AWS::ECR::PullThroughCacheRule\n"
        "    Properties:\n"
        "      EcrRepositoryPrefix: public-cache\n"
        "      UpstreamRegistryUrl: https://public.ecr.aws"
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return _ecr006(ctx)
