"""ECR-006 — ECR pull-through cache rule has an untrusted upstream registry."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="ECR-006",
    title="ECR pull-through cache rule uses an untrusted upstream",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    cwe=("CWE-829",),
    recommendation=(
        "Scope pull-through cache rules to AWS-trusted registries (ECR "
        "Public, Quay.io with authentication, or a vetted private registry). "
        "Avoid wildcard or unauthenticated upstreams — a malicious image "
        "there gets cached into your account registry on first pull."
    ),
    docs_note=(
        "AWS supports pull-through cache for ECR Public, Quay, K8s, GitHub "
        "Container Registry, GitLab, and Docker Hub. A rule pointing at "
        "``registry-1.docker.io`` without an authenticated credential "
        "silently caches whatever the public namespace resolves to."
    ),
)

#: Registry hostnames that are safe by policy (explicit allow-list).
_TRUSTED = {
    "public.ecr.aws",
    "registry.k8s.io",
    "ghcr.io",
    "gcr.io",
}


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for rule_row in catalog.ecr_pull_through_cache_rules():
        prefix = rule_row.get("ecrRepositoryPrefix", "<unnamed>")
        upstream = rule_row.get("upstreamRegistryUrl", "") or ""
        has_credential = bool(rule_row.get("credentialArn"))
        passed = upstream in _TRUSTED or has_credential
        desc = (
            f"Pull-through prefix '{prefix}' uses upstream {upstream}"
            + (" with an authenticated credential." if has_credential else " (on trusted allow-list).")
            if passed else
            f"Pull-through prefix '{prefix}' uses upstream {upstream!r} with "
            "no authenticated credential — any image published under that "
            "namespace gets cached into this account."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=prefix, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
