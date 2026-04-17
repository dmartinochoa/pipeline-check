"""CA-002 — CodeArtifact repository connects to ``public:*`` upstream."""
from __future__ import annotations

from botocore.exceptions import ClientError

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CA-002",
    title="CodeArtifact repository has a public external connection",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    cwe=("CWE-829",),
    recommendation=(
        "Route public package consumption through a pull-through cache "
        "repository governed by an allow-list of package names, and point "
        "build-time repos at that cache rather than directly at "
        "``public:npmjs``/``public:pypi``. Unscoped public upstreams expose "
        "builds to dependency-confusion and typosquatting attacks."
    ),
)

_PUBLIC_PREFIXES = ("public:",)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    client = catalog.client("codeartifact")
    for repo in catalog.codeartifact_repositories():
        name = repo.get("name", "<unnamed>")
        domain = repo.get("domainName", "")
        if not domain:
            continue
        try:
            detail = client.describe_repository(domain=domain, repository=name)
        except ClientError:
            continue
        connections = (detail.get("repository") or {}).get("externalConnections", []) or []
        public = [c.get("externalConnectionName") for c in connections
                  if (c.get("externalConnectionName") or "").startswith(_PUBLIC_PREFIXES)]
        passed = not public
        desc = (
            f"Repo '{name}' has no direct public external connections."
            if passed else
            f"Repo '{name}' connects directly to public upstream(s): {', '.join(public)}."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=f"{domain}/{name}", description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
