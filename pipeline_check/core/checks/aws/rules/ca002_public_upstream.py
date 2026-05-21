"""CA-002. CodeArtifact repository connects to ``public:*`` upstream."""
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
    docs_note=(
        "An external connection to ``public:npmjs`` / ``public:pypi`` "
        "/ ``public:nuget`` / ``public:maven-central`` fetches packages "
        "from the public registry on first resolution. A typo-squat "
        "(``request`` vs ``requests``) or a compromised upstream lands "
        "in the cache the first time anyone names it; every subsequent "
        "build pulls the cached substitute. The pull-through cache "
        "with an allow-list is the same risk shape solved by an "
        "explicit allowlist."
    ),
    exploit_example=(
        "# Vulnerable: a CodeArtifact repository wired to a public\n"
        "# upstream (npm.org / pypi.org / maven-central) without\n"
        "# allow-listing. Internal package names harvested from\n"
        "# repo manifests can be claimed on the public upstream\n"
        "# with a higher version; CodeArtifact resolves them via\n"
        "# the public upstream and ships attacker code to every\n"
        "# consumer (Birsan dependency confusion).\n"
        "import boto3\n"
        "ca = boto3.client('codeartifact')\n"
        "ca.create_repository(\n"
        "    domain='myorg', repository='shared',\n"
        "    upstreams=[{'repositoryName': 'public-pypi-store'}],\n"
        "    externalConnections=['public:pypi']\n"
        ")\n"
        "\n"
        "# Safe: drop the public external connection. Mirror only\n"
        "# the packages your org actually needs into a curated\n"
        "# internal upstream so an arbitrary public publisher\n"
        "# can't poison resolution.\n"
        "ca.delete_repository_permissions_policy(\n"
        "    domain='myorg', repository='shared'\n"
        ")\n"
        "ca.disassociate_external_connection(\n"
        "    domain='myorg', repository='shared',\n"
        "    externalConnection='public:pypi'\n"
        ")"
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
