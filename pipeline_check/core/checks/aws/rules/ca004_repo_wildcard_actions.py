"""CA-004. CodeArtifact repo permissions policy grants codeartifact:* with Resource *."""
from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from ..._iam_policy import as_list, iter_allow
from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CA-004",
    title="CodeArtifact repo policy grants ``codeartifact:*`` with ``Resource '*'``",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-732",),
    recommendation=(
        "Scope Allow statements to specific ``codeartifact:`` actions "
        "(e.g. ``codeartifact:ReadFromRepository``) and to specific "
        "package-group ARNs. Wildcard action + wildcard resource is the "
        "classic over-broad grant that lets a consumer also publish."
    ),
    docs_note=(
        "``codeartifact:*`` on ``Resource: '*'`` collapses the entire "
        "repository's authority into one grant: the holder can read, "
        "write, delete, dispose, and re-publish every package. Even "
        "for a service principal that nominally only consumes "
        "packages, the grant lets a compromise of that consumer "
        "rewrite every dependency the team relies on."
    ),
    exploit_example=(
        "# Vulnerable: ``codeartifact:*`` on ``Resource: *``. The\n"
        "# bound principal can DeleteRepository,\n"
        "# DisposePackageVersions, UpdatePackageVersionsStatus\n"
        "# (mark malicious versions as Published), and PutRepository\n"
        "# PermissionsPolicy on every repo in every domain.\n"
        "{\n"
        "  \"Version\": \"2012-10-17\",\n"
        "  \"Statement\": [{\n"
        "    \"Effect\": \"Allow\",\n"
        "    \"Action\": \"codeartifact:*\",\n"
        "    \"Resource\": \"*\"\n"
        "  }]\n"
        "}\n"
        "\n"
        "# Safe: enumerate the verbs the workload actually needs\n"
        "# and scope ``Resource`` to the specific repo / domain.\n"
        "{\n"
        "  \"Version\": \"2012-10-17\",\n"
        "  \"Statement\": [{\n"
        "    \"Effect\": \"Allow\",\n"
        "    \"Action\": [\n"
        "      \"codeartifact:GetPackageVersionAsset\",\n"
        "      \"codeartifact:ReadFromRepository\"\n"
        "    ],\n"
        "    \"Resource\": [\n"
        "      \"arn:aws:codeartifact:us-east-1:123456789012:repository/myorg/shared\",\n"
        "      \"arn:aws:codeartifact:us-east-1:123456789012:package/myorg/shared/*/*/*\"\n"
        "    ]\n"
        "  }]\n"
        "}"
    ),
)


def _has_wildcard(doc: dict[str, Any]) -> bool:
    for stmt in iter_allow(doc):
        actions = as_list(stmt.get("Action"))
        has_wild = any(
            a in ("*", "codeartifact:*") for a in actions if isinstance(a, str)
        )
        resources = as_list(stmt.get("Resource"))
        if has_wild and (not resources or "*" in resources):
            return True
    return False


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    client = catalog.client("codeartifact")
    for repo in catalog.codeartifact_repositories():
        name = repo.get("name", "<unnamed>")
        domain = repo.get("domainName", "")
        if not domain:
            continue
        try:
            resp = client.get_repository_permissions_policy(
                domain=domain, repository=name,
            )
        except ClientError:
            continue
        raw = (resp.get("policy") or {}).get("document")
        if not raw:
            continue
        try:
            doc = json.loads(raw) if isinstance(raw, str) else raw
        except (TypeError, json.JSONDecodeError):
            continue
        over_broad = _has_wildcard(doc)
        passed = not over_broad
        desc = (
            f"Repo '{name}' policy scopes actions or resources appropriately."
            if passed else
            f"Repo '{name}' policy grants codeartifact:* with Resource '*'."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=f"{domain}/{name}", description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
