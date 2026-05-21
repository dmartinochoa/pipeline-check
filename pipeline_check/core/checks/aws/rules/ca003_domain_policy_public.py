"""CA-003. CodeArtifact domain permissions policy allows wildcard principals."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from ..._iam_policy import iter_allow, public_principal
from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="CA-003",
    title="CodeArtifact domain policy allows cross-account wildcard",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-8",),
    cwe=("CWE-732",),
    recommendation=(
        "Remove Allow statements with ``Principal: '*'`` from every "
        "CodeArtifact domain permissions policy, or restrict them with an "
        "``aws:PrincipalOrgID`` condition so only accounts in your org can "
        "consume packages from the domain."
    ),
    docs_note=(
        "A wildcard-principal Allow on a CodeArtifact domain lets any "
        "AWS account reach the domain's permissions surface. The "
        "exact damage depends on the action set, but at minimum it "
        "lets external accounts read package names and versions, "
        "which is enough for typosquat-against-private-package "
        "attacks. ``aws:PrincipalOrgID`` is the org-level rescue "
        "without enumerating accounts."
    ),
    exploit_example=(
        "# Vulnerable: CodeArtifact domain policy with\n"
        "# ``Principal: '*'`` and no condition. Any AWS principal\n"
        "# in any account can pull artifacts from the domain;\n"
        "# private package names + versions are also discoverable.\n"
        "{\n"
        "  \"Version\": \"2012-10-17\",\n"
        "  \"Statement\": [{\n"
        "    \"Effect\": \"Allow\",\n"
        "    \"Principal\": \"*\",\n"
        "    \"Action\": [\"codeartifact:GetPackageVersion*\"],\n"
        "    \"Resource\": \"*\"\n"
        "  }]\n"
        "}\n"
        "\n"
        "# Safe: scope ``Principal`` to your org's account IDs (or\n"
        "# use the ``aws:PrincipalOrgID`` condition with your\n"
        "# Organizations org ID). External access is denied by\n"
        "# default unless explicitly granted.\n"
        "{\n"
        "  \"Version\": \"2012-10-17\",\n"
        "  \"Statement\": [{\n"
        "    \"Effect\": \"Allow\",\n"
        "    \"Principal\": {\"AWS\": \"*\"},\n"
        "    \"Action\": [\"codeartifact:GetPackageVersion*\"],\n"
        "    \"Resource\": \"*\",\n"
        "    \"Condition\": {\"StringEquals\": {\"aws:PrincipalOrgID\": \"o-abc123def4\"}}\n"
        "  }]\n"
        "}"
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    client = catalog.client("codeartifact")
    for domain in catalog.codeartifact_domains():
        name = domain.get("name", "<unnamed>")
        try:
            resp = client.get_domain_permissions_policy(domain=name)
        except ClientError:
            continue
        raw = (resp.get("policy") or {}).get("document")
        if not raw:
            continue
        try:
            doc = json.loads(raw) if isinstance(raw, str) else raw
        except (TypeError, json.JSONDecodeError):
            continue
        offenders = [
            idx for idx, stmt in enumerate(iter_allow(doc))
            if public_principal(stmt)
        ]
        passed = not offenders
        desc = (
            f"Domain '{name}' policy has no wildcard-principal Allow."
            if passed else
            f"Domain '{name}' policy Allow statement(s) {offenders} grant "
            "access to Principal: '*'."
        )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
        ))
    return findings
