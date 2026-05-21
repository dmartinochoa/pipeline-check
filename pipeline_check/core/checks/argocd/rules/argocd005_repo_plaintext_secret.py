"""ARGOCD-005. argocd-cm repository entry stores plaintext credentials."""
from __future__ import annotations

from typing import Any

import yaml

from ...base import Finding, Severity, safe_load_yaml
from ...rule import Rule
from ..base import ArgoCDContext, argocd_cm

RULE = Rule(
    id="ARGOCD-005",
    title="Argo CD repository entry stores plaintext credentials",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798",),
    recommendation=(
        "Don't write ``password`` / ``sshPrivateKey`` / "
        "``tlsClientCertKey`` values directly into the "
        "``repositories`` block of ``argocd-cm``. Move the entry to "
        "a separate Kubernetes ``Secret`` carrying the credential "
        "(plus the ``argocd.argoproj.io/secret-type: repository`` "
        "label) and reference it; or move the whole repo block to a "
        "``Secret`` of type ``repo-creds``. ConfigMap data is "
        "world-readable to every namespace member with "
        "``configmaps: get``."
    ),
    docs_note=(
        "Parses ``data.repositories`` (and the legacy ``repository.credentials`` "
        "key) on ``argocd-cm`` as YAML. For each entry, fires when a "
        "``password``, ``sshPrivateKey``, ``tlsClientCertKey``, or "
        "``githubAppPrivateKey`` field is a literal non-empty "
        "string. Entries using the documented "
        "``passwordSecret`` / ``sshPrivateKeySecret`` indirection "
        "pass."
    ),
    exploit_example=(
        "# Vulnerable: the repo password is a literal value in a\n"
        "# ConfigMap any cluster reader can fetch.\n"
        "apiVersion: v1\n"
        "kind: ConfigMap\n"
        "metadata: { name: argocd-cm, namespace: argocd }\n"
        "data:\n"
        "  repositories: |\n"
        "    - url: https://github.com/example/private-manifests\n"
        "      type: git\n"
        "      username: deploy-bot\n"
        "      password: ghp_examplePATvaluehere\n"
        "\n"
        "# Safe: reference a Secret instead.\n"
        "data:\n"
        "  repositories: |\n"
        "    - url: https://github.com/example/private-manifests\n"
        "      type: git\n"
        "      usernameSecret: { name: repo-creds, key: username }\n"
        "      passwordSecret: { name: repo-creds, key: password }"
    ),
)


_LITERAL_FIELDS = (
    "password", "sshPrivateKey", "tlsClientCertKey", "githubAppPrivateKey",
)


def _scan_repo_blob(blob: str) -> list[str]:
    try:
        parsed: Any = safe_load_yaml(blob)
    except yaml.YAMLError:
        return []
    if not isinstance(parsed, list):
        return []
    hits: list[str] = []
    for entry in parsed:
        if not isinstance(entry, dict):
            continue
        url = entry.get("url") if isinstance(entry.get("url"), str) else "<no-url>"
        for field in _LITERAL_FIELDS:
            v = entry.get(field)
            if isinstance(v, str) and v.strip():
                hits.append(f"{url}: literal {field}")
    return hits


def check(ctx: ArgoCDContext) -> Finding:
    cm = argocd_cm(ctx)
    if cm is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argocd",
            description="No argocd-cm ConfigMap to check.",
            recommendation="No action required.", passed=True,
        )
    data = cm.data.get("data") or {}
    if not isinstance(data, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argocd",
            description="argocd-cm has no data map.",
            recommendation="No action required.", passed=True,
        )
    offenders: list[str] = []
    for key in ("repositories", "repository.credentials"):
        blob = data.get(key)
        if isinstance(blob, str):
            for h in _scan_repo_blob(blob):
                offenders.append(f"data.{key}: {h}")
    passed = not offenders
    desc = (
        "No literal repo credentials in argocd-cm."
        if passed else
        f"{len(offenders)} plaintext credential field(s): "
        f"{'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argocd", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
