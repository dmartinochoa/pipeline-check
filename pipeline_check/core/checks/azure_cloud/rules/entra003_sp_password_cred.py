"""ENTRA-003. Service principal uses password credential instead of certificate."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="ENTRA-003",
    title="Service principal uses password credential",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-287",),
    recommendation=(
        "Replace client-secret (password) credentials with certificate "
        "credentials or managed identities. Certificate authentication "
        "eliminates the risk of secret leakage in logs, environment "
        "variables, or pipeline definitions."
    ),
    docs_note=(
        "Password credentials (client secrets) are string tokens that "
        "can be copy-pasted, logged, or leaked. Certificate "
        "credentials bind to a key pair; the private key never leaves "
        "the host."
    ),
    exploit_example=(
        "A service principal authenticates with a client secret stored "
        "in the pipeline. The secret leaks through a build log, a "
        "committed .env, or an environment dump, and because it's a "
        "bearer string an attacker authenticates as the principal from "
        "anywhere. A certificate credential can't be copy-pasted out "
        "the same way: the private key never leaves the host."
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for sp in catalog.service_principals():
        sp_name = sp.get("displayName", "<unnamed>")
        sp_id = sp.get("id", "<unknown>")
        app_id = sp.get("appId", "")
        has_password = bool(sp.get("passwordCredentials"))
        has_key = bool(sp.get("keyCredentials"))
        if not has_password and not has_key:
            continue
        passed = not has_password
        if passed:
            desc = (
                f"Service principal '{sp_name}' (appId={app_id}) uses "
                "certificate credentials only."
            )
        else:
            desc = (
                f"Service principal '{sp_name}' (appId={app_id}) has "
                "password credentials configured. Password credentials "
                "are string tokens vulnerable to leakage."
            )
        findings.append(Finding(
            check_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            resource=f"{sp_name} ({sp_id})",
            description=desc,
            recommendation=RULE.recommendation,
            passed=passed,
        ))
    return findings
