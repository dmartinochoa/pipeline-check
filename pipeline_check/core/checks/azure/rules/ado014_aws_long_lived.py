"""ADO-014, pipeline should not embed long-lived AWS access keys."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs, iter_steps
from ._helpers import aws_key_in

_AWS_CONFIGURE_RE = re.compile(
    r"aws\s+configure\s+set\s+aws_access_key_id\b"
    r"|aws\s+configure\s+set\s+aws_secret_access_key\b"
)

RULE = Rule(
    id="ADO-014",
    title="AWS auth uses long-lived access keys",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-TOKEN-HYGIENE",),
    cwe=("CWE-522",),
    recommendation=(
        "Use workload identity federation or an Azure Key Vault task "
        "to inject short-lived AWS credentials at runtime. Remove "
        "static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from "
        "pipeline variables and task parameters."
    ),
    docs_note=(
        "Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` "
        "values in pipeline variables or task inputs can't be rotated "
        "on a fine-grained schedule. Prefer OIDC or vault-based "
        "credential injection for cross-cloud access."
    ),
    known_fp=(
        "The check only flags literal AKIA-shaped *values*, never "
        "variable names. The residual false positive is a literal "
        "AKIA-shaped value that is actually a deactivated or test "
        "key (a documentation sample, or a deliberately revoked "
        "credential left in place). The rule can't tell a live key "
        "from a dead one. Suppress per-pipeline via "
        "``--ignore-file`` once you've confirmed the value is "
        "deactivated or non-production.",
    ),
    exploit_example=(
        "# Vulnerable: long-lived AWS keys in pipeline variables.\n"
        "variables:\n"
        "  AWS_ACCESS_KEY_ID: AKIA…\n"
        "  AWS_SECRET_ACCESS_KEY: …\n"
        "steps:\n"
        "  - script: aws s3 sync ./dist s3://prod-site\n"
        "\n"
        "# Attack: the keys are in the YAML (or a plain variable),\n"
        "# exposed to every task's environment. A leaked log or a\n"
        "# malicious dependency exfiltrates them; the long-lived IAM\n"
        "# user keys keep working until someone rotates them by hand.\n"
        "\n"
        "# Safe: a federated service connection (workload identity) or a\n"
        "# Key Vault task, both injecting short-lived credentials.\n"
        "steps:\n"
        "  - task: AWSShellScript@1\n"
        "    inputs:\n"
        "      awsCredentials: prod-oidc-connection\n"
        "      scriptType: inline\n"
        "      inlineScript: aws s3 sync ./dist s3://prod-site"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    static_keys = False
    # Scan top-level variables.
    for v in _walk_vars(doc.get("variables")):
        if aws_key_in(v):
            static_keys = True
    # Scan job-level variables, step env, and script bodies.
    for _, job in iter_jobs(doc):
        for v in _walk_vars(job.get("variables")):
            if aws_key_in(v):
                static_keys = True
        for _, step in iter_steps(job):
            env = step.get("env") or {}
            if isinstance(env, dict):
                for val in env.values():
                    if isinstance(val, str) and aws_key_in(val):
                        static_keys = True
            # Detect `aws configure set` in script bodies.
            for key in ("script", "bash", "pwsh", "powershell"):
                body = step.get(key)
                if isinstance(body, str) and _AWS_CONFIGURE_RE.search(body):
                    static_keys = True
    if not static_keys:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="Pipeline does not reference long-lived AWS keys.",
            recommendation="No action required.", passed=True,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path,
        description=(
            "Pipeline references long-lived AWS access keys "
            "(AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY) in variables "
            "or task parameters."
        ),
        recommendation=RULE.recommendation, passed=False,
    )


def _walk_vars(variables: Any) -> list[str]:
    """Extract string values from ADO variables (mapping or list form)."""
    out: list[str] = []
    if isinstance(variables, dict):
        for v in variables.values():
            if isinstance(v, str):
                out.append(v)
            elif isinstance(v, dict) and isinstance(v.get("value"), str):
                out.append(v["value"])
    elif isinstance(variables, list):
        for entry in variables:
            if isinstance(entry, dict) and isinstance(entry.get("value"), str):
                out.append(entry["value"])
    return out
