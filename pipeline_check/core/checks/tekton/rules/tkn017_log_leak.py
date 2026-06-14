"""TKN-017. Secret-named variable echoed to the step log."""
from __future__ import annotations

from ..._primitives.log_leak import scan_script_for_leaked_secrets
from ...base import Finding, Severity
from ...rule import Rule
from ..base import TektonContext, iter_step_scripts

RULE = Rule(
    id="TKN-017",
    title="Secret-named variable echoed / printed in a step script",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-532", "CWE-200"),
    recommendation=(
        "Don't print secret values in step scripts. A secret mounted from "
        "a Kubernetes ``Secret`` (via ``secret.secretName`` or a workspace) "
        "is plaintext in the pod, and ``echo`` / ``set -x`` / ``env`` / "
        "``printenv`` write it straight to the TaskRun log, which anyone "
        "with read access to the cluster or its log sink can see. Log a "
        "boolean instead (``[ -n \"$TOKEN\" ] && echo set || echo unset``), "
        "and avoid ``set -x`` while a credential variable is in scope."
    ),
    docs_note=(
        "Scans every Task / ClusterTask step ``script`` for a secret-named "
        "variable handed to ``echo`` / ``printf`` / ``cat`` / ``tee``, for "
        "an ``env`` / ``printenv`` dump, and for ``set -x`` with a "
        "secret-named variable in scope (the shared ``log_leak`` detector, "
        "with GHA-033 / GL-036 / BB-032 / ADO-031 / CC-032 / JF-042 / "
        "HARNESS-013 / BK-017 / DR-018). Variable names matching common "
        "secret patterns (PASSWORD / TOKEN / SECRET / API_KEY / CREDENTIAL) "
        "trigger the rule. The Tekton analog of GL-036 / CC-032."
    ),
)


def check(ctx: TektonContext) -> Finding:
    offenders: list[str] = []
    examined = 0
    for doc in ctx.docs:
        if doc.kind not in ("Task", "ClusterTask"):
            continue
        examined += 1
        for sname, script in iter_step_scripts(doc):
            for h in scan_script_for_leaked_secrets(script):
                offenders.append(f"{doc.kind}/{doc.name} {sname}: {h}")
    if examined == 0:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="tekton",
            description="No Task / ClusterTask documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "No step script prints a secret-named variable to the log."
        if passed else
        f"{len(offenders)} step script(s) print a secret-named variable to "
        f"the log: {'; '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="tekton", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
