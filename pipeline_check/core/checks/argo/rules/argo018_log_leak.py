"""ARGO-018. Secret-named variable echoed to the step log."""
from __future__ import annotations

from ..._primitives.log_leak import scan_script_for_leaked_secrets
from ...base import Finding, Severity
from ...rule import Rule
from ..base import ArgoContext, iter_containers, iter_templates, template_name

RULE = Rule(
    id="ARGO-018",
    title="Secret-named variable echoed / printed in a template script",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-532", "CWE-200"),
    recommendation=(
        "Don't print secret values in template scripts. A secret mounted "
        "from a Kubernetes ``Secret`` (via ``valueFrom.secretKeyRef`` or an "
        "artifact) is plaintext in the pod, and ``echo`` / ``set -x`` / "
        "``env`` / ``printenv`` write it straight to the workflow-pod log, "
        "which anyone with read access to the cluster or its log sink can "
        "see. Log a boolean instead (``[ -n \"$TOKEN\" ] && echo set || "
        "echo unset``), and avoid ``set -x`` while a credential variable is "
        "in scope."
    ),
    docs_note=(
        "Scans every template ``script.source`` and ``container.args`` for "
        "a secret-named variable handed to ``echo`` / ``printf`` / ``cat`` "
        "/ ``tee``, for an ``env`` / ``printenv`` dump, and for ``set -x`` "
        "with a secret-named variable in scope (the shared ``log_leak`` "
        "detector, with GHA-033 / GL-036 / BB-032 / ADO-031 / CC-032 / "
        "JF-042 / HARNESS-013 / BK-017 / DR-018). Variable names matching "
        "common secret patterns (PASSWORD / TOKEN / SECRET / API_KEY / "
        "CREDENTIAL) trigger the rule. The Argo analog of GL-036 / CC-032."
    ),
)


def check(ctx: ArgoContext) -> Finding:
    offenders: list[str] = []
    for doc in ctx.docs:
        for idx, tmpl in enumerate(iter_templates(doc)):
            tname = template_name(tmpl, idx)
            for container in iter_containers(tmpl):
                # Scan ``script.source`` and each ``container.args`` element
                # on its own: a shell script is a single arg, so joining the
                # args would push it off the line start where the detector
                # anchors.
                texts: list[str] = []
                src = container.get("source")
                if isinstance(src, str):
                    texts.append(src)
                # ``command`` and ``args`` both carry executed shell: the
                # ``command: ["sh","-c","<script>"]`` idiom puts the whole
                # body in ``command``. Scan each string element of both.
                for field in ("command", "args"):
                    value = container.get(field)
                    if isinstance(value, list):
                        texts += [a for a in value if isinstance(a, str)]
                for text in texts:
                    for h in scan_script_for_leaked_secrets(text):
                        offenders.append(
                            f"{doc.kind}/{doc.name} {tname}: {h}"
                        )
    passed = not offenders
    desc = (
        "No template script prints a secret-named variable to the log."
        if passed else
        f"{len(offenders)} template script(s) print a secret-named variable "
        f"to the log: {'; '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argo", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
