"""K8S-012. Pod ``automountServiceAccountToken`` not explicitly false."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import KubernetesContext, iter_workload_pod_specs

RULE = Rule(
    id="K8S-012",
    title="Pod automountServiceAccountToken not false",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2", "CICD-SEC-6"),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-732",),
    recommendation=(
        "Set ``spec.automountServiceAccountToken: false`` on every "
        "workload that doesn't need to talk to the Kubernetes API. "
        "Auto-mounted SA tokens are a free credential for an attacker "
        "who lands a shell, without explicit opt-out the token sits "
        "at ``/var/run/secrets/kubernetes.io/serviceaccount/token`` "
        "ready to be exfiltrated. If the workload needs API access, "
        "leave it true but pair with a tight, dedicated RBAC role."
    ),
    docs_note=(
        "An unset value defaults to True in Kubernetes. This rule "
        "fails on unset because most application workloads do NOT "
        "need API access and the default exposes credentials by "
        "accident. Workloads that explicitly call the API should "
        "set the field to ``true`` so the choice is visible in code "
        "review."
    ),
    exploit_example=(
        "# Vulnerable: SA token auto-mounted into a workload that\n"
        "# never calls the Kubernetes API.\n"
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        "  name: web\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: app\n"
        "          image: web:1.2.3\n"
        "\n"
        "# Attack: automountServiceAccountToken defaults to true, so the\n"
        "# SA token is mounted at\n"
        "# /var/run/secrets/kubernetes.io/serviceaccount/. An attacker\n"
        "# who lands a shell in the container (RCE, SSRF-to-exec) reads\n"
        "# the token and calls the Kubernetes API as the pod's SA, no\n"
        "# extra credential needed.\n"
        "\n"
        "# Safe: opt out for workloads that never call the API.\n"
        "    spec:\n"
        "      automountServiceAccountToken: false\n"
        "      containers:\n"
        "        - name: app\n"
        "          image: web:1.2.3"
    ),
)


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    for m, ps in iter_workload_pod_specs(ctx):
        if ps.get("automountServiceAccountToken") is not False:
            offenders.append(f"{m.kind}/{m.name}")
    passed = not offenders
    desc = (
        "Every workload sets automountServiceAccountToken: false."
        if passed else
        f"{len(offenders)} workload(s) leave SA tokens auto-mounted: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
