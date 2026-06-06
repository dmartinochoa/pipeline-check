"""K8S-025. System priority class used outside kube-system."""
from __future__ import annotations

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import KubernetesContext, iter_workload_pod_specs, manifest_location

RULE = Rule(
    id="K8S-025",
    title="System priority class used outside kube-system",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-269",),
    recommendation=(
        "Reserve ``system-cluster-critical`` and ``system-node-critical`` "
        "priority classes for control-plane workloads in ``kube-system``. "
        "Application pods that adopt them gain the right to evict normal "
        "workloads under resource pressure, which is a quiet path to a "
        "cluster-wide outage if the application has a bug or the "
        "attacker has any control over its spec."
    ),
    docs_note=(
        "The kubelet reserves the two ``system-*`` priority classes "
        "for its own pods (kube-proxy, CNI agents). Granting them to a "
        "user workload also grants the right to preempt and evict "
        "anything below 2000000000, which is every non-system pod on "
        "the cluster. Outside kube-system this is almost always a "
        "misconfiguration copy-pasted from a control-plane manifest."
    ),
    exploit_example=(
        "# Vulnerable: a non-system workload uses\n"
        "# ``priorityClassName: system-cluster-critical`` or\n"
        "# ``system-node-critical``. Those classes are reserved\n"
        "# for kube-system control-plane components; using them\n"
        "# on app workloads lets the app preempt critical\n"
        "# system Pods under resource pressure and degrade\n"
        "# the cluster control plane.\n"
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata: { name: app, namespace: prod }\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      priorityClassName: system-cluster-critical\n"
        "      containers:\n"
        "        - name: app\n"
        "          image: app@sha256:abc123...\n"
        "\n"
        "# Safe: use a custom PriorityClass for app workloads\n"
        "# that need elevated priority. The class can preempt\n"
        "# best-effort workloads but never system Pods.\n"
        "apiVersion: scheduling.k8s.io/v1\n"
        "kind: PriorityClass\n"
        "metadata: { name: app-high }\n"
        "value: 100000\n"
        "globalDefault: false\n"
        "description: \"High-priority app workloads\"\n"
        "---\n"
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata: { name: app, namespace: prod }\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      priorityClassName: app-high"
    ),
)


_SYSTEM_PCS = frozenset({"system-cluster-critical", "system-node-critical"})


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for m, ps in iter_workload_pod_specs(ctx):
        if m.namespace == "kube-system":
            continue
        pc = ps.get("priorityClassName")
        if isinstance(pc, str) and pc in _SYSTEM_PCS:
            ns = m.namespace or "(no-namespace)"
            offenders.append(f"{m.kind}/{m.name} in {ns}: {pc}")
            locations.append(manifest_location(m, ps))
    passed = not offenders
    desc = (
        "No workload outside kube-system claims a system-* priority class."
        if passed else
        f"{len(offenders)} workload(s) outside kube-system use a "
        f"system-* priority class: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
