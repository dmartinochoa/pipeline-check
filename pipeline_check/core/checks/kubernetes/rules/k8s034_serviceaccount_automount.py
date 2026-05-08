"""K8S-034 — ServiceAccount automountServiceAccountToken not explicitly disabled."""
from __future__ import annotations

from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import KubernetesContext

RULE = Rule(
    id="K8S-034",
    title="ServiceAccount automountServiceAccountToken not explicitly false",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2",),
    esf=("ESF-D-LEAST-PRIV", "ESF-C-LEAST-PRIV"),
    cwe=("CWE-732",),
    recommendation=(
        "Set ``automountServiceAccountToken: false`` at the "
        "ServiceAccount level for every SA that doesn't actively "
        "need to call the Kubernetes API. The pods that legitimately "
        "do (operators, sidecars that read namespaces, controllers) "
        "can opt back in per-pod via ``spec.automountServiceAccountToken: "
        "true``. The default is mount-everywhere, which is the "
        "wrong direction for least privilege."
    ),
    docs_note=(
        "K8S-012 covers the pod-level ``automountServiceAccountToken`` "
        "setting; this rule covers the same control at the "
        "ServiceAccount level. The two are complementary: the SA-level "
        "default flips the cluster-wide baseline (``true`` -> "
        "``false``), the pod-level override re-enables only where "
        "needed. Without the SA-level disable, every pod that doesn't "
        "set its own override mounts a token that can call the K8s "
        "API as that SA — a useful credential for an attacker who "
        "lands code in any pod, regardless of the workload's own "
        "intent."
    ),
    known_fp=(
        "Operator / controller workloads (cert-manager, "
        "metrics-server, ingress controllers) legitimately need API "
        "access from every pod. Their dedicated SAs should keep "
        "automount enabled — leave them out of the cluster-wide "
        "disable. ``default`` SA in every namespace is the high-fire "
        "case worth disabling.",
    ),
)


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for m in ctx.manifests:
        if m.kind != "ServiceAccount":
            continue
        # The field can be absent (-> default true), explicitly true,
        # or explicitly false. Only an explicit false counts as a
        # pass; both the absent case and explicit true fail.
        automount = m.data.get("automountServiceAccountToken")
        if automount is False:
            continue
        offenders.append(f"ServiceAccount/{m.namespace or 'default'}/{m.name}")
        line = _line_of(m.data.get("metadata") or m.data)
        locations.append(Location(
            path=m.path, start_line=line, end_line=line,
            doc_index=m.doc_index,
        ))
    passed = not offenders
    desc = (
        "Every ServiceAccount has automountServiceAccountToken: false."
        if passed else
        f"{len(offenders)} ServiceAccount(s) leave automount "
        f"enabled (default or explicit true): "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
