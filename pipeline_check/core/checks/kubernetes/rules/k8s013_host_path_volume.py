"""K8S-013. Pod uses a ``hostPath`` volume."""
from __future__ import annotations

from ..._primitives.anchors import k8s_sa
from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, ResourceAnchor, Severity
from ...rule import Rule
from ..base import KubernetesContext, iter_volumes, iter_workload_pod_specs

RULE = Rule(
    id="K8S-013",
    title="Pod uses a hostPath volume",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV", "ESF-D-ISOLATION"),
    cwe=("CWE-732",),
    recommendation=(
        "Replace ``hostPath`` volumes with ``configMap``, ``secret``, "
        "``emptyDir``, ``persistentVolumeClaim``, or CSI volumes. "
        "``hostPath`` opens a direct read/write window onto the "
        "node's filesystem; combined with even mild container "
        "compromise it gives the attacker access to other pods' "
        "data, kubelet credentials, and the container runtime."
    ),
    docs_note=(
        "Some legitimate system DaemonSets need hostPath (log "
        "collectors, CSI node plugins). Those should be deployed "
        "with explicit security review and a narrow ``path:``; "
        "this rule fires regardless because *application* workloads "
        "should never use hostPath."
    ),
    incident_refs=(
        "[CVE-2021-25741](https://www.cve.org/CVERecord?id=CVE-2021-25741) "
        "(Kubernetes subPath volume traversal): a container could "
        "craft a ``subPath`` on a volume mount to access files "
        "outside the volume boundary. The bug affected multiple "
        "volume kinds; ``hostPath`` makes the blast radius worse "
        "because the volume already references host paths, so "
        "escaping the subpath lands directly on the node "
        "filesystem with the kubelet's privileges in scope.",
        "TeamTNT / Kinsing crypto-jacking campaigns (2020-2022): "
        "cluster compromise reports repeatedly traced lateral movement "
        "from a single misconfigured pod to the underlying node via "
        "hostPath:/, then to kubelet credentials and other tenants. "
        "Sysdig and Aqua incident reports document the pattern.",
    ),
    exploit_example=(
        "# Vulnerable: pod mounts the host's root filesystem.\n"
        "apiVersion: v1\n"
        "kind: Pod\n"
        "metadata:\n"
        "  name: attacker\n"
        "spec:\n"
        "  containers:\n"
        "    - name: shell\n"
        "      image: busybox\n"
        "      command: [\"sleep\", \"infinity\"]\n"
        "      volumeMounts:\n"
        "        - name: host-root\n"
        "          mountPath: /host\n"
        "  volumes:\n"
        "    - name: host-root\n"
        "      hostPath:\n"
        "        path: /            # full node filesystem\n"
        "\n"
        "# Attack from a shell inside the container:\n"
        "#\n"
        "#   # Read kubelet credentials and pivot to API server:\n"
        "#   cat /host/var/lib/kubelet/kubeconfig\n"
        "#   cat /host/etc/kubernetes/admin.conf\n"
        "#\n"
        "#   # Read service account tokens for every other pod on\n"
        "#   # the node and impersonate them:\n"
        "#   ls /host/var/lib/kubelet/pods/*/volumes/kubernetes.io~projected/*/token\n"
        "#\n"
        "#   # Drop a setuid binary and pin persistence on the host:\n"
        "#   cp /bin/busybox /host/usr/local/bin/.bd\n"
        "#   chmod 4755 /host/usr/local/bin/.bd\n"
        "\n"
        "# Safe: use scoped volume types that don't bridge to the host.\n"
        "spec:\n"
        "  volumes:\n"
        "    - name: data\n"
        "      persistentVolumeClaim:\n"
        "        claimName: app-data"
    ),
)


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    # ResourceAnchor phase 1: emit one k8s_sa anchor per offending
    # workload, identifying the ServiceAccount under which the
    # hostPath pod actually runs. AC-011 / AC-020 intersect this
    # against K8S-020's cluster-admin binding subjects so the chain
    # only confirms when the host-escape pod runs as the
    # cluster-admin SA (the single-step node-escape ⇒ cluster-takeover
    # primitive). Pods that omit ``serviceAccountName`` inherit the
    # namespace's ``default`` SA — the canonicalizer's same default.
    anchor_set: dict[str, ResourceAnchor] = {}
    for m, ps in iter_workload_pod_specs(ctx):
        sa = ps.get("serviceAccountName")
        sa_name = sa.strip() if isinstance(sa, str) and sa.strip() else "default"
        for v in iter_volumes(ps):
            hp = v.get("hostPath")
            if isinstance(hp, dict):
                vol_name = v.get("name", "?")
                offenders.append(f"{m.kind}/{m.name} volume={vol_name}")
                # Land on the ``hostPath:`` block when it carries
                # source-line markers; fall back to the volume entry.
                line = _line_of(hp) or _line_of(v)
                locations.append(Location(
                    path=m.path, start_line=line, end_line=line,
                    doc_index=m.doc_index,
                ))
                built = k8s_sa(m.namespace, sa_name)
                if built is not None:
                    anchor_set[built.identity] = built
    passed = not offenders
    desc = (
        "No workload uses hostPath volumes."
        if passed else
        f"{len(offenders)} hostPath volume(s) declared: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
        resource_anchors=tuple(anchor_set.values()),
    )
