"""K8S-014. Pod ``hostPath`` references a sensitive host directory."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import KubernetesContext, iter_volumes, iter_workload_pod_specs

#: Host paths whose mount inside a container amounts to cluster takeover.
_SENSITIVE_PREFIXES: tuple[str, ...] = (
    "/var/run/docker.sock",
    "/var/run/crio/crio.sock",
    "/var/run/containerd/containerd.sock",
    "/var/lib/kubelet",
    "/var/lib/docker",
    "/etc/kubernetes",
    "/proc",
    "/sys",
    "/etc",
    "/root",
)

#: Mounting ``/`` (the entire host filesystem) is always critical.
_ROOT_MOUNT = "/"


RULE = Rule(
    id="K8S-014",
    title="Pod hostPath references a sensitive host directory",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV", "ESF-D-ISOLATION"),
    cwe=("CWE-552",),
    recommendation=(
        "Never mount the container runtime socket "
        "(``/var/run/docker.sock``, ``containerd.sock``, ``crio.sock``), "
        "kubelet credentials (``/var/lib/kubelet``), the cluster "
        "config (``/etc/kubernetes``), the host root (``/``), or "
        "``/proc`` / ``/sys`` / ``/etc`` into a workload container. "
        "Each of these is a one-line cluster takeover. If a container "
        "genuinely needs node-level metrics, use an exporter "
        "DaemonSet with a narrowly-scoped read-only mount."
    ),
    docs_note=(
        "Stricter than K8S-013: that rule flags any hostPath, this "
        "one upgrades to CRITICAL when the path is one of the "
        "well-known cluster-escape vectors."
    ),
    exploit_example=(
        "# Vulnerable: ``/var/run/docker.sock`` mounted into the\n"
        "# container exposes the Docker API as root on the node.\n"
        "# A compromised pod (RCE in app, malicious image) runs\n"
        "# ``docker run -v /:/host --privileged`` and now owns the\n"
        "# entire node — kubelet credentials, every co-tenant pod's\n"
        "# filesystem, every secret mounted into a pod scheduled on\n"
        "# this node.\n"
        "apiVersion: v1\n"
        "kind: Pod\n"
        "metadata: { name: build }\n"
        "spec:\n"
        "  containers:\n"
        "    - name: builder\n"
        "      image: docker:latest\n"
        "      volumeMounts:\n"
        "        - name: docker-sock\n"
        "          mountPath: /var/run/docker.sock\n"
        "  volumes:\n"
        "    - name: docker-sock\n"
        "      hostPath:\n"
        "        path: /var/run/docker.sock\n"
        "\n"
        "# Safe: don't mount the runtime socket. Use a sandboxed\n"
        "# builder (Kaniko, BuildKit rootless, img) that produces\n"
        "# images from a Dockerfile without root access to the\n"
        "# node's container runtime.\n"
        "apiVersion: v1\n"
        "kind: Pod\n"
        "metadata: { name: build }\n"
        "spec:\n"
        "  containers:\n"
        "    - name: builder\n"
        "      image: gcr.io/kaniko-project/executor:v1.21.0\n"
        "      args:\n"
        "        - --context=git://github.com/myorg/myapp\n"
        "        - --destination=registry.example.com/myapp:tag"
    ),
)


def _is_sensitive(path: str) -> bool:
    if path == _ROOT_MOUNT:
        return True
    for prefix in _SENSITIVE_PREFIXES:
        if path == prefix or path.startswith(prefix + "/"):
            return True
    return False


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    for m, ps in iter_workload_pod_specs(ctx):
        for v in iter_volumes(ps):
            hp = v.get("hostPath")
            if not isinstance(hp, dict):
                continue
            path = hp.get("path")
            if not isinstance(path, str):
                continue
            if _is_sensitive(path):
                offenders.append(f"{m.kind}/{m.name}: {path}")
    passed = not offenders
    desc = (
        "No hostPath volume references a sensitive host directory."
        if passed else
        f"{len(offenders)} sensitive hostPath mount(s): "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
