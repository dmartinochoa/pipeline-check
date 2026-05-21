"""K8S-007. Container ``runAsNonRoot`` not true / ``runAsUser`` is 0."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    KubernetesContext,
    container_name,
    iter_containers,
    iter_workload_pod_specs,
)

RULE = Rule(
    id="K8S-007",
    title="Container runAsNonRoot not true / runAsUser is 0",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-250",),
    recommendation=(
        "Set ``securityContext.runAsNonRoot: true`` and "
        "``runAsUser: <non-zero UID>`` on every container, OR set "
        "the same fields at pod level so all containers inherit. "
        "Running as UID 0 inside a container makes container-escape "
        "exploits dramatically more dangerous, the attacker already "
        "has root inside the container, so any kernel CVE that "
        "matters becomes immediately exploitable."
    ),
    docs_note=(
        "A container is considered safe when EITHER its own "
        "securityContext OR the pod-level securityContext sets "
        "``runAsNonRoot: true`` and a non-zero ``runAsUser``. "
        "An explicit ``runAsUser: 0`` always fails, even if "
        "``runAsNonRoot`` is unset."
    ),
    exploit_example=(
        "# Vulnerable: ``runAsNonRoot`` not declared (or\n"
        "# explicitly false) AND ``runAsUser`` not set lets the\n"
        "# image's default user run the container — for most\n"
        "# upstream images that's root. Any escape from the\n"
        "# container starts with UID 0 on the node.\n"
        "apiVersion: v1\n"
        "kind: Pod\n"
        "metadata: { name: app }\n"
        "spec:\n"
        "  containers:\n"
        "    - name: app\n"
        "      image: app@sha256:abc123...   # USER root in Dockerfile\n"
        "\n"
        "# Safe: explicit ``runAsNonRoot: true`` + a non-zero\n"
        "# ``runAsUser``. The kubelet refuses to start the\n"
        "# container if the image's ENTRYPOINT runs as UID 0.\n"
        "apiVersion: v1\n"
        "kind: Pod\n"
        "metadata: { name: app }\n"
        "spec:\n"
        "  containers:\n"
        "    - name: app\n"
        "      image: app@sha256:abc123...\n"
        "      securityContext:\n"
        "        runAsNonRoot: true\n"
        "        runAsUser: 10001"
    ),
)


def _sec_ctx(c: dict[str, Any]) -> dict[str, Any]:
    sc = c.get("securityContext")
    return sc if isinstance(sc, dict) else {}


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    for m, ps in iter_workload_pod_specs(ctx):
        pod_sc = ps.get("securityContext")
        pod_sc = pod_sc if isinstance(pod_sc, dict) else {}
        for kind, c in iter_containers(ps):
            csc = _sec_ctx(c)
            non_root = csc.get("runAsNonRoot")
            if non_root is None:
                non_root = pod_sc.get("runAsNonRoot")
            run_as = csc.get("runAsUser")
            if run_as is None:
                run_as = pod_sc.get("runAsUser")
            if run_as == 0 or non_root is not True:
                offenders.append(
                    f"{m.kind}/{m.name} {kind}={container_name(c)}"
                )
    passed = not offenders
    desc = (
        "Every container runs as a non-root UID."
        if passed else
        f"{len(offenders)} container(s) may run as root: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
