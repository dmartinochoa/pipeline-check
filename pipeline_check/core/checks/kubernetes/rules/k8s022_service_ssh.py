"""K8S-022 — Service exposes SSH (port 22)."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import KubernetesContext

RULE = Rule(
    id="K8S-022",
    title="Service exposes SSH (port 22)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-668",),
    recommendation=(
        "Containers should not run sshd. If you need an interactive "
        "shell into a running pod, use ``kubectl exec`` (subject to "
        "RBAC) or ``kubectl debug``. Removing the port-22 Service "
        "removes a pre-auth network surface that's a frequent "
        "lateral-movement target after initial cluster compromise."
    ),
    docs_note=(
        "Mirrors DF-013 (``EXPOSE 22`` in a Dockerfile) at the "
        "Service level. The check fires on Service ports whose "
        "``port`` or ``targetPort`` is 22, regardless of Service "
        "type — a NodePort/LoadBalancer 22 is dramatically worse "
        "but a ClusterIP 22 still indicates an sshd container "
        "somewhere."
    ),
)


def _is_ssh(port: Any) -> bool:
    if isinstance(port, int) and port == 22:
        return True
    if isinstance(port, str) and port == "ssh":
        return True
    return False


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    for m in ctx.manifests:
        if m.kind != "Service":
            continue
        spec = m.data.get("spec")
        if not isinstance(spec, dict):
            continue
        ports = spec.get("ports")
        if not isinstance(ports, list):
            continue
        for idx, p in enumerate(ports):
            if not isinstance(p, dict):
                continue
            if _is_ssh(p.get("port")) or _is_ssh(p.get("targetPort")):
                pname = p.get("name", f"ports[{idx}]")
                offenders.append(f"Service/{m.name} {pname}=22")
                break
    passed = not offenders
    desc = (
        "No Service exposes SSH (port 22)."
        if passed else
        f"{len(offenders)} Service(s) expose port 22: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
