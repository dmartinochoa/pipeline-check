"""ARGO-004 — Volumes / podSpecPatch grant host-namespace access."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import ArgoContext, workflow_spec

RULE = Rule(
    id="ARGO-004",
    title="Argo workflow mounts hostPath or shares host namespaces",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-5",),
    esf=("ESF-D-RUNTIME-HARDENING",),
    cwe=("CWE-250", "CWE-668"),
    recommendation=(
        "Use ``emptyDir`` or PVC-backed volumes instead of "
        "``hostPath``. Drop ``hostNetwork: true`` / ``hostPID: true`` "
        "/ ``hostIPC: true`` from any inline ``podSpecPatch``. A "
        "hostPath mount of ``/var/run/docker.sock`` or ``/`` lets "
        "the workflow break out of the pod and act as the underlying "
        "node."
    ),
    docs_note=(
        "Walks ``spec.volumes[].hostPath`` and the raw "
        "``spec.podSpecPatch`` string for ``hostNetwork``, "
        "``hostPID``, ``hostIPC``, and ``hostPath``."
    ),
)


def _scan_volumes(spec: dict[str, Any]) -> list[str]:
    out: list[str] = []
    vols = spec.get("volumes")
    if isinstance(vols, list):
        for v in vols:
            if isinstance(v, dict) and isinstance(v.get("hostPath"), dict):
                hp_path = v["hostPath"].get("path", "<unset>")
                out.append(f"hostPath {hp_path}")
    return out


def _scan_pod_spec_patch(spec: dict[str, Any]) -> list[str]:
    out: list[str] = []
    psp = spec.get("podSpecPatch")
    if not isinstance(psp, str):
        return out
    for token in ("hostNetwork: true", "hostPID: true", "hostIPC: true"):
        if token in psp:
            out.append(f"podSpecPatch {token}")
    if "hostPath:" in psp:
        out.append("podSpecPatch hostPath")
    return out


def check(ctx: ArgoContext) -> Finding:
    offenders: list[str] = []
    for doc in ctx.docs:
        spec = workflow_spec(doc)
        for h in _scan_volumes(spec) + _scan_pod_spec_patch(spec):
            offenders.append(f"{doc.kind}/{doc.name}: {h}")
    if not ctx.docs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argo",
            description="No Argo documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "No hostPath / host-namespace usage."
        if passed else
        f"{len(offenders)} host-level escalation surface(s): "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argo", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
