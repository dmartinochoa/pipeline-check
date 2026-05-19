"""TKN-004, ``hostPath`` / host-namespace volumes in Task workspaces."""
from __future__ import annotations

from typing import Any

from ..._primitives.anchors import k8s_sa
from ...base import Finding, ResourceAnchor, Severity
from ...rule import Rule
from ..base import TektonContext

RULE = Rule(
    id="TKN-004",
    title="Tekton Task mounts hostPath or shares host namespaces",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-5",),
    esf=("ESF-D-RUNTIME-HARDENING",),
    cwe=("CWE-250", "CWE-668"),
    recommendation=(
        "Use Tekton ``workspaces:`` backed by ``emptyDir`` or "
        "``persistentVolumeClaim`` instead of ``hostPath``. Drop "
        "``hostNetwork: true`` / ``hostPID: true`` / ``hostIPC: true`` "
        "on the Task's ``podTemplate``. A hostPath mount of "
        "``/var/run/docker.sock`` or ``/`` lets the build break out of "
        "the pod and act as the underlying node."
    ),
    docs_note=(
        "Checks ``spec.volumes[].hostPath`` (legacy v1beta1 form), "
        "``spec.workspaces[].volumeClaimTemplate.spec.storageClassName"
        " == 'hostpath'``, and ``spec.podTemplate`` host-namespace "
        "flags."
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


def _scan_workspaces(spec: dict[str, Any]) -> list[str]:
    out: list[str] = []
    ws = spec.get("workspaces")
    if not isinstance(ws, list):
        return out
    for w in ws:
        if not isinstance(w, dict):
            continue
        vct = w.get("volumeClaimTemplate")
        if isinstance(vct, dict):
            inner = vct.get("spec") or {}
            if isinstance(inner, dict):
                sc = inner.get("storageClassName")
                if isinstance(sc, str) and sc.lower() in {"hostpath", "host-path"}:
                    out.append(f"workspace {w.get('name', '?')} on hostpath")
    return out


def _scan_pod_template(spec: dict[str, Any]) -> list[str]:
    out: list[str] = []
    pt = spec.get("podTemplate")
    if not isinstance(pt, dict):
        return out
    for key in ("hostNetwork", "hostPID", "hostIPC"):
        if pt.get(key) is True:
            out.append(f"podTemplate.{key}: true")
    return out


def check(ctx: TektonContext) -> Finding:
    offenders: list[str] = []
    examined = 0
    # ResourceAnchor phase 1: emit one k8s_sa anchor only when the
    # Task pins ``spec.podTemplate.serviceAccountName`` explicitly.
    # Tekton's runtime SA is normally chosen by the TaskRun /
    # PipelineRun (not visible in the Task manifest), so the
    # conservative call when no explicit pin exists is to emit
    # nothing rather than guess ``default`` and over-confirm AC-020.
    # The chain then falls back to scan-level co-occurrence, which
    # is still useful evidence.
    anchor_set: dict[str, ResourceAnchor] = {}
    for doc in ctx.docs:
        if doc.kind not in ("Task", "ClusterTask", "Pipeline"):
            continue
        examined += 1
        spec = doc.data.get("spec") or {}
        if not isinstance(spec, dict):
            spec = {}
        hits = (
            _scan_volumes(spec)
            + _scan_workspaces(spec)
            + _scan_pod_template(spec)
        )
        for h in hits:
            offenders.append(f"{doc.kind}/{doc.name}: {h}")
        if hits:
            pt = spec.get("podTemplate")
            if isinstance(pt, dict):
                sa = pt.get("serviceAccountName")
                if isinstance(sa, str) and sa.strip():
                    built = k8s_sa(doc.namespace or None, sa.strip())
                    if built is not None:
                        anchor_set[built.identity] = built
    if examined == 0:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="tekton",
            description="No Task / ClusterTask / Pipeline documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "No hostPath / host-namespace usage in any Task / Pipeline."
        if passed else
        f"{len(offenders)} host-level escalation surface(s): "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="tekton", description=desc,
        recommendation=RULE.recommendation, passed=passed,
        resource_anchors=tuple(anchor_set.values()),
    )
