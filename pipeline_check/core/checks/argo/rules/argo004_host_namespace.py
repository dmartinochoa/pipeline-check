"""ARGO-004. Volumes / podSpecPatch grant host-namespace access."""
from __future__ import annotations

import json
import re
from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import ArgoContext, doc_location, workflow_spec

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
    exploit_example=(
        "# Vulnerable: ``hostPath: /var/run/docker.sock`` mounts the\n"
        "# Docker socket into the template's container. The workflow\n"
        "# can then ``docker run --privileged -v /:/host ...`` and\n"
        "# own the entire node — kubelet credentials, every other\n"
        "# pod's filesystem, every secret mounted on the node.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: Workflow\n"
        "spec:\n"
        "  volumes:\n"
        "    - name: docker-sock\n"
        "      hostPath:\n"
        "        path: /var/run/docker.sock\n"
        "  templates:\n"
        "    - name: build\n"
        "      container:\n"
        "        image: docker:latest\n"
        "        volumeMounts:\n"
        "          - { name: docker-sock, mountPath: /var/run/docker.sock }\n"
        "\n"
        "# Safe: use a sandboxed builder (Kaniko, BuildKit rootless)\n"
        "# in a PVC-backed workspace. The template never needs node-\n"
        "# level access to the container runtime, just a writable\n"
        "# scratch volume scoped to the workflow run.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: Workflow\n"
        "spec:\n"
        "  volumes:\n"
        "    - name: scratch\n"
        "      emptyDir: {}\n"
        "  templates:\n"
        "    - name: build\n"
        "      container:\n"
        "        image: gcr.io/kaniko-project/executor:v1.21.0\n"
        "        args: [--context=git://..., --destination=registry/app:tag]\n"
        "        volumeMounts:\n"
        "          - { name: scratch, mountPath: /workspace }"
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


_HOST_NS_KEYS = ("hostNetwork", "hostPID", "hostIPC")
_HOST_NS_RES = {
    key: re.compile(rf'["\']?{key}["\']?\s*:\s*true\b', re.IGNORECASE)
    for key in _HOST_NS_KEYS
}
_HOST_PATH_RE = re.compile(r'["\']?hostPath["\']?\s*:')


def _scan_pod_spec_patch(spec: dict[str, Any]) -> list[str]:
    out: list[str] = []
    psp = spec.get("podSpecPatch")
    if not isinstance(psp, str):
        return out
    # podSpecPatch is often a JSON-merge-patch string. Try JSON first
    # so quoted-key / compact variants are caught; fall back to regex
    # for YAML or partial strings that don't parse.
    parsed: Any = None
    try:
        parsed = json.loads(psp)
    except (ValueError, TypeError):
        parsed = None
    if isinstance(parsed, dict):
        for key in _HOST_NS_KEYS:
            if parsed.get(key) is True:
                out.append(f"podSpecPatch {key}: true")
        if "hostPath" in parsed:
            out.append("podSpecPatch hostPath")
        return out
    for key, regex in _HOST_NS_RES.items():
        if regex.search(psp):
            out.append(f"podSpecPatch {key}: true")
    if _HOST_PATH_RE.search(psp):
        out.append("podSpecPatch hostPath")
    return out


def check(ctx: ArgoContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for doc in ctx.docs:
        spec = workflow_spec(doc)
        for h in _scan_volumes(spec) + _scan_pod_spec_patch(spec):
            offenders.append(f"{doc.kind}/{doc.name}: {h}")
            locations.append(doc_location(doc))
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
        locations=locations,
    )
