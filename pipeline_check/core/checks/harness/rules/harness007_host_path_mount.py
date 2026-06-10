"""HARNESS-007. Stage infrastructure mounts a sensitive host path."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import HarnessPipeline, iter_stages

RULE = Rule(
    id="HARNESS-007",
    title="Stage infrastructure mounts a sensitive host path",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-5",),
    esf=("ESF-D-RUNTIME-HARDENING", "ESF-D-LEAST-PRIV"),
    cwe=("CWE-250", "CWE-732"),
    recommendation=(
        "Drop the ``HostPath`` volume from the stage infrastructure. "
        "Mounting ``/var/run/docker.sock`` from the build node into the "
        "build pod hands it root-equivalent control over every other "
        "workload on that node (it can launch arbitrary, including "
        "privileged, containers). ``/var/lib/docker`` exposes every image "
        "and container on the node, ``/proc`` and ``/sys`` expose host "
        "kernel state, and ``/`` is full host takeover. If the build "
        "genuinely needs container builds, use a rootless builder "
        "(``kaniko``, ``buildah --isolation=chroot``, BuildKit rootless) "
        "or a remote builder, rather than bind-mounting the node's "
        "filesystem."
    ),
    docs_note=(
        "Harness CI Kubernetes infrastructure "
        "(``stage.spec.infrastructure.spec.volumes``) accepts ``EmptyDir`` "
        "/ ``PersistentVolumeClaim`` (safe) or ``HostPath`` (a bind mount "
        "of the build node's filesystem, the dangerous shape). The rule "
        "fires when a ``HostPath`` volume's ``spec.path`` matches a "
        "sensitive prefix: ``/var/run/docker.sock`` (the canonical "
        "container-escape socket), ``/var/lib/docker``, ``/var/run``, "
        "``/etc``, ``/proc``, ``/sys``, or ``/`` (full host root). "
        "``EmptyDir`` / PVC volumes pass. Same model as DR-007 / K8S-019 "
        "across providers."
    ),
    known_fp=(
        "Trusted-only pipelines on a dedicated, isolated build cluster "
        "sometimes deliberately mount the Docker socket for image build / "
        "push. Suppress via ignore-file when the cluster's isolation is "
        "documented; the rule can't see the cluster's trust boundary from "
        "the pipeline YAML alone.",
    ),
    exploit_example=(
        "# Vulnerable: the build pod bind-mounts the node's Docker socket,\n"
        "# so a build-script RCE gets the Docker API as root on the node\n"
        "# (docker run --privileged -v /:/host then owns the node).\n"
        "- stage:\n"
        "    type: CI\n"
        "    identifier: build\n"
        "    spec:\n"
        "      infrastructure:\n"
        "        type: KubernetesDirect\n"
        "        spec:\n"
        "          connectorRef: k8s\n"
        "          namespace: harness\n"
        "          volumes:\n"
        "            - mountPath: /var/run\n"
        "              type: HostPath\n"
        "              spec:\n"
        "                path: /var/run/docker.sock\n"
        "\n"
        "# Safe: use an EmptyDir for build scratch and a rootless builder.\n"
        "          volumes:\n"
        "            - mountPath: /cache\n"
        "              type: EmptyDir"
    ),
)

#: Host paths that grant the mounting pod privilege over the build node.
#: Each is a documented escape primitive, matched as a prefix.
_SENSITIVE_PREFIXES: tuple[str, ...] = (
    "/var/run/docker.sock",
    "/var/lib/docker",
    "/var/run",
    "/etc",
    "/proc",
    "/sys",
)


def _is_sensitive(host_path: str) -> bool:
    norm = host_path.strip().rstrip("/")
    if norm in ("", "/"):
        return True
    for prefix in _SENSITIVE_PREFIXES:
        if norm == prefix or norm.startswith(prefix + "/"):
            return True
    return False


def _infra_volumes(stage: dict[str, Any]) -> list[dict[str, Any]]:
    spec = stage.get("spec")
    infra = spec.get("infrastructure") if isinstance(spec, dict) else None
    ispec = infra.get("spec") if isinstance(infra, dict) else None
    vols = ispec.get("volumes") if isinstance(ispec, dict) else None
    return [v for v in vols if isinstance(v, dict)] if isinstance(vols, list) else []


def check(pipeline: HarnessPipeline) -> Finding:
    offenders: list[str] = []
    for stage_id, stage in iter_stages(pipeline):
        for vol in _infra_volumes(stage):
            if str(vol.get("type", "")).strip() != "HostPath":
                continue
            vspec = vol.get("spec")
            path = vspec.get("path") if isinstance(vspec, dict) else None
            if isinstance(path, str) and _is_sensitive(path):
                offenders.append(f"{stage_id}: {path.strip()}")
    passed = not offenders
    desc = (
        "No stage infrastructure mounts a sensitive host path."
        if passed else
        f"{len(offenders)} stage(s) bind-mount a sensitive host path into "
        f"the build pod: {'; '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
