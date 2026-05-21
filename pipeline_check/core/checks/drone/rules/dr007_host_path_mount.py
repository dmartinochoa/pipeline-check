"""DR-007. Step mounts a sensitive host path via Drone volumes."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Pipeline, iter_services, iter_steps, step_label

RULE = Rule(
    id="DR-007",
    title="Step mounts a sensitive host path",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-5",),
    esf=("ESF-D-RUNTIME-HARDENING", "ESF-D-LEAST-PRIV"),
    cwe=("CWE-250", "CWE-732"),
    recommendation=(
        "Drop the host volume from the pipeline. Mounting "
        "``/var/run/docker.sock`` from the agent host into a "
        "build container hands the container root-equivalent "
        "control over every other workload on the same agent "
        "(it can spawn arbitrary containers, including "
        "privileged ones). ``/var/lib/docker`` exposes every "
        "image and container on the host, ``/proc`` and "
        "``/sys`` expose the host kernel state, and ``/`` "
        "(the host root) is full takeover. If the build "
        "genuinely needs Docker, run a rootless alternative "
        "(``kaniko``, ``buildah --isolation=chroot``, ``docker "
        "buildx`` against a remote builder) or use Drone's "
        "``trusted: true`` repo flag plus a dedicated "
        "host-isolated runner pool, rather than mounting the "
        "shared host's socket."
    ),
    docs_note=(
        "Drone's pipeline-level ``volumes:`` block accepts "
        "either ``temp:`` (an ephemeral tmpfs, safe) or "
        "``host: { path: ... }`` (a bind mount of the agent's "
        "filesystem, the dangerous shape). The rule fires when "
        "any pipeline-level volume's ``host.path`` matches a "
        "sensitive prefix:\n\n"
        "- ``/var/run/docker.sock`` — the canonical Docker-in-"
        "Docker escape; equivalent to ``--privileged`` for "
        "container takeover purposes;\n"
        "- ``/var/lib/docker`` — exposes every image / "
        "container on the host;\n"
        "- ``/etc`` — config + credential files;\n"
        "- ``/proc`` / ``/sys`` — host kernel state;\n"
        "- ``/`` — full host takeover.\n\n"
        "The rule fires on the volume *declaration*, not on "
        "step-level mounts. A pipeline that declares a "
        "sensitive host volume but no step actually mounts it "
        "is still flagged: the declaration alone signals the "
        "agent's Drone runner is configured to permit the bind "
        "mount, which is itself a risk-shape decision worth "
        "review."
    ),
    known_fp=(
        "Trusted-only pipelines on a dedicated runner fleet "
        "(no fork-PR access, no untrusted contributors) "
        "sometimes deliberately mount the Docker socket for "
        "image build / push workflows. Suppress via "
        "ignore-file when this is the deliberate posture and "
        "the runner pool's isolation is documented "
        "elsewhere; the rule has no way to know whether "
        "``trusted: true`` is set on the repo from the "
        "pipeline YAML alone.",
    ),
    exploit_example=(
        "# Vulnerable: mounting ``/var/run/docker.sock`` into the\n"
        "# step gives the step's container the Docker API as root\n"
        "# on the runner. ``docker run --privileged -v /:/host``\n"
        "# from inside the step then owns the runner.\n"
        "kind: pipeline\n"
        "type: docker\n"
        "name: build\n"
        "steps:\n"
        "  - name: build\n"
        "    image: docker:24\n"
        "    volumes:\n"
        "      - name: dockersock\n"
        "        path: /var/run/docker.sock\n"
        "    commands:\n"
        "      - docker build -t app .\n"
        "volumes:\n"
        "  - name: dockersock\n"
        "    host:\n"
        "      path: /var/run/docker.sock\n"
        "\n"
        "# Safe: use a rootless image builder (Kaniko / BuildKit\n"
        "# rootless) that doesn't need the host runtime socket.\n"
        "# An empty temp volume is enough for the build cache.\n"
        "kind: pipeline\n"
        "type: docker\n"
        "name: build\n"
        "steps:\n"
        "  - name: build\n"
        "    image: gcr.io/kaniko-project/executor@sha256:abc123...\n"
        "    commands:\n"
        "      - /kaniko/executor --context=. --destination=registry/app:tag"
    ),
)


# Host paths that grant the mounting container privilege over the
# agent host. The list is intentionally short: each entry is a
# documented escape primitive, matched as a prefix (so
# ``/var/lib/docker/...`` also fires).
_SENSITIVE_PREFIXES: tuple[str, ...] = (
    "/var/run/docker.sock",
    "/var/lib/docker",
    "/var/run",
    "/etc",
    "/proc",
    "/sys",
)


def _is_sensitive(host_path: str) -> bool:
    """Return True when *host_path* is a sensitive prefix.

    The exact root (``/``) is its own special case because the
    prefix-match rule below would otherwise match nothing
    longer than zero chars. Anything longer than ``/`` falls
    under one of the listed prefixes (or doesn't fire).
    """
    norm = host_path.strip().rstrip("/")
    if norm == "" or norm == "/":
        return True
    for prefix in _SENSITIVE_PREFIXES:
        if norm == prefix or norm.startswith(prefix + "/"):
            return True
    return False


def _sensitive_volumes(pipeline: Pipeline) -> list[tuple[str, str]]:
    """Return ``[(volume_name, host_path), ...]`` for offenders.

    Walks the pipeline-level ``volumes:`` declaration. A volume
    with a ``temp:`` block (tmpfs) is not a host bind and is
    skipped; only entries with a ``host.path`` field are
    classified.
    """
    out: list[tuple[str, str]] = []
    volumes = pipeline.data.get("volumes")
    if not isinstance(volumes, list):
        return out
    for entry in volumes:
        if not isinstance(entry, dict):
            continue
        host = entry.get("host")
        if not isinstance(host, dict):
            continue
        path = host.get("path")
        if not isinstance(path, str):
            continue
        if _is_sensitive(path):
            name = entry.get("name", "")
            out.append((str(name), path))
    return out


def _step_mounts(volume_name: str, step: dict[str, Any]) -> bool:
    """True when *step* mounts the named pipeline-level volume."""
    if not volume_name:
        return False
    volumes = step.get("volumes")
    if not isinstance(volumes, list):
        return False
    for v in volumes:
        if isinstance(v, dict) and v.get("name") == volume_name:
            return True
    return False


def check(pipeline: Pipeline) -> Finding:
    sensitive = _sensitive_volumes(pipeline)
    if not sensitive:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pipeline.path,
            description=(
                "Pipeline declares no host-bind volume of a "
                "sensitive host path."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    # Build a list of mounting steps per volume so the description
    # names exactly which step is the consumer of the dangerous
    # mount. A volume that's declared but unmounted still fires
    # but with a different breadcrumb so triage can distinguish
    # the two cases.
    offender_lines: list[str] = []
    for vol_name, host_path in sensitive:
        mounting_steps: list[str] = []
        for idx, step in iter_steps(pipeline):
            if _step_mounts(vol_name, step):
                mounting_steps.append(
                    f"steps.{step_label(step, idx)}"
                )
        for idx, svc in iter_services(pipeline):
            if _step_mounts(vol_name, svc):
                mounting_steps.append(
                    f"services.{step_label(svc, idx, kind='services')}"
                )
        if mounting_steps:
            offender_lines.append(
                f"volumes.{vol_name} -> {host_path} mounted by "
                f"{', '.join(mounting_steps[:3])}"
                f"{'...' if len(mounting_steps) > 3 else ''}"
            )
        else:
            offender_lines.append(
                f"volumes.{vol_name} -> {host_path} (declared, "
                f"not mounted by any step)"
            )
    desc = (
        f"{len(offender_lines)} sensitive host-path volume(s): "
        f"{'; '.join(offender_lines[:3])}"
        f"{'...' if len(offender_lines) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=False,
    )
