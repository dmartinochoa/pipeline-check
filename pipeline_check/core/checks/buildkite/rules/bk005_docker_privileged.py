"""BK-005 — ``docker run --privileged`` in step commands."""
from __future__ import annotations

from typing import Any

from ...base import DOCKER_INSECURE_RE, Finding, Severity
from ...rule import Rule
from ..base import iter_command_steps, step_commands, step_label

RULE = Rule(
    id="BK-005",
    title="Container started with --privileged or host-bind escalation",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-5",),
    esf=("ESF-D-RUNTIME-HARDENING",),
    cwe=("CWE-269", "CWE-250"),
    recommendation=(
        "Drop ``--privileged``, ``--cap-add=SYS_ADMIN``, ``--pid=host``, "
        "and ``-v /var/run/docker.sock`` from container invocations. If "
        "the workload needs Docker-in-Docker, use a build-specific "
        "rootless option (``buildx``, ``kaniko``, ``buildah --isolation"
        "=chroot``) instead of opening the host kernel and the agent's "
        "Docker socket to the build script."
    ),
    docs_note=(
        "Detection fires on ``--privileged``, ``--cap-add=SYS_ADMIN``, "
        "``--pid=host`` / ``--ipc=host`` / ``--userns=host``, and "
        "explicit mounts of the host Docker socket "
        "(``/var/run/docker.sock``)."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for idx, step in iter_command_steps(doc):
        for cmd in step_commands(step):
            m = DOCKER_INSECURE_RE.search(cmd)
            if m:
                offenders.append(
                    f"{step_label(step, idx)}: {m.group(0)}"
                )
                break
    passed = not offenders
    desc = (
        "No --privileged / host-bind container invocations."
        if passed else
        f"{len(offenders)} step(s) run containers with elevated host "
        f"access: {'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Switch to a rootless "
        f"build path (buildx, kaniko, buildah)."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
