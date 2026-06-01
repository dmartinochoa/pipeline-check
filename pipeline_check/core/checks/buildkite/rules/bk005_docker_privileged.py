"""BK-005, ``docker run --privileged`` in step commands."""
from __future__ import annotations

from typing import Any

from ...base import DOCKER_INSECURE_RE, Finding, Severity
from ...rule import Rule
from ..base import iter_command_steps, iter_plugins, step_commands, step_label


def _plugin_escalation(step: dict[str, Any]) -> str | None:
    """Return a reason string when a docker plugin opts into host access.

    The docker / docker-compose Buildkite plugins express the same
    escalation as a ``docker run --privileged`` command through config:
    ``privileged: true`` or mounting the host Docker socket.
    """
    for ref, cfg in iter_plugins(step):
        if "docker" not in ref.lower() or not isinstance(cfg, dict):
            continue
        if cfg.get("privileged") is True:
            return f"{ref}: privileged: true"
        volumes = cfg.get("volumes")
        if isinstance(volumes, list) and any(
            isinstance(vol, str) and "/var/run/docker.sock" in vol
            for vol in volumes
        ):
            return f"{ref}: /var/run/docker.sock mount"
    return None

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
    exploit_example=(
        "# Vulnerable: ``--privileged`` plus the host Docker socket\n"
        "# gives the build container full access to the agent's\n"
        "# kernel and the runtime that started it. A compromise\n"
        "# (poisoned base image, RCE in app code) escapes to the\n"
        "# agent and from there to every other build sharing the\n"
        "# agent.\n"
        "steps:\n"
        "  - command: ./integration-test.sh\n"
        "    plugins:\n"
        "      - docker#v5.10.0:\n"
        "          image: app@sha256:abc123...\n"
        "          privileged: true\n"
        "          volumes:\n"
        "            - /var/run/docker.sock:/var/run/docker.sock\n"
        "\n"
        "# Safe: drop ``privileged`` and the socket mount. If the\n"
        "# build genuinely needs to build images, use a rootless\n"
        "# sandbox (Kaniko, BuildKit rootless, buildah\n"
        "# ``--isolation=chroot``) that produces images without\n"
        "# host-runtime access.\n"
        "steps:\n"
        "  - command: ./integration-test.sh\n"
        "    plugins:\n"
        "      - docker#v5.10.0:\n"
        "          image: app@sha256:abc123...\n"
        "          privileged: false"
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for idx, step in iter_command_steps(doc):
        matched = False
        for cmd in step_commands(step):
            m = DOCKER_INSECURE_RE.search(cmd)
            if m:
                offenders.append(f"{step_label(step, idx)}: {m.group(0)}")
                matched = True
                break
        if matched:
            continue
        reason = _plugin_escalation(step)
        if reason:
            offenders.append(f"{step_label(step, idx)}: {reason}")
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
