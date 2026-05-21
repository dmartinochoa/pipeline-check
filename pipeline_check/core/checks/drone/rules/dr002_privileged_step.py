"""DR-002. Step runs with ``privileged: true``."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    Pipeline,
    is_container_pipeline,
    iter_services,
    iter_steps,
    step_label,
)

RULE = Rule(
    id="DR-002",
    title="Step runs with privileged: true",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-5",),
    esf=("ESF-D-RUNTIME-HARDENING", "ESF-D-LEAST-PRIV"),
    cwe=("CWE-269", "CWE-250"),
    recommendation=(
        "Drop ``privileged: true`` from the step. The flag "
        "removes the container's syscall and capability "
        "boundary, giving the step kernel-level access to the "
        "agent host. Most workloads that reach for it are "
        "Docker-in-Docker pipelines that can use a rootless "
        "alternative (``buildx``, ``kaniko``, ``buildah "
        "--isolation=chroot``) instead. If the workload "
        "genuinely needs syscalls, scope down with explicit "
        "``cap_add: [SYS_ADMIN]`` and an isolated runner pool, "
        "rather than blanket privileged."
    ),
    docs_note=(
        "Drone's ``privileged: true`` is a step-scoped switch "
        "that maps directly to ``docker run --privileged``. The "
        "rule fires on either steps or services declaring the "
        "flag. The agent admin can also globally allow / deny "
        "privileged steps via the trusted-flag on the "
        "repository, the rule doesn't try to reach into Drone's "
        "server config and assumes the worst (a malicious or "
        "accidentally-trusted repo) so a ``privileged: true`` "
        "in source is always a finding."
    ),
    exploit_example=(
        "# Vulnerable: ``privileged: true`` grants the step\n"
        "# container access to the host kernel's namespaces and\n"
        "# /dev. A workload compromise (poisoned image, build-\n"
        "# script RCE) escapes to the runner host and from there\n"
        "# to every other build sharing the runner.\n"
        "kind: pipeline\n"
        "type: docker\n"
        "name: build\n"
        "steps:\n"
        "  - name: dind-build\n"
        "    image: docker:24\n"
        "    privileged: true\n"
        "    commands:\n"
        "      - docker build -t app .\n"
        "\n"
        "# Safe: use a rootless image builder (Kaniko, BuildKit\n"
        "# rootless) that produces images without privileged host\n"
        "# access. Drop ``privileged`` entirely.\n"
        "kind: pipeline\n"
        "type: docker\n"
        "name: build\n"
        "steps:\n"
        "  - name: kaniko-build\n"
        "    image: gcr.io/kaniko-project/executor@sha256:abc123...\n"
        "    commands:\n"
        "      - /kaniko/executor --context=. --destination=registry/app:tag"
    ),
)


def _is_privileged(node: dict[str, object]) -> bool:
    """Drone accepts both YAML boolean ``true`` and the string
    ``\"true\"``; tolerate both."""
    value = node.get("privileged")
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return False


def check(pipeline: Pipeline) -> Finding:
    if not is_container_pipeline(pipeline):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=pipeline.path,
            description=(
                "Pipeline type is not container-flavored "
                "(docker/kubernetes); the privileged flag does "
                "not apply."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    for idx, step in iter_steps(pipeline):
        if _is_privileged(step):
            offenders.append(f"steps.{step_label(step, idx)}")
    for idx, svc in iter_services(pipeline):
        if _is_privileged(svc):
            offenders.append(
                f"services.{step_label(svc, idx, kind='services')}"
            )
    passed = not offenders
    desc = (
        "No step or service runs with ``privileged: true``."
        if passed else
        f"{len(offenders)} step(s) / service(s) declare "
        f"``privileged: true``: {', '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
