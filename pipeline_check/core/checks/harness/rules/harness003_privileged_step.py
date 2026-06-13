"""HARNESS-003. Step runs with ``privileged: true``."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import HarnessPipeline, iter_steps, step_label, step_spec

RULE = Rule(
    id="HARNESS-003",
    title="Step runs with privileged: true",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-5",),
    esf=("ESF-D-RUNTIME-HARDENING", "ESF-D-LEAST-PRIV"),
    cwe=("CWE-269", "CWE-250"),
    recommendation=(
        "Drop ``privileged: true`` from the step. The flag removes the "
        "container's syscall and capability boundary, giving the step "
        "kernel-level access to the build host. Most workloads that reach "
        "for it are Docker-in-Docker builds that can use a rootless "
        "alternative (``kaniko``, ``buildah --isolation=chroot``, BuildKit "
        "rootless) instead. If a genuine syscall is needed, scope it down "
        "with explicit added capabilities on an isolated build-infra pool "
        "rather than blanket privileged mode."
    ),
    docs_note=(
        "Harness CI ``Run`` / ``Background`` steps accept a "
        "``spec.privileged: true`` flag that maps to "
        "``docker run --privileged`` on the build pod / VM. The rule fires "
        "on any step (across CI and CD stages, through ``parallel`` / "
        "``stepGroup`` nesting) whose ``spec.privileged`` is truthy. Same "
        "model as DR-002 / BK-006 in this catalog."
    ),
    exploit_example=(
        "# Vulnerable: privileged removes the container boundary, so a\n"
        "# build-script RCE or poisoned image escapes to the build host\n"
        "# and from there to every other build sharing the infrastructure.\n"
        "- step:\n"
        "    type: Run\n"
        "    identifier: dind\n"
        "    spec:\n"
        "      image: docker:24\n"
        "      privileged: true\n"
        "      command: docker build -t app .\n"
        "\n"
        "# Safe: a rootless builder needs no privileged flag.\n"
        "- step:\n"
        "    type: Run\n"
        "    identifier: build\n"
        "    spec:\n"
        "      image: gcr.io/kaniko-project/executor@sha256:...\n"
        "      command: /kaniko/executor --destination app"
    ),
)


def _is_privileged(spec: dict[str, object]) -> bool:
    """Tolerate both YAML boolean ``true`` and the quoted string
    ``"true"`` (the docs_note promises "truthy"), mirroring drone DR-002."""
    value = spec.get("privileged")
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return False


def check(pipeline: HarnessPipeline) -> Finding:
    offenders: list[str] = []
    for stage_id, step in iter_steps(pipeline):
        if _is_privileged(step_spec(step)):
            offenders.append(step_label(stage_id, step))
    passed = not offenders
    desc = (
        "No step runs with privileged: true."
        if passed else
        f"{len(offenders)} step(s) run with privileged: true (full host "
        f"kernel access): {'; '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
