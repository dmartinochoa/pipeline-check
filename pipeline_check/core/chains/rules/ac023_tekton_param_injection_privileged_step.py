"""AC-023. Tekton param interpolated unsafely lands in a privileged step.

The Tekton-side analog of the AC-002 / AC-022 injection-meets-impact
shape, but the impact leg is *container privilege* rather than a
deploy gate. Two findings on the same Task / ClusterTask compose into
a node-escape primitive:

- **TKN-003.** A step's ``script:`` interpolates ``$(params.<name>)``
  directly into the shell body without quoting. PipelineRuns are the
  trigger surface. Anyone who can create a PipelineRun (a Git push
  to a GitOps repo, a webhook payload routed through a Tekton
  EventListener, a fork PR that fires a CEL Trigger filter) supplies
  the param value, and that value reaches the runner shell as
  literal syntax.

- **TKN-002.** The same step runs with
  ``securityContext.privileged: true``, ``runAsUser: 0``, or with
  ``capabilities.add`` granting a node-level capability
  (SYS_ADMIN, NET_ADMIN, SYS_PTRACE). The container has the kernel
  surface needed to mount block devices, write to ``/proc/sysrq-
  trigger``, attach to host processes, or load kernel modules
  through ``/lib/modules`` mounts.

Combined: a crafted PipelineRun param value injects a shell command
that executes inside a privileged container with root user. The
attacker has the two ingredients for a Kubernetes node escape (an
arbitrary command and a kernel-adjacent execution context) without
needing to touch cluster RBAC at all. AC-020 captures the
*lateral-movement* shape (cluster-admin binding lets an inside
runner pivot the cluster API); AC-023 captures the *initial-access
to execution* shape (the Task itself converts an external trigger
into privileged code execution).

Each leg has a fix that breaks the chain: drop the param from the
step body and pass it through ``env:`` (Tekton substitutes
``$(params.foo)`` into env values, where the shell then sees
``"$FOO"`` as a quoted argument), or remove the privileged /
root configuration. Both is best. The privileged step is a
hygiene smell even when the param injection isn't there, and a
quoted param is the right shape even on a non-privileged step.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-023",
    title="Tekton param injection lands in a privileged or root step",
    severity=Severity.CRITICAL,
    summary=(
        "A Tekton Task interpolates ``$(params.<name>)`` directly "
        "into a step's ``script:`` body without quoting (TKN-003) "
        "AND the same step runs ``privileged: true`` / "
        "``runAsUser: 0`` / with node-level ``capabilities.add`` "
        "(TKN-002). A crafted PipelineRun param value, supplied "
        "via a webhook payload, GitOps merge, or fork-PR-triggered "
        "EventListener, injects a shell command that executes "
        "inside a kernel-privileged container, the two ingredients "
        "for a Kubernetes node escape."
    ),
    mitre_attack=(
        "T1059",      # Command and Scripting Interpreter
        "T1068",      # Exploitation for Privilege Escalation
        "T1611",      # Escape to Host
    ),
    kill_chain_phase="initial-access -> execution -> privilege-escalation",
    references=(
        "https://tekton.dev/docs/pipelines/tasks/#using-variable-substitution",
        "https://tekton.dev/docs/triggers/eventlisteners/",
        "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution",
    ),
    recommendation=(
        "On the injection side: stop interpolating ``$(params.<name>)`` "
        "directly into a step's shell body. Pass the param through "
        "``env:``. Tekton substitutes the param into the env value "
        "at run time, and the shell then sees a quoted variable "
        "(``\"$FOO\"``) rather than syntax it can interpret. On the "
        "privilege side: drop ``securityContext.privileged: true``, "
        "set ``runAsNonRoot: true`` + a non-zero ``runAsUser``, and "
        "list only the specific Linux capabilities the step needs "
        "(most build tooling needs none). Either fix breaks the "
        "chain, a non-privileged container makes the injection a "
        "hygiene smell rather than a node-escape primitive, and a "
        "quoted param removes the injection regardless of "
        "container capabilities. Best is both, plus a Pod Security "
        "Admission ``restricted`` label on the namespace to enforce "
        "the privilege side at admission time."
    ),
    providers=("tekton",),
    triggering_check_ids=("TKN-002", "TKN-003"),
)


def match(findings: list[Finding]) -> list[Chain]:
    grouped = group_by_resource(findings, ["TKN-002", "TKN-003"])
    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        triggers = [ck_map["TKN-002"], ck_map["TKN-003"]]
        narrative = (
            f"In `{resource}`:\n"
            "  1. A step's ``script:`` interpolates "
            "``$(params.<name>)`` directly into the shell body "
            "without quoting (TKN-003). The Tekton variable "
            "substitution happens before the shell parses the "
            "command, so a param value supplied at PipelineRun "
            "creation time becomes literal shell syntax, a crafted "
            "value can append commands, redirect output, or open a "
            "subshell.\n"
            "  2. The same step runs with elevated container "
            "privileges (TKN-002): ``privileged: true``, "
            "``runAsUser: 0``, or ``capabilities.add`` carrying a "
            "node-level capability. The container has the kernel "
            "surface needed to escape to the host, mount block "
            "devices, write to ``/proc`` controls, attach to other "
            "processes, load kernel modules.\n"
            "  3. Combined: anyone who can create a PipelineRun for "
            "this Task, a webhook through a Tekton EventListener, "
            "a Git push to a GitOps repo, a fork PR routed through "
            "a CEL Trigger filter, supplies a param value that "
            "executes as a shell command inside a kernel-privileged "
            "container, with root or near-root authority on the "
            "node. Pass the param via ``env:`` (Tekton substitutes "
            "into env values, the shell sees a quoted variable) or "
            "drop the privileged / root setting, either fix "
            "breaks the chain."
        )
        out.append(Chain(
            chain_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            confidence=min_confidence(triggers),
            summary=RULE.summary,
            narrative=narrative,
            mitre_attack=list(RULE.mitre_attack),
            kill_chain_phase=RULE.kill_chain_phase,
            triggering_check_ids=["TKN-002", "TKN-003"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
        ))
    return out
