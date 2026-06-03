"""AC-025. Argo param interpolated unsafely lands in a privileged step.

The Argo-side mirror of AC-023. Same two-leg shape, attacker-
controllable param meets kernel-privileged container, but routed
through Argo Workflows' template / parameter / Sensor mechanics
rather than Tekton's params + EventListener path. Also distinct
from AC-021 (Argo default-SA + K8S-029 RoleBinding): AC-021
captures the *static-RBAC lateral-movement* shape (the default SA
the workflow inherits has dangerous binding), AC-025 captures the
*trigger-to-execution* shape (the Workflow itself converts a
Sensor / CronWorkflow / WorkflowEventBinding payload into in-pod
privileged code execution, regardless of what the SA can reach).

Two findings on the same Workflow / WorkflowTemplate / ClusterWorkflowTemplate:

- **ARGO-005.** A template's ``script.source`` or ``container.command
  ``/``args`` interpolates ``{{inputs.parameters.<name>}}`` /
  ``{{workflow.parameters.<name>}}`` directly into a shell body
  without quoting. Argo substitutes the value before the shell
  parses, so a Sensor-supplied param value reaches the runner
  shell as literal syntax, append commands, redirect output,
  open a subshell.

- **ARGO-002.** The same template's container runs with
  ``securityContext.privileged: true``, ``runAsUser: 0``, or with
  ``capabilities.add`` carrying a node-level capability
  (SYS_ADMIN, NET_ADMIN, SYS_PTRACE). The container has the
  kernel surface needed for a node escape, mount block devices,
  write to ``/proc/sysrq-trigger``, attach to host processes,
  load kernel modules.

Combined: anyone who can submit a Workflow against this template
(a webhook payload that fires an Argo Events Sensor, a GitOps PR
merge that triggers a CronWorkflow, a CEL-filtered fork PR via a
WorkflowEventBinding) supplies a param value that executes as a
shell command inside a kernel-privileged container. The
``serviceAccountName`` and any RoleBindings are irrelevant to
this leg of the attack: the escape is to the *node*, not via the
*K8s API*. RBAC fixes (AC-021's recommendations) don't break this
chain.

Each leg has an independent fix. Drop the param from the script
body and pass it via the template's ``env:`` (Argo substitutes
into env values, where the shell sees a quoted variable), or
strip the privileged / root configuration. Best is both, and a
Pod Security Admission ``restricted`` label on the namespace to
enforce the privilege side at admission time, since template-
level config is easy to drift back over time.
"""
from __future__ import annotations

from ...checks.base import Confidence, Finding, Severity
from .._reachability import assess_reachability
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-025",
    title="Argo param injection lands in a privileged or root step",
    severity=Severity.CRITICAL,
    summary=(
        "An Argo Workflow / WorkflowTemplate interpolates "
        "``{{inputs.parameters.<name>}}`` / "
        "``{{workflow.parameters.<name>}}`` directly into a "
        "template's ``script.source`` or container "
        "``command``/``args`` without quoting (ARGO-005) AND the "
        "same template runs ``privileged: true`` / ``runAsUser: 0`` "
        "/ with node-level ``capabilities.add`` (ARGO-002). A "
        "crafted param value supplied via an Argo Events Sensor "
        "webhook, a CronWorkflow trigger, or a WorkflowEventBinding "
        "fork-PR path injects a shell command that executes inside "
        "a kernel-privileged container, the two ingredients for "
        "a Kubernetes node escape, regardless of what the workflow's "
        "ServiceAccount can reach via the API."
    ),
    mitre_attack=(
        "T1059",      # Command and Scripting Interpreter
        "T1068",      # Exploitation for Privilege Escalation
        "T1611",      # Escape to Host
    ),
    kill_chain_phase="initial-access -> execution -> privilege-escalation",
    references=(
        "https://argo-workflows.readthedocs.io/en/latest/walk-through/parameters/",
        "https://argoproj.github.io/argo-events/sensors/sensor/",
        "https://argo-workflows.readthedocs.io/en/latest/workflow-of-workflows/",
        "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution",
    ),
    recommendation=(
        "On the injection side: stop interpolating "
        "``{{inputs.parameters.<name>}}`` / "
        "``{{workflow.parameters.<name>}}`` directly into a "
        "template's shell body. Bind the param to a template "
        "``env:`` entry (``env: [{name: FOO, value: '{{inputs."
        "parameters.foo}}'}]``) and reference the env var "
        "inside double quotes (``echo \"$FOO\"``). Argo "
        "substitutes into env values, the shell then sees one "
        "literal argument rather than interpreted syntax. On the "
        "privilege side: drop ``securityContext.privileged: "
        "true``, set ``runAsNonRoot: true`` + a non-zero "
        "``runAsUser``, and list only the specific Linux "
        "capabilities the step needs. Either fix breaks the "
        "chain, a non-privileged container makes the injection "
        "a hygiene smell rather than a node-escape primitive, "
        "and a quoted param removes the injection regardless of "
        "container capabilities. Best is both, plus a Pod "
        "Security Admission ``restricted`` label on the "
        "namespace to enforce the privilege side at admission "
        "time."
    ),
    providers=("argo",),
    triggering_check_ids=("ARGO-002", "ARGO-005"),
)


def match(findings: list[Finding]) -> list[Chain]:
    # Reachability mirrors the AC-022 (GitLab) phase-2 pattern, scoped
    # to Argo's template namespace. A shared template anchor
    # (``<Kind>/<name>:<template>``) between ARGO-002 (privileged / root
    # container) and ARGO-005 (unsafe ``{{inputs.parameters.X}}`` in
    # script / args / command) confirms the same template is BOTH the
    # injection sink AND the privilege amplifier, the single-template
    # node-escape primitive. TAINT-007 adds Argo's cross-template
    # channel, ``{{tasks.<t>.outputs.parameters.<o>}}``, as structured
    # source->sink edges keyed by the same ``<Kind>/<name>:<template>``
    # anchors: ``assess_reachability`` walks them from the injection
    # template(s) (widened with the output-producer templates) to the
    # privileged template(s), so a producer template whose tainted
    # output flows into a *separate* privileged consumer template still
    # resolves to a confirmed dataflow path. When ARGO-002's privilege
    # comes from a workflow-wide ``spec.podSpecPatch``, it fans out an
    # anchor per template so any one consumer still matches. Disjoint
    # anchors with no dataflow edge keep the weaker co-occurrence signal
    # so existing detections don't regress.
    grouped = group_by_resource(findings, ["ARGO-002", "ARGO-005"])
    # Map resource -> TAINT-007 finding (cross-template outputs taint).
    taint_by_resource: dict[str, Finding] = {}
    for f in findings:
        if not f.passed and f.check_id == "TAINT-007":
            taint_by_resource[f.resource] = f

    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        argo002 = ck_map["ARGO-002"]
        argo005 = ck_map["ARGO-005"]
        triggers = [argo002, argo005]

        priv_templates = set(argo002.job_anchors)
        inj_templates = set(argo005.job_anchors)

        # TAINT-007 supplies the cross-template outputs channel as
        # source->sink edges; widen the injection side with the
        # producer templates so a producer->privileged-consumer flow
        # resolves to a confirmed path.
        taint_findings: list[Finding] = []
        taint = taint_by_resource.get(resource)
        if taint is not None:
            triggers.append(taint)
            taint_findings.append(taint)
            inj_templates |= {fl.source_job for fl in taint.taint_flows}

        reach = assess_reachability(taint_findings, inj_templates, priv_templates)
        confirmed = reach.confirmed
        reach_note = reach.note
        if reach.via_dataflow:
            reach_narrative = (
                f"  4. Reachability confirmed by dataflow: {reach.note}. "
                f"A producer template's tainted "
                f"``outputs.parameters`` value is carried into the "
                f"privileged template via "
                f"``{{{{tasks.<t>.outputs.parameters.<o>}}}}``, so the "
                f"injection reaches the kernel-privileged container "
                f"across templates, not just within one."
            )
        elif confirmed:
            reach_narrative = (
                f"  4. Reachability confirmed: {reach.note}. The same "
                f"template BOTH runs privileged AND interpolates "
                f"``{{{{inputs.parameters.<name>}}}}`` unquoted. A "
                f"crafted Workflow-submission param value executes as "
                f"a shell command inside the kernel-privileged "
                f"container in one go, no inter-template dataflow "
                f"required."
            )
        else:
            reach_narrative = (
                "  4. Reachability unconfirmed: the privileged "
                "template and the param-injection sink live in "
                "different templates of this Argo corpus, with no "
                "``outputs.parameters`` dataflow link between them. "
                "Each leg is independently risky but neither single "
                "template exposes the kernel-RCE primitive; treat as "
                "a co-occurrence signal."
            )

        narrative = (
            f"In `{resource}`:\n"
            "  1. A template's ``script.source`` or container "
            "``args`` interpolates ``{{inputs.parameters.<name>}} "
            "`` or ``{{workflow.parameters.<name>}}`` directly "
            "into a shell body without quoting (ARGO-005). Argo "
            "performs the substitution before the shell parses "
            "the command, so a param value supplied at Workflow-"
            "submission time becomes literal shell syntax, a "
            "crafted value can append commands, redirect output, "
            "or open a subshell.\n"
            "  2. The same template runs with elevated container "
            "privileges (ARGO-002): ``privileged: true``, "
            "``runAsUser: 0``, or ``capabilities.add`` carrying a "
            "node-level capability. The container has the kernel "
            "surface needed to escape to the host.\n"
            "  3. Combined: anyone who can submit a Workflow "
            "against this template (a webhook routed through an "
            "Argo Events Sensor, a CronWorkflow trigger, a CEL-"
            "filtered fork PR via WorkflowEventBinding, a direct "
            "``argo submit`` from a developer with namespace "
            "access) supplies a param value that executes as a "
            "shell command inside a kernel-privileged container, "
            "with root or near-root authority on the node. "
            "ServiceAccount-side fixes (AC-021's recommendations) "
            "don't break this chain. The escape route is the "
            "node, not the K8s API. Pass the param via ``env:`` "
            "or drop the privileged / root setting; either fix "
            "alone breaks the chain.\n"
            f"{reach_narrative}"
        )
        if reach.path:
            narrative += f"\n  Dataflow evidence: {reach.path}"

        chain_confidence = Confidence.HIGH if confirmed else min_confidence(triggers)

        out.append(Chain(
            chain_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            confidence=chain_confidence,
            summary=RULE.summary,
            narrative=narrative,
            mitre_attack=list(RULE.mitre_attack),
            kill_chain_phase=RULE.kill_chain_phase,
            triggering_check_ids=sorted({f.check_id for f in triggers}),
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
            confirmed_reachable=confirmed,
            reachability_note=reach_note,
            via_dataflow=reach.via_dataflow,
        ))
    return out
