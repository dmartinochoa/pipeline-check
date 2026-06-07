"""AC-026. Buildkite untrusted-variable injection lands on unmanual deploy.

The Buildkite analog of AC-002 (``GHA-003`` + ``GHA-014``) and
AC-022 (``GL-002`` + ``GL-004``). Every CI provider with a script-
injection primitive and a deploy-gate primitive can compose this
same shape; until now the chain catalog covered GitHub and GitLab
on this surface and left Buildkite as the one provider with both
ingredients but no chain combining them.

The two findings, firing on the same ``pipeline.yml``, compose into
a fork-controllable production push:

- **BK-003.** A step's ``command:`` interpolates an untrusted
  Buildkite variable: a commit subject, branch name, tag, or
  pull-request title. Buildkite expands these (``$BUILDKITE_MESSAGE``,
  ``$BUILDKITE_BRANCH``, ``$BUILDKITE_TAG``, ``$BUILDKITE_PULL_REQUEST_TITLE``)
  before the shell parses the command, so a crafted commit message
  becomes literal shell syntax inside the runner.

- **BK-007.** A deploy-named step (``deploy``, ``release``,
  ``publish``, ``promote``) has no ``manual:`` block and no
  ``input:`` block. The pipeline rolls forward automatically when
  the upstream conditions match.

Combined: anyone who can land a commit on a branch the pipeline
runs against (a fork PR build, a feature branch the runner
auto-deploys from, or a tag push if the deploy step is tag-gated)
supplies the injection vector AND triggers the unattended deploy
in the same run. The injection executes inside the runner with
the deploy step's environment: secrets, AWS / GCP credentials,
Kubernetes contexts, registry push tokens. Exfil or substitute is
trivial; rollback is much harder than refusing the deploy in the
first place.

Each leg has a clean fix that breaks the chain. Quote the
interpolation (or, better, push the untrusted value through a
step env binding so the shell sees a quoted variable) and you
remove the injection regardless of what the deploy step does.
Add ``manual: { prompt: 'Deploy to prod?' }`` (or a separate
``input:`` step) and you require a human to acknowledge the
deploy regardless of what the previous step's command did. Best
is both: defense in depth on the same kill chain.
"""
from __future__ import annotations

from ...checks.base import Confidence, Finding, Severity
from .._reachability import assess_reachability
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-026",
    title="Buildkite injection lands on auto-deploy step with no manual gate",
    severity=Severity.CRITICAL,
    summary=(
        "A ``pipeline.yml`` interpolates an untrusted Buildkite "
        "variable (``$BUILDKITE_MESSAGE``, ``$BUILDKITE_BRANCH``, "
        "``$BUILDKITE_PULL_REQUEST_TITLE``, etc.) into a step's "
        "``command:`` body (BK-003) AND a deploy-named step in the "
        "same pipeline runs without a ``manual:`` or ``input:`` "
        "gate (BK-007). The combination converts a fork-controllable "
        "injection point into an unattended production push, the "
        "Buildkite analog of AC-002 / AC-022 on the GitHub and "
        "GitLab surfaces."
    ),
    mitre_attack=(
        "T1059",      # Command and Scripting Interpreter
        "T1078",      # Valid Accounts (deploy creds)
        "T1556",      # Modify Authentication Process
    ),
    kill_chain_phase="initial-access -> execution -> impact",
    references=(
        "https://buildkite.com/docs/pipelines/environment-variables",
        "https://buildkite.com/docs/pipelines/block-step",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-01-Insufficient-Flow-Control-Mechanisms",
    ),
    recommendation=(
        "On the injection side: stop interpolating Buildkite "
        "metadata variables directly into ``command:`` bodies. "
        "Bind the value through ``env:`` instead "
        "(``env: { MSG: \"$BUILDKITE_MESSAGE\" }`` then reference "
        "``\"$MSG\"`` inside the command) so the shell sees a "
        "quoted variable rather than syntax it can interpret. On "
        "the gate side: every deploy-named step should carry a "
        "``manual:`` block (or be preceded by a separate "
        "``input:`` step) so a human reviewer acknowledges the "
        "deploy. Configure the manual block's ``branches:`` filter "
        "and the surrounding step's ``branches:`` filter together "
        "so a fork PR build can't trigger production. Either fix "
        "breaks the chain; both is best."
    ),
    providers=("buildkite",),
    triggering_check_ids=("BK-003", "BK-007"),
)


def match(findings: list[Finding]) -> list[Chain]:
    # Reachability mirrors the AC-022 (GitLab) phase-2 pattern.
    # Buildkite pipelines are a flat list of steps, not named jobs, so
    # the "anchor" each leg surfaces is the step label (``key`` >
    # ``label`` > ``steps[N]`` fallback). TAINT-005 models the canonical
    # cross-step channel, ``buildkite-agent meta-data set`` in a
    # producer step read back via ``meta-data get`` in a consumer step,
    # as structured ``source_job -> sink_job`` edges keyed by the same
    # step labels. ``assess_reachability`` walks those edges from the
    # injection step(s) (widened with the meta-data producer steps) to
    # the deploy step(s): a hit means the untrusted value the producer
    # wrote is read by the ungated deploy step, a proven path rather
    # than mere file co-occurrence. With no dataflow edge it falls back
    # to the phase-1 shared-step signal, and to plain co-occurrence
    # when the legs are on different steps, so nothing regresses.
    grouped = group_by_resource(findings, ["BK-003", "BK-007"])
    # Map resource -> TAINT-005 finding (the meta-data taint graph) so a
    # producer-side injection in one step and a consumer-side read in
    # the deploy step still resolve to a confirmed dataflow chain.
    taint_by_resource: dict[str, Finding] = {}
    for f in findings:
        if not f.passed and f.check_id == "TAINT-005":
            taint_by_resource[f.resource] = f

    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        bk003 = ck_map["BK-003"]
        bk007 = ck_map["BK-007"]
        triggers = [bk003, bk007]

        injection_steps = set(bk003.job_anchors)
        deploy_steps = set(bk007.job_anchors)

        # TAINT-005 supplies Buildkite's cross-step meta-data channel as
        # structured source->sink edges; widen the injection side with
        # the producer steps so a meta-data round-trip into the deploy
        # step resolves to a confirmed path.
        taint_findings: list[Finding] = []
        taint = taint_by_resource.get(resource)
        if taint is not None:
            triggers.append(taint)
            taint_findings.append(taint)
            injection_steps |= {fl.source_job for fl in taint.taint_flows}

        reach = assess_reachability(taint_findings, injection_steps, deploy_steps)
        confirmed = reach.confirmed
        reach_note = reach.note
        if reach.via_dataflow:
            reach_narrative = (
                f"  4. Reachability confirmed by dataflow: {reach.note}. "
                f"The untrusted value is carried to the unmanual deploy "
                f"by a real meta-data round-trip "
                f"(``buildkite-agent meta-data set`` -> ``get``), not "
                f"just co-location in `{resource}`."
            )
        elif confirmed:
            shared_repr = reach.note
            reach_narrative = (
                f"  4. Co-located (unverified): {shared_repr}. The "
                f"untrusted interpolation and the unmanual deploy fire "
                f"on the same step, so the injected command executes "
                f"in the deploy step's own runner with its secrets in "
                f"scope."
            )
        else:
            reach_narrative = (
                "  4. Reachability unconfirmed: the injection and "
                "the unmanual deploy fire on the same pipeline file "
                "but on different steps, with no meta-data dataflow "
                "link between them. Treat as a co-occurrence signal "
                "rather than a proven path."
            )

        narrative = (
            f"In `{resource}`:\n"
            "  1. A step's ``command:`` interpolates an untrusted "
            "Buildkite variable (BK-003): commit subject, branch "
            "name, tag name, or pull-request title. Buildkite "
            "expands these before the shell parses the command, so "
            "a crafted commit message becomes literal shell syntax "
            "inside the runner.\n"
            "  2. A deploy-named step in the same pipeline has no "
            "``manual:`` or ``input:`` gate (BK-007). The pipeline "
            "rolls forward automatically when its upstream "
            "conditions match.\n"
            "  3. Combined: anyone who can land a commit on a "
            "branch this pipeline builds, fork-PR builds, feature "
            "branches the runner auto-deploys from, supplies the "
            "injection vector AND triggers the unattended deploy "
            "in the same run. The injected command executes with "
            "the deploy step's secrets and credentials. Quote the "
            "interpolation (or push it through ``env:``) AND add "
            "a ``manual:`` block to the deploy step; either fix "
            "breaks the chain, both is best.\n"
            f"{reach_narrative}"
        )
        if reach.path:
            narrative += f"\n  Dataflow evidence: {reach.path}"

        if confirmed:
            chain_confidence = Confidence.HIGH
        else:
            chain_confidence = min_confidence(triggers)

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
