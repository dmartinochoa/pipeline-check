"""AC-022. GitLab CI script injection lands on a deploy job with no
manual approval or environment gate.

The GitLab analog of AC-002 (the GHA ``script-injection +
unprotected-deploy`` chain). Two findings each individually wrong
become an end-to-end CI takeover when they fire on the same
``.gitlab-ci.yml``:

- **GL-002.** A job's ``script:`` interpolates an attacker-influenced
  field (``$CI_COMMIT_TITLE``, ``$CI_COMMIT_DESCRIPTION``,
  ``$CI_MERGE_REQUEST_TITLE``, or a branch / tag name). Any of these
  reach the runner shell unsanitized, so a fork-MR author who
  controls the field controls the command line.

- **GL-004.** A deploy job (``deploy:``, ``stage: deploy``,
  ``environment:`` set to a prod-like name) runs without a manual
  approval (``when: manual``), without ``environment.deployment_tier:
  production`` + protected branches, and without ``rules:`` /
  ``only:`` that limit it to the default branch. The job ships
  whatever artifacts the upstream stages produced, on every
  successful pipeline.

Combined: a fork MR (or a push to any branch the pipeline runs on)
that crafts a malicious commit title injects a shell command into
the build stage's runner, which writes its payload into the
artifacts the deploy stage consumes, and the deploy stage runs
unattended. The runner's ``CI_JOB_TOKEN`` plus whatever deploy
secrets the job needs (cloud provider keys, kube configs,
container-registry credentials) become attacker-controlled with
no human in the loop.

Each leg has a fix that breaks the chain: switch the
``$CI_COMMIT_*`` interpolation to a quoted ``CI_*`` env-var
reference (``echo "$TITLE"`` where ``variables: TITLE:
$CI_COMMIT_TITLE``) or move the deploy job behind ``when: manual``
+ a protected ``environment:``. Both is best.
"""
from __future__ import annotations

from ...checks.base import Confidence, Finding, Severity
from .._reachability import assess_reachability
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-022",
    title="GitLab script injection lands on deploy job with no manual gate",
    severity=Severity.CRITICAL,
    summary=(
        "A ``.gitlab-ci.yml`` job interpolates an attacker-controlled "
        "context field directly into its ``script:`` (GL-002) AND a "
        "deploy job in the same file lacks a manual approval / "
        "protected ``environment:`` gate (GL-004). A crafted commit "
        "title or MR description from any branch the pipeline runs "
        "on injects a shell command into the build stage; the "
        "deploy stage then ships the resulting artifacts to "
        "production unattended."
    ),
    mitre_attack=(
        "T1059",      # Command and Scripting Interpreter
        "T1078",      # Valid Accounts
        "T1556",      # Modify Authentication Process
    ),
    kill_chain_phase="initial-access -> execution -> impact",
    references=(
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution",
        "https://docs.gitlab.com/ee/ci/environments/protected_environments.html",
        "https://docs.gitlab.com/ee/ci/yaml/#whenmanual",
        "https://docs.gitlab.com/ee/ci/variables/predefined_variables.html",
    ),
    recommendation=(
        "On the injection side: never interpolate ``$CI_COMMIT_*`` / "
        "``$CI_MERGE_REQUEST_*`` directly into a shell command. "
        "Bind the field to a job-scoped ``variables:`` entry and "
        "reference the variable inside double quotes (``echo "
        "\"$TITLE\"``), so the shell sees one literal argument "
        "rather than interpreted syntax. On the deploy side: gate "
        "every job that publishes artifacts, applies infrastructure, "
        "or pushes to a registry behind ``when: manual`` plus an "
        "``environment:`` mapped to a *protected* environment in "
        "GitLab settings, and use ``rules:``/``only:`` to limit the "
        "job to the default branch. Either fix breaks the chain; "
        "doing both also closes off the same primitive against "
        "future rule additions."
    ),
    providers=("gitlab",),
    triggering_check_ids=("GL-002", "GL-004"),
)


def match(findings: list[Finding]) -> list[Chain]:
    # Reachability mirrors the AC-002 (GHA) pilot: intersect the
    # injection-side ``job_anchors`` (GL-002, the jobs whose ``script:``
    # interpolated an untrusted CI variable) with the deploy-side
    # ``job_anchors`` (GL-004, the jobs that deploy without a manual
    # gate or protected environment). A non-empty intersection means
    # the same job both interpolates untrusted input AND ships
    # unattended — a confirmed end-to-end path, not just file co-
    # occurrence. TAINT-004 (dotenv-artifact cross-job propagation)
    # and TAINT-008 (``extends:`` template-inheritance propagation)
    # widen the injection-side set with sink jobs reachable via
    # GitLab's two cross-job dataflow channels, so a producer-side
    # GL-002 in one job and a consumer-side read in another job still
    # resolves to a confirmed chain. The chain still fires when the
    # intersection is empty so we don't regress the legacy co-
    # occurrence signal, but the report flags it as unconfirmed and
    # keeps the weakest-leg confidence.
    grouped = group_by_resource(findings, ["GL-002", "GL-004"])
    # Map resource -> { check_id -> Finding } for the injection-side
    # corroborators, picked up if present on the same pipeline file.
    taint_by_resource: dict[str, dict[str, Finding]] = {}
    for f in findings:
        if f.passed or f.check_id not in {"TAINT-004", "TAINT-008"}:
            continue
        taint_by_resource.setdefault(f.resource, {})[f.check_id] = f

    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        gl002 = ck_map["GL-002"]
        gl004 = ck_map["GL-004"]
        triggers: list[Finding] = [gl002, gl004]

        injection_jobs = set(gl002.job_anchors)
        deploy_jobs = set(gl004.job_anchors)
        # TAINT-004 (dotenv) and TAINT-008 (extends) supply GitLab's two
        # cross-job dataflow channels as structured source->sink edges.
        taint_findings: list[Finding] = []
        for check_id in ("TAINT-004", "TAINT-008"):
            tf = taint_by_resource.get(resource, {}).get(check_id)
            if tf is None:
                continue
            triggers.append(tf)
            taint_findings.append(tf)
            injection_jobs |= {fl.source_job for fl in tf.taint_flows}

        # Phase-2 reachability: walk the dotenv / extends taint graph
        # between the injection job(s) and the deploy job(s); fall back
        # to the phase-1 shared-job signal when no dataflow path exists.
        reach = assess_reachability(taint_findings, injection_jobs, deploy_jobs)
        confirmed = reach.confirmed
        reach_note = reach.note
        if reach.via_dataflow:
            reach_narrative = (
                f"  4. Reachability confirmed by dataflow: {reach.note}. "
                f"The untrusted value is carried to the ungated deploy by "
                f"a real source-to-sink taint path (dotenv artifact or "
                f"``extends:`` inheritance), not just co-location in "
                f"`{resource}`."
            )
        elif confirmed:
            reach_narrative = (
                f"  4. Reachability confirmed: {reach.note}. The "
                f"untrusted interpolation and the ungated deploy execute "
                f"in the same job, so the injection reaches the deploy "
                f"context."
            )
        else:
            reach_narrative = (
                "  4. Reachability unconfirmed: the injection sink "
                "and the ungated deploy fire on the same pipeline "
                "file but on different jobs, with no dotenv-"
                "artifact or ``extends:`` dataflow link detected "
                "between them. Treat as a co-occurrence signal "
                "rather than a proven path."
            )

        narrative = (
            f"In `{resource}`:\n"
            "  1. A job's ``script:`` interpolates an attacker-"
            "controlled GitLab context field (a commit title, MR "
            "description, branch name, or similar) (GL-002). The "
            "field reaches the runner's shell unsanitized, so a "
            "crafted commit message becomes a shell command in the "
            "build stage.\n"
            "  2. A deploy job in the same file has no ``when: "
            "manual`` approval and no protected ``environment:`` "
            "binding (GL-004). GitLab's protected-environment "
            "rules (required reviewers, deployment-branch "
            "restrictions, manual approval) only apply to jobs "
            "that opt in, so this job ships whatever the upstream "
            "stages produced on every successful pipeline.\n"
            "  3. Together: the injection in stage 1 modifies the "
            "artifacts (or env / config) that stage 2 consumes, "
            "and stage 2 deploys without a human in the loop. The "
            "runner's ``CI_JOB_TOKEN`` plus the deploy job's "
            "production secrets execute attacker-controlled "
            "behavior. Quote the interpolation through a "
            "``variables:`` indirection or move the deploy behind "
            "``when: manual``. Either breaks the chain.\n"
            f"{reach_narrative}"
        )
        if reach.path:
            narrative += f"\n  Dataflow evidence: {reach.path}"

        # Confirmed reachability promotes the composite to HIGH
        # confidence; unconfirmed chains keep the weakest-leg
        # confidence so they don't outrank a single HIGH finding.
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
