"""AC-002. Script Injection to Unprotected Production Deploy.

A workflow that interpolates untrusted PR/issue input into a shell
step (script-injection) and deploys without a gated environment
gives a PR opener a path straight to production.
"""
from __future__ import annotations

from ...checks.base import Confidence, Finding, Severity
from .._reachability import assess_reachability
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-002",
    title="Script Injection to Unprotected Deploy",
    severity=Severity.CRITICAL,
    summary=(
        "A workflow interpolates untrusted GitHub event data into a "
        "shell command (script-injection) and the same workflow "
        "deploys without an environment-gated approval. An attacker "
        "with PR/issue access can hijack the deploy."
    ),
    mitre_attack=(
        "T1059.004",  # Command and Scripting Interpreter: Unix Shell
        "T1190",      # Exploit Public-Facing Application
        "T1648",      # Serverless Execution
    ),
    kill_chain_phase="initial-access -> execution -> impact",
    references=(
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution-PPE",
        "https://github.blog/security/application-security/four-tips-to-keep-your-github-actions-workflows-secure/",
    ),
    recommendation=(
        "Pipe untrusted input through an env-var (one-shot quoting) and "
        "add `environment: production` with required reviewers to the "
        "deploy job. Either fix alone narrows the chain."
    ),
    providers=("github",),
    triggering_check_ids=("GHA-003", "GHA-014"),
)


def match(findings: list[Finding]) -> list[Chain]:
    # Reachability (phase 2): walk the taint graph between the injection
    # leg and the deploy leg. ``assess_reachability`` first looks for a
    # real source-to-sink taint path (TAINT-001 / TAINT-002 expose the
    # ``source_job -> sink_job`` edges) connecting the injection job(s)
    # to the deploy job(s), multi-hop included; only if none exists does
    # it fall back to the phase-1 shared-job signal. The chain still
    # fires without any confirmation (co-occurrence in one workflow is
    # the legacy signal), but the report distinguishes a proven dataflow
    # path from mere co-location.
    grouped = group_by_resource(findings, ["GHA-003", "GHA-014"])
    # Map resource -> { check_id -> Finding } for the injection-side
    # corroborators, picked up if present on the same workflow file.
    taint_by_resource: dict[str, dict[str, Finding]] = {}
    for f in findings:
        if f.passed or f.check_id not in {"TAINT-001", "TAINT-002"}:
            continue
        taint_by_resource.setdefault(f.resource, {})[f.check_id] = f

    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        gha003 = ck_map["GHA-003"]
        gha014 = ck_map["GHA-014"]
        triggers: list[Finding] = [gha003, gha014]

        deploy_jobs = set(gha014.job_anchors)
        # The injection source is the job GHA-003 fired in; the taint
        # findings supply the source->sink edges between there and the
        # deploy job.
        injection_jobs = set(gha003.job_anchors)
        taint_findings: list[Finding] = []
        for check_id in ("TAINT-001", "TAINT-002"):
            tf = taint_by_resource.get(resource, {}).get(check_id)
            if tf is None:
                continue
            triggers.append(tf)
            taint_findings.append(tf)
            # A taint flow's source is also an injection entry point, so
            # widen the source set with the taint sources' jobs.
            injection_jobs |= {fl.source_job for fl in tf.taint_flows}

        reach = assess_reachability(taint_findings, injection_jobs, deploy_jobs)
        confirmed = reach.confirmed
        reach_note = reach.note
        if reach.via_dataflow:
            reach_narrative = (
                f"  4. Reachability confirmed by dataflow: {reach.note}. "
                f"The untrusted value is carried to the ungated deploy "
                f"by a real source-to-sink taint path, not just "
                f"co-location in `{resource}`."
            )
        elif confirmed:
            reach_narrative = (
                f"  4. Reachability confirmed: {reach.note}. The "
                f"injection and the ungated deploy execute in the same "
                f"job, so untrusted input reaches the deploy context."
            )
        else:
            reach_narrative = (
                "  4. Reachability unconfirmed: the injection sink "
                "and the ungated deploy fire on the same workflow "
                "but on different jobs, with no `needs:` or step-"
                "output dataflow link detected between them. Treat "
                "as a co-occurrence signal rather than a proven path."
            )

        narrative = (
            f"In `{resource}`:\n"
            "  1. A shell `run:` step interpolates "
            "`${{ github.event.* }}` directly (GHA-003), an attacker "
            "controls the value via PR title/body/branch name.\n"
            "  2. A deploy step in the same workflow has no `environment:` "
            "binding (GHA-014), so no required-reviewer gate fires.\n"
            "  3. Attacker submits a PR whose title contains a shell "
            "payload; the runner executes it and the deploy step pushes "
            "attacker artifacts to production.\n"
            f"{reach_narrative}"
        )
        if reach.path:
            narrative += f"\n  Dataflow evidence: {reach.path}"

        # Confirmed reachability promotes the composite to HIGH
        # confidence even if a single leg is heuristic; the cross-
        # finding evidence is what we're trusting, not any one rule.
        # Unconfirmed chains stay at the weakest-leg confidence so
        # they don't outrank a single HIGH-confidence finding.
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

    # ── Cross-document tier (reusable-workflow boundary). ─────────────
    # The same injection-to-deploy shape, but split across two
    # documents: a caller passes untrusted input into a reusable
    # workflow (TAINT-003), the callee consumes it in an unquoted
    # ``${{ inputs.<name> }}`` sink (TAINT-003 confirmed the forward, so
    # its flow's ``sink_job`` is the resolved callee path), and that same
    # callee deploys without an ``environment:`` gate (GHA-014 on the
    # callee path). The untrusted input reaches the ungated deploy across
    # the reusable-workflow boundary, a path the per-document grouping
    # above can't see. Only a confirmed forward into a loaded callee keys
    # its ``sink_job`` on a real path, so this never fires without the
    # callee body in scope (``--resolve-remote`` or an on-disk callee).
    gha014_by_resource: dict[str, Finding] = {}
    for f in findings:
        if not f.passed and f.check_id == "GHA-014":
            gha014_by_resource.setdefault(f.resource, f)
    seen_cross: set[tuple[str, str]] = set()
    for f in findings:
        if f.passed or f.check_id != "TAINT-003":
            continue
        for fl in f.taint_flows:
            if not fl.cross_document or fl.sink_job == f.resource:
                continue
            callee_deploy = gha014_by_resource.get(fl.sink_job)
            if callee_deploy is None:
                continue
            key = (f.resource, fl.sink_job)
            if key in seen_cross:
                continue
            seen_cross.add(key)

            triggers = [f, callee_deploy]
            reach_note = (
                f"untrusted input forwarded from `{f.resource}` reaches "
                f"the ungated deploy in reusable workflow `{fl.sink_job}` "
                f"via a confirmed cross-document taint path"
            )
            narrative = (
                f"Across the reusable-workflow boundary "
                f"(`{f.resource}` -> `{fl.sink_job}`):\n"
                "  1. The caller passes an attacker-controlled value "
                "into a reusable workflow's ``with:`` inputs, and the "
                "callee consumes it unquoted in a "
                "``${{ inputs.<name> }}`` sink (TAINT-003, confirmed "
                "end-to-end), so a PR/issue author controls a command "
                "in the callee's runtime.\n"
                "  2. That same reusable workflow deploys without an "
                "``environment:`` gate (GHA-014), so no required-"
                "reviewer approval fires.\n"
                "  3. The attacker's injected command runs in the "
                "callee and rides its ungated deploy to production. "
                "Sanitize the value at the caller before forwarding it, "
                "and add ``environment:`` with required reviewers to the "
                "callee's deploy job. Either fix alone narrows the "
                "chain.\n"
                f"  4. Reachability confirmed by dataflow: {reach_note}.\n"
                f"  Dataflow evidence: {fl.rendered}"
            )
            out.append(Chain(
                chain_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                confidence=Confidence.HIGH,
                summary=RULE.summary,
                narrative=narrative,
                mitre_attack=list(RULE.mitre_attack),
                kill_chain_phase=RULE.kill_chain_phase,
                triggering_check_ids=sorted({t.check_id for t in triggers}),
                triggering_findings=triggers,
                resources=[f.resource, fl.sink_job],
                references=list(RULE.references),
                recommendation=RULE.recommendation,
                confirmed_reachable=True,
                reachability_note=reach_note,
                via_dataflow=True,
            ))
    return out
