"""AC-002. Script Injection to Unprotected Production Deploy.

A workflow that interpolates untrusted PR/issue input into a shell
step (script-injection) and deploys without a gated environment
gives a PR opener a path straight to production.
"""
from __future__ import annotations

from ...checks.base import Confidence, Finding, Severity
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
    # Reachability is computed by intersecting the injection-side
    # ``job_anchors`` (from GHA-003 / TAINT-001 / TAINT-002) with the
    # deploy-side ``job_anchors`` (from GHA-014). When the same job
    # both interpolates untrusted input AND performs an ungated deploy,
    # we have a confirmed executable path; the chain still fires
    # without that intersection (co-occurrence in the same workflow
    # is the legacy signal), but the report flags it as unconfirmed.
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
        injection_jobs = set(gha003.job_anchors)
        # TAINT-001 / TAINT-002 widen the injection-side set with
        # sink jobs reachable via step / job-output propagation.
        taint_paths: list[str] = []
        for check_id in ("TAINT-001", "TAINT-002"):
            tf = taint_by_resource.get(resource, {}).get(check_id)
            if tf is None:
                continue
            triggers.append(tf)
            injection_jobs |= set(tf.job_anchors)
            taint_paths.extend(tf.path_evidence)

        shared = sorted(deploy_jobs & injection_jobs)
        confirmed = bool(shared)
        if confirmed:
            shared_repr = ", ".join(f"`{j}`" for j in shared)
            reach_note = (
                f"injection and ungated deploy share job {shared_repr}"
            )
            reach_narrative = (
                f"  4. Reachability confirmed: untrusted input "
                f"reaches the same job(s) that perform the ungated "
                f"deploy ({shared_repr}). The two legs are not just "
                f"co-located in `{resource}`, they execute together."
            )
        else:
            reach_note = ""
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
        if taint_paths:
            narrative += "\n  Dataflow evidence: " + "; ".join(taint_paths[:3])
            if len(taint_paths) > 3:
                narrative += "..."

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
        ))
    return out
