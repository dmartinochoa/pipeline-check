"""AC-014. Caller-Controlled Runner with Token Persistence (GitLab CI).

GitLab parity for AC-013. A pipeline whose ``tags:`` is computed
from an attacker-controllable CI variable (GL-032) AND that
writes ``CI_JOB_TOKEN`` (or another CI-managed credential) to
persistent storage (GL-020) is a one-step credential delivery to
an attacker-chosen runner. The pipeline trigger picks which
tagged runner the job lands on; the job then drops its
short-lived token onto that runner's filesystem; whoever owns the
picked runner harvests the token and acts as the workflow.

Distinct from:

  * GL-032 alone, runner targeting risk without a token-on-disk
    leg is a routing concern but not a credential exfiltration.
  * GL-020 alone, token persistence on a known, hard-coded
    runner is its own incident model (hostile co-tenant, ex-
    employee with runner access) but doesn't grant the attacker
    runner choice.

The chain fires when both GL-032 and GL-020 fire on the *same*
pipeline file. A different-file combo is not the same threat,
the runner-targeting decision and the token-persistence step
have to be in the same execution.
"""
from __future__ import annotations

from ...checks.base import Confidence, Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-014",
    title="Caller-Controlled Runner with Token Persistence (GitLab)",
    severity=Severity.CRITICAL,
    summary=(
        "A pipeline's ``tags:`` is computed from an attacker-"
        "controllable CI variable (GL-032) AND a script line in "
        "the same job writes ``CI_JOB_TOKEN`` (or another CI-"
        "managed credential) to persistent storage (GL-020). The "
        "pipeline trigger picks which tagged runner the job lands "
        "on; the job then drops its short-lived token onto that "
        "runner's filesystem; whoever owns the picked runner "
        "harvests the token and acts as the pipeline against the "
        "GitLab API."
    ),
    mitre_attack=(
        "T1078",      # Valid Accounts
        "T1552.001",  # Unsecured Credentials: in Files
        "T1133",      # External Remote Services
    ),
    kill_chain_phase="initial-access -> credential-access -> exfiltration",
    references=(
        "https://docs.gitlab.com/ee/ci/runners/configure_runners.html#runner-security",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-7-Insecure-System-Configuration",
    ),
    recommendation=(
        "Break either leg of the chain. (a) Hard-code ``tags:`` "
        "to a specific runner-tag list, or validate the value "
        "against an allowlist in a ``rules:`` guard before the "
        "job runs, so the trigger can't pick an attacker-"
        "controlled runner. (b) Stop writing ``CI_JOB_TOKEN`` "
        "(or other CI-managed credentials) to disk, use the "
        "token inline in the command that needs it and let "
        "GitLab revoke it automatically when the job finishes. "
        "Doing (a) closes the targeting leg; (b) limits blast "
        "radius even if (a) is somehow bypassed because the "
        "token no longer outlives the step that consumes it."
    ),
    providers=("gitlab",),
    triggering_check_ids=("GL-032", "GL-020"),
)


def match(findings: list[Finding]) -> list[Chain]:
    # Same-pipeline pairing matters: GL-032 in pipeline A and
    # GL-020 in pipeline B are independent risks, not a chain.
    # Reachability: a shared job between GL-032 (the trigger picks
    # this job's runner via a tainted ``tags:``) and GL-020 (this
    # job writes the CI token to disk) confirms the single-job
    # credential delivery path.
    grouped = group_by_resource(findings, ["GL-032", "GL-020"])
    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        gl032 = ck_map["GL-032"]
        gl020 = ck_map["GL-020"]
        triggers = [gl032, gl020]

        target_jobs = set(gl032.job_anchors)
        persist_jobs = set(gl020.job_anchors)
        shared = sorted(target_jobs & persist_jobs)
        confirmed = bool(shared)
        if confirmed:
            shared_repr = ", ".join(f"`{j}`" for j in shared)
            reach_note = (
                f"caller-targeted runner and token persistence share "
                f"job {shared_repr}"
            )
            reach_narrative = (
                f"  4. Reachability confirmed: the same job(s) "
                f"({shared_repr}) both let the pipeline trigger pick "
                f"the runner via a tainted ``tags:`` AND write the "
                f"CI token to disk on whatever runner was picked."
            )
        else:
            reach_note = ""
            reach_narrative = (
                "  4. Reachability unconfirmed: caller-targeted "
                "``tags:`` and CI-token persistence land in different "
                "jobs. Treat as a co-occurrence signal."
            )

        narrative = (
            f"In `{resource}`:\n"
            "  1. A job's ``tags:`` is computed from an attacker-"
            "controllable CI variable (GL-032), "
            "``$CI_COMMIT_REF_NAME``, ``$CI_MERGE_REQUEST_TITLE``, "
            "``${CI_COMMIT_MESSAGE}``, or another caller-supplied "
            "field. Whoever triggers the pipeline picks which "
            "tagged runner it lands on, including any privileged "
            "self-managed tag the instance exposes.\n"
            "  2. The same pipeline writes ``CI_JOB_TOKEN`` (or "
            "``CI_DEPLOY_TOKEN`` / ``CI_REGISTRY_PASSWORD`` / "
            "``CI_DEPLOY_PASSWORD``) to persistent storage on the "
            "runner (GL-020), typically a redirect, a tee, or a "
            "dotenv-report append. The token lives past the script "
            "boundary on that runner's filesystem.\n"
            "  3. An attacker who controls the picked runner reads "
            "the persisted token from disk and acts as the job for "
            "the rest of the token's lifetime, pushing to "
            "branches, accessing the package registry, downloading "
            "protected artifacts, all under the job's credential "
            "scope.\n"
            f"{reach_narrative}"
        )

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
            triggering_check_ids=["GL-032", "GL-020"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
            confirmed_reachable=confirmed,
            reachability_note=reach_note,
        ))
    return out
