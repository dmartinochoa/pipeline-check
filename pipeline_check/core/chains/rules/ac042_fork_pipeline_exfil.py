"""AC-042. Fork pipeline executed and exfiltrated credentials, same pipeline.

The GitLab analog of AC-041, built from the ``gitlab_runs`` run-forensics
legs. Two findings on the *same* fork merge-request pipeline:

  * ``GLRUN-002`` — a fork merge request's pipeline actually executed in
    this project's CI, so untrusted contributor code ran.
  * ``GLRUN-003`` (a secret-shaped string leaked in that pipeline's job
    trace, past GitLab's variable masking) OR ``GLRUN-004`` (that pipeline
    minted a cloud OIDC token).

GitLab has no "compromised action" IOC analog (so no RUN-006 leg); the
untrusted-code leg here is the fork pipeline itself. GLRUN-003 / GLRUN-004
already only scan fork pipelines, but pairing them with GLRUN-002 on one
pipeline resource turns two HIGH signals into the run-history confirmation
that untrusted fork code reached a credential in a single execution: the
fork pipeline ran and a secret left it (or it minted a cloud token) in the
same pipeline. This is poisoned-pipeline-execution confirmed to have
*succeeded*, not merely been possible, so it warrants incident response,
not triage.

Reachability is structural, not co-occurrence: both legs carry the same
``gitlab:group/project#pipeline/<id>`` resource, so they provably happened
in one pipeline (the same execution, the same downloaded trace). The chain
is emitted ``confirmed_reachable`` at HIGH confidence, the GitLab twin of
AC-041's same-run pairing.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-042",
    title="Fork pipeline executed and exfiltrated credentials in the same pipeline",
    severity=Severity.CRITICAL,
    summary=(
        "A fork merge-request pipeline actually executed in the project's "
        "CI (GLRUN-002) AND the same pipeline exposed a credential: a "
        "secret-shaped string leaked in its job trace past GitLab's masking "
        "(GLRUN-003) or it minted a cloud OIDC token (GLRUN-004). Both legs "
        "on one pipeline is the run-history confirmation that untrusted fork "
        "code reached a credential in a single execution, the GitLab face of "
        "the poisoned-pipeline-execution class confirmed to have succeeded."
    ),
    mitre_attack=(
        "T1199",      # Trusted Relationship
        "T1552",      # Unsecured Credentials
        "T1078.004",  # Valid Accounts: Cloud Accounts
        "T1567",      # Exfiltration Over Web Service
    ),
    kill_chain_phase=(
        "initial-access (a fork merge request opens, untrusted contributor "
        "code) -> execution (its pipeline runs in the project's CI) -> "
        "credential-access (a secret leaks in the job trace, or the pipeline "
        "mints a cloud OIDC token) -> exfiltration (the untrusted code ships "
        "the credential out, the leak / mint is the evidence)"
    ),
    references=(
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/"
        "CICD-SEC-04-Poisoned-Pipeline-Execution-PPE",
        "https://docs.gitlab.com/ee/ci/pipelines/merge_request_pipelines.html"
        "#run-pipelines-in-the-parent-project-for-merge-requests-from-a-forked-project",
    ),
    recommendation=(
        "Respond as to a confirmed breach: rotate every credential and token "
        "the affected pipeline could reach (the leaked secret, the federated "
        "cloud role for an OIDC mint, the CI job token), review the "
        "pipeline's outbound network and any pushes / deployments it made, "
        "and audit downstream systems the credential can reach. Then close "
        "the entry point: keep protected CI/CD variables and runners away "
        "from fork merge-request pipelines and require approval before they "
        "run (GLRUN-002), stop the credential reaching the trace (GLRUN-003) "
        "or scope the cloud trust policy so a fork ref cannot assume the role "
        "(GLRUN-004)."
    ),
    providers=("gitlab_runs",),
    triggering_check_ids=("GLRUN-002", "GLRUN-003", "GLRUN-004"),
)

#: Credential-exposure legs, either confirms a credential left the pipeline.
_EXFIL_LEGS = ("GLRUN-003", "GLRUN-004")


def match(findings: list[Finding]) -> list[Chain]:
    out: list[Chain] = []
    for exfil_id in _EXFIL_LEGS:
        grouped = group_by_resource(findings, ["GLRUN-002", exfil_id])
        for resource, ck_map in grouped.items():
            fork = ck_map["GLRUN-002"]
            exfil = ck_map[exfil_id]
            triggers = [fork, exfil]
            exfil_leg = (
                "a secret-shaped string leaked in that same pipeline's job "
                "trace past GitLab's masking (GLRUN-003), so the untrusted "
                "code's credential access is visible in the trace"
                if exfil_id == "GLRUN-003"
                else "that same pipeline minted a cloud OIDC token "
                "(GLRUN-004), so the untrusted code reached cloud federation "
                "and could assume the federated role"
            )
            narrative = (
                f"On pipeline `{resource}`:\n"
                f"  1. A fork merge request's pipeline actually executed in "
                f"this project's CI (GLRUN-002), so untrusted contributor "
                f"code ran here.\n"
                f"  2. In the same pipeline, {exfil_leg}.\n"
                f"  3. Composite: this is poisoned pipeline execution "
                f"confirmed to have succeeded. Untrusted fork code ran and a "
                f"credential left the pipeline in one execution. Treat it as "
                f"an active breach."
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
                triggering_check_ids=["GLRUN-002", exfil_id],
                triggering_findings=triggers,
                resources=[resource],
                references=list(RULE.references),
                recommendation=RULE.recommendation,
                confirmed_reachable=True,
                via_structural=True,
                reachability_note=(
                    f"GLRUN-002 and {exfil_id} both fired on the same "
                    f"pipeline `{resource}`"
                ),
            ))
    # A pipeline that trips both GLRUN-003 and GLRUN-004 alongside GLRUN-002
    # should surface a single AC-042, not two. Keep the first (GLRUN-003).
    seen: set[str] = set()
    deduped: list[Chain] = []
    for c in out:
        if c.resources[0] not in seen:
            seen.add(c.resources[0])
            deduped.append(c)
    return deduped
