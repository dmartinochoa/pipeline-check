"""AC-039. Untrusted trigger reaches a bulk-secrets serialization.

Two legs on the same workflow file:

  1. **Untrusted trigger reaches the workflow** — ``pull_request_target``
     checking out PR head (GHA-002), a ``workflow_run`` consuming an
     unverified upstream artifact (GHA-009), or an unguarded
     ``issue_comment`` trigger (GHA-013). An attacker who opens a fork
     PR or posts a comment causes the workflow to run with the base
     repository's secrets.

  2. **The workflow serializes the entire secrets context** —
     ``${{ toJSON(secrets) }}`` materializes every credential the job
     can read into one string (GHA-116). On a public repo the workflow
     log is world-readable; a single ``echo`` or outbound request then
     hands the attacker every secret at once.

Either leg is bad on its own. Together they are the reachable form of
the 2025 secret-harvesting wave: where the tj-actions / GhostAction
payloads needed a compromised action or a pushed workflow, this lane
lets an *external* attacker trigger the full-secret dump directly, with
no write access, just by opening a pull request.
"""
from __future__ import annotations

from collections import defaultdict

from ...checks.base import Confidence, Finding, Severity
from ..base import Chain, ChainRule, min_confidence

RULE = ChainRule(
    id="AC-039",
    title="Untrusted trigger reaches a bulk-secrets serialization",
    severity=Severity.CRITICAL,
    summary=(
        "A single workflow combines an attacker-influenced trigger "
        "(GHA-002 / GHA-009 / GHA-013) with a step that serializes the "
        "whole secrets context via ``toJSON(secrets)`` (GHA-116). An "
        "external attacker who opens a fork PR or posts a comment "
        "triggers a run that dumps every secret the workflow can read "
        "into a world-readable log, the reachable form of the 2025 "
        "tj-actions / GhostAction secret-harvesting attacks."
    ),
    mitre_attack=(
        "T1195.002",  # Supply Chain Compromise: Compromise Software Supply Chain
        "T1552",      # Unsecured Credentials
        "T1567.002",  # Exfiltration Over Web Service: Exfiltration to Cloud Storage
    ),
    kill_chain_phase="initial-access -> credential-access -> exfiltration",
    references=(
        "https://blog.gitguardian.com/ghostaction-campaign-3-325-secrets-stolen/",
        "https://github.com/advisories/ghsa-mrrh-fwg8-r2c3",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/"
        "CICD-SEC-06-Insufficient-Credential-Hygiene",
    ),
    recommendation=(
        "Break the lane at either leg. Either: (a) drop the untrusted "
        "trigger from this workflow (re-trigger on ``push`` to the "
        "default branch / a tag, or gate ``pull_request_target`` / "
        "``issue_comment`` / ``workflow_run`` behind an environment "
        "with required reviewers), or (b) stop serializing the whole "
        "secrets context, reference only the specific secrets each step "
        "needs by name and prefer short-lived OIDC tokens. Doing (b) is "
        "the stronger fix because ``toJSON(secrets)`` is dangerous on "
        "any trigger; removing the untrusted trigger alone still leaves "
        "the full-secret dump a push away."
    ),
    providers=("github",),
    triggering_check_ids=(
        "GHA-002", "GHA-009", "GHA-013",  # untrusted-trigger leg (any-of)
        "GHA-116",                          # bulk-secrets-dump leg
    ),
)

_TRIGGER_LEG = ("GHA-002", "GHA-009", "GHA-013")
_DUMP_LEG = ("GHA-116",)


def _union_anchors(findings: list[Finding]) -> set[str]:
    out: set[str] = set()
    for f in findings:
        out.update(f.job_anchors)
    return out


def match(findings: list[Finding]) -> list[Chain]:
    by_resource: dict[str, dict[str, list[Finding]]] = defaultdict(
        lambda: defaultdict(list),
    )
    interesting = set(_TRIGGER_LEG) | set(_DUMP_LEG)
    for f in findings:
        if f.passed or f.check_id not in interesting:
            continue
        by_resource[f.resource][f.check_id].append(f)

    out: list[Chain] = []
    for resource, ck_map in by_resource.items():
        trig_hits = [c for c in _TRIGGER_LEG if c in ck_map]
        dump_hits = [c for c in _DUMP_LEG if c in ck_map]
        if not (trig_hits and dump_hits):
            continue
        trig_findings = [f for c in trig_hits for f in ck_map[c]]
        dump_findings = [f for c in dump_hits for f in ck_map[c]]
        triggers = [*trig_findings, *dump_findings]

        # Reachability: a job that is BOTH attacker-reachable (trigger
        # leg) and serializes the secrets (dump leg) is a direct exfil
        # in one execution context. Even without a shared job the dump
        # lands in the same world-readable workflow log the attacker's
        # trigger produces, so the unconfirmed case is still a real
        # exfil, just not pinned to one job.
        shared = sorted(_union_anchors(trig_findings) & _union_anchors(dump_findings))
        confirmed = bool(shared)
        if confirmed:
            shared_repr = ", ".join(f"`{j}`" for j in shared)
            reach_note = (
                f"Untrusted-trigger and secrets-dump legs share job {shared_repr}"
            )
            reach_narrative = (
                f"  3. Reachability confirmed: job {shared_repr} is both "
                f"attacker-reachable and serializes the secrets context, "
                f"so one fork PR / comment dumps every secret in a single "
                f"execution context."
            )
        else:
            reach_note = ""
            reach_narrative = (
                "  3. Reachability: the two legs fire on the same "
                "workflow but no single job carries both. The dump still "
                "lands in the same world-readable log the attacker's "
                "trigger produces, so treat it as a reachable exfil and "
                "fix either leg."
            )

        narrative = (
            f"In `{resource}`:\n"
            f"  1. Untrusted-trigger leg ({', '.join(trig_hits)}): an "
            "external attacker who opens a fork PR, comments on an "
            "issue, or triggers a follow-on ``workflow_run`` causes this "
            "workflow to run with the base repo's secrets.\n"
            f"  2. Bulk-secrets-dump leg ({', '.join(dump_hits)}): the "
            "workflow serializes the entire secrets context via "
            "``toJSON(secrets)``, so every credential it can read is "
            "exposed in one string (a log line or one outbound request).\n"
            f"{reach_narrative}"
        )

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
            triggering_check_ids=trig_hits + dump_hits,
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
            confirmed_reachable=confirmed,
            reachability_note=reach_note,
        ))
    return out
