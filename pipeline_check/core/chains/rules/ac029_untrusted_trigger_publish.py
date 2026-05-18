"""AC-029. Untrusted-trigger publish path (s1ngularity / Ultralytics class).

A workflow exposes three legs on the same file:

  1. **Untrusted trigger reaches code** — ``pull_request_target``
     checking out PR head (GHA-002), ``workflow_run`` consuming an
     unverified upstream artifact (GHA-009), or an unguarded
     ``issue_comment`` trigger (GHA-013). An attacker can land code
     execution under the workflow's privileges by opening a PR or
     posting a comment.

  2. **Long-lived publish credential present** — the workflow runs
     ``npm publish`` / ``twine upload`` / ``pypa/gh-action-pypi-
     publish`` against a static registry token (GHA-050), OR the AWS
     auth path uses long-lived access keys instead of OIDC (GHA-005).

  3. **No integrity guard between the two** — the install step that
     feeds the publish picks dependencies from a floating registry
     range (GHA-021 no lockfile) or pulls from a non-registry source
     (GHA-029 source-integrity bypass).

Each leg is independently bad; the combination is the exact lane
the Ultralytics PyPI compromise (cache-poison via branch-name
script-injection + Trusted Publishing OIDC issued from the same
poisoned job) and the Nx s1ngularity compromise (PR-title injection
on a stale branch + ``npm publish`` with a long-lived token) ran
through.
"""
from __future__ import annotations

from collections import defaultdict

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, min_confidence

RULE = ChainRule(
    id="AC-029",
    title="Untrusted trigger reaches a long-lived publish credential",
    severity=Severity.CRITICAL,
    summary=(
        "A single workflow file combines an attacker-influenced "
        "trigger (GHA-002 / GHA-009 / GHA-013), a long-lived publish "
        "or cloud credential (GHA-050 / GHA-005), and an unguarded "
        "dependency-install path (GHA-021 / GHA-029). The "
        "combination is the Ultralytics / s1ngularity attack lane: "
        "an attacker lands code via PR or comment, the same workflow "
        "publishes their payload to a public registry under the "
        "victim's identity."
    ),
    mitre_attack=(
        "T1195.002",  # Supply Chain Compromise: Compromise Software Supply Chain
        "T1078.004",  # Valid Accounts: Cloud Accounts
        "T1606",      # Forge Web Credentials
    ),
    kill_chain_phase="initial-access -> credential-access -> impact",
    references=(
        "https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/",
        "https://nx.dev/blog/s1ngularity-postmortem",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/"
        "CICD-SEC-04-Poisoned-Pipeline-Execution-PPE",
    ),
    recommendation=(
        "Break the lane at any one leg. Either: (a) re-trigger publish "
        "on tag-only / push-to-default-branch (drop "
        "``pull_request_target`` / ``issue_comment`` / ``workflow_run`` "
        "from the publish workflow), (b) swap the long-lived token for "
        "OIDC Trusted Publishing (PyPI) / a federated identity (AWS) "
        "/ GitHub's ``id-token: write`` flow, (c) enforce a committed "
        "lockfile and registry-integrity verification on the dep "
        "install. Doing all three is the long-term posture; doing any "
        "one breaks the chain."
    ),
    providers=("github",),
    triggering_check_ids=(
        "GHA-002", "GHA-009", "GHA-013",  # trigger leg (any-of)
        "GHA-050", "GHA-005",             # credential leg (any-of)
        "GHA-021", "GHA-029",             # integrity leg (any-of)
    ),
)


_TRIGGER_LEG = ("GHA-002", "GHA-009", "GHA-013")
_CREDENTIAL_LEG = ("GHA-050", "GHA-005")
_INTEGRITY_LEG = ("GHA-021", "GHA-029")


def match(findings: list[Finding]) -> list[Chain]:
    by_resource: dict[str, dict[str, Finding]] = defaultdict(dict)
    interesting = set(_TRIGGER_LEG) | set(_CREDENTIAL_LEG) | set(_INTEGRITY_LEG)
    for f in findings:
        if f.passed or f.check_id not in interesting:
            continue
        if f.check_id not in by_resource[f.resource]:
            by_resource[f.resource][f.check_id] = f
    out: list[Chain] = []
    for resource, ck_map in by_resource.items():
        trig_hits = [c for c in _TRIGGER_LEG if c in ck_map]
        cred_hits = [c for c in _CREDENTIAL_LEG if c in ck_map]
        intg_hits = [c for c in _INTEGRITY_LEG if c in ck_map]
        if not (trig_hits and cred_hits and intg_hits):
            continue
        triggers = [
            ck_map[c] for c in trig_hits + cred_hits + intg_hits
        ]
        narrative = (
            f"In `{resource}`:\n"
            f"  1. Untrusted-trigger leg ({', '.join(trig_hits)}): an "
            "attacker who can open a PR, comment on an issue, or "
            "trigger a follow-on ``workflow_run`` gets code execution "
            "in this workflow.\n"
            f"  2. Long-lived credential leg ({', '.join(cred_hits)}): "
            "the workflow holds a static publish or cloud token that "
            "the attacker-controlled code can read.\n"
            f"  3. Integrity-bypass leg ({', '.join(intg_hits)}): the "
            "install step that feeds the publish has no lockfile / "
            "registry-integrity guard, so an attacker who can swap a "
            "dependency or poison the cache lands their payload in "
            "the published artifact.\n"
            "  4. Together: the Ultralytics PyPI compromise (cache-"
            "poison via branch-name injection + Trusted Publishing "
            "from the same poisoned job) and the Nx s1ngularity "
            "compromise (PR-title injection on a stale branch + npm "
            "publish with a long-lived token) both used this exact "
            "three-leg shape."
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
            triggering_check_ids=trig_hits + cred_hits + intg_hits,
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
        ))
    return out
