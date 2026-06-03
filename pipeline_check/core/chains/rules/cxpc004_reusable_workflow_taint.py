"""CXPC-004. Reusable workflow producer taint + consumer in partner repo.

Fires when one repo has a tainted workflow (TAINT-001, TAINT-002, or
TAINT-003 indicating exploitable dataflow) and a different repo in the
same fleet has any failing GitHub Actions finding (GHA-NNN prefix).

The producer repo's workflow carries a taint path that an attacker
can exploit. Other repos in the org that call the producer's reusable
workflows inherit the taint. The cross-repo split means the consumer
repo's maintainers may not see the producer's vulnerability.

v1 reachability: co-occurrence across the corpus. We confirm one repo
has a taint finding and another repo uses GitHub Actions, but we
cannot confirm the consumer actually calls the producer's reusable
workflows without workflow-call graph analysis.
"""
from __future__ import annotations

from ...checks.base import Confidence, Finding, Severity
from ..base import Chain, ChainRule, group_cross_repo

RULE = ChainRule(
    id="CXPC-004",
    title="Tainted reusable workflow producer + GitHub Actions consumer in partner repo",
    severity=Severity.HIGH,
    summary=(
        "One repo has a workflow with an exploitable taint path "
        "(TAINT-001 / TAINT-002 / TAINT-003) and another repo in "
        "the fleet uses GitHub Actions. If the consumer calls the "
        "producer's reusable workflows, it inherits the taint. "
        "The cross-repo split means the consumer's maintainers "
        "may not see the vulnerability."
    ),
    mitre_attack=("T1195.002", "T1199"),
    kill_chain_phase="initial-access -> execution",
    references=(
        "https://docs.github.com/en/actions/sharing-automations/reusing-workflows",
        "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
    ),
    recommendation=(
        "Remediate the taint path in the producer repo's workflow "
        "(TAINT-001 / TAINT-002 / TAINT-003). Consumer repos should "
        "pin reusable workflow references to a specific commit SHA "
        "and review the producer's workflow for untrusted-input "
        "interpolation before calling it."
    ),
    providers=("github",),
    triggering_check_ids=("TAINT-001", "TAINT-002", "TAINT-003"),
)

_LEG_A_IDS = ["TAINT-001", "TAINT-002", "TAINT-003"]


def _gha_findings(
    findings_by_repo: dict[str, list[Finding]],
) -> list[tuple[str, Finding]]:
    """Collect failing GHA-NNN findings across repos."""
    out: list[tuple[str, Finding]] = []
    for repo, findings in findings_by_repo.items():
        for f in findings:
            if (not f.passed) and f.check_id.startswith("GHA-"):
                out.append((repo, f))
    return out


def match_cross_repo(
    findings_by_repo: dict[str, list[Finding]],
) -> list[Chain]:
    leg_a = group_cross_repo(findings_by_repo, _LEG_A_IDS)
    leg_b = _gha_findings(findings_by_repo)

    if not leg_a or not leg_b:
        return []

    out: list[Chain] = []
    seen: set[tuple[str, str]] = set()
    for repo_a, fa in leg_a:
        for repo_b, fb in leg_b:
            if repo_a == repo_b:
                continue
            # Directional key: the chain runs producer -> consumer, so
            # X->Y and Y->X are distinct attack paths and must not
            # collapse into one (an unordered min/max key drops the
            # reverse direction when both repos satisfy both legs).
            pair_key = (repo_a, repo_b)
            if pair_key in seen:
                continue
            seen.add(pair_key)
            triggers = [fa, fb]
            out.append(Chain(
                chain_id=RULE.id,
                title=RULE.title,
                severity=RULE.severity,
                confidence=Confidence.MEDIUM,
                summary=RULE.summary,
                narrative=(
                    f"Cross-repo chain:\n"
                    f"  1. Repo `{repo_a}` has a workflow with an "
                    f"exploitable taint path ({fa.check_id} on "
                    f"`{fa.resource}`). An attacker can inject "
                    f"untrusted input through this dataflow.\n"
                    f"  2. Repo `{repo_b}` uses GitHub Actions "
                    f"({fb.check_id} on `{fb.resource}`). If it "
                    f"calls reusable workflows from `{repo_a}`, it "
                    f"inherits the taint.\n"
                    f"  3. The cross-repo split means `{repo_b}`'s "
                    f"maintainers may not audit `{repo_a}`'s "
                    f"workflows for injection paths, leaving the "
                    f"consumer silently exposed."
                ),
                mitre_attack=list(RULE.mitre_attack),
                kill_chain_phase=RULE.kill_chain_phase,
                triggering_check_ids=list(RULE.triggering_check_ids),
                triggering_findings=triggers,
                resources=[fa.resource, fb.resource],
                repos=[repo_a, repo_b],
                references=list(RULE.references),
                recommendation=RULE.recommendation,
                confirmed_reachable=False,
                reachability_note=(
                    f"Cross-repo co-occurrence: {repo_a} x {repo_b}. "
                    "Reachability unconfirmed."
                ),
            ))
    return out
