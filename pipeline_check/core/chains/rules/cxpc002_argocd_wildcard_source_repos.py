"""CXPC-002. Argo CD wildcard sourceRepos + weakened app-repo CI gates.

Fires when one repo defines an Argo CD AppProject with ``sourceRepos:
'*'`` (ARGOCD-001) and a different repo has a weakened CI gate that
allows PR-level code injection: GHA-002 (PR-head checkout on
``pull_request_target``), TAINT-001, or TAINT-002 (tainted workflow
dataflow).

The wildcard trust in the Argo CD project means any source repo the
cluster can reach is accepted for deployment. A weakened CI gate in
a partner repo lets an attacker inject code through a pull request.
Combined: the attacker's PR lands code that Argo CD's wildcard trust
deploys into the cluster without additional review.

v1 reachability: co-occurrence across the corpus. Both legs fire in
different repos within the same fleet scan.
"""
from __future__ import annotations

from ...checks.base import Confidence, Finding, Severity
from ..base import Chain, ChainRule, group_cross_repo

RULE = ChainRule(
    id="CXPC-002",
    title="Argo CD wildcard sourceRepos + weakened CI gate in partner repo",
    severity=Severity.CRITICAL,
    summary=(
        "An Argo CD AppProject accepts any source repo (ARGOCD-001) "
        "and a partner repo has a weakened CI gate (GHA-002 / "
        "TAINT-001 / TAINT-002) that allows PR-level code injection. "
        "An attacker's PR in the weakened repo lands code that Argo "
        "CD's wildcard trust deploys into the cluster."
    ),
    mitre_attack=("T1195.002", "T1199", "T1078.004"),
    kill_chain_phase="initial-access -> execution -> persistence",
    references=(
        "https://argo-cd.readthedocs.io/en/stable/user-guide/projects/",
        "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/",
    ),
    recommendation=(
        "Restrict the AppProject's ``sourceRepos`` to an explicit "
        "allowlist of trusted repositories. In the partner repo, "
        "fix the CI gate: avoid checking out PR-head code in "
        "``pull_request_target`` workflows (GHA-002) and remediate "
        "tainted dataflows (TAINT-001 / TAINT-002)."
    ),
    providers=("argocd", "github"),
    triggering_check_ids=("ARGOCD-001", "GHA-002", "TAINT-001", "TAINT-002"),
)

_LEG_A_IDS = ["ARGOCD-001"]
_LEG_B_IDS = ["GHA-002", "TAINT-001", "TAINT-002"]


def match_cross_repo(
    findings_by_repo: dict[str, list[Finding]],
) -> list[Chain]:
    leg_a = group_cross_repo(findings_by_repo, _LEG_A_IDS)
    leg_b = group_cross_repo(findings_by_repo, _LEG_B_IDS)

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
                    f"  1. Repo `{repo_a}` defines an Argo CD "
                    f"AppProject with wildcard sourceRepos "
                    f"(ARGOCD-001 on `{fa.resource}`). Any source "
                    f"repo the cluster can reach is accepted.\n"
                    f"  2. Repo `{repo_b}` has a weakened CI gate "
                    f"({fb.check_id} on `{fb.resource}`) that allows "
                    f"PR-level code injection.\n"
                    f"  3. An attacker opens a PR in `{repo_b}`, "
                    f"injects code through the weakened gate, and "
                    f"Argo CD's wildcard trust in `{repo_a}` deploys "
                    f"the poisoned commit into the cluster."
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
