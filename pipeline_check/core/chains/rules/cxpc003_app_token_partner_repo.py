"""CXPC-003. Over-broad App-token scope + credential exposure in partner repo.

Fires when one repo mints an unscoped GitHub App token (GHA-061,
no permissions filter) and a different repo in the same fleet exposes
credentials (GHA-005, plaintext credentials in workflow) or hardcoded
secrets (GHA-008).

The unscoped App token's installation likely covers other repos in the
same org. Credential exposure in the partner repo gives the attacker a
second vector into the same org. Combined: the App token from repo A
can reach repo B, and the exposed credentials in repo B provide
lateral-movement footholds.

v1 reachability: co-occurrence across the corpus. Both repos are in
the same org fleet scan.
"""
from __future__ import annotations

from ...checks.base import Confidence, Finding, Severity
from ..base import Chain, ChainRule, group_cross_repo

RULE = ChainRule(
    id="CXPC-003",
    title="Unscoped App token + credential exposure in partner repo",
    severity=Severity.HIGH,
    summary=(
        "One repo mints an unscoped GitHub App token (GHA-061) "
        "whose installation likely covers other repos in the same "
        "org. A partner repo exposes credentials (GHA-005 / GHA-008). "
        "The App token from the first repo can reach the second; "
        "credential exposure in the second gives the attacker a "
        "lateral-movement foothold."
    ),
    mitre_attack=("T1078.004", "T1098.001"),
    kill_chain_phase="credential-access -> lateral-movement",
    references=(
        "https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app",
    ),
    recommendation=(
        "Scope the App token in repo A by passing an explicit "
        "``permissions`` map to the token-mint action (GHA-061). "
        "In repo B, rotate and remove plaintext credentials "
        "(GHA-005) and hardcoded secrets (GHA-008), replacing them "
        "with GitHub Actions secrets or OIDC federation."
    ),
    providers=("github",),
    triggering_check_ids=("GHA-061", "GHA-005", "GHA-008"),
)

_LEG_A_IDS = ["GHA-061"]
_LEG_B_IDS = ["GHA-005", "GHA-008"]


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
                    f"  1. Repo `{repo_a}` mints an unscoped GitHub "
                    f"App token (GHA-061 on `{fa.resource}`). The "
                    f"installation's default scope covers all repos "
                    f"the App is installed on.\n"
                    f"  2. Repo `{repo_b}` exposes credentials "
                    f"({fb.check_id} on `{fb.resource}`). An "
                    f"attacker who obtains the App token from "
                    f"`{repo_a}` can read or write `{repo_b}`.\n"
                    f"  3. Credential exposure in `{repo_b}` provides "
                    f"a second pivot point. The attacker chains the "
                    f"broad token with the leaked credential for "
                    f"lateral movement across the org."
                ),
                mitre_attack=list(RULE.mitre_attack),
                kill_chain_phase=RULE.kill_chain_phase,
                triggering_check_ids=list(RULE.triggering_check_ids),
                triggering_findings=triggers,
                resources=[fa.resource, fb.resource],
                references=list(RULE.references),
                recommendation=RULE.recommendation,
                confirmed_reachable=False,
                reachability_note=(
                    f"Cross-repo co-occurrence: {repo_a} x {repo_b}. "
                    "Reachability unconfirmed."
                ),
            ))
    return out
