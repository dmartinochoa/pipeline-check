"""CXPC-001. npm publish-side + floating consume-side on the same package name.

Fires when one repo in the fleet has NPM-008 (version published inside
the cooldown window, meaning the repo recently published a package)
and a different repo has NPM-001 (floating version range) or NPM-002
(missing integrity hash).

The publish-side repo pushed a new version; the consume-side repo
pulls npm packages with loose constraints. If the publish-side repo
is compromised, the floating consumer in the other repo pulls the
poisoned version on the next ``npm ci``.

v1 reachability: co-occurrence across the corpus. Both legs fire in
different repos within the same fleet scan. We flag the pair but
cannot confirm the consumer actually depends on the producer's
package name without manifest correlation.
"""
from __future__ import annotations

from ...checks.base import Confidence, Finding, Severity
from ..base import Chain, ChainRule, group_cross_repo

RULE = ChainRule(
    id="CXPC-001",
    title="npm publish-side cooldown + floating consumer in partner repo",
    severity=Severity.HIGH,
    summary=(
        "One repo recently published an npm package (NPM-008) and "
        "another repo in the fleet consumes npm packages with a "
        "floating version range (NPM-001) or without integrity "
        "hashes (NPM-002). If the publish-side repo is compromised, "
        "the floating consumer pulls the poisoned version on the "
        "next install."
    ),
    mitre_attack=("T1195.002", "T1078.004"),
    kill_chain_phase="initial-access -> lateral-movement",
    references=(
        "https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json",
    ),
    recommendation=(
        "Pin exact versions in the consumer repo's package.json "
        "and commit a lock file with integrity hashes (NPM-002). "
        "On the publish side, enforce 2FA-on-publish and review "
        "the cooldown window flagged by NPM-008."
    ),
    providers=("npm",),
    triggering_check_ids=("NPM-008", "NPM-001", "NPM-002"),
)

_LEG_A_IDS = ["NPM-008"]
_LEG_B_IDS = ["NPM-001", "NPM-002"]


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
                    f"Cross-repo supply-chain chain:\n"
                    f"  1. Repo `{repo_a}` recently published an npm "
                    f"package (NPM-008 on `{fa.resource}`). The "
                    f"cooldown window indicates a live publish "
                    f"pipeline.\n"
                    f"  2. Repo `{repo_b}` consumes npm packages with "
                    f"a floating version or missing integrity hash "
                    f"({fb.check_id} on `{fb.resource}`).\n"
                    f"  3. If `{repo_a}` is compromised, a poisoned "
                    f"version propagates to `{repo_b}` on the next "
                    f"`npm ci` because the consumer's constraints "
                    f"accept any compatible release."
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
