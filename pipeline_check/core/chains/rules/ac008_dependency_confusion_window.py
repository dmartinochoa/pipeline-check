"""AC-008. Dependency Confusion Window.

A workflow installs packages without a lockfile AND skips integrity
verification, leaving a window for dependency-confusion / typosquatting
attacks on every run.
"""
from __future__ import annotations

from ...checks.base import Confidence, Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-008",
    title="Dependency Confusion Window",
    severity=Severity.HIGH,
    summary=(
        "A workflow installs packages without a lockfile AND without "
        "integrity verification. On every run the dependency resolver "
        "picks the highest-version match across configured registries, "
        "ideal conditions for a dependency-confusion / typosquatting "
        "attack to land in the build."
    ),
    mitre_attack=(
        "T1195.001",  # Supply Chain Compromise: Software Dependencies
    ),
    kill_chain_phase="supply-chain -> execution",
    references=(
        "https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-03-Dependency-Chain-Abuse",
    ),
    recommendation=(
        "Use lockfile-enforcing install commands (`npm ci`, "
        "`pip install -r requirements.txt --require-hashes`, "
        "`yarn install --frozen-lockfile`). Pin the registry to a "
        "private one and disable upstream fall-through."
    ),
    providers=("github",),
    triggering_check_ids=("GHA-021", "GHA-029"),
)


def match(findings: list[Finding]) -> list[Chain]:
    # Reachability: a shared job between GHA-021 (the install command
    # that skips lockfile enforcement) and GHA-029 (the install
    # command that aims the resolver at a source the lockfile can't
    # protect: git URL, local path, tarball URL) confirms the
    # dependency-confusion / typosquatting window opens in one
    # execution context. Disjoint jobs still co-occur on a
    # poisonable workflow file but typically reflect two separate
    # build paths (e.g. a Python deploy job + a Node test job); we
    # keep that as the unconfirmed signal rather than dropping the
    # chain, because either install path alone is still exploitable.
    grouped = group_by_resource(findings, ["GHA-021", "GHA-029"])
    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        gha021 = ck_map["GHA-021"]
        gha029 = ck_map["GHA-029"]
        triggers = [gha021, gha029]

        lockfile_jobs = set(gha021.job_anchors)
        integrity_jobs = set(gha029.job_anchors)
        shared = sorted(lockfile_jobs & integrity_jobs)
        confirmed = bool(shared)
        if confirmed:
            shared_repr = ", ".join(f"`{j}`" for j in shared)
            reach_note = (
                f"Lockfile-skipping install and integrity-bypass install "
                f"share job {shared_repr}"
            )
            reach_narrative = (
                f"  4. Reachability confirmed: the same job(s) "
                f"({shared_repr}) both install without lockfile "
                f"enforcement AND from a source the lockfile cannot "
                f"protect. A registry takeover or a poisoned tarball "
                f"URL lands code in the same build context, no extra "
                f"reachability step required."
            )
        else:
            reach_note = ""
            reach_narrative = (
                "  4. Reachability unconfirmed: the lockfile miss and "
                "the integrity-bypass install fire on the same "
                "workflow file but in different jobs. Each install "
                "path is still individually exploitable; treat as a "
                "co-occurrence signal."
            )

        narrative = (
            f"In `{resource}`:\n"
            "  1. Package install runs without lockfile enforcement "
            "(GHA-021), `npm install`, `pip install <pkg>` (no -r), "
            "`yarn install` (no `--frozen-lockfile`).\n"
            "  2. Install commands also bypass source-integrity "
            "verification (GHA-029), git URL installs, local-path "
            "installs, or tarball-URL installs.\n"
            "  3. Each run resolves to whatever the registry currently "
            "serves. An attacker publishing a higher-version package "
            "with the right name (dep-confusion) or a typo "
            "(typosquatting) lands code in the build.\n"
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
            triggering_check_ids=["GHA-021", "GHA-029"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
            confirmed_reachable=confirmed,
            reachability_note=reach_note,
        ))
    return out
