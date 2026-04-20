"""AC-008 — Dependency Confusion Window.

A workflow installs packages without a lockfile AND skips integrity
verification, leaving a window for dependency-confusion / typosquatting
attacks on every run.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-008",
    title="Dependency Confusion Window",
    severity=Severity.HIGH,
    summary=(
        "A workflow installs packages without a lockfile AND without "
        "integrity verification. On every run the dependency resolver "
        "picks the highest-version match across configured registries "
        "— ideal conditions for a dependency-confusion / typosquatting "
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
)


def match(findings: list[Finding]) -> list[Chain]:
    grouped = group_by_resource(findings, ["GHA-021", "GHA-029"])
    out: list[Chain] = []
    for resource, ck_map in grouped.items():
        triggers = [ck_map["GHA-021"], ck_map["GHA-029"]]
        narrative = (
            f"In `{resource}`:\n"
            "  1. Package install runs without lockfile enforcement "
            "(GHA-021) — `npm install`, `pip install <pkg>` (no -r), "
            "`yarn install` (no `--frozen-lockfile`).\n"
            "  2. Install commands also bypass source-integrity "
            "verification (GHA-029) — git URL installs, local-path "
            "installs, or tarball-URL installs.\n"
            "  3. Each run resolves to whatever the registry currently "
            "serves. An attacker publishing a higher-version package "
            "with the right name (dep-confusion) or a typo "
            "(typosquatting) lands code in the build."
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
            triggering_check_ids=["GHA-021", "GHA-029"],
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
        ))
    return out
