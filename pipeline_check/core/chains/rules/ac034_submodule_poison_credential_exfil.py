"""AC-034. Submodule-poisoned PR to credential exfiltration.

Two legs:

  * ``GHA-102`` — ``actions/checkout`` with ``submodules: recursive``
    on a PR trigger. A contributor PR can modify ``.gitmodules`` to
    point a submodule at an attacker-controlled repository; the
    checkout action clones it into the workspace.
  * ``GHA-037`` (persist-credentials not disabled) or ``GHA-004``
    (overly broad ``permissions:`` including ``contents: write``).
    The GITHUB_TOKEN persisted by the checkout step or the workflow's
    write-all token is available to every subsequent step in the job.

Independently: GHA-102 is a supply-chain risk; GHA-037/GHA-004 are
credential-hygiene issues. Together: the attacker's submodule
content (Makefile, package.json lifecycle scripts, build.rs) executes
with access to the persisted GITHUB_TOKEN with write scope. The
attacker can push to the base repo, create releases, or exfiltrate
repository secrets via the token.

Reachability model: per-workflow co-occurrence. Both legs fire on the
same workflow file. The submodule checkout and the credential persist
are in the same job by construction (``actions/checkout`` is the step
that creates the credential).
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-034",
    title="Submodule-poisoned PR to credential exfiltration",
    severity=Severity.CRITICAL,
    summary=(
        "A PR-triggered workflow clones submodules from an attacker-"
        "controllable ``.gitmodules`` (GHA-102) AND persists "
        "credentials or runs with overly broad permissions "
        "(GHA-037 / GHA-004). The attacker's submodule code "
        "executes with access to the GITHUB_TOKEN at write scope, "
        "enabling pushes to the base repo, release creation, or "
        "secret exfiltration."
    ),
    mitre_attack=(
        "T1195.002",  # Compromise Software Supply Chain
        "T1078.004",  # Valid Accounts: Cloud Accounts
        "T1059",      # Command and Scripting Interpreter
    ),
    kill_chain_phase=(
        "initial-access (PR with modified .gitmodules) -> "
        "execution (submodule lifecycle scripts) -> "
        "credential-access (persisted GITHUB_TOKEN) -> "
        "impact (repo write / secret exfiltration)"
    ),
    references=(
        "https://github.com/nicksrandall/supply-chain-attack-demo",
        "https://docs.github.com/en/actions/security-for-github-actions/"
        "security-guides/security-hardening-for-github-actions",
    ),
    recommendation=(
        "Break either leg:\n"
        "  1. Remove ``submodules: recursive`` from PR-triggered "
        "checkout steps (GHA-102). If submodules are required, "
        "validate submodule origins before the build step.\n"
        "  2. Set ``persist-credentials: false`` on the checkout "
        "step (GHA-037) AND scope ``permissions:`` to the minimum "
        "needed (GHA-004). Without a persisted token or write "
        "scope, the attacker's code can't push or exfiltrate.\n"
        "Both fixes together are best: no submodule clone means "
        "no attacker code; no credentials means no blast radius."
    ),
    providers=("github",),
    triggering_check_ids=("GHA-102", "GHA-037", "GHA-004"),
)


def match(findings: list[Finding]) -> list[Chain]:
    out: list[Chain] = []
    for cred_check in ("GHA-037", "GHA-004"):
        grouped = group_by_resource(findings, ["GHA-102", cred_check])
        for resource, ck_map in grouped.items():
            submodule = ck_map["GHA-102"]
            credential = ck_map[cred_check]
            triggers = [submodule, credential]
            narrative = (
                f"On workflow `{resource}`:\n"
                f"  1. A PR-triggered workflow checks out submodules "
                f"with ``submodules: recursive`` (GHA-102). A "
                f"contributor PR can modify ``.gitmodules`` to point "
                f"at an attacker-controlled repository.\n"
                f"  2. The checkout step persists credentials or the "
                f"workflow runs with broad permissions ({cred_check}). "
                f"The GITHUB_TOKEN is available to every step in the "
                f"job, including attacker-controlled code from the "
                f"submodule.\n"
                f"  3. Composite: the attacker's submodule content "
                f"(Makefile, postinstall script, build.rs) executes "
                f"with the persisted GITHUB_TOKEN at write scope. "
                f"The attacker can push to the base repo, create "
                f"releases, or exfiltrate secrets."
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
                triggering_check_ids=["GHA-102", cred_check],
                triggering_findings=triggers,
                resources=[resource],
                references=list(RULE.references),
                recommendation=RULE.recommendation,
            ))
    seen: set[str] = set()
    deduped: list[Chain] = []
    for c in out:
        if c.resources[0] not in seen:
            seen.add(c.resources[0])
            deduped.append(c)
    return deduped
