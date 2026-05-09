"""AC-010. Self-Hosted Runner Environment Exfiltration.

A non-ephemeral self-hosted runner that fetches and executes
unpinned remote code is a one-shot foothold: the attacker only has
to land code once. They can then mint a persistent backdoor in the
runner's filesystem that survives across jobs and harvest every
secret the runner sees on subsequent workflow executions.

The chain fires when a workflow runs on a self-hosted runner
without ephemeral isolation (GHA-012) AND either pipes a remote
script straight into a shell (GHA-016) or persists the GitHub
token across jobs (GHA-019). Both legs give the same "land code
once, harvest forever" property.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, failing, min_confidence

RULE = ChainRule(
    id="AC-010",
    title="Self-Hosted Runner Environment Exfiltration",
    severity=Severity.CRITICAL,
    summary=(
        "A self-hosted runner without ephemeral isolation (GHA-012) "
        "executes a workflow that either pipes a remote script into "
        "a shell (GHA-016) or persists the GitHub token across jobs "
        "(GHA-019). Both legs give an attacker a route to plant "
        "persistence on the runner; the runner's filesystem then "
        "harvests every secret subsequent workflows expose."
    ),
    mitre_attack=(
        "T1552.001",  # Unsecured Credentials: Credentials In Files
        "T1078.004",  # Valid Accounts: Cloud Accounts
        "T1195.002",  # Supply Chain Compromise
    ),
    kill_chain_phase="execution -> persistence -> credential-access",
    references=(
        "https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security",
        "https://www.legitsecurity.com/blog/github-self-hosted-runners-vulnerabilities",
    ),
    recommendation=(
        "Configure self-hosted runners as ephemeral (one job per "
        "VM, recycled afterward). For each job, replace remote-"
        "script-into-shell idioms (``curl ... | bash``) with a "
        "verified, version-pinned download step, and set "
        "``persist-credentials: false`` on every checkout."
    ),
    providers=("github",),
    triggering_check_ids=("GHA-012", "GHA-016", "GHA-019"),
)


# AC-010 fires when GHA-012 (non-ephemeral self-hosted) coincides with
# at least one of (GHA-016 curl-pipe, GHA-019 token persistence) on
# the *same* workflow file. group_by_resource enforces all-required;
# the OR-of-two-legs case wants something more flexible.
def _resources_for(findings: list[Finding], check_ids: tuple[str, ...]) -> dict[str, dict[str, Finding]]:
    by_res: dict[str, dict[str, Finding]] = {}
    for f in failing(findings, *check_ids):
        slot = by_res.setdefault(f.resource, {})
        # Keep the first occurrence per (resource, check_id); chain
        # narrative only needs evidence the leg fired, not every hit.
        if f.check_id not in slot:
            slot[f.check_id] = f
    return by_res


def match(findings: list[Finding]) -> list[Chain]:
    res_map = _resources_for(
        findings, ("GHA-012", "GHA-016", "GHA-019"),
    )
    out: list[Chain] = []
    for resource, ck_map in res_map.items():
        if "GHA-012" not in ck_map:
            continue
        secondary = [c for c in ("GHA-016", "GHA-019") if c in ck_map]
        if not secondary:
            continue
        triggers = [ck_map["GHA-012"]] + [ck_map[c] for c in secondary]
        leg_descriptions = []
        if "GHA-016" in ck_map:
            leg_descriptions.append(
                "  2a. A `run:` block pipes a remote script into a "
                "shell (GHA-016). On a non-ephemeral runner an "
                "attacker who lands a single malicious response "
                "can drop a backdoor in `~`, `/tmp`, or the runner "
                "work directory."
            )
        if "GHA-019" in ck_map:
            leg_descriptions.append(
                "  2b. The GitHub token is persisted across jobs "
                "(GHA-019). A malicious payload landed in any one "
                "job retains access to the token for the lifetime "
                "of the runner process."
            )
        narrative = (
            f"In `{resource}`:\n"
            "  1. The workflow runs on a self-hosted runner that "
            "isn't configured as ephemeral (GHA-012). State "
            "(filesystem, environment, in-memory caches) survives "
            "between jobs.\n"
            + "\n".join(leg_descriptions) + "\n"
            "  3. Once persistence lands, every subsequent workflow "
            "execution leaks its secrets via the runner's "
            "filesystem to the attacker's foothold."
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
            triggering_check_ids=["GHA-012"] + secondary,
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
        ))
    return out
