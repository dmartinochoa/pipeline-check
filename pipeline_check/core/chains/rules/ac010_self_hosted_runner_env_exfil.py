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

from ...checks.base import Confidence, Finding, Severity
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
        secondary: list[str] = [c for c in ("GHA-016", "GHA-019") if c in ck_map]
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

        # Reachability is computed from GHA-019's job_anchors only;
        # GHA-016 currently runs as a blob scan with no per-job
        # attribution, so we can't anchor that leg precisely. When
        # GHA-019 is the secondary leg AND its anchors intersect
        # the non-ephemeral self-hosted job set from GHA-012, the
        # persistence-to-secret-harvest path is confirmed in a single
        # job. The GHA-016-only branch stays as co-occurrence.
        runner_jobs = set(ck_map["GHA-012"].job_anchors)
        confirmed = False
        shared: list[str] = []
        if "GHA-019" in ck_map:
            persist_jobs = set(ck_map["GHA-019"].job_anchors)
            shared = sorted(runner_jobs & persist_jobs)
            confirmed = bool(shared)
        if confirmed:
            shared_repr = ", ".join(f"`{j}`" for j in shared)
            reach_note = (
                f"token persistence and non-ephemeral runner share "
                f"job {shared_repr}"
            )
            reach_narrative = (
                f"  4. Co-located (unverified): the same job(s) "
                f"({shared_repr}) both persist the GitHub token AND "
                f"run on a non-ephemeral self-hosted runner. The "
                f"token outlives the step that wrote it on a host "
                f"that outlives the job."
            )
        else:
            reach_note = ""
            reach_narrative = (
                "  4. Reachability unconfirmed: the persistence "
                "primitive and the non-ephemeral runner fire on the "
                "same workflow file but no shared-job claim is "
                "available (GHA-016 is a blob scan; GHA-019 anchors "
                "didn't intersect). Treat as a co-occurrence signal."
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
            "filesystem to the attacker's foothold.\n"
            f"{reach_narrative}"
        )

        if confirmed:
            chain_confidence = Confidence.HIGH
        else:
            chain_confidence = min_confidence(triggers)

        out.append(Chain(
            chain_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            confidence=chain_confidence,
            summary=RULE.summary,
            narrative=narrative,
            mitre_attack=list(RULE.mitre_attack),
            kill_chain_phase=RULE.kill_chain_phase,
            triggering_check_ids=["GHA-012"] + secondary,
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
            confirmed_reachable=confirmed,
            reachability_note=reach_note,
        ))
    return out
