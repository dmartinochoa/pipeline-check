"""AC-036. Untrusted-code execution with no runtime egress containment.

Two legs on the same workflow:

  * An *execution* leg: the workflow runs attacker-influenced or
    remotely-fetched code. Script injection (``GHA-003``), github-script
    injection (``GHA-035``), a ``curl | bash`` remote-script fetch
    (``GHA-016``), or build-tool lifecycle scripts on an untrusted
    trigger (``GHA-044``). Any of these means code the attacker can
    shape runs on the runner.
  * An *egress* leg: the workflow has no enforced network-egress
    allowlist. Either step-security/harden-runner is absent on a
    workflow that mints an OIDC token or deploys (``GHA-108``), or it
    is present but left in audit mode, which records traffic without
    blocking it (``GHA-107``). ``GHA-107`` and ``GHA-108`` are mutually
    exclusive on a given workflow, so at most one fires.

Independently, each leg is already a finding. Together they remove the
last line of defense: the executing code can read the runner's OIDC
token, ``GITHUB_TOKEN``, or secrets and POST them to an attacker host
with nothing at the network layer to drop the connection. This is the
exact failure mode harden-runner's block mode exists to stop, and the
mechanism behind the tj-actions / Shai-Hulud class of credential
exfiltration.

Reachability model: when the execution leg and the egress leg share a
job (intersected via ``Finding.job_anchors``), the injected code runs
in the same job that holds the credential, a confirmed exfil path.
Otherwise the chain still fires on same-workflow co-occurrence but is
flagged unconfirmed (the credential is job-scoped, so a cross-job combo
is a weaker signal). GHA-107 carries no job anchors, so a GHA-107 leg
is always co-occurrence.
"""
from __future__ import annotations

from collections import defaultdict

from ...checks.base import Confidence, Finding, Severity
from ..base import Chain, ChainRule, min_confidence

#: Execution legs: code the attacker can influence runs on the runner.
_EXEC_LEGS = ("GHA-003", "GHA-016", "GHA-035", "GHA-044")
#: Egress legs: no enforced egress allowlist (absent, or audit-only).
_EGRESS_LEGS = ("GHA-107", "GHA-108")

_EXEC_SET = frozenset(_EXEC_LEGS)
_EGRESS_SET = frozenset(_EGRESS_LEGS)

RULE = ChainRule(
    id="AC-036",
    title="Untrusted-code execution with no runtime egress containment",
    severity=Severity.HIGH,
    summary=(
        "A workflow runs attacker-influenced or remotely-fetched code "
        "(script injection, github-script injection, `curl | bash`, or "
        "build-tool lifecycle scripts on an untrusted trigger) AND has "
        "no enforced egress allowlist: harden-runner is absent on an "
        "OIDC/deploy workflow (GHA-108) or present but in audit mode "
        "(GHA-107). The executing code can read the runner's OIDC "
        "token, GITHUB_TOKEN, or secrets and exfiltrate them with "
        "nothing at the network layer to stop it."
    ),
    mitre_attack=(
        "T1059",  # Command and Scripting Interpreter
        "T1552",  # Unsecured Credentials
        "T1041",  # Exfiltration Over C2 Channel
    ),
    kill_chain_phase=(
        "execution (attacker-influenced code runs on the runner) -> "
        "credential-access (reads the OIDC token / GITHUB_TOKEN / "
        "secrets) -> exfiltration (no egress allowlist blocks the "
        "outbound connection)"
    ),
    references=(
        "https://www.stepsecurity.io/blog/popular-github-action-"
        "tj-actions-changed-files-is-compromised",
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/"
        "CICD-SEC-04-Poisoned-Pipeline-Execution-PPE",
    ),
    recommendation=(
        "Break either leg:\n"
        "  1. Close the execution primitive: route untrusted input "
        "through an `env:` var instead of inlining `${{ github.event.* "
        "}}` (GHA-003 / GHA-035), pin and verify actions, and replace "
        "`curl | bash` (GHA-016) / untrusted build-tool scripts "
        "(GHA-044) with pinned, checksummed installs.\n"
        "  2. Add an enforced egress allowlist: run "
        "`step-security/harden-runner` as the first step with "
        "`egress-policy: block` and an `allowed-endpoints` list "
        "(GHA-107 / GHA-108).\n"
        "Either fix narrows the chain; do both. Egress blocking is the "
        "defense-in-depth layer that contains an execution primitive "
        "you missed."
    ),
    providers=("github",),
    triggering_check_ids=(
        "GHA-003", "GHA-016", "GHA-035", "GHA-044", "GHA-107", "GHA-108",
    ),
)


def match(findings: list[Finding]) -> list[Chain]:
    exec_by_res: dict[str, list[Finding]] = defaultdict(list)
    egress_by_res: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        if f.passed:
            continue
        if f.check_id in _EXEC_SET:
            exec_by_res[f.resource].append(f)
        elif f.check_id in _EGRESS_SET:
            egress_by_res[f.resource].append(f)

    out: list[Chain] = []
    for resource in sorted(exec_by_res):
        egress_fs = egress_by_res.get(resource)
        if not egress_fs:
            continue
        exec_fs = exec_by_res[resource]
        triggers = exec_fs + egress_fs

        exec_jobs: set[str] = set()
        for f in exec_fs:
            exec_jobs |= set(f.job_anchors)
        egress_jobs: set[str] = set()
        for f in egress_fs:
            egress_jobs |= set(f.job_anchors)
        shared = sorted(exec_jobs & egress_jobs)
        confirmed = bool(shared)

        exec_ids = ", ".join(sorted({f.check_id for f in exec_fs}))
        egress_ids = ", ".join(sorted({f.check_id for f in egress_fs}))
        if confirmed:
            shared_repr = ", ".join(f"`{j}`" for j in shared)
            reach_note = (
                f"untrusted execution and the uncontained credential "
                f"share job {shared_repr}"
            )
            reach_narrative = (
                f"  4. Reachability confirmed: the executing code and "
                f"the uncontained credential are in the same job(s) "
                f"({shared_repr}). The injected payload runs where the "
                f"OIDC token / secret lives, a direct exfil path."
            )
        else:
            reach_note = ""
            reach_narrative = (
                "  4. Reachability unconfirmed: both legs fire on the "
                "same workflow but no shared job was proven (a GHA-107 "
                "leg carries no job anchors, or the credential sits in "
                "a different job). Treat as co-occurrence."
            )

        narrative = (
            f"In `{resource}`:\n"
            f"  1. Attacker-influenced or remotely-fetched code runs on "
            f"the runner ({exec_ids}).\n"
            f"  2. The workflow has no enforced egress allowlist "
            f"({egress_ids}): outbound traffic is unblocked.\n"
            f"  3. The executing code reads the runner's OIDC token / "
            f"GITHUB_TOKEN / secrets and POSTs them to an attacker "
            f"host; nothing at the network layer drops the connection.\n"
            f"{reach_narrative}"
        )

        out.append(Chain(
            chain_id=RULE.id,
            title=RULE.title,
            severity=RULE.severity,
            confidence=Confidence.HIGH if confirmed else min_confidence(triggers),
            summary=RULE.summary,
            narrative=narrative,
            mitre_attack=list(RULE.mitre_attack),
            kill_chain_phase=RULE.kill_chain_phase,
            triggering_check_ids=sorted({f.check_id for f in triggers}),
            triggering_findings=triggers,
            resources=[resource],
            references=list(RULE.references),
            recommendation=RULE.recommendation,
            confirmed_reachable=confirmed,
            reachability_note=reach_note,
        ))
    return out
