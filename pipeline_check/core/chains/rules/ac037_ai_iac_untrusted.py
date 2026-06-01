"""AC-037. AI agent applies attacker-influenced IaC to the cloud.

Two legs on the same workflow:

  * An *untrusted-input* leg: an agentic CLI runs in a topology where
    it reads attacker-controlled content. ``GHA-058`` (an agentic CLI
    invoked with permission-bypass flags or in the PR-checkout
    topology, where the agent reads a checked-out fork PR) or
    ``GHA-103`` (an AI review bot on a ``pull_request_target`` /
    ``issue_comment`` trigger without an environment gate). Either way
    the agent's prompt is shaped by an attacker.
  * An *IaC-apply* leg: ``GHA-111`` — a job runs an agentic CLI
    alongside an unattended IaC apply (``terraform apply`` /
    ``cloudformation deploy`` / ``cdk deploy`` / ``pulumi up`` /
    ``sam deploy``), so the agent's generated infrastructure is pushed
    to the cloud account with no plan review.

Independently each leg is already a finding. Together they close the
loop from untrusted input to cloud-state change: a prompt-injection
payload in the PR diff / comment redirects the agent to write malicious
Terraform / CloudFormation (an admin IAM user, a ``0.0.0.0/0`` security
group, disabled CloudTrail), and the unattended apply realizes it in
the account. GHA-111 alone is the privileged-apply gap; pairing it with
a confirmed untrusted-input topology is what makes the prompt injection
reachable, so the composite is the cloud-account analog of AC-035's
repo-write reviewer-and-committer loop (HackerBot-Claw, February 2026).

Reachability model: per-workflow co-occurrence (the GHA-058 / GHA-103
legs carry no job anchors). Both legs fire on the same workflow file;
the untrusted-input leg establishes the attacker-reachable agent that
GHA-111 then arms with an unattended apply.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-037",
    title="AI agent applies attacker-influenced IaC to the cloud",
    severity=Severity.CRITICAL,
    summary=(
        "An agentic CLI reads attacker-controlled input, via "
        "permission-bypass flags or a PR-checkout topology (GHA-058) "
        "or an AI review bot on an untrusted trigger (GHA-103), AND the "
        "same workflow runs an agent alongside an unattended IaC apply "
        "(GHA-111). A prompt-injection payload in the PR or comment "
        "makes the agent write malicious Terraform / CloudFormation "
        "that the apply pushes straight to the cloud account, no human "
        "reviewing the plan."
    ),
    mitre_attack=(
        "T1195.002",  # Compromise Software Supply Chain
        "T1059",      # Command and Scripting Interpreter
        "T1078.004",  # Valid Accounts: Cloud Accounts
    ),
    kill_chain_phase=(
        "initial-access (prompt injection via untrusted PR / comment) -> "
        "execution (AI agent follows the injected instruction and edits "
        "the IaC) -> impact (unattended apply realizes the malicious "
        "infrastructure in the cloud account, no human review)"
    ),
    references=(
        "https://owasp.org/www-project-top-10-ci-cd-security-risks/"
        "CICD-SEC-04-Poisoned-Pipeline-Execution-PPE",
        "https://docs.github.com/en/actions/security-for-github-actions/"
        "security-guides/security-hardening-for-github-actions",
    ),
    recommendation=(
        "Break either leg:\n"
        "  1. Cut the untrusted-input path: don't run an agentic CLI on "
        "an untrusted trigger or over a checked-out fork PR, and don't "
        "pass attacker-authored text into the prompt (GHA-058 / "
        "GHA-103).\n"
        "  2. Take the apply away from the agent's job: have the agent "
        "only propose changes into a reviewable PR, and run "
        "``terraform apply`` / ``cloudformation deploy`` from a "
        "separate job on the merged, human-reviewed plan behind a "
        "protected ``environment:`` (GHA-111).\n"
        "Best: never let one workflow both feed an agent untrusted "
        "input and apply that agent's infrastructure changes "
        "unattended."
    ),
    providers=("github",),
    triggering_check_ids=("GHA-058", "GHA-103", "GHA-111"),
)

#: Untrusted-input legs, either establishes an attacker-reachable agent.
_INPUT_LEGS = ("GHA-058", "GHA-103")


def match(findings: list[Finding]) -> list[Chain]:
    out: list[Chain] = []
    for input_check in _INPUT_LEGS:
        grouped = group_by_resource(findings, [input_check, "GHA-111"])
        for resource, ck_map in grouped.items():
            reader = ck_map[input_check]
            applier = ck_map["GHA-111"]
            triggers = [reader, applier]
            input_leg = (
                "an agentic CLI runs with permission-bypass flags or in "
                "the PR-checkout topology, reading attacker content "
                "(GHA-058)"
                if input_check == "GHA-058"
                else "an AI review bot runs on an untrusted trigger with "
                "no environment gate (GHA-103)"
            )
            narrative = (
                f"On workflow `{resource}`:\n"
                f"  1. {input_leg}. The agent's prompt is shaped by an "
                f"attacker (a fork PR diff, an issue comment).\n"
                f"  2. The same workflow runs an agent alongside an "
                f"unattended IaC apply (GHA-111): its generated "
                f"Terraform / CloudFormation is pushed to the cloud "
                f"account with no plan review.\n"
                f"  3. Composite: a prompt-injection line in the PR or "
                f"comment redirects the agent to write malicious IaC (an "
                f"admin IAM user, a `0.0.0.0/0` security group, disabled "
                f"logging), and the apply realizes it in the account "
                f"with no human between the untrusted input and the "
                f"cloud-state change."
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
                triggering_check_ids=[input_check, "GHA-111"],
                triggering_findings=triggers,
                resources=[resource],
                references=list(RULE.references),
                recommendation=RULE.recommendation,
            ))
    # A workflow that trips both GHA-058 and GHA-103 should surface a
    # single AC-037, not two. Keep the first (GHA-058) per resource.
    seen: set[str] = set()
    deduped: list[Chain] = []
    for c in out:
        if c.resources[0] not in seen:
            seen.add(c.resources[0])
            deduped.append(c)
    return deduped
