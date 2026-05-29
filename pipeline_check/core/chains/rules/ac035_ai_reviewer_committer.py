"""AC-035. AI agent is both reviewer and committer.

Two legs:

  * ``GHA-103`` — an AI code-review bot runs on an untrusted trigger
    (``pull_request_target`` / ``issue_comment``) with write
    permissions and no ``environment:`` gate. The agent reads
    attacker-authored content (the PR diff, an issue comment).
  * ``GHA-104`` (the agent pushes commits directly without a PR) OR
    ``GHA-106`` (the agent's job holds a write-scoped GITHUB_TOKEN).
    Either way the same agent can write back to the repository.

Independently: GHA-103 is an untrusted-input exposure; GHA-104 /
GHA-106 are write-capability gaps. Together the AI is both the
reviewer (it ingests attacker-controlled input) and the committer (it
can push). A prompt-injection payload in the PR / comment redirects
the agent to approve and commit its own malicious change, closing the
loop with no human in it. This is the "AI reviewer and committer"
gap the HackerBot-Claw campaign (February 2026) exploited.

Reachability model: per-workflow co-occurrence. Both legs fire on the
same workflow file; GHA-103 already establishes the untrusted-trigger
+ write-permission topology that GHA-104 / GHA-106 then weaponize.
"""
from __future__ import annotations

from ...checks.base import Finding, Severity
from ..base import Chain, ChainRule, group_by_resource, min_confidence

RULE = ChainRule(
    id="AC-035",
    title="AI agent is both reviewer and committer",
    severity=Severity.CRITICAL,
    summary=(
        "An AI review bot runs on an untrusted trigger without an "
        "environment gate (GHA-103) AND the same workflow lets the "
        "agent write back, by pushing commits directly (GHA-104) or "
        "by holding a write-scoped GITHUB_TOKEN (GHA-106). A "
        "prompt-injection payload in the PR or comment makes the AI "
        "approve and commit its own malicious change with no human "
        "review in the loop."
    ),
    mitre_attack=(
        "T1195.002",  # Compromise Software Supply Chain
        "T1059",      # Command and Scripting Interpreter
        "T1078.004",  # Valid Accounts: Cloud Accounts
    ),
    kill_chain_phase=(
        "initial-access (prompt injection via untrusted PR / comment) -> "
        "execution (AI agent follows the injected instruction) -> "
        "defense-evasion (the AI is its own reviewer) -> "
        "impact (agent commits / pushes without human review)"
    ),
    references=(
        "https://docs.github.com/en/actions/security-for-github-actions/"
        "security-guides/security-hardening-for-github-actions",
    ),
    recommendation=(
        "Break either leg:\n"
        "  1. Don't run the AI bot on an untrusted trigger with write "
        "scope (GHA-103): move review to ``pull_request`` with a "
        "read-only token, or gate the privileged job behind a "
        "protected ``environment:``.\n"
        "  2. Take away the agent's write path: route its output "
        "through a reviewable PR instead of a direct push (GHA-104), "
        "and scope the job to ``contents: read`` (GHA-106).\n"
        "Best: never let one workflow both feed an agent untrusted "
        "input and grant it the ability to write back. Split review "
        "(read-only) from any apply step (human-approved)."
    ),
    providers=("github",),
    triggering_check_ids=("GHA-103", "GHA-104", "GHA-106"),
)


def match(findings: list[Finding]) -> list[Chain]:
    out: list[Chain] = []
    for write_check in ("GHA-104", "GHA-106"):
        grouped = group_by_resource(findings, ["GHA-103", write_check])
        for resource, ck_map in grouped.items():
            reviewer = ck_map["GHA-103"]
            writer = ck_map[write_check]
            triggers = [reviewer, writer]
            write_leg = (
                "pushes commits directly without a PR (GHA-104)"
                if write_check == "GHA-104"
                else "holds a write-scoped GITHUB_TOKEN (GHA-106)"
            )
            narrative = (
                f"On workflow `{resource}`:\n"
                f"  1. An AI review bot runs on an untrusted trigger "
                f"with write permissions and no ``environment:`` gate "
                f"(GHA-103). It ingests attacker-authored content, the "
                f"PR diff or an issue comment.\n"
                f"  2. The same workflow lets the agent write back: it "
                f"{write_leg}.\n"
                f"  3. Composite: the AI is both reviewer and "
                f"committer. A prompt-injection line in the PR or "
                f"comment redirects the agent to approve and commit "
                f"its own malicious change, with no human review "
                f"between the untrusted input and the push."
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
                triggering_check_ids=["GHA-103", write_check],
                triggering_findings=triggers,
                resources=[resource],
                references=list(RULE.references),
                recommendation=RULE.recommendation,
            ))
    # A workflow that trips both GHA-104 and GHA-106 should surface a
    # single AC-035, not two. Keep the first (GHA-104) per resource.
    seen: set[str] = set()
    deduped: list[Chain] = []
    for c in out:
        if c.resources[0] not in seen:
            seen.add(c.resources[0])
            deduped.append(c)
    return deduped
