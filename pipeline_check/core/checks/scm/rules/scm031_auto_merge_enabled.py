"""SCM-031. Repo allows auto-merge (no human-timing gate on merge)."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    SCMRepoSnapshot,
    archived_state_label,
    github_only_skip,
    repo_resource,
)

RULE = Rule(
    id="SCM-031",
    title="Repo allows auto-merge (no human-timing gate)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1", "CICD-SEC-4"),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-693", "CWE-863"),
    recommendation=(
        "In repo Settings → General → Pull Requests, uncheck "
        "``Allow auto-merge``. With auto-merge on, the PR merges "
        "the moment its required checks pass — including any "
        "required reviews already on the PR — with no further "
        "human gate on *when* the merge happens. The risk is "
        "compositional: combined with SCM-021 (Actions can "
        "self-approve PRs) or SCM-018 (PR-review bypass "
        "allowance), a workflow that opens a PR, satisfies its "
        "own required-review gate, and waits for status checks "
        "lands code into main without a human ever looking at "
        "the diff at the merge moment. If the workflow itself is "
        "what was compromised (Shai-Hulud, postinstall worm), "
        "the auto-merge step is the last gate that didn't fire.\n\n"
        "If your team relies on auto-merge for throughput, the "
        "compensating controls are SCM-021 (Actions cannot "
        "self-approve), SCM-002 (required reviews ≥ 1), SCM-011 "
        "(CODEOWNERS reviews required), and SCM-014 (last-push "
        "approval) — all together. Without all four, auto-merge "
        "is the path of least resistance for an unauthored "
        "commit to reach main."
    ),
    docs_note=(
        "Reads ``allow_auto_merge`` from the repo metadata "
        "(already fetched by every SCM scan; no extra endpoint). "
        "Fires when the value is ``true``. A missing field is "
        "treated as the GitHub default (``false``) and passes. "
        "The check is intentionally orthogonal to whether reviews "
        "are required — auto-merge with strong required-review "
        "controls is sometimes acceptable, auto-merge with weak "
        "ones is not. SCM-031 surfaces the trade-off; the "
        "operator pairs the finding with the SCM-002 / SCM-011 / "
        "SCM-014 / SCM-021 status to decide whether to keep "
        "auto-merge."
    ),
    known_fp=(
        "High-throughput engineering orgs that pair auto-merge "
        "with rigorous required-reviews + CODEOWNERS + last-push "
        "approval + no-Actions-self-approval (SCM-021) "
        "legitimately depend on auto-merge for velocity. The "
        "right pattern is to suppress this rule with a rationale "
        "that names the compensating controls so the trade-off "
        "stays visible at every audit. Suppressing without "
        "naming the controls makes the trade-off invisible to "
        "the next reviewer.",
    ),
)


def check(snapshot: SCMRepoSnapshot) -> Finding:
    skip = github_only_skip(snapshot)
    if skip is not None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=skip,
            recommendation=RULE.recommendation, passed=True,
        )
    if label := archived_state_label(snapshot):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                f"Repo is {label}; auto-merge check skipped."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    meta = snapshot.repo_meta
    if not isinstance(meta, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "repo metadata unavailable; auto-merge check "
                "skipped."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    if meta.get("allow_auto_merge") is not True:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "Auto-merge disabled; merges require an explicit "
                "human-initiated action."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot),
        description=(
            "Auto-merge is enabled (``allow_auto_merge: true``). "
            "Merges run automatically the moment required checks "
            "pass — no human-timing gate. Combined with SCM-018 "
            "(PR-review bypass) or SCM-021 (Actions can self-"
            "approve PRs), a workflow that opens its own PR can "
            "land code into main without a human ever looking at "
            "the diff at the merge moment."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
