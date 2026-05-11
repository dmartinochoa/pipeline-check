"""SCM-017. Repository has no CODEOWNERS file.

CODEOWNERS is a two-leg control: the branch-protection toggle
(SCM-011) requests review from code owners; the CODEOWNERS file at
``.github/CODEOWNERS``, ``CODEOWNERS``, or ``docs/CODEOWNERS`` names
them. With the toggle on but the file absent, GitHub silently treats
the requirement as satisfied for any reviewer — the path-scoped
sign-off the team thinks is enforced is not.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    SCMRepoSnapshot,
    archived_state_label,
    is_empty_repo,
    repo_resource,
)

RULE = Rule(
    id="SCM-017",
    title="Repository has no CODEOWNERS file",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-732",),
    recommendation=(
        "Add a ``CODEOWNERS`` file at ``.github/CODEOWNERS`` (the "
        "GitHub-recommended location), ``CODEOWNERS`` at the repo "
        "root, or ``docs/CODEOWNERS``. Map directories to the team or "
        "individual responsible for them. With SCM-011's "
        "``require_code_owner_reviews`` knob enabled, GitHub auto-"
        "requests review from the matched owners on every PR; without "
        "the file, the toggle is meaningless and any reviewer can "
        "approve any change."
    ),
    docs_note=(
        "Probes the three canonical CODEOWNERS locations via "
        "``GET /repos/{owner}/{repo}/contents/<path>``. Fires when "
        "none of the three returns a file response. Pairs with "
        "SCM-011 (the protection-rule toggle): SCM-011 covers intent, "
        "SCM-017 covers reality. A repo with both set is auditing the "
        "path-scoped review actually happens."
    ),
    known_fp=(
        "Single-team repos where every contributor is a code owner "
        "of every path may legitimately skip CODEOWNERS — the file "
        "adds no routing in that case. Suppress via ignore-file when "
        "the team intentionally stays flat. The same suppression "
        "applies to SCM-011.",
    ),
)


_CODEOWNERS_PATHS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")


def check(snapshot: SCMRepoSnapshot) -> Finding:
    if snapshot.repo_meta is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "Repo metadata is unavailable. CODEOWNERS presence "
                "cannot be evaluated; see ctx.warnings for the "
                "underlying fetch failure."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    if is_empty_repo(snapshot):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "Repo is empty (no commits, no default branch). "
                "Add CODEOWNERS as part of the initial commit set."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    label = archived_state_label(snapshot)
    if label is not None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                f"Repo is {label}; CODEOWNERS skipped (read-only)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    path = snapshot.codeowners_path
    passed = path is not None
    desc = (
        f"CODEOWNERS file present at ``{path}``."
        if passed else
        "No CODEOWNERS file at ``.github/CODEOWNERS``, "
        "``CODEOWNERS``, or ``docs/CODEOWNERS``. Any path-scoped "
        "review configured via SCM-011 is silently unenforced — "
        "GitHub has no map from directories to owners."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
