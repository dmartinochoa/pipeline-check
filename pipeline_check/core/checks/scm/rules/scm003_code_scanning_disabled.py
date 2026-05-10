"""SCM-003. GitHub default code scanning is not enabled.

Maps to OpenSSF Scorecard ``SAST``. Default code scanning (the
GitHub-managed CodeQL setup) gives a baseline static-analysis
signal without requiring the team to author and maintain a
CodeQL workflow themselves. When neither default setup nor a
CodeQL workflow is enabled, no SAST signal lands in the GitHub
Code Scanning UI on PRs.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    SCMRepoSnapshot,
    archived_state_label,
    repo_resource,
)

RULE = Rule(
    id="SCM-003",
    title="GitHub default code scanning is not enabled",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-10",),
    esf=("ESF-V-VULN-MGMT",),
    cwe=("CWE-1059",),
    recommendation=(
        "Enable default code scanning under the repository's Settings "
        "-> Code security -> Code scanning -> Default. The "
        "GitHub-managed CodeQL setup picks the right languages "
        "automatically and writes findings into the Code Scanning UI "
        "on every push and PR. Teams that already ship a CodeQL "
        "workflow can leave this rule's check off — but the default "
        "setup is the lowest-friction path for repos that don't have "
        "one."
    ),
    docs_note=(
        "Reads ``state`` from the default code-scanning setup "
        "endpoint (``GET /repos/{owner}/{repo}/code-scanning/"
        "default-setup``). Fires when ``state`` is anything other "
        "than ``configured`` (``not-configured``, missing, or 404). "
        "This check only evaluates the default-setup endpoint. Repos "
        "running hand-authored CodeQL workflows or third-party SARIF "
        "uploads can still fail SCM-003; suppress per repo via "
        "ignore-file when that alternative coverage is intentional."
    ),
    known_fp=(
        "Repos that ship a hand-authored CodeQL workflow (or use "
        "Semgrep / Snyk / another SAST whose results land in the "
        "Code Scanning UI via SARIF upload) get the same coverage "
        "without enabling default setup. Suppress via ignore-file "
        "rather than removing the rule.",
    ),
    exploit_example=(
        "# Without code scanning, the only signal that a PR\n"
        "# introduces (e.g.) a SQL injection or hardcoded secret\n"
        "# comes from the human reviewer:\n"
        "#\n"
        "#   - def lookup(user_id):\n"
        "#   -     return db.query(\"SELECT * FROM u WHERE id = ?\", user_id)\n"
        "#   + def lookup(user_id):\n"
        "#   +     return db.query(f\"SELECT * FROM u WHERE id = {user_id}\")\n"
        "#\n"
        "# A reviewer skimming a 400-line PR misses this. Default\n"
        "# CodeQL setup catches the same change as a CWE-89 finding\n"
        "# in the PR check, surfaces it inline in the diff, and\n"
        "# blocks the merge if the protection rule wires it up as\n"
        "# a required status check (see SCM-008)."
    ),
)


def check(snapshot: SCMRepoSnapshot) -> Finding:
    # Archived/disabled-repo guard: GitHub auto-disables code
    # scanning runs on archived or admin-disabled repos. Without
    # this guard SCM-003 would FP on every archived repo regardless
    # of historical scanning posture.
    if state_label := archived_state_label(snapshot):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                f"Repo is {state_label}; GitHub auto-disables code "
                f"scanning on {state_label} repos. Skipped."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    setup = snapshot.code_scanning_default_setup
    state = ""
    if isinstance(setup, dict):
        raw = setup.get("state")
        if isinstance(raw, str):
            state = raw
    passed = state == "configured"
    desc = (
        "Default code scanning is enabled and configured."
        if passed else
        f"Default code scanning is not enabled (state="
        f"``{state or 'unavailable'}``). PR builds receive no "
        f"GitHub-managed SAST signal in the Code Scanning UI unless "
        f"a CodeQL workflow or third-party SARIF upload covers the "
        f"same ground."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
