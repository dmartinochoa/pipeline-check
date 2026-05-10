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
from ..base import SCMRepoSnapshot, repo_resource

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
        "Does NOT fire when default setup is off but a CodeQL "
        "workflow is configured — a future SCM-NNN rule keyed off "
        "the workflow-uploaded code-scanning results endpoint will "
        "cover that path."
    ),
    known_fp=(
        "Repos that ship a hand-authored CodeQL workflow (or use "
        "Semgrep / Snyk / another SAST whose results land in the "
        "Code Scanning UI via SARIF upload) get the same coverage "
        "without enabling default setup. Suppress via ignore-file "
        "rather than removing the rule.",
    ),
)


def check(snapshot: SCMRepoSnapshot) -> Finding:
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
