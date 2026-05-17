"""SCM-022. Repo allows actions from any source (no allow-list)."""
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
    id="SCM-022",
    title="Repo Actions permissions allow any source (no allow-list)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-8"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-829",),
    recommendation=(
        "In repo Settings → Actions → General → Actions "
        "permissions, set the allow-list mode to ``Allow "
        "<owner>, and select non-<owner>, actions and reusable "
        "workflows`` (``selected``) and curate a list of trusted "
        "publishers. Each new third-party action becomes an "
        "explicit decision rather than the result of a workflow "
        "writer adding ``uses: random/unknown@v1`` and CI silently "
        "executing it. The shipped pack of GHA-040 (compromised-"
        "action registry) plus GHA-041..047 (action reputation "
        "checks) provides the workflow-time signal; SCM-022 is "
        "the org-policy gate that says ``don't even let an "
        "untrusted action onto the runner.``"
    ),
    docs_note=(
        "Reads ``allowed_actions`` from ``GET /repos/{owner}/"
        "{repo}/actions/permissions``. Values: ``\"selected\"`` "
        "(allow-listed) and ``\"local_only\"`` (org-internal only) "
        "pass; ``\"all\"`` (no restriction) fails. Requires admin "
        "scope. The rule passes silently when Actions is disabled "
        "at the repo level (``enabled: false``) — nothing runs, "
        "so the source restriction is moot."
    ),
    known_fp=(
        "Repos that legitimately consume a wide variety of "
        "third-party actions (open-source CI examples, "
        "marketplace-aggregator demos) may accept the ``all`` "
        "mode as a trade-off. The right defense in that case is "
        "rigorous SHA-pinning (GHA-001) plus the GHA-040..047 "
        "reputation pack; SCM-022 is the org-level allow-list "
        "that becomes redundant when every workflow already "
        "pins to a vetted commit.",
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
                f"Repo is {label}; Actions allow-list check skipped."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    ap = snapshot.actions_permissions
    if not isinstance(ap, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "actions/permissions endpoint unavailable (token "
                "likely lacks ``admin`` scope)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    if ap.get("enabled") is False:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "GitHub Actions is disabled at the repo level; "
                "source allow-list is moot."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    allowed = ap.get("allowed_actions")
    if allowed in ("selected", "local_only"):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                f"Repo restricts Actions sources to "
                f"``{allowed}``."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    if allowed != "all":
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                f"actions/permissions returned an unrecognized "
                f"``allowed_actions`` value: {allowed!r}. Treating "
                f"as unavailable."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot),
        description=(
            "Repo Actions permissions allow any source "
            "(``allowed_actions: all``). A workflow writer can add "
            "``uses: arbitrary/unknown@v1`` and CI will execute it "
            "without further policy review."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
