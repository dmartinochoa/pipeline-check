"""SCM-008. Default branch protection does not require status checks.

Maps to CIS Software Supply Chain Security Guide section 1.1.5
(ensure any change to code requires review from authorized
personnel). Required-status-checks gate merges on automated
verification (CI build, security scan, lint), removing the
"approver eyeballed it but the build was red" failure mode.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMRepoSnapshot, default_branch_name, repo_resource

RULE = Rule(
    id="SCM-008",
    title="Default branch protection does not require status checks",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1", "CICD-SEC-10"),
    esf=("ESF-S-CHANGE-CONTROL", "ESF-V-VULN-MGMT"),
    cwe=("CWE-693",),
    recommendation=(
        "In the default-branch protection rule, enable ``Require "
        "status checks to pass before merging`` and list every check "
        "the team relies on (CI build, code scanning, secret "
        "scanning, lint). Set ``strict: true`` (``Require branches "
        "to be up to date before merging``) so a stale base doesn't "
        "land regressions the latest checks would catch."
    ),
    docs_note=(
        "Reads ``required_status_checks.contexts`` (or the newer "
        "``checks`` shape) from the branch protection payload. Fires "
        "when the field is missing or the contexts list is empty. "
        "Without required checks the merge gate degrades to "
        "human-only review; SCM-002 covers the review knob, this "
        "rule covers the automated-verification knob, and both "
        "should be on for high-trust default branches."
    ),
    known_fp=(
        "The ``restrictions`` block (users / teams / apps allowed "
        "to push directly to the protected branch) is not consulted "
        "today: a rule that requires status checks but lists every "
        "contributor in the push-restrictions allowlist still "
        "passes this rule even though those identities can land "
        "code without the checks running. Audit the allowlist in "
        "the GitHub UI when this rule passes on a high-trust repo.",
        "Status-check names are matched as opaque strings; a "
        "configured required check that no workflow actually emits "
        "(typo, deleted job) will still pass this rule. The check "
        "would block the merge in practice (GitHub waits for the "
        "named context forever), but the misconfiguration itself "
        "isn't visible from the protection payload.",
    ),
)


def check(snapshot: SCMRepoSnapshot) -> Finding:
    branch = default_branch_name(snapshot)
    protection = snapshot.default_branch_protection
    if not isinstance(protection, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                f"Default branch ``{branch}`` has no protection rule "
                f"to evaluate. See SCM-001."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    rsc = protection.get("required_status_checks")
    contexts: list[str] = []
    if isinstance(rsc, dict):
        # GitHub returns ``contexts`` (legacy flat list) and
        # ``checks`` (new shape with per-check app id). Either is a
        # signal that the user wired up at least one required check.
        raw_contexts = rsc.get("contexts")
        if isinstance(raw_contexts, list):
            contexts.extend(c for c in raw_contexts if isinstance(c, str))
        raw_checks = rsc.get("checks")
        if isinstance(raw_checks, list):
            for entry in raw_checks:
                if isinstance(entry, dict):
                    name = entry.get("context")
                    if isinstance(name, str):
                        contexts.append(name)
    passed = bool(contexts)
    desc = (
        f"Default branch ``{branch}`` requires "
        f"{len(contexts)} status check(s) before merge: "
        f"{', '.join(sorted(set(contexts))[:3])}"
        f"{'...' if len(set(contexts)) > 3 else ''}."
        if passed else
        f"Default branch ``{branch}`` has a protection rule but does "
        f"not require any status check before merge. A red CI build "
        f"or a failing security scan does not block the merge unless "
        f"a reviewer notices and refuses to approve."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
