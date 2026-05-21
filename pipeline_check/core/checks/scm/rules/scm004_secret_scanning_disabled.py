"""SCM-004. GitHub secret scanning is not enabled on the repo.

Maps to CIS Software Supply Chain Security Guide section 1.5.1
(scanners in place to identify and prevent sensitive data in code).
GitHub native secret scanning catches credentials committed to
history before they leak — anything from tokens to private keys.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    SCMRepoSnapshot,
    archived_state_label,
    repo_resource,
    security_feature_state,
)

RULE = Rule(
    id="SCM-004",
    title="GitHub secret scanning is not enabled",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798",),
    recommendation=(
        "Enable secret scanning under the repository's Settings -> "
        "Code security -> Secret scanning. The GitHub-managed scanner "
        "covers ~200 token patterns from major providers and runs on "
        "every push. Pair with push protection so secrets are blocked "
        "at commit time rather than caught after the fact."
    ),
    docs_note=(
        "Reads ``security_and_analysis.secret_scanning.status`` from "
        "the repo metadata payload. Fires when the value is anything "
        "other than ``enabled``. Public repos get secret scanning "
        "free since 2023; private repos require a GitHub Advanced "
        "Security license. Without secret scanning, a credential "
        "committed even briefly is recoverable from git history "
        "indefinitely."
    ),
    known_fp=(
        "When the scanning token lacks ``admin`` scope on the repo, "
        "the ``security_and_analysis`` block is omitted from the API "
        "response and this rule cannot tell ``disabled`` from "
        "``unknown``. The fix is to grant the token admin scope on "
        "the repo (or re-run with a personal token from a maintainer) "
        "rather than to suppress the rule.",
    ),
    incident_refs=(
        "GitGuardian's annual State of Secrets Sprawl reports find "
        "millions of fresh credential leaks per year across public "
        "GitHub commits, with the median time-to-revocation measured "
        "in days. Native secret scanning alerts the maintainer within "
        "minutes of the push, collapsing the exploitable window from "
        "days to minutes for the patterns it covers.",
    ),
    exploit_example=(
        "# Vulnerable: a developer pushes a commit that contains a\n"
        "# leaked AWS access key in source code. Without secret\n"
        "# scanning enabled, GitHub never surfaces an alert; the\n"
        "# secret stays in the repo's git history forever and any\n"
        "# repo reader (or future fork) extracts it. Public repos\n"
        "# are crawled by attackers continuously for AKIA-prefixed\n"
        "# strings.\n"
        "# GET /repos/myorg/myrepo (vulnerable response):\n"
        "{\n"
        "  \"security_and_analysis\": {\n"
        "    \"secret_scanning\": {\"status\": \"disabled\"}\n"
        "  }\n"
        "}\n"
        "\n"
        "# Safe: enable secret scanning. GitHub then scans every\n"
        "# push and historical commit for known credential\n"
        "# patterns and surfaces alerts; pair with push protection\n"
        "# (SCM-015) so secrets are blocked at push time before\n"
        "# they land in history.\n"
        "# PATCH /repos/myorg/myrepo:\n"
        "{\n"
        "  \"security_and_analysis\": {\n"
        "    \"secret_scanning\": {\"status\": \"enabled\"}\n"
        "  }\n"
        "}"
    ),
)


def check(snapshot: SCMRepoSnapshot) -> Finding:
    # Archived/disabled-repo guard: GitHub auto-disables secret
    # scanning on archived repos.
    if state_label := archived_state_label(snapshot):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                f"Repo is {state_label}; GitHub auto-disables secret "
                f"scanning on {state_label} repos. Skipped."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    state = security_feature_state(snapshot, "secret_scanning")
    passed = state == "enabled"
    if state is None:
        desc = (
            "GitHub secret scanning state is unavailable from the API "
            "response (token may lack ``admin`` scope on this repo). "
            "Treating as not-enabled; re-run with admin scope to "
            "confirm."
        )
    elif passed:
        desc = "GitHub secret scanning is enabled on this repository."
    else:
        desc = (
            f"GitHub secret scanning is not enabled (state="
            f"``{state}``). Credentials committed even briefly remain "
            f"recoverable from git history; native scanning alerts "
            f"within minutes of the push, anything else relies on "
            f"after-the-fact discovery."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
