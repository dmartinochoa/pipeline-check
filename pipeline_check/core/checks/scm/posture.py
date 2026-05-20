"""SCM posture orchestrator.

Each ``SCM-*`` rule lives in its own module under ``rules/``. This
orchestrator auto-discovers them and runs each against every loaded
repo snapshot. Mirrors :class:`OCIManifestChecks` and the rest of
the rule-based provider orchestrators.

Platform routing: snapshots carry a ``platform`` slot
(``"github"`` / ``"gitlab"`` / ``"bitbucket"``). GitHub-specific
rules (those keyed off ``security_and_analysis`` or off
GitHub-only protection-rule knobs) are skipped on non-GitHub
snapshots and produce a passing Finding with a "not applicable on
PLATFORM" description so the operator sees the deliberate skip
rather than a silent absence.
"""
from __future__ import annotations

from ..base import Finding
from ..rule import apply_rule_metadata, discover_rules
from .base import SCMBaseCheck, SCMContext, repo_resource

#: Rule IDs that only make sense against a GitHub-hosted repository.
#: Anything keyed off the ``security_and_analysis`` block or a
#: GitHub-only protection-rule knob (``enforce_admins``,
#: ``require_code_owner_reviews``, ``dismiss_stale_reviews``,
#: ``required_conversation_resolution``, ``require_last_push_approval``,
#: ``bypass_pull_request_allowances``, ``restrictions``) is listed
#: here. Universal rules (SCM-001 / -002 / -006 / -007 / -008 / -009
#: / -017) iterate normalized slots and run on every platform.
_GITHUB_ONLY_IDS: frozenset[str] = frozenset({
    "SCM-003",  # GitHub default code scanning
    "SCM-004",  # secret scanning (security_and_analysis)
    "SCM-005",  # Dependabot security updates
    "SCM-010",  # enforce_admins
    "SCM-011",  # require_code_owner_reviews
    "SCM-012",  # dismiss_stale_reviews
    "SCM-013",  # required_conversation_resolution
    "SCM-014",  # require_last_push_approval
    "SCM-015",  # secret_scanning_push_protection
    "SCM-016",  # private_vulnerability_reporting
    "SCM-018",  # bypass_pull_request_allowances
    "SCM-019",  # push restrictions individual users (GitHub shape)
    "SCM-043",  # tag-ruleset signed_commits (GitHub Rulesets API)
    "SCM-044",  # required_signatures + enforce_admins (GitHub branch protection)
    "SCM-045",  # default code scanning query_suite (GitHub default setup)
    "SCM-046",  # default code scanning schedule (GitHub default setup)
    "SCM-047",  # repo languages vs default-setup languages (GitHub linguist)
})


class SCMPostureChecks(SCMBaseCheck):

    def __init__(
        self, ctx: SCMContext, target: str | None = None,
    ) -> None:
        super().__init__(ctx, target)
        self._rules = discover_rules(
            "pipeline_check.core.checks.scm.rules"
        )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for snapshot in self.ctx.repos:
            for rule, check_fn in self._rules:
                if (
                    snapshot.platform != "github"
                    and rule.id in _GITHUB_ONLY_IDS
                ):
                    finding = Finding(
                        check_id=rule.id,
                        title=rule.title,
                        severity=rule.severity,
                        resource=repo_resource(snapshot),
                        description=(
                            f"Rule is GitHub-specific (relies on the "
                            f"``security_and_analysis`` block or a "
                            f"GitHub-only protection knob); skipped "
                            f"on the {snapshot.platform} snapshot."
                        ),
                        recommendation=rule.recommendation, passed=True,
                    )
                else:
                    finding = check_fn(snapshot)
                apply_rule_metadata(finding, rule)
                findings.append(finding)
        return findings
