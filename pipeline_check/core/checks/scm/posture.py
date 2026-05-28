"""SCM posture orchestrator.

Each ``SCM-*`` rule lives in its own module under ``rules/``. This
orchestrator auto-discovers them and runs each against every loaded
repo snapshot. Mirrors :class:`OCIManifestChecks` and the rest of
the rule-based provider orchestrators.

Platform routing: snapshots carry a ``platform`` slot
(``"github"`` / ``"gitlab"`` / ``"bitbucket"``). Platform-specific
rules (GitHub-only, GitLab-only, Bitbucket-only) are short-circuited
on the wrong platform and produce a passing Finding with a "not
applicable on PLATFORM" description so the operator sees the
deliberate skip rather than a silent absence.

The orchestrator handles the short-circuit centrally rather than
requiring every rule to call ``<platform>_only_skip()`` at the top
of its ``check`` function (existing GitHub-only rules use the
helper directly; new GitLab / Bitbucket rules can defer to either
pattern). Centralizing here also keeps the platform-routing table
in one place, so adding a new platform (Gitea SCM, Azure DevOps
SCM, ...) is a single dict edit.
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

#: Rule IDs that only apply to GitLab repositories. Each reads
#: GitLab-shaped payloads (push rules, project metadata) stashed
#: under ``repo_meta["_gitlab_*"]`` by the GitLab hydrator. Rules
#: are still defensive about the platform via ``gitlab_only_skip``
#: so they degrade gracefully if called directly; the orchestrator
#: short-circuits here so non-GitLab snapshots don't even enter the
#: rule body.
_GITLAB_ONLY_IDS: frozenset[str] = frozenset({
    "SCM-050",  # push rules: prevent_secrets
    "SCM-051",  # push rules: commit_committer_check
    "SCM-052",  # project: only_allow_merge_if_all_discussions_are_resolved
    "SCM-053",  # project: merge_requests_author_approval
})

#: Rule IDs that only apply to Bitbucket Cloud repositories. Each
#: reads Bitbucket-shaped payloads stashed under
#: ``repo_meta["_bitbucket_repo"]`` by the Bitbucket hydrator.
_BITBUCKET_ONLY_IDS: frozenset[str] = frozenset({
    "SCM-054",  # fork_policy on private repos
    "SCM-055",  # write-side branch-restriction kinds
})


def _platform_skip_note(snapshot_platform: str, rule_id: str) -> str | None:
    """Return a "not applicable on PLATFORM" note when ``rule_id`` is
    platform-locked and the snapshot is from a different platform.
    Returns ``None`` when the rule applies to the snapshot's platform
    and should run normally.
    """
    if rule_id in _GITHUB_ONLY_IDS and snapshot_platform != "github":
        return (
            f"Rule is GitHub-specific (relies on the "
            f"``security_and_analysis`` block or a GitHub-only "
            f"protection knob); skipped on the "
            f"{snapshot_platform} snapshot."
        )
    if rule_id in _GITLAB_ONLY_IDS and snapshot_platform != "gitlab":
        return (
            f"Rule is GitLab-specific (reads GitLab push-rule / "
            f"merge-request settings); skipped on the "
            f"{snapshot_platform} snapshot."
        )
    if rule_id in _BITBUCKET_ONLY_IDS and snapshot_platform != "bitbucket":
        return (
            f"Rule is Bitbucket-specific (reads Bitbucket Cloud "
            f"repo settings); skipped on the {snapshot_platform} "
            f"snapshot."
        )
    return None


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
                skip = _platform_skip_note(snapshot.platform, rule.id)
                if skip is not None:
                    finding = Finding(
                        check_id=rule.id,
                        title=rule.title,
                        severity=rule.severity,
                        resource=repo_resource(snapshot),
                        description=skip,
                        recommendation=rule.recommendation, passed=True,
                    )
                else:
                    finding = check_fn(snapshot)
                apply_rule_metadata(finding, rule)
                findings.append(finding)
        return findings
