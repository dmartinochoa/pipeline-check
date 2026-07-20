"""SCM-055. Bitbucket repo has no branch-restriction kinds on its main branch.

This rule is the Bitbucket-specific analog of SCM-001: while SCM-001
treats any branch-restriction entry on the default branch as enough
to pass, SCM-055 audits the *shape* of the restrictions, catching the
common Bitbucket misconfiguration where someone configures
``require_approvals_to_merge`` but forgets the ``push`` /
``force`` / ``delete`` kinds, leaving the branch effectively unguarded
for direct writes.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    SCMRepoSnapshot,
    bitbucket_only_skip,
    default_branch_name,
    repo_resource,
)

#: Bitbucket Cloud branch-restriction kinds. The ``push`` /
#: ``force`` / ``delete`` triad enforces who can write to a branch;
#: the ``require_*`` kinds enforce *what* a merge must satisfy. SCM-055
#: scopes to the write-side triad — without at least one of those,
#: an admin can push past every other restriction directly.
_WRITE_KINDS: frozenset[str] = frozenset({
    "push",
    "force",
    "delete",
})

RULE = Rule(
    id="SCM-055",
    title="Bitbucket default branch has no write-side restriction kinds",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-1",),
    esf=("ESF-S-CHANGE-CONTROL",),
    cwe=("CWE-732",),
    recommendation=(
        "On the repo Settings -> Branch restrictions panel, add at "
        "least one write-side restriction (``Prevent push`` / "
        "``Prevent force push`` / ``Prevent deletion``) on the "
        "default branch in addition to any merge-side checks "
        "(``Require approvals``, ``Require passing builds``). "
        "Without a ``push``-kind restriction, branch admins can "
        "still push directly to the default branch, bypassing the "
        "PR-and-approve flow that the merge-side checks gate. The "
        "common misconfiguration is to add ``Require N approvals "
        "to merge`` but no ``Prevent push``, which means PRs are "
        "well-gated but direct pushes are unrestricted."
    ),
    docs_note=(
        "Reads the branch-restrictions list from "
        "``GET /2.0/repositories/{ws}/{repo}/branch-restrictions`` "
        "(populated by the universal SCM-001 path) and inspects "
        "the restrictions on the default branch. Fires when no "
        "restriction of kind ``push`` / ``force`` / ``delete`` is "
        "present, even if other merge-side restrictions exist. "
        "SCM-001 ensures *some* restriction is present; SCM-055 "
        "ensures the right *kind* is present.\n\n"
        "Reads the raw payload via ``repo_meta._bitbucket_repo`` "
        "for the default-branch name and the universal-rules "
        "``default_branch_protection`` slot for the presence "
        "signal."
    ),
    known_fp=(
        "Some workspaces gate writes entirely via workspace-level "
        "user-group permissions rather than per-branch "
        "restrictions; in that case the branch-restrictions list "
        "is intentionally empty of write-side kinds and the "
        "control is enforced one layer up. Suppress per-repo with "
        "a rationale naming the workspace-level enforcement.",
    ),
    incident_refs=(
        "Bitbucket admin-push bypass: a repo with ``require_"
        "approvals_to_merge=2`` and ``require_passing_builds_to_"
        "merge`` but no ``push``-kind restriction. A repo admin "
        "with stolen credentials pushes a malicious commit "
        "directly to main, bypassing both merge-side gates "
        "because the gates only apply to PRs.",
    ),
    exploit_example=(
        "# Vulnerable: branch restrictions cover merge-side but\n"
        "# not write-side.\n"
        "GET /2.0/repositories/myworkspace/myrepo/branch-restrictions\n"
        "{\n"
        "  \"values\": [\n"
        "    {\"kind\": \"require_approvals_to_merge\",\n"
        "     \"value\": 2, \"pattern\": \"main\"},\n"
        "    {\"kind\": \"require_passing_builds_to_merge\",\n"
        "     \"pattern\": \"main\"}\n"
        "  ]\n"
        "}\n"
        "\n"
        "# Attack: an admin with stolen credentials runs\n"
        "# ``git push origin main``. The push isn't a PR so the\n"
        "# merge-side gates don't apply; no ``push``-kind\n"
        "# restriction exists; the commit lands directly.\n"
        "\n"
        "# Safe: add a ``push``-kind restriction\n"
        "# (``Prevent push`` in the UI) with an empty allowlist\n"
        "# of users / groups so only the merge path can land\n"
        "# changes on main."
    ),
)


def check(snapshot: SCMRepoSnapshot) -> Finding:
    if skip := bitbucket_only_skip(snapshot):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=skip,
            recommendation=RULE.recommendation, passed=True,
        )
    branch = default_branch_name(snapshot)
    protection = snapshot.default_branch_protection
    if not isinstance(protection, dict):
        # SCM-001 already fires when no protection exists at all; we
        # pass silently to avoid cascading from a single root cause.
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                f"Default branch ``{branch}`` has no branch "
                f"restrictions at all. See SCM-001."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    # The ``push`` kind (Bitbucket's "Prevent push" / Write-access
    # restriction) is the primary write-side control but has no
    # GitHub-shaped slot; the hydrator surfaces it via the raw
    # ``_bitbucket_restriction_kinds`` list. ``force`` / ``delete`` do
    # have normalized slots (``allow_force_pushes`` / ``allow_deletions``
    # set to ``enabled: False`` when the restriction is present).
    raw_kinds = protection.get("_bitbucket_restriction_kinds")
    push_restricted = (
        isinstance(raw_kinds, list) and "push" in raw_kinds
    )
    allow_force: Any = protection.get("allow_force_pushes")
    allow_delete: Any = protection.get("allow_deletions")
    force_restricted = (
        isinstance(allow_force, dict)
        and allow_force.get("enabled") is False
    )
    delete_restricted = (
        isinstance(allow_delete, dict)
        and allow_delete.get("enabled") is False
    )
    has_write_kind = push_restricted or force_restricted or delete_restricted
    passed = has_write_kind
    if passed:
        kinds = []
        if push_restricted:
            kinds.append("push")
        if force_restricted:
            kinds.append("force")
        if delete_restricted:
            kinds.append("delete")
        desc = (
            f"Default branch ``{branch}`` has write-side "
            f"restriction kind(s): {', '.join(kinds)}."
        )
    else:
        desc = (
            f"Default branch ``{branch}`` has only merge-side "
            f"restrictions, no write-side (``push`` / ``force`` / "
            f"``delete``) restriction kind. An admin can push "
            f"directly to the branch, bypassing the merge gates."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
