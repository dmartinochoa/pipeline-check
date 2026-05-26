"""SCM-049. Scanner token is a classic PAT instead of a fine-grained token."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    SCMRepoSnapshot,
    github_only_skip,
    repo_resource,
)

RULE = Rule(
    id="SCM-049",
    title="Classic PAT used where a fine-grained token suffices",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-2",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-269",),
    recommendation=(
        "Replace the classic personal access token (``ghp_`` prefix) "
        "with a fine-grained PAT (``github_pat_`` prefix). Fine-"
        "grained tokens restrict scope to named repos, carry "
        "per-permission grants, support expiration policies, and "
        "have a distinct audit-log shape. Classic PATs implicitly "
        "carry org-wide scope for every granted permission and "
        "cannot be restricted to individual repos.\n\n"
        "Generate a fine-grained token at "
        "``github.com/settings/personal-access-tokens/new`` and "
        "select only the repos and permissions the scanner needs "
        "(typically ``repo`` read + ``admin:org`` read for SCM "
        "posture scans)."
    ),
    docs_note=(
        "Inspects the prefix of the ``$GITHUB_TOKEN`` (or "
        "``--scm-token``) used for the SCM scan. ``ghp_`` indicates "
        "a classic PAT; ``github_pat_`` indicates a fine-grained "
        "PAT. Classic tokens carry org-wide scope and cannot be "
        "restricted to individual repos, which violates the "
        "principle of least privilege.\n\n"
        "The rule passes silently when no token is provided or when "
        "the token is a GitHub App installation token (``ghs_`` / "
        "``ghr_``), which already carries scoped permissions."
    ),
    known_fp=(
        "Some organizations have not yet adopted fine-grained PATs "
        "because of feature-parity gaps (e.g., some GraphQL "
        "endpoints require classic tokens). Suppress with a "
        "rationale documenting the specific API gap.",
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
    tt = snapshot.token_type
    if tt is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description="No authentication token provided; check skipped.",
            recommendation=RULE.recommendation, passed=True,
        )
    if tt != "classic":
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                f"Token type is '{tt}', not a classic PAT."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot),
        description=(
            "The scanner token is a classic PAT (``ghp_`` prefix). "
            "Classic tokens carry org-wide scope for every granted "
            "permission and cannot be restricted to individual repos. "
            "Switch to a fine-grained PAT (``github_pat_`` prefix) "
            "to enforce repo-level and permission-level least privilege."
        ),
        recommendation=RULE.recommendation, passed=False,
    )
