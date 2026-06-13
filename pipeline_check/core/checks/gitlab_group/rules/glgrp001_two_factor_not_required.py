"""GLGRP-001. The GitLab group does not require two-factor authentication."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import GitLabGroupContext, group_resource

RULE = Rule(
    id="GLGRP-001",
    title="GitLab group does not require two-factor authentication",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-308",),
    recommendation=(
        "Turn on ``Require all users in this group to set up two-factor "
        "authentication`` (Group Settings -> General -> Permissions and "
        "group features). Without it, a single phished or reused member "
        "password is enough to push to the group's projects, approve merge "
        "requests, or run pipelines as that member. Enabling the requirement "
        "starts a grace period after which members without 2FA lose access, "
        "so set ``two_factor_grace_period`` and notify the group first. The "
        "GitHub-org analog is ORG-001."
    ),
    docs_note=(
        "Reads ``require_two_factor_authentication`` from "
        "``GET /groups/{group}``. Fires when it is ``false``. The field is "
        "only returned to a token with Owner access to the group "
        "(``read_api``); when it is absent the rule passes with an "
        "'unavailable' note rather than guessing, so a low-scope token never "
        "produces a false finding. Group-wide 2FA is the single "
        "highest-leverage account-takeover control."
    ),
)


def check(ctx: GitLabGroupContext) -> Finding:
    meta = ctx.group_meta
    if not isinstance(meta, dict):
        return RULE.pass_finding(
            group_resource(ctx),
            "Group settings were not available (see warnings); the "
            "two-factor requirement could not be read.",
        )
    if "require_two_factor_authentication" not in meta:
        return RULE.pass_finding(
            group_resource(ctx),
            "The token cannot read the group's two-factor requirement "
            "(needs Owner access / ``read_api``); not evaluated.",
        )
    if meta.get("require_two_factor_authentication") is True:
        return RULE.pass_finding(
            group_resource(ctx),
            f"Group ``{ctx.group}`` requires two-factor authentication for "
            "all members.",
        )
    return RULE.fail_finding(
        group_resource(ctx),
        f"Group ``{ctx.group}`` does not require two-factor authentication: "
        "a single compromised member password can push code, approve merge "
        "requests, or run pipelines as that member.",
    )
