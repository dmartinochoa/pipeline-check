"""GLGRP-005. A group webhook delivers events over insecure transport."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import GitLabGroupContext, group_resource


def _transport_issues(hook: dict[str, Any]) -> list[str]:
    """Insecure-transport failure labels for *hook*, empty when secure.

    Scoped to transport only (plain-HTTP URL, TLS verification disabled).
    GitLab's group hooks endpoint does not report whether a webhook secret
    token is configured, so, like the org-level ORG-011, this rule does not
    flag a missing secret (that would false-positive).
    """
    issues: list[str] = []
    url = hook.get("url")
    if isinstance(url, str) and url.lower().startswith("http://"):
        issues.append("plain-HTTP URL")
        # An http:// endpoint has no TLS to verify, so the ssl flag is moot
        # there; only report it for an https endpoint.
        return issues
    ssl = hook.get("enable_ssl_verification")
    if ssl is False or (isinstance(ssl, str) and ssl.lower() == "false"):
        issues.append("SSL verification disabled")
    return issues


RULE = Rule(
    id="GLGRP-005",
    title="GitLab group webhook delivers events over insecure transport",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6", "CICD-SEC-10"),
    cwe=("CWE-319",),
    recommendation=(
        "For each flagged group webhook (Group Settings -> Webhooks -> "
        "edit), switch the URL to ``https://`` and enable ``SSL "
        "verification``. A group webhook fires on events across every "
        "project in the group, so its payloads carry merge-request diffs, "
        "push commits, and pipeline / security content for the whole group. "
        "Over plain HTTP (or HTTPS with verification disabled) a network "
        "attacker between GitLab and the receiver reads all of it and can "
        "tamper with deliveries. Also set a ``Secret token`` and validate "
        "the ``X-Gitlab-Token`` header on the receiver. The GitHub-org "
        "analog is ORG-011; the per-project analog is SCM-026."
    ),
    docs_note=(
        "Reads ``GET /groups/{group}/hooks`` and fires on any webhook whose "
        "``url`` starts with ``http://`` or whose "
        "``enable_ssl_verification`` is ``false`` (an https endpoint with "
        "TLS verification off). Scoped to transport security: unlike the "
        "per-project SCM-026 it does not flag a missing secret token, "
        "because the group hooks endpoint does not report secret presence. "
        "Needs a token with ``read_api`` and Owner access to the group; "
        "when the endpoint is unavailable the rule passes with a note "
        "rather than firing on absence."
    ),
)


def check(ctx: GitLabGroupContext) -> Finding:
    hooks = ctx.group_hooks
    if not isinstance(hooks, list):
        return RULE.pass_finding(
            group_resource(ctx),
            "The group's webhooks were not available (needs a token with "
            "``read_api`` and Owner access to the group); not evaluated.",
        )
    offenders: list[str] = []
    for hook in hooks:
        if not isinstance(hook, dict):
            continue
        issues = _transport_issues(hook)
        if not issues:
            continue
        url = hook.get("url")
        label = url if isinstance(url, str) and url else f"hook #{hook.get('id')}"
        offenders.append(f"{label} ({', '.join(issues)})")
    if not offenders:
        return RULE.pass_finding(
            group_resource(ctx),
            f"Group ``{ctx.group}`` has no webhook delivering over insecure "
            "transport.",
        )
    sample = "; ".join(offenders[:5])
    if len(offenders) > 5:
        sample += f"; ... (+{len(offenders) - 5} more)"
    return RULE.fail_finding(
        group_resource(ctx),
        f"Group ``{ctx.group}`` has {len(offenders)} webhook(s) delivering "
        f"events over insecure transport: {sample}. Group-wide event "
        "payloads (MR diffs, push commits, pipeline content) are exposed to "
        "a network attacker; use ``https://`` with SSL verification enabled.",
    )
