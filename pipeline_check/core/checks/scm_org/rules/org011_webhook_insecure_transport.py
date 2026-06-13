"""ORG-011. An org webhook delivers events over insecure transport."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMOrgContext, org_resource


def _transport_issues(hook: dict[str, Any]) -> list[str]:
    """Insecure-transport failure labels for *hook*, empty when secure.

    Scoped to transport only (plain-HTTP URL, TLS verification disabled).
    The HMAC-secret check the per-repo SCM-026 does is deliberately left
    out here: ``GET /orgs/{org}/hooks`` does not reliably return whether a
    secret is configured, so flagging its absence would false-positive.
    """
    config = hook.get("config")
    if not isinstance(config, dict):
        return []
    issues: list[str] = []
    url = config.get("url")
    if isinstance(url, str) and url.lower().startswith("http://"):
        issues.append("plain-HTTP URL")
    # GitHub returns ``insecure_ssl`` as the string "0" / "1"; be permissive
    # in case a future API version switches to int / bool.
    if config.get("insecure_ssl") in ("1", 1, True, "true"):
        issues.append("insecure_ssl=1 (TLS verification disabled)")
    return issues


RULE = Rule(
    id="ORG-011",
    title="Organization webhook delivers events over insecure transport",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6", "CICD-SEC-10"),
    cwe=("CWE-319",),
    recommendation=(
        "For each flagged organization webhook (Org Settings -> Webhooks -> "
        "edit), switch the Payload URL to ``https://`` and set SSL "
        "verification to ``Enable SSL verification``. An org-level webhook "
        "fires on events across every repository, so its payloads carry pull "
        "request diffs, push commits, and security-alert content for the "
        "whole org. Over plain HTTP (or HTTPS with verification disabled) a "
        "network attacker between GitHub and the receiver reads all of it, "
        "and can tamper with deliveries. Also set a strong ``Secret`` and "
        "validate the ``X-Hub-Signature-256`` header on the receiver."
    ),
    docs_note=(
        "Reads ``GET /orgs/{org}/hooks`` and fires on any active webhook "
        "whose ``config.url`` starts with ``http://`` or whose "
        "``config.insecure_ssl`` is ``\"1\"`` (TLS verification off). "
        "Inactive hooks (``active: false``) are skipped. Scoped to transport "
        "security: unlike the per-repo SCM-026 it does not flag a missing "
        "HMAC secret, because the org hooks endpoint does not reliably report "
        "secret presence. Needs a token with the ``admin:org_hook`` / "
        "``admin:org`` scope; when the endpoint is unavailable the rule "
        "passes with a note. The org-level analog of SCM-026."
    ),
)


def check(ctx: SCMOrgContext) -> Finding:
    hooks = ctx.org_hooks
    if not isinstance(hooks, list):
        return RULE.pass_finding(
            org_resource(ctx),
            "The organization's webhooks were not available (needs a token "
            "with the ``admin:org_hook`` / ``admin:org`` scope); not "
            "evaluated.",
        )
    offenders: list[str] = []
    for hook in hooks:
        if not isinstance(hook, dict) or hook.get("active") is False:
            continue
        issues = _transport_issues(hook)
        if not issues:
            continue
        config = hook.get("config")
        url = config.get("url") if isinstance(config, dict) else None
        label = url if isinstance(url, str) and url else f"hook #{hook.get('id')}"
        offenders.append(f"{label} ({', '.join(issues)})")
    if not offenders:
        return RULE.pass_finding(
            org_resource(ctx),
            f"Organization ``{ctx.org}`` has no webhook delivering over "
            "insecure transport.",
        )
    sample = "; ".join(offenders[:5])
    if len(offenders) > 5:
        sample += f"; ... (+{len(offenders) - 5} more)"
    return RULE.fail_finding(
        org_resource(ctx),
        f"Organization ``{ctx.org}`` has {len(offenders)} webhook(s) "
        f"delivering events over insecure transport: {sample}. Org-wide "
        "event payloads (PR diffs, push commits, security alerts) are "
        "exposed to a network attacker; use ``https://`` with SSL "
        "verification enabled.",
    )
