"""SCM-026. Webhook ships events insecurely (HTTP / no-TLS / no-secret)."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    SCMRepoSnapshot,
    archived_state_label,
    github_only_skip,
    repo_resource,
)

RULE = Rule(
    id="SCM-026",
    title="Webhook ships events insecurely (HTTP / no-TLS / no-secret)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6", "CICD-SEC-10"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-319", "CWE-345"),
    recommendation=(
        "For each flagged webhook, fix all three knobs at once "
        "(Settings → Webhooks → <hook> → Edit):\n\n"
        "* Switch the Payload URL to ``https://`` and enable "
        "``Verify SSL`` (the field is labeled ``SSL "
        "verification`` on the form; setting it to "
        "``Enable SSL verification`` is the safe value).\n"
        "* Set the ``Secret`` field to a long random value and "
        "validate the incoming ``X-Hub-Signature-256`` header on "
        "the receiving end. Without the secret + verification, an "
        "attacker who learns the URL (URLs are not secrets; they "
        "appear in receiving-system logs, in CI screenshots, in "
        "support tickets) can forge events.\n\n"
        "If the receiving service genuinely cannot handle HTTPS "
        "or shared secrets, terminate TLS at a reverse proxy in "
        "front of the receiver and keep the public-facing URL "
        "``https://`` with a real cert. The webhook content "
        "carries the full event payload — pull requests with "
        "diff content, push events with the commits, secret "
        "scanning alerts — which is exactly what an unauthenticated "
        "MITM is looking for."
    ),
    docs_note=(
        "Reads ``GET /repos/{owner}/{repo}/hooks`` and flags any "
        "active webhook with one or more failure modes:\n\n"
        "* ``config.url`` starts with ``http://`` — push payloads "
        "  including code diffs leak over plain HTTP\n"
        "* ``config.insecure_ssl == \"1\"`` — TLS certificate "
        "  verification disabled, MITM possible on the HTTPS "
        "  endpoint\n"
        "* ``config.secret`` is null / missing — no HMAC "
        "  signature, so anyone who learns the URL can forge "
        "  events into the receiver\n\n"
        "Inactive webhooks (``active: false``) are skipped — "
        "they don't fire. Each finding's description lists every "
        "failure mode hit so the operator sees the full fix "
        "scope per webhook. Requires admin scope; without it the "
        "endpoint returns 403 / 404 and the rule passes silently. "
        "GitHub never returns the actual secret value via the API; "
        "the slot reports either ``\"********\"`` (configured) or "
        "``null`` (missing), so this rule detects the absence "
        "without ever handling the credential itself."
    ),
    known_fp=(
        "Long-running internal-only webhooks pointing at a "
        "hostname only resolvable inside a private network "
        "(``http://internal.svc/hook``) often skip TLS by "
        "convention. The right fix is still to terminate TLS at "
        "an ingress and use a non-empty secret; the rule does "
        "not have visibility into network topology and cannot "
        "distinguish 'public HTTP' from 'private-network HTTP', "
        "so it errs toward flagging. Suppress per webhook id "
        "with a rationale that names the receiving service.",
    ),
    incident_refs=(
        "Long-running pattern of webhook payloads leaking via "
        "plain-HTTP receivers (Zapier, IFTTT, custom legacy "
        "endpoints) — the GitHub repo's commit-diff content, "
        "pull-request body, and secret-scanning alert payloads "
        "all land on the wire unencrypted. Public catalogs of "
        "compromised internal webhooks document the receiver-"
        "side breach where the URL alone was enough to inject "
        "forged events when no shared secret was configured.",
    ),
)


def _classify(hook: dict[str, Any]) -> list[str]:
    """Return the list of failure-mode labels for *hook*, empty when
    the hook is secure across all checks."""
    config = hook.get("config")
    if not isinstance(config, dict):
        return ["malformed config block"]
    issues: list[str] = []
    url = config.get("url")
    if isinstance(url, str) and url.lower().startswith("http://"):
        issues.append("plain-HTTP URL")
    insecure = config.get("insecure_ssl")
    # GitHub returns the value as a string "0" / "1". Be permissive
    # in case future API versions switch to int / bool.
    if insecure in ("1", 1, True, "true"):
        issues.append("insecure_ssl=1 (TLS verify disabled)")
    secret = config.get("secret")
    if not secret:
        # ``None`` / empty string / missing — all mean no HMAC.
        # The configured value is masked as ``"********"`` when set,
        # which is truthy and so doesn't trip this branch.
        issues.append("no shared secret (no HMAC verification)")
    return issues


def check(snapshot: SCMRepoSnapshot) -> Finding:
    skip = github_only_skip(snapshot)
    if skip is not None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=skip,
            recommendation=RULE.recommendation, passed=True,
        )
    if label := archived_state_label(snapshot):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                f"Repo is {label}; webhooks check skipped."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    hooks = snapshot.webhooks
    if hooks is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description=(
                "repos/hooks endpoint unavailable (token likely "
                "lacks ``admin`` scope on the repo)."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    if not hooks:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=repo_resource(snapshot),
            description="No webhooks configured.",
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    for hook in hooks:
        # Skip disabled hooks — they don't fire and can't leak
        # payloads. Operator hygiene says to delete them eventually,
        # but the rule isn't the right place to argue that.
        if hook.get("active") is False:
            continue
        issues = _classify(hook)
        if not issues:
            continue
        hook_id = hook.get("id")
        # ``name`` on GitHub webhooks is always "web" (the type);
        # the URL is the human-readable handle.
        config = hook.get("config") if isinstance(hook.get("config"), dict) else {}
        url = config.get("url") if isinstance(config, dict) else None
        label = url if isinstance(url, str) and url else (
            f"hook:{hook_id}" if isinstance(hook_id, int) else "(unnamed hook)"
        )
        offenders.append(f"{label}: {'; '.join(issues)}")
    passed = not offenders
    desc = (
        f"All {len(hooks)} webhook(s) ship events securely "
        "(HTTPS, TLS-verified, HMAC-signed)."
        if passed else
        f"{len(offenders)} webhook(s) ship events insecurely: "
        f"{'; '.join(offenders[:3])}"
        f"{' (+ more)' if len(offenders) > 3 else ''}. Push "
        f"payloads include diff content; the URL alone is not a "
        f"secret."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=repo_resource(snapshot), description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
