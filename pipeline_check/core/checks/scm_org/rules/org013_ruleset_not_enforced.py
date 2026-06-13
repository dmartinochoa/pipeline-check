"""ORG-013. An organization ruleset is in evaluate / disabled mode."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMOrgContext, org_resource

RULE = Rule(
    id="ORG-013",
    title="Organization ruleset is in evaluate / disabled mode (not enforced)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1", "CICD-SEC-5"),
    cwe=("CWE-693", "CWE-269"),
    recommendation=(
        "Flip every non-enforcing organization ruleset to "
        "``enforcement: active`` (Org Settings -> Repository -> Rulesets -> "
        "<name> -> Enforcement status -> Active). An org-level ruleset "
        "applies branch / tag / push governance across every repository the "
        "ruleset targets, so a single ruleset left in ``evaluate`` (preview, "
        "runs the rule logic but never blocks) or ``disabled`` (explicit "
        "off) leaves all of those repos with the audit appearance of "
        "org-wide governance and the behavior of none. Operators commonly "
        "create a ruleset in ``evaluate`` to preview its effect and forget "
        "to promote it."
    ),
    docs_note=(
        "Walks ``GET /orgs/{org}/rulesets`` and flags every entry whose "
        "``enforcement`` is anything other than ``\"active\"`` "
        "(``evaluate`` = dry-run, ``disabled`` = explicit off). Passes when "
        "no org rulesets are configured (``[]``). Needs a token with the "
        "``admin:org`` scope; when the endpoint is unavailable the rule "
        "passes with a note. The org-level analog of SCM-029."
    ),
    known_fp=(
        "A freshly-authored org ruleset legitimately sits in ``evaluate`` "
        "mode for a short audit window before promotion to ``active``. "
        "Suppress for that specific ruleset id with a calendar-bound "
        "rationale; the rule keeps flagging until the promotion lands so the "
        "transition window doesn't quietly become permanent.",
    ),
)


def _offenders(rulesets: list[Any]) -> list[str]:
    """Labels for rulesets whose ``enforcement`` is not ``active``."""
    out: list[str] = []
    for rs in rulesets:
        if not isinstance(rs, dict):
            continue
        enforcement = rs.get("enforcement")
        if enforcement == "active":
            continue
        name = rs.get("name")
        rs_id = rs.get("id")
        label = name if isinstance(name, str) and name else (
            f"ruleset:{rs_id}" if isinstance(rs_id, int) else "(unnamed)"
        )
        mode = enforcement if isinstance(enforcement, str) else "unknown"
        out.append(f"{label} ({mode})")
    return out


def check(ctx: SCMOrgContext) -> Finding:
    rulesets = ctx.org_rulesets
    if not isinstance(rulesets, list):
        return RULE.pass_finding(
            org_resource(ctx),
            "The organization's rulesets were not available (needs a token "
            "with the ``admin:org`` scope); not evaluated.",
        )
    if not rulesets:
        return RULE.pass_finding(
            org_resource(ctx),
            f"Organization ``{ctx.org}`` has no org-level rulesets "
            "configured (per-repo rulesets / branch protection carry the "
            "governance load).",
        )
    offenders = _offenders(rulesets)
    if not offenders:
        return RULE.pass_finding(
            org_resource(ctx),
            f"All {len(rulesets)} organization ruleset(s) are actively "
            "enforced.",
        )
    sample = ", ".join(offenders[:5])
    if len(offenders) > 5:
        sample += f", ... (+{len(offenders) - 5} more)"
    return RULE.fail_finding(
        org_resource(ctx),
        f"Organization ``{ctx.org}`` has {len(offenders)} ruleset(s) not "
        f"actively enforced: {sample}. The ruleset's rules run but do not "
        "block (evaluate) or do not run at all (disabled) across every repo "
        "they target: governance documented, not enforced.",
    )
