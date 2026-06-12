"""ORG-010. New org repos default to secret scanning without push protection."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMOrgContext, org_resource

_PUSH = "secret_scanning_push_protection_enabled_for_new_repositories"
_SCAN = "secret_scanning_enabled_for_new_repositories"

RULE = Rule(
    id="ORG-010",
    title="New repositories default to secret scanning without push protection",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-798",),
    recommendation=(
        "Turn on ``Automatically enable for new repositories`` for secret "
        "scanning push protection (Org Settings -> Code security -> Secret "
        "protection / Push protection). The organization already enables "
        "secret scanning by default for new repos (the detect step), but "
        "without push protection (the prevent step) every new repo starts "
        "out catching credentials only after they land in git history, where "
        "rotation is the only fix. Enabling the push-protection default "
        "refuses the push before the secret is ever committed. The per-repo "
        "analog is SCM-015."
    ),
    docs_note=(
        "Reads ``secret_scanning_enabled_for_new_repositories`` and "
        "``secret_scanning_push_protection_enabled_for_new_repositories`` "
        "from ``GET /orgs/{org}`` (the same fetch ORG-001 / ORG-002 use) and "
        "fires only when scanning is on for new repos but push protection is "
        "not, the org-default half-adoption. When scanning itself is off for "
        "new repos the rule passes (the push-protection default is then moot, "
        "and the field is plan-dependent), so an org without GitHub Advanced "
        "Security never produces a false finding. When the fields are absent "
        "(low scope / no security features) the rule passes with a note. The "
        "org-default analog of SCM-015 (per-repo push protection off)."
    ),
)


def check(ctx: SCMOrgContext) -> Finding:
    meta = ctx.org_meta
    if not isinstance(meta, dict):
        return RULE.pass_finding(
            org_resource(ctx),
            "Organization settings were not available (see warnings); the "
            "new-repository security defaults could not be read.",
        )
    if _PUSH not in meta:
        return RULE.pass_finding(
            org_resource(ctx),
            "The token cannot read the organization's new-repository "
            "push-protection default (needs ``admin:org`` and the security "
            "features); not evaluated.",
        )
    if meta.get(_SCAN) is not True:
        return RULE.pass_finding(
            org_resource(ctx),
            f"Organization ``{ctx.org}`` does not enable secret scanning by "
            "default for new repositories, so the push-protection default is "
            "not evaluated here (enable scanning first).",
        )
    if meta.get(_PUSH) is True:
        return RULE.pass_finding(
            org_resource(ctx),
            f"Organization ``{ctx.org}`` enables both secret scanning and "
            "push protection by default for new repositories.",
        )
    return RULE.fail_finding(
        org_resource(ctx),
        f"Organization ``{ctx.org}`` enables secret scanning for new "
        "repositories but not push protection: every new repo catches "
        "credentials only after they reach git history, where rotation is "
        "the only fix. Enable the push-protection default to refuse the push "
        "first.",
    )
