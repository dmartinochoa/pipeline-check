"""GLGRP-006. A group CI/CD variable holds a secret with a weak control."""
from __future__ import annotations

from typing import Any

from ..._secrets import find_secret_values
from ...base import Finding, Severity
from ...rule import Rule
from ..base import GitLabGroupContext, group_resource


def _weaknesses(var: dict[str, Any]) -> list[str]:
    """Weak-control labels for *var*, empty when both controls are on.

    Only an explicit ``False`` counts as a weakness: a missing flag (an
    older GitLab / a limited response) is treated as "can't tell", not as
    insecure, so the rule never fires on absence.
    """
    issues: list[str] = []
    if var.get("protected") is False:
        issues.append(
            "not protected (readable by a pipeline on any branch / MR in any "
            "project in the group, including feature branches and fork MRs "
            "where fork pipelines are enabled)"
        )
    if var.get("masked") is False:
        issues.append("not masked (printed in cleartext in job logs)")
    return issues


RULE = Rule(
    id="GLGRP-006",
    title="GitLab group CI/CD variable exposes a secret with a weak control",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    cwe=("CWE-522",),
    recommendation=(
        "For each flagged group CI/CD variable (Group Settings -> CI/CD -> "
        "Variables), turn on both ``Protect variable`` and ``Mask "
        "variable`` (or ``Masked and hidden`` on newer GitLab). A group "
        "variable is inherited by every project in the group, so its blast "
        "radius is the whole group, not one project. Without ``Protected`` "
        "it is handed to pipelines on every branch and merge request, so a "
        "feature-branch push (or a fork MR where fork pipelines run) can "
        "print or use the credential; without ``Masked`` it appears in "
        "cleartext in any job log. Prefer scoping a real secret to the "
        "single project that needs it, or to a protected environment, and "
        "rotate any credential that has been exposed this way. The "
        "per-project / in-YAML analogs are GL-003 and GL-008."
    ),
    docs_note=(
        "Reads ``GET /groups/{group}/variables`` and fires on a variable "
        "whose value matches a known credential shape (the shared "
        "``find_secret_values`` catalog: PATs, cloud keys, provider tokens, "
        "PEM blocks) AND that is ``protected: false`` or ``masked: false``. "
        "The value-shape gate is what keeps this low-FP: an ordinary "
        "unprotected config variable (a URL, a flag, a region) is not "
        "flagged, only an actual secret with a weakened control. The token "
        "body is never echoed, only its detector label. A fully protected "
        "and masked secret passes. This is the group-API surface the static "
        "``.gitlab-ci.yml`` rules (GL-003 / GL-008) cannot see; needs a "
        "token with ``read_api`` and Owner / Maintainer access, and passes "
        "with a note when the endpoint is unavailable."
    ),
)


def check(ctx: GitLabGroupContext) -> Finding:
    variables = ctx.group_variables
    if not isinstance(variables, list):
        return RULE.pass_finding(
            group_resource(ctx),
            "The group's CI/CD variables were not available (needs a token "
            "with ``read_api`` and Owner / Maintainer access to the group); "
            "not evaluated.",
        )
    offenders: list[str] = []
    for var in variables:
        if not isinstance(var, dict):
            continue
        value = var.get("value")
        if not isinstance(value, str) or not value.strip():
            continue
        hits = find_secret_values([value])
        if not hits:
            continue
        weaknesses = _weaknesses(var)
        if not weaknesses:
            continue
        key = var.get("key") or "<unnamed>"
        # ``hits`` are already redacted ("<detector>:<redacted>"); take the
        # detector label only so the offender line names the secret type
        # without echoing any of the value.
        detectors = sorted({h.split(":", 1)[0] for h in hits})
        offenders.append(
            f"{key} ({', '.join(detectors)}; {', '.join(weaknesses)})"
        )
    if not offenders:
        return RULE.pass_finding(
            group_resource(ctx),
            f"Group ``{ctx.group}`` has no CI/CD variable exposing a secret "
            "with a weak control.",
        )
    sample = "; ".join(offenders[:5])
    if len(offenders) > 5:
        sample += f"; ... (+{len(offenders) - 5} more)"
    return RULE.fail_finding(
        group_resource(ctx),
        f"Group ``{ctx.group}`` has {len(offenders)} CI/CD variable(s) that "
        f"hold a secret with a weak control: {sample}. A group variable "
        "reaches every project in the group; protect and mask it, or scope "
        "the credential to the single project / environment that needs it.",
    )
