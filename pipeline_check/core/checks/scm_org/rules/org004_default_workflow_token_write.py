"""ORG-004. The org default workflow token is read-write, not read-only."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import SCMOrgContext, org_resource

RULE = Rule(
    id="ORG-004",
    title="Organization default workflow token grants write permissions",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-250",),
    recommendation=(
        "Set the organization's default ``GITHUB_TOKEN`` permissions to "
        "read-only (Org Settings -> Actions -> Workflow permissions -> "
        "``Read repository contents and packages permissions``). A "
        "``write`` default hands every workflow in every repo a token that "
        "can push code, publish packages, and edit releases unless a "
        "workflow narrows it with a ``permissions:`` block, so a script "
        "injection or a compromised action escalates straight to repo "
        "write. Grant write back per-workflow / per-job where it's needed."
    ),
    docs_note=(
        "Reads ``default_workflow_permissions`` from "
        "``GET /orgs/{org}/actions/permissions/workflow`` and fires when it "
        "is ``write``. ``read`` passes. The endpoint needs a token with the "
        "``actions`` / org-admin scope; when unavailable the rule passes "
        "with a note. This is the org-wide default; individual workflows "
        "can still scope the token down (or up) with a ``permissions:`` "
        "block, which the per-workflow GHA rules evaluate."
    ),
)


def check(ctx: SCMOrgContext) -> Finding:
    perms = ctx.actions_workflow_permissions
    if not isinstance(perms, dict):
        return RULE.pass_finding(
            org_resource(ctx),
            "The organization's default workflow-permission setting was not "
            "available (needs a token with the ``actions`` / org-admin "
            "scope); not evaluated.",
        )
    default = perms.get("default_workflow_permissions")
    if default != "write":
        shown = default if isinstance(default, str) else "read"
        return RULE.pass_finding(
            org_resource(ctx),
            f"Organization ``{ctx.org}`` default workflow token is "
            f"``{shown}`` (least privilege; write is granted per workflow).",
        )
    return RULE.fail_finding(
        org_resource(ctx),
        f"Organization ``{ctx.org}`` grants every workflow a read-write "
        "``GITHUB_TOKEN`` by default: a script injection or compromised "
        "action escalates to repo write unless each workflow narrows it. "
        "Default the org token to read-only and grant write per workflow.",
    )
