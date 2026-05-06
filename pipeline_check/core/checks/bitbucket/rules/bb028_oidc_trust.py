"""BB-028 — `oidc: true` step without deployment-gated environment."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_steps


def _is_oidc_step(step: dict[str, Any]) -> bool:
    """Return True if *step* opts into Bitbucket's OIDC token issuance.

    Bitbucket exposes a single ``oidc: true`` boolean at step scope;
    no other shape requests the JWT, so this is a one-key check.
    """
    return step.get("oidc") is True


RULE = Rule(
    id="BB-028",
    title="OIDC step without deployment-gated environment",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-2",),
    cwe=("CWE-284",),
    recommendation=(
        "Every step that sets ``oidc: true`` must also declare a "
        "``deployment:`` (production / staging / test). Bitbucket "
        "deployments enforce manual approvals, restricted variables, "
        "and audit logs that an ungated step bypasses. Steps reached "
        "through ``pull-requests:`` should never request OIDC tokens — "
        "any forked PR can drive the role assumption."
    ),
    docs_note=(
        "Pairs with IAM-008 — IAM-008 verifies the cloud-side trust "
        "policy pins audience + subject; this rule verifies the "
        "Bitbucket-side workflow can't request a token without a "
        "deployment gate. Bitbucket's ``pull-requests:`` triggers from "
        "forks so OIDC under that branch is always an unbounded "
        "blast radius."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for loc, step in iter_steps(doc):
        if not _is_oidc_step(step):
            continue
        # ``pull-requests:`` is unconditionally unsafe: forked PRs can
        # drive the assume-role with no deployment gate available.
        if loc.startswith("pull-requests"):
            offenders.append(f"{loc}: oidc step under pull-requests (forked PRs)")
            continue
        if "deployment" not in step:
            offenders.append(f"{loc}: oidc step without deployment:")
    passed = not offenders
    desc = (
        "Every ``oidc: true`` step is bound to a deployment environment "
        "and lives outside the ``pull-requests:`` block."
        if passed else
        f"OIDC scoping is incomplete: {'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Without a deployment "
        f"gate (or with the step exposed to forked PRs), any branch "
        f"push can drive a federated assume-role on the consumer side."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
