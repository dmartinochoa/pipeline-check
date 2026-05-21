"""BB-028, `oidc: true` step without deployment-gated environment."""
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
        "through ``pull-requests:`` should never request OIDC tokens, "
        "any forked PR can drive the role assumption."
    ),
    docs_note=(
        "Pairs with IAM-008. IAM-008 verifies the cloud-side trust "
        "policy pins audience + subject; this rule verifies the "
        "Bitbucket-side workflow can't request a token without a "
        "deployment gate. Bitbucket's ``pull-requests:`` triggers from "
        "forks so OIDC under that branch is always an unbounded "
        "blast radius."
    ),
    exploit_example=(
        "# Vulnerable: an OIDC step (``oidc: true``) runs on every\n"
        "# trigger, including pull-request builds. The OIDC role's\n"
        "# trust policy accepts any token from the repo, so a\n"
        "# fork-PR build assumes prod and runs whatever the role\n"
        "# permits.\n"
        "pipelines:\n"
        "  default:\n"
        "    - step:\n"
        "        oidc: true\n"
        "        script:\n"
        "          - aws configure set role_arn arn:aws:iam::123:role/prod\n"
        "          - aws deploy ...\n"
        "\n"
        "# Safe: route the OIDC step through a deployment-gated\n"
        "# environment (Bitbucket Deployments) so reviewer\n"
        "# approval is required before the token is minted, and\n"
        "# restrict the trigger to the protected branch.\n"
        "pipelines:\n"
        "  branches:\n"
        "    main:\n"
        "      - step:\n"
        "          oidc: true\n"
        "          deployment: production   # reviewer-gated\n"
        "          script:\n"
        "            - aws configure set role_arn arn:aws:iam::123:role/prod\n"
        "            - aws deploy ..."
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
