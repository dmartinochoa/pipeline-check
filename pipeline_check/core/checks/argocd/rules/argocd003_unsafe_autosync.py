"""ARGOCD-003. Application auto-sync with prune but no self-heal guardrail."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import ArgoCDContext, iter_applications

RULE = Rule(
    id="ARGOCD-003",
    title="Argo CD Application auto-sync prunes without selfHeal guardrail",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-O-DEPLOY-CONTROL",),
    cwe=("CWE-732",),
    recommendation=(
        "If you enable ``syncPolicy.automated.prune: true`` (auto-"
        "deletes resources that disappear from git), enable "
        "``selfHeal: true`` alongside it so any out-of-band hotfix "
        "is detected and reconciled rather than silently kept. The "
        "common failure mode is an oncall hand-applies a fix in a "
        "fire, then Argo CD prunes it on the next auto-sync because "
        "the change isn't in git, recreating the incident."
    ),
    docs_note=(
        "Walks ``spec.syncPolicy.automated`` on every Application. "
        "Fires when ``prune: true`` is set and ``selfHeal`` is either "
        "missing or explicitly ``false``. Auto-sync without prune is "
        "ignored, the failure mode this rule tracks is the prune-"
        "without-detect combination."
    ),
    exploit_example=(
        "# Risky: an out-of-band hotfix gets silently pruned on the\n"
        "# next sync because no selfHeal flags the drift.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: Application\n"
        "metadata: { name: payments, namespace: argocd }\n"
        "spec:\n"
        "  syncPolicy:\n"
        "    automated:\n"
        "      prune: true\n"
        "      # no selfHeal\n"
        "\n"
        "# Safer: selfHeal forces the controller to detect and\n"
        "# reconcile any out-of-band changes so the prune behavior is\n"
        "# at least visible in the sync history before it bites.\n"
        "spec:\n"
        "  syncPolicy:\n"
        "    automated:\n"
        "      prune: true\n"
        "      selfHeal: true"
    ),
)


def check(ctx: ArgoCDContext) -> Finding:
    offenders: list[str] = []
    apps = list(iter_applications(ctx))
    for app in apps:
        spec = app.data.get("spec") or {}
        if not isinstance(spec, dict):
            continue
        sync_policy = spec.get("syncPolicy")
        if not isinstance(sync_policy, dict):
            continue
        automated = sync_policy.get("automated")
        if not isinstance(automated, dict):
            continue
        if automated.get("prune") is True and automated.get("selfHeal") is not True:
            offenders.append(f"{app.display}: prune=true without selfHeal=true")
    if not apps:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argocd",
            description="No Argo CD Application documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "No auto-sync Application prunes without selfHeal."
        if passed else
        f"{len(offenders)} Application(s) auto-prune without selfHeal: "
        f"{'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argocd", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
