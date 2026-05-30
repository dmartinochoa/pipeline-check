"""ARGOCD-018. argocd-cm ships custom resource health / action Lua."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import ArgoCDContext, argocd_cm

RULE = Rule(
    id="ARGOCD-018",
    title="argocd-cm ships custom resource health / action Lua",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-4",),
    esf=("ESF-C-LEAST-PRIV",),
    cwe=("CWE-94", "CWE-829"),
    recommendation=(
        "Treat every ``resource.customizations`` Lua block in "
        "``argocd-cm`` as code that runs inside the Argo CD "
        "application controller. Health-check and resource-action "
        "Lua is evaluated by the controller against live cluster "
        "objects on every reconcile, so a malicious or buggy script "
        "runs with the controller's broad read (and, for actions, "
        "mutate) access to managed resources. Review each script, "
        "keep them minimal and side-effect-free (health scripts "
        "should only read ``obj`` and return a status; actions "
        "should be narrowly scoped), gate changes to ``argocd-cm`` "
        "behind the same review as RBAC changes, and prefer the "
        "built-in health checks where they suffice. Anyone who can "
        "edit ``argocd-cm`` can ship controller-side code, so the "
        "ConfigMap's write access is part of this rule's threat "
        "model."
    ),
    docs_note=(
        "Fires when ``argocd-cm`` carries one or more "
        "``resource.customizations`` keys with a non-empty value, "
        "either the per-resource form "
        "(``resource.customizations.health.<group_kind>``, "
        "``resource.customizations.actions.<group_kind>``) or the "
        "legacy aggregate ``resource.customizations`` block whose "
        "value embeds ``health.lua`` / ``actions`` entries.\n\n"
        "This is a posture / visibility signal (MEDIUM), not proof "
        "of compromise: custom health and action Lua is a normal, "
        "useful Argo CD feature. The rule surfaces the "
        "controller-side execution surface so a reviewer can confirm "
        "each script is trusted, minimal, and (for actions) "
        "narrowly scoped."
    ),
    known_fp=(
        "Many production Argo CD instances legitimately define "
        "custom health checks for CRDs the built-ins don't cover. "
        "The rule fires on their presence; suppress per instance "
        "with a rationale once the scripts are reviewed, or scope "
        "the suppression to the specific resource keys.",
    ),
    incident_refs=(
        "Controller-side code-execution surface: resource-action Lua "
        "can patch managed objects, and health Lua runs against live "
        "cluster state on every reconcile, so an over-broad or "
        "attacker-supplied script in argocd-cm executes with the "
        "Argo CD controller's cluster access.",
    ),
    exploit_example=(
        "# Vulnerable: a resource action that patches arbitrary objects.\n"
        "apiVersion: v1\n"
        "kind: ConfigMap\n"
        "metadata:\n"
        "  name: argocd-cm\n"
        "data:\n"
        "  resource.customizations.actions.apps_Deployment: |\n"
        "    discovery.lua: |\n"
        "      actions = {}\n"
        "      actions[\"backdoor\"] = {}\n"
        "      return actions\n"
        "    definitions:\n"
        "    - name: backdoor\n"
        "      action.lua: |\n"
        "        obj.spec.template.spec.containers[1].image = \"evil:latest\"\n"
        "        return obj\n"
        "\n"
        "# Attack: anyone who can edit argocd-cm ships controller-side\n"
        "# Lua. The action mutates managed Deployments (swap the\n"
        "# image, add a sidecar) with the controller's access; a\n"
        "# health script runs against live objects every reconcile.\n"
        "\n"
        "# Safe: drop custom Lua where a built-in health check works;\n"
        "# review and narrowly scope any that remain, and gate\n"
        "# argocd-cm edits behind RBAC-level review.\n"
    ),
)


def check(ctx: ArgoCDContext) -> Finding:
    cm = argocd_cm(ctx)
    if cm is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argocd",
            description="No argocd-cm ConfigMap to check.",
            recommendation="No action required.", passed=True,
        )
    data = cm.data.get("data") or {}
    if not isinstance(data, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argocd",
            description="argocd-cm has no data map.",
            recommendation="No action required.", passed=True,
        )
    offenders: list[str] = []
    for key, value in data.items():
        if not isinstance(key, str):
            continue
        if not key.startswith("resource.customizations"):
            continue
        # Aggregate key only counts when its value actually carries Lua.
        if key == "resource.customizations":
            text = value if isinstance(value, str) else ""
            if "health.lua" not in text and "actions" not in text:
                continue
        elif not (isinstance(value, str) and value.strip()):
            continue
        offenders.append(key)
    passed = not offenders
    if passed:
        desc = "argocd-cm ships no custom resource health / action Lua."
    else:
        desc = (
            f"argocd-cm defines {len(offenders)} custom "
            f"resource.customizations Lua block(s): "
            f"{', '.join(offenders[:5])}"
            f"{'…' if len(offenders) > 5 else ''}. Each runs inside "
            f"the Argo CD controller against live cluster objects; "
            f"confirm every script is trusted and narrowly scoped."
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argocd", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
