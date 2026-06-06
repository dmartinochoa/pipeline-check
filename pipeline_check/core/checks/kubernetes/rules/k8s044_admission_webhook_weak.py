"""K8S-044. Admission webhook fails open or mutates cluster-wide unscoped."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import KubernetesContext, manifest_location

_WEBHOOK_KINDS = frozenset({
    "MutatingWebhookConfiguration", "ValidatingWebhookConfiguration",
})

RULE = Rule(
    id="K8S-044",
    title="Admission webhook fails open or mutates cluster-wide unscoped",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-PRIV-BUILD",),
    cwe=("CWE-693", "CWE-862"),
    recommendation=(
        "Set ``failurePolicy: Fail`` on any admission webhook that "
        "enforces a security control (a policy engine like OPA "
        "Gatekeeper / Kyverno, a sidecar injector), so an attacker can't "
        "disable it cluster-wide by knocking the backend offline. Scope "
        "a ``MutatingWebhookConfiguration`` with a ``namespaceSelector`` "
        "and/or ``objectSelector`` (and the narrowest ``rules``) so it "
        "cannot rewrite every pod in the cluster: an unscoped mutating "
        "webhook over ``pods`` is a tenant-escape primitive (inject a "
        "sidecar, add ``hostPID``, mount the host). Restrict who can "
        "create ``admissionregistration.k8s.io`` objects via RBAC."
    ),
    docs_note=(
        "Fires on a ``MutatingWebhookConfiguration`` / "
        "``ValidatingWebhookConfiguration`` whose webhook either (a) sets "
        "``failurePolicy: Ignore`` while its ``rules`` match a broad "
        "target (``pods`` / ``*`` resources or ``*`` apiGroups), so "
        "DoSing or deleting the backend silently disables the admission "
        "control cluster-wide (the ``v1`` default is ``Fail``; ``Ignore`` "
        "is an explicit opt-out), or (b) is a *mutating* webhook with no "
        "``namespaceSelector`` and no ``objectSelector`` and broad "
        "``rules``, so whoever controls the backend can rewrite every "
        "pod spec in the cluster. RBAC rules (K8S-020 / 021) reason about "
        "who can call the API; admission webhooks intercept every call "
        "regardless of RBAC, and no other rule reads "
        "``admissionregistration.k8s.io`` objects."
    ),
    known_fp=(
        "A non-security, best-effort webhook (a label / annotation "
        "decorator) may legitimately run ``failurePolicy: Ignore`` to "
        "favor availability; the rule still flags it when its rules are "
        "broad. A cluster-wide mutating injector (a service mesh) is "
        "sometimes intentional; scope it with a selector or suppress with "
        "a rationale once the backend's trust is established.",
    ),
    exploit_example=(
        "# Vulnerable: a policy webhook fails open on a broad rule, and a\n"
        "# separate mutating webhook rewrites every pod unscoped.\n"
        "apiVersion: admissionregistration.k8s.io/v1\n"
        "kind: ValidatingWebhookConfiguration\n"
        "metadata: { name: policy-guard }\n"
        "webhooks:\n"
        "  - name: guard.example.com\n"
        "    failurePolicy: Ignore          # <- DoS the backend = no policy\n"
        "    rules:\n"
        "      - apiGroups: [\"\"]\n"
        "        apiVersions: [\"v1\"]\n"
        "        operations: [CREATE]\n"
        "        resources: [pods]\n"
        "\n"
        "# Attack: an attacker floods / deletes the webhook backend, then\n"
        "# creates a privileged pod the policy would have rejected; the\n"
        "# fail-open webhook waves it through. Or, with an unscoped\n"
        "# MutatingWebhookConfiguration over pods, whoever owns the\n"
        "# backend injects a sidecar / hostPID into every pod cluster-wide.\n"
        "\n"
        "# Safe: fail closed and scope the mutation to one namespace.\n"
        "kind: ValidatingWebhookConfiguration\n"
        "webhooks:\n"
        "  - name: guard.example.com\n"
        "    failurePolicy: Fail\n"
        "    namespaceSelector:\n"
        "      matchLabels: { policy: enforced }\n"
        "    rules:\n"
        "      - apiGroups: [\"\"]\n"
        "        apiVersions: [\"v1\"]\n"
        "        operations: [CREATE]\n"
        "        resources: [pods]"
    ),
)


def _broad_rules(webhook: dict[str, Any]) -> bool:
    rules = webhook.get("rules")
    if not isinstance(rules, list):
        return False
    for r in rules:
        if not isinstance(r, dict):
            continue
        groups = r.get("apiGroups")
        if isinstance(groups, list) and "*" in groups:
            return True
        resources = r.get("resources")
        if isinstance(resources, list):
            for res in resources:
                if not isinstance(res, str):
                    continue
                base = res.split("/", 1)[0]
                if base in ("*", "pods"):
                    return True
    return False


def _empty_selector(sel: Any) -> bool:
    """True when a webhook selector matches everything (absent or empty)."""
    if sel is None:
        return True
    if isinstance(sel, dict):
        match = sel.get("matchLabels")
        expr = sel.get("matchExpressions")
        return not match and not expr
    return False


def check(ctx: KubernetesContext) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for m in ctx.manifests:
        if m.kind not in _WEBHOOK_KINDS:
            continue
        mutating = m.kind == "MutatingWebhookConfiguration"
        webhooks = m.data.get("webhooks")
        if not isinstance(webhooks, list):
            continue
        for wh in webhooks:
            if not isinstance(wh, dict):
                continue
            name = wh.get("name") if isinstance(wh.get("name"), str) else "?"
            broad = _broad_rules(wh)
            if wh.get("failurePolicy") == "Ignore" and broad:
                offenders.append(
                    f"{m.display}: webhook {name} failurePolicy=Ignore "
                    f"on a broad rule (fail-open bypass)"
                )
                locations.append(manifest_location(m, wh))
            elif (
                mutating and broad
                and _empty_selector(wh.get("namespaceSelector"))
                and _empty_selector(wh.get("objectSelector"))
            ):
                offenders.append(
                    f"{m.display}: webhook {name} mutates cluster-wide "
                    f"with no namespace/object selector"
                )
                locations.append(manifest_location(m, wh))
    passed = not offenders
    desc = (
        "No admission webhook fails open on a broad rule or mutates "
        "cluster-wide unscoped."
        if passed else
        f"{len(offenders)} admission webhook(s) weaken cluster admission "
        f"control: {'; '.join(offenders[:3])}"
        f"{' ...' if len(offenders) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests", description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
