"""ARGOCD-019. Application disables drift detection on a sensitive field."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import ArgoCDContext, iter_applications, iter_applicationsets

# Tokens that mark an ``ignoreDifferences`` path as security-relevant. If
# the controller stops reconciling one of these, an out-of-band edit to a
# privileged field (an image swap, an RBAC widening, a securityContext
# relaxation) persists in the live cluster while Argo CD reports the app
# Synced / Healthy. Matched case-insensitively against the path strings
# (``jsonPointers`` / ``jqPathExpressions``) and the entry's ``kind``.
_SENSITIVE_TOKENS = (
    "image", "securitycontext", "rules", "subjects", "roleref",
    "clusterrole", "role", "env", "command", "args", "privileged",
    "hostpath", "hostnetwork", "hostpid", "serviceaccount",
    "automount", "capabilities", "runasuser", "allowprivilege",
)

RULE = Rule(
    id="ARGOCD-019",
    title="Argo CD Application disables drift detection on a sensitive field",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-5",),
    esf=("ESF-C-LEAST-PRIV",),
    cwe=("CWE-1059", "CWE-778"),
    recommendation=(
        "Don't add ``spec.ignoreDifferences`` on a security-relevant "
        "field (a container ``image``, a Role/ClusterRole ``rules``, a "
        "RoleBinding ``subjects`` / ``roleRef``, a ``securityContext``), "
        "and don't set ``syncPolicy.syncOptions: [Validate=false]``. Both "
        "tell Argo CD to stop enforcing the field's desired state, so an "
        "attacker who edits the live object out of band (or lands a drift "
        "the controller now ignores) keeps the change while the dashboard "
        "stays Synced / Healthy. If a field is genuinely controller-owned "
        "(an HPA-managed replica count, a webhook-injected annotation), "
        "scope the ``ignoreDifferences`` entry to exactly that "
        "non-security field and document why."
    ),
    docs_note=(
        "Fires when an Application (or ApplicationSet template) sets "
        "``syncPolicy.syncOptions`` to include ``Validate=false`` (server-"
        "side schema validation off, cluster-wide for that app), or "
        "carries a ``spec.ignoreDifferences`` entry whose "
        "``jsonPointers`` / ``jqPathExpressions`` / ``kind`` references a "
        "security-relevant field (image, RBAC rules / subjects / roleRef, "
        "securityContext, host namespaces, service account, capabilities). "
        "A non-security ``ignoreDifferences`` (a replica count, a "
        "webhook-injected annotation) does not fire, to keep the false-"
        "positive rate low. Distinct from ARGOCD-003 (auto-sync prune / "
        "selfHeal, a reliability guardrail) and ARGOCD-010 / 017 (mutable "
        "source ref): those reason about the input; this flags the "
        "controller being told to ignore what it deploys."
    ),
    known_fp=(
        "``ignoreDifferences`` legitimately suppresses controller-owned "
        "drift (HPA replica counts, cert-manager-injected CA bundles, "
        "webhook defaults). Those paths don't carry the sensitive tokens "
        "this rule matches, so they pass. If a sensitive-looking path is "
        "genuinely benign in your setup, suppress per Application with a "
        "rationale.",
    ),
    exploit_example=(
        "# Vulnerable: the app tells Argo CD to stop reconciling the\n"
        "# Deployment's container image, then someone edits the live\n"
        "# image out of band. Argo CD never corrects it and keeps\n"
        "# reporting Synced.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: Application\n"
        "metadata: { name: payments, namespace: argocd }\n"
        "spec:\n"
        "  source: { repoURL: https://github.com/example/payments, path: k8s, targetRevision: v1.4.2 }\n"
        "  destination: { server: https://kubernetes.default.svc, namespace: payments }\n"
        "  ignoreDifferences:\n"
        "    - group: apps\n"
        "      kind: Deployment\n"
        "      jsonPointers:\n"
        "        - /spec/template/spec/containers/0/image\n"
        "  syncPolicy:\n"
        "    syncOptions: [Validate=false]\n"
        "\n"
        "# Attack: an attacker with cluster access (or a compromised\n"
        "# admission path) swaps the live image to a backdoored tag.\n"
        "# Argo CD's diff ignores the image field, so it never reverts and\n"
        "# the UI shows green: stealth persistence sanctioned by GitOps.\n"
        "\n"
        "# Safe: let Argo CD reconcile the image; scope ignoreDifferences\n"
        "# to a genuinely controller-owned field only (or drop it).\n"
        "spec:\n"
        "  syncPolicy:\n"
        "    automated: { selfHeal: true }"
    ),
)


def _app_spec(doc: Any) -> dict[str, Any] | None:
    """Return the effective spec (ApplicationSet nests it under template)."""
    if doc.kind == "ApplicationSet":
        tmpl = (doc.data.get("spec") or {}).get("template") or {}
        spec = tmpl.get("spec") if isinstance(tmpl, dict) else None
    else:
        spec = doc.data.get("spec")
    return spec if isinstance(spec, dict) else None


def _validate_off(spec: dict[str, Any]) -> bool:
    sp = spec.get("syncPolicy")
    if not isinstance(sp, dict):
        return False
    opts = sp.get("syncOptions")
    if not isinstance(opts, list):
        return False
    return any(
        isinstance(o, str) and o.replace(" ", "").lower() == "validate=false"
        for o in opts
    )


def _sensitive_ignore(spec: dict[str, Any]) -> bool:
    entries = spec.get("ignoreDifferences")
    if not isinstance(entries, list):
        return False
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        blob = ""
        for key in ("jsonPointers", "jqPathExpressions"):
            v = entry.get(key)
            if isinstance(v, list):
                blob += " ".join(str(x) for x in v)
        kind = entry.get("kind")
        if isinstance(kind, str):
            blob += " " + kind
        lowered = blob.lower()
        if any(tok in lowered for tok in _SENSITIVE_TOKENS):
            return True
    return False


def check(ctx: ArgoCDContext) -> Finding:
    apps = list(iter_applications(ctx)) + list(iter_applicationsets(ctx))
    if not apps:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="(no Applications)",
            description=(
                "No Argo CD Application / ApplicationSet documents in "
                "scope; nothing to audit."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    for app in apps:
        spec = _app_spec(app)
        if spec is None:
            continue
        if _validate_off(spec):
            offenders.append(f"{app.display}: syncOptions Validate=false")
        if _sensitive_ignore(spec):
            offenders.append(
                f"{app.display}: ignoreDifferences on a security-relevant field"
            )
    passed = not offenders
    desc = (
        "No Application disables drift detection on a sensitive field."
        if passed else
        f"{len(offenders)} Application setting(s) stop the controller "
        f"enforcing desired state: {'; '.join(offenders[:3])}"
        f"{' ...' if len(offenders) > 3 else ''}. Out-of-band drift on "
        f"the ignored field persists while Argo CD reports Synced."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=apps[0].display, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
