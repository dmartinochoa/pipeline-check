"""ARGO-017. `resource` template applies a manifest built from a parameter."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import ArgoContext, iter_templates, template_name

# Argo `resource` template actions that REALIZE a state change by handing
# the rendered manifest to `kubectl`. `get` is read-only; `delete` takes a
# name/selector rather than a full manifest body, so neither is the sink.
_MUTATING_ACTIONS = frozenset({"create", "apply", "patch", "replace"})

# Argo substitutes these tokens into the manifest TEXT before kubectl
# applies it. Any occurrence in the manifest body is dangerous: unlike a
# shell sink (ARGO-005), quoting gives no protection here because the sink
# is the YAML object structure itself, so a crafted parameter injects whole
# fields or entire objects (a privileged Pod, a cluster-admin RoleBinding).
# Covers the plain ``{{ inputs.parameters.X }}`` form, the expr-template
# ``{{= inputs.parameters.X }}`` form, and bracket access
# ``parameters['X']`` / ``item['k']`` -- all reach the same text sink.
_PARAM_TOKEN_RE = re.compile(
    r"\{\{=?\s*(?:inputs|workflow|item)\.parameters?"
    r"(?:\.[A-Za-z0-9_-]+|\s*\[[^\]]+\])+\s*\}\}"
    r"|\{\{=?\s*item(?:\.[A-Za-z0-9_-]+|\s*\[[^\]]+\])*\s*\}\}"
)

RULE = Rule(
    id="ARGO-017",
    title="Argo resource template applies a manifest built from an untrusted parameter",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-4", "CICD-SEC-2"),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-94", "CWE-77"),
    recommendation=(
        "Don't interpolate `{{inputs.parameters.X}}` / "
        "`{{workflow.parameters.X}}` / `{{item}}` into a `resource` "
        "template's `manifest:` when `action:` is `create` / `apply` / "
        "`patch` / `replace`. Argo substitutes the value into the "
        "manifest text before `kubectl` applies it, so a parameter "
        "carrying YAML injects arbitrary fields or whole objects, applied "
        "by the workflow's ServiceAccount. Build the object from a fixed "
        "template and pass only scalar leaf values through `kubectl` "
        "field args, restrict who can set the parameter, and scope the "
        "ServiceAccount's RBAC to the exact objects the workflow needs."
    ),
    docs_note=(
        "Fires when a `resource` template with `action: create` / "
        "`apply` / `patch` / `replace` has an inline `manifest:` string "
        "containing a `{{...parameters...}}` or `{{item...}}` token. The "
        "manifest is K8s-object injection, not shell injection, so it "
        "fires regardless of quoting (ARGO-005's quoting carve-out does "
        "not apply) and `iter_containers` never visits `resource` "
        "templates, so no other rule sees this sink. A caller who can set "
        "the parameter (a webhook / Sensor, or anyone with Submit on the "
        "template) creates attacker-chosen objects, e.g. a privileged Pod "
        "or a cluster-admin binding, under the workflow's SA."
    ),
    exploit_example=(
        "# Vulnerable: a resource template applies a manifest whose body\n"
        "# is built from a caller-supplied parameter.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: WorkflowTemplate\n"
        "metadata: { name: provision }\n"
        "spec:\n"
        "  entrypoint: apply\n"
        "  templates:\n"
        "    - name: apply\n"
        "      inputs: { parameters: [ { name: spec } ] }\n"
        "      resource:\n"
        "        action: apply\n"
        "        manifest: |\n"
        "          apiVersion: v1\n"
        "          kind: ConfigMap\n"
        "          metadata: { name: cfg }\n"
        "          data:\n"
        "            payload: {{inputs.parameters.spec}}\n"
        "\n"
        "# Attack: the caller sets `spec` to a value that closes the\n"
        "# ConfigMap and appends a second document, e.g.\n"
        "#   x }\\n---\\napiVersion: rbac.authorization.k8s.io/v1\\n"
        "#   kind: ClusterRoleBinding ... roleRef: cluster-admin ...\n"
        "# Argo splices it into the manifest text before `kubectl apply`,\n"
        "# so the workflow's ServiceAccount creates the attacker's\n"
        "# cluster-admin binding. No shell metacharacters are needed.\n"
        "\n"
        "# Safe: keep the object fixed; pass only a scalar leaf via a\n"
        "# kubectl field arg or an env-substituted, schema-validated value.\n"
        "      resource:\n"
        "        action: apply\n"
        "        setOwnerReference: true\n"
        "        manifest: |\n"
        "          apiVersion: v1\n"
        "          kind: ConfigMap\n"
        "          metadata: { name: cfg }\n"
        "          data: { payload: fixed-value }"
    ),
)


def check(ctx: ArgoContext) -> Finding:
    if not ctx.docs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argo",
            description="No Argo documents to check.",
            recommendation="No action required.", passed=True,
        )
    offenders: list[str] = []
    # Per-template anchor (``<Kind>/<name>:<template>``) so a future
    # reachability chain can intersect with ARGO-002/005's anchors.
    anchor_templates: dict[str, None] = {}
    for doc in ctx.docs:
        for idx, tmpl in enumerate(iter_templates(doc)):
            resource = tmpl.get("resource")
            if not isinstance(resource, dict):
                continue
            action = resource.get("action")
            if not (isinstance(action, str) and action.lower() in _MUTATING_ACTIONS):
                continue
            manifest = resource.get("manifest")
            if not isinstance(manifest, str):
                # ``manifestFrom`` (an artifact / configmap ref) can't be
                # inspected statically; only the inline string is a sink.
                continue
            m = _PARAM_TOKEN_RE.search(manifest)
            if m:
                tname = template_name(tmpl, idx)
                offenders.append(
                    f"{doc.kind}/{doc.name} {tname} "
                    f"({action}): {m.group(0)}"
                )
                anchor_templates[f"{doc.kind}/{doc.name}:{tname}"] = None
    passed = not offenders
    desc = (
        "No resource template applies a parameter-built manifest."
        if passed else
        f"{len(offenders)} resource template(s) apply a manifest built "
        f"from an untrusted parameter: {'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A caller who sets the "
        f"parameter injects arbitrary K8s objects, applied by the "
        f"workflow's ServiceAccount."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argo", description=desc,
        recommendation=RULE.recommendation, passed=passed,
        job_anchors=tuple(anchor_templates),
    )
