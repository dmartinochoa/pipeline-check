"""ARGOCD-007. Helm valueFiles / parameters interpolate generator output without goTemplate."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    ArgoCDContext,
    application_sources,
    iter_applications,
    iter_applicationsets,
)

RULE = Rule(
    id="ARGOCD-007",
    title="Argo CD Helm parameters interpolate generator output without goTemplate",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4", "CICD-SEC-1"),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-94",),
    recommendation=(
        "Set ``spec.goTemplate: true`` on the ApplicationSet (with "
        "``goTemplateOptions: ['missingkey=error']``) so generator "
        "placeholders go through Go's template engine, which "
        "respects YAML quoting. Without it, Argo CD's default "
        "``fasttemplate`` substitution is a literal string-splice, "
        "so a generator-controlled value containing newlines, "
        "shell metacharacters, or YAML structural characters lands "
        "verbatim in the rendered Helm values."
    ),
    docs_note=(
        "Walks ``spec.template.spec.source.helm.valueFiles[]`` and "
        "``parameters[].value`` on ApplicationSets, plus the "
        "single-Application equivalent. Fires when the value "
        "contains a ``{{...}}`` placeholder and the enclosing "
        "ApplicationSet doesn't set ``spec.goTemplate: true``. "
        "Single-Application Helm sources are checked too: a "
        "placeholder there always indicates an upstream "
        "ApplicationSet so the same flag must be set."
    ),
    exploit_example=(
        "# Vulnerable: branch name flows verbatim into valueFiles.\n"
        "apiVersion: argoproj.io/v1alpha1\n"
        "kind: ApplicationSet\n"
        "metadata: { name: previews, namespace: argocd }\n"
        "spec:\n"
        "  # no goTemplate: true\n"
        "  generators:\n"
        "    - pullRequest: { github: { owner: example-corp, repo: app } }\n"
        "  template:\n"
        "    spec:\n"
        "      source:\n"
        "        helm:\n"
        "          valueFiles:\n"
        "            - values-{{branch}}.yaml\n"
        "          parameters:\n"
        "            - { name: image.tag, value: '{{branch}}' }\n"
        "\n"
        "# Safer: goTemplate true makes the templating engine YAML-\n"
        "# aware and respects per-field quoting.\n"
        "spec:\n"
        "  goTemplate: true\n"
        "  goTemplateOptions: ['missingkey=error']"
    ),
)


_PLACEHOLDER_RE = re.compile(r"\{\{[^}]+\}\}")


def _go_template_on(appset_spec: dict) -> bool:
    return appset_spec.get("goTemplate") is True


def _scan_source(src: dict) -> list[str]:
    helm = src.get("helm") if isinstance(src, dict) else None
    if not isinstance(helm, dict):
        return []
    hits: list[str] = []
    files = helm.get("valueFiles")
    if isinstance(files, list):
        for f in files:
            if isinstance(f, str) and _PLACEHOLDER_RE.search(f):
                hits.append(f"valueFiles: {f}")
    params = helm.get("parameters")
    if isinstance(params, list):
        for p in params:
            if not isinstance(p, dict):
                continue
            name = p.get("name", "")
            value = p.get("value")
            if isinstance(value, str) and _PLACEHOLDER_RE.search(value):
                hits.append(f"parameters.{name}: {value}")
    return hits


def check(ctx: ArgoCDContext) -> Finding:
    offenders: list[str] = []
    appsets = list(iter_applicationsets(ctx))
    apps = list(iter_applications(ctx))
    for aset in appsets:
        spec = aset.data.get("spec") or {}
        if not isinstance(spec, dict):
            continue
        if _go_template_on(spec):
            continue
        for src in application_sources(aset):
            for h in _scan_source(src):
                offenders.append(f"{aset.display}: {h}")
    for app in apps:
        for src in application_sources(app):
            for h in _scan_source(src):
                offenders.append(f"{app.display}: {h}")
    if not appsets and not apps:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argocd",
            description="No Argo CD Application / ApplicationSet documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "No unquoted generator placeholders in Helm values."
        if passed else
        f"{len(offenders)} placeholder(s) flowing into Helm values without goTemplate: "
        f"{'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argocd", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
