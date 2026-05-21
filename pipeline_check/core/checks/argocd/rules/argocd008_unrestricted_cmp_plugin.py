"""ARGOCD-008. Application invokes a config-management plugin (CMP)."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    ArgoCDContext,
    application_sources,
    iter_applications,
    iter_applicationsets,
)

RULE = Rule(
    id="ARGOCD-008",
    title="Argo CD Application invokes a config-management plugin",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-3", "CICD-SEC-4"),
    esf=("ESF-S-VERIFY-DEPS",),
    cwe=("CWE-94",),
    recommendation=(
        "CMPs are arbitrary code: Argo CD execs ``generate.command`` "
        "inside the repo-server pod at every sync, with whatever "
        "manifest content the source repo ships. Audit the CMP's "
        "``discover.find.command`` allowlist, confirm "
        "``generate.command`` doesn't shell out to user-controlled "
        "input, and treat each plugin invocation as a build-step "
        "review item, not a Kustomize / Helm equivalent."
    ),
    docs_note=(
        "Walks ``spec.source.plugin`` on every Application and "
        "ApplicationSet template. Fires whenever the field is set "
        "with a non-empty ``name``. Helm and Kustomize sources are "
        "ignored (they're separately covered by ARGOCD-007 / future "
        "Kustomize rules). This is a deliberate noisy-but-correct "
        "v1, suppress per-Application once you've reviewed the CMP."
    ),
)


def _scan_source(src: dict, app_label: str) -> list[str]:
    plugin = src.get("plugin")
    if not isinstance(plugin, dict):
        return []
    name = plugin.get("name")
    if not isinstance(name, str) or not name.strip():
        return [f"{app_label}: plugin (unnamed)"]
    return [f"{app_label}: plugin {name!r}"]


def check(ctx: ArgoCDContext) -> Finding:
    offenders: list[str] = []
    apps = list(iter_applications(ctx))
    appsets = list(iter_applicationsets(ctx))
    for app in apps:
        for src in application_sources(app):
            offenders.extend(_scan_source(src, app.display))
    for aset in appsets:
        for src in application_sources(aset):
            offenders.extend(_scan_source(src, aset.display))
    if not apps and not appsets:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource="argocd",
            description="No Argo CD Application / ApplicationSet documents to check.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "No CMP plugin invocations in Application sources."
        if passed else
        f"{len(offenders)} CMP plugin invocation(s): "
        f"{'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="argocd", description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
