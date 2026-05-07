"""Adapter that runs loaded custom rules through a provider's context.

The Scanner appends one ``CustomRulesCheck`` (built by
:func:`make_custom_rules_check`) to a provider's check-class list at
construction time. From the orchestrator's point of view, custom
rules look like just another check — same ``BaseCheck`` shape, same
:class:`Finding` output, no special plumbing in reporting / scoring /
SARIF / `--explain`.

Provider-specific iteration lives here, not in the loader, because
the per-context shape (``ctx.workflows`` vs ``ctx.pipelines`` vs
``ctx.manifests``) is incidental to the YAML rule and shouldn't leak
into the user's authoring surface.
"""
from __future__ import annotations

from typing import Any

from ..base import BaseCheck, Finding
from .loader import (
    CompiledCustomRule,
    LoadedCustomRules,
    make_kubernetes_check,
    make_yaml_provider_check,
)

# Providers whose rules iterate per-document (one Finding per
# (rule, document) pair). The context exposes a list of objects each
# with ``.path`` and ``.data``.
_YAML_PROVIDERS_DOC_LIST_ATTR: dict[str, str] = {
    "github":     "workflows",
    "gitlab":     "pipelines",
    "bitbucket":  "pipelines",
    "azure":      "pipelines",
    "circleci":   "pipelines",
    "cloudbuild": "pipelines",
}


def make_custom_rules_check(
    provider_name: str,
    loaded: LoadedCustomRules,
) -> type[BaseCheck]:
    """Return a BaseCheck subclass that runs every custom rule for *provider_name*.

    The returned class captures *provider_name* and the rules list in
    its closure, so the Scanner can construct it with the standard
    ``check_class(context, target=...)`` signature without provider-
    specific kwargs.
    """
    compiled_rules: list[CompiledCustomRule] = list(
        loaded.by_provider.get(provider_name, []),
    )
    doc_attr: str | None = _YAML_PROVIDERS_DOC_LIST_ATTR.get(provider_name)

    class CustomRulesCheck(BaseCheck):
        """Run every loaded custom rule for one provider."""

        # Class name surfaces in the verbose log line ("running
        # CustomRulesCheck..."); keep it descriptive but generic.
        PROVIDER = provider_name

        def __init__(self, ctx: Any, target: str | None = None) -> None:
            super().__init__(context=ctx, target=target)
            self.ctx = ctx

        def run(self) -> list[Finding]:
            findings: list[Finding] = []
            if not compiled_rules:
                return findings
            if provider_name == "kubernetes":
                # The K8s adapter walks the whole context and rolls
                # offenders across every manifest into one Finding,
                # matching the built-in K8s rule shape.
                for compiled in compiled_rules:
                    k8s_fn = make_kubernetes_check(compiled)
                    finding = k8s_fn(self.ctx)
                    finding.cwe = list(compiled.rule.cwe)
                    findings.append(finding)
                return findings
            if doc_attr is None:
                # Provider isn't in the YAML-doc-list set and isn't K8s.
                # Should not happen — the loader's ALLOWED_PROVIDERS
                # mirrors this set — but failing closed beats crashing.
                return findings
            docs = getattr(self.ctx, doc_attr, None) or []
            for compiled in compiled_rules:
                yaml_fn = make_yaml_provider_check(compiled)
                for d in docs:
                    path = getattr(d, "path", "<unknown>")
                    data = getattr(d, "data", None)
                    if not isinstance(data, dict):
                        continue
                    finding = yaml_fn(path, data)
                    finding.cwe = list(compiled.rule.cwe)
                    findings.append(finding)
            return findings

    CustomRulesCheck.__name__ = f"CustomRulesCheck_{provider_name}"
    return CustomRulesCheck


__all__ = ["make_custom_rules_check"]
