"""Adapter that runs loaded custom rules through a provider's context.

The Scanner appends one ``CustomRulesCheck`` (built by
:func:`make_custom_rules_check`) to a provider's check-class list at
construction time. From the orchestrator's point of view, custom
rules look like just another check, same ``BaseCheck`` shape, same
:class:`Finding` output, no special plumbing in reporting / scoring /
SARIF / ``--explain``.

Provider-specific iteration lives here, not in the loader, because
the per-context shape (``ctx.workflows`` vs ``ctx.pipelines`` vs
``ctx.manifests``) is incidental to the YAML rule and shouldn't leak
into the user's authoring surface.
"""
from __future__ import annotations

import logging
from typing import Any

from ..base import BaseCheck, Finding
from .loader import (
    CompiledCustomRule,
    LoadedCustomRules,
    make_kubernetes_check,
    make_yaml_provider_check,
)
from .rego_errors import OpaNotFoundError, RegoRuleError
from .rego_loader import RegoRuleMetadata
from .rego_runner import evaluate_rego_rules, make_passing_findings

_log = logging.getLogger(__name__)

_YAML_PROVIDERS_DOC_LIST_ATTR: dict[str, str] = {
    "github":     "workflows",
    "gitlab":     "pipelines",
    "bitbucket":  "pipelines",
    "azure":      "pipelines",
    "circleci":   "pipelines",
    "cloudbuild": "pipelines",
}

_REGO_DOC_LIST_ATTR: dict[str, str] = {
    **_YAML_PROVIDERS_DOC_LIST_ATTR,
    "jenkins":    "pipelines",
    "drone":      "pipelines",
    "buildkite":  "pipelines",
    "tekton":     "pipelines",
    "argo":       "pipelines",
    "argocd":     "pipelines",
}


def make_custom_rules_check(
    provider_name: str,
    loaded: LoadedCustomRules,
) -> type[BaseCheck[Any]]:
    """Return a BaseCheck subclass that runs every custom rule for *provider_name*.

    The returned class captures *provider_name* and the rules list in
    its closure, so the Scanner can construct it with the standard
    ``check_class(context, target=...)`` signature without provider-
    specific kwargs.
    """
    compiled_rules: list[CompiledCustomRule] = list(
        loaded.by_provider.get(provider_name, []),
    )
    rego_rules: list[RegoRuleMetadata] = list(
        loaded.rego_by_provider.get(provider_name, []),
    )
    doc_attr: str | None = _YAML_PROVIDERS_DOC_LIST_ATTR.get(provider_name)
    rego_doc_attr: str | None = _REGO_DOC_LIST_ATTR.get(provider_name)

    class CustomRulesCheck(BaseCheck[Any]):
        """Run every loaded custom rule for one provider."""

        PROVIDER = provider_name

        def __init__(self, ctx: Any, target: str | None = None) -> None:
            super().__init__(context=ctx, target=target)
            self.ctx = ctx

        def run(self) -> list[Finding]:
            findings: list[Finding] = []
            findings.extend(self._run_yaml_rules())
            findings.extend(self._run_rego_rules())
            return findings

        def _run_yaml_rules(self) -> list[Finding]:
            findings: list[Finding] = []
            if not compiled_rules:
                return findings
            if provider_name == "kubernetes":
                for compiled in compiled_rules:
                    k8s_fn = make_kubernetes_check(compiled)
                    finding = k8s_fn(self.ctx)
                    finding.cwe = list(compiled.rule.cwe)
                    if not finding.incident_refs:
                        finding.incident_refs = list(compiled.rule.incident_refs)
                    if finding.exploit_example is None:
                        finding.exploit_example = compiled.rule.exploit_example
                    findings.append(finding)
                return findings
            if doc_attr is None:
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
                    if not finding.incident_refs:
                        finding.incident_refs = list(compiled.rule.incident_refs)
                    if finding.exploit_example is None:
                        finding.exploit_example = compiled.rule.exploit_example
                    findings.append(finding)
            return findings

        def _run_rego_rules(self) -> list[Finding]:
            if not rego_rules:
                return []
            findings: list[Finding] = []
            try:
                if provider_name == "kubernetes":
                    findings.extend(
                        self._eval_rego_kubernetes()
                    )
                else:
                    findings.extend(
                        self._eval_rego_doc_list()
                    )
            except (OpaNotFoundError, RegoRuleError):
                raise
            except Exception:
                _log.warning(
                    "Rego evaluation failed for provider %s",
                    provider_name,
                    exc_info=True,
                )
                return []
            deny_ids = {f.check_id for f in findings if not f.passed}
            default_resource = _guess_resource(self.ctx, rego_doc_attr)
            findings.extend(
                make_passing_findings(rego_rules, deny_ids, default_resource)
            )
            return findings

        def _eval_rego_kubernetes(self) -> list[Finding]:
            manifests_raw: list[dict[str, Any]] = []
            for m in getattr(self.ctx, "manifests", []):
                manifests_raw.append({
                    "kind": getattr(m, "kind", ""),
                    "name": getattr(m, "name", ""),
                    "namespace": getattr(m, "namespace", ""),
                    "path": getattr(m, "path", ""),
                    "data": getattr(m, "data", {}),
                })
            input_data: dict[str, Any] = {
                "manifests": manifests_raw,
                "provider": "kubernetes",
            }
            return evaluate_rego_rules(rego_rules, input_data)

        def _eval_rego_doc_list(self) -> list[Finding]:
            attr = rego_doc_attr or doc_attr
            if attr is None:
                return []
            docs = getattr(self.ctx, attr, None) or []
            findings: list[Finding] = []
            for d in docs:
                path = getattr(d, "path", "<unknown>")
                data = getattr(d, "data", None)
                if not isinstance(data, dict):
                    continue
                input_data: dict[str, Any] = {
                    "path": path,
                    "doc": data,
                    "provider": provider_name,
                }
                findings.extend(
                    evaluate_rego_rules(rego_rules, input_data)
                )
            return findings

    CustomRulesCheck.__name__ = f"CustomRulesCheck_{provider_name}"
    return CustomRulesCheck


def _guess_resource(ctx: Any, attr: str | None) -> str:
    if attr is None:
        return "<unknown>"
    docs = getattr(ctx, attr, None) or []
    if docs:
        return str(getattr(docs[0], "path", "<unknown>"))
    return "<unknown>"


__all__ = ["make_custom_rules_check"]
