"""NuGet orchestrator.

Each NUGET-* rule lives in its own module under ``rules/``. This
orchestrator auto-discovers them and runs each against every loaded
file. Rules signal which file kind they want by their ``check()``
signature's first-parameter annotation.
"""
from __future__ import annotations

import inspect
from collections.abc import Callable

from ..base import Finding
from ..rule import apply_rule_metadata, discover_rules, wants_ctx_kwarg
from .base import NuGetBaseCheck, NuGetConfig, NuGetContext, NuGetProject


class NuGetChecks(NuGetBaseCheck):

    def __init__(
        self, ctx: NuGetContext, target: str | None = None,
    ) -> None:
        super().__init__(ctx, target)
        self._rules = discover_rules(
            "pipeline_check.core.checks.nuget.rules"
        )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for rule, check_fn in self._rules:
            kind = _input_kind(check_fn)
            if kind == "project":
                targets: list[NuGetProject | NuGetConfig | NuGetContext] = list(self.ctx.projects)
            elif kind == "config":
                targets = list(self.ctx.configs)
            else:
                targets = [self.ctx]
            has_ctx = wants_ctx_kwarg(check_fn)
            for tgt in targets:
                if has_ctx:
                    finding = check_fn(tgt, self.ctx)
                else:
                    finding = check_fn(tgt)
                apply_rule_metadata(finding, rule)
                findings.append(finding)
        return findings


def _input_kind(check_fn: Callable[..., Finding]) -> str:
    try:
        params = list(inspect.signature(check_fn).parameters.values())
    except (TypeError, ValueError):
        return "ctx"
    if not params:
        return "ctx"
    annotation = params[0].annotation
    name = (
        annotation if isinstance(annotation, str)
        else getattr(annotation, "__name__", "")
    )
    if name == "NuGetProject" or annotation is NuGetProject:
        return "project"
    if name == "NuGetConfig" or annotation is NuGetConfig:
        return "config"
    return "ctx"
