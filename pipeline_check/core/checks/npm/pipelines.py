"""npm orchestrator.

Each NPM-* rule lives in its own module under ``rules/``. This
orchestrator auto-discovers them and runs each against every loaded
file. Rules signal which file kind they want by their ``check()``
signature, the orchestrator looks at the callable's first parameter
annotation and dispatches accordingly.
"""
from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

from ..base import Finding
from ..rule import apply_rule_metadata, discover_rules, wants_ctx_kwarg
from .base import NpmBaseCheck, NpmContext, NpmLock, NpmManifest, NpmRc


class NpmChecks(NpmBaseCheck):

    def __init__(
        self, ctx: NpmContext, target: str | None = None,
    ) -> None:
        super().__init__(ctx, target)
        self._rules = discover_rules(
            "pipeline_check.core.checks.npm.rules"
        )

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        for rule, check_fn in self._rules:
            kind = _input_kind(check_fn)
            if kind == "manifest":
                targets: list[Any] = list(self.ctx.manifests)
            elif kind == "lock":
                targets = list(self.ctx.locks)
            elif kind == "rc":
                targets = list(self.ctx.rcs)
            else:
                # ``ctx`` form: rule wants the whole context (rare).
                targets = [self.ctx]
            # Rules that need cross-target state (NPM-008's publish-
            # time table populated by --resolve-remote) declare a
            # second parameter; pass the context for those.
            wants_ctx = wants_ctx_kwarg(check_fn)
            for tgt in targets:
                if wants_ctx:
                    finding = check_fn(tgt, self.ctx)
                else:
                    finding = check_fn(tgt)
                apply_rule_metadata(finding, rule)
                findings.append(finding)
        return findings


def _input_kind(check_fn: Callable[..., Finding]) -> str:
    """Return ``"manifest"`` / ``"lock"`` / ``"ctx"`` for *check_fn*.

    Inspected via the first parameter's annotation so rule modules
    stay declarative — they just type their input and the orchestrator
    routes by kind. Rule modules use ``from __future__ import
    annotations``, so the annotation surfaces as a string here; we
    match either shape.
    """
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
    if name == "NpmManifest" or annotation is NpmManifest:
        return "manifest"
    if name == "NpmLock" or annotation is NpmLock:
        return "lock"
    if name == "NpmRc" or annotation is NpmRc:
        return "rc"
    return "ctx"
