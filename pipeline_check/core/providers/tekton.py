"""Tekton provider, scans ``Task`` / ``Pipeline`` / ``*Run`` YAML."""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.tekton.base import TektonContext
from ..checks.tekton.pipelines import TektonChecks
from ..inventory import Component
from .base import BaseProvider


class TektonProvider(BaseProvider):
    """Tekton provider, multi-doc YAML, kinds under tekton.dev/*."""

    NAME = "tekton"

    def build_context(
        self,
        tekton_path: str | None = None,
        **_: Any,
    ) -> TektonContext:
        if not tekton_path:
            raise ValueError(
                "The tekton provider requires --tekton-path "
                "<file-or-dir> pointing at a Tekton YAML file or a "
                "directory containing one."
            )
        return TektonContext.from_path(tekton_path)

    @property
    def check_classes(self) -> list[type[BaseCheck]]:
        return [TektonChecks]

    def inventory(self, context: TektonContext) -> list[Component]:
        out: list[Component] = []
        for d in context.docs:
            metadata: dict[str, Any] = {
                "kind": d.kind,
                "api_version": d.api_version,
            }
            if d.namespace:
                metadata["namespace"] = d.namespace
            spec = d.data.get("spec") or {}
            if isinstance(spec, dict):
                steps = spec.get("steps")
                if isinstance(steps, list):
                    metadata["step_count"] = len(steps)
                tasks = spec.get("tasks")
                if isinstance(tasks, list):
                    metadata["task_count"] = len(tasks)
            out.append(Component(
                provider=self.NAME,
                type=d.kind.lower(),
                identifier=f"{d.kind}/{d.name or '<unnamed>'}",
                source=d.path,
                metadata=metadata,
            ))
        return out
