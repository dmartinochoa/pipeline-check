"""Argo Workflows provider — scans ``Workflow`` / ``WorkflowTemplate`` YAML."""
from __future__ import annotations

from typing import Any

from ..checks.argo.base import ArgoContext
from ..checks.argo.pipelines import ArgoChecks
from ..checks.base import BaseCheck
from ..inventory import Component
from .base import BaseProvider


class ArgoProvider(BaseProvider):
    """Argo Workflows provider — multi-doc YAML, kinds under argoproj.io/*."""

    NAME = "argo"

    def build_context(
        self,
        argo_path: str | None = None,
        **_: Any,
    ) -> ArgoContext:
        if not argo_path:
            raise ValueError(
                "The argo provider requires --argo-path "
                "<file-or-dir> pointing at an Argo Workflow YAML "
                "file or a directory containing one."
            )
        return ArgoContext.from_path(argo_path)

    @property
    def check_classes(self) -> list[type[BaseCheck]]:
        return [ArgoChecks]

    def inventory(self, context: ArgoContext) -> list[Component]:
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
                templates = spec.get("templates")
                if isinstance(templates, list):
                    metadata["template_count"] = len(templates)
                ep = spec.get("entrypoint")
                if isinstance(ep, str):
                    metadata["entrypoint"] = ep
            out.append(Component(
                provider=self.NAME,
                type=d.kind.lower(),
                identifier=f"{d.kind}/{d.name or '<unnamed>'}",
                source=d.path,
                metadata=metadata,
            ))
        return out
