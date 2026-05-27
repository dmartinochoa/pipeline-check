"""Argo CD provider, scans Application / ApplicationSet / AppProject YAML."""
from __future__ import annotations

from typing import Any

from ..checks.argocd.base import ArgoCDContext
from ..checks.argocd.pipelines import ArgoCDChecks
from ..checks.base import BaseCheck
from ..inventory import Component
from .base import BaseProvider


class ArgoCDProvider(BaseProvider):
    """Argo CD provider, multi-doc YAML, kinds under argoproj.io/* plus argocd-cm/rbac ConfigMaps."""

    NAME = "argocd"

    def build_context(
        self,
        argocd_path: str | None = None,
        **_: Any,
    ) -> ArgoCDContext:
        if not argocd_path:
            raise ValueError(
                "The argocd provider requires --argocd-path "
                "<file-or-dir> pointing at an Argo CD Application / "
                "ApplicationSet / AppProject YAML file (or a "
                "directory containing one)."
            )
        return ArgoCDContext.from_path(argocd_path)

    @property
    def check_classes(self) -> list[type[BaseCheck[Any]]]:
        return [ArgoCDChecks]

    def inventory(self, context: ArgoCDContext) -> list[Component]:
        out: list[Component] = []
        for d in context.docs:
            if d.kind == "ConfigMap":
                # argocd-cm / argocd-rbac-cm are instance-config docs,
                # not deployable components. Keep --inventory focused
                # on the Application/AppProject surface.
                continue
            metadata: dict[str, Any] = {
                "kind": d.kind,
                "api_version": d.api_version,
            }
            if d.namespace:
                metadata["namespace"] = d.namespace
            spec = d.data.get("spec") or {}
            if isinstance(spec, dict):
                if d.kind == "Application":
                    proj = spec.get("project")
                    if isinstance(proj, str):
                        metadata["project"] = proj
                elif d.kind == "AppProject":
                    dests = spec.get("destinations")
                    if isinstance(dests, list):
                        metadata["destinations_count"] = len(dests)
                elif d.kind == "ApplicationSet":
                    gens = spec.get("generators")
                    if isinstance(gens, list):
                        kinds: list[str] = []
                        for g in gens:
                            if isinstance(g, dict):
                                for k in g:
                                    if isinstance(k, str):
                                        kinds.append(k)
                        metadata["generator_kinds"] = kinds
            out.append(Component(
                provider=self.NAME,
                type=d.kind.lower(),
                identifier=f"{d.kind}/{d.name or '<unnamed>'}",
                source=d.path,
                metadata=metadata,
            ))
        return out
