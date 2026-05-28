"""Composer provider, scans ``composer.json`` / ``composer.lock`` on disk.

    pipeline_check --pipeline composer --composer-path path/to/composer.json

Text-only static analysis of the Composer manifest and lockfile
shapes (no Packagist pull, no ``composer install``, no PHP
runtime access). Mirrors the npm / PyPI / Maven / NuGet / Go
modules / Cargo provider contracts.
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.composer.base import ComposerContext
from ..checks.composer.pipelines import ComposerChecks
from ..inventory import Component
from ..sbom import BuildDependency
from .base import BaseProvider


class ComposerProvider(BaseProvider):
    """Composer provider, parses ``composer.json`` documents."""

    NAME = "composer"

    def build_context(
        self,
        composer_path: str | None = None,
        **_: Any,
    ) -> ComposerContext:
        if not composer_path:
            raise ValueError(
                "The composer provider requires --composer-path "
                "<file-or-dir> pointing at a composer.json or a "
                "directory containing one."
            )
        return ComposerContext.from_path(composer_path)

    @property
    def check_classes(self) -> list[type[BaseCheck[Any]]]:
        return [ComposerChecks]

    def build_dependencies(
        self, context: ComposerContext,
    ) -> list[BuildDependency]:
        deps: list[BuildDependency] = []
        for pom in context.files:
            for dep in pom.dependencies:
                pinned = bool(
                    dep.constraint
                    and not any(
                        c in dep.constraint
                        for c in "^~*<>|,"
                    )
                    and not dep.constraint.startswith("dev-")
                )
                # ``composer`` PURL type per the purl-spec uses
                # ``pkg:composer/<namespace>/<name>@<version>``.
                deps.append(BuildDependency(
                    name=dep.name,
                    version=dep.constraint,
                    dep_type="composer",
                    purl=f"pkg:composer/{dep.name}@{dep.constraint}",
                    provider=self.NAME,
                    source=pom.path,
                    pinned=pinned,
                ))
        return deps

    def inventory(self, context: ComposerContext) -> list[Component]:
        out: list[Component] = []
        for pom in context.files:
            metadata: dict[str, Any] = {
                "kind": "composer.json",
                "package": pom.package_name or None,
                "dependency_count": len(pom.dependencies),
                "repository_count": len(pom.repositories),
                "has_lockfile": pom.has_lockfile,
            }
            out.append(Component(
                provider=self.NAME, type="composer.json",
                identifier=pom.path, source=pom.path,
                metadata=metadata,
            ))
            if pom.lockfile_path:
                out.append(Component(
                    provider=self.NAME, type="composer.lock",
                    identifier=pom.lockfile_path,
                    source=pom.lockfile_path,
                    metadata={"kind": "composer.lock"},
                ))
        return out
