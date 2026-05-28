"""RubyGems provider, scans ``Gemfile`` / ``Gemfile.lock`` on disk.

    pipeline_check --pipeline rubygems --rubygems-path path/to/Gemfile

Text-only static analysis of the Bundler manifest and lockfile
shape (no ``bundle install``, no rubygems.org API access, no Ruby
runtime required). Mirrors the npm / PyPI / Maven / NuGet / Go
modules / Cargo / Composer provider contracts.
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.rubygems.base import GemContext
from ..checks.rubygems.pipelines import RubyGemsChecks
from ..inventory import Component
from ..sbom import BuildDependency
from .base import BaseProvider


class RubyGemsProvider(BaseProvider):
    """RubyGems provider, parses ``Gemfile`` documents."""

    NAME = "rubygems"

    def build_context(
        self,
        rubygems_path: str | None = None,
        **_: Any,
    ) -> GemContext:
        if not rubygems_path:
            raise ValueError(
                "The rubygems provider requires --rubygems-path "
                "<file-or-dir> pointing at a Gemfile or a "
                "directory containing one."
            )
        return GemContext.from_path(rubygems_path)

    @property
    def check_classes(self) -> list[type[BaseCheck[Any]]]:
        return [RubyGemsChecks]

    def build_dependencies(
        self, context: GemContext,
    ) -> list[BuildDependency]:
        deps: list[BuildDependency] = []
        for pom in context.files:
            for dep in pom.dependencies:
                # Skip dev-group entries for the production SBOM.
                if dep.groups and all(
                    g in {"development", "test"} for g in dep.groups
                ):
                    continue
                version_text = dep.version or (
                    f"git:{dep.git_ref}"
                    if dep.is_git and dep.git_ref
                    else "git:HEAD" if dep.is_git
                    else "path" if dep.is_path
                    else "unpinned"
                )
                pinned = bool(
                    dep.version
                    and not any(
                        op in dep.version
                        for op in ("~>", ">=", "<=", "!=", ">", "<", ",")
                    )
                )
                deps.append(BuildDependency(
                    name=dep.name,
                    version=version_text,
                    dep_type="gem",
                    purl=f"pkg:gem/{dep.name}@{version_text}",
                    provider=self.NAME,
                    source=pom.path,
                    pinned=pinned,
                ))
        return deps

    def inventory(self, context: GemContext) -> list[Component]:
        out: list[Component] = []
        for pom in context.files:
            metadata: dict[str, Any] = {
                "kind": "Gemfile",
                "dependency_count": len(pom.dependencies),
                "source_count": len(pom.sources),
                "has_lockfile": pom.has_lockfile,
            }
            out.append(Component(
                provider=self.NAME, type="Gemfile",
                identifier=pom.path, source=pom.path,
                metadata=metadata,
            ))
            if pom.lockfile_path:
                out.append(Component(
                    provider=self.NAME, type="Gemfile.lock",
                    identifier=pom.lockfile_path,
                    source=pom.lockfile_path,
                    metadata={"kind": "Gemfile.lock"},
                ))
        return out
