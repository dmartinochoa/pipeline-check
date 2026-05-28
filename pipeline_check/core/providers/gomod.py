"""Go modules provider, scans ``go.mod`` / ``go.sum`` on disk.

    pipeline_check --pipeline gomod --gomod-path path/to/go.mod

Default mode is text-only static analysis of the manifest and
integrity-manifest shapes (no registry pull, no ``go mod tidy``,
no module-proxy access). Mirrors the npm / PyPI / Maven / NuGet
provider contracts; a future ``--resolve-remote`` extension can
add publish-time + OSV-advisory rules without touching the
existing pack.
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.gomod.base import GoModContext
from ..checks.gomod.pipelines import GoModChecks
from ..inventory import Component
from ..sbom import BuildDependency
from .base import BaseProvider


class GoModProvider(BaseProvider):
    """Go modules provider, parses ``go.mod`` documents."""

    NAME = "gomod"

    def build_context(
        self,
        gomod_path: str | None = None,
        **_: Any,
    ) -> GoModContext:
        if not gomod_path:
            raise ValueError(
                "The gomod provider requires --gomod-path "
                "<file-or-dir> pointing at a go.mod or a directory "
                "containing one."
            )
        return GoModContext.from_path(gomod_path)

    @property
    def check_classes(self) -> list[type[BaseCheck[Any]]]:
        return [GoModChecks]

    def build_dependencies(
        self, context: GoModContext,
    ) -> list[BuildDependency]:
        """Emit one BuildDependency per declared require.

        Indirect requires are emitted too, the consumer's CycloneDX
        BOM should reflect the full module graph just as
        ``go mod graph`` would. Pinned status is always True for Go:
        every require entry carries an exact version, even when the
        upstream tag points at a commit SHA (the pseudo-version
        form ``v0.0.0-YYYYMMDDHHMMSS-commitsha`` is still an exact
        pin).
        """
        deps: list[BuildDependency] = []
        for pom in context.files:
            for req in pom.requires:
                deps.append(BuildDependency(
                    name=req.path,
                    version=req.version,
                    dep_type="go",
                    purl=f"pkg:golang/{req.path}@{req.version}",
                    provider=self.NAME,
                    source=pom.path,
                    pinned=True,
                ))
        return deps

    def inventory(self, context: GoModContext) -> list[Component]:
        out: list[Component] = []
        for pom in context.files:
            metadata: dict[str, Any] = {
                "kind": "go.mod",
                "module": pom.module_path,
                "go_version": pom.go_version or None,
                "toolchain": pom.toolchain or None,
                "require_count": len(pom.requires),
                "direct_require_count": sum(
                    1 for r in pom.requires if not r.indirect
                ),
                "replace_count": len(pom.replaces),
                "exclude_count": len(pom.excludes),
                "has_sumfile": pom.has_sumfile,
            }
            out.append(Component(
                provider=self.NAME, type="go.mod",
                identifier=pom.path, source=pom.path,
                metadata=metadata,
            ))
            if pom.sumfile_path:
                out.append(Component(
                    provider=self.NAME, type="go.sum",
                    identifier=pom.sumfile_path,
                    source=pom.sumfile_path,
                    metadata={"kind": "go.sum"},
                ))
        return out
