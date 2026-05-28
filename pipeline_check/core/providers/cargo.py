"""Cargo provider, scans ``Cargo.toml`` / ``Cargo.lock`` on disk.

    pipeline_check --pipeline cargo --cargo-path path/to/Cargo.toml

Text-only static analysis of the Cargo manifest and lockfile
shapes (no registry pull, no ``cargo update``, no toolchain
access). Mirrors the npm / PyPI / Maven / NuGet / Go-modules
provider contracts.
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.cargo.base import CargoContext
from ..checks.cargo.pipelines import CargoChecks
from ..inventory import Component
from ..sbom import BuildDependency
from .base import BaseProvider


class CargoProvider(BaseProvider):
    """Cargo provider, parses ``Cargo.toml`` documents."""

    NAME = "cargo"

    def build_context(
        self,
        cargo_path: str | None = None,
        **_: Any,
    ) -> CargoContext:
        if not cargo_path:
            raise ValueError(
                "The cargo provider requires --cargo-path "
                "<file-or-dir> pointing at a Cargo.toml or a "
                "directory containing one."
            )
        return CargoContext.from_path(cargo_path)

    @property
    def check_classes(self) -> list[type[BaseCheck[Any]]]:
        return [CargoChecks]

    def build_dependencies(
        self, context: CargoContext,
    ) -> list[BuildDependency]:
        deps: list[BuildDependency] = []
        for pom in context.files:
            for dep in pom.dependencies:
                # Skip workspace-inherited entries on per-crate
                # manifests; they're audited on the workspace root.
                if dep.from_workspace:
                    continue
                version_text = dep.version or (
                    f"git:{dep.git_rev}" if dep.is_git and dep.git_rev
                    else "git:HEAD" if dep.is_git
                    else "path" if dep.is_path else "unspecified"
                )
                # ``cargo`` PURL type per the purl-spec. For path /
                # git entries the version slot still has to carry
                # *something*, so we emit the synthetic prefix
                # markers above.
                deps.append(BuildDependency(
                    name=dep.name,
                    version=version_text,
                    dep_type="cargo",
                    purl=f"pkg:cargo/{dep.name}@{version_text}",
                    provider=self.NAME,
                    source=pom.path,
                    pinned=(
                        dep.version is not None
                        and dep.version.lstrip().startswith("=")
                    ),
                ))
        return deps

    def inventory(self, context: CargoContext) -> list[Component]:
        out: list[Component] = []
        for pom in context.files:
            metadata: dict[str, Any] = {
                "kind": "Cargo.toml",
                "crate": pom.crate_name or None,
                "dependency_count": len(pom.dependencies),
                "has_lockfile": pom.has_lockfile,
                "is_workspace_root": pom.is_workspace_root,
            }
            out.append(Component(
                provider=self.NAME, type="Cargo.toml",
                identifier=pom.path, source=pom.path,
                metadata=metadata,
            ))
            if pom.lockfile_path:
                out.append(Component(
                    provider=self.NAME, type="Cargo.lock",
                    identifier=pom.lockfile_path,
                    source=pom.lockfile_path,
                    metadata={"kind": "Cargo.lock"},
                ))
        return out
