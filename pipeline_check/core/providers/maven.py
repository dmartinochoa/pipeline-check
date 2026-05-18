"""Maven provider, scans ``pom.xml`` / ``settings.xml`` on disk.

    pipeline_check --pipeline maven --maven-path path/to/pom.xml

No registry pull, no install, no Maven daemon access; text-only
static analysis of the POM and settings XML shapes.
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.maven.base import MavenContext
from ..checks.maven.pipelines import MavenChecks
from ..inventory import Component
from .base import BaseProvider


class MavenProvider(BaseProvider):
    """Maven provider, parses ``pom.xml`` + ``settings.xml`` documents."""

    NAME = "maven"

    def build_context(
        self,
        maven_path: str | None = None,
        **_: Any,
    ) -> MavenContext:
        if not maven_path:
            raise ValueError(
                "The maven provider requires --maven-path <file-or-dir> "
                "pointing at a pom.xml / settings.xml or a directory "
                "containing one."
            )
        return MavenContext.from_path(maven_path)

    @property
    def check_classes(self) -> list[type[BaseCheck]]:
        return [MavenChecks]

    def inventory(self, context: MavenContext) -> list[Component]:
        out: list[Component] = []
        for pom in context.files:
            kind = "settings.xml" if pom.is_settings else "pom.xml"
            metadata: dict[str, Any] = {
                "kind": kind,
                "dependency_count": len(pom.dependencies),
                "repository_count": len(pom.repositories),
                "mirror_count": len(pom.mirrors),
            }
            out.append(Component(
                provider=self.NAME, type=kind,
                identifier=pom.path, source=pom.path, metadata=metadata,
            ))
        return out
