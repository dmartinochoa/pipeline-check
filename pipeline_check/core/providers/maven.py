"""Maven provider, scans ``pom.xml`` / ``settings.xml`` on disk.

    pipeline_check --pipeline maven --maven-path path/to/pom.xml

Default mode is text-only static analysis of the POM and settings
XML shapes (no registry pull, no install, no Maven daemon access).
Opt in to publish-time resolution against Maven Central via
``--resolve-remote`` so MVN-008 (cooldown gate) can flag freshly-
published direct dependencies.
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.maven.base import MavenContext, iter_resolved_coordinates
from ..checks.maven.pipelines import MavenChecks
from ..checks.maven.registry_fetcher import (
    FileSystemCache,
    HttpRegistryFetcher,
    default_cache_dir,
    fetch_publish_times,
)
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

    def post_filter(
        self,
        context: MavenContext,
        resolve_remote: bool = False,
        no_cache: bool = False,
        **_: Any,
    ) -> None:
        """Populate ``context.publish_times`` from Maven Central.

        Off by default. When ``resolve_remote`` is true, walks every
        non-managed dependency in every loaded POM, fetches per-
        coordinate metadata from the Maven Central search API, and
        stores ``{"group:artifact": {version: ts}}`` on the context
        so MVN-008 can compute cooldown ages.

        Failures (404, network error, malformed metadata) land in
        ``context.warnings`` rather than raising — mirrors the GHA
        / npm / pypi resolvers' strictly-additive contract.
        """
        if not resolve_remote:
            return
        coordinates: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for pom in context.files:
            if pom.is_settings:
                continue
            for group_id, artifact_id, _version in iter_resolved_coordinates(pom):
                pair = (group_id, artifact_id)
                if pair in seen:
                    continue
                seen.add(pair)
                coordinates.append(pair)
        if not coordinates:
            return
        fetcher = HttpRegistryFetcher()
        cache = FileSystemCache(
            default_cache_dir(), enabled=not no_cache,
        )
        publish_times, warnings = fetch_publish_times(
            coordinates, fetcher, cache=cache,
        )
        context.publish_times = publish_times
        context.warnings.extend(warnings)

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
