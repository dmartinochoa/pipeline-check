"""npm provider, scans package.json / package-lock.json on disk.

    pipeline_check --pipeline npm --npm-path path/to/package.json

No registry pull, no install, no daemon access; text-only static
analysis of the manifest and lockfile shapes by default. Opt in to
publish-time resolution against ``registry.npmjs.org`` via
``--resolve-remote`` so NPM-008 (cooldown gate) can flag freshly-
published direct deps.
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.npm.base import NpmContext, iter_manifest_dependencies
from ..checks.npm.pipelines import NpmChecks
from ..checks.npm.registry_fetcher import (
    FileSystemCache,
    HttpRegistryFetcher,
    default_cache_dir,
    fetch_publish_times,
)
from ..inventory import Component
from .base import BaseProvider


class NpmProvider(BaseProvider):
    """npm provider, parses package.json + package-lock.json documents."""

    NAME = "npm"

    def build_context(
        self,
        npm_path: str | None = None,
        **_: Any,
    ) -> NpmContext:
        if not npm_path:
            raise ValueError(
                "The npm provider requires --npm-path <file-or-dir> "
                "pointing at a package.json / package-lock.json or a "
                "directory containing one."
            )
        return NpmContext.from_path(npm_path)

    @property
    def check_classes(self) -> list[type[BaseCheck]]:
        return [NpmChecks]

    def post_filter(
        self,
        context: NpmContext,
        resolve_remote: bool = False,
        no_cache: bool = False,
        **_: Any,
    ) -> None:
        """Populate ``context.publish_times`` from ``registry.npmjs.org``.

        Off by default. When ``resolve_remote`` is true, walks every
        direct dependency in every loaded ``package.json``, fetches
        per-package metadata, and stores ``{name: {version: ts}}``
        on the context so NPM-008 can compute cooldown ages.

        Failures (404, network error, malformed metadata) land in
        ``context.warnings`` rather than raising, mirroring the GHA
        resolver's strictly-additive contract — a transient
        registry outage shouldn't fail CI.
        """
        if not resolve_remote:
            return
        names: list[str] = []
        for manifest in context.manifests:
            for _section, name, _spec in iter_manifest_dependencies(
                manifest,
            ):
                names.append(name)
        if not names:
            return
        fetcher = HttpRegistryFetcher()
        cache = FileSystemCache(
            default_cache_dir(), enabled=not no_cache,
        )
        publish_times, warnings = fetch_publish_times(
            names, fetcher, cache=cache,
        )
        context.publish_times = publish_times
        context.warnings.extend(warnings)

    def inventory(self, context: NpmContext) -> list[Component]:
        out: list[Component] = []
        for m in context.manifests:
            deps = m.data.get("dependencies") or {}
            dev_deps = m.data.get("devDependencies") or {}
            metadata: dict[str, Any] = {
                "kind": "package.json",
                "name": m.data.get("name"),
                "version": m.data.get("version"),
                "dependency_count": len(deps) if isinstance(deps, dict) else 0,
                "dev_dependency_count": (
                    len(dev_deps) if isinstance(dev_deps, dict) else 0
                ),
            }
            out.append(Component(
                provider=self.NAME, type="package.json",
                identifier=m.path, source=m.path, metadata=metadata,
            ))
        for lock in context.locks:
            packages = lock.data.get("packages") or lock.data.get("dependencies") or {}
            metadata = {
                "kind": "package-lock.json",
                "lockfile_version": lock.lockfile_version,
                "package_count": (
                    len(packages) if isinstance(packages, dict) else 0
                ),
            }
            out.append(Component(
                provider=self.NAME, type="package-lock.json",
                identifier=lock.path, source=lock.path, metadata=metadata,
            ))
        return out
