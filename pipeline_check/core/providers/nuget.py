"""NuGet provider, scans .NET project files and NuGet configuration.

Parses ``*.csproj``, ``Directory.Packages.props``, ``packages.config``,
``NuGet.config``, and ``packages.lock.json``. Fifth dependency-supply-
chain provider after npm / pypi / maven.

    pipeline_check --pipeline nuget --nuget-path ./src/
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.nuget.base import NuGetContext
from ..checks.nuget.pipelines import NuGetChecks
from ..inventory import Component
from .base import BaseProvider


def _is_range(version: str) -> bool:
    return any(c in version for c in "[](),*")


class NuGetProvider(BaseProvider):
    """Scans .NET NuGet project files and configuration."""

    NAME = "nuget"

    def build_context(
        self, nuget_path: str | None = None, **_: Any,
    ) -> NuGetContext:
        return NuGetContext.from_path(nuget_path or ".")

    @property
    def check_classes(self) -> list[type[BaseCheck[Any]]]:
        return [NuGetChecks]

    def post_filter(
        self,
        context: NuGetContext,
        resolve_remote: bool = False,
        no_cache: bool = False,
        **_: Any,
    ) -> None:
        if not resolve_remote:
            return
        osv_queries: list[tuple[str, str, str]] = []
        for proj in context.projects:
            for ref in proj.package_refs:
                if ref.version and not _is_range(ref.version):
                    osv_queries.append((
                        ref.name.lower(), ref.version, "NuGet",
                    ))
        if osv_queries:
            from ..checks._primitives.osv_fetcher import query_osv_batch
            from ..checks._primitives.registry_fetcher import (
                FileSystemCache,
                default_cache_dir,
            )
            osv_cache = FileSystemCache(
                default_cache_dir() / "osv", enabled=not no_cache,
            )
            context.osv_advisories = query_osv_batch(
                osv_queries, cache=osv_cache,
                warnings=context.warnings,
            )

    def inventory(self, context: NuGetContext) -> list[Component]:
        out: list[Component] = []
        for proj in context.projects:
            for ref in proj.package_refs:
                out.append(Component(
                    provider=self.NAME,
                    type="nuget-package",
                    identifier=ref.name,
                    source=proj.path,
                    metadata={"version": ref.version or "<unmanaged>"},
                ))
        return out
