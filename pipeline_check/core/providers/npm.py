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
from ..checks.npm.base import (
    NpmContext,
    iter_manifest_dependencies,
    load_base_locks_via_git,
)
from ..checks.npm.pipelines import NpmChecks
from ..checks.npm.registry_fetcher import (
    FileSystemCache,
    HttpRegistryFetcher,
    default_cache_dir,
    fetch_maintainer_counts,
    fetch_provenance,
    fetch_publish_times,
    fetch_repo_slugs,
)
from ..inventory import Component
from ..sbom import BuildDependency, make_npm_purl
from .base import BaseProvider

_EXACT_VERSION_RE = __import__("re").compile(
    r"^=?v?(\d+\.\d+\.\d+(?:[\w.+-]*)?)$"
)


def _collect_osv_queries_npm(
    context: NpmContext,
) -> list[tuple[str, str, str]]:
    queries: list[tuple[str, str, str]] = []
    for manifest in context.manifests:
        for _section, name, spec in iter_manifest_dependencies(manifest):
            m = _EXACT_VERSION_RE.match(spec.strip())
            if m:
                queries.append((name, m.group(1), "npm"))
    return queries


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
    def check_classes(self) -> list[type[BaseCheck[Any]]]:
        return [NpmChecks]

    def post_filter(
        self,
        context: NpmContext,
        resolve_remote: bool = False,
        no_cache: bool = False,
        npm_path: str | None = None,
        npm_base_ref: str | None = None,
        **_: Any,
    ) -> None:
        """Populate ``context.publish_times`` and ``context.base_locks``.

        Two opt-ins:

        * ``resolve_remote`` (off by default). When true, walks every
          direct dependency in every loaded ``package.json``, fetches
          per-package metadata from ``registry.npmjs.org``, and
          stores ``{name: {version: ts}}`` on the context so NPM-008
          can compute cooldown ages.
        * ``npm_base_ref`` (off by default). When set, resolves each
          loaded lockfile's contents at the given git ref via
          ``git show`` and populates ``context.base_locks`` so
          NPM-009 (new-transitive-dep diff gate) can pair the
          current and base lockfiles.

        Failures (404, network error, missing base ref, malformed
        metadata) land in ``context.warnings`` rather than raising,
        mirroring the GHA resolver's strictly-additive contract.
        A transient registry outage or a brand-new lockfile in
        this branch shouldn't fail CI on its own.
        """
        if npm_base_ref and context.locks:
            load_base_locks_via_git(
                context, npm_base_ref, npm_path or ".",
            )
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

        # Publisher counts and build-provenance both come from the same
        # packument the publish-time pass just cached, so these add no
        # network requests. The warnings half is dropped: any fetch
        # failure was already surfaced by the publish-time pass above.
        context.maintainer_counts = fetch_maintainer_counts(
            names, fetcher, cache=cache,
        )[0]
        context.provenance = fetch_provenance(
            names, fetcher, cache=cache,
        )[0]

        # OpenSSF Scorecard (NPM-016): the GitHub repo slug comes free
        # from the cached packument, but the Scorecard lookup itself is a
        # separate external API (api.securityscorecards.dev), so it only
        # runs when there are GitHub-linked deps to query.
        repo_slugs = fetch_repo_slugs(names, fetcher, cache=cache)[0]
        if repo_slugs:
            from ..checks._primitives.scorecard import (
                fetch_scorecards,
                scorecard_cache_dir,
            )
            sc_cache = FileSystemCache(
                scorecard_cache_dir(), enabled=not no_cache,
            )
            context.scorecards = fetch_scorecards(
                repo_slugs, cache=sc_cache,
            )[0]

        osv_queries = _collect_osv_queries_npm(context)
        if osv_queries:
            from ..checks._primitives.osv_fetcher import query_osv_batch
            osv_cache = FileSystemCache(
                default_cache_dir() / "osv", enabled=not no_cache,
            )
            context.osv_advisories = query_osv_batch(
                osv_queries, cache=osv_cache,
                warnings=context.warnings,
            )

    def build_dependencies(
        self, context: NpmContext,
    ) -> list[BuildDependency]:
        deps: list[BuildDependency] = []
        for m in context.manifests:
            for section in ("dependencies", "devDependencies"):
                raw = m.data.get(section)
                if not isinstance(raw, dict):
                    continue
                for name, version_spec in raw.items():
                    if not isinstance(name, str) or not isinstance(version_spec, str):
                        continue
                    version = version_spec.lstrip("^~>=<! ")
                    if not version:
                        continue
                    deps.append(BuildDependency(
                        name=name,
                        version=version,
                        dep_type="npm",
                        purl=make_npm_purl(name, version),
                        provider=self.NAME,
                        source=m.path,
                        pinned=not any(
                            c in version_spec for c in "^~><=*x"
                        ),
                    ))
        return deps

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
