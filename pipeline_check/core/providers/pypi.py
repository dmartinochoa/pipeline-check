"""pypi provider, scans requirements*.txt / *.in on disk.

    pipeline_check --pipeline pypi --pypi-path path/to/requirements.txt

Default mode is text-only static analysis of pip requirements file
shapes (no registry pull, no install, no PyPI API access). Opt in
to publish-time resolution against ``pypi.org`` via
``--resolve-remote`` so PYPI-008 (cooldown gate) can flag freshly-
published direct pins.
"""
from __future__ import annotations

import re
from typing import Any

from ..checks.base import BaseCheck
from ..checks.pypi.base import PypiContext, iter_specs
from ..checks.pypi.pipelines import PypiChecks
from ..checks.pypi.registry_fetcher import (
    FileSystemCache,
    HttpRegistryFetcher,
    default_cache_dir,
    fetch_publish_times,
)
from ..inventory import Component
from .base import BaseProvider

# Matches ``name==version`` (with optional ``[extras]``) — the
# only shape PYPI-008 reasons about. Mirrors the rule's own
# extractor so the provider doesn't fetch metadata for packages
# the rule wouldn't consider anyway.
_NAME_FROM_EXACT_PIN_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)"
    r"(?:\[[^\]]*\])?"
    r"\s*==\s*",
)


class PypiProvider(BaseProvider):
    """pypi provider, parses pip requirements files."""

    NAME = "pypi"

    def build_context(
        self,
        pypi_path: str | None = None,
        **_: Any,
    ) -> PypiContext:
        if not pypi_path:
            raise ValueError(
                "The pypi provider requires --pypi-path <file-or-dir> "
                "pointing at a requirements.txt or a directory "
                "containing one."
            )
        return PypiContext.from_path(pypi_path)

    @property
    def check_classes(self) -> list[type[BaseCheck[Any]]]:
        return [PypiChecks]

    def post_filter(
        self,
        context: PypiContext,
        resolve_remote: bool = False,
        no_cache: bool = False,
        **_: Any,
    ) -> None:
        """Populate ``context.publish_times`` from ``pypi.org``.

        Off by default. When ``resolve_remote`` is true, walks every
        exact-pin requirement in every loaded requirements file,
        fetches per-package metadata from the PyPI JSON API, and
        stores ``{name: {version: ts}}`` on the context so PYPI-008
        can compute cooldown ages.

        Failures (404, network error, malformed metadata) land in
        ``context.warnings`` rather than raising — mirrors the GHA
        resolver's strictly-additive contract.
        """
        if not resolve_remote:
            return
        names: list[str] = []
        for rf in context.files:
            for line in iter_specs(rf):
                m = _NAME_FROM_EXACT_PIN_RE.match(line.body)
                if m is not None:
                    names.append(m.group(1).strip().lower())
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

        osv_queries: list[tuple[str, str, str]] = []
        for rf in context.files:
            for line in iter_specs(rf):
                m = _NAME_FROM_EXACT_PIN_RE.match(line.body)
                if m is not None:
                    parts = line.body.split("==", 1)
                    if len(parts) == 2:
                        version = parts[1].strip().split(";")[0].strip()
                        if version:
                            osv_queries.append((
                                m.group(1).strip().lower(), version, "PyPI",
                            ))
        if osv_queries:
            from ..checks._primitives.osv_fetcher import query_osv_batch
            osv_cache = FileSystemCache(
                default_cache_dir() / "osv", enabled=not no_cache,
            )
            context.osv_advisories = query_osv_batch(
                osv_queries, cache=osv_cache,
                warnings=context.warnings,
            )

    def inventory(self, context: PypiContext) -> list[Component]:
        out: list[Component] = []
        for rf in context.files:
            metadata: dict[str, Any] = {
                "kind": "requirements.txt",
                "requirement_count": len(rf.lines),
                "option_count": len(rf.options),
            }
            out.append(Component(
                provider=self.NAME, type="requirements.txt",
                identifier=rf.path, source=rf.path, metadata=metadata,
            ))
        return out
