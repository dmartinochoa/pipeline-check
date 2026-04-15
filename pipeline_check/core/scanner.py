"""Scanner — orchestrates check classes via the provider registry.

Adding a new provider or check module never requires editing this file.
See the relevant provider module for instructions:
  - AWS:  pipeline_check/core/providers/aws.py
  - New:  pipeline_check/core/providers/base.py  (BaseProvider contract)
          pipeline_check/core/providers/__init__.py  (register it there)
"""
from __future__ import annotations

from typing import Any

from .checks.base import Finding
from . import providers as _providers
from . import standards as _standards
from . import diff as _diff


class Scanner:
    """Runs all check classes registered for the given provider.

    Parameters
    ----------
    pipeline:
        Provider name (must match a registered BaseProvider.NAME).
    region:
        Forwarded to the provider's build_context (AWS: region to scan).
    profile:
        Forwarded to the provider's build_context (AWS: named CLI profile).

    Additional keyword arguments are forwarded to the provider's
    build_context, allowing future providers to accept platform-specific
    credentials without changing this class.
    """

    def __init__(
        self,
        pipeline: str = "aws",
        region: str = "us-east-1",
        profile: str | None = None,
        diff_base: str | None = None,
        **provider_kwargs: Any,
    ) -> None:
        provider = _providers.get(pipeline)
        if provider is None:
            available = ", ".join(_providers.available()) or "none registered"
            raise ValueError(
                f"Unknown provider '{pipeline}'. Available: {available}"
            )
        self.pipeline = pipeline.lower()
        self._check_classes = provider.check_classes
        self._context: Any = provider.build_context(
            region=region, profile=profile, **provider_kwargs
        )
        if diff_base:
            _filter_context_by_diff(self._context, diff_base)

    def run(
        self,
        checks: list[str] | None = None,
        target: str | None = None,
        standards: list[str] | None = None,
    ) -> list[Finding]:
        """Execute every registered check class for the active provider.

        Parameters
        ----------
        checks:
            Optional allowlist of check IDs (e.g. ``["CB-001", "CB-003"]``).
            When provided, only findings whose ``check_id`` matches are kept.
        target:
            Optional resource name to scope the scan to (e.g. a CodePipeline
            pipeline name).  Checks that support targeting restrict their API
            calls accordingly; others run over the full region.
        standards:
            Optional list of standard names (e.g. ``["owasp_cicd_top_10"]``)
            to annotate findings with. When ``None``, every registered
            standard is used.
        """
        findings: list[Finding] = []
        for check_class in self._check_classes:
            checker = check_class(self._context, target=target)
            findings.extend(checker.run())

        if checks:
            normalised = {c.upper() for c in checks}
            findings = [f for f in findings if f.check_id.upper() in normalised]

        active_standards = _standards.resolve(standards)
        for f in findings:
            f.controls = _standards.resolve_for_check(f.check_id, active_standards)

        return findings


def _filter_context_by_diff(context: Any, base_ref: str) -> None:
    """Drop workflow/pipeline entries whose file was not changed vs ``base_ref``.

    Only workflow-style providers carry file-scoped context — AWS and
    Terraform build contexts hold live API clients or a single plan
    and are left untouched. Workflow providers expose either
    ``.workflows`` (GitHub) or ``.pipelines`` (GitLab / Bitbucket /
    Azure), each a list of objects with a ``.path`` attribute; filter
    those lists in place.

    ``changed_files`` returning ``None`` (git missing / base ref bad)
    is treated as "no filter" — better to over-scan than to silently
    skip everything in CI.
    """
    allowed = _diff.changed_files(base_ref)
    if allowed is None:
        return
    for attr in ("workflows", "pipelines"):
        items = getattr(context, attr, None)
        if not isinstance(items, list):
            continue
        paths = [getattr(i, "path", "") for i in items]
        kept = set(_diff.filter_paths(paths, allowed))
        setattr(
            context,
            attr,
            [i for i in items if getattr(i, "path", "") in kept],
        )
