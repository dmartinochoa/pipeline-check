"""Scanner — orchestrates check classes via the provider registry.

Adding a new provider or check module never requires editing this file.
See the relevant provider module for instructions:
  - AWS:  pipeline_check/core/providers/aws.py
  - New:  pipeline_check/core/providers/base.py  (BaseProvider contract)
          pipeline_check/core/providers/__init__.py  (register it there)
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from . import chains as _chains
from . import diff as _diff
from . import providers as _providers
from . import standards as _standards
from .chains import Chain
from .checks import _secrets as _secret_registry
from .checks._confidence import confidence_for
from .checks.base import Confidence, Finding, clear_blob_cache
from .inventory import Component


@dataclass
class ScanMetadata:
    """Metadata about a scan run, surfaced in the CLI summary line."""

    provider: str = ""
    files_scanned: int = 0
    files_skipped: int = 0
    warnings: list[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0


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
        secret_patterns: list[str] | tuple[str, ...] | None = None,
        chains_enabled: bool = True,
        log: Any = None,
        **provider_kwargs: Any,
    ) -> None:
        self._log = log
        self._chains_enabled = chains_enabled
        #: Attack-chains detected by the most recent ``run()``. Populated
        #: as a side effect — chains derive from findings 1:1 with the
        #: run, so consumers always want both together. Empty list when
        #: chains are disabled or no chains matched.
        self.chains: list[Chain] = []
        provider = _providers.get(pipeline)
        if provider is None:
            available = ", ".join(_providers.available()) or "none registered"
            raise ValueError(
                f"Unknown provider '{pipeline}'. Available: {available}"
            )
        self.pipeline = pipeline.lower()
        self._provider = provider
        self._check_classes = provider.check_classes
        # Reset the global secret-pattern registry at the start of
        # every Scanner construction so patterns registered for a
        # prior scan (common in long-lived Lambda containers) don't
        # leak into the next invocation. Callers pass the patterns
        # they want applied to this scan via ``secret_patterns``.
        _secret_registry.reset_patterns()
        for pat in secret_patterns or ():
            _secret_registry.register_pattern(pat)
        self._context: Any = provider.build_context(
            region=region, profile=profile, **provider_kwargs
        )
        if diff_base:
            _filter_context_by_diff(self._context, diff_base, self.pipeline)

        self.metadata = ScanMetadata(
            provider=self.pipeline,
            files_scanned=getattr(self._context, "files_scanned", 0),
            files_skipped=getattr(self._context, "files_skipped", 0),
            warnings=list(getattr(self._context, "warnings", [])),
        )

    def inventory(
        self,
        type_patterns: list[str] | None = None,
    ) -> list[Component]:
        """Return the list of components the active provider discovered.

        Delegates to ``provider.inventory(context)``. Safe to call
        independently of ``run()`` — shift-left providers answer from
        the already-loaded context, the AWS provider performs a fresh
        enumeration pass (one extra round-trip per service). Either
        call order works:

            scanner.inventory()
            scanner.run()

        or vice-versa; the inventory function does not depend on
        findings having been collected.

        Parameters
        ----------
        type_patterns:
            Optional glob patterns (``aws_*``, ``AWS::IAM::*``,
            ``workflow``). A component is kept when its ``type`` matches
            any pattern. Case-sensitive — CFN types are PascalCase,
            Terraform types are snake_case; callers should match the
            casing of the provider they're slicing.
        """
        provider = getattr(self, "_provider", None)
        if provider is None:
            provider = _providers.get(self.pipeline)
        if provider is None:
            return []
        components = provider.inventory(self._context)
        if type_patterns:
            import fnmatch
            components = [
                c for c in components
                if any(fnmatch.fnmatchcase(c.type, p) for p in type_patterns)
            ]
        return components

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
        # Reset the blob cache so id()-keyed entries from a prior scan
        # can't alias a newly-allocated doc object in the same process.
        clear_blob_cache()

        # Guard for callers that bypass __init__ (e.g. tests using __new__).
        if not hasattr(self, "metadata"):
            self.metadata = ScanMetadata(provider=getattr(self, "pipeline", ""))

        t0 = time.monotonic()

        log = getattr(self, "_log", None)

        findings: list[Finding] = []
        for check_class in self._check_classes:
            checker = check_class(self._context, target=target)
            batch = checker.run()
            if log:
                log(f"running {check_class.__name__}... {len(batch)} finding(s)")
            findings.extend(batch)

        if checks:
            # Support glob patterns (``GHA-*``, ``*-008``) alongside
            # exact IDs. fnmatch semantics: ``*`` matches any run of
            # chars, ``?`` matches one, ``[abc]`` matches a set.
            import fnmatch
            patterns = [c.upper() for c in checks]
            findings = [
                f for f in findings
                if any(fnmatch.fnmatchcase(f.check_id.upper(), p) for p in patterns)
            ]

        active_standards = _standards.resolve(standards)
        for f in findings:
            f.controls = _standards.resolve_for_check(f.check_id, active_standards)
            # Apply the centralised confidence default unless the rule
            # opted out by setting ``confidence_locked=True`` on the
            # Finding. Rules that want per-finding control (e.g. CB-005
            # emitting HIGH for two-versions-behind even though the
            # blanket default is MEDIUM) set the lock flag on the
            # specific findings they want to preserve.
            if not f.confidence_locked:
                f.confidence = confidence_for(f.check_id)

        # Attack-chain correlation runs after confidence is finalised so
        # ``min_confidence(triggers)`` reflects the post-demotion value.
        # A chain rule that crashes never aborts the scan — chains are
        # an additive signal, not a gate. ``getattr`` guards against
        # callers that bypass ``__init__`` (older tests use ``__new__``
        # + manual attribute setting); default-on matches the CLI
        # default of chains enabled.
        if getattr(self, "_chains_enabled", True):
            self.chains = _chains.evaluate(findings)
        else:
            self.chains = []

        self.metadata.elapsed_seconds = time.monotonic() - t0

        return findings


def _filter_context_by_diff(context: Any, base_ref: str, provider: str) -> None:
    """Drop workflow/pipeline entries whose file was not changed vs ``base_ref``.

    Workflow providers expose either ``.workflows`` (GitHub) or
    ``.pipelines`` (GitLab / Bitbucket / Azure), each a list of objects
    with a ``.path`` attribute; filter those lists in place.

    Terraform provider: filter ``planned_values.root_module.resources``
    by whether any ``.tf`` file mentioning the resource address
    changed. Coarse but correct — if nothing in the plan's source
    files changed, nothing in the plan can have changed.

    AWS provider: ``--diff-base`` has no natural analogue (live API
    calls aren't bound to git files). Raise loudly rather than
    silently ignoring the flag.

    ``changed_files`` returning ``None`` (git missing / base ref bad)
    is treated as "no filter" — better to over-scan than to silently
    skip everything in CI.
    """
    if provider == "aws":
        raise ValueError(
            "--diff-base is not supported for the AWS provider. "
            "Live AWS resources are not bound to git refs; scan the "
            "whole region or narrow scope with --target NAME."
        )
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
    if provider == "terraform":
        _filter_terraform_by_diff(context, allowed)


def _filter_terraform_by_diff(context: Any, allowed: set[str]) -> None:
    """Keep only planned resources whose module directory touched a changed file.

    A plan's resources don't carry source file locations directly,
    but their ``address`` starts with a module path (e.g.
    ``module.vpc.aws_subnet.public[0]``). We approximate "changed
    resources" as "resources whose module path maps to a .tf file
    under a directory that appears in the diff." When the plan has
    no module prefix (root module), any .tf file change in the
    working directory keeps all resources in play.
    """
    plan = getattr(context, "plan", None)
    if not isinstance(plan, dict):
        return
    tf_files_touched = {
        p for p in allowed
        if isinstance(p, str) and p.endswith(".tf")
    }
    root_changed = any(
        "/" not in p and "\\" not in p for p in tf_files_touched
    )
    module_dirs_changed = {
        _tf_dir(p) for p in tf_files_touched if _tf_dir(p)
    }
    # Defensive nested-dict traversal — a malformed plan with a
    # non-dict ``planned_values`` or ``root_module`` value would
    # otherwise raise AttributeError here. Missing/wrong shape → skip
    # the filter (safer to over-scan than to crash the CI run).
    pv = plan.get("planned_values")
    if not isinstance(pv, dict):
        return
    rm = pv.get("root_module")
    if not isinstance(rm, dict):
        return
    planned = rm.get("resources")
    if not isinstance(planned, list):
        return

    def _keep(res: dict) -> bool:
        addr = res.get("address", "")
        if not isinstance(addr, str):
            return True
        if not addr.startswith("module."):
            return root_changed
        # module.<name>.<type>.<...> — use <name> as a directory hint.
        parts = addr.split(".")
        if len(parts) < 2:
            return root_changed
        mod_name = parts[1]
        # Exact match only. Substring (``vpc in "vpc-prod"``) would
        # keep resources from unrelated modules whose directory name
        # happens to share a prefix.
        return mod_name in module_dirs_changed

    rm["resources"] = [r for r in planned if _keep(r)]


def _tf_dir(path: str) -> str:
    from pathlib import Path as _P
    parts = _P(path).parent.parts
    return parts[-1] if parts else ""
