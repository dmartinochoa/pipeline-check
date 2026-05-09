"""Scanner, orchestrates check classes via the provider registry.

Adding a new provider or check module never requires editing this file.
See the relevant provider module for instructions:
  - AWS:  pipeline_check/core/providers/aws.py
  - New:  pipeline_check/core/providers/base.py  (BaseProvider contract)
          pipeline_check/core/providers/__init__.py  (register it there)
"""
from __future__ import annotations

import fnmatch
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
from .checks.base import Finding, Severity, clear_blob_cache
from .checks.custom.loader import LoadedCustomRules, load_custom_rules
from .checks.custom.runner import make_custom_rules_check
from .inventory import Component


@dataclass(slots=True)
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
        detect_entropy: bool = False,
        chains_enabled: bool = True,
        overrides: dict[str, dict[str, str]] | None = None,
        custom_rules: list[str] | tuple[str, ...] | None = None,
        log: Any = None,
        **provider_kwargs: Any,
    ) -> None:
        self._log = log
        self._chains_enabled = chains_enabled
        # Per-rule severity overrides applied after confidence resolution.
        # The value mapping currently only carries ``"severity"`` (other
        # knobs may follow). Keys are upper-cased here so programmatic
        # callers don't have to match the casing convention; the config
        # loader already normalizes before reaching us.
        self._overrides: dict[str, dict[str, str]] = {
            (k.upper() if isinstance(k, str) else k): v
            for k, v in (overrides or {}).items()
        }
        #: Attack-chains detected by the most recent ``run()``. Populated
        #: as a side effect, chains derive from findings 1:1 with the
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
        # Custom rules load before the built-in check-class list is
        # frozen so the per-provider runner can be appended in one
        # place. Loading defers ID-collision checks to the loader,
        # which uses the union of every built-in registry.
        self._custom_rules: LoadedCustomRules = self._load_custom_rules(
            custom_rules,
        )
        check_classes = list(provider.check_classes)
        if self._custom_rules.by_provider.get(self.pipeline):
            check_classes.append(
                make_custom_rules_check(self.pipeline, self._custom_rules),
            )
        self._check_classes = check_classes
        # Reset the global secret-pattern registry at the start of
        # every Scanner construction so patterns registered for a
        # prior scan (common in long-lived Lambda containers) don't
        # leak into the next invocation. Callers pass the patterns
        # they want applied to this scan via ``secret_patterns``.
        # ``reset_patterns`` also clears the entropy-detection flag,
        # so opting in for one scan doesn't carry into the next.
        _secret_registry.reset_patterns()
        for pat in secret_patterns or ():
            _secret_registry.register_pattern(pat)
        if detect_entropy:
            _secret_registry.enable_entropy_detection(True)
        self._context = self._build_context(
            provider, region, profile, diff_base, provider_kwargs,
        )
        self.metadata = ScanMetadata(
            provider=self.pipeline,
            files_scanned=getattr(self._context, "files_scanned", 0),
            files_skipped=getattr(self._context, "files_skipped", 0),
            warnings=list(getattr(self._context, "warnings", [])),
        )

    def _build_context(
        self,
        provider: Any,
        region: str,
        profile: str | None,
        diff_base: str | None,
        provider_kwargs: dict[str, Any],
    ) -> Any:
        """Construct the provider context, apply the diff filter, run
        ``post_filter``.

        Pulled out of ``__init__`` so tests can substitute their own
        context-building strategy without re-implementing the rest of
        Scanner construction. ``post_filter`` exceptions never abort
        the scan, they're surfaced as a context warning so the
        operator sees the breakage in the report's metadata block.
        """
        ctx: Any = provider.build_context(
            region=region, profile=profile, **provider_kwargs,
        )
        if diff_base:
            _filter_context_by_diff(ctx, diff_base, self.pipeline)

        # ``post_filter`` runs after the diff filter so resolver-driven
        # provider extensions (GHA reusable workflow resolution) don't
        # waste fetches on callers that the diff filter already pruned.
        try:
            provider.post_filter(ctx, **provider_kwargs)
        except Exception as exc:
            warnings_list = getattr(ctx, "warnings", None)
            if isinstance(warnings_list, list):
                warnings_list.append(
                    f"[{self.pipeline}] post_filter hook raised: {exc}"
                )
        return ctx

    @staticmethod
    def _load_custom_rules(
        paths: list[str] | tuple[str, ...] | None,
    ) -> LoadedCustomRules:
        """Load custom rules and reject IDs that collide with built-ins.

        Built-in IDs come from the union of every provider's rule
        registry. We deliberately don't filter by the active pipeline
       , a custom rule with id ``GHA-001`` is rejected even when the
        current scan is ``--pipeline kubernetes``, because the same
        rule file should round-trip across providers without surprise.
        """
        if not paths:
            return LoadedCustomRules()
        builtin_ids: set[str] = set()
        # Discover rule packages from the filesystem. Adding a new
        # provider under ``pipeline_check/core/checks/<name>/rules/``
        # automatically participates in collision detection, no
        # registry edit required. The same import is also used by the
        # CLI's ``--list-checks`` / completion path, so the source of
        # truth stays singular.
        from pathlib import Path as _Path

        from .checks.rule import discover_rules
        checks_root = _Path(__file__).parent / "checks"
        builtin_packages = sorted(
            f"pipeline_check.core.checks.{p.parent.parent.name}.rules"
            for p in checks_root.glob("*/rules/__init__.py")
        )
        for pkg in builtin_packages:
            try:
                for rule, _ in discover_rules(pkg):
                    builtin_ids.add(rule.id)
            except (ImportError, AttributeError):
                # A misconfigured package shouldn't block custom-rule
                # loading. Worst case: a built-in ID isn't in the
                # collision set and a clashing custom rule loads;
                # the collision will still surface as duplicate
                # findings at scan time.
                continue
        return load_custom_rules(paths, builtin_ids=builtin_ids)

    def inventory(
        self,
        type_patterns: list[str] | None = None,
    ) -> list[Component]:
        """Return the list of components the active provider discovered.

        Delegates to ``provider.inventory(context)``. Safe to call
        independently of ``run()``, shift-left providers answer from
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
            any pattern. Case-sensitive. CFN types are PascalCase,
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
            # Apply user-configured per-rule overrides last so they
            # win over both the rule-default severity and any rule-set
            # confidence. Unknown check IDs are silently ignored, the
            # config loader already warned on the typo. ``getattr``
            # guards against callers that bypass ``__init__`` (older
            # AWS test fixtures construct the Scanner via ``__new__``
            # plus manual attribute setting).
            overrides = getattr(self, "_overrides", None) or {}
            override = overrides.get(f.check_id.upper())
            if override:
                sev_str = override.get("severity")
                if sev_str:
                    try:
                        f.severity = Severity(sev_str.upper())
                    except ValueError:
                        # Defensive, config loader filters bad values
                        # already, but a programmatic caller could
                        # pass anything.
                        pass

        # Attack-chain correlation runs after confidence is finalised so
        # ``min_confidence(triggers)`` reflects the post-demotion value.
        # A chain rule that crashes never aborts the scan, chains are
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


class MultiScanner:
    """Run several :class:`Scanner` instances over one CLI invocation
    and evaluate the chain engine once on the union of their findings.

    The single-provider :class:`Scanner` invokes the chain engine at
    the end of its own ``run()``, which is the right shape when only
    one provider's findings are in scope. For cross-provider chain
    rules (``XPC-NNN``) to fire, the chain engine has to see findings
    from BOTH providers in the same evaluation pass; that's what
    :class:`MultiScanner` provides.

    The class deliberately delegates to :class:`Scanner` per provider
    rather than reimplementing context construction, the per-provider
    diff filter, the post_filter hook, or the override / custom-rule
    plumbing. Each delegated Scanner runs with ``chains_enabled=False``
    so single-provider chains aren't evaluated twice; the multi-scan
    re-evaluates every chain (single and cross-provider alike) on the
    union once all per-provider scans are done.

    Parameters
    ----------
    pipelines:
        Ordered list of provider names (must each match a registered
        :class:`BaseProvider.NAME`). Order determines the order
        per-provider sub-scans run and the order findings appear in
        the unified result list.

    Every other keyword argument is forwarded verbatim to each
    :class:`Scanner` so the existing CLI flag → kwarg flow keeps
    working without per-flag fan-out logic here. Provider-specific
    path flags (e.g., ``gha_path``, ``oci_manifest``) flow through
    each Scanner; the providers that don't recognize a given flag
    silently ignore it.
    """

    def __init__(
        self,
        pipelines: list[str] | tuple[str, ...],
        chains_enabled: bool = True,
        **scanner_kwargs: Any,
    ) -> None:
        if not pipelines:
            raise ValueError(
                "MultiScanner requires at least one pipeline; pass "
                "Scanner directly when scanning a single provider."
            )
        # Per-sub-scanner chains stay disabled regardless of
        # ``chains_enabled``: when chains are wanted we run them once
        # over the union (so cross-provider chains see both sides);
        # when disabled the union pass is skipped too.
        scanner_kwargs.pop("chains_enabled", None)
        self._chains_enabled = chains_enabled
        self.pipelines: list[str] = [p.lower() for p in pipelines]
        self._scanners: list[Scanner] = [
            Scanner(pipeline=p, chains_enabled=False, **scanner_kwargs)
            for p in self.pipelines
        ]
        #: Per-provider scan metadata, keyed by lower-case provider
        #: name. Mirrors ``Scanner.metadata`` so reporters that
        #: consume per-scan stats (warnings, files_scanned) can
        #: iterate this dict.
        self.metadata_by_provider: dict[str, ScanMetadata] = {
            p: s.metadata for p, s in zip(
                self.pipelines, self._scanners, strict=True,
            )
        }
        #: Chains detected across the union of every sub-scan's
        #: findings. Populated as a side effect of :meth:`run`,
        #: matches the :class:`Scanner.chains` shape so reporters
        #: can use either type interchangeably.
        self.chains: list[Chain] = []

    def run(
        self,
        checks: list[str] | None = None,
        target: str | None = None,
        standards: list[str] | None = None,
    ) -> list[Finding]:
        """Run every sub-scanner, return the union of findings.

        Side effects:

          * ``self.chains`` is set to the chain engine's evaluation
            over the unified findings list (per-Scanner ``chains``
            attributes stay empty since we constructed each with
            ``chains_enabled=False``);
          * ``self.metadata_by_provider`` retains the per-Scanner
            ``ScanMetadata`` reference so ``elapsed_seconds`` /
            ``files_scanned`` / ``warnings`` are queryable per
            provider.

        Sub-scanners run in the order ``self.pipelines`` was
        constructed; findings are concatenated in that order so a
        consumer iterating the result list sees a stable, repeatable
        sequence.
        """
        findings: list[Finding] = []
        for scanner in self._scanners:
            findings.extend(scanner.run(
                checks=checks, target=target, standards=standards,
            ))
        # Single chain-engine pass over the unified findings so
        # cross-provider chain rules (XPC-NNN) see both providers'
        # findings at once. Single-provider chain rules still match
        # against the same union, so a chain that fires on findings
        # from one provider continues to fire here.
        if self._chains_enabled:
            self.chains = _chains.evaluate(findings)
        else:
            self.chains = []
        return findings

    def inventory(
        self,
        type_patterns: list[str] | None = None,
    ) -> list[Component]:
        """Aggregate component inventory across every sub-scanner.

        Mirrors :meth:`Scanner.inventory` so reporters can call
        the same method whether the scanner is single- or
        multi-provider. Each sub-scanner's inventory pass runs
        independently and the results are concatenated; ordering
        is the same as ``self.pipelines``.
        """
        out: list[Component] = []
        for scanner in self._scanners:
            out.extend(scanner.inventory(type_patterns=type_patterns))
        return out

    @property
    def _check_classes(self) -> list[Any]:
        """Concatenated check-class list across every sub-scanner.

        Used by the CLI's verbose-mode logging only. The actual
        scan dispatch happens via the per-Scanner ``run()`` calls
        in :meth:`run`; this accessor exists so callers that hold
        a ``Scanner | MultiScanner`` union can introspect the
        count without branching on the type.
        """
        out: list[Any] = []
        for scanner in self._scanners:
            out.extend(scanner._check_classes)
        return out

    @property
    def metadata(self) -> ScanMetadata:
        """Aggregate :class:`ScanMetadata` over every sub-scanner.

        Reporters that want a single ``metadata`` value (the same
        shape :class:`Scanner` exposes) can use this property
        without having to walk the per-provider dict. Provider name
        is rendered as a comma-joined list; counts are summed;
        warnings are concatenated; ``elapsed_seconds`` is the sum
        of every sub-scan's elapsed time.
        """
        warnings: list[str] = []
        files_scanned = 0
        files_skipped = 0
        elapsed = 0.0
        for meta in self.metadata_by_provider.values():
            warnings.extend(meta.warnings)
            files_scanned += meta.files_scanned
            files_skipped += meta.files_skipped
            elapsed += meta.elapsed_seconds
        return ScanMetadata(
            provider=",".join(self.pipelines),
            files_scanned=files_scanned,
            files_skipped=files_skipped,
            warnings=warnings,
            elapsed_seconds=elapsed,
        )


def _filter_context_by_diff(context: Any, base_ref: str, provider: str) -> None:
    """Drop workflow/pipeline entries whose file was not changed vs ``base_ref``.

    Workflow providers expose either ``.workflows`` (GitHub) or
    ``.pipelines`` (GitLab / Bitbucket / Azure), each a list of objects
    with a ``.path`` attribute; filter those lists in place.

    Terraform provider: filter ``planned_values.root_module.resources``
    by whether any ``.tf`` file mentioning the resource address
    changed. Coarse but correct, if nothing in the plan's source
    files changed, nothing in the plan can have changed.

    AWS provider: ``--diff-base`` has no natural analogue (live API
    calls aren't bound to git files). Raise loudly rather than
    silently ignoring the flag.

    ``changed_files`` returning ``None`` (git missing / base ref bad)
    is treated as "no filter", better to over-scan than to silently
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
    # Defensive nested-dict traversal, a malformed plan with a
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

    def _keep(res: Any) -> bool:
        # Fail open on shape errors, a malformed plan with a non-dict
        # resource entry shouldn't crash the diff filter. The
        # surrounding helpers already chose "skip the filter, scan
        # everything" over raising on bad shape; this preserves that
        # contract at the per-item level too.
        if not isinstance(res, dict):
            return True
        addr = res.get("address", "")
        if not isinstance(addr, str):
            return True
        if not addr.startswith("module."):
            return root_changed
        # module.<name>.<type>.<...>, use <name> as a directory hint.
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
