"""Terraform-specific base check and context.

Check modules under this package subclass ``TerraformBaseCheck`` and read
resources from ``self.ctx``, a :class:`TerraformContext` wrapping either
the parsed output of ``terraform show -json`` (plan path) or directly
parsed ``*.tf`` files (HCL source path).

Plan path (canonical, fully resolved attributes):

    terraform plan -out=tfplan
    terraform show -json tfplan > plan.json
    pipeline_check --pipeline terraform --tf-plan plan.json

HCL source path (best-effort, partial variable resolution):

    pipeline_check --pipeline terraform --tf-source ./infra/
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..base import BaseCheck


@dataclass(frozen=True, slots=True)
class TerraformResource:
    """A single resource extracted from a Terraform plan JSON document."""

    address: str            # e.g. "module.foo.aws_codebuild_project.app"
    type: str               # e.g. "aws_codebuild_project"
    name: str               # e.g. "app"
    values: dict[str, Any]  # attribute map mirroring the Terraform schema


class TerraformContext:
    """Flattened, queryable view of Terraform resources.

    Resources come from either a ``terraform show -json`` plan document
    (``from_path``) or from direct HCL source parsing (``from_hcl_dir``).
    Child modules are walked recursively so checks do not have to care
    about module nesting.
    """

    def __init__(self, plan: dict[str, Any]) -> None:
        self._plan = plan
        self.source_mode: str = "plan"
        self.warnings: list[str] = []
        self.unresolved_refs: set[str] = set()
        self._resources_with_unresolved: set[str] = set()
        self.files_scanned: int = 0
        self.files_skipped: int = 0
        resources, data_sources = _split_resources(plan)
        self._resources: list[TerraformResource] = resources
        self._data_sources: list[TerraformResource] = data_sources
        self._after_unknown: dict[str, dict[str, Any]] = (
            _index_after_unknown(plan)
        )
        self._config_references: dict[str, dict[str, list[str]]] = (
            _index_config_references(plan)
        )

    @classmethod
    def from_path(cls, path: str | Path) -> TerraformContext:
        try:
            with open(path, encoding="utf-8") as fh:
                plan = json.load(fh)
        except (
            OSError, UnicodeDecodeError, json.JSONDecodeError,
            RecursionError, MemoryError,
        ) as exc:
            # build_context runs unguarded, so a malformed or
            # pathologically deep tf-plan would abort the whole scan with
            # a raw traceback (RecursionError / MemoryError slip past
            # JSONDecodeError). Degrade to an empty plan with a warning,
            # like the other loaders, so the scan reports "0 scanned" with
            # a reason instead of crashing.
            ctx = cls({})
            ctx.files_skipped = 1
            ctx.warnings = [
                f"{path}: tf-plan parse error: "
                f"{str(exc).split(chr(10), 1)[0]}"
            ]
            return ctx
        return cls(plan)

    @classmethod
    def from_hcl_dir(cls, path: str | Path) -> TerraformContext:
        """Parse ``*.tf`` files in *path* and build a context from raw HCL.

        Requires ``python-hcl2`` (``pip install pipeline-check[hcl]``).
        """
        from ._hcl_parser import parse_tf_directory

        result = parse_tf_directory(Path(path))
        ctx = cls.__new__(cls)
        ctx._plan = {}
        ctx.source_mode = "hcl"
        ctx.warnings = result.warnings
        ctx.unresolved_refs = result.unresolved_refs
        ctx._resources_with_unresolved = result.resources_with_unresolved
        ctx.files_scanned = result.files_scanned
        ctx.files_skipped = 0
        ctx._resources = result.resources
        ctx._data_sources = result.data_sources
        # HCL source mode has no plan ``after_unknown`` metadata; rules
        # fall back to the interpolation-string heuristics there.
        ctx._after_unknown = {}
        if result.unresolved_refs:
            refs = ", ".join(sorted(result.unresolved_refs)[:10])
            ctx.warnings.append(
                f"[hcl] Best-effort parse: {len(result.unresolved_refs)} "
                f"reference(s) could not be resolved ({refs}). "
                f"Findings referencing these values may be imprecise."
            )
        return ctx

    def resources(self, resource_type: str | None = None) -> Iterator[TerraformResource]:
        """Yield **managed** resources, optionally filtered by Terraform *resource_type*."""
        for r in self._resources:
            if resource_type is None or r.type == resource_type:
                yield r

    def data_sources(self, resource_type: str | None = None) -> Iterator[TerraformResource]:
        """Yield **data sources** (``mode == "data"``), optionally filtered by type.

        Exposed separately from ``resources()`` so rules that only care
        about managed-state changes keep their current semantics. Data
        sources are useful when a check needs to follow an indirect
        reference, e.g. an ``aws_iam_policy_document`` rendered via
        ``.json`` output and consumed elsewhere in the plan.
        """
        for r in self._data_sources:
            if resource_type is None or r.type == resource_type:
                yield r

    def after_unknown(self, address: str) -> dict[str, Any]:
        """Return the ``after_unknown`` map for *address*, or ``{}``.

        A ``terraform show -json`` plan carries, per resource change, an
        ``after_unknown`` tree mirroring ``after`` with ``true`` at every
        attribute whose value is computed at apply time (a reference to
        a not-yet-created resource, a generated id, ...). Rules consult
        this to tell "attribute genuinely absent / false" from "attribute
        set to a value the plan can't resolve yet", so they don't false
        -fire on a fresh plan. Empty in HCL source mode.
        """
        return self._after_unknown.get(address, {})

    def config_references(self, address: str, attr: str) -> list[str]:
        """Resource addresses referenced by *address*'s *attr* expression.

        Sourced from the plan's ``configuration`` block (``terraform show
        -json``), which records the static reference graph even when the
        referenced value is computed at apply time and therefore absent
        from ``planned_values``. Lets a rule join, e.g., an
        ``aws_iam_role_policy_attachment`` to the ``aws_iam_policy`` it
        attaches when both ARNs are unknown on a create plan. Count /
        for_each indices on *address* are ignored. Empty in HCL-source
        mode (no configuration block)."""
        base = _INDEX_SUFFIX_RE.sub("", address)
        return self._config_references.get(base, {}).get(attr, [])

    def __len__(self) -> int:
        return len(self._resources)


#: Trailing count / for_each index on a planned_values address
#: (``aws_iam_policy.ci[0]`` / ``...["prod"]``); configuration-block
#: addresses carry no index, so strip it before the lookup.
_INDEX_SUFFIX_RE = re.compile(r"\[[^\]]*\]$")


def _index_config_references(
    plan: dict[str, Any],
) -> dict[str, dict[str, list[str]]]:
    """Map ``address -> {attr -> [referenced addresses]}`` from ``configuration``.

    Walks ``configuration.root_module`` (and nested ``module_calls``) and
    records each resource attribute's ``references`` list. This is the
    static reference graph, present even when the referenced value is
    computed at apply time. Empty when the plan carries no configuration
    block (HCL-source mode).
    """
    out: dict[str, dict[str, list[str]]] = {}
    config = plan.get("configuration")
    if not isinstance(config, dict):
        return out
    root = config.get("root_module")
    if isinstance(root, dict):
        _walk_config_module(root, out)
    return out


def _walk_config_module(
    module: dict[str, Any], out: dict[str, dict[str, list[str]]],
) -> None:
    for res in module.get("resources") or []:
        if not isinstance(res, dict):
            continue
        addr = res.get("address")
        exprs = res.get("expressions")
        if not isinstance(addr, str) or not isinstance(exprs, dict):
            continue
        attr_refs: dict[str, list[str]] = {}
        for attr, spec in exprs.items():
            if isinstance(spec, dict):
                refs = spec.get("references")
                if isinstance(refs, list):
                    attr_refs[attr] = [r for r in refs if isinstance(r, str)]
        if attr_refs:
            out[addr] = attr_refs
    module_calls = module.get("module_calls")
    if isinstance(module_calls, dict):
        for call in module_calls.values():
            if isinstance(call, dict):
                sub = call.get("module")
                if isinstance(sub, dict):
                    _walk_config_module(sub, out)


def _index_after_unknown(
    plan: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Map each resource address to its ``change.after_unknown`` tree.

    Only entries whose ``after_unknown`` is a mapping are kept, so a
    fully-known change (``after_unknown`` is often ``false`` / ``{}``)
    simply doesn't appear and ``after_unknown(addr)`` returns ``{}``.
    """
    out: dict[str, dict[str, Any]] = {}
    for rc in plan.get("resource_changes") or []:
        if not isinstance(rc, dict):
            continue
        addr = rc.get("address")
        change = rc.get("change")
        if not isinstance(addr, str) or not isinstance(change, dict):
            continue
        au = change.get("after_unknown")
        if isinstance(au, dict):
            out[addr] = au
    return out


def _split_resources(
    plan: dict[str, Any],
) -> tuple[list[TerraformResource], list[TerraformResource]]:
    """Partition ``planned_values`` into (managed, data) resource lists."""
    managed: list[TerraformResource] = []
    data: list[TerraformResource] = []
    root = plan.get("planned_values", {}).get("root_module", {})
    for r in _walk_module(root):
        (managed if r[0] else data).append(r[1])
    return managed, data


def _walk_module(
    module: dict[str, Any],
) -> Iterator[tuple[bool, TerraformResource]]:
    """Yield ``(is_managed, TerraformResource)`` pairs from *module* recursively."""
    for r in module.get("resources", []) or []:
        mode = r.get("mode")
        if mode not in ("managed", "data"):
            continue
        yield (
            mode == "managed",
            TerraformResource(
                address=r.get("address", ""),
                type=r.get("type", ""),
                name=r.get("name", ""),
                values=r.get("values", {}) or {},
            ),
        )
    for child in module.get("child_modules", []) or []:
        yield from _walk_module(child)


class TerraformBaseCheck(BaseCheck[TerraformContext]):
    """Base class for every Terraform check module."""

    PROVIDER = "terraform"

    def __init__(self, ctx: TerraformContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: TerraformContext = ctx
