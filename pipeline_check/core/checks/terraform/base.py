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

    @classmethod
    def from_path(cls, path: str | Path) -> TerraformContext:
        with open(path, encoding="utf-8") as fh:
            return cls(json.load(fh))

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

    def __len__(self) -> int:
        return len(self._resources)


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
