"""Terraform-specific base check and context.

Check modules under this package subclass ``TerraformBaseCheck`` and read
resources from ``self.ctx`` — a :class:`TerraformContext` wrapping the
parsed output of ``terraform show -json``. Checks never parse HCL; they
operate on the resolved, typed plan representation Terraform emits.

Typical producer workflow for the caller:

    terraform plan -out=tfplan
    terraform show -json tfplan > plan.json
    pipeline_check --pipeline terraform --tf-plan plan.json
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..base import BaseCheck


@dataclass(frozen=True)
class TerraformResource:
    """A single resource extracted from a Terraform plan JSON document."""

    address: str            # e.g. "module.foo.aws_codebuild_project.app"
    type: str               # e.g. "aws_codebuild_project"
    name: str               # e.g. "app"
    values: dict[str, Any]  # attribute map mirroring the Terraform schema


class TerraformContext:
    """Flattened, queryable view of a ``terraform show -json`` document.

    Resources in child modules are walked recursively so checks do not have
    to care about module nesting.
    """

    def __init__(self, plan: dict[str, Any]) -> None:
        self._plan = plan
        resources, data_sources = _split_resources(plan)
        self._resources: list[TerraformResource] = resources
        self._data_sources: list[TerraformResource] = data_sources

    @classmethod
    def from_path(cls, path: str | Path) -> TerraformContext:
        with open(path, encoding="utf-8") as fh:
            return cls(json.load(fh))

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
        reference — e.g. an ``aws_iam_policy_document`` rendered via
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


class TerraformBaseCheck(BaseCheck):
    """Base class for every Terraform check module."""

    PROVIDER = "terraform"

    def __init__(self, ctx: TerraformContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: TerraformContext = ctx
