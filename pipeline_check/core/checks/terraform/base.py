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
        self._resources: list[TerraformResource] = list(_iter_resources(plan))

    @classmethod
    def from_path(cls, path: str | Path) -> TerraformContext:
        with open(path, encoding="utf-8") as fh:
            return cls(json.load(fh))

    def resources(self, resource_type: str | None = None) -> Iterator[TerraformResource]:
        """Yield resources, optionally filtered by Terraform *resource_type*."""
        for r in self._resources:
            if resource_type is None or r.type == resource_type:
                yield r

    def __len__(self) -> int:
        return len(self._resources)


def _iter_resources(plan: dict[str, Any]) -> Iterator[TerraformResource]:
    """Walk planned_values.root_module (and child_modules) recursively."""
    root = plan.get("planned_values", {}).get("root_module", {})
    yield from _walk_module(root)


def _walk_module(module: dict[str, Any]) -> Iterator[TerraformResource]:
    for r in module.get("resources", []) or []:
        if r.get("mode") != "managed":
            continue  # skip data sources
        yield TerraformResource(
            address=r.get("address", ""),
            type=r.get("type", ""),
            name=r.get("name", ""),
            values=r.get("values", {}) or {},
        )
    for child in module.get("child_modules", []) or []:
        yield from _walk_module(child)


class TerraformBaseCheck(BaseCheck):
    """Base class for every Terraform check module."""

    PROVIDER = "terraform"

    def __init__(self, ctx: TerraformContext, target: str | None = None) -> None:
        super().__init__(context=ctx, target=target)
        self.ctx: TerraformContext = ctx
