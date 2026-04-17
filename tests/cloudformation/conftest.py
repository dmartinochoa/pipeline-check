"""Shared helpers for CloudFormation tests."""
from __future__ import annotations

from pipeline_check.core.checks.cloudformation.base import CloudFormationContext


def make_context(resources: dict, **top_level) -> CloudFormationContext:
    """Build a CloudFormationContext from an in-memory template.

    ``resources`` is the raw mapping that would normally sit under the
    ``Resources:`` key (``{"LogicalId": {"Type": "...", "Properties": {...}}}``).
    Extra top-level keys (``Parameters``, ``Outputs``, ``Transform``)
    can be passed via ``**top_level``.
    """
    template = {"Resources": resources, **top_level}
    ctx = CloudFormationContext.__new__(CloudFormationContext)
    ctx._templates = [("<in-memory>", template)]
    # Import lazily to avoid a circular at test-collection time.
    from pipeline_check.core.checks.cloudformation.base import _iter_resources
    ctx._resources = list(_iter_resources(ctx._templates))
    return ctx


def r(logical_id: str, rtype: str, properties: dict, **attrs) -> dict:
    """Shorthand for a single CFN resource entry."""
    entry = {"Type": rtype, "Properties": properties}
    entry.update(attrs)
    return entry
