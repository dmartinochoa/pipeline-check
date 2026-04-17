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
    # Use the real constructor so parameter-default extraction runs.
    return CloudFormationContext([("<in-memory>", template)])


def r(logical_id: str, rtype: str, properties: dict, **attrs) -> dict:
    """Shorthand for a single CFN resource entry."""
    entry = {"Type": rtype, "Properties": properties}
    entry.update(attrs)
    return entry
