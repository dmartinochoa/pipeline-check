"""Shared S3 artifact-bucket enumeration for the S3-* Terraform rules.

The S3 rules all care about the same set of buckets: those declared as
``aws_codepipeline.artifact_store[*].location``. Each rule additionally
needs a ``bucket → side-resource.values`` index for its specific
``aws_s3_bucket_*`` resource type. Centralizing the discovery here
keeps each rule's ``check(ctx)`` short.

Underscore-prefixed so :func:`discover_rules` skips it.
"""
from __future__ import annotations

from typing import Any

from ..base import TerraformContext


def artifact_buckets(ctx: TerraformContext) -> set[str]:
    """Return the set of bucket names used as pipeline artifact stores."""
    buckets: set[str] = set()
    for r in ctx.resources("aws_codepipeline"):
        for store in r.values.get("artifact_store", []) or []:
            loc = store.get("location")
            if loc:
                buckets.add(loc)
    return buckets


def index_by_bucket(
    ctx: TerraformContext, resource_type: str,
) -> dict[str, dict[str, Any]]:
    """Index resources of *resource_type* by their ``bucket`` attribute."""
    out: dict[str, dict[str, Any]] = {}
    for r in ctx.resources(resource_type):
        bucket = r.values.get("bucket")
        if bucket:
            out[bucket] = r.values
    return out


def bucket_resource_values(
    ctx: TerraformContext, bucket_name: str,
) -> dict[str, Any] | None:
    """Return the ``aws_s3_bucket`` values whose ``bucket`` matches, else
    ``None``.

    Used for the AWS-provider-v3 fallback: versioning / encryption /
    logging were inline blocks on ``aws_s3_bucket`` before the v4 split
    into standalone ``aws_s3_bucket_*`` resources. Stacks still pinned to
    v3 parse fine but have no standalone side-resource to join, so the
    S3-002/003/004 rules would false-fire; they consult the inline block
    here before failing.
    """
    for r in ctx.resources("aws_s3_bucket"):
        if r.values.get("bucket") == bucket_name:
            return r.values
    return None


def _first_block(value: object) -> dict[str, Any]:
    """First dict of a Terraform block list, or ``{}``."""
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return value[0]
    return {}


def has_unresolved_bucket(
    ctx: TerraformContext, resource_type: str,
) -> bool:
    """Whether any resource of *resource_type* has an unusable ``bucket``.

    On a ``terraform plan`` that creates the bucket in the same run, the
    side-resource's ``bucket = aws_s3_bucket.x.id`` is a computed value
    that ``planned_values`` omits, so :func:`index_by_bucket` can't key
    it and the artifact-bucket join silently misses. When that happens
    the caller can't prove the bucket is misconfigured, so it should
    report "could not correlate" rather than a hard failure. Returns
    ``True`` when at least one resource of the type carries no usable
    (non-empty string) ``bucket`` value.
    """
    for r in ctx.resources(resource_type):
        bucket = r.values.get("bucket")
        if not (isinstance(bucket, str) and bucket):
            return True
    return False
