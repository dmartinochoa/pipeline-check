"""Shared S3 artifact-bucket enumeration for the S3-* CloudFormation rules.

Discovers pipeline artifact buckets via ``ArtifactStore.Location`` /
``ArtifactStores[*].Location`` references, then indexes
``AWS::S3::Bucket`` and ``AWS::S3::BucketPolicy`` resources so each
rule can pull the relevant properties + policy in one shot.

Underscore-prefixed so :func:`discover_rules` skips it.
"""
from __future__ import annotations

from typing import Any

from ..base import CloudFormationContext, CloudFormationResource, as_str
from ..s3 import _target_key


def discover_targets(
    ctx: CloudFormationContext,
) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    """Return ``[(bucket_name, bucket_props, policy_props), …]`` for every
    pipeline artifact bucket.
    """
    targets: set[str] = set()
    for r in ctx.resources("AWS::CodePipeline::Pipeline"):
        single = r.properties.get("ArtifactStore") or {}
        key = _target_key(single.get("Location"))
        if key:
            targets.add(key)
        plural = r.properties.get("ArtifactStores") or []
        if isinstance(plural, list):
            for entry in plural:
                if not isinstance(entry, dict):
                    continue
                store = entry.get("ArtifactStore") or {}
                key = _target_key(store.get("Location"))
                if key:
                    targets.add(key)
    if not targets:
        return []

    bucket_by_name: dict[str, CloudFormationResource] = {}
    for b in ctx.resources("AWS::S3::Bucket"):
        if lit := as_str(b.properties.get("BucketName")):
            bucket_by_name[lit] = b
        bucket_by_name[b.logical_id] = b

    policies_by_bucket: dict[str, dict[str, Any]] = {}
    for p in ctx.resources("AWS::S3::BucketPolicy"):
        key = _target_key(p.properties.get("Bucket"))
        if key:
            policies_by_bucket[key] = p.properties

    out: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    for tgt in sorted(targets):
        bucket = bucket_by_name.get(tgt)
        props = bucket.properties if bucket else {}
        bucket_name = as_str(props.get("BucketName")) or tgt
        policy_props = (
            policies_by_bucket.get(tgt) or policies_by_bucket.get(bucket_name) or {}
        )
        out.append((bucket_name, props, policy_props))
    return out
