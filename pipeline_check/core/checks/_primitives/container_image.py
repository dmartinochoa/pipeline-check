"""Container-image reference classifier.

Every provider that scans CodeBuild (AWS runtime, Terraform, CFN)
evaluates the same question about ``aws_codebuild_project.environment.image``:

1. Is this an AWS-managed image? (``aws/codebuild/standard:X.Y``)
2. Is it pinned by digest (``@sha256:<64 hex>``)?
3. Is it pulled from a trusted registry? (ECR, public.ecr.aws, etc.)

The structural decomposition (registry / repo / tag / digest) lives
in :mod:`image_ref`. This module owns the domain verdict:
AWS-managed shortform, trusted-registry membership, and the pinning
rule used by AWS / Terraform / CloudFormation rules (tag-only is
acceptable for trusted registries; only digest or AWS-managed
counts as ``pinned`` everywhere else).

The classifier is deliberately pure, no I/O, no registry calls.
``classify(ref)`` returns a dataclass the caller can render however it
wants.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .image_ref import parse_image_ref

_AWS_MANAGED_RE = re.compile(r"^aws/codebuild/")

# Registries whose contents are signed + maintained by the vendor and
# where tag-pinning is an acceptable trade-off for readability. Matches
# the trusted-upstream list used by ECR-006 so the two rules agree on
# what "reputable" means.
_TRUSTED_REGISTRY_HOSTS = frozenset({
    "public.ecr.aws",
    "registry.k8s.io",
    "ghcr.io",
    "gcr.io",
})


@dataclass(frozen=True, slots=True)
class ImageInfo:
    """Parsed view of a container-image reference.

    ``pinned`` is True for AWS-managed images (AWS controls the pull-
    through semantics), digest-pinned references, and empty refs (the
    caller's pinning rule has nothing to score). Other tag-only refs,
    even from a trusted registry, are not pinned; the trusted-registry
    flag is separate information the rule can use to downgrade severity
    if it chooses.
    """

    ref: str
    aws_managed: bool
    digest: str | None
    trusted_registry: bool
    pinned: bool
    tag: str = ""
    registry: str = ""


def classify(ref: str | None) -> ImageInfo:
    """Parse *ref* (a CodeBuild ``Image`` / Docker ref) into its pin facts."""
    parsed = parse_image_ref(ref)
    if parsed is None:
        return ImageInfo(
            ref="", aws_managed=False, digest=None,
            trusted_registry=False, pinned=True,
        )
    aws_managed = bool(_AWS_MANAGED_RE.match(parsed.raw))
    digest = parsed.digest_hex if parsed.is_digest_pinned else None
    trusted = parsed.registry in _TRUSTED_REGISTRY_HOSTS
    pinned = aws_managed or bool(digest)
    # Surface ``registry`` matches the prior behavior: dot-bearing
    # hostnames only. ``localhost`` / port-only registries deliberately
    # return "" so existing callers that branch on truthiness keep
    # their semantics. AWS-managed shortforms also return "".
    surface_registry = (
        parsed.registry if not aws_managed and "." in parsed.registry else ""
    )
    # ``tag`` is intentionally blank when a digest pin is present;
    # callers that need both fields read them off :func:`parse_image_ref`
    # directly.
    surface_tag = "" if digest else parsed.tag
    return ImageInfo(
        ref=parsed.raw,
        aws_managed=aws_managed,
        digest=digest,
        trusted_registry=trusted,
        pinned=pinned,
        tag=surface_tag,
        registry=surface_registry,
    )
