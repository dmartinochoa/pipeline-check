"""Container-image reference classifier.

Every provider that scans CodeBuild (AWS runtime, Terraform, CFN)
evaluates the same question about ``aws_codebuild_project.environment.image``:

1. Is this an AWS-managed image? (``aws/codebuild/standard:X.Y``)
2. Is it pinned by digest (``@sha256:<64 hex>``)?
3. Is it pulled from a trusted registry? (ECR, public.ecr.aws, etc.)

Prior to this primitive, each provider carried its own copy of
``_AWS_MANAGED_RE`` / ``_DIGEST_RE`` and interpreted them slightly
differently. Consolidating here means (a) a registry or regex update
lands everywhere at once, and (b) workflow providers that later
grow a CodeBuild-style pinning rule can reuse the classifier without
re-litigating the managed-image or trusted-registry list.

The classifier is deliberately pure — no I/O, no registry calls.
``classify(ref)`` returns a dataclass the caller can render however it
wants.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_DIGEST_RE = re.compile(r"@sha256:([0-9a-f]{64})$")
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


@dataclass(frozen=True)
class ImageInfo:
    """Parsed view of a container-image reference.

    ``pinned`` is True for AWS-managed images (AWS controls the pull-
    through semantics), digest-pinned references, and empty refs (the
    caller's pinning rule has nothing to score). Other tag-only refs —
    even from a trusted registry — are not pinned; the trusted-registry
    flag is separate information the rule can use to downgrade severity
    if it chooses.
    """

    ref: str
    aws_managed: bool
    digest: str | None
    trusted_registry: bool
    pinned: bool

    @property
    def tag(self) -> str:
        """The ``:tag`` component, or ``""`` for digest/unscoped refs."""
        if self.digest:
            return ""
        base = self.ref.split("@", 1)[0]
        # Only split on ``:`` after the last ``/`` — a registry host with
        # a port (``registry:5000/repo:v1``) would otherwise mis-split.
        _, _, rest = base.rpartition("/")
        if ":" in rest:
            return rest.split(":", 1)[1]
        return ""

    @property
    def registry(self) -> str:
        """Registry host, or ``""`` when the ref is an AWS-managed shortform or bare repo name."""
        if self.aws_managed:
            return ""
        host, sep, _ = self.ref.partition("/")
        # A ref like ``python:3.11`` has no ``/`` — treat as Docker Hub
        # short form with no explicit registry. ``public.ecr.aws/X/Y``
        # and ``ghcr.io/org/img`` both have a ``.`` in the first segment,
        # which is how Docker's own parser distinguishes the two cases.
        if not sep or "." not in host:
            return ""
        return host


def classify(ref: str | None) -> ImageInfo:
    """Parse *ref* (a CodeBuild ``Image`` / Docker ref) into its pin facts."""
    ref = (ref or "").strip()
    if not ref:
        return ImageInfo(
            ref="", aws_managed=False, digest=None,
            trusted_registry=False, pinned=True,
        )
    aws_managed = bool(_AWS_MANAGED_RE.match(ref))
    digest_match = _DIGEST_RE.search(ref)
    digest = digest_match.group(1) if digest_match else None
    host, sep, _ = ref.partition("/")
    trusted = bool(sep) and host in _TRUSTED_REGISTRY_HOSTS
    pinned = aws_managed or bool(digest)
    return ImageInfo(
        ref=ref,
        aws_managed=aws_managed,
        digest=digest,
        trusted_registry=trusted,
        pinned=pinned,
    )
