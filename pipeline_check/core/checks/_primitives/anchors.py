"""Canonicalizers for :class:`ResourceAnchor` construction.

The cross-provider chain engine intersects findings by
``(ResourceAnchor.kind, ResourceAnchor.identity)``. That works only
when both legs of a chain emit the *same canonical string* for the
same logical resource. Hand-rolling normalization per rule
guarantees drift (one rule lowercases account IDs, another
preserves case; one strips the registry host from an ECR repo URI,
another doesn't). Concentrating it here means every rule that
needs to reference a role / repo / SA goes through one helper.

Each helper returns either a :class:`ResourceAnchor` or ``None``
when the input is too partial to canonicalize. The rule then drops
the anchor entry rather than emit a half-formed one that would
silently miss in a chain intersection.

Kinds (locked vocabulary, additions require a versioned changelog
entry just like ``Severity`` / ``Confidence``):

* ``iam_role`` — full ARN
  (``arn:aws:iam::<account>:role/<name>``)
* ``iam_role_name`` — bare role name when the ARN isn't resolvable
* ``ecr_repo`` — full registry URI
  (``<account>.dkr.ecr.<region>.amazonaws.com/<repo>``)
* ``lambda_fn`` — full ARN
  (``arn:aws:lambda:<region>:<account>:function:<name>``)
* ``k8s_sa`` — ``<namespace>/<name>``; namespace defaults to
  ``default`` when omitted (matches kubectl semantics)
* ``oci_image`` — ``<registry>/<repo>`` with tag stripped (image
  identity is its repo, not its tag — chains that need tag-level
  reasoning model that separately)
"""
from __future__ import annotations

import re

from ..base import ResourceAnchor

# ── IAM role ───────────────────────────────────────────────────────

# Strict shape for an IAM role ARN. We deliberately do not relax this
# to "any string starting with arn:" — a malformed ARN that happens
# to share a prefix with a real one would silently match in a chain
# intersection, which is worse than emitting no anchor.
_IAM_ROLE_ARN_RE = re.compile(
    r"^arn:(?P<partition>aws|aws-cn|aws-us-gov):iam::"
    r"(?P<account>\d{12}):role/(?P<name>[\w+=,.@/-]+)$"
)

# A bare role name as it would appear in a workflow's
# ``role-to-assume`` input or an IAM ``RoleName`` field.
_IAM_ROLE_NAME_RE = re.compile(r"^[\w+=,.@-]+$")


def iam_role(
    arn: str,
) -> ResourceAnchor | None:
    """Build an ``iam_role`` anchor from a full ARN.

    Returns ``None`` when *arn* isn't a recognized role-ARN shape.
    The canonical identity is the ARN verbatim — IAM ARNs are
    case-sensitive in the role-name suffix, so we preserve case;
    the account ID and partition are already canonical.
    """
    if not isinstance(arn, str):
        return None
    arn = arn.strip()
    if not _IAM_ROLE_ARN_RE.match(arn):
        return None
    return ResourceAnchor(kind="iam_role", identity=arn)


def iam_role_name(name: str) -> ResourceAnchor | None:
    """Build an ``iam_role_name`` anchor from a bare role name.

    Used when a rule has the role name but can't resolve the account
    ID and partition — typically a workflow's ``role-to-assume:
    deploy-admin`` short form. Cross-provider chains that need to
    intersect partial against full forms have to opt in to the
    looser kind explicitly; we don't fuzzy-match from
    ``iam_role_name`` to ``iam_role``.
    """
    if not isinstance(name, str):
        return None
    name = name.strip()
    if not name or not _IAM_ROLE_NAME_RE.match(name):
        return None
    return ResourceAnchor(kind="iam_role_name", identity=name)


# ── ECR repo ───────────────────────────────────────────────────────

# Full ECR URI: <account>.dkr.ecr.<region>.amazonaws.com/<repo>
# Repo path can include slashes (namespaced repos: ``team-a/svc``).
_ECR_URI_RE = re.compile(
    r"^(?P<account>\d{12})\.dkr\.ecr\."
    r"(?P<region>[a-z0-9-]+)\.amazonaws\.com"
    r"/(?P<repo>[a-z0-9._/-]+)$"
)


def ecr_repo(
    uri: str,
) -> ResourceAnchor | None:
    """Build an ``ecr_repo`` anchor from a full registry URI.

    Returns ``None`` for short forms (``my-repo``) — those would
    silently match across accounts and aren't safe as a chain
    anchor. A rule that has only the short form should skip the
    anchor; the chain falls back to co-occurrence.
    """
    if not isinstance(uri, str):
        return None
    uri = uri.strip()
    # Strip ``@sha256:digest`` first because digests contain both
    # ``@`` and ``:`` — splitting on ``:`` first would chop the URI
    # in the wrong place. Tag (``:tag``) comes second.
    if "@" in uri:
        uri = uri.split("@", 1)[0]
    if ":" in uri:
        uri = uri.split(":", 1)[0]
    if not _ECR_URI_RE.match(uri):
        return None
    return ResourceAnchor(kind="ecr_repo", identity=uri)


# ── Lambda function ────────────────────────────────────────────────

_LAMBDA_ARN_RE = re.compile(
    r"^arn:(?P<partition>aws|aws-cn|aws-us-gov):lambda:"
    r"(?P<region>[a-z0-9-]+):"
    r"(?P<account>\d{12}):function:"
    r"(?P<name>[a-zA-Z0-9-_]+)"
    r"(?::(?P<qualifier>[a-zA-Z0-9$-_]+))?$"
)


def lambda_fn(arn: str) -> ResourceAnchor | None:
    """Build a ``lambda_fn`` anchor from a function ARN.

    Strips the optional ``:<qualifier>`` suffix (alias / version)
    because the function identity is its name, not its alias —
    multiple aliases point at the same function, and chains
    reasoning about "this function's role" need to agree across
    aliases.
    """
    if not isinstance(arn, str):
        return None
    arn = arn.strip()
    m = _LAMBDA_ARN_RE.match(arn)
    if m is None:
        return None
    # Reconstruct without the qualifier so two callers — one with an
    # alias-qualified ARN, one without — still meet at the same
    # canonical identity.
    canonical = (
        f"arn:{m.group('partition')}:lambda:{m.group('region')}:"
        f"{m.group('account')}:function:{m.group('name')}"
    )
    return ResourceAnchor(kind="lambda_fn", identity=canonical)


# ── Kubernetes ServiceAccount ──────────────────────────────────────

# K8s names: lowercase RFC 1123 labels separated by dots, up to 253
# chars. We don't enforce the full RFC here — the loader already
# accepted the manifest — but reject anything obviously not a name.
_K8S_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")


def k8s_sa(
    namespace: str | None,
    name: str,
) -> ResourceAnchor | None:
    """Build a ``k8s_sa`` anchor.

    Canonical identity is ``<namespace>/<name>``; namespace defaults
    to ``default`` when omitted, matching kubectl semantics. Always
    carries the namespace because most RBAC is namespace-scoped;
    cluster-scoped RBAC (ClusterRoleBinding subjects) still names
    the SA by ``(namespace, name)``, so the chain meets in the
    middle.
    """
    if not isinstance(name, str):
        return None
    name = name.strip()
    if not name or not _K8S_NAME_RE.match(name):
        return None
    if namespace is None or namespace == "":
        ns = "default"
    elif isinstance(namespace, str):
        ns = namespace.strip()
        if not _K8S_NAME_RE.match(ns):
            return None
    else:
        return None
    return ResourceAnchor(kind="k8s_sa", identity=f"{ns}/{name}")


# ── OCI image ─────────────────────────────────────────────────────

# Image references are gnarly. The shape we accept:
#   [registry/]repo[:tag|@sha256:digest]
# Registry is the part before the first slash IFF it contains a "."
# or ":" (matches Docker's heuristic for distinguishing
# ``library/redis`` from ``registry.example.com/redis``).
_DIGEST_RE = re.compile(r"@sha[0-9]+:[a-f0-9]+$")


def oci_image(ref: str) -> ResourceAnchor | None:
    """Build an ``oci_image`` anchor from an image reference.

    Strips the ``:tag`` / ``@sha256:digest`` suffix so the identity
    is the repo. A chain that wants tag-level reasoning (mutable
    tag detection) models that on top of separate evidence; the
    anchor here is "this image" in the repository sense.

    Implicit Docker Hub registries are normalized to
    ``docker.io/<repo>`` so ``redis`` and ``docker.io/redis`` meet
    at the same identity. Implicit ``library/`` namespace
    (single-component repos under Docker Hub) is also normalized:
    ``redis`` becomes ``docker.io/library/redis``.
    """
    if not isinstance(ref, str):
        return None
    ref = ref.strip()
    if not ref:
        return None
    # Strip digest first (anchored), then tag (after the LAST colon,
    # but only when the colon is in the final path component to
    # avoid mistaking a registry port for a tag).
    ref = _DIGEST_RE.sub("", ref)
    head, sep, tail = ref.rpartition("/")
    if ":" in tail:
        tail = tail.rsplit(":", 1)[0]
        ref = f"{head}{sep}{tail}" if sep else tail
    # Distinguish registry from repo path.
    first, sep, rest = ref.partition("/")
    if sep and ("." in first or ":" in first):
        registry = first.lower()
        repo = rest
    else:
        # No explicit registry. Docker Hub conventions:
        # single-component name implies ``library/<name>``.
        registry = "docker.io"
        if "/" in ref:
            repo = ref
        else:
            repo = f"library/{ref}"
    if not repo:
        return None
    return ResourceAnchor(
        kind="oci_image", identity=f"{registry}/{repo}",
    )


__all__ = [
    "iam_role",
    "iam_role_name",
    "ecr_repo",
    "lambda_fn",
    "k8s_sa",
    "oci_image",
]
