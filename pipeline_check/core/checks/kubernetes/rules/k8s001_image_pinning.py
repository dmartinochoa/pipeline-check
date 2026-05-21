"""K8S-001. Container image not pinned by ``@sha256:<digest>``."""
from __future__ import annotations

from ..._primitives.anchors import oci_image
from ..._primitives.image_pinning import PinKind, classify
from ..._yaml_lines import line_of as _line_of
from ...base import Finding, Location, ResourceAnchor, Severity
from ...rule import Rule
from ..base import (
    KubernetesContext,
    container_name,
    iter_containers,
    iter_workload_pod_specs,
)

RULE = Rule(
    id="K8S-001",
    title="Container image not pinned by sha256 digest",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-IMMUTABLE", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "Resolve every workload container image to its current digest "
        "(``crane digest <ref>`` or ``docker buildx imagetools inspect``) "
        "and pin via ``image: repo@sha256:<digest>``. Floating tags "
        "(``:latest``, ``:3``, no tag) silently swap the running image "
        "on the next rollout, breaking provenance and reproducibility."
    ),
    docs_note=(
        "Reuses ``_primitives.image_pinning.classify`` so the floating-"
        "tag semantics match DF-001 / GL-001 / JF-009 / ADO-009 / "
        "CC-003. Even a ``PINNED_TAG`` like ``nginx:1.25.4`` is treated "
        "as unpinned, only an explicit ``@sha256:`` survives, since "
        "a tag is mutable on the registry side and Kubernetes will "
        "happily pull the new content on a node restart."
    ),
    exploit_example=(
        "# Vulnerable: ``image: nginx:1.25`` is a mutable tag.\n"
        "# Docker Hub's nginx team rebuilds it on every point\n"
        "# release; a publisher takeover repoints the tag\n"
        "# silently and every Pod that uses it picks up the\n"
        "# substituted image on the next scheduling decision.\n"
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata: { name: web }\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: nginx\n"
        "          image: nginx:1.25\n"
        "\n"
        "# Safe: pin to the content-addressable digest. The\n"
        "# kubelet refuses to start the Pod if the image's\n"
        "# digest doesn't match the manifest.\n"
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata: { name: web }\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: nginx\n"
        "          image: nginx@sha256:abc123...   # nginx:1.25.4"
    ),
)


def check(ctx: KubernetesContext) -> Finding:
    unpinned: list[str] = []
    locations: list[Location] = []
    anchors: list[ResourceAnchor] = []
    seen_identities: set[str] = set()
    for m, ps in iter_workload_pod_specs(ctx):
        for kind, c in iter_containers(ps):
            image = c.get("image")
            if not isinstance(image, str):
                continue
            pin = classify(image)
            if pin is PinKind.DIGEST:
                continue
            unpinned.append(
                f"{m.kind}/{m.name} {kind}={container_name(c)}: "
                f"{image} ({pin.value})"
            )
            line = _line_of(c) if isinstance(c, dict) else None
            locations.append(Location(
                path=m.path, start_line=line, end_line=line,
                doc_index=m.doc_index,
            ))
            # ResourceAnchor phase 1: XPC-002 intersects DF-001 and
            # K8S-001 on the canonical ``oci_image`` identity so the
            # chain confirms when the same image is unpinned at both
            # the base-image and runtime-workload boundaries.
            anchor = oci_image(image)
            if anchor is not None and anchor.identity not in seen_identities:
                seen_identities.add(anchor.identity)
                anchors.append(anchor)
    passed = not unpinned
    desc = (
        "Every workload container image is pinned by sha256 digest."
        if passed else
        f"{len(unpinned)} container image(s) are not digest-pinned: "
        f"{', '.join(unpinned[:5])}"
        f"{'…' if len(unpinned) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource="kubernetes/manifests",
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
        resource_anchors=tuple(anchors) if not passed else (),
    )
