"""OCI-007. Image manifest uses legacy schemaVersion 1."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import OCIManifest

RULE = Rule(
    id="OCI-007",
    title="Image manifest uses legacy schemaVersion 1 (no content addressing)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3", "CICD-SEC-9"),
    esf=("ESF-S-IMMUTABLE", "ESF-S-PROVENANCE"),
    cwe=("CWE-345", "CWE-1104"),
    recommendation=(
        "Rebuild and re-push the image with a current builder "
        "(``docker buildx build`` / ``buildah`` / ``ko``) so the "
        "registry produces a v2 manifest with content-addressed "
        "layer descriptors. Docker Distribution v1 manifests "
        "predate the digest-pinned design that lets a client "
        "verify a pulled blob matches the manifest the registry "
        "served, so a v1 pull has no way to detect tampering "
        "between the registry and the runtime. Registries have "
        "been refusing v1 pushes for years (Docker Hub since "
        "2019, GHCR / quay.io / ECR / Artifact Registry never "
        "supported them on read), but a pre-existing v1 image "
        "can still be sitting in a private registry; the rule "
        "catches it before that image gets promoted."
    ),
    docs_note=(
        "The OCI image-spec (1.0+) and Docker Distribution v2 "
        "both encode ``schemaVersion: 2`` on every manifest. The "
        "older Docker v1 format set ``schemaVersion: 1`` and "
        "stored the rootfs as a chain of un-addressed tarballs "
        "with the chain identity hashed end-to-end at pull time. "
        "Anything below 2 is by definition a non-content-"
        "addressed manifest. The detection is a strict equality "
        "check against schemaVersion."
    ),
    known_fp=(
        "Some internal Harbor / Nexus deployments still proxy "
        "legacy Docker images that haven't been rebuilt; a pull "
        "succeeds because the proxy upgrades the manifest at "
        "request time, but the on-disk JSON if you saved it "
        "with ``inspect --raw`` may still report the original "
        "schemaVersion. If your registry is doing this in-flight "
        "promotion you can suppress; otherwise re-run the build.",
    ),
    exploit_example=(
        "# Vulnerable: ``schemaVersion: 1`` predates the digest-\n"
        "# pinned design. The client has no way to verify that the\n"
        "# pulled blobs match what the registry served; a swapped\n"
        "# blob is silently accepted. Modern registries refuse v1\n"
        "# pushes, but a pre-existing v1 image in a private\n"
        "# registry stays pullable and unverified.\n"
        "{\n"
        "  \"schemaVersion\": 1,\n"
        "  \"name\": \"myorg/legacy-app\",\n"
        "  \"tag\": \"latest\",\n"
        "  \"architecture\": \"amd64\",\n"
        "  \"fsLayers\": [\n"
        "    { \"blobSum\": \"sha256:abc123...\" }\n"
        "  ],\n"
        "  \"history\": [\n"
        "    { \"v1Compatibility\": \"...\" }\n"
        "  ]\n"
        "}\n"
        "\n"
        "# Safe: rebuild with a current builder (``docker buildx\n"
        "# build`` / ``buildah`` / ``ko``). The registry produces a\n"
        "# v2 manifest with content-addressed layer descriptors and\n"
        "# a ``config`` descriptor that pins the image config by\n"
        "# digest.\n"
        "{\n"
        "  \"schemaVersion\": 2,\n"
        "  \"mediaType\": \"application/vnd.oci.image.manifest.v1+json\",\n"
        "  \"config\": {\n"
        "    \"mediaType\": \"application/vnd.oci.image.config.v1+json\",\n"
        "    \"digest\": \"sha256:config-digest...\",\n"
        "    \"size\": 7023\n"
        "  },\n"
        "  \"layers\": [\n"
        "    {\n"
        "      \"mediaType\": \"application/vnd.oci.image.layer.v1.tar+gzip\",\n"
        "      \"digest\": \"sha256:layer-digest...\",\n"
        "      \"size\": 32654\n"
        "    }\n"
        "  ]\n"
        "}"
    ),
)


def check(manifest: OCIManifest) -> Finding:
    passed = manifest.schema_version == 2
    desc = (
        "Image manifest declares schemaVersion: 2, content "
        "addressing is intact."
        if passed else
        f"Image manifest declares schemaVersion: "
        f"{manifest.schema_version}, the legacy Docker v1 "
        "format. Pulled bytes are not content-addressed."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=manifest.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
