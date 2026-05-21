"""ECR-002. ECR repository has mutable image tags."""
from __future__ import annotations

from ..._primitives.anchors import ecr_repo
from ...base import Finding, ResourceAnchor, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="ECR-002",
    title="Image tags are mutable",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-494",),
    recommendation=(
        "Set imageTagMutability=IMMUTABLE on the repository. Reference images "
        "by digest (sha256:...) in deployment manifests for strongest "
        "immutability guarantees."
    ),
    docs_note=(
        "Mutable tags mean ``:latest``, ``:v1.0``, and ``:stable`` "
        "can be re-pushed silently, the same tag points to different "
        "image content over time. Pinning by digest (``sha256:...``) "
        "in deployment manifests is the only durable reference; "
        "IMMUTABLE on the repo enforces the property registry-side "
        "so a forgotten digest reference doesn't drift."
    ),
    exploit_example=(
        "# Vulnerable: ECR repo with ``imageTagMutability:\n"
        "# MUTABLE``. Anyone with ``ecr:PutImage`` (build role,\n"
        "# CI/CD credential, leaked token) can push a different\n"
        "# image under the same tag, silently swapping what\n"
        "# downstream consumers pull next.\n"
        "import boto3\n"
        "ecr = boto3.client('ecr')\n"
        "ecr.create_repository(\n"
        "    repositoryName='myapp',\n"
        "    imageTagMutability='MUTABLE',\n"
        ")\n"
        "\n"
        "# Safe: ``IMMUTABLE``. Tags can only be pushed once;\n"
        "# re-pushing the same tag fails. Updates ship as a new\n"
        "# version tag (and the digest never collides), forcing\n"
        "# downstream consumers to explicitly bump.\n"
        "ecr.put_image_tag_mutability(\n"
        "    repositoryName='myapp',\n"
        "    imageTagMutability='IMMUTABLE',\n"
        ")"
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for repo in catalog.ecr_repositories():
        name = repo.get("repositoryName", "<unnamed>")
        mutability = repo.get("imageTagMutability", "MUTABLE")
        passed = mutability == "IMMUTABLE"
        if passed:
            desc = "Image tags are immutable, pushed tags cannot be overwritten."
        else:
            desc = (
                "Image tag mutability is MUTABLE. Any principal with ecr:PutImage "
                "can silently overwrite a tag (e.g. :latest or a semver tag), "
                "allowing a malicious or accidental image swap to affect deployments "
                "that pull by tag without verifying a digest."
            )
        # ResourceAnchor phase 1: emit the canonical ECR registry URI
        # (e.g. ``123456789012.dkr.ecr.us-east-1.amazonaws.com/myapp``)
        # so AC-017 can intersect with workflow-side push targets, and
        # any future cross-provider chain keyed on ``ecr_repo`` lands
        # on the same canonical identity. boto3's
        # describe_repositories already returns ``repositoryUri`` in
        # the full registry-URI shape.
        anchors: tuple[ResourceAnchor, ...] = ()
        uri = repo.get("repositoryUri")
        if isinstance(uri, str):
            built = ecr_repo(uri)
            if built is not None:
                anchors = (built,)
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=passed,
            resource_anchors=anchors,
        ))
    return findings
