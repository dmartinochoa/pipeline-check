"""ECR-001. ECR repository has imageScanningConfiguration.scanOnPush disabled."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="ECR-001",
    title="Image scanning on push not enabled",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    cwe=("CWE-1104",),
    recommendation=(
        "Enable imageScanningConfiguration.scanOnPush on the repository. "
        "Consider also enabling Amazon Inspector continuous scanning for "
        "ongoing CVE detection against images already in the registry."
    ),
    docs_note=(
        "scan-on-push runs a CVE check against the image's OS "
        "package layers at the moment it lands in ECR. Without it, "
        "an image with a known CVE deploys silently. The ECR basic "
        "scanner is free; ECR-007 covers the Inspector v2 enhanced "
        "scanner that adds language-ecosystem CVEs (npm, pip, gem)."
    ),
    exploit_example=(
        "# Vulnerable: ECR repo with ``imageScanningConfiguration.\n"
        "# scanOnPush: false``. Every pushed image lands without\n"
        "# a vulnerability scan; the registry's downstream consumers\n"
        "# pull whatever CVE-laden base layer the build produced.\n"
        "import boto3\n"
        "ecr = boto3.client('ecr')\n"
        "ecr.create_repository(\n"
        "    repositoryName='myapp',\n"
        "    imageScanningConfiguration={'scanOnPush': False},\n"
        ")\n"
        "\n"
        "# Safe: enable scan-on-push. Pair with Inspector v2\n"
        "# enhanced scanning (ECR-007) for continuous re-scans\n"
        "# against the latest CVE database. Block deploys on\n"
        "# scan failures via an Inspector finding -> EventBridge\n"
        "# -> CodePipeline gate.\n"
        "ecr.put_image_scanning_configuration(\n"
        "    repositoryName='myapp',\n"
        "    imageScanningConfiguration={'scanOnPush': True},\n"
        ")\n"
        "# Enable enhanced scanning org-wide:\n"
        "inspector = boto3.client('inspector2')\n"
        "inspector.enable(resourceTypes=['ECR'])"
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    findings: list[Finding] = []
    for repo in catalog.ecr_repositories():
        name = repo.get("repositoryName", "<unnamed>")
        enabled = (repo.get("imageScanningConfiguration") or {}).get("scanOnPush", False)
        if enabled:
            desc = "Image scanning on push is enabled."
        else:
            desc = (
                "Image scanning on push is disabled. Vulnerabilities in base images "
                "or dependencies will not be detected when images are pushed, allowing "
                "unvetted images to propagate through the pipeline."
            )
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name, description=desc,
            recommendation=RULE.recommendation, passed=bool(enabled),
        ))
    return findings
