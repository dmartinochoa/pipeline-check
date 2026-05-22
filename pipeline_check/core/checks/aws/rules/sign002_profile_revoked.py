"""SIGN-002. Signing profile is revoked or expired."""
from __future__ import annotations

from botocore.exceptions import ClientError

from ...base import Finding, Severity
from ...rule import Rule
from .._catalog import ResourceCatalog

RULE = Rule(
    id="SIGN-002",
    title="AWS Signer profile is revoked or inactive",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-347",),
    recommendation=(
        "Rotate the signing profile: create a replacement and update every "
        "code-signing config that references the revoked profile. A "
        "revoked or canceled profile invalidates every signature it "
        "produced, lambdas relying on it will fail verification."
    ),
    docs_note=(
        "A revoked or canceled Signer profile invalidates every "
        "signature it ever produced. Lambda functions configured "
        "to enforce code-signing fail to deploy until the profile "
        "is replaced (or, if ``UntrustedArtifactOnDeployment = "
        "Warn``, deploy with a CloudWatch warning the operator "
        "rarely reads)."
    ),
    exploit_example=(
        "# Vulnerable: AWS Signer profile is revoked or\n"
        "# inactive. Code-signing pipelines that route through\n"
        "# this profile silently fail (or fall back to\n"
        "# unsigned artifacts if the gate is permissive); the\n"
        "# unsigned artifacts then deploy without integrity\n"
        "# verification.\n"
        "import boto3\n"
        "signer = boto3.client('signer')\n"
        "signer.get_signing_profile(profileName='prod-lambda-signer')\n"
        "# {'status': 'Revoked', 'statusReason': 'compromise suspected'}\n"
        "\n"
        "# Safe: investigate the revocation, rotate to a new\n"
        "# profile if compromise is confirmed, or restore the\n"
        "# original if revoked in error. Either way, the\n"
        "# downstream pipeline reference (CodeSigningConfig on\n"
        "# Lambdas) must be updated to point at the active\n"
        "# profile so signed deploys resume.\n"
        "new_prof = signer.put_signing_profile(\n"
        "    profileName='prod-lambda-signer-v2',\n"
        "    platformId='AWSLambda-SHA384-ECDSA',\n"
        ")\n"
        "lambdacli = boto3.client('lambda')\n"
        "lambdacli.update_code_signing_config(\n"
        "    CodeSigningConfigArn='arn:aws:lambda:us-east-1:123:code-signing-config:csc-...',\n"
        "    AllowedPublishers={\n"
        "        'SigningProfileVersionArns': [new_prof['profileVersionArn']]\n"
        "    },\n"
        ")"
    ),
)


def check(catalog: ResourceCatalog) -> list[Finding]:
    try:
        client = catalog.client("signer")
    except Exception:
        return []
    try:
        resp = client.list_signing_profiles(includeCanceled=True)
    except ClientError:
        return []
    findings: list[Finding] = []
    for profile in resp.get("profiles", []):
        status = (profile.get("status") or "").lower()
        name = profile.get("profileName", "<unnamed>")
        if status in ("active",):
            continue
        findings.append(Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=name,
            description=f"Signing profile '{name}' status is {status or 'unknown'}.",
            recommendation=RULE.recommendation, passed=False,
        ))
    return findings
