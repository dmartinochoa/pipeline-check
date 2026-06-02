"""S3-005 (CloudFormation). Artifact bucket has no SecureTransport deny."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import CloudFormationContext
from ..s3 import _s3005_secure_transport
from ._s3_context import discover_targets

RULE = Rule(
    id="S3-005",
    title="Artifact bucket missing aws:SecureTransport deny",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-9",),
    cwe=("CWE-319",),
    recommendation=(
        "Attach an ``AWS::S3::BucketPolicy`` carrying a ``Deny`` "
        "statement on ``Action: \"s3:*\"`` when "
        "``Bool aws:SecureTransport = false``."
    ),
    docs_note=(
        "Looks for an ``AWS::S3::BucketPolicy`` joined to the "
        "artifact bucket by ``Bucket`` (literal name or "
        "``{ Ref: <BucketLogicalId> }``). Parses the policy and "
        "scans for any ``Deny`` statement whose ``Condition`` "
        "matches ``aws:SecureTransport = false``."
    ),
    exploit_example=(
        "# Vulnerable: a pipeline artifact bucket with no BucketPolicy\n"
        "# denying plaintext transport. An on-path attacker can read or\n"
        "# swap artifacts fetched over http:// before the next stage.\n"
        "Resources:\n"
        "  ArtifactBucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      BucketName: my-pipeline-artifacts\n"
        "  Pipeline:\n"
        "    Type: AWS::CodePipeline::Pipeline\n"
        "    Properties:\n"
        "      RoleArn: arn:aws:iam::123456789012:role/PipelineRole\n"
        "      ArtifactStore:\n"
        "        Type: S3\n"
        "        Location: !Ref ArtifactBucket\n"
        "      Stages: []\n"
        "\n"
        "# Safe: deny every S3 action when the request did not arrive\n"
        "# over TLS.\n"
        "Resources:\n"
        "  ArtifactBucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      BucketName: my-pipeline-artifacts\n"
        "  Pipeline:\n"
        "    Type: AWS::CodePipeline::Pipeline\n"
        "    Properties:\n"
        "      RoleArn: arn:aws:iam::123456789012:role/PipelineRole\n"
        "      ArtifactStore:\n"
        "        Type: S3\n"
        "        Location: !Ref ArtifactBucket\n"
        "      Stages: []\n"
        "  BucketPolicy:\n"
        "    Type: AWS::S3::BucketPolicy\n"
        "    Properties:\n"
        "      Bucket: !Ref ArtifactBucket\n"
        "      PolicyDocument:\n"
        "        Version: \"2012-10-17\"\n"
        "        Statement:\n"
        "          - Effect: Deny\n"
        "            Principal: \"*\"\n"
        "            Action: \"s3:*\"\n"
        "            Resource:\n"
        "              - !GetAtt ArtifactBucket.Arn\n"
        "              - !Sub \"${ArtifactBucket.Arn}/*\"\n"
        "            Condition:\n"
        "              Bool:\n"
        "                aws:SecureTransport: \"false\""
    ),
)


def check(ctx: CloudFormationContext) -> list[Finding]:
    return [
        _s3005_secure_transport(policy, name)
        for name, _, policy in discover_targets(ctx)
    ]
