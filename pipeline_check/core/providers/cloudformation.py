"""CloudFormation provider — scans a CFN template (or directory).

Templates are either YAML (short-form intrinsics supported) or JSON.
Input is resolved via ``--cfn-template``; auto-detects common
top-level filenames (``template.yml``, ``template.yaml``,
``template.json``, ``cloudformation.yml``, ``cfn.yaml``) when
omitted.

To add a new CloudFormation check module
----------------------------------------
1. Create ``pipeline_check/core/checks/cloudformation/<service>.py``
   subclassing ``CloudFormationBaseCheck``.
2. Import it here and append to the ``check_classes`` property.
3. Add unit tests under ``tests/cloudformation/``.
"""
from __future__ import annotations

from typing import Any

from ..checks.base import BaseCheck
from ..checks.cloudformation.base import CloudFormationContext
from ..inventory import Component
from ..checks.cloudformation.codebuild import CodeBuildChecks
from ..checks.cloudformation.codedeploy import CodeDeployChecks
from ..checks.cloudformation.codepipeline import CodePipelineChecks
from ..checks.cloudformation.ecr import ECRChecks
from ..checks.cloudformation.extended import ExtendedChecks
from ..checks.cloudformation.iam import IAMChecks
from ..checks.cloudformation.pbac import PBACChecks
from ..checks.cloudformation.phase3 import Phase3Checks
from ..checks.cloudformation.s3 import S3Checks
from ..checks.cloudformation.services import ServiceChecks
from .base import BaseProvider


class CloudFormationProvider(BaseProvider):
    """Scans one or more CloudFormation templates."""

    NAME = "cloudformation"

    def build_context(self, cfn_template: str | None = None, **_: Any) -> CloudFormationContext:
        if not cfn_template:
            raise ValueError(
                "The cloudformation provider requires --cfn-template <path> "
                "pointing at a YAML/JSON template or a directory containing one."
            )
        return CloudFormationContext.from_path(cfn_template)

    @property
    def check_classes(self) -> list[type[BaseCheck]]:
        return [
            CodeBuildChecks,
            CodePipelineChecks,
            CodeDeployChecks,
            ECRChecks,
            IAMChecks,
            PBACChecks,
            S3Checks,
            ExtendedChecks,
            ServiceChecks,
            Phase3Checks,
        ]

    def inventory(self, context: CloudFormationContext) -> list[Component]:
        out: list[Component] = []
        for r in context.resources():
            metadata: dict = {}
            # Lifecycle attributes — protection on stack delete/replace,
            # and conditional-resource gates.
            for key in ("DeletionPolicy", "UpdateReplacePolicy", "Condition"):
                if key in r.attributes:
                    metadata[key] = r.attributes[key]
            # Tags are a top-level property on most AWS::* resources.
            tags = r.properties.get("Tags")
            if isinstance(tags, list) and tags:
                kv = {}
                for t in tags:
                    if isinstance(t, dict) and "Key" in t and "Value" in t:
                        kv[str(t["Key"])] = t["Value"]
                if kv:
                    metadata["tags"] = kv
            metadata.update(_cfn_metadata(r.type, r.properties))
            out.append(Component(
                provider=self.NAME,
                type=r.type,
                identifier=r.logical_id,
                source=r.address,
                metadata={k: v for k, v in metadata.items() if v is not None},
            ))
        return out


def _cfn_metadata(resource_type: str, props: dict) -> dict:
    """Per-CFN-type security/audit-relevant metadata extractor.

    Only fields that characterise security posture without running the
    checks. Intrinsics (``{"Ref": ...}``, ``{"Fn::GetAtt": ...}``)
    pass through as-is — consumers that understand CFN can resolve
    them; those that don't can flag the entry for manual review.
    """
    meta: dict = {}
    if resource_type == "AWS::CodeBuild::Project":
        env = props.get("Environment") or {}
        meta["image"] = env.get("Image")
        meta["compute_type"] = env.get("ComputeType")
        meta["privileged_mode"] = bool(env.get("PrivilegedMode"))
        src = props.get("Source") or {}
        meta["source_type"] = src.get("Type")
        meta["timeout_minutes"] = props.get("TimeoutInMinutes")
    elif resource_type == "AWS::CodePipeline::Pipeline":
        meta["stage_count"] = len(props.get("Stages") or [])
        meta["pipeline_type"] = props.get("PipelineType")
    elif resource_type == "AWS::IAM::Role":
        meta["permissions_boundary"] = bool(props.get("PermissionsBoundary"))
        meta["managed_policy_count"] = len(props.get("ManagedPolicyArns") or [])
        meta["inline_policy_count"] = len(props.get("Policies") or [])
    elif resource_type == "AWS::S3::Bucket":
        meta["bucket_name"] = props.get("BucketName")
        enc = ((props.get("BucketEncryption") or {}).get(
            "ServerSideEncryptionConfiguration") or [])
        if enc and isinstance(enc[0], dict):
            sse = enc[0].get("ServerSideEncryptionByDefault") or {}
            meta["sse_algorithm"] = sse.get("SSEAlgorithm")
    elif resource_type == "AWS::ECR::Repository":
        meta["tag_mutability"] = props.get("ImageTagMutability")
        scan_cfg = props.get("ImageScanningConfiguration") or {}
        meta["scan_on_push"] = bool(scan_cfg.get("ScanOnPush"))
    elif resource_type == "AWS::Lambda::Function":
        meta["runtime"] = props.get("Runtime")
        meta["handler"] = props.get("Handler")
        meta["code_signing_config_arn"] = props.get("CodeSigningConfigArn")
    elif resource_type == "AWS::KMS::Key":
        meta["key_rotation"] = bool(props.get("EnableKeyRotation"))
        meta["key_spec"] = props.get("KeySpec") or "SYMMETRIC_DEFAULT"
    elif resource_type == "AWS::CloudTrail::Trail":
        meta["multi_region"] = bool(props.get("IsMultiRegionTrail"))
        meta["log_file_validation"] = bool(props.get("EnableLogFileValidation"))
    elif resource_type == "AWS::SecretsManager::Secret":
        meta["secret_name"] = props.get("Name")
    elif resource_type == "AWS::SSM::Parameter":
        meta["parameter_type"] = props.get("Type")
    return meta
