"""AWS rule orchestrator — runs every rule under ``aws/rules/``.

Mirrors the GitHub/GitLab/etc rule-based providers: a single orchestrator
class auto-discovers rules, hands each one a shared
:class:`ResourceCatalog`, and collects findings. The existing class-based
service modules (CodeBuildChecks, IAMChecks, etc.) stay untouched; new
checks land here as one-file-per-rule modules.

Degraded findings: each rule calls catalog methods that record an error
per service on failure. After every rule has run, the orchestrator emits
a single ``<SERVICE>-000`` finding per service that had an error, instead
of every dependent rule emitting its own copy.
"""
from __future__ import annotations

from ..base import Finding, Severity
from ..rule import discover_rules
from ._catalog import ResourceCatalog
from .base import AWSBaseCheck

#: Rule id prefix -> catalog service tag. Used to attribute rule
#: crashes to the right service for degraded-finding emission.
_RULE_PREFIX_TO_SERVICE: dict[str, str] = {
    "CB": "codebuild",
    "CP": "codepipeline",
    "CD": "codedeploy",
    "CT": "cloudtrail",
    "CWL": "logs",
    "SM": "secretsmanager",
    "IAM": "iam",
    "CA": "codeartifact",
    "CCM": "codecommit",
    "LMB": "lambda",
    "KMS": "kms",
    "SSM": "ssm",
    "ECR": "ecr",
    "EB": "events",
    # PBAC rules inspect CodeBuild VPC/role posture, so errors route there.
    "PBAC": "codebuild",
    "S3": "s3",
}


#: Map catalog service tag -> (degraded-finding check id, human-readable
#: label, recommendation).
_DEGRADED: dict[str, tuple[str, str, str]] = {
    "codebuild": (
        "CB-000",
        "CodeBuild",
        "Ensure codebuild:ListProjects and codebuild:BatchGetProjects are allowed.",
    ),
    "codepipeline": (
        "CP-000",
        "CodePipeline",
        "Ensure codepipeline:ListPipelines and codepipeline:GetPipeline are allowed.",
    ),
    "cloudtrail": (
        "CT-000",
        "CloudTrail",
        "Ensure cloudtrail:DescribeTrails and cloudtrail:GetTrailStatus are allowed.",
    ),
    "logs": (
        "CWL-000",
        "CloudWatch Logs",
        "Ensure logs:DescribeLogGroups is allowed.",
    ),
    "secretsmanager": (
        "SM-000",
        "Secrets Manager",
        "Ensure secretsmanager:ListSecrets and secretsmanager:GetResourcePolicy are allowed.",
    ),
    "iam": (
        "IAM-000",
        "IAM",
        "Ensure iam:ListRoles, iam:ListUsers, iam:ListAccessKeys are allowed.",
    ),
    "codeartifact": (
        "CA-000",
        "CodeArtifact",
        "Ensure codeartifact:ListDomains, ListRepositories, and Get*Policy are allowed.",
    ),
    "codecommit": (
        "CCM-000",
        "CodeCommit",
        "Ensure codecommit:ListRepositories and GetRepository are allowed.",
    ),
    "lambda": (
        "LMB-000",
        "Lambda",
        "Ensure lambda:ListFunctions, GetFunctionUrlConfig, GetFunctionCodeSigningConfig, and GetPolicy are allowed.",
    ),
    "kms": (
        "KMS-000",
        "KMS",
        "Ensure kms:ListKeys, DescribeKey, GetKeyRotationStatus, and GetKeyPolicy are allowed.",
    ),
    "ssm": (
        "SSM-000",
        "SSM Parameter Store",
        "Ensure ssm:DescribeParameters and GetParameters are allowed.",
    ),
    "ecr": (
        "ECR-000",
        "ECR",
        "Ensure ecr:DescribePullThroughCacheRules is allowed.",
    ),
    "events": (
        "EB-000",
        "EventBridge",
        "Ensure events:ListRules and ListTargetsByRule are allowed.",
    ),
    "codedeploy": (
        "CD-000",
        "CodeDeploy",
        "Ensure codedeploy:ListApplications, ListDeploymentGroups, and "
        "BatchGetDeploymentGroups are allowed.",
    ),
    "s3": (
        "S3-000",
        "S3",
        "Ensure s3:GetBucketPublicAccessBlock, GetEncryptionConfiguration, "
        "GetBucketVersioning, GetBucketLogging, and GetBucketPolicy are allowed.",
    ),
}


class AWSRuleChecks(AWSBaseCheck):
    """Runs every rule under ``pipeline_check.core.checks.aws.rules``."""

    def __init__(self, session, target: str | None = None) -> None:
        super().__init__(session, target)
        self._rules = discover_rules("pipeline_check.core.checks.aws.rules")

    def run(self) -> list[Finding]:
        catalog = ResourceCatalog(self.session)
        # Collect (rule, batch) pairs first so we can drop findings whose
        # service errored during *any* rule's enumeration — otherwise the
        # first rule to trip an API failure emits a misleading "no
        # resources" finding alongside the subsequent degraded entry.
        pending: list[tuple[str, list[Finding]]] = []
        for rule, check_fn in self._rules:
            try:
                batch = check_fn(catalog) or []
            except Exception as exc:  # noqa: BLE001
                prefix = rule.id.split("-", 1)[0]
                svc = _RULE_PREFIX_TO_SERVICE.get(prefix, prefix.lower())
                catalog.errors.setdefault(svc, f"{type(exc).__name__}: {exc}")
                continue
            for finding in batch:
                if not finding.cwe:
                    finding.cwe = list(rule.cwe)
            pending.append((rule.id, batch))

        findings: list[Finding] = []
        degraded_services = set(catalog.errors)
        for rule_id, batch in pending:
            prefix = rule_id.split("-", 1)[0]
            svc = _RULE_PREFIX_TO_SERVICE.get(prefix)
            if svc in degraded_services:
                # Suppress this rule's output — a <PREFIX>-000 will cover it.
                continue
            findings.extend(batch)

        for svc, msg in catalog.errors.items():
            meta = _DEGRADED.get(svc)
            if meta is None:
                continue
            check_id, label, recommendation = meta
            findings.append(Finding(
                check_id=check_id,
                title=f"{label} API access failed",
                severity=Severity.INFO,
                resource=label,
                description=(
                    f"Could not enumerate {label} resources: {msg}. "
                    "Rules depending on this data were skipped."
                ),
                recommendation=recommendation,
                passed=False,
            ))
        return findings
