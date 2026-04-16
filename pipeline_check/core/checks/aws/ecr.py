"""ECR security checks.

ECR-001  Image scanning on push not enabled              HIGH      CICD-SEC-3
ECR-002  Image tags are mutable                          HIGH      CICD-SEC-9
ECR-003  Repository policy allows public access          CRITICAL  CICD-SEC-8
ECR-004  No lifecycle policy configured                  LOW       CICD-SEC-7
ECR-005  Repository encrypted with AES256 rather than KMS MEDIUM    CICD-SEC-9
"""

import json

from botocore.exceptions import ClientError

from .base import AWSBaseCheck, Finding, Severity


class ECRChecks(AWSBaseCheck):

    def run(self) -> list[Finding]:
        client = self.client("ecr")

        try:
            repos = self._list_repositories(client)
        except ClientError as exc:
            return [Finding(
                check_id="ECR-000",
                title="ECR API access failed",
                severity=Severity.INFO,
                resource="ecr",
                description=f"Could not list ECR repositories: {exc}. ECR checks skipped.",
                recommendation=(
                    "Ensure the IAM principal has ecr:DescribeRepositories permission."
                ),
                passed=False,
            )]

        findings: list[Finding] = []
        for repo in repos:
            findings.extend(self._check_repo(client, repo))
        return findings

    @staticmethod
    def _list_repositories(client) -> list[dict]:
        repos: list[dict] = []
        paginator = client.get_paginator("describe_repositories")
        for page in paginator.paginate():
            repos.extend(page.get("repositories", []))
        return repos

    def _check_repo(self, client, repo: dict) -> list[Finding]:
        name = repo["repositoryName"]
        arn = repo["repositoryArn"]
        return [
            self._ecr001_scan_on_push(repo, name),
            self._ecr002_tag_mutability(repo, name),
            self._ecr003_public_policy(client, name, arn),
            self._ecr004_lifecycle_policy(client, name),
            self._ecr005_kms_encryption(repo, name),
        ]

    @staticmethod
    def _ecr005_kms_encryption(repo: dict, name: str) -> Finding:
        cfg = repo.get("encryptionConfiguration", {}) or {}
        enc_type = cfg.get("encryptionType") or "AES256"
        kms_key = cfg.get("kmsKey")
        passed = enc_type == "KMS" and bool(kms_key)
        desc = (
            f"Repository uses KMS encryption with key {kms_key}."
            if passed else
            f"Repository encryptionType is {enc_type!r}. AES256 uses an "
            f"AWS-managed key, which cannot be audited or restricted via key policies."
        )
        return Finding(
            check_id="ECR-005",
            title="Repository encrypted with AES256 rather than KMS CMK",
            severity=Severity.MEDIUM,
            resource=name,
            description=desc,
            recommendation=(
                "Set encryptionType=KMS with a customer-managed key ARN."
            ),
            passed=passed,
        )

    @staticmethod
    def _ecr001_scan_on_push(repo: dict, name: str) -> Finding:
        scan_config = repo.get("imageScanningConfiguration", {})
        enabled = scan_config.get("scanOnPush", False)

        if enabled:
            desc = "Image scanning on push is enabled."
        else:
            desc = (
                "Image scanning on push is disabled. Vulnerabilities in base images "
                "or dependencies will not be detected when images are pushed, allowing "
                "unvetted images to propagate through the pipeline."
            )

        return Finding(
            check_id="ECR-001",
            title="Image scanning on push not enabled",
            severity=Severity.HIGH,
            resource=name,
            description=desc,
            recommendation=(
                "Enable imageScanningConfiguration.scanOnPush on the repository. "
                "Consider also enabling Amazon Inspector continuous scanning for "
                "ongoing CVE detection against images already in the registry."
            ),
            passed=enabled,
        )

    @staticmethod
    def _ecr002_tag_mutability(repo: dict, name: str) -> Finding:
        mutability = repo.get("imageTagMutability", "MUTABLE")
        passed = mutability == "IMMUTABLE"

        if passed:
            desc = "Image tags are immutable — pushed tags cannot be overwritten."
        else:
            desc = (
                "Image tag mutability is MUTABLE. Any principal with ecr:PutImage "
                "can silently overwrite a tag (e.g. :latest or a semver tag), "
                "allowing a malicious or accidental image swap to affect deployments "
                "that pull by tag without verifying a digest."
            )

        return Finding(
            check_id="ECR-002",
            title="Image tags are mutable",
            severity=Severity.HIGH,
            resource=name,
            description=desc,
            recommendation=(
                "Set imageTagMutability=IMMUTABLE on the repository. Reference images "
                "by digest (sha256:...) in deployment manifests for strongest "
                "immutability guarantees."
            ),
            passed=passed,
        )

    @staticmethod
    def _ecr003_public_policy(client, name: str, arn: str) -> Finding:
        try:
            resp = client.get_repository_policy(repositoryName=name)
            policy = json.loads(resp.get("policyText", "{}"))
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "")
            if error_code == "RepositoryPolicyNotFoundException":
                # No policy = private by default = pass
                return Finding(
                    check_id="ECR-003",
                    title="Repository policy allows public access",
                    severity=Severity.CRITICAL,
                    resource=name,
                    description="No resource-based policy is attached; repository is private.",
                    recommendation=(
                        "Keep the repository private. If cross-account access is "
                        "needed, restrict the policy to specific account principals."
                    ),
                    passed=True,
                )
            # Other error — skip
            return Finding(
                check_id="ECR-003",
                title="Repository policy allows public access",
                severity=Severity.CRITICAL,
                resource=name,
                description=f"Could not retrieve repository policy: {exc}",
                recommendation="Verify IAM permissions include ecr:GetRepositoryPolicy.",
                passed=False,
            )

        # Check for a wildcard principal allowing public access
        public_statements = [
            s for s in policy.get("Statement", [])
            if s.get("Effect") == "Allow"
            and (
                s.get("Principal") == "*"
                or s.get("Principal", {}).get("AWS") == "*"
                or s.get("Principal", {}).get("Service") == "*"
            )
        ]
        passed = not public_statements

        if passed:
            desc = "Repository policy does not grant public access."
        else:
            desc = (
                "The repository policy contains statements that allow unauthenticated "
                "or public access (Principal: '*'). This could expose proprietary "
                "images or allow unauthorised parties to push images."
            )

        return Finding(
            check_id="ECR-003",
            title="Repository policy allows public access",
            severity=Severity.CRITICAL,
            resource=name,
            description=desc,
            recommendation=(
                "Remove wildcard principals from the repository policy. Grant access "
                "only to specific AWS account IDs or IAM principals that require it."
            ),
            passed=passed,
        )

    @staticmethod
    def _ecr004_lifecycle_policy(client, name: str) -> Finding:
        try:
            client.get_lifecycle_policy(repositoryName=name)
            passed = True
            desc = "A lifecycle policy is configured on the repository."
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "")
            if error_code == "LifecyclePolicyNotFoundException":
                passed = False
                desc = (
                    "No lifecycle policy is configured. Without automated cleanup, "
                    "old and potentially vulnerable images accumulate indefinitely, "
                    "increasing storage costs and the attack surface for older tags."
                )
            else:
                passed = False
                desc = f"Could not retrieve lifecycle policy: {exc}"

        return Finding(
            check_id="ECR-004",
            title="No lifecycle policy configured",
            severity=Severity.LOW,
            resource=name,
            description=desc,
            recommendation=(
                "Add a lifecycle policy that expires untagged images after a short "
                "period (e.g. 7 days) and limits the number of tagged images retained, "
                "reducing exposure to images with known CVEs."
            ),
            passed=passed,
        )
