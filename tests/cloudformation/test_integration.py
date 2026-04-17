"""End-to-end CFN integration tests — full Scanner pipeline on real templates."""
from __future__ import annotations

from pathlib import Path

import pytest

from pipeline_check.core.scanner import Scanner


_INSECURE_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:

  # CodeBuild project violating CB-001/002/003/004/005/006/008/009/010
  # and contributing to PBAC-001/002 (no VPC, shared role).
  InsecureProject:
    Type: AWS::CodeBuild::Project
    Properties:
      Name: insecure-build
      ServiceRole: !GetAtt SharedRole.Arn
      Environment:
        Image: 'ghcr.io/corp/builder:latest'
        PrivilegedMode: true
        EnvironmentVariables:
          - Name: DB_PASSWORD
            Type: PLAINTEXT
            Value: leaked-in-template
      LogsConfig:
        CloudWatchLogs:
          Status: DISABLED
        S3Logs:
          Status: DISABLED
      TimeoutInMinutes: 480
      Source:
        Type: GITHUB
        Auth:
          Type: OAUTH
        BuildSpec: |
          version: 0.2
          phases:
            build:
              commands:
                - make build
      Triggers:
        Webhook: true
        FilterGroups:
          - - Type: EVENT
              Pattern: PULL_REQUEST_CREATED

  # Second project sharing the role → PBAC-002.
  SecondaryProject:
    Type: AWS::CodeBuild::Project
    Properties:
      Name: insecure-build-2
      ServiceRole: !GetAtt SharedRole.Arn
      Environment:
        Image: aws/codebuild/standard:7.0

  # IAM role hitting IAM-001/002/003/004/005 and IAM-008.
  SharedRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: shared-cicd-role
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: codebuild.amazonaws.com
            Action: sts:AssumeRole
          - Effect: Allow
            Principal:
              Federated: 'arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com'
            Action: sts:AssumeRoleWithWebIdentity
          - Effect: Allow
            Principal:
              AWS: 'arn:aws:iam::999999999999:root'
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - 'arn:aws:iam::aws:policy/AdministratorAccess'
      Policies:
        - PolicyName: wild
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action: '*'
                Resource: '*'
              - Effect: Allow
                Action: iam:PassRole
                Resource: '*'

  # CodeDeploy group — CD-001/002/003.
  BadDeploymentGroup:
    Type: AWS::CodeDeploy::DeploymentGroup
    Properties:
      ApplicationName: MyApp
      DeploymentGroupName: prod
      DeploymentConfigName: CodeDeployDefault.AllAtOnce

  # ECR repo — ECR-001/002/003/004/005.
  BadEcr:
    Type: AWS::ECR::Repository
    Properties:
      RepositoryName: bad
      ImageScanningConfiguration:
        ScanOnPush: false
      ImageTagMutability: MUTABLE
      RepositoryPolicyText:
        Statement:
          - Effect: Allow
            Principal: '*'
            Action: 'ecr:GetDownloadUrlForLayer'
      EncryptionConfiguration:
        EncryptionType: AES256

  # S3 artifact bucket — S3-001..005.
  ArtifactBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: insecure-artifacts
      # Explicitly NO public-access-block, versioning, encryption, or logging.

  InsecurePipeline:
    Type: AWS::CodePipeline::Pipeline
    Properties:
      Name: insecure-pipe
      RoleArn: !GetAtt SharedRole.Arn
      PipelineType: V2
      ArtifactStore:
        Type: S3
        Location: !Ref ArtifactBucket
      Triggers:
        - ProviderType: CodeStarSourceConnection
          GitConfiguration:
            PullRequest:
              - Branches:
                  Includes: ['*']
      Stages:
        - Name: Source
          Actions:
            - Name: Src
              RoleArn: !GetAtt SharedRole.Arn
              ActionTypeId:
                Category: Source
                Owner: ThirdParty
                Provider: GitHub
              Configuration:
                PollForSourceChanges: 'true'
        - Name: DeployProd
          Actions:
            - Name: Deploy
              RoleArn: !GetAtt SharedRole.Arn
              ActionTypeId:
                Category: Deploy
                Owner: AWS
                Provider: CodeDeploy

  # CloudTrail — CT-002/003.
  Trail:
    Type: AWS::CloudTrail::Trail
    Properties:
      TrailName: weak
      EnableLogFileValidation: false
      IsMultiRegionTrail: false
      S3BucketName: !Ref ArtifactBucket
      IsLogging: true

  # CW Logs — CWL-001/002.
  CbLogs:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/codebuild/insecure-build

  # Secrets Manager — SM-001 (no rotation), SM-002 (wildcard policy).
  DbSecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Name: prod-db-password

  DbSecretPolicy:
    Type: AWS::SecretsManager::ResourcePolicy
    Properties:
      SecretId: !Ref DbSecret
      ResourcePolicy:
        Statement:
          - Effect: Allow
            Principal: '*'
            Action: 'secretsmanager:GetSecretValue'

  # CodeArtifact — CA-001/002/003/004.
  ArtifactDomain:
    Type: AWS::CodeArtifact::Domain
    Properties:
      DomainName: corp
      PermissionsPolicyDocument:
        Statement:
          - Effect: Allow
            Principal: '*'
            Action: '*'

  ArtifactRepo:
    Type: AWS::CodeArtifact::Repository
    Properties:
      RepositoryName: shared
      DomainName: corp
      ExternalConnections: ['public:npmjs']
      PermissionsPolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              AWS: 'arn:aws:iam::111111111111:root'
            Action: 'codeartifact:*'
            Resource: '*'

  # CodeCommit — CCM-002.
  Repo:
    Type: AWS::CodeCommit::Repository
    Properties:
      RepositoryName: app
      KmsKeyId: 'alias/aws/codecommit'

  # Lambda — LMB-001/002/003/004.
  Fn:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: worker
      Environment:
        Variables:
          DB_PASSWORD: literally-leaked

  FnUrl:
    Type: AWS::Lambda::Url
    Properties:
      TargetFunctionArn: !Ref Fn
      AuthType: NONE

  FnPermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref Fn
      Principal: '*'
      Action: 'lambda:InvokeFunction'

  # KMS — KMS-001/002.
  BadKey:
    Type: AWS::KMS::Key
    Properties:
      EnableKeyRotation: false
      KeyPolicy:
        Statement:
          - Effect: Allow
            Principal:
              AWS: 'arn:aws:iam::111111111111:root'
            Action: 'kms:*'

  # SSM — SSM-001.
  SecretParam:
    Type: AWS::SSM::Parameter
    Properties:
      Name: /app/DB_PASSWORD
      Type: String
      Value: leaked

  # ECR pull-through — ECR-006.
  DockerHubCache:
    Type: AWS::ECR::PullThroughCacheRule
    Properties:
      EcrRepositoryPrefix: docker
      UpstreamRegistryUrl: registry-1.docker.io

  # EC2 SG — PBAC-003.
  OpenSg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: open egress
      SecurityGroupEgress:
        - IpProtocol: '-1'
          FromPort: 0
          ToPort: 0
          CidrIp: 0.0.0.0/0

  # EventBridge — EB-001 (no matching rule means the rule fires).
  NoisyRule:
    Type: AWS::Events::Rule
    Properties:
      EventPattern:
        detail-type: ['EC2 Instance State-change Notification']
"""


_SECURE_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:

  SecureProject:
    Type: AWS::CodeBuild::Project
    Properties:
      Name: secure-build
      ServiceRole: !GetAtt BuildRole.Arn
      Environment:
        Image: aws/codebuild/standard:7.0
        PrivilegedMode: false
      LogsConfig:
        CloudWatchLogs:
          Status: ENABLED
      TimeoutInMinutes: 30
      Source:
        Type: GITHUB
        Auth:
          Type: CODECONNECTIONS
        BuildSpec: ci/build.yml
      VpcConfig:
        VpcId: vpc-1
        Subnets: [subnet-1]
        SecurityGroupIds: [!Ref EgressSg]

  BuildRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: secure-build-role
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service: codebuild.amazonaws.com
            Action: sts:AssumeRole
      PermissionsBoundary: 'arn:aws:iam::111111111111:policy/secure-boundary'

  EgressSg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: scoped
      SecurityGroupEgress:
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 10.0.0.0/8

  Trail:
    Type: AWS::CloudTrail::Trail
    Properties:
      TrailName: prod
      IsLogging: true
      IsMultiRegionTrail: true
      EnableLogFileValidation: true
      S3BucketName: !Ref LogBucket

  LogBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: ct-logs
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        IgnorePublicAcls: true
        BlockPublicPolicy: true
        RestrictPublicBuckets: true
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: aws:kms
      VersioningConfiguration:
        Status: Enabled
      LoggingConfiguration:
        DestinationBucketName: log-bucket
"""


@pytest.fixture()
def insecure_template(tmp_path):
    p = tmp_path / "template.yaml"
    p.write_text(_INSECURE_TEMPLATE, encoding="utf-8")
    return str(p)


@pytest.fixture()
def secure_template(tmp_path):
    p = tmp_path / "template.yaml"
    p.write_text(_SECURE_TEMPLATE, encoding="utf-8")
    return str(p)


def _scan(path: str):
    return Scanner(pipeline="cloudformation", cfn_template=path).run()


def _failed(findings) -> set[str]:
    return {f.check_id for f in findings if not f.passed}


# ── Insecure template: assert every expected rule fires end-to-end ──

class TestInsecureTemplate:
    @pytest.fixture()
    def findings(self, insecure_template):
        return _scan(insecure_template)

    @pytest.mark.parametrize("check_id", [
        # Core services
        "CB-001", "CB-002", "CB-003", "CB-004", "CB-006",
        "CP-001", "CP-002", "CP-003", "CP-004",
        "CD-001", "CD-002", "CD-003",
        "ECR-001", "ECR-002", "ECR-003", "ECR-004", "ECR-005",
        "IAM-001", "IAM-002", "IAM-003", "IAM-004", "IAM-005",
        "PBAC-001", "PBAC-002",
        "S3-001", "S3-002", "S3-003", "S3-004", "S3-005",
        # Phase 1 mirrors
        "CB-008", "CB-009", "CB-010",
        "CT-002", "CT-003",
        "CWL-001", "CWL-002",
        "SM-001", "SM-002",
        "IAM-008",
        # Phase 2 mirrors
        "CA-001", "CA-002", "CA-003", "CA-004",
        "CCM-002",
        "LMB-001", "LMB-002", "LMB-003", "LMB-004",
        "KMS-001", "KMS-002",
        "SSM-001",
        # Phase 3 mirrors
        "ECR-006",
        "PBAC-003", "PBAC-005",
        "CP-005", "CP-007",
        "EB-001",
    ])
    def test_rule_fires(self, findings, check_id):
        assert check_id in _failed(findings), (
            f"{check_id} should fire on the insecure template but didn't. "
            f"Failed set: {sorted(_failed(findings))}"
        )

    def test_findings_carry_owasp_controls(self, findings):
        """Scanner annotates every failing finding with OWASP controls."""
        unmapped = [
            f.check_id for f in findings
            if not f.passed
            and not any(c.standard == "owasp_cicd_top_10" for c in f.controls)
        ]
        assert not unmapped, f"CFN findings without OWASP mapping: {unmapped}"


# ── Secure template: no Phase-1-3 rule should fail ──

class TestSecureTemplate:
    def test_no_phase_1_3_rule_fails(self, secure_template):
        findings = _scan(secure_template)
        new_rule_ids = {
            "CB-008", "CB-009", "CB-010",
            "CT-001", "CT-002", "CT-003",
            "CWL-001", "CWL-002",
            "SM-001", "SM-002",
            "IAM-008",
            "CA-001", "CA-002", "CA-003", "CA-004",
            "CCM-002",
            "LMB-001", "LMB-002", "LMB-003", "LMB-004",
            "KMS-001", "KMS-002",
            "SSM-001", "SSM-002",
            "ECR-006",
            "PBAC-003", "PBAC-005",
            "CP-005", "CP-007",
            "EB-001",
        }
        offenders = [
            f.check_id for f in findings
            if not f.passed and f.check_id in new_rule_ids
        ]
        assert not offenders, (
            f"Secure template tripped Phase 1-3 rules it should not: {offenders}"
        )


# ── CLI filter / check selection ──

class TestCheckFiltering:
    def test_glob_filter_scopes_output(self, insecure_template):
        findings = Scanner(
            pipeline="cloudformation", cfn_template=insecure_template,
        ).run(checks=["CT-*"])
        assert findings
        assert all(f.check_id.startswith("CT-") for f in findings)

    def test_exact_id_filter(self, insecure_template):
        findings = Scanner(
            pipeline="cloudformation", cfn_template=insecure_template,
        ).run(checks=["SM-002"])
        assert {f.check_id for f in findings} == {"SM-002"}
