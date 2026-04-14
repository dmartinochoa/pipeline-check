# ---------------------------------------------------------------------------
# PipelineCheck — intentionally MISCONFIGURED LocalStack fixture
#
# Every resource here is configured to FAIL PipelineCheck checks, verifying
# that the scanner correctly detects bad configurations.
#
# Expected failures:
#   IAM-002, IAM-003
#   S3-001, S3-002, S3-003, S3-004
#   CP-001, CP-002, CP-003
#   CB-001, CB-002, CB-003, CB-004, CB-005
#   ECR-001, ECR-002, ECR-004
#   CD-001, CD-002, CD-003
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# IAM — bad CI/CD role
#
# IAM-002: inline policy uses Action: "*"
# IAM-003: no permissions boundary
# ---------------------------------------------------------------------------

resource "aws_iam_role" "bad" {
  name = "pipeline-check-bad-role"
  # No permissions_boundary — triggers IAM-003

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = {
        Service = [
          "codepipeline.amazonaws.com",
          "codebuild.amazonaws.com",
          "codedeploy.amazonaws.com"
        ]
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "bad" {
  name = "BadWildcardPolicy"
  role = aws_iam_role.bad.id
  # IAM-002: Action: "*" in an Allow statement
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# ---------------------------------------------------------------------------
# S3 — artifact bucket with no security controls
#
# S3-001: no public access block
# S3-002: no server-side encryption
# S3-003: no versioning
# S3-004: no access logging
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "bad_artifacts" {
  bucket        = "pipeline-check-bad-artifacts"
  force_destroy = true
}

# No aws_s3_bucket_public_access_block   → S3-001
# No aws_s3_bucket_server_side_encryption_configuration → S3-002
# No aws_s3_bucket_versioning            → S3-003
# No aws_s3_bucket_logging               → S3-004

# ---------------------------------------------------------------------------
# CodePipeline — pipeline with no approval, no KMS, polling source
#
# CP-001: Deploy stage has no preceding approval
# CP-002: artifact store has no customer-managed KMS key
# CP-003: source action uses PollForSourceChanges=true
# ---------------------------------------------------------------------------

resource "aws_codepipeline" "bad" {
  name     = "pipeline-check-bad-pipeline"
  role_arn = aws_iam_role.bad.arn

  # CP-002: no encryption_key — uses default AWS-managed key
  artifact_store {
    location = aws_s3_bucket.bad_artifacts.bucket
    type     = "S3"
  }

  stage {
    name = "Source"
    action {
      name             = "Source"
      category         = "Source"
      owner            = "AWS"
      provider         = "S3"
      version          = "1"
      output_artifacts = ["source_output"]
      configuration = {
        S3Bucket             = aws_s3_bucket.bad_artifacts.bucket
        S3ObjectKey          = "source.zip"
        PollForSourceChanges = "true"  # CP-003: polling instead of events
      }
    }
  }

  # CP-001: no Approve stage before Deploy
  stage {
    name = "Deploy"
    action {
      name            = "Deploy"
      category        = "Deploy"
      owner           = "AWS"
      provider        = "S3"
      version         = "1"
      input_artifacts = ["source_output"]
      configuration = {
        BucketName = aws_s3_bucket.bad_artifacts.bucket
        Extract    = "true"
      }
    }
  }
}

# ---------------------------------------------------------------------------
# CodeBuild — project with every bad setting
#
# CB-001: plaintext env var with secret-like name
# CB-002: privileged mode enabled
# CB-003: logging disabled
# CB-004: timeout at AWS maximum (480 min)
# CB-005: outdated managed image (standard:5.0)
# ---------------------------------------------------------------------------

resource "aws_codebuild_project" "bad" {
  name          = "pipeline-check-bad-app"
  service_role  = aws_iam_role.bad.arn
  build_timeout = 480  # CB-004: at the AWS maximum

  environment {
    compute_type    = "BUILD_GENERAL1_SMALL"
    image           = "aws/codebuild/standard:5.0"  # CB-005: outdated image
    type            = "LINUX_CONTAINER"
    privileged_mode = true  # CB-002: privileged mode on

    # CB-001: secret-like name stored as PLAINTEXT
    environment_variable {
      name  = "SECRET_KEY"
      value = "not-a-real-secret"
      type  = "PLAINTEXT"
    }
  }

  # CB-003: logging explicitly disabled
  logs_config {
    cloudwatch_logs {
      status = "DISABLED"
    }
    s3_logs {
      status = "DISABLED"
    }
  }

  source {
    type      = "NO_SOURCE"
    buildspec = <<-BUILDSPEC
      version: 0.2
      phases:
        build:
          commands:
            - echo "bad fixture"
    BUILDSPEC
  }

  artifacts {
    type = "NO_ARTIFACTS"
  }
}

# ---------------------------------------------------------------------------
# ECR — repository with no security controls
#
# ECR-001: scan on push disabled
# ECR-002: mutable tags
# ECR-004: no lifecycle policy
# ---------------------------------------------------------------------------

resource "aws_ecr_repository" "bad" {
  name                 = "pipeline-check-bad-app"
  image_tag_mutability = "MUTABLE"  # ECR-002: mutable tags

  image_scanning_configuration {
    scan_on_push = false  # ECR-001: no scanning
  }
}

# No aws_ecr_lifecycle_policy → ECR-004

# ---------------------------------------------------------------------------
# CodeDeploy — deployment group with no safety controls
#
# CD-001: no auto rollback on failure
# CD-002: AllAtOnce deployment strategy
# CD-003: no CloudWatch alarm monitoring
# ---------------------------------------------------------------------------

resource "aws_codedeploy_app" "bad" {
  name             = "pipeline-check-bad-app"
  compute_platform = "Server"
}

resource "aws_codedeploy_deployment_group" "bad" {
  app_name              = aws_codedeploy_app.bad.name
  deployment_group_name = "pipeline-check-bad-deployment-group"
  service_role_arn      = aws_iam_role.bad.arn

  # CD-002: AllAtOnce — no canary or rolling strategy
  deployment_config_name = "CodeDeployDefault.AllAtOnce"

  # CD-001: no auto_rollback_configuration block
  # CD-003: no alarm_configuration block

  ec2_tag_set {
    ec2_tag_filter {
      key   = "Name"
      type  = "KEY_AND_VALUE"
      value = "pipeline-check-bad-app"
    }
  }
}
