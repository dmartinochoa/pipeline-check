# ---------------------------------------------------------------------------
# PipelineCheck LocalStack fixture
#
# Every resource here is intentionally configured to pass all PipelineCheck
# checks (CB-001…CB-005, CP-001…CP-003, CD-001…CD-003, ECR-001…ECR-004,
# IAM-001…IAM-003, S3-001…S3-004).
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# KMS — artifact encryption key (CP-002)
# ---------------------------------------------------------------------------

resource "aws_kms_key" "pipeline" {
  description             = "PipelineCheck pipeline artifact encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

# ---------------------------------------------------------------------------
# S3 — artifact bucket (S3-001…S3-004)
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "logs" {
  bucket        = "pipeline-check-logs"
  force_destroy = true
}

resource "aws_s3_bucket" "source" {
  bucket        = "pipeline-check-source"
  force_destroy = true
}

resource "aws_s3_bucket" "artifacts" {
  bucket        = "pipeline-check-artifacts"
  force_destroy = true
}

# S3-001: all four Block Public Access settings enabled
resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# S3-002: server-side encryption (KMS)
resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.pipeline.arn
    }
  }
}

# S3-003: versioning enabled
resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

# S3-004: access logging enabled
resource "aws_s3_bucket_logging" "artifacts" {
  bucket        = aws_s3_bucket.artifacts.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "artifact-access-logs/"
}

# ---------------------------------------------------------------------------
# IAM — permission boundary (IAM-001…IAM-003)
#
# IAM-001: no AdministratorAccess attached to any CI/CD role
# IAM-002: no inline policy with Action: "*"
# IAM-003: every CI/CD role has this boundary attached
#
# Note: LocalStack Pro does not return PermissionsBoundary in list_roles
# responses, so IAM-003 will report false negatives in the integration test.
# The boundaries are correctly configured here and pass on real AWS.
# ---------------------------------------------------------------------------

resource "aws_iam_policy" "boundary" {
  name = "PipelineCheckCicdBoundary"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "codebuild:*", "codepipeline:*", "codedeploy:*",
          "s3:*", "logs:*", "kms:Decrypt", "kms:GenerateDataKey",
          "ecr:*", "iam:PassRole"
        ]
        Resource = "*"
      }
    ]
  })
}

# CodeBuild service role
resource "aws_iam_role" "codebuild" {
  name                 = "pipeline-check-codebuild-role"
  permissions_boundary = aws_iam_policy.boundary.arn  # IAM-003

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "codebuild.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "codebuild" {
  name = "CodeBuildPolicy"
  role = aws_iam_role.codebuild.id
  # IAM-002: no wildcard Action — only specific actions
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:GetObjectVersion"]
        Resource = ["${aws_s3_bucket.artifacts.arn}/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = [aws_kms_key.pipeline.arn]
      }
    ]
  })
}

# CodePipeline service role
resource "aws_iam_role" "codepipeline" {
  name                 = "pipeline-check-codepipeline-role"
  permissions_boundary = aws_iam_policy.boundary.arn  # IAM-003

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "codepipeline.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "codepipeline" {
  name = "CodePipelinePolicy"
  role = aws_iam_role.codepipeline.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject", "s3:PutObject",
          "s3:GetBucketVersioning", "s3:GetObjectVersion"
        ]
        Resource = [
          aws_s3_bucket.artifacts.arn,
          "${aws_s3_bucket.artifacts.arn}/*",
          aws_s3_bucket.source.arn,
          "${aws_s3_bucket.source.arn}/*"
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = [aws_kms_key.pipeline.arn]
      },
      {
        Effect   = "Allow"
        Action   = ["codedeploy:CreateDeployment", "codedeploy:GetDeploymentConfig", "codedeploy:RegisterApplicationRevision"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["iam:PassRole"]
        Resource = [aws_iam_role.codedeploy.arn]
      }
    ]
  })
}

# CodeDeploy service role
resource "aws_iam_role" "codedeploy" {
  name                 = "pipeline-check-codedeploy-role"
  permissions_boundary = aws_iam_policy.boundary.arn  # IAM-003

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "codedeploy.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "codedeploy" {
  name = "CodeDeployPolicy"
  role = aws_iam_role.codedeploy.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "ec2:DescribeInstances", "tag:GetResources"]
      Resource = "*"
    }]
  })
}

# ---------------------------------------------------------------------------
# ECR — container registry (ECR-001…ECR-004)
# ---------------------------------------------------------------------------

# ECR-001: scan on push; ECR-002: immutable tags; ECR-003: no public policy (none attached)
resource "aws_ecr_repository" "app" {
  name                 = "pipeline-check-app"
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

# ECR-004: lifecycle policy configured
resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name
  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images after 7 days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 7
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Keep only the last 10 tagged images"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["v"]
          countType     = "imageCountMoreThan"
          countNumber   = 10
        }
        action = { type = "expire" }
      }
    ]
  })
}

# ---------------------------------------------------------------------------
# CloudWatch — log group + alarm (CB-003, CD-003)
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "codebuild" {
  name              = "/aws/codebuild/pipeline-check-app"
  retention_in_days = 30
}

# CD-003: CloudWatch alarm attached to deployment group
resource "aws_cloudwatch_metric_alarm" "deploy_errors" {
  alarm_name          = "pipeline-check-deploy-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "Errors"
  namespace           = "AWS/CodeDeploy"
  period              = "60"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "Alert when CodeDeploy deployment errors occur"
}

# ---------------------------------------------------------------------------
# CodeBuild — project (CB-001…CB-005)
# ---------------------------------------------------------------------------

resource "aws_codebuild_project" "app" {
  name          = "pipeline-check-app"
  service_role  = aws_iam_role.codebuild.arn
  build_timeout = 60  # CB-004: < 480 minutes

  environment {
    compute_type    = "BUILD_GENERAL1_SMALL"
    image           = "aws/codebuild/standard:7.0"  # CB-005: latest managed image
    type            = "LINUX_CONTAINER"
    privileged_mode = false  # CB-002: privileged mode disabled
    # CB-001: no environment variables with secret-like names
  }

  # CB-003: CloudWatch logging enabled
  logs_config {
    cloudwatch_logs {
      status     = "ENABLED"
      group_name = aws_cloudwatch_log_group.codebuild.name
    }
  }

  source {
    type      = "NO_SOURCE"
    buildspec = <<-BUILDSPEC
      version: 0.2
      phases:
        build:
          commands:
            - echo "PipelineCheck LocalStack fixture build"
    BUILDSPEC
  }

  artifacts {
    type = "NO_ARTIFACTS"
  }
}

# ---------------------------------------------------------------------------
# CodeDeploy — application + deployment group (CD-001…CD-003)
# ---------------------------------------------------------------------------

resource "aws_codedeploy_app" "app" {
  name             = "pipeline-check-app"
  compute_platform = "Server"
}

resource "aws_codedeploy_deployment_group" "app" {
  app_name              = aws_codedeploy_app.app.name
  deployment_group_name = "pipeline-check-deployment-group"
  service_role_arn      = aws_iam_role.codedeploy.arn

  # CD-002: not AllAtOnce — use a graduated deployment strategy
  deployment_config_name = "CodeDeployDefault.HalfAtATime"

  # CD-001: auto rollback on deployment failure
  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }

  # CD-003: CloudWatch alarm monitoring enabled
  alarm_configuration {
    alarms  = [aws_cloudwatch_metric_alarm.deploy_errors.alarm_name]
    enabled = true
  }

  ec2_tag_set {
    ec2_tag_filter {
      key   = "Name"
      type  = "KEY_AND_VALUE"
      value = "pipeline-check-app"
    }
  }
}

# ---------------------------------------------------------------------------
# CodePipeline — pipeline (CP-001…CP-003)
# ---------------------------------------------------------------------------

resource "aws_codepipeline" "pipeline" {
  name     = "pipeline-check-pipeline"
  role_arn = aws_iam_role.codepipeline.arn

  # CP-002: artifact store encrypted with customer-managed KMS key
  artifact_store {
    location = aws_s3_bucket.artifacts.bucket
    type     = "S3"
    encryption_key {
      id   = aws_kms_key.pipeline.arn
      type = "KMS"
    }
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
        S3Bucket             = aws_s3_bucket.source.bucket
        S3ObjectKey          = "source.zip"
        PollForSourceChanges = "false"  # CP-003: event-driven, not polling
      }
    }
  }

  # CP-001: manual approval before any Deploy stage
  stage {
    name = "Approve"
    action {
      name     = "ManualApproval"
      category = "Approval"
      owner    = "AWS"
      provider = "Manual"
      version  = "1"
    }
  }

  stage {
    name = "Deploy"
    action {
      name            = "Deploy"
      category        = "Deploy"
      owner           = "AWS"
      provider        = "CodeDeploy"
      version         = "1"
      input_artifacts = ["source_output"]
      configuration = {
        ApplicationName     = aws_codedeploy_app.app.name
        DeploymentGroupName = aws_codedeploy_deployment_group.app.deployment_group_name
      }
    }
  }
}
