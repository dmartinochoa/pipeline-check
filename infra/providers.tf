# LocalStack-targeted provider config used by the `terraform-fixture`
# CI job (see .github/workflows/localstack-test.yml). Every AWS service
# endpoint is redirected to http://localhost:4566 so the Terraform
# fixtures in ../infra apply against the local container, and dummy
# credentials plus skip_* flags bypass real-account validation.
#
# Not intended for real deployments — swap this file out or override via
# TF_VAR / -var-file before using the fixtures against an actual account.
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  # Point every service at the LocalStack community container.
  # s3_use_path_style avoids virtual-hosted DNS (*.s3.localhost.localstack.cloud)
  # which does not resolve reliably in CI.
  s3_use_path_style = true

  endpoints {
    cloudwatch   = "http://localhost:4566"
    cloudwatchlogs = "http://localhost:4566"
    codebuild    = "http://localhost:4566"
    codedeploy   = "http://localhost:4566"
    codepipeline = "http://localhost:4566"
    ec2          = "http://localhost:4566"
    ecr          = "http://localhost:4566"
    iam          = "http://localhost:4566"
    kms          = "http://localhost:4566"
    s3           = "http://localhost:4566"
  }
}
