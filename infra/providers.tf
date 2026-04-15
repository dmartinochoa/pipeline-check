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
