# AWS provider

The AWS provider uses a `boto3.Session` scoped to a single region. It
supports named AWS CLI profiles via `--profile` and honours the
`AWS_ENDPOINT_URL` environment variable (for LocalStack).

## Services covered

| Service       | Check IDs                                  |
|---------------|--------------------------------------------|
| CodeBuild     | CB-001, CB-002, CB-003, CB-004, CB-005     |
| CodePipeline  | CP-001, CP-002, CP-003                     |
| CodeDeploy    | CD-001, CD-002, CD-003                     |
| ECR           | ECR-001, ECR-002, ECR-003, ECR-004         |
| IAM           | IAM-001, IAM-002, IAM-003                  |
| PBAC (CodeBuild roles/VPC) | PBAC-001, PBAC-002            |
| S3            | S3-001, S3-002, S3-003, S3-004             |

## Check reference

### CodeBuild (`CB-*`)

| ID     | Severity | Title                                                 |
|--------|----------|-------------------------------------------------------|
| CB-001 | CRITICAL | Secrets in plaintext environment variables            |
| CB-002 | HIGH     | Privileged mode enabled                               |
| CB-003 | MEDIUM   | Build logging not enabled                             |
| CB-004 | LOW      | No build timeout configured                           |
| CB-005 | MEDIUM   | Outdated managed build image                          |

### CodePipeline (`CP-*`)

| ID     | Severity | Title                                                 |
|--------|----------|-------------------------------------------------------|
| CP-001 | HIGH     | No manual approval action before production deploy    |
| CP-002 | HIGH     | Artifact store not encrypted with customer-managed KMS|
| CP-003 | MEDIUM   | Source stage pulls from an unprotected branch         |

### CodeDeploy (`CD-*`)

| ID     | Severity | Title                                                 |
|--------|----------|-------------------------------------------------------|
| CD-001 | MEDIUM   | Deployment group missing automatic rollback           |
| CD-002 | MEDIUM   | Deployment group has no alarm configuration           |
| CD-003 | MEDIUM   | Deployment application not integrated with CloudTrail |

### ECR (`ECR-*`)

| ID      | Severity | Title                                                |
|---------|----------|------------------------------------------------------|
| ECR-001 | HIGH     | Image scanning on push is disabled                   |
| ECR-002 | HIGH     | Repository tag mutability is MUTABLE                 |
| ECR-003 | MEDIUM   | Repository permits cross-account pulls              |
| ECR-004 | LOW      | No lifecycle policy set                              |

### IAM (`IAM-*`)

| ID      | Severity | Title                                                |
|---------|----------|------------------------------------------------------|
| IAM-001 | CRITICAL | AdministratorAccess attached to build role           |
| IAM-002 | HIGH     | Wildcard action in inline policy                     |
| IAM-003 | MEDIUM   | No permissions boundary on build role                |

### PBAC (`PBAC-*`)

| ID       | Severity | Title                                               |
|----------|----------|-----------------------------------------------------|
| PBAC-001 | HIGH     | CodeBuild project has no VPC configuration          |
| PBAC-002 | MEDIUM   | CodeBuild service role shared across projects       |

### S3 (`S3-*`)

| ID     | Severity | Title                                                 |
|--------|----------|-------------------------------------------------------|
| S3-001 | CRITICAL | Artifact bucket public access block not fully enabled |
| S3-002 | HIGH     | Artifact bucket not encrypted at rest                 |
| S3-003 | HIGH     | Artifact bucket policy allows non-HTTPS access        |
| S3-004 | MEDIUM   | Artifact bucket has no server access logging          |

## Adding a new AWS check

1. Create `pipeline_check/core/checks/aws/<service>.py` subclassing
   `AWSBaseCheck`. Each public check method should return one or more
   `Finding` objects.
2. Import it and append to `check_classes` in
   `pipeline_check/core/providers/aws.py`.
3. (Optional) Add rule metadata to
   `pipeline_check/core/checks/aws/rules/<service>.yml` to enrich the HTML
   report.
4. Add unit tests in `tests/aws/test_<service>.py`.
5. Add mappings for the new check IDs in the relevant standard file(s) under
   `pipeline_check/core/standards/data/`.
