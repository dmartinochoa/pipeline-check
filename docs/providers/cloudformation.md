# CloudFormation provider

Scans a **CloudFormation template** (YAML or JSON), no live AWS
credentials required. Short-form intrinsics (`!Ref`, `!Sub`, `!GetAtt`,
`!Join`, `!If`, …) are normalized to their JSON-form equivalents at
parse time so rules operate on one uniform structure.

Every AWS-mirrored check ID (CB-*, CP-*, CD-*, ECR-*, IAM-*, PBAC-*,
S3-*, CT-*, CWL-*, SM-*, CA-*, CCM-*, LMB-*, KMS-*, SSM-*, EB-*,
SIGN-*, CW-*) maps one-to-one to its AWS-provider counterpart. The
semantics are identical, only the data source differs (template
properties instead of boto3 list/describe). CF-* rules are
CloudFormation-only and have no AWS-runtime analogue.

## Producer workflow

```bash
pipeline_check --pipeline cloudformation --cfn-template path/to/template.yaml
# or point at a directory and every *.yml / *.yaml / *.json / *.template is scanned
pipeline_check --pipeline cloudformation --cfn-template infra/
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the AWS provider.

## Intrinsic handling

CFN values may be literals (``"ap-southeast-2"``), booleans,
unresolved intrinsics (``{"Ref": "Region"}``, ``{"Fn::Sub": "..."}``),
or condition references. The scanner follows two conventions:

1. **Anything not provably safe is treated as a potential offender
   unless the rule explicitly skips unresolved values.** For
   instance, ``is_true(value)`` returns ``True`` only for ``True`` or
   ``"true"``, so a template that hides a ``Ref`` behind a
   boolean-typed property is scored as if the flag were disabled.
2. **Statically-reducible intrinsics are reduced before matching.**
   ``resolve_literal(value, parameters)`` in
   ``cloudformation/base.py`` evaluates
   ``{"Ref": "ParamName"}`` against the template's
   ``Parameters.<Name>.Default``, ``{"Fn::Sub": "literal"}`` /
   ``{"Fn::Sub": "...${Var}..."}`` including the
   ``[template, {var-map}]`` form, and ``{"Fn::Join": [delim,
   [list]]}`` when every list item resolves. Rules that benefit
   (``EB-002`` target ARNs, ``CF-003`` VPC IDs) call the resolver
   first and fall back to the old "skip unresolved" path only when
   the intrinsic references a pseudo-parameter (``AWS::Region``) or
   a runtime-dependent intrinsic (``Fn::GetAtt``,
   ``Fn::ImportValue``, ``Fn::If``).

Rule helpers (importable from ``cloudformation/base.py``):

- ``as_str(value)`` — literal-only accessor, returns ``""`` for intrinsics.
- ``resolve_literal(value, parameters)`` — tries to reduce every
  statically-resolvable intrinsic; returns ``None`` when it can't.
- ``is_true(value)`` — strict boolean gate.
- ``is_intrinsic(value)`` — predicate used by ``CF-002`` to skip
  intrinsic dicts entirely when walking for hard-coded secrets.

This matches cfn-lint and cfn-nag conventions and keeps findings
useful under the common case where templates are parameterised.

## Resource-type coverage

| Service          | IDs               | CloudFormation resources consumed |
|------------------|-------------------|-----------------------------------|
| CodeBuild        | `CB-001…011`      | `AWS::CodeBuild::Project`, `AWS::CodeBuild::SourceCredential` |
| CodePipeline     | `CP-001…005`, `CP-007` | `AWS::CodePipeline::Pipeline` |
| CodeDeploy       | `CD-001…003`      | `AWS::CodeDeploy::DeploymentGroup` |
| ECR              | `ECR-001…006`     | `AWS::ECR::Repository`, `AWS::ECR::PullThroughCacheRule` |
| IAM              | `IAM-001…006`, `IAM-008` | `AWS::IAM::Role`, `AWS::IAM::Policy`, `AWS::IAM::ManagedPolicy` |
| PBAC             | `PBAC-001…003`, `PBAC-005` | `AWS::CodeBuild::Project`, `AWS::EC2::SecurityGroup` |
| S3               | `S3-001…005`      | `AWS::S3::Bucket` (artifact buckets discovered from pipelines) |
| CloudTrail       | `CT-001…003`      | `AWS::CloudTrail::Trail` |
| CloudWatch Logs  | `CWL-001…002`     | `AWS::Logs::LogGroup` |
| Secrets Manager  | `SM-001…002`      | `AWS::SecretsManager::Secret`, `AWS::SecretsManager::RotationSchedule` |
| CodeArtifact     | `CA-001…004`      | `AWS::CodeArtifact::Domain`, `AWS::CodeArtifact::Repository` |
| CodeCommit       | `CCM-002…003`     | `AWS::CodeCommit::Repository` (CCM-001 omitted, no equivalent CFN resource) |
| Lambda           | `LMB-001…004`     | `AWS::Lambda::Function`, `AWS::Lambda::Url`, `AWS::Lambda::Permission` |
| KMS              | `KMS-001…002`     | `AWS::KMS::Key` |
| SSM              | `SSM-001…002`     | `AWS::SSM::Parameter` |
| EventBridge      | `EB-001…002`      | `AWS::Events::Rule` (targets are inline) |
| Signer           | `SIGN-001`        | `AWS::Lambda::Function.CodeSigningConfigArn`, `AWS::Signer::SigningProfile` |
| CloudWatch       | `CW-001`          | `AWS::CloudWatch::Alarm` (namespace=`AWS/CodeBuild`, metric=`FailedBuilds`) |
| CFN-native       | `CF-001…003`      | `AWS::IAM::AccessKey`, stateful data-store types, `AWS::EC2::Subnet` |

## Limitations

- **Template-level only.** Resources provisioned outside the
  template (console, SDK, sister stacks) are not scanned — use
  `--pipeline aws` alongside for a live view.
- **Intrinsics are not evaluated** beyond the statically-reducible
  forms above. A ``Fn::GetAtt``, ``Fn::ImportValue``, or ``Fn::If``
  passes through as an opaque dict; rules that require a literal
  value silently skip the finding rather than guess at the resolved
  shape.
- **No cross-stack resolution.** ``Fn::ImportValue`` references are
  preserved as-is; the exporting stack is not fetched.
- **Transform macros are ignored.** ``AWS::Serverless-2016-10-31``
  (SAM) and custom transforms run server-side; the pre-transform
  resources are what the scanner sees.

## What it covers

70 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [CA-001](#ca-001) | CodeArtifact domain not encrypted with customer KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CA-002](#ca-002) | CodeArtifact repository has a public external connection | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CA-003](#ca-003) | CodeArtifact domain policy allows cross-account wildcard | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [CA-004](#ca-004) | CodeArtifact repo policy grants codeartifact:* with Resource '*' | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CB-001](#cb-001) | Secrets in plaintext environment variables | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [CB-002](#cb-002) | Privileged mode enabled | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CB-003](#cb-003) | Build logging not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CB-004](#cb-004) | No build timeout configured | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [CB-005](#cb-005) | Outdated managed build image | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CB-006](#cb-006) | CodeBuild source auth uses long-lived token | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CB-007](#cb-007) | CodeBuild webhook has no filter_group | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CB-008](#cb-008) | CodeBuild buildspec is inline (not sourced from a protected repo) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CB-009](#cb-009) | CodeBuild image not pinned by digest | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CB-010](#cb-010) | CodeBuild webhook allows fork-PR builds without actor filtering | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CB-011](#cb-011) | CodeBuild buildspec contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [CCM-002](#ccm-002) | CodeCommit repository not encrypted with customer KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CCM-003](#ccm-003) | CodeCommit trigger targets SNS/Lambda in a different account | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CD-001](#cd-001) | Automatic rollback on failure not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CD-002](#cd-002) | AllAtOnce deployment config, no canary or rolling strategy | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CD-003](#cd-003) | No CloudWatch alarm monitoring on deployment group | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CF-001](#cf-001) | Template declares AWS::IAM::AccessKey (long-lived credential) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CF-002](#cf-002) | Stateful data-store resource carries a plaintext secret | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [CF-003](#cf-003) | CodeBuild VPC config references a public subnet | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CP-001](#cp-001) | No approval action before deploy stages | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CP-002](#cp-002) | Artifact store not encrypted with customer-managed KMS key | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CP-003](#cp-003) | Source stage using polling instead of event-driven trigger | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [CP-004](#cp-004) | Legacy ThirdParty/GitHub source action (OAuth token) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CP-005](#cp-005) | Production Deploy stage has no preceding ManualApproval | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CP-007](#cp-007) | CodePipeline v2 PR trigger accepts all branches | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CT-001](#ct-001) | No active CloudTrail trail in region | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [CT-002](#ct-002) | CloudTrail log-file validation disabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CT-003](#ct-003) | CloudTrail trail is not multi-region | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [CW-001](#cw-001) | No CloudWatch alarm on CodeBuild FailedBuilds metric | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [CWL-001](#cwl-001) | CodeBuild log group has no retention policy | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [CWL-002](#cwl-002) | CodeBuild log group not KMS-encrypted | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [EB-001](#eb-001) | No EventBridge rule for CodePipeline failure notifications | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [EB-002](#eb-002) | EventBridge rule has a wildcard target ARN | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ECR-001](#ecr-001) | Image scanning on push not enabled | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ECR-002](#ecr-002) | Image tags are mutable | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [ECR-003](#ecr-003) | Repository policy allows public access | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [ECR-004](#ecr-004) | No lifecycle policy configured | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [ECR-005](#ecr-005) | Repository encrypted with AES256 rather than KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [ECR-006](#ecr-006) | ECR pull-through cache rule uses an untrusted upstream | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [IAM-001](#iam-001) | CI/CD role has AdministratorAccess policy attached | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [IAM-002](#iam-002) | CI/CD role has wildcard Action in attached policy | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [IAM-003](#iam-003) | CI/CD role has no permission boundary | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [IAM-004](#iam-004) | CI/CD role can PassRole to any role | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [IAM-005](#iam-005) | CI/CD role trust policy missing sts:ExternalId | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [IAM-006](#iam-006) | Sensitive actions granted with wildcard Resource | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [IAM-008](#iam-008) | OIDC-federated role trust policy missing audience or subject pin | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [KMS-001](#kms-001) | Customer-managed symmetric KMS key has rotation disabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [KMS-002](#kms-002) | KMS key policy grants kms:* to an IAM principal | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [LMB-001](#lmb-001) | Lambda function has no code-signing config | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [LMB-002](#lmb-002) | Lambda Function URL configured with AuthType = NONE | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [LMB-003](#lmb-003) | Lambda environment variables contain plaintext secrets | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [LMB-004](#lmb-004) | Lambda resource policy grants wildcard principal | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [PBAC-001](#pbac-001) | CodeBuild project has no VPC configuration | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [PBAC-002](#pbac-002) | CodeBuild service role shared across multiple projects | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [PBAC-003](#pbac-003) | CodeBuild security group allows 0.0.0.0/0 all-port egress | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [PBAC-005](#pbac-005) | Pipeline action roles all equal the pipeline-level role | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [S3-001](#s3-001) | Artifact bucket public access block not fully enabled | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [S3-002](#s3-002) | Artifact bucket server-side encryption not configured | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [S3-003](#s3-003) | Artifact bucket versioning not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [S3-004](#s3-004) | Artifact bucket access logging not enabled | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [S3-005](#s3-005) | Artifact bucket missing aws:SecureTransport deny | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SIGN-001](#sign-001) | No active AWS Signer profile exists for the Lambda platform | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [SM-001](#sm-001) | Secrets Manager secret has no rotation configured | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [SM-002](#sm-002) | Secrets Manager resource policy allows wildcard principal | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [SSM-001](#ssm-001) | SSM parameter with secret-like name stored as String, not SecureString | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [SSM-002](#ssm-002) | SecureString uses alias/aws/ssm rather than a customer CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |

---

<div class="pg-rule pg-rule--medium" markdown>

## CA-001: CodeArtifact domain not encrypted with customer KMS CMK { #ca-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-311</span>
</div>

Reads ``AWS::CodeArtifact::Domain.Properties.EncryptionKey``. An empty value means anyone with ``codeartifact:Read*`` can read packages — the encryption key isn't a separate authorization boundary.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``EncryptionKey`` on every ``AWS::CodeArtifact::Domain`` to a customer-managed CMK ARN. The default AWS-owned key can't be rotated or scoped by IAM.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CA-002: CodeArtifact repository has a public external connection { #ca-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Reads ``AWS::CodeArtifact::Repository.Properties.ExternalConnections``. Any value beginning with ``public:`` (e.g. ``public:npmjs``) fetches packages directly from the public ecosystem with no intermediate scrub.

<div class="pg-rule__rec" markdown>

**Recommended action**

Route every ``ExternalConnections`` entry through a private mirror that caches and vets public packages, or scope with upstream allow-lists. Direct ``public:npmjs`` / ``public:pypi`` is dependency-confusion fuel.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## CA-003: CodeArtifact domain policy allows cross-account wildcard { #ca-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Parses ``AWS::CodeArtifact::Domain.Properties.PermissionsPolicyDocument``. Fires on any ``Allow`` statement that names a wildcard principal — wildcard at the domain level grants access to every repo in the domain.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove ``Principal: "*"`` (or ``Principal.AWS: "*"``) from every ``Allow`` statement in ``PermissionsPolicyDocument``. Name the specific accounts and add an ``aws:PrincipalOrgID`` condition.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CA-004: CodeArtifact repo policy grants codeartifact:* with Resource '*' { #ca-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Parses ``AWS::CodeArtifact::Repository.Properties.PermissionsPolicyDocument``. Fires when an ``Allow`` statement pairs ``codeartifact:*`` (or ``*``) with ``Resource: "*"``. That combination lets the principal publish, delete, and rewrite every package version in the repo.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enumerate specific actions and resources instead of ``codeartifact:*`` with ``Resource: "*"``.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## CB-001: Secrets in plaintext environment variables { #cb-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Walks every ``AWS::CodeBuild::Project``'s ``Properties.Environment.EnvironmentVariables`` list. Flags any entry whose ``Type`` is ``PLAINTEXT`` (or absent — the CFN default) when (a) the ``Name`` matches a secret-like pattern (``PASSWORD``, ``TOKEN``, ``API_KEY``, …) or (b) the ``Value`` matches a known credential shape (AKIA/ASIA, GitHub tokens, JWTs).

<div class="pg-rule__rec" markdown>

**Recommended action**

Move secrets to AWS Secrets Manager or SSM Parameter Store and reference them via ``Type: SECRETS_MANAGER`` or ``Type: PARAMETER_STORE`` on the corresponding ``Environment.EnvironmentVariables`` entry.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CB-002: Privileged mode enabled { #cb-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Reads ``AWS::CodeBuild::Project.Properties.Environment.PrivilegedMode``. Privileged mode grants the build container root-level access to the Docker daemon on the host.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``Environment.PrivilegedMode: false`` (or omit it; the CFN default is ``false``). Where Docker-in-Docker is unavoidable, consider Kaniko or BuildKit and keep the buildspec under branch protection.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CB-003: Build logging not enabled { #cb-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Reads both ``LogsConfig.CloudWatchLogs.Status`` and ``LogsConfig.S3Logs.Status``. Without either, the build's stdout/stderr is captured only in the in-flight console view — audit and incident review have no record.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable at least one of ``LogsConfig.CloudWatchLogs.Status: ENABLED`` or ``LogsConfig.S3Logs.Status: ENABLED``. CloudWatch is the easier default; pair S3 with an object-lock bucket for tamper-evident retention.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## CB-004: No build timeout configured { #cb-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--cwe">CWE-400</span>
</div>

Reads ``AWS::CodeBuild::Project.Properties.TimeoutInMinutes``. Projects left at the AWS maximum of 480 minutes let a runaway or hijacked build consume compute and delay detection of a compromised pipeline stage.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``TimeoutInMinutes`` to a value matched to your real build duration (15–60 minutes is typical). Pair with a CloudWatch alarm on ``AWS/CodeBuild`` ``BuildDuration``.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CB-005: Outdated managed build image { #cb-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Matches ``Environment.Image`` against ``aws/codebuild/standard:<major>.<minor>``. Older managed images carry unpatched OS packages, runtimes, and build tools — every artifact they produce inherits those gaps.

<div class="pg-rule__rec" markdown>

**Recommended action**

Update ``Environment.Image`` to the latest ``aws/codebuild/standard:<major>.0`` release. For custom or third-party images, pin by ``@sha256:<digest>`` rather than a mutable tag.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CB-006: CodeBuild source auth uses long-lived token { #cb-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Reads ``Source.Type`` and ``Source.Auth.Type`` plus any ``AWS::CodeBuild::SourceCredential.{ServerType,AuthType}`` side resource. Fires when an external VCS source (``GITHUB``, ``GITHUB_ENTERPRISE``, ``BITBUCKET``) is authenticated with a long-lived credential.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``OAUTH`` / ``PERSONAL_ACCESS_TOKEN`` / ``BASIC_AUTH`` with an AWS CodeConnections (CodeStar) connection. Tokens stored via ``AWS::CodeBuild::SourceCredential`` or inline ``Source.Auth`` don't rotate.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CB-007: CodeBuild webhook has no filter_group { #cb-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Unlike Terraform (where webhooks are a separate resource), CFN models the webhook as a property of ``AWS::CodeBuild::Project.Triggers``. Reads ``Triggers.{Webhook,FilterGroups}`` and fires when a webhook is enabled with no filter groups.

<div class="pg-rule__rec" markdown>

**Recommended action**

Define ``Triggers.FilterGroups`` entries that restrict triggers to specific branches, actors, and event types. At minimum include an ``ACTOR_ACCOUNT_ID`` filter to keep fork PRs from triggering builds.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CB-008: CodeBuild buildspec is inline (not sourced from a protected repo) { #cb-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Inspects ``AWS::CodeBuild::Project.Properties.Source.BuildSpec``. Flags multi-line literal values or values that begin with YAML preamble (``version:``, ``phases:``) — those indicate an inline spec that any principal with ``codebuild:UpdateProject`` can rewrite without going through code review.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move buildspec content into a ``buildspec.yml`` inside the source repository, under branch protection. Reference it from ``Source.BuildSpec`` only by relative path.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CB-009: CodeBuild image not pinned by digest { #cb-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Classifies ``Environment.Image`` using the same shared image classifier the workflow providers use. Mutable tags let an upstream image swap execute on the next build with no template change.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin ``Environment.Image`` by ``@sha256:<digest>`` rather than a mutable tag. AWS-managed ``aws/codebuild/standard:N`` images are exempted.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CB-010: CodeBuild webhook allows fork-PR builds without actor filtering { #cb-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--cwe">CWE-863</span>
</div>

Reads ``Triggers.FilterGroups[*]``. For each group that covers a ``PULL_REQUEST_*`` event, fires when no sibling ``ACTOR_ACCOUNT_ID`` filter constrains the PR author.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add an ``ACTOR_ACCOUNT_ID`` filter to every ``Triggers.FilterGroups`` entry whose ``EVENT`` filter covers a ``PULL_REQUEST_*`` event. Without it, a fork-PR build runs with the project's service role.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## CB-011: CodeBuild buildspec contains indicators of malicious activity { #cb-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--cwe">CWE-506</span>
</div>

Runs the shared buildspec-IOC matcher against any inline ``Source.BuildSpec``. The matcher looks for reverse-shell payloads, miner CLIs, secret-exfil patterns, and credential-grabbing one-liners.

<div class="pg-rule__rec" markdown>

**Recommended action**

Treat any hit on this rule as a potential pipeline compromise. Identify the commit that introduced the buildspec, rotate every credential reachable by the project's service role, and move the buildspec to a repo-sourced file under branch protection (see CB-008).

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CCM-002: CodeCommit repository not encrypted with customer KMS CMK { #ccm-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-311</span>
</div>

Reads ``AWS::CodeCommit::Repository.Properties.KmsKeyId``. Empty values fall back to AWS-owned encryption, which can't be audited or scoped to a specific role via key policy.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``KmsKeyId`` on every ``AWS::CodeCommit::Repository`` to a customer-managed CMK ARN. Source code carries IP, credentials, and customer data — the encryption boundary matters.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CCM-003: CodeCommit trigger targets SNS/Lambda in a different account { #ccm-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--cwe">CWE-942</span>
</div>

Compares ``Triggers[*].DestinationArn`` against the account id of the current stack (extracted from sibling resource ARNs when possible). A trigger whose destination lives in another account leaks repository activity outside the trust boundary.

<div class="pg-rule__rec" markdown>

**Recommended action**

Point ``Triggers[*].DestinationArn`` at an SNS topic or Lambda function in the same account. If cross-account is intentional, document the receiving account in your threat model and baseline this finding.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CD-001: Automatic rollback on failure not enabled { #cd-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--cwe">CWE-754</span>
</div>

Reads ``AWS::CodeDeploy::DeploymentGroup.Properties.AutoRollbackConfiguration``. The block needs ``Enabled: true`` AND ``"DEPLOYMENT_FAILURE"`` present in ``Events`` for the deployment group to self-heal.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enable ``AutoRollbackConfiguration`` with at least the ``DEPLOYMENT_FAILURE`` event so a failed release returns the environment to its prior state without manual intervention.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CD-002: AllAtOnce deployment config, no canary or rolling strategy { #cd-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--cwe">CWE-754</span>
</div>

Reads ``AWS::CodeDeploy::DeploymentGroup.Properties.DeploymentConfigName``. Fires when the value is ``CodeDeployDefault.AllAtOnce``, ``LambdaAllAtOnce``, or ``ECSAllAtOnce`` — these route every request to the new revision simultaneously.

<div class="pg-rule__rec" markdown>

**Recommended action**

Switch ``DeploymentConfigName`` to a canary or linear config (e.g. ``CodeDeployDefault.LambdaCanary10Percent5Minutes``). A staged rollout gives alarm-based rollback a window to catch regressions before they hit 100% of traffic.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CD-003: No CloudWatch alarm monitoring on deployment group { #cd-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Reads ``AWS::CodeDeploy::DeploymentGroup.Properties.AlarmConfiguration.{Enabled,Alarms}``. Without an alarm list, error spikes or latency regressions from a release won't auto-halt the deployment.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add CloudWatch alarms to ``AlarmConfiguration.Alarms`` and set ``AlarmConfiguration.Enabled: true``. Pair with CD-001 — alarm-triggered rollback only fires when at least one alarm exists to monitor.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CF-001: Template declares AWS::IAM::AccessKey (long-lived credential) { #cf-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Fires on every ``AWS::IAM::AccessKey`` in the template. CloudFormation writes the resulting ``SecretAccessKey`` to stack outputs — the secret is now in every stack update log and every ``DescribeStacks`` response.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace static keys with role-based access: an ``AWS::IAM::Role`` plus an ``AWS::IAM::OIDCProvider`` for CI, or an IAM role for service-to-service auth. Static keys live forever in stack outputs and any tool that ever read them.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## CF-002: Stateful data-store resource carries a plaintext secret { #cf-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--cwe">CWE-312</span>
</div>

Walks every string value of the stateful data-store resources (``AWS::RDS::DBInstance``, ``AWS::RDS::DBCluster``, ``AWS::Redshift::Cluster``, ``AWS::ElastiCache::ReplicationGroup``, ``AWS::DocDB::DBCluster``, ``AWS::Neptune::DBCluster``, ``AWS::OpenSearchService::Domain``, ``AWS::MemoryDB::Cluster``). Fires when a string leaf matches a credential shape OR when a secret-named attribute (``*Password``, ``*Token``, …) carries a non-placeholder literal.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move the secret into Secrets Manager (or SSM Parameter Store SecureString) and reference it via ``'{{resolve:secretsmanager:…}}'`` at deploy time. Never literal-string a credential into a stateful resource — the value lives in the template, the stack history, and any drift detection report.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CF-003: CodeBuild VPC config references a public subnet { #cf-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--cwe">CWE-1327</span>
</div>

When ``AWS::CodeBuild::Project.Properties.VpcConfig.VpcId`` resolves to a concrete reference, walks every ``AWS::EC2::Subnet`` in the same VPC and fires if any has ``MapPublicIpOnLaunch: true``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Place CodeBuild projects in private subnets (``MapPublicIpOnLaunch: false``) with egress routed through a NAT gateway or VPC interface endpoints. Public subnets put the build host on a public IP for the duration of the build.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CP-001: No approval action before deploy stages { #cp-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--cwe">CWE-862</span>
</div>

Walks ``AWS::CodePipeline::Pipeline.Stages[*].Actions[*].ActionTypeId.Category``. Fires when any ``Deploy`` action is reachable from the source without an intervening ``Approval`` action upstream.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``Manual`` approval action to a stage that precedes every ``Deploy``-category action. Pipelines that auto-promote to production trust every prior stage's findings absolutely.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CP-002: Artifact store not encrypted with customer-managed KMS key { #cp-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-311</span>
</div>

Reads ``ArtifactStore.EncryptionKey`` (or ``ArtifactStores`` for cross-region pipelines). An empty value means the store falls back to AWS-owned-key S3 SSE; with a CMK you control key policy and rotation independently.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``ArtifactStore.EncryptionKey`` (or every entry in ``ArtifactStores.EncryptionKey``) to a customer-managed KMS CMK. Default S3 SSE is encrypted by an AWS-owned key you can't rotate or scope by IAM.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## CP-003: Source stage using polling instead of event-driven trigger { #cp-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--cwe">CWE-1188</span>
</div>

Reads ``Stages[*].Actions[*]`` where ``ActionTypeId.Category == "Source"`` and ``Configuration.PollForSourceChanges`` is the string ``"true"``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``Configuration.PollForSourceChanges: false`` on every ``Source`` action and create an EventBridge rule (or CodeStar connection) to drive change detection on commit.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CP-004: Legacy ThirdParty/GitHub source action (OAuth token) { #cp-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Fires on ``Stages[*].Actions[*]`` whose ``ActionTypeId.Owner == "ThirdParty"`` AND ``ActionTypeId.Provider == "GitHub"``. The v1 GitHub action stores a long-lived OAuth token literally in the pipeline configuration.

<div class="pg-rule__rec" markdown>

**Recommended action**

Switch the source action to ``ActionTypeId.Owner: AWS`` + ``ActionTypeId.Provider: CodeStarSourceConnection`` and point ``Configuration.ConnectionArn`` at an ``AWS::CodeStarConnections::Connection``.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CP-005: Production Deploy stage has no preceding ManualApproval { #cp-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--cwe">CWE-862</span>
</div>

A stricter version of CP-001 scoped to production-named stages. Walks ``Stages[*].Name`` for ``prod`` / ``production`` / ``live`` substrings and requires a preceding ``Approval`` action.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``Manual`` approval action in the stage that precedes any stage whose name contains ``prod`` / ``production`` / ``live`` and contains a Deploy action.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CP-007: CodePipeline v2 PR trigger accepts all branches { #cp-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--cwe">CWE-863</span>
</div>

Inspects v2 pipelines (``PipelineType: V2``) whose ``Triggers[*].GitConfiguration`` declares a ``PullRequest`` block without ``Branches.Includes``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``Triggers[*].GitConfiguration.PullRequest[*].Branches.Includes`` to the specific branches the pipeline expects. An empty include list runs on every branch event, including fork-PR rebases.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## CT-001: No active CloudTrail trail in region { #ct-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Counts ``AWS::CloudTrail::Trail`` resources. Without a trail (declared here or out-of-band), management-plane activity has no durable audit record.

<div class="pg-rule__rec" markdown>

**Recommended action**

Declare at least one ``AWS::CloudTrail::Trail`` — typically a single ``IsMultiRegionTrail: true`` trail sending events to a write-protected S3 bucket. If trails are managed out-of-band, baseline this rule's INFO emission.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CT-002: CloudTrail log-file validation disabled { #ct-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-353</span>
</div>

Reads ``AWS::CloudTrail::Trail.Properties.EnableLogFileValidation``. Without it, an attacker with ``s3:PutObject`` on the trail's bucket can rewrite event records and there's no cryptographic record of the original.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``EnableLogFileValidation: true`` on every ``AWS::CloudTrail::Trail``. CloudTrail then writes hash digests S3 cannot tamper with, post-incident validation can detect log forgery.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CT-003: CloudTrail trail is not multi-region { #ct-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Reads ``AWS::CloudTrail::Trail.Properties.IsMultiRegionTrail``. Multi-region is the only configuration that guarantees you'll see ``CreateAccessKey`` in ``ap-south-1`` from your ``us-east-1`` trail.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``IsMultiRegionTrail: true`` so a single trail captures activity from every region. A region-scoped trail misses anything an attacker does in another region.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## CW-001: No CloudWatch alarm on CodeBuild FailedBuilds metric { #cw-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Gated check: fires only when the template declares ``AWS::CodeBuild::Project``. Passes when at least one ``AWS::CloudWatch::Alarm`` is configured for ``Namespace: AWS/CodeBuild`` + ``MetricName: FailedBuilds``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Declare an ``AWS::CloudWatch::Alarm`` with ``Namespace: AWS/CodeBuild`` and ``MetricName: FailedBuilds`` and route it to an actionable destination (PagerDuty, Slack via Chatbot, SNS topic with a human responder).

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## CWL-001: CodeBuild log group has no retention policy { #cwl-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-1188</span>
</div>

Filters ``AWS::Logs::LogGroup`` by ``LogGroupName`` prefix ``/aws/codebuild/`` and reads ``RetentionInDays``. Unbounded retention isn't free; it also makes incident response harder when there are years of irrelevant logs to grep.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``RetentionInDays`` on every ``AWS::Logs::LogGroup`` whose name starts with ``/aws/codebuild/``. 30 / 90 / 365 days are typical.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## CWL-002: CodeBuild log group not KMS-encrypted { #cwl-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-311</span>
</div>

Reads ``AWS::Logs::LogGroup.Properties.KmsKeyId`` on log groups whose name starts with ``/aws/codebuild/``. Without a CMK, logs are encrypted with an AWS-owned key, which can't be audited or scoped by IAM.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``KmsKeyId`` on every ``AWS::Logs::LogGroup`` whose name starts with ``/aws/codebuild/`` to a customer-managed CMK ARN. Build logs commonly carry secret fragments and environment dumps.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## EB-001: No EventBridge rule for CodePipeline failure notifications { #eb-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Looks for at least one ``AWS::Events::Rule`` whose ``EventPattern`` JSON matches ``aws.codepipeline`` ``Pipeline Execution State Change`` events filtered to ``FAILED``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Declare an ``AWS::Events::Rule`` whose ``EventPattern`` matches ``aws.codepipeline`` events with ``detail.state: FAILED``, and target it at the notification destination of your choice (SNS, Slack via Chatbot, PagerDuty).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## EB-002: EventBridge rule has a wildcard target ARN { #eb-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--cwe">CWE-441</span>
</div>

Reads ``AWS::Events::Rule.Properties.Targets[*].Arn``. A literal ``*`` in the ARN is the offending shape — it makes the target opaque to any reviewer tracing event flow.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin ``AWS::Events::Rule.Targets[*].Arn`` to a specific function or queue ARN. Wildcards in target ARNs defeat the per-target audit trail and let any resource matching the pattern receive the event.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ECR-001: Image scanning on push not enabled { #ecr-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Reads ``AWS::ECR::Repository.Properties.ImageScanningConfiguration.ScanOnPush``. Without it, a freshly-pushed image goes straight into deployable storage with no known-CVE pass.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``ImageScanningConfiguration.ScanOnPush: true`` on every ``AWS::ECR::Repository``. For deeper coverage, also enable Inspector v2 enhanced scanning at the registry level.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ECR-002: Image tags are mutable { #ecr-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Reads ``AWS::ECR::Repository.Properties.ImageTagMutability``. Default is ``MUTABLE`` — anyone with ``ecr:PutImage`` on the repo can overwrite release tags consumed by production deployments.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``ImageTagMutability: IMMUTABLE`` on every ``AWS::ECR::Repository``. Immutable tags point at exactly one digest forever — an attacker can't swap ``:latest`` mid-deploy.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## ECR-003: Repository policy allows public access { #ecr-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Parses ``AWS::ECR::Repository.Properties.RepositoryPolicyText`` (or the standalone resource if used). Flags any ``Allow`` statement that names a wildcard principal — wildcard there lets every AWS account in the world pull the image.

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop any ``Statement`` with ``Effect: Allow`` plus ``Principal: "*"`` (or ``Principal.AWS: "*"`` / ``Principal.Service: "*"``). Use specific account IDs.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## ECR-004: No lifecycle policy configured { #ecr-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--cwe">CWE-400</span>
</div>

Reads ``AWS::ECR::Repository.Properties.LifecyclePolicy``. Without one, images and untagged digests accumulate indefinitely — old vulnerable images stay deployable.

<div class="pg-rule__rec" markdown>

**Recommended action**

Configure ``LifecyclePolicy.LifecyclePolicyText`` with rules that expire untagged and old tagged images. Bounded image age and bounded image count are reasonable starting points.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## ECR-005: Repository encrypted with AES256 rather than KMS CMK { #ecr-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-311</span>
</div>

Reads ``AWS::ECR::Repository.Properties.EncryptionConfiguration.{EncryptionType,KmsKey}``. The AES256 default uses an AWS-owned key — you can't audit who used it or revoke access with a key policy.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``EncryptionConfiguration.EncryptionType: KMS`` and ``EncryptionConfiguration.KmsKey: <CMK ARN>`` referencing a customer-managed CMK with a key policy scoped to the principals that legitimately pull.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## ECR-006: ECR pull-through cache rule uses an untrusted upstream { #ecr-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Reads ``AWS::ECR::PullThroughCacheRule.Properties.{UpstreamRegistryUrl,CredentialArn}``. Fires when the upstream is not on the trusted allow-list AND no credential ARN is configured.

<div class="pg-rule__rec" markdown>

**Recommended action**

Either scope ``UpstreamRegistryUrl`` to a trusted registry (``public.ecr.aws``, ``registry.k8s.io``, ``ghcr.io``, ``gcr.io``) or set ``CredentialArn`` so the upstream authenticates the pull.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## IAM-001: CI/CD role has AdministratorAccess policy attached { #iam-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Considers a role CI/CD-scoped when its ``AssumeRolePolicyDocument`` trusts ``codebuild.amazonaws.com``, ``codepipeline.amazonaws.com``, or ``codedeploy.amazonaws.com``. Reads ``ManagedPolicyArns`` literal entries; fires when ``arn:aws:iam::aws:policy/AdministratorAccess`` appears.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``AdministratorAccess`` with least-privilege policies that grant only the specific actions and resources the build needs. Pair with IAM-003 (permissions boundary) so a future policy edit can't quietly re-broaden the role.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## IAM-002: CI/CD role has wildcard Action in attached policy { #iam-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Walks every policy document attached to a CI/CD role: inline ``Role.Policies`` plus the resolved ``AWS::IAM::ManagedPolicy`` referenced via ``ManagedPolicyArns: { Ref: … }``. Fires when any ``Allow`` statement names ``"*"`` in ``Action``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enumerate the specific IAM actions the role needs and drop ``Action: "*"`` entirely. Access Analyzer or CloudTrail-based policy generation can suggest a minimum set.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## IAM-003: CI/CD role has no permission boundary { #iam-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Reads ``AWS::IAM::Role.Properties.PermissionsBoundary``. Without a boundary, every additive policy attached to the role takes immediate effect — there's no second layer constraining the maximum reach.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``PermissionsBoundary`` on every CI/CD role to a managed policy ARN (or ``{ Ref: <ManagedPolicy> }``). Boundaries cap effective permissions even if an admin later attaches a broader policy.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## IAM-004: CI/CD role can PassRole to any role { #iam-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Inspects every policy reachable from a CI/CD role. Fires on any ``Allow`` statement granting ``iam:PassRole`` (or ``iam:*`` / ``*``) with ``Resource: "*"``. PassRole on a wildcard resource is the canonical AWS privilege-escalation primitive.

<div class="pg-rule__rec" markdown>

**Recommended action**

Scope ``iam:PassRole`` to the specific role ARNs the pipeline must hand off to. Add an ``iam:PassedToService`` condition so the role can only be passed to the service that actually consumes it.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## IAM-005: CI/CD role trust policy missing sts:ExternalId { #iam-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-441</span>
</div>

Parses ``AssumeRolePolicyDocument``. Walks every ``Allow`` statement whose ``Principal.AWS`` is an external account, and fires when no ``Condition`` carries ``sts:ExternalId``. Without it, the role is vulnerable to the confused-deputy pattern.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``Condition`` block with ``StringEquals.sts:ExternalId`` to every trust-policy statement that allows an external AWS account to assume the role. Generate a high-entropy ExternalId once and store it in the relying party's configuration.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## IAM-006: Sensitive actions granted with wildcard Resource { #iam-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Inspects every policy reachable from a CI/CD role. Fires on any ``Allow`` statement that pairs a sensitive service action (``s3:*``, ``kms:*``, ``secretsmanager:*``, ``ssm:*``, ``iam:*``, ``sts:*``, ``dynamodb:*``, ``lambda:*``, ``ec2:*``) with ``Resource: "*"``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Scope ``Resource`` to specific ARNs (bucket ARNs, key ARNs, secret ARNs, role ARNs). Reserve ``Resource: "*"`` for actions that genuinely require it (``ec2:Describe*``, ``cloudwatch:DescribeAlarms``).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## IAM-008: OIDC-federated role trust policy missing audience or subject pin { #iam-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-287</span>
</div>

Inspects every ``AWS::IAM::Role.Properties.AssumeRolePolicyDocument`` that carries an OIDC trust statement (provider URL like ``token.actions.githubusercontent.com``). Fires when ``Condition`` omits the audience or subject claim — without both, any repo under the IdP can assume the role.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add ``Condition.StringEquals`` (or ``StringLike``) entries pinning both ``<host>:aud`` and ``<host>:sub`` to specific values. For GitHub Actions: pin ``aud`` to ``sts.amazonaws.com`` and ``sub`` to ``repo:<org>/<repo>:ref:refs/heads/main`` (or the env / branch combination the role expects).

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## KMS-001: Customer-managed symmetric KMS key has rotation disabled { #kms-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--cwe">CWE-322</span>
</div>

Reads ``AWS::KMS::Key.Properties.EnableKeyRotation`` on symmetric keys (``KeySpec`` = ``SYMMETRIC_DEFAULT`` or absent). Asymmetric keys are skipped — KMS doesn't rotate them, key replacement is the only path.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``EnableKeyRotation: true`` on every symmetric ``AWS::KMS::Key``. KMS rotates the underlying key material once per year transparently, no downstream change is needed.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## KMS-002: KMS key policy grants kms:* to an IAM principal { #kms-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Parses ``AWS::KMS::Key.Properties.KeyPolicy``. Fires on any ``Allow`` statement that pairs ``kms:*`` with a non-root IAM principal — that's the canonical key-compromise primitive.

<div class="pg-rule__rec" markdown>

**Recommended action**

Enumerate the specific KMS actions each principal needs (``kms:Encrypt``, ``kms:Decrypt``, ``kms:GenerateDataKey``, ``kms:DescribeKey``). Reserve ``kms:*`` for the root principal that owns the key.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## LMB-001: Lambda function has no code-signing config { #lmb-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Reads ``AWS::Lambda::Function.Properties.CodeSigningConfigArn``. Without it, Lambda accepts any zip the deployer can upload — there's no cryptographic check that the artifact came from the expected pipeline.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``CodeSigningConfigArn`` on every ``AWS::Lambda::Function`` to an ``AWS::Lambda::CodeSigningConfig`` whose allowed publishers list signing profiles your release pipeline uses.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## LMB-002: Lambda Function URL configured with AuthType = NONE { #lmb-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--cwe">CWE-862</span>
</div>

Reads ``AWS::Lambda::Url.Properties.AuthType``. The ``NONE`` setting exposes the function over a public HTTPS endpoint with no authentication.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``AuthType: AWS_IAM`` on every ``AWS::Lambda::Url`` and grant invoke via explicit ``AWS::Lambda::Permission`` resources rather than leaving the URL public.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## LMB-003: Lambda environment variables contain plaintext secrets { #lmb-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Walks ``AWS::Lambda::Function.Properties.Environment.Variables`` for (a) secret-like names (``PASSWORD``, ``TOKEN``, ``API_KEY``) and (b) credential-shaped values (``AKIA…``, ``ghp_…``, ``xox*``, JWTs).

<div class="pg-rule__rec" markdown>

**Recommended action**

Move secrets to Secrets Manager or SSM Parameter Store and read them at function init time. For static values that must live in the env, encrypt them at rest with a customer CMK via ``KmsKeyArn``.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## LMB-004: Lambda resource policy grants wildcard principal { #lmb-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Inspects every ``AWS::Lambda::Permission`` resource. Fires when ``Principal`` is ``"*"`` or any other wildcard form. A wildcard invoker exposes the function — and the role it executes with — to the whole internet.

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop any ``AWS::Lambda::Permission`` with ``Principal: "*"``. Name the specific service principal or account that needs invoke, and scope further with ``SourceAccount`` / ``SourceArn`` conditions.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## PBAC-001: CodeBuild project has no VPC configuration { #pbac-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--cwe">CWE-1327</span>
</div>

Reads ``AWS::CodeBuild::Project.Properties.VpcConfig.{VpcId,Subnets,SecurityGroupIds}``. All three must be set. Without VPC config, build nodes run in AWS-managed infrastructure with unrestricted outbound internet.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``VpcConfig.VpcId``, ``VpcConfig.Subnets``, and ``VpcConfig.SecurityGroupIds`` on every ``AWS::CodeBuild::Project``. Use private subnets with egress scoped to the package mirrors and AWS endpoints the build actually needs.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## PBAC-002: CodeBuild service role shared across multiple projects { #pbac-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Counts ``AWS::CodeBuild::Project.ServiceRole`` collisions (``Ref`` / ``Fn::GetAtt`` references are resolved to the target logical id so identical-target references coalesce). When two or more projects point at the same role, a build compromise in any one inherits the others' permissions.

<div class="pg-rule__rec" markdown>

**Recommended action**

Create one ``AWS::IAM::Role`` per ``AWS::CodeBuild::Project`` and reference it via ``ServiceRole``. Per-project roles cap the blast radius of a hijacked build.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## PBAC-003: CodeBuild security group allows 0.0.0.0/0 all-port egress { #pbac-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--cwe">CWE-1327</span>
</div>

Walks ``AWS::EC2::SecurityGroup.Properties.SecurityGroupEgress`` for every SG attached to a CodeBuild project's ``VpcConfig``. Fires on any rule that allows ``0.0.0.0/0`` on the full port range — that's a completely open exfiltration channel.

<div class="pg-rule__rec" markdown>

**Recommended action**

Scope egress to the specific destinations the build needs. Drop the catch-all ``SecurityGroupEgress: { CidrIp: 0.0.0.0/0, IpProtocol: -1 }``.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## PBAC-005: Pipeline action roles all equal the pipeline-level role { #pbac-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Compares each ``Stages[*].Actions[*].RoleArn`` against the pipeline's top-level ``RoleArn``. When all action-level values are empty or identical to the pipeline role, every stage runs with the same blast-radius.

<div class="pg-rule__rec" markdown>

**Recommended action**

Assign a least-privilege ``RoleArn`` to every ``Stages[*].Actions[*]`` that needs cross-account or cross-service permissions, instead of falling back to the pipeline's top-level ``RoleArn``.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## S3-001: Artifact bucket public access block not fully enabled { #s3-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Discovers pipeline artifact buckets via ``ArtifactStore.Location`` / ``ArtifactStores[*].Location`` and reads ``AWS::S3::Bucket.Properties.PublicAccessBlockConfiguration``. Any of the four PAB flags left ``false`` (or missing) lets an ACL or bucket policy expose build artifacts.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``PublicAccessBlockConfiguration.{BlockPublicAcls,IgnorePublicAcls,BlockPublicPolicy,RestrictPublicBuckets}`` all to ``true`` on every artifact bucket.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## S3-002: Artifact bucket server-side encryption not configured { #s3-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-311</span>
</div>

Reads ``AWS::S3::Bucket.Properties.BucketEncryption.ServerSideEncryptionConfiguration[0].ServerSideEncryptionByDefault.SSEAlgorithm``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Configure ``BucketEncryption.ServerSideEncryptionConfiguration`` with ``ServerSideEncryptionByDefault.SSEAlgorithm: aws:kms`` and ``KMSMasterKeyID`` set to a customer-managed CMK.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## S3-003: Artifact bucket versioning not enabled { #s3-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-353</span>
</div>

Reads ``AWS::S3::Bucket.Properties.VersioningConfiguration.Status`` — must be ``Enabled``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``VersioningConfiguration.Status: Enabled`` on every artifact bucket. Versioning lets you recover from accidental or malicious overwrites without restoring from external backups.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## S3-004: Artifact bucket access logging not enabled { #s3-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--cwe">CWE-778</span>
</div>

Reads ``AWS::S3::Bucket.Properties.LoggingConfiguration.DestinationBucketName``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``LoggingConfiguration.DestinationBucketName`` to a central, write-protected logging bucket. Access logs are what forensics use to reconstruct who pulled which artifact during an incident.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## S3-005: Artifact bucket missing aws:SecureTransport deny { #s3-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-319</span>
</div>

Looks for an ``AWS::S3::BucketPolicy`` joined to the artifact bucket by ``Bucket`` (literal name or ``{ Ref: <BucketLogicalId> }``). Parses the policy and scans for any ``Deny`` statement whose ``Condition`` matches ``aws:SecureTransport = false``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Attach an ``AWS::S3::BucketPolicy`` carrying a ``Deny`` statement on ``Action: "s3:*"`` when ``Bool aws:SecureTransport = false``.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SIGN-001: No active AWS Signer profile exists for the Lambda platform { #sign-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Gated check: fires only when an ``AWS::Lambda::Function`` references ``CodeSigningConfigArn``. Passes when at least one ``AWS::Signer::SigningProfile`` with ``PlatformId`` starting with ``AWSLambda-`` exists in the template.

<div class="pg-rule__rec" markdown>

**Recommended action**

Declare an ``AWS::Signer::SigningProfile`` with ``PlatformId: AWSLambda-SHA384-ECDSA`` and reference it from an ``AWS::Lambda::CodeSigningConfig``. Without one, Lambda code signing has no signer to validate against (see LMB-001).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## SM-001: Secrets Manager secret has no rotation configured { #sm-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--cwe">CWE-262</span>
</div>

Joins ``AWS::SecretsManager::RotationSchedule`` to ``AWS::SecretsManager::Secret`` by ``SecretId``. Fires when a secret has no matching rotation resource — a static secret lives forever in any backup or snapshot taken since the leak.

<div class="pg-rule__rec" markdown>

**Recommended action**

Declare an ``AWS::SecretsManager::RotationSchedule`` that targets the secret via ``SecretId`` (literal ARN or ``{ Ref: <SecretLogicalId> }``), with ``HostedRotationLambda`` or a ``RotationLambdaARN`` plus ``RotationRules.AutomaticallyAfterDays``.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## SM-002: Secrets Manager resource policy allows wildcard principal { #sm-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Parses ``AWS::SecretsManager::ResourcePolicy.Properties.ResourcePolicy``. Fires on any ``Allow`` statement that names a wildcard principal — the secret content is readable by every AWS account in the world until the policy is fixed.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove ``Principal: "*"`` (or ``Principal.AWS: "*"``) from every ``Allow`` statement on ``AWS::SecretsManager::ResourcePolicy``. If cross-account access is intentional, name the specific accounts and add an ``aws:PrincipalOrgID`` condition.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## SSM-001: SSM parameter with secret-like name stored as String, not SecureString { #ssm-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--cwe">CWE-312</span>
</div>

Checks ``AWS::SSM::Parameter.Properties.Name`` against the standard secret-name regex. If the name matches and ``Type`` is ``String`` (the CFN-only default — ``SecureString`` is not creatable via CFN, see AWS docs), the value is in plaintext.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``Type: SecureString`` on every ``AWS::SSM::Parameter`` whose name or value looks secret-like. SecureString parameters are encrypted with KMS and audited separately from plain ``GetParameter`` access.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## SSM-002: SecureString uses alias/aws/ssm rather than a customer CMK { #ssm-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--cwe">CWE-311</span>
</div>

Reads ``AWS::SSM::Parameter.Properties.{Type,KeyId}``. Fires on a ``SecureString`` whose ``KeyId`` is empty or set to ``alias/aws/ssm``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``KeyId`` on every ``SecureString`` ``AWS::SSM::Parameter`` to a customer-managed KMS CMK ARN. Default ``alias/aws/ssm`` is an AWS-owned key that can't be scoped or rotated by your key policy.

</div>

</div>

---

## Adding a new CloudFormation check

1. Drop a single module at
   `pipeline_check/core/checks/cloudformation/rules/<id>_<slug>.py`
   exporting a `RULE` (metadata) and a
   `check(ctx: CloudFormationContext) -> list[Finding]` callable. The
   orchestrator (`CloudFormationRuleChecks`) auto-discovers it and
   this doc's table picks it up on the next regen.
2. If the rule needs side resources (managed-policy dereferencing,
   artifact-bucket discovery, policy documents joined on
   ``Bucket`` / ``RoleName``), add a private helper to
   `pipeline_check/core/checks/cloudformation/rules/_<service>_context.py`
   following the `_iam_context.py` / `_s3_context.py` pattern.
3. Add the check ID to
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
4. Add unit tests in `tests/cloudformation/test_<service>.py` using
   `make_cfn_ctx` or one of the existing template fixtures.
5. (Recommended) Add an AWS-runtime parity rule under
   `pipeline_check/core/checks/aws/rules/` and a Terraform parity
   rule under `pipeline_check/core/checks/terraform/rules/` so the
   three IaC entry points stay aligned.
6. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py cloudformation
   ```
