# CloudFormation provider

Scans a **CloudFormation template** (YAML or JSON) — no live AWS
credentials required. Short-form intrinsics (`!Ref`, `!Sub`, `!GetAtt`,
`!Join`, `!If`, …) are normalised to their JSON-form equivalents at
parse time so rules operate on one uniform structure.

Every check ID mirrors its AWS-provider counterpart one-to-one. The
semantics are identical; only the data source differs.

## Producer workflow

```bash
pipeline_check --pipeline cloudformation --cfn-template path/to/template.yaml
# or point at a directory and every *.yml / *.yaml / *.json / *.template is scanned
pipeline_check --pipeline cloudformation --cfn-template infra/
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the AWS provider.

## What it covers

| Service          | IDs               | CloudFormation resources consumed                                            |
|------------------|-------------------|------------------------------------------------------------------------------|
| CodeBuild        | `CB-001…011`      | `AWS::CodeBuild::Project`, `AWS::CodeBuild::SourceCredential`                |
| CodePipeline     | `CP-001…007`      | `AWS::CodePipeline::Pipeline`                                                |
| CodeDeploy       | `CD-001…003`      | `AWS::CodeDeploy::DeploymentGroup`                                           |
| ECR              | `ECR-001…006`     | `AWS::ECR::Repository`, `AWS::ECR::PullThroughCacheRule`                     |
| IAM              | `IAM-001…008`     | `AWS::IAM::Role`, `AWS::IAM::Policy`, `AWS::IAM::ManagedPolicy`              |
| PBAC             | `PBAC-001…005`    | `AWS::CodeBuild::Project`, `AWS::EC2::SecurityGroup`                         |
| S3               | `S3-001…005`      | `AWS::S3::Bucket` (artifact buckets discovered from pipelines)               |
| CloudTrail       | `CT-001…003`      | `AWS::CloudTrail::Trail`                                                     |
| CloudWatch Logs  | `CWL-001…002`     | `AWS::Logs::LogGroup`                                                        |
| Secrets Manager  | `SM-001…002`      | `AWS::SecretsManager::Secret`, `AWS::SecretsManager::RotationSchedule`       |
| CodeArtifact     | `CA-001…004`      | `AWS::CodeArtifact::Domain`, `AWS::CodeArtifact::Repository`                 |
| CodeCommit       | `CCM-002`         | `AWS::CodeCommit::Repository` (CCM-001/003 omitted — no CFN resource)        |
| Lambda           | `LMB-001…004`     | `AWS::Lambda::Function`, `AWS::Lambda::Url`, `AWS::Lambda::Permission`       |
| KMS              | `KMS-001…002`     | `AWS::KMS::Key`                                                              |
| SSM              | `SSM-001…002`     | `AWS::SSM::Parameter`                                                        |
| EventBridge      | `EB-001…002`      | `AWS::Events::Rule` (targets are inline)                                     |
| Signer           | `SIGN-001`        | `AWS::Lambda::Function.CodeSigningConfigArn`, `AWS::Signer::SigningProfile`  |
| CloudWatch       | `CW-001`          | `AWS::CloudWatch::Alarm` (namespace=`AWS/CodeBuild`, metric=`FailedBuilds`)  |
| CFN-native       | `CF-001…003`      | `AWS::IAM::AccessKey`, stateful data-store types, `AWS::EC2::Subnet`         |

## Intrinsic handling

CFN values may be literals (``"ap-southeast-2"``), booleans, unresolved
intrinsics (``{"Ref": "Region"}``, ``{"Fn::Sub": "..."}``), or condition
references. The scanner follows two conventions:

1. **Anything not provably safe is treated as a potential offender
   unless the rule explicitly skips unresolved values.** For instance,
   ``is_true(value)`` returns ``True`` only for ``True`` or ``"true"`` —
   so a template that hides a ``Ref`` behind a boolean-typed property
   is scored as if the flag were disabled.
2. **Statically-reducible intrinsics are reduced before matching.**
   ``resolve_literal(value, parameters)`` in ``cloudformation/base.py``
   evaluates:
   - ``{"Ref": "ParamName"}`` against the template's ``Parameters.<Name>.Default``
   - ``{"Fn::Sub": "literal"}`` / ``{"Fn::Sub": "...${Var}..."}`` including
     the ``[template, {var-map}]`` form
   - ``{"Fn::Join": [delim, [list]]}`` when every list item resolves

   Rules that benefit (``EB-002`` target ARNs, ``CF-003`` VPC IDs)
   call the resolver first and fall back to the old "skip unresolved"
   path only when the intrinsic references a pseudo-parameter
   (``AWS::Region``) or a runtime-dependent intrinsic
   (``Fn::GetAtt``, ``Fn::ImportValue``, ``Fn::If``).

- Rule helpers:
  - ``as_str(value)`` — literal-only accessor, returns ``""`` for
    intrinsics. Used when the rule doesn't need resolution (e.g. a
    string-prefix match on a known-literal property).
  - ``resolve_literal(value, parameters)`` — tries to reduce every
    statically-resolvable intrinsic; returns ``None`` when it can't.
  - ``is_true(value)`` — strict boolean gate.
  - ``is_intrinsic(value)`` — predicate used by ``CF-002`` to skip
    intrinsic dicts entirely when walking for hard-coded secrets.

This matches cfn-lint and cfn-nag conventions and keeps findings
useful under the common case where templates are parameterised.

## Phase-4 gap fills and CFN-native rules

| Check    | Resource(s) read                                         | Condition                                                                           |
|----------|----------------------------------------------------------|-------------------------------------------------------------------------------------|
| SIGN-001 | `AWS::Lambda::Function`, `AWS::Signer::SigningProfile`   | Gated: only emits when a Lambda references `CodeSigningConfigArn`. Passes if any profile has `PlatformId` containing `AWSLambda`. |
| EB-002   | `AWS::Events::Rule`                                      | Fails when any `Targets[].Arn` literal contains a `*`. Intrinsic Arns are skipped.  |
| CW-001   | `AWS::CodeBuild::Project`, `AWS::CloudWatch::Alarm`      | Gated: only emits when the template declares CodeBuild. Passes if any alarm has `Namespace = AWS/CodeBuild` and `MetricName = FailedBuilds`. |
| CF-001   | `AWS::IAM::AccessKey`                                    | Fails for every `AWS::IAM::AccessKey` — the key material is emitted as a stack output or referenced by `Fn::GetAtt` and has no rotation. |
| CF-002   | Stateful data stores (`AWS::RDS::DBInstance`, `AWS::RDS::DBCluster`, `AWS::Redshift::Cluster`, `AWS::ElastiCache::ReplicationGroup`, `AWS::DocDB::DBCluster`, `AWS::Neptune::DBCluster`, `AWS::OpenSearchService::Domain`, `AWS::MemoryDB::Cluster`) | Fails when a string leaf matches a vendor-token shape or a secret-named property (`*Password`, `*Token`, …) carries a literal 8+ char value. `AWS::Lambda::Function` / `AWS::SSM::Parameter` / `AWS::CodeBuild::Project` / `AWS::SecretsManager::Secret` are skipped. |
| CF-003   | `AWS::CodeBuild::Project`, `AWS::EC2::Subnet`            | When `VpcConfig.VpcId` is a literal string, fails if any `AWS::EC2::Subnet` in the same `VpcId` has `MapPublicIpOnLaunch = true`. Silent when `VpcId` is an intrinsic. |

## Limitations

- **Template-level only.** Resources provisioned outside the template
  (console, SDK, sister stacks) are not scanned — use `--pipeline aws`
  alongside for a live view.
- **Intrinsics are not evaluated.** A ``Ref`` to a parameter, a
  ``Fn::Sub``, or a ``Fn::If`` passes through as an opaque dict. Rules
  that require a literal value silently skip the finding rather than
  guess at the resolved shape.
- **No cross-stack resolution.** ``Fn::ImportValue`` references are
  preserved as-is; the exporting stack is not fetched.
- **Transform macros are ignored.** `AWS::Serverless-2016-10-31` (SAM)
  and custom transforms run server-side — the pre-transform resources
  are what the scanner sees.
