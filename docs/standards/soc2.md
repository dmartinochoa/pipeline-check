# SOC 2 Trust Services Criteria

- **Version:** 2017 (revised 2022)
- **URL:** <https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022>
- **Source of truth:** `pipeline_check/core/standards/data/soc2.py`

SOC 2 Trust Services Criteria, CI/CD-relevant subset. Findings
evidence control gaps; they are not a substitute for an auditor's
opinion. Use this page to prepare CC6 / CC7 / CC8 evidence walks.

## At a glance

- **Controls in this standard:** 11
- **Controls evidenced by at least one check:** 11 / 11
- **Distinct checks evidencing this standard:** 649
- **Of those, autofixable with `--fix`:** 111

_Severity levels (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`) follow the same scale across every provider and standard. See [How to read severity](README.md#how-to-read-severity) on the standards overview for the definitions._

## Coverage by control

Click a control ID to jump to the per-control section with the full check list. The severity mix column shows the spread of evidencing checks by severity (`C`ritical / `H`igh / `M`edium / `L`ow / `I`nfo).

| Control | Title | Checks | Severity mix |
|---------|-------|-------:|--------------|
| [`CC6.1`](#ctrl-cc6-1) | Logical access controls restrict entities to authorized system resources | 131 | 24C · 67H · 35M · 5L |
| [`CC6.2`](#ctrl-cc6-2) | New internal and external users are registered, authorized, and provisioned | 24 | 10C · 8H · 6M |
| [`CC6.3`](#ctrl-cc6-3) | Access modifications (including revocation) are tracked and timely | 23 | 1C · 13H · 9M |
| [`CC6.6`](#ctrl-cc6-6) | Boundary-protection measures restrict access from outside the system boundary | 89 | 21C · 33H · 29M · 6L |
| [`CC6.7`](#ctrl-cc6-7) | Data in transit is protected from unauthorized disclosure | 32 | 27H · 4M · 1L |
| [`CC6.8`](#ctrl-cc6-8) | Controls prevent or detect the introduction of malicious software | 147 | 36C · 82H · 28M · 1L |
| [`CC7.1`](#ctrl-cc7-1) | Detection procedures identify configuration changes that introduce vulnerabilities | 30 | 8C · 6H · 10M · 6L |
| [`CC7.2`](#ctrl-cc7-2) | System components are monitored for anomalies indicative of malicious acts or failures | 40 | 4H · 13M · 7L · 16I |
| [`CC7.3`](#ctrl-cc7-3) | Security events are evaluated to determine if they require response | 8 | 1H · 5M · 2L |
| [`CC7.4`](#ctrl-cc7-4) | Identified security incidents trigger a response process | 6 | 4M · 2L |
| [`CC8.1`](#ctrl-cc8-1) | Changes to infrastructure, data, software, and procedures are authorized, designed, tested, approved, and implemented | 251 | 11C · 92H · 123M · 25L |

## Filter at runtime

Restrict a scan to checks that evidence this standard with `--standard soc2`:

```bash
# All providers, only checks tied to this standard
pipeline_check --standard soc2

# Compose with --pipeline to scope by provider
pipeline_check --pipeline github --standard soc2

# Compose with another standard to widen the lens
pipeline_check --pipeline aws --standard soc2 --standard owasp_cicd_top_10
```

## Controls in scope

### CC6.1: Logical access controls restrict entities to authorized system resources { #ctrl-cc6-1 }

**Evidenced by 131 checks** across 19 providers (AWS, Argo Workflows, Azure Cloud, Bitbucket, Buildkite, CircleCI, Cloud Build, CloudFormation, Dockerfile, Drone CI, GCP, GitHub Actions, GitLab CI, Jenkins, Kubernetes, SCM, Tekton, Terraform, npm).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ACR-001`](../providers/azure_cloud.md) | Container registry admin user enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`AKV-001`](../providers/azure_cloud.md) | Key Vault soft delete not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`AKV-002`](../providers/azure_cloud.md) | Key Vault purge protection not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`ARGO-002`](../providers/argo.md#argo-002) | Argo template container runs privileged or as root | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-003`](../providers/argo.md#argo-003) | Argo workflow uses the default ServiceAccount | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-006`](../providers/argo.md#argo-006) | Literal secret value in Argo template env or parameter default | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo Workflows](../providers/argo.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ARGO-013`](../providers/argo.md#argo-013) | Argo workflow does not opt out of SA token automount | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`AZST-003`](../providers/azure_cloud.md) | Storage account not encrypted with customer-managed key | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`BB-005`](../providers/bitbucket.md#bb-005) | Step has no `max-time`, unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-017`](../providers/bitbucket.md#bb-017) | Repository token written to persistent storage | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-019`](../providers/bitbucket.md#bb-019) | after-script references secrets | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-020`](../providers/bitbucket.md#bb-020) | Full clone depth exposes complete history | <span class="pg-sev pg-sev--low">LOW</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-028`](../providers/bitbucket.md#bb-028) | OIDC step without deployment-gated environment | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-002`](../providers/buildkite.md#bk-002) | Literal secret value in pipeline env block | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-005`](../providers/buildkite.md#bk-005) | Container started with --privileged or host-bind escalation | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-006`](../providers/buildkite.md#bk-006) | Step has no timeout_in_minutes | <span class="pg-sev pg-sev--low">LOW</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CA-001`](../providers/aws.md#ca-001) | CodeArtifact domain not encrypted with customer KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CA-003`](../providers/aws.md#ca-003) | CodeArtifact domain policy allows cross-account wildcard | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`CA-004`](../providers/aws.md#ca-004) | CodeArtifact repo policy grants ``codeartifact:*`` with ``Resource '*'`` | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CC-004`](../providers/circleci.md#cc-004) | Secret-like environment variable not managed via context | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-030`](../providers/circleci.md#cc-030) | Workflow job uses context without branch filter or approval gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-031`](../providers/circleci.md#cc-031) | OIDC role assumption without branch filter or approval gate | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CCM-002`](../providers/aws.md#ccm-002) | CodeCommit repository not encrypted with customer KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CCM-003`](../providers/aws.md#ccm-003) | CodeCommit trigger targets SNS/Lambda in a different account | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CF-001`](../providers/cloudformation.md#cf-001) | Template declares AWS::IAM::AccessKey (long-lived credential) | <span class="pg-sev pg-sev--high">HIGH</span> | [CloudFormation](../providers/cloudformation.md) |  |
| [`CF-002`](../providers/cloudformation.md#cf-002) | Stateful data-store resource carries a plaintext secret | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CloudFormation](../providers/cloudformation.md) |  |
| [`CP-002`](../providers/aws.md#cp-002) | Artifact store not encrypted with customer-managed KMS key | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`DF-002`](../providers/dockerfile.md#df-002) | Container runs as root (missing or root USER directive) | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-006`](../providers/dockerfile.md#df-006) | ENV or ARG carries a credential-shaped literal value | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-008`](../providers/dockerfile.md#df-008) | RUN invokes docker --privileged or escalates capabilities | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-012`](../providers/dockerfile.md#df-012) | RUN invokes sudo | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-019`](../providers/dockerfile.md#df-019) | COPY/ADD source path looks like a credential file | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-020`](../providers/dockerfile.md#df-020) | ARG declares a credential-named build argument | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-025`](../providers/dockerfile.md#df-025) | RUN writes a registry auth token into a Docker layer | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DR-002`](../providers/drone.md#dr-002) | Step runs with privileged: true | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-004`](../providers/drone.md#dr-004) | Literal credential in step environment / settings | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Drone CI](../providers/drone.md) |  |
| [`EB-002`](../providers/aws.md#eb-002) | EventBridge rule has a wildcard target ARN | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`ECR-005`](../providers/aws.md#ecr-005) | Repository encrypted with AES256 rather than KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`ENTRA-001`](../providers/azure_cloud.md) | Service principal assigned Global Administrator | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`ENTRA-003`](../providers/azure_cloud.md) | Service principal uses password credential | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`GCB-002`](../providers/cloudbuild.md#gcb-002) | Cloud Build uses the default service account | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-012`](../providers/cloudbuild.md#gcb-012) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-018`](../providers/cloudbuild.md#gcb-018) | Legacy KMS secrets block in use (prefer availableSecrets / Secret Manager) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-020`](../providers/cloudbuild.md#gcb-020) | serviceAccount points at the default Cloud Build service account | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCIAM-001`](../providers/gcp.md) | Service account has Owner or Editor role on project | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GCP](../providers/gcp.md) |  |
| [`GCIAM-002`](../providers/gcp.md) | Service account has user-managed key | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |
| [`GCIAM-003`](../providers/gcp.md) | Service account token creator granted without constraint | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |
| [`GCKMS-001`](../providers/gcp.md) | KMS key rotation period exceeds 365 days | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |
| [`GCKMS-002`](../providers/gcp.md) | KMS key IAM policy grants public access | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |
| [`GCKMS-003`](../providers/gcp.md) | KMS key not using HSM protection level | <span class="pg-sev pg-sev--low">LOW</span> | [GCP](../providers/gcp.md) |  |
| [`GCS-002`](../providers/gcp.md) | Bucket does not enforce uniform bucket-level access | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |
| [`GHA-004`](../providers/github.md#gha-004) | Workflow permissions block missing or overprovisioned | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-018`](../providers/github.md#gha-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-019`](../providers/github.md#gha-019) | GITHUB_TOKEN written to persistent storage | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-030`](../providers/github.md#gha-030) | OIDC token requested without environment-protected job | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-033`](../providers/github.md#gha-033) | Secret value echoed / printed in a run: block | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-034`](../providers/github.md#gha-034) | Reusable workflow called with secrets: inherit | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-037`](../providers/github.md#gha-037) | actions/checkout persists GITHUB_TOKEN into .git/config | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-039`](../providers/github.md#gha-039) | services / container credentials embedded as literal in workflow | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-049`](../providers/github.md#gha-049) | Workflow step makes a privileged git write (cross-repo or actions[bot] bypass) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-050`](../providers/github.md#gha-050) | Publish step relies on long-lived registry token | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-054`](../providers/github.md#gha-054) | actions/checkout with ssh-key persists SSH credential in repo | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-055`](../providers/github.md#gha-055) | Reusable workflow outputs derive a secret or caller-input value | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-057`](../providers/github.md#gha-057) | Secret-scanner output sent to network egress | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-061`](../providers/github.md#gha-061) | GitHub App token minted without a `permissions:` filter | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-062`](../providers/github.md#gha-062) | OIDC subject claim in sibling IaC grants overly broad scope | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-063`](../providers/github.md#gha-063) | ``if:`` predicate gates on a spoofable bot-actor comparison | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-066`](../providers/github.md#gha-066) | ``actions/upload-artifact`` path is a workspace wildcard | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-067`](../providers/github.md#gha-067) | ``actions/cache`` writes credential-shaped paths | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-069`](../providers/github.md#gha-069) | ``id-token: write`` granted without an OIDC-consumer step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-070`](../providers/github.md#gha-070) | ``ssh-keyscan`` / disabled host-key check trust-on-first-use | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-072`](../providers/github.md#gha-072) | Secret in env: at a wider scope than its consumer | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-073`](../providers/github.md#gha-073) | Reusable workflow declares an unused ``workflow_call`` secret | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-087`](../providers/github.md#gha-087) | Derived value of a secret printed to the build log | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-093`](../providers/github.md#gha-093) | Living-off-the-Pipeline indicators (workflow-command abuse) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-099`](../providers/github.md#gha-099) | Deployment job has a secret-shaped plaintext env var | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-020`](../providers/gitlab.md#gl-020) | CI_JOB_TOKEN written to persistent storage | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-031`](../providers/gitlab.md#gl-031) | id_tokens: missing audience pin or environment binding | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`IAM-001`](../providers/aws.md#iam-001) | CI/CD role has AdministratorAccess policy attached | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`IAM-002`](../providers/aws.md#iam-002) | CI/CD role has wildcard Action in attached policy | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-003`](../providers/aws.md#iam-003) | CI/CD role has no permission boundary | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`IAM-004`](../providers/aws.md#iam-004) | CI/CD role can PassRole to any role | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-006`](../providers/aws.md#iam-006) | Sensitive actions granted with wildcard Resource | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`JF-033`](../providers/jenkins.md#jf-033) | withCredentials secret leaked via Groovy ${...} interpolation in sh step | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-034`](../providers/jenkins.md#jf-034) | Pipeline declares a password() build parameter | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`K8S-011`](../providers/kubernetes.md#k8s-011) | Pod serviceAccountName unset or 'default' | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-012`](../providers/kubernetes.md#k8s-012) | Pod automountServiceAccountToken not false | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-017`](../providers/kubernetes.md#k8s-017) | Container env value carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-018`](../providers/kubernetes.md#k8s-018) | Secret stringData/data carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-019`](../providers/kubernetes.md#k8s-019) | Workload deployed in the 'default' namespace | <span class="pg-sev pg-sev--low">LOW</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-020`](../providers/kubernetes.md#k8s-020) | ClusterRoleBinding grants cluster-admin or system:masters | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-021`](../providers/kubernetes.md#k8s-021) | Role or ClusterRole grants wildcard verbs+resources | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-025`](../providers/kubernetes.md#k8s-025) | System priority class used outside kube-system | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-029`](../providers/kubernetes.md#k8s-029) | RoleBinding grants permissions to the default ServiceAccount | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-030`](../providers/kubernetes.md#k8s-030) | Workload schedules onto a control-plane node | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-034`](../providers/kubernetes.md#k8s-034) | ServiceAccount automountServiceAccountToken not explicitly false | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-037`](../providers/kubernetes.md#k8s-037) | ConfigMap data carries a credential-shaped literal | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-042`](../providers/kubernetes.md#k8s-042) | RoleBinding grants access to system:anonymous / system:unauthenticated | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`KMS-001`](../providers/aws.md#kms-001) | KMS customer-managed key has rotation disabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`KMS-002`](../providers/aws.md#kms-002) | KMS key policy grants wildcard KMS actions | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`LMB-003`](../providers/aws.md#lmb-003) | Lambda function env vars may contain plaintext secrets | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`NPM-011`](../providers/npm.md#npm-011) | package.json files field includes secret-shaped paths | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NPM-012`](../providers/npm.md#npm-012) | .npmrc publish token lacks IP or readonly restriction | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`PBAC-001`](../providers/aws.md#pbac-001) | CodeBuild project has no VPC configuration | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`PBAC-002`](../providers/aws.md#pbac-002) | CodeBuild service role shared across multiple projects | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`PBAC-003`](../providers/aws.md#pbac-003) | CodeBuild security group allows 0.0.0.0/0 all-port egress | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`PBAC-005`](../providers/aws.md#pbac-005) | CodePipeline stage action roles mirror the pipeline role | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`S3-002`](../providers/aws.md#s3-002) | Artifact bucket server-side encryption not configured | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`SCM-004`](../providers/scm.md#scm-004) | GitHub secret scanning is not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-006`](../providers/scm.md#scm-006) | Default branch protection does not require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-015`](../providers/scm.md#scm-015) | Secret scanning push protection is not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-019`](../providers/scm.md#scm-019) | Push restrictions allowlist names individual users | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-020`](../providers/scm.md#scm-020) | Default workflow GITHUB_TOKEN has write permission | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-025`](../providers/scm.md#scm-025) | Repo has write-enabled deploy keys (push backdoor) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-026`](../providers/scm.md#scm-026) | Webhook ships events insecurely (HTTP / no-TLS / no-secret) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-027`](../providers/scm.md#scm-027) | Outside collaborator holds write / maintain / admin access | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-028`](../providers/scm.md#scm-028) | Private repo allows forking | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-036`](../providers/scm.md#scm-036) | Active ruleset doesn't require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-043`](../providers/scm.md#scm-043) | Tag-targeted ruleset doesn't require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-044`](../providers/scm.md#scm-044) | Default-branch signed-commits requirement bypassed for admins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-048`](../providers/scm.md#scm-048) | Org codespace secret scoped to all repos | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-049`](../providers/scm.md#scm-049) | Classic PAT used where a fine-grained token suffices | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SSM-001`](../providers/aws.md#ssm-001) | SSM Parameter with secret-like name is not a SecureString | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`SSM-002`](../providers/aws.md#ssm-002) | SSM SecureString uses the default AWS-managed key | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`TAINT-009`](../providers/github.md#taint-009) | Environment-protected secret flows to unprotected job | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`TF-001`](../providers/terraform.md#tf-001) | Plan declares aws_iam_access_key (long-lived credential) | <span class="pg-sev pg-sev--high">HIGH</span> | [Terraform](../providers/terraform.md) |  |
| [`TF-002`](../providers/terraform.md#tf-002) | Stateful data-store resource carries a plaintext secret | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Terraform](../providers/terraform.md) |  |
| [`TKN-002`](../providers/tekton.md#tkn-002) | Tekton step runs privileged or as root | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-005`](../providers/tekton.md#tkn-005) | Literal secret value in Tekton step env or param default | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Tekton](../providers/tekton.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`TKN-007`](../providers/tekton.md#tkn-007) | Tekton run uses the default ServiceAccount | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-013`](../providers/tekton.md#tkn-013) | Tekton sidecar runs privileged or as root | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |

### CC6.2: New internal and external users are registered, authorized, and provisioned { #ctrl-cc6-2 }

**Evidenced by 24 checks** across 10 providers (AWS, Azure Cloud, Azure DevOps, Bitbucket, CircleCI, Cloud Build, GitHub Actions, GitLab CI, Jenkins, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ACR-001`](../providers/azure_cloud.md) | Container registry admin user enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`ADO-003`](../providers/azure.md#ado-003) | Variables contain literal secret values | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-008`](../providers/azure.md#ado-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-014`](../providers/azure.md#ado-014) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-003`](../providers/bitbucket.md#bb-003) | Variables contain literal secret values | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-008`](../providers/bitbucket.md#bb-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-011`](../providers/bitbucket.md#bb-011) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CB-001`](../providers/aws.md#cb-001) | Secrets in plaintext environment variables | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`CC-005`](../providers/circleci.md#cc-005) | AWS auth uses long-lived access keys in environment block | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-008`](../providers/circleci.md#cc-008) | Credential-shaped literal in config body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ENTRA-003`](../providers/azure_cloud.md) | Service principal uses password credential | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`GCB-003`](../providers/cloudbuild.md#gcb-003) | Secret Manager value referenced in step args | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-005`](../providers/github.md#gha-005) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-008`](../providers/github.md#gha-008) | Credential-shaped literal in workflow body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-003`](../providers/gitlab.md#gl-003) | Variables contain literal secret values | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-008`](../providers/gitlab.md#gl-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-013`](../providers/gitlab.md#gl-013) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`IAM-005`](../providers/aws.md#iam-005) | CI/CD role trust policy missing sts:ExternalId | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-008`](../providers/aws.md#iam-008) | OIDC-federated role trust policy missing audience or subject pin | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`JF-004`](../providers/jenkins.md#jf-004) | AWS auth uses long-lived access keys via withCredentials | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-008`](../providers/jenkins.md#jf-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-010`](../providers/jenkins.md#jf-010) | Long-lived AWS keys exposed via environment {} block | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-033`](../providers/jenkins.md#jf-033) | withCredentials secret leaked via Groovy ${...} interpolation in sh step | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`SCM-027`](../providers/scm.md#scm-027) | Outside collaborator holds write / maintain / admin access | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |

### CC6.3: Access modifications (including revocation) are tracked and timely { #ctrl-cc6-3 }

**Evidenced by 23 checks** across 14 providers (AWS, Azure Cloud, Azure DevOps, Bitbucket, CircleCI, Cloud Build, CloudFormation, GCP, GitHub Actions, GitLab CI, Jenkins, Kubernetes, SCM, Terraform).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-014`](../providers/azure.md#ado-014) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-011`](../providers/bitbucket.md#bb-011) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CB-006`](../providers/aws.md#cb-006) | CodeBuild source auth uses long-lived token | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CC-005`](../providers/circleci.md#cc-005) | AWS auth uses long-lived access keys in environment block | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-019`](../providers/circleci.md#cc-019) | `add_ssh_keys` without fingerprint restriction | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CF-001`](../providers/cloudformation.md#cf-001) | Template declares AWS::IAM::AccessKey (long-lived credential) | <span class="pg-sev pg-sev--high">HIGH</span> | [CloudFormation](../providers/cloudformation.md) |  |
| [`CP-004`](../providers/aws.md#cp-004) | Legacy ThirdParty/GitHub source action (OAuth token) | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`ENTRA-002`](../providers/azure_cloud.md) | App registration credential valid beyond 180 days | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`GCB-007`](../providers/cloudbuild.md#gcb-007) | availableSecrets references ``versions/latest`` | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCIAM-002`](../providers/gcp.md) | Service account has user-managed key | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |
| [`GHA-005`](../providers/github.md#gha-005) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-050`](../providers/github.md#gha-050) | Publish step relies on long-lived registry token | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-061`](../providers/github.md#gha-061) | GitHub App token minted without a `permissions:` filter | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-062`](../providers/github.md#gha-062) | OIDC subject claim in sibling IaC grants overly broad scope | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-013`](../providers/gitlab.md#gl-013) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`IAM-005`](../providers/aws.md#iam-005) | CI/CD role trust policy missing sts:ExternalId | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-007`](../providers/aws.md#iam-007) | IAM user has access key older than 90 days | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`JF-004`](../providers/jenkins.md#jf-004) | AWS auth uses long-lived access keys via withCredentials | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-042`](../providers/kubernetes.md#k8s-042) | RoleBinding grants access to system:anonymous / system:unauthenticated | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`SCM-025`](../providers/scm.md#scm-025) | Repo has write-enabled deploy keys (push backdoor) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-049`](../providers/scm.md#scm-049) | Classic PAT used where a fine-grained token suffices | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SM-001`](../providers/aws.md#sm-001) | Secrets Manager secret has no rotation configured | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`TF-001`](../providers/terraform.md#tf-001) | Plan declares aws_iam_access_key (long-lived credential) | <span class="pg-sev pg-sev--high">HIGH</span> | [Terraform](../providers/terraform.md) |  |

### CC6.6: Boundary-protection measures restrict access from outside the system boundary { #ctrl-cc6-6 }

**Evidenced by 89 checks** across 18 providers (AWS, Argo Workflows, Azure Cloud, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, CloudFormation, Dockerfile, Drone CI, GCP, GitHub Actions, GitLab CI, Jenkins, Kubernetes, Tekton, Terraform).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ACR-002`](../providers/azure_cloud.md) | Container registry allows public network access | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`ADO-010`](../providers/azure.md#ado-010) | Cross-pipeline `download:` ingestion unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-011`](../providers/azure.md#ado-011) | `template: <local-path>` on PR-validated pipeline | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-012`](../providers/azure.md#ado-012) | Cache@2 key derives from $(System.PullRequest.*) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-013`](../providers/azure.md#ado-013) | Self-hosted pool without explicit ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-015`](../providers/azure.md#ado-015) | Job has no `timeoutInMinutes`, unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-017`](../providers/azure.md#ado-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-019`](../providers/azure.md#ado-019) | `extends:` template on PR-validated pipeline points to local path | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`AKV-003`](../providers/azure_cloud.md) | Key Vault allows access from all networks | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`ARGO-004`](../providers/argo.md#argo-004) | Argo workflow mounts hostPath or shares host namespaces | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-007`](../providers/argo.md#argo-007) | Argo workflow has no activeDeadlineSeconds | <span class="pg-sev pg-sev--low">LOW</span> | [Argo Workflows](../providers/argo.md) |  |
| [`AZST-001`](../providers/azure_cloud.md) | Storage account allows public blob access | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`BB-010`](../providers/bitbucket.md#bb-010) | Deploy step ingests pull-request artifact unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-013`](../providers/bitbucket.md#bb-013) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-016`](../providers/bitbucket.md#bb-016) | Self-hosted runner without ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-018`](../providers/bitbucket.md#bb-018) | Cache key derives from attacker-controllable input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`CA-002`](../providers/aws.md#ca-002) | CodeArtifact repository has a public external connection | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CB-002`](../providers/aws.md#cb-002) | Privileged mode enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CB-004`](../providers/aws.md#cb-004) | No build timeout configured | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`CB-007`](../providers/aws.md#cb-007) | CodeBuild webhook has no filter group | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CB-010`](../providers/aws.md#cb-010) | CodeBuild webhook allows fork-PR builds without actor filtering | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CC-010`](../providers/circleci.md#cc-010) | Self-hosted runner without ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-012`](../providers/circleci.md#cc-012) | Dynamic config via `setup: true` enables code injection | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-014`](../providers/circleci.md#cc-014) | Job missing `resource_class` declaration | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-015`](../providers/circleci.md#cc-015) | No `no_output_timeout` configured | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-017`](../providers/circleci.md#cc-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-025`](../providers/circleci.md#cc-025) | Cache key derives from attacker-controllable input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CF-003`](../providers/cloudformation.md#cf-003) | CodeBuild VPC config references a public subnet | <span class="pg-sev pg-sev--high">HIGH</span> | [CloudFormation](../providers/cloudformation.md) |  |
| [`CP-003`](../providers/aws.md#cp-003) | Source stage using polling instead of event-driven trigger | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`CP-007`](../providers/aws.md#cp-007) | CodePipeline v2 PR trigger accepts all branches | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`DF-013`](../providers/dockerfile.md#df-013) | EXPOSE declares sensitive remote-access port | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DR-007`](../providers/drone.md#dr-007) | Step mounts a sensitive host path | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-009`](../providers/drone.md#dr-009) | Cache plugin key embeds an attacker-controllable Drone variable | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`ECR-003`](../providers/aws.md#ecr-003) | Repository policy allows public access | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`GAR-002`](../providers/gcp.md) | Artifact Registry repository is publicly readable | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |
| [`GCB-005`](../providers/cloudbuild.md#gcb-005) | Build timeout unset or excessive | <span class="pg-sev pg-sev--low">LOW</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCB-021`](../providers/cloudbuild.md#gcb-021) | No private worker pool, build runs on the shared default pool | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCKMS-002`](../providers/gcp.md) | KMS key IAM policy grants public access | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |
| [`GCS-001`](../providers/gcp.md) | Cloud Storage bucket is publicly accessible | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |
| [`GHA-002`](../providers/github.md#gha-002) | pull_request_target checks out PR head | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-009`](../providers/github.md#gha-009) | workflow_run downloads upstream artifact unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-010`](../providers/github.md#gha-010) | Local action (./path) on untrusted-trigger workflow | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-011`](../providers/github.md#gha-011) | Cache key derives from attacker-controllable input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-012`](../providers/github.md#gha-012) | Self-hosted runner without ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-013`](../providers/github.md#gha-013) | issue_comment trigger without author guard | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-015`](../providers/github.md#gha-015) | Job has no `timeout-minutes`, unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-017`](../providers/github.md#gha-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-026`](../providers/github.md#gha-026) | Container job disables isolation via `options:` | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-052`](../providers/github.md#gha-052) | actions/cache key includes untrusted PR-controllable input | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-057`](../providers/github.md#gha-057) | Secret-scanner output sent to network egress | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-010`](../providers/gitlab.md#gl-010) | Multi-project pipeline ingests upstream artifact unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-011`](../providers/gitlab.md#gl-011) | include: local file pulled in MR-triggered pipeline | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-012`](../providers/gitlab.md#gl-012) | Cache key derives from MR-controlled CI variable | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-014`](../providers/gitlab.md#gl-014) | Self-managed runner without ephemeral tag | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-015`](../providers/gitlab.md#gl-015) | Job has no `timeout`, unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-017`](../providers/gitlab.md#gl-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-003`](../providers/jenkins.md#jf-003) | Pipeline uses `agent any` (no executor isolation) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-013`](../providers/jenkins.md#jf-013) | copyArtifacts ingests another job's output unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-014`](../providers/jenkins.md#jf-014) | Agent label missing ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-015`](../providers/jenkins.md#jf-015) | Pipeline has no `timeout` wrapper, unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-017`](../providers/jenkins.md#jf-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-025`](../providers/jenkins.md#jf-025) | Kubernetes agent pod template runs privileged or mounts hostPath | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`K8S-002`](../providers/kubernetes.md#k8s-002) | Pod hostNetwork: true | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-015`](../providers/kubernetes.md#k8s-015) | Container missing resources.limits.memory | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-016`](../providers/kubernetes.md#k8s-016) | Container missing resources.limits.cpu | <span class="pg-sev pg-sev--low">LOW</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-022`](../providers/kubernetes.md#k8s-022) | Service exposes SSH (port 22) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-026`](../providers/kubernetes.md#k8s-026) | LoadBalancer Service has no loadBalancerSourceRanges | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-028`](../providers/kubernetes.md#k8s-028) | Container declares hostPort | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-030`](../providers/kubernetes.md#k8s-030) | Workload schedules onto a control-plane node | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-032`](../providers/kubernetes.md#k8s-032) | Namespace lacks default-deny NetworkPolicy | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-038`](../providers/kubernetes.md#k8s-038) | NetworkPolicy ingress / egress allows all sources or destinations | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-041`](../providers/kubernetes.md#k8s-041) | Service.externalIPs allows traffic interception (CVE-2020-8554) | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-043`](../providers/kubernetes.md#k8s-043) | Ingress rule has wildcard or missing host (catch-all) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`LMB-002`](../providers/aws.md#lmb-002) | Lambda function URL has AuthType=NONE | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`LMB-004`](../providers/aws.md#lmb-004) | Lambda resource policy allows wildcard principal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`S3-001`](../providers/aws.md#s3-001) | Artifact bucket public access block not fully enabled | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`S3-005`](../providers/aws.md#s3-005) | Artifact bucket missing aws:SecureTransport deny | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`SM-002`](../providers/aws.md#sm-002) | Secrets Manager resource policy allows wildcard principal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`TAINT-001`](../providers/github.md#taint-001) | Untrusted input flows across step boundaries via step outputs | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`TAINT-002`](../providers/github.md#taint-002) | Untrusted input flows across jobs via ``jobs.<id>.outputs:`` | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`TAINT-003`](../providers/github.md#taint-003) | Untrusted input forwarded into reusable workflow ``with:`` | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`TAINT-004`](../providers/gitlab.md#taint-004) | Untrusted input flows across jobs via dotenv artifact | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`TAINT-005`](../providers/buildkite.md#taint-005) | Untrusted input flows across steps via ``buildkite-agent meta-data`` | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`TAINT-006`](../providers/tekton.md#taint-006) | Untrusted input flows across tasks via Tekton ``results`` | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |
| [`TAINT-007`](../providers/argo.md#taint-007) | Untrusted input flows across templates via Argo ``outputs.parameters`` | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`TAINT-008`](../providers/gitlab.md#taint-008) | Untrusted input flows via GitLab ``extends:`` template inheritance | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`TF-003`](../providers/terraform.md#tf-003) | CodeBuild VPC config references a public subnet | <span class="pg-sev pg-sev--high">HIGH</span> | [Terraform](../providers/terraform.md) |  |
| [`TKN-004`](../providers/tekton.md#tkn-004) | Tekton Task mounts hostPath or shares host namespaces | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-006`](../providers/tekton.md#tkn-006) | Tekton run lacks an explicit timeout | <span class="pg-sev pg-sev--low">LOW</span> | [Tekton](../providers/tekton.md) |  |

### CC6.7: Data in transit is protected from unauthorized disclosure { #ctrl-cc6-7 }

**Evidenced by 32 checks** across 20 providers (AWS, Argo Workflows, Azure Cloud, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, Drone CI, GitHub Actions, GitLab CI, Helm, Jenkins, Kubernetes, NuGet, PyPI, SCM, Tekton, maven).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-023`](../providers/azure.md#ado-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ARGO-008`](../providers/argo.md#argo-008) | Argo script source pipes remote install or disables TLS | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ARGO-015`](../providers/argo.md#argo-015) | Input artifact pulls from an insecure (non-HTTPS) URL | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`AZST-002`](../providers/azure_cloud.md) | Storage account allows non-HTTPS traffic | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`BB-023`](../providers/bitbucket.md#bb-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-004`](../providers/buildkite.md#bk-004) | Remote script piped into shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-008`](../providers/buildkite.md#bk-008) | TLS verification disabled in step command | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-023`](../providers/circleci.md#cc-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-003`](../providers/dockerfile.md#df-003) | ADD pulls remote URL without integrity verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-004`](../providers/dockerfile.md#df-004) | RUN executes a remote script via curl-pipe / wget-pipe | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-021`](../providers/dockerfile.md#df-021) | RUN pip install bypasses TLS or uses an HTTP index | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-026`](../providers/dockerfile.md#df-026) | ENV disables Node.js TLS certificate verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-027`](../providers/dockerfile.md#df-027) | ENV disables Python HTTPS certificate verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-028`](../providers/dockerfile.md#df-028) | ENV disables Git TLS certificate verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-029`](../providers/dockerfile.md#df-029) | ENV neuters Python requests CA bundle | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DR-006`](../providers/drone.md#dr-006) | TLS verification disabled in step commands | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`GCB-010`](../providers/cloudbuild.md#gcb-010) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-011`](../providers/cloudbuild.md#gcb-011) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-022`](../providers/github.md#gha-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-023`](../providers/github.md#gha-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-023`](../providers/gitlab.md#gl-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-003`](../providers/helm.md#helm-003) | Chart dependency declared on a non-HTTPS repository | <span class="pg-sev pg-sev--high">HIGH</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-009`](../providers/helm.md#helm-009) | Chart home / sources URL uses a non-HTTPS scheme | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`JF-023`](../providers/jenkins.md#jf-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-035`](../providers/jenkins.md#jf-035) | httpRequest step disables SSL verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`K8S-027`](../providers/kubernetes.md#k8s-027) | Ingress has no TLS configuration | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`MVN-003`](../providers/maven.md#mvn-003) | pom.xml declares a plaintext-HTTP Maven repository | <span class="pg-sev pg-sev--high">HIGH</span> | [maven](../providers/maven.md) |  |
| [`NUGET-004`](../providers/nuget.md#nuget-004) | HTTP-only NuGet package source | <span class="pg-sev pg-sev--high">HIGH</span> | [NuGet](../providers/nuget.md) |  |
| [`PYPI-003`](../providers/pypi.md#pypi-003) | requirements.txt uses an HTTP index or disables TLS verification | <span class="pg-sev pg-sev--high">HIGH</span> | [PyPI](../providers/pypi.md) |  |
| [`S3-005`](../providers/aws.md#s3-005) | Artifact bucket missing aws:SecureTransport deny | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`SCM-026`](../providers/scm.md#scm-026) | Webhook ships events insecurely (HTTP / no-TLS / no-secret) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`TKN-008`](../providers/tekton.md#tkn-008) | Tekton step script pipes remote install or disables TLS | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### CC6.8: Controls prevent or detect the introduction of malicious software { #ctrl-cc6-8 }

**Evidenced by 147 checks** across 20 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, Drone CI, GCP, GitHub Actions, GitLab CI, Jenkins, Kubernetes, NuGet, PyPI, SCM, Tekton, maven, npm).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-002`](../providers/azure.md#ado-002) | Script injection via attacker-controllable context | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-010`](../providers/azure.md#ado-010) | Cross-pipeline `download:` ingestion unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-011`](../providers/azure.md#ado-011) | `template: <local-path>` on PR-validated pipeline | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-012`](../providers/azure.md#ado-012) | Cache@2 key derives from $(System.PullRequest.*) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-016`](../providers/azure.md#ado-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-019`](../providers/azure.md#ado-019) | `extends:` template on PR-validated pipeline points to local path | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-020`](../providers/azure.md#ado-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-026`](../providers/azure.md#ado-026) | Pipeline contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-027`](../providers/azure.md#ado-027) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-030`](../providers/azure.md#ado-030) | pool interpolates attacker-controllable value | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ARGO-002`](../providers/argo.md#argo-002) | Argo template container runs privileged or as root | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-004`](../providers/argo.md#argo-004) | Argo workflow mounts hostPath or shares host namespaces | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-005`](../providers/argo.md#argo-005) | Argo input parameter interpolated unsafely in script / args | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-002`](../providers/bitbucket.md#bb-002) | Script injection via attacker-controllable context | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-005`](../providers/bitbucket.md#bb-005) | Step has no `max-time`, unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-010`](../providers/bitbucket.md#bb-010) | Deploy step ingests pull-request artifact unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-012`](../providers/bitbucket.md#bb-012) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-015`](../providers/bitbucket.md#bb-015) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-018`](../providers/bitbucket.md#bb-018) | Cache key derives from attacker-controllable input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-025`](../providers/bitbucket.md#bb-025) | Pipeline contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-026`](../providers/bitbucket.md#bb-026) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-003`](../providers/buildkite.md#bk-003) | Untrusted Buildkite variable interpolated in command | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-005`](../providers/buildkite.md#bk-005) | Container started with --privileged or host-bind escalation | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-015`](../providers/buildkite.md#bk-015) | agents map interpolates attacker-controllable Buildkite variable | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CB-011`](../providers/aws.md#cb-011) | CodeBuild buildspec contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`CC-002`](../providers/circleci.md#cc-002) | Script injection via untrusted environment variable | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-012`](../providers/circleci.md#cc-012) | Dynamic config via `setup: true` enables code injection | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-016`](../providers/circleci.md#cc-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-020`](../providers/circleci.md#cc-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-025`](../providers/circleci.md#cc-025) | Cache key derives from attacker-controllable input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-026`](../providers/circleci.md#cc-026) | Config contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-027`](../providers/circleci.md#cc-027) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`DF-002`](../providers/dockerfile.md#df-002) | Container runs as root (missing or root USER directive) | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-005`](../providers/dockerfile.md#df-005) | RUN uses shell-eval (eval / sh -c on a variable / backticks) | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-008`](../providers/dockerfile.md#df-008) | RUN invokes docker --privileged or escalates capabilities | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-013`](../providers/dockerfile.md#df-013) | EXPOSE declares sensitive remote-access port | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-014`](../providers/dockerfile.md#df-014) | WORKDIR set to a system / kernel filesystem path | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-015`](../providers/dockerfile.md#df-015) | RUN grants world-writable permissions (chmod 777 / a+w) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-017`](../providers/dockerfile.md#df-017) | ENV PATH prepends a world-writable directory | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-018`](../providers/dockerfile.md#df-018) | RUN chown rewrites ownership of a system path | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-023`](../providers/dockerfile.md#df-023) | ENV sets a dynamic-loader hijack variable | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-024`](../providers/dockerfile.md#df-024) | RUN npm/yarn/pnpm install runs lifecycle scripts | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-030`](../providers/dockerfile.md#df-030) | ENV NODE_OPTIONS preloads code or opens an inspector | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DR-002`](../providers/drone.md#dr-002) | Step runs with privileged: true | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-003`](../providers/drone.md#dr-003) | Untrusted Drone template variable in shell command | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-007`](../providers/drone.md#dr-007) | Step mounts a sensitive host path | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-009`](../providers/drone.md#dr-009) | Cache plugin key embeds an attacker-controllable Drone variable | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-011`](../providers/drone.md#dr-011) | node map interpolates attacker-controllable Drone variable | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`ECR-001`](../providers/aws.md#ecr-001) | Image scanning on push not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`ECR-007`](../providers/aws.md#ecr-007) | Inspector v2 enhanced scanning disabled for ECR | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`GAR-001`](../providers/gcp.md) | Artifact Registry repository has no vulnerability scanning | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |
| [`GCB-006`](../providers/cloudbuild.md#gcb-006) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-008`](../providers/cloudbuild.md#gcb-008) | No vulnerability scanning step in Cloud Build pipeline | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-016`](../providers/cloudbuild.md#gcb-016) | Step dir field contains parent-directory escape (..) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-019`](../providers/cloudbuild.md#gcb-019) | Shell entrypoint inlines a user substitution into args | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-022`](../providers/cloudbuild.md#gcb-022) | options.substitutionOption set to ALLOW_LOOSE | <span class="pg-sev pg-sev--low">LOW</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCB-023`](../providers/cloudbuild.md#gcb-023) | Step references a user substitution not declared in substitutions: | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-002`](../providers/github.md#gha-002) | pull_request_target checks out PR head | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-003`](../providers/github.md#gha-003) | Script injection via untrusted context | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-009`](../providers/github.md#gha-009) | workflow_run downloads upstream artifact unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-010`](../providers/github.md#gha-010) | Local action (./path) on untrusted-trigger workflow | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-011`](../providers/github.md#gha-011) | Cache key derives from attacker-controllable input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-013`](../providers/github.md#gha-013) | issue_comment trigger without author guard | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-016`](../providers/github.md#gha-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-020`](../providers/github.md#gha-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-027`](../providers/github.md#gha-027) | Workflow contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-028`](../providers/github.md#gha-028) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-031`](../providers/github.md#gha-031) | Workflow uses retired set-output / save-state command | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-032`](../providers/github.md#gha-032) | run: invokes local script on untrusted-trigger workflow | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-035`](../providers/github.md#gha-035) | github-script step interpolates untrusted context | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-036`](../providers/github.md#gha-036) | runs-on interpolates untrusted context | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-038`](../providers/github.md#gha-038) | Workflow re-enables retired ::set-env / ::add-path commands | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-040`](../providers/github.md#gha-040) | Action reference matches a known-compromised SHA or tag | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-044`](../providers/github.md#gha-044) | Build tool runs lifecycle scripts on untrusted-trigger workflow | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-045`](../providers/github.md#gha-045) | Caller-controlled ref input feeds actions/checkout | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-046`](../providers/github.md#gha-046) | Manual PR-head fetch on untrusted-trigger workflow | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-053`](../providers/github.md#gha-053) | if: predicate evaluates attacker-controllable context as expression | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-056`](../providers/github.md#gha-056) | Workflow body contains a known supply-chain worm indicator | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-058`](../providers/github.md#gha-058) | Agentic CLI invoked with permission-bypass flags | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-088`](../providers/github.md#gha-088) | Action ``uses:`` slug is a near-edit of a top-traffic action | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-089`](../providers/github.md#gha-089) | Action upstream repo is archived | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-090`](../providers/github.md#gha-090) | Action SHA pin references a commit absent from the claimed repo | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-091`](../providers/github.md#gha-091) | Action upstream repo is missing (takeover-eligible namespace) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-092`](../providers/github.md#gha-092) | PR head SHA captured then re-fetched (force-push race) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-094`](../providers/github.md#gha-094) | Action SHA pin matches the current tip of an upstream branch | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-096`](../providers/github.md#gha-096) | Action reference has a known GHSA vulnerability | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-098`](../providers/github.md#gha-098) | Pipeline deploys without a security scan gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-102`](../providers/github.md#gha-102) | ``actions/checkout`` with submodule fetch on a PR trigger | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-002`](../providers/gitlab.md#gl-002) | Script injection via untrusted commit/MR context | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-010`](../providers/gitlab.md#gl-010) | Multi-project pipeline ingests upstream artifact unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-011`](../providers/gitlab.md#gl-011) | include: local file pulled in MR-triggered pipeline | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-012`](../providers/gitlab.md#gl-012) | Cache key derives from MR-controlled CI variable | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-016`](../providers/gitlab.md#gl-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-019`](../providers/gitlab.md#gl-019) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-025`](../providers/gitlab.md#gl-025) | Pipeline contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-026`](../providers/gitlab.md#gl-026) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-032`](../providers/gitlab.md#gl-032) | tags: interpolates untrusted CI variable | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-033`](../providers/gitlab.md#gl-033) | Global before_script / after_script propagates taint to every job | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-002`](../providers/jenkins.md#jf-002) | Script step interpolates attacker-controllable env var | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-013`](../providers/jenkins.md#jf-013) | copyArtifacts ingests another job's output unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-016`](../providers/jenkins.md#jf-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-019`](../providers/jenkins.md#jf-019) | Groovy sandbox escape pattern detected | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-020`](../providers/jenkins.md#jf-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-029`](../providers/jenkins.md#jf-029) | Jenkinsfile contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-030`](../providers/jenkins.md#jf-030) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-032`](../providers/jenkins.md#jf-032) | Agent label interpolates attacker-controllable value | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-003`](../providers/kubernetes.md#k8s-003) | Pod hostPID: true | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-004`](../providers/kubernetes.md#k8s-004) | Pod hostIPC: true | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-005`](../providers/kubernetes.md#k8s-005) | Container securityContext.privileged: true | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-006`](../providers/kubernetes.md#k8s-006) | Container allowPrivilegeEscalation not explicitly false | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-007`](../providers/kubernetes.md#k8s-007) | Container runAsNonRoot not true / runAsUser is 0 | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-008`](../providers/kubernetes.md#k8s-008) | Container readOnlyRootFilesystem not true | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-009`](../providers/kubernetes.md#k8s-009) | Container capabilities not dropping ALL / adding dangerous caps | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-010`](../providers/kubernetes.md#k8s-010) | Container seccompProfile not RuntimeDefault or Localhost | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-013`](../providers/kubernetes.md#k8s-013) | Pod uses a hostPath volume | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-014`](../providers/kubernetes.md#k8s-014) | Pod hostPath references a sensitive host directory | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-035`](../providers/kubernetes.md#k8s-035) | Container securityContext.runAsUser is 0 | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-039`](../providers/kubernetes.md#k8s-039) | Pod uses shareProcessNamespace: true | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-040`](../providers/kubernetes.md#k8s-040) | Container securityContext.procMount: Unmasked | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`MVN-006`](../providers/maven.md#mvn-006) | pom.xml pins a known-compromised Maven Central artifact version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [maven](../providers/maven.md) |  |
| [`MVN-008`](../providers/maven.md#mvn-008) | Direct dependency was published within the cooldown window | <span class="pg-sev pg-sev--high">HIGH</span> | [maven](../providers/maven.md) |  |
| [`MVN-009`](../providers/maven.md#mvn-009) | Maven artifact has a known OSV advisory | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [maven](../providers/maven.md) |  |
| [`NPM-004`](../providers/npm.md#npm-004) | package.json declares an install-time lifecycle script | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NPM-006`](../providers/npm.md#npm-006) | package-lock.json pins a known-compromised package version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [npm](../providers/npm.md) |  |
| [`NPM-007`](../providers/npm.md#npm-007) | .npmrc does not disable install-time lifecycle scripts | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NPM-008`](../providers/npm.md#npm-008) | Direct dependency was published within the cooldown window | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NPM-010`](../providers/npm.md#npm-010) | npm package has a known OSV advisory | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [npm](../providers/npm.md) |  |
| [`NUGET-005`](../providers/nuget.md#nuget-005) | Known-compromised NuGet package version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [NuGet](../providers/nuget.md) |  |
| [`NUGET-008`](../providers/nuget.md#nuget-008) | NuGet package published within the cooldown window | <span class="pg-sev pg-sev--high">HIGH</span> | [NuGet](../providers/nuget.md) |  |
| [`NUGET-009`](../providers/nuget.md#nuget-009) | NuGet package has a known OSV advisory | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [NuGet](../providers/nuget.md) |  |
| [`PYPI-006`](../providers/pypi.md#pypi-006) | requirements.txt pins a known-compromised PyPI package version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [PyPI](../providers/pypi.md) |  |
| [`PYPI-008`](../providers/pypi.md#pypi-008) | Direct dependency was published within the cooldown window | <span class="pg-sev pg-sev--high">HIGH</span> | [PyPI](../providers/pypi.md) |  |
| [`PYPI-009`](../providers/pypi.md#pypi-009) | PyPI package has a known OSV advisory | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [PyPI](../providers/pypi.md) |  |
| [`SCM-022`](../providers/scm.md#scm-022) | Repo Actions permissions allow any source (no allow-list) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`TAINT-001`](../providers/github.md#taint-001) | Untrusted input flows across step boundaries via step outputs | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`TAINT-002`](../providers/github.md#taint-002) | Untrusted input flows across jobs via ``jobs.<id>.outputs:`` | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`TAINT-003`](../providers/github.md#taint-003) | Untrusted input forwarded into reusable workflow ``with:`` | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`TAINT-004`](../providers/gitlab.md#taint-004) | Untrusted input flows across jobs via dotenv artifact | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`TAINT-005`](../providers/buildkite.md#taint-005) | Untrusted input flows across steps via ``buildkite-agent meta-data`` | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`TAINT-006`](../providers/tekton.md#taint-006) | Untrusted input flows across tasks via Tekton ``results`` | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |
| [`TAINT-007`](../providers/argo.md#taint-007) | Untrusted input flows across templates via Argo ``outputs.parameters`` | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`TAINT-008`](../providers/gitlab.md#taint-008) | Untrusted input flows via GitLab ``extends:`` template inheritance | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`TKN-002`](../providers/tekton.md#tkn-002) | Tekton step runs privileged or as root | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-003`](../providers/tekton.md#tkn-003) | Tekton param interpolated unsafely in step script | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-004`](../providers/tekton.md#tkn-004) | Tekton Task mounts hostPath or shares host namespaces | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-013`](../providers/tekton.md#tkn-013) | Tekton sidecar runs privileged or as root | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-015`](../providers/tekton.md#tkn-015) | Workspace subPath interpolates a Task parameter (path traversal) | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |

### CC7.1: Detection procedures identify configuration changes that introduce vulnerabilities { #ctrl-cc7-1 }

**Evidenced by 30 checks** across 12 providers (AWS, Argo Workflows, Buildkite, Cloud Build, GCP, Kubernetes, NuGet, PyPI, SCM, Tekton, maven, npm).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ARGO-012`](../providers/argo.md#argo-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BK-012`](../providers/buildkite.md#bk-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CB-005`](../providers/aws.md#cb-005) | Outdated managed build image | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`ECR-002`](../providers/aws.md#ecr-002) | Image tags are mutable | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`ECR-004`](../providers/aws.md#ecr-004) | No lifecycle policy configured | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`GAR-003`](../providers/gcp.md) | Artifact Registry has no cleanup policy | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |
| [`GCB-007`](../providers/cloudbuild.md#gcb-007) | availableSecrets references ``versions/latest`` | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-023`](../providers/kubernetes.md#k8s-023) | Namespace missing Pod Security Admission enforcement label | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-031`](../providers/kubernetes.md#k8s-031) | Namespace missing PSA warn label | <span class="pg-sev pg-sev--low">LOW</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`MVN-006`](../providers/maven.md#mvn-006) | pom.xml pins a known-compromised Maven Central artifact version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [maven](../providers/maven.md) |  |
| [`MVN-008`](../providers/maven.md#mvn-008) | Direct dependency was published within the cooldown window | <span class="pg-sev pg-sev--high">HIGH</span> | [maven](../providers/maven.md) |  |
| [`MVN-009`](../providers/maven.md#mvn-009) | Maven artifact has a known OSV advisory | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [maven](../providers/maven.md) |  |
| [`NPM-006`](../providers/npm.md#npm-006) | package-lock.json pins a known-compromised package version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [npm](../providers/npm.md) |  |
| [`NPM-008`](../providers/npm.md#npm-008) | Direct dependency was published within the cooldown window | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NPM-010`](../providers/npm.md#npm-010) | npm package has a known OSV advisory | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [npm](../providers/npm.md) |  |
| [`NUGET-005`](../providers/nuget.md#nuget-005) | Known-compromised NuGet package version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [NuGet](../providers/nuget.md) |  |
| [`NUGET-008`](../providers/nuget.md#nuget-008) | NuGet package published within the cooldown window | <span class="pg-sev pg-sev--high">HIGH</span> | [NuGet](../providers/nuget.md) |  |
| [`NUGET-009`](../providers/nuget.md#nuget-009) | NuGet package has a known OSV advisory | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [NuGet](../providers/nuget.md) |  |
| [`PYPI-006`](../providers/pypi.md#pypi-006) | requirements.txt pins a known-compromised PyPI package version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [PyPI](../providers/pypi.md) |  |
| [`PYPI-008`](../providers/pypi.md#pypi-008) | Direct dependency was published within the cooldown window | <span class="pg-sev pg-sev--high">HIGH</span> | [PyPI](../providers/pypi.md) |  |
| [`PYPI-009`](../providers/pypi.md#pypi-009) | PyPI package has a known OSV advisory | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [PyPI](../providers/pypi.md) |  |
| [`SCM-003`](../providers/scm.md#scm-003) | GitHub default code scanning is not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-005`](../providers/scm.md#scm-005) | Dependabot security updates are not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-039`](../providers/scm.md#scm-039) | Active ruleset doesn't pin a required workflow | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-040`](../providers/scm.md#scm-040) | Active ruleset doesn't gate on code scanning results | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-042`](../providers/scm.md#scm-042) | Active ruleset doesn't require merge queue | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-045`](../providers/scm.md#scm-045) | Default code scanning uses the limited query suite | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-046`](../providers/scm.md#scm-046) | Default code scanning is configured but paused | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-047`](../providers/scm.md#scm-047) | Repo language excluded from default code-scanning coverage | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`TKN-012`](../providers/tekton.md#tkn-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### CC7.2: System components are monitored for anomalies indicative of malicious acts or failures { #ctrl-cc7-2 }

**Evidenced by 40 checks** across 8 providers (AWS, Azure Cloud, CircleCI, Cloud Build, Dockerfile, GCP, Jenkins, Kubernetes).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZMON-001`](../providers/azure_cloud.md) | No diagnostic setting for subscription Activity Log | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`AZMON-002`](../providers/azure_cloud.md) | Activity Log retention less than 365 days | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`AZMON-003`](../providers/azure_cloud.md) | No alert rule for critical administrative operations | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`CA-000`](../providers/aws.md#ca-000) | CodeArtifact API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`CB-000`](../providers/aws.md#cb-000) | CodeBuild API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`CB-003`](../providers/aws.md#cb-003) | Build logging not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CC-011`](../providers/circleci.md#cc-011) | No store_test_results step (test results not archived) | <span class="pg-sev pg-sev--low">LOW</span> | [CircleCI](../providers/circleci.md) |  |
| [`CCM-000`](../providers/aws.md#ccm-000) | CodeCommit API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`CD-000`](../providers/aws.md#cd-000) | CodeDeploy API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`CP-000`](../providers/aws.md#cp-000) | CodePipeline API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`CT-000`](../providers/aws.md#ct-000) | CloudTrail API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`CT-001`](../providers/aws.md#ct-001) | No active CloudTrail trail in region | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CT-002`](../providers/aws.md#ct-002) | CloudTrail log-file validation disabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CT-003`](../providers/aws.md#ct-003) | CloudTrail trail is not multi-region | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CW-001`](../providers/aws.md#cw-001) | No CloudWatch alarm on CodeBuild FailedBuilds metric | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`CWL-000`](../providers/aws.md#cwl-000) | CloudWatch Logs API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`CWL-001`](../providers/aws.md#cwl-001) | CodeBuild log group has no retention policy | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`CWL-002`](../providers/aws.md#cwl-002) | CodeBuild log group not KMS-encrypted | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`DF-007`](../providers/dockerfile.md#df-007) | No HEALTHCHECK directive declared | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`EB-000`](../providers/aws.md#eb-000) | EventBridge API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`EB-001`](../providers/aws.md#eb-001) | No EventBridge rule for CodePipeline failure notifications | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`ECR-000`](../providers/aws.md#ecr-000) | ECR API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`GCB-014`](../providers/cloudbuild.md#gcb-014) | Build logging disabled (options.logging: NONE) | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCB-025`](../providers/cloudbuild.md#gcb-025) | Build has no tags for audit / discoverability | <span class="pg-sev pg-sev--low">LOW</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCLOG-001`](../providers/gcp.md) | Cloud Audit Logs not enabled for all services | <span class="pg-sev pg-sev--high">HIGH</span> | [GCP](../providers/gcp.md) |  |
| [`GCLOG-002`](../providers/gcp.md) | No log sink configured for audit logs | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |
| [`GCLOG-003`](../providers/gcp.md) | Log bucket retention less than 365 days | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |
| [`GCS-003`](../providers/gcp.md) | Bucket versioning not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GCP](../providers/gcp.md) |  |
| [`IAM-000`](../providers/aws.md#iam-000) | IAM API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`JF-011`](../providers/jenkins.md#jf-011) | Pipeline has no `buildDiscarder` retention policy | <span class="pg-sev pg-sev--low">LOW</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-024`](../providers/kubernetes.md#k8s-024) | Container missing both livenessProbe and readinessProbe | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-033`](../providers/kubernetes.md#k8s-033) | Namespace lacks ResourceQuota or LimitRange | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`KMS-000`](../providers/aws.md#kms-000) | KMS API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`LMB-000`](../providers/aws.md#lmb-000) | Lambda API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`PBAC-000`](../providers/aws.md#pbac-000) | PBAC enumeration failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`S3-000`](../providers/aws.md#s3-000) | S3 API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`S3-003`](../providers/aws.md#s3-003) | Artifact bucket versioning not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`S3-004`](../providers/aws.md#s3-004) | Artifact bucket access logging not enabled | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`SM-000`](../providers/aws.md#sm-000) | Secrets Manager API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`SSM-000`](../providers/aws.md#ssm-000) | SSM Parameter Store API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |

### CC7.3: Security events are evaluated to determine if they require response { #ctrl-cc7-3 }

**Evidenced by 8 checks** across 3 providers (AWS, Azure Cloud, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZMON-003`](../providers/azure_cloud.md) | No alert rule for critical administrative operations | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`CD-003`](../providers/aws.md#cd-003) | No CloudWatch alarm monitoring on deployment group | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CT-001`](../providers/aws.md#ct-001) | No active CloudTrail trail in region | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CT-002`](../providers/aws.md#ct-002) | CloudTrail log-file validation disabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CT-003`](../providers/aws.md#ct-003) | CloudTrail trail is not multi-region | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CW-001`](../providers/aws.md#cw-001) | No CloudWatch alarm on CodeBuild FailedBuilds metric | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`EB-001`](../providers/aws.md#eb-001) | No EventBridge rule for CodePipeline failure notifications | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`SCM-016`](../providers/scm.md#scm-016) | Private vulnerability reporting is not enabled | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |

### CC7.4: Identified security incidents trigger a response process { #ctrl-cc7-4 }

**Evidenced by 6 checks** across 3 providers (AWS, Azure Cloud, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`AZMON-003`](../providers/azure_cloud.md) | No alert rule for critical administrative operations | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`CD-001`](../providers/aws.md#cd-001) | Automatic rollback on failure not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CD-003`](../providers/aws.md#cd-003) | No CloudWatch alarm monitoring on deployment group | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CW-001`](../providers/aws.md#cw-001) | No CloudWatch alarm on CodeBuild FailedBuilds metric | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`EB-001`](../providers/aws.md#eb-001) | No EventBridge rule for CodePipeline failure notifications | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`SCM-016`](../providers/scm.md#scm-016) | Private vulnerability reporting is not enabled | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |

### CC8.1: Changes to infrastructure, data, software, and procedures are authorized, designed, tested, approved, and implemented { #ctrl-cc8-1 }

**Evidenced by 251 checks** across 22 providers (AWS, Argo Workflows, Azure Cloud, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, Drone CI, GitHub Actions, GitLab CI, Helm, Jenkins, Kubernetes, NuGet, OCI manifest, PyPI, SCM, Tekton, maven, npm).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ACR-003`](../providers/azure_cloud.md) | Container registry content trust not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure Cloud](../providers/azure_cloud.md) |  |
| [`ADO-001`](../providers/azure.md#ado-001) | Task reference not pinned to specific version | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-004`](../providers/azure.md#ado-004) | Deployment job missing environment binding | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-005`](../providers/azure.md#ado-005) | Container image not pinned to specific version | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-006`](../providers/azure.md#ado-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-007`](../providers/azure.md#ado-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-009`](../providers/azure.md#ado-009) | Container image pinned by tag rather than sha256 digest | <span class="pg-sev pg-sev--low">LOW</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-018`](../providers/azure.md#ado-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-021`](../providers/azure.md#ado-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-022`](../providers/azure.md#ado-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-024`](../providers/azure.md#ado-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-025`](../providers/azure.md#ado-025) | Cross-repo template not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-028`](../providers/azure.md#ado-028) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-029`](../providers/azure.md#ado-029) | Service-connection-using job without environment or branch gate | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-001`](../providers/argo.md#argo-001) | Argo template container image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-008`](../providers/argo.md#argo-008) | Argo script source pipes remote install or disables TLS | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ARGO-009`](../providers/argo.md#argo-009) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-010`](../providers/argo.md#argo-010) | No SBOM generated for build artifacts | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-011`](../providers/argo.md#argo-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-014`](../providers/argo.md#argo-014) | Argo template script runs unpinned package install | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ATTEST-001`](../providers/oci.md#attest-001) | SLSA provenance attests an untrusted builder identity | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`ATTEST-002`](../providers/oci.md#attest-002) | SLSA provenance source-repo claim is missing or unverifiable | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`ATTEST-003`](../providers/oci.md#attest-003) | SBOM contains floating-version dependencies | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [OCI manifest](../providers/oci.md) |  |
| [`ATTEST-004`](../providers/oci.md#attest-004) | SLSA provenance ships without a resolved-dependencies set | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [OCI manifest](../providers/oci.md) |  |
| [`ATTEST-005`](../providers/oci.md#attest-005) | In-toto Statement subject is missing or unpinned | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`ATTEST-006`](../providers/oci.md#attest-006) | SLSA provenance lacks a meaningful buildType | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [OCI manifest](../providers/oci.md) |  |
| [`ATTEST-007`](../providers/oci.md#attest-007) | SBOM packages lack supplier / originator attribution | <span class="pg-sev pg-sev--low">LOW</span> | [OCI manifest](../providers/oci.md) |  |
| [`BB-001`](../providers/bitbucket.md#bb-001) | pipe: action not pinned to exact version | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-004`](../providers/bitbucket.md#bb-004) | Deploy step missing `deployment:` environment gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-006`](../providers/bitbucket.md#bb-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-007`](../providers/bitbucket.md#bb-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-009`](../providers/bitbucket.md#bb-009) | pipe: pinned by version rather than sha256 digest | <span class="pg-sev pg-sev--low">LOW</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-014`](../providers/bitbucket.md#bb-014) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-021`](../providers/bitbucket.md#bb-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-022`](../providers/bitbucket.md#bb-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-024`](../providers/bitbucket.md#bb-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-027`](../providers/bitbucket.md#bb-027) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-028`](../providers/bitbucket.md#bb-028) | OIDC step without deployment-gated environment | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-029`](../providers/bitbucket.md#bb-029) | image: (step or service) not pinned by sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-030`](../providers/bitbucket.md#bb-030) | npm install without registry-signature verification step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-031`](../providers/bitbucket.md#bb-031) | pip install without `--require-hashes` verification | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-001`](../providers/buildkite.md#bk-001) | Buildkite plugin not pinned to an exact version | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-004`](../providers/buildkite.md#bk-004) | Remote script piped into shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-007`](../providers/buildkite.md#bk-007) | Deploy step not gated by a manual block / input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-009`](../providers/buildkite.md#bk-009) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-010`](../providers/buildkite.md#bk-010) | No SBOM generated for build artifacts | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-011`](../providers/buildkite.md#bk-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-013`](../providers/buildkite.md#bk-013) | Deploy step has no branches: filter | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-014`](../providers/buildkite.md#bk-014) | Step commands run unpinned package installs | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CB-007`](../providers/aws.md#cb-007) | CodeBuild webhook has no filter group | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CB-008`](../providers/aws.md#cb-008) | CodeBuild buildspec is inline (not sourced from a protected repo) | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CB-009`](../providers/aws.md#cb-009) | CodeBuild image not pinned by digest | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CB-010`](../providers/aws.md#cb-010) | CodeBuild webhook allows fork-PR builds without actor filtering | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CC-001`](../providers/circleci.md#cc-001) | Orb not pinned to exact semver | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-003`](../providers/circleci.md#cc-003) | Docker image not pinned by digest | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-006`](../providers/circleci.md#cc-006) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-007`](../providers/circleci.md#cc-007) | SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-009`](../providers/circleci.md#cc-009) | Deploy job missing manual approval gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-013`](../providers/circleci.md#cc-013) | Deploy job in workflow has no branch filter | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-018`](../providers/circleci.md#cc-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-021`](../providers/circleci.md#cc-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-022`](../providers/circleci.md#cc-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-024`](../providers/circleci.md#cc-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-028`](../providers/circleci.md#cc-028) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-029`](../providers/circleci.md#cc-029) | Machine executor image not pinned | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-031`](../providers/circleci.md#cc-031) | OIDC role assumption without branch filter or approval gate | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CCM-001`](../providers/aws.md#ccm-001) | CodeCommit repository has no approval rule template attached | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CD-002`](../providers/aws.md#cd-002) | AllAtOnce deployment config, no canary or rolling strategy | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CP-001`](../providers/aws.md#cp-001) | No approval action before deploy stages | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CP-005`](../providers/aws.md#cp-005) | Production Deploy stage has no preceding ManualApproval | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`DF-001`](../providers/dockerfile.md#df-001) | FROM image not pinned to sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-003`](../providers/dockerfile.md#df-003) | ADD pulls remote URL without integrity verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-004`](../providers/dockerfile.md#df-004) | RUN executes a remote script via curl-pipe / wget-pipe | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-009`](../providers/dockerfile.md#df-009) | ADD used where COPY would suffice | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-010`](../providers/dockerfile.md#df-010) | apt-get dist-upgrade / upgrade pulls unknown package versions | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-011`](../providers/dockerfile.md#df-011) | Package manager install without cache cleanup in same layer | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-016`](../providers/dockerfile.md#df-016) | Image lacks OCI provenance labels | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-022`](../providers/dockerfile.md#df-022) | RUN uses npm install instead of npm ci | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DR-001`](../providers/drone.md#dr-001) | Step image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-005`](../providers/drone.md#dr-005) | Plugin step uses a floating image tag | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-008`](../providers/drone.md#dr-008) | Step uses ``pull: never`` (skips registry verification) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-010`](../providers/drone.md#dr-010) | Step commands run unpinned package installs | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Drone CI](../providers/drone.md) |  |
| [`ECR-006`](../providers/aws.md#ecr-006) | ECR pull-through cache rule uses an untrusted upstream | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GCB-001`](../providers/cloudbuild.md#gcb-001) | Cloud Build step image not pinned by digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCB-004`](../providers/cloudbuild.md#gcb-004) | dynamicSubstitutions on with user substitutions in step args | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-009`](../providers/cloudbuild.md#gcb-009) | Artifacts not signed (no cosign / sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-010`](../providers/cloudbuild.md#gcb-010) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-013`](../providers/cloudbuild.md#gcb-013) | Package install bypasses registry integrity (git / path / tarball) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-015`](../providers/cloudbuild.md#gcb-015) | SBOM not produced (no CycloneDX / syft / Trivy-SBOM step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-017`](../providers/cloudbuild.md#gcb-017) | Image-producing build does not request SLSA provenance | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-024`](../providers/cloudbuild.md#gcb-024) | Build pushes Docker images but top-level images: is empty | <span class="pg-sev pg-sev--low">LOW</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-026`](../providers/cloudbuild.md#gcb-026) | Step waitFor: references an unknown step id | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-001`](../providers/github.md#gha-001) | Action not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-006`](../providers/github.md#gha-006) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-007`](../providers/github.md#gha-007) | SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-014`](../providers/github.md#gha-014) | Deploy job missing environment binding | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-021`](../providers/github.md#gha-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-024`](../providers/github.md#gha-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-025`](../providers/github.md#gha-025) | Reusable workflow not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-029`](../providers/github.md#gha-029) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-030`](../providers/github.md#gha-030) | OIDC token requested without environment-protected job | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-040`](../providers/github.md#gha-040) | Action reference matches a known-compromised SHA or tag | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-041`](../providers/github.md#gha-041) | Action upstream repo has a single contributor | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-042`](../providers/github.md#gha-042) | Action upstream repo is newly created | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-043`](../providers/github.md#gha-043) | Low-star action runs with sensitive permissions | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-047`](../providers/github.md#gha-047) | Action ref resolves to a recently committed tag or SHA | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-048`](../providers/github.md#gha-048) | Workflow step writes a file under .github/workflows/ | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-051`](../providers/github.md#gha-051) | services / container image is not pinned by digest | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-059`](../providers/github.md#gha-059) | npm install without registry-signature verification step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-060`](../providers/github.md#gha-060) | pip install without `--require-hashes` verification | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-064`](../providers/github.md#gha-064) | ``contains()`` invoked with comma-delimited string operand | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-065`](../providers/github.md#gha-065) | Workflow body contains zero-width or bidi Unicode characters | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-068`](../providers/github.md#gha-068) | ``runs-on:`` targets an end-of-life hosted-runner image | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-071`](../providers/github.md#gha-071) | ``shell: pwsh`` / ``powershell`` on a Linux / macOS step | <span class="pg-sev pg-sev--low">LOW</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-086`](../providers/github.md#gha-086) | Wildcard branch trigger gates an environment-bound deploy | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-088`](../providers/github.md#gha-088) | Action ``uses:`` slug is a near-edit of a top-traffic action | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-089`](../providers/github.md#gha-089) | Action upstream repo is archived | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-090`](../providers/github.md#gha-090) | Action SHA pin references a commit absent from the claimed repo | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-091`](../providers/github.md#gha-091) | Action upstream repo is missing (takeover-eligible namespace) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-094`](../providers/github.md#gha-094) | Action SHA pin matches the current tip of an upstream branch | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-096`](../providers/github.md#gha-096) | Action reference has a known GHSA vulnerability | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-097`](../providers/github.md#gha-097) | Recursive PR auto-merge loop | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-098`](../providers/github.md#gha-098) | Pipeline deploys without a security scan gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-100`](../providers/github.md#gha-100) | ``cosign verify`` without certificate identity binding | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-001`](../providers/gitlab.md#gl-001) | Image not pinned to specific version or digest | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-004`](../providers/gitlab.md#gl-004) | Deploy job lacks manual approval or environment gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-005`](../providers/gitlab.md#gl-005) | include: pulls remote / project without pinned ref | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-006`](../providers/gitlab.md#gl-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-007`](../providers/gitlab.md#gl-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-009`](../providers/gitlab.md#gl-009) | Image pinned to version tag rather than sha256 digest | <span class="pg-sev pg-sev--low">LOW</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-018`](../providers/gitlab.md#gl-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-021`](../providers/gitlab.md#gl-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-022`](../providers/gitlab.md#gl-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-024`](../providers/gitlab.md#gl-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-027`](../providers/gitlab.md#gl-027) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-028`](../providers/gitlab.md#gl-028) | services: image not pinned | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-029`](../providers/gitlab.md#gl-029) | Manual deploy job defaults to allow_failure: true | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-030`](../providers/gitlab.md#gl-030) | trigger: include: pulls child pipeline without pinned ref | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-031`](../providers/gitlab.md#gl-031) | id_tokens: missing audience pin or environment binding | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-034`](../providers/gitlab.md#gl-034) | npm install without registry-signature verification step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-035`](../providers/gitlab.md#gl-035) | pip install without `--require-hashes` verification | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`HELM-001`](../providers/helm.md#helm-001) | Chart.yaml declares legacy apiVersion: v1 | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-002`](../providers/helm.md#helm-002) | Chart.lock missing per-dependency digests | <span class="pg-sev pg-sev--high">HIGH</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-003`](../providers/helm.md#helm-003) | Chart dependency declared on a non-HTTPS repository | <span class="pg-sev pg-sev--high">HIGH</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-004`](../providers/helm.md#helm-004) | Chart dependency version is a range, not an exact pin | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Helm](../providers/helm.md) |  |
| [`HELM-005`](../providers/helm.md#helm-005) | Chart maintainers field empty or missing chain-of-custody info | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`HELM-006`](../providers/helm.md#helm-006) | Chart.yaml does not declare a kubeVersion compatibility range | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`HELM-007`](../providers/helm.md#helm-007) | Chart.yaml description field is empty or missing | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`HELM-008`](../providers/helm.md#helm-008) | Chart.lock generated more than 90 days ago | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Helm](../providers/helm.md) |  |
| [`HELM-010`](../providers/helm.md#helm-010) | Chart.yaml appVersion field is empty or missing | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`JF-001`](../providers/jenkins.md#jf-001) | Shared library not pinned to a tag or commit | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-005`](../providers/jenkins.md#jf-005) | Deploy stage missing manual `input` approval | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-006`](../providers/jenkins.md#jf-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-007`](../providers/jenkins.md#jf-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-009`](../providers/jenkins.md#jf-009) | Agent docker image not pinned to sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-012`](../providers/jenkins.md#jf-012) | `load` step pulls Groovy from disk without integrity pin | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-018`](../providers/jenkins.md#jf-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-021`](../providers/jenkins.md#jf-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-022`](../providers/jenkins.md#jf-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-024`](../providers/jenkins.md#jf-024) | `input` approval step missing submitter restriction | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-026`](../providers/jenkins.md#jf-026) | `build job:` trigger ignores downstream failure | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-027`](../providers/jenkins.md#jf-027) | `archiveArtifacts` does not record a fingerprint | <span class="pg-sev pg-sev--low">LOW</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-028`](../providers/jenkins.md#jf-028) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-031`](../providers/jenkins.md#jf-031) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`K8S-001`](../providers/kubernetes.md#k8s-001) | Container image not pinned by sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-036`](../providers/kubernetes.md#k8s-036) | ServiceAccount imagePullSecrets references missing Secret | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`LMB-001`](../providers/aws.md#lmb-001) | Lambda function has no code-signing config | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`MVN-001`](../providers/maven.md#mvn-001) | pom.xml dependency uses a floating version range | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [maven](../providers/maven.md) |  |
| [`MVN-002`](../providers/maven.md#mvn-002) | pom.xml depends on a mutable SNAPSHOT version | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [maven](../providers/maven.md) |  |
| [`MVN-003`](../providers/maven.md#mvn-003) | pom.xml declares a plaintext-HTTP Maven repository | <span class="pg-sev pg-sev--high">HIGH</span> | [maven](../providers/maven.md) |  |
| [`MVN-004`](../providers/maven.md#mvn-004) | pom.xml dependency omits an explicit ``<version>`` | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [maven](../providers/maven.md) |  |
| [`MVN-005`](../providers/maven.md#mvn-005) | Maven repository accepts artifacts without strict checksum gating | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [maven](../providers/maven.md) |  |
| [`MVN-006`](../providers/maven.md#mvn-006) | pom.xml pins a known-compromised Maven Central artifact version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [maven](../providers/maven.md) |  |
| [`MVN-007`](../providers/maven.md#mvn-007) | settings.xml mirror routes external traffic through one repo | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [maven](../providers/maven.md) |  |
| [`MVN-008`](../providers/maven.md#mvn-008) | Direct dependency was published within the cooldown window | <span class="pg-sev pg-sev--high">HIGH</span> | [maven](../providers/maven.md) |  |
| [`MVN-009`](../providers/maven.md#mvn-009) | Maven artifact has a known OSV advisory | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [maven](../providers/maven.md) |  |
| [`NPM-001`](../providers/npm.md#npm-001) | package.json dependency uses a floating version range | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [npm](../providers/npm.md) |  |
| [`NPM-002`](../providers/npm.md#npm-002) | package-lock.json entry missing integrity hash | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NPM-003`](../providers/npm.md#npm-003) | package-lock.json entry resolves from a non-registry source | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NPM-005`](../providers/npm.md#npm-005) | package.json git dependency uses a mutable ref | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NPM-006`](../providers/npm.md#npm-006) | package-lock.json pins a known-compromised package version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [npm](../providers/npm.md) |  |
| [`NPM-008`](../providers/npm.md#npm-008) | Direct dependency was published within the cooldown window | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NPM-009`](../providers/npm.md#npm-009) | New transitive dependency added since the base ref | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NPM-010`](../providers/npm.md#npm-010) | npm package has a known OSV advisory | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [npm](../providers/npm.md) |  |
| [`NPM-012`](../providers/npm.md#npm-012) | .npmrc publish token lacks IP or readonly restriction | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NUGET-001`](../providers/nuget.md#nuget-001) | Floating NuGet version range | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [NuGet](../providers/nuget.md) |  |
| [`NUGET-002`](../providers/nuget.md#nuget-002) | Wildcard prerelease NuGet version | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [NuGet](../providers/nuget.md) |  |
| [`NUGET-003`](../providers/nuget.md#nuget-003) | PackageReference missing explicit version | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [NuGet](../providers/nuget.md) |  |
| [`NUGET-004`](../providers/nuget.md#nuget-004) | HTTP-only NuGet package source | <span class="pg-sev pg-sev--high">HIGH</span> | [NuGet](../providers/nuget.md) |  |
| [`NUGET-005`](../providers/nuget.md#nuget-005) | Known-compromised NuGet package version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [NuGet](../providers/nuget.md) |  |
| [`NUGET-006`](../providers/nuget.md#nuget-006) | No NuGet lock file for reproducible restores | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [NuGet](../providers/nuget.md) |  |
| [`NUGET-007`](../providers/nuget.md#nuget-007) | Multiple NuGet sources without packageSourceMapping | <span class="pg-sev pg-sev--high">HIGH</span> | [NuGet](../providers/nuget.md) |  |
| [`NUGET-008`](../providers/nuget.md#nuget-008) | NuGet package published within the cooldown window | <span class="pg-sev pg-sev--high">HIGH</span> | [NuGet](../providers/nuget.md) |  |
| [`NUGET-009`](../providers/nuget.md#nuget-009) | NuGet package has a known OSV advisory | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [NuGet](../providers/nuget.md) |  |
| [`OCI-001`](../providers/oci.md#oci-001) | Image manifest is missing OCI provenance annotations | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [OCI manifest](../providers/oci.md) |  |
| [`OCI-002`](../providers/oci.md#oci-002) | Image is missing a build attestation manifest | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`OCI-003`](../providers/oci.md#oci-003) | Image manifest is missing the ``image.created`` annotation | <span class="pg-sev pg-sev--low">LOW</span> | [OCI manifest](../providers/oci.md) |  |
| [`OCI-004`](../providers/oci.md#oci-004) | Image layer references an arbitrary URL (foreign layer) | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`OCI-005`](../providers/oci.md#oci-005) | Image manifest is missing the ``image.licenses`` annotation | <span class="pg-sev pg-sev--low">LOW</span> | [OCI manifest](../providers/oci.md) |  |
| [`OCI-006`](../providers/oci.md#oci-006) | Image has an excessive layer count | <span class="pg-sev pg-sev--low">LOW</span> | [OCI manifest](../providers/oci.md) |  |
| [`OCI-007`](../providers/oci.md#oci-007) | Image manifest uses legacy schemaVersion 1 (no content addressing) | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`OCI-008`](../providers/oci.md#oci-008) | Manifest references digest using unsupported hash algorithm | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`PYPI-001`](../providers/pypi.md#pypi-001) | requirements.txt entry missing an exact version pin | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [PyPI](../providers/pypi.md) |  |
| [`PYPI-002`](../providers/pypi.md#pypi-002) | requirements.txt missing hash pinning (--require-hashes / --hash=) | <span class="pg-sev pg-sev--high">HIGH</span> | [PyPI](../providers/pypi.md) |  |
| [`PYPI-003`](../providers/pypi.md#pypi-003) | requirements.txt uses an HTTP index or disables TLS verification | <span class="pg-sev pg-sev--high">HIGH</span> | [PyPI](../providers/pypi.md) |  |
| [`PYPI-004`](../providers/pypi.md#pypi-004) | requirements.txt VCS dependency uses a mutable ref | <span class="pg-sev pg-sev--high">HIGH</span> | [PyPI](../providers/pypi.md) |  |
| [`PYPI-005`](../providers/pypi.md#pypi-005) | requirements.txt declares --extra-index-url (dependency-confusion surface) | <span class="pg-sev pg-sev--high">HIGH</span> | [PyPI](../providers/pypi.md) |  |
| [`PYPI-006`](../providers/pypi.md#pypi-006) | requirements.txt pins a known-compromised PyPI package version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [PyPI](../providers/pypi.md) |  |
| [`PYPI-008`](../providers/pypi.md#pypi-008) | Direct dependency was published within the cooldown window | <span class="pg-sev pg-sev--high">HIGH</span> | [PyPI](../providers/pypi.md) |  |
| [`PYPI-009`](../providers/pypi.md#pypi-009) | PyPI package has a known OSV advisory | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [PyPI](../providers/pypi.md) |  |
| [`SCM-001`](../providers/scm.md#scm-001) | Default branch has no protection rule | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-002`](../providers/scm.md#scm-002) | Default branch protection does not require pull request reviews | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-003`](../providers/scm.md#scm-003) | GitHub default code scanning is not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-006`](../providers/scm.md#scm-006) | Default branch protection does not require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-007`](../providers/scm.md#scm-007) | Default branch protection allows force-pushes | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-008`](../providers/scm.md#scm-008) | Default branch protection does not require status checks | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-009`](../providers/scm.md#scm-009) | Default branch protection allows branch deletion | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-010`](../providers/scm.md#scm-010) | Branch protection allows administrators to bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-011`](../providers/scm.md#scm-011) | Default branch protection does not require CODEOWNERS reviews | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-012`](../providers/scm.md#scm-012) | Default branch protection keeps stale reviews after a push | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-013`](../providers/scm.md#scm-013) | Default branch protection does not require conversation resolution | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-014`](../providers/scm.md#scm-014) | Default branch protection does not require approval of the most recent push | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-017`](../providers/scm.md#scm-017) | Repository has no CODEOWNERS file | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-018`](../providers/scm.md#scm-018) | Required PR reviews can be bypassed by named identities | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-021`](../providers/scm.md#scm-021) | Actions can approve pull requests (self-approval bypass) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-023`](../providers/scm.md#scm-023) | Deployment environment lacks required-reviewer protection | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-024`](../providers/scm.md#scm-024) | Deployment environment can deploy from any branch | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-029`](../providers/scm.md#scm-029) | Repository ruleset is in evaluate / disabled mode (not enforced) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-030`](../providers/scm.md#scm-030) | Repository ruleset has bypass actor with bypass_mode: always | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-031`](../providers/scm.md#scm-031) | Repo allows auto-merge (no human-timing gate) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-032`](../providers/scm.md#scm-032) | Active ruleset doesn't require a PR review (governance theater) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-033`](../providers/scm.md#scm-033) | Active ruleset doesn't require status checks | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-034`](../providers/scm.md#scm-034) | Active ruleset doesn't block force-push | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-035`](../providers/scm.md#scm-035) | Active ruleset doesn't block branch deletion | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-036`](../providers/scm.md#scm-036) | Active ruleset doesn't require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-037`](../providers/scm.md#scm-037) | Active ruleset's pull_request rule doesn't dismiss stale reviews | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-038`](../providers/scm.md#scm-038) | Active ruleset doesn't require linear history | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-039`](../providers/scm.md#scm-039) | Active ruleset doesn't pin a required workflow | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-040`](../providers/scm.md#scm-040) | Active ruleset doesn't gate on code scanning results | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-041`](../providers/scm.md#scm-041) | Active ruleset doesn't gate on a deployment environment | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-042`](../providers/scm.md#scm-042) | Active ruleset doesn't require merge queue | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-043`](../providers/scm.md#scm-043) | Tag-targeted ruleset doesn't require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-044`](../providers/scm.md#scm-044) | Default-branch signed-commits requirement bypassed for admins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SIGN-001`](../providers/aws.md#sign-001) | No AWS Signer profile defined for Lambda deploys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`SIGN-002`](../providers/aws.md#sign-002) | AWS Signer profile is revoked or inactive | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`TKN-001`](../providers/tekton.md#tkn-001) | Tekton step image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-008`](../providers/tekton.md#tkn-008) | Tekton step script pipes remote install or disables TLS | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`TKN-009`](../providers/tekton.md#tkn-009) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-010`](../providers/tekton.md#tkn-010) | No SBOM generated for build artifacts | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-011`](../providers/tekton.md#tkn-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-014`](../providers/tekton.md#tkn-014) | Tekton step script runs unpinned package install | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

---

_This page is generated. Edit `pipeline_check/core/standards/data/soc2.py` (mappings) or `scripts/gen_standards_docs.py` (intro / per-control prose) and run `python scripts/gen_standards_docs.py soc2`._
