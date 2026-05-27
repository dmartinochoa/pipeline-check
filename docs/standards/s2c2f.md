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
- **Distinct checks evidencing this standard:** 221
- **Of those, autofixable with `--fix`:** 41

_Severity levels (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`) follow the same scale across every provider and standard. See [How to read severity](README.md#how-to-read-severity) on the standards overview for the definitions._

## Coverage by control

Click a control ID to jump to the per-control section with the full check list. The severity mix column shows the spread of evidencing checks by severity (`C`ritical / `H`igh / `M`edium / `L`ow / `I`nfo).

| Control | Title | Checks | Severity mix |
|---------|-------|-------:|--------------|
| [`ING-1`](#ctrl-ing-1) | L1: Use package managers trusted by your organization | 49 | 1C · 37H · 10M · 1L |
| [`ING-3`](#ctrl-ing-3) | L1: Have the capability to deny-list specific vulnerable / malicious OSS | 20 | 10C · 7H · 3M |
| [`SCA-1`](#ctrl-sca-1) | L1: Scan OSS for known vulnerabilities | 12 | 1H · 11M |
| [`SCA-3`](#ctrl-sca-3) | L2: Scan OSS for malware | 29 | 18C · 5H · 6M |
| [`UPD-1`](#ctrl-upd-1) | L1: Update vulnerable OSS manually (pin + track versions) | 61 | 34H · 22M · 5L |
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

**Evidenced by 49 checks** across 18 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, Drone CI, GitHub Actions, GitLab CI, Helm, Jenkins, NuGet, PyPI, Tekton, maven, npm).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-018`](../providers/azure.md#ado-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-023`](../providers/azure.md#ado-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-028`](../providers/azure.md#ado-028) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-008`](../providers/argo.md#argo-008) | Argo script source pipes remote install or disables TLS | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-014`](../providers/bitbucket.md#bb-014) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-023`](../providers/bitbucket.md#bb-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-027`](../providers/bitbucket.md#bb-027) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-004`](../providers/buildkite.md#bk-004) | Remote script piped into shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-008`](../providers/buildkite.md#bk-008) | TLS verification disabled in step command | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CA-002`](../providers/aws.md#ca-002) | CodeArtifact repository has a public external connection | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CC-018`](../providers/circleci.md#cc-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-028`](../providers/circleci.md#cc-028) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`DF-001`](../providers/dockerfile.md#df-001) | FROM image not pinned to sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-003`](../providers/dockerfile.md#df-003) | ADD pulls remote URL without integrity verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-004`](../providers/dockerfile.md#df-004) | RUN executes a remote script via curl-pipe / wget-pipe | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-021`](../providers/dockerfile.md#df-021) | RUN pip install bypasses TLS or uses an HTTP index | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-022`](../providers/dockerfile.md#df-022) | RUN uses npm install instead of npm ci | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-024`](../providers/dockerfile.md#df-024) | RUN npm/yarn/pnpm install runs lifecycle scripts | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-026`](../providers/dockerfile.md#df-026) | ENV disables Node.js TLS certificate verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-027`](../providers/dockerfile.md#df-027) | ENV disables Python HTTPS certificate verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-028`](../providers/dockerfile.md#df-028) | ENV disables Git TLS certificate verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-029`](../providers/dockerfile.md#df-029) | ENV neuters Python requests CA bundle | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DR-006`](../providers/drone.md#dr-006) | TLS verification disabled in step commands | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`ECR-006`](../providers/aws.md#ecr-006) | ECR pull-through cache rule uses an untrusted upstream | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GCB-011`](../providers/cloudbuild.md#gcb-011) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-016`](../providers/github.md#gha-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-017`](../providers/github.md#gha-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-018`](../providers/github.md#gha-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-029`](../providers/github.md#gha-029) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-018`](../providers/gitlab.md#gl-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-023`](../providers/gitlab.md#gl-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-027`](../providers/gitlab.md#gl-027) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`HELM-001`](../providers/helm.md#helm-001) | Chart.yaml declares legacy apiVersion: v1 | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-003`](../providers/helm.md#helm-003) | Chart dependency declared on a non-HTTPS repository | <span class="pg-sev pg-sev--high">HIGH</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-009`](../providers/helm.md#helm-009) | Chart home / sources URL uses a non-HTTPS scheme | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`JF-018`](../providers/jenkins.md#jf-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-023`](../providers/jenkins.md#jf-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-031`](../providers/jenkins.md#jf-031) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-035`](../providers/jenkins.md#jf-035) | httpRequest step disables SSL verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`MVN-003`](../providers/maven.md#mvn-003) | pom.xml declares a plaintext-HTTP Maven repository | <span class="pg-sev pg-sev--high">HIGH</span> | [maven](../providers/maven.md) |  |
| [`MVN-007`](../providers/maven.md#mvn-007) | settings.xml mirror routes external traffic through one repo | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [maven](../providers/maven.md) |  |
| [`NPM-003`](../providers/npm.md#npm-003) | package-lock.json entry resolves from a non-registry source | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NPM-004`](../providers/npm.md#npm-004) | package.json declares an install-time lifecycle script | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NPM-007`](../providers/npm.md#npm-007) | .npmrc does not disable install-time lifecycle scripts | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NUGET-004`](../providers/nuget.md#nuget-004) | HTTP-only NuGet package source | <span class="pg-sev pg-sev--high">HIGH</span> | [NuGet](../providers/nuget.md) |  |
| [`NUGET-007`](../providers/nuget.md#nuget-007) | Multiple NuGet sources without packageSourceMapping | <span class="pg-sev pg-sev--high">HIGH</span> | [NuGet](../providers/nuget.md) |  |
| [`PYPI-003`](../providers/pypi.md#pypi-003) | requirements.txt uses an HTTP index or disables TLS verification | <span class="pg-sev pg-sev--high">HIGH</span> | [PyPI](../providers/pypi.md) |  |
| [`PYPI-005`](../providers/pypi.md#pypi-005) | requirements.txt declares --extra-index-url (dependency-confusion surface) | <span class="pg-sev pg-sev--high">HIGH</span> | [PyPI](../providers/pypi.md) |  |
| [`TKN-008`](../providers/tekton.md#tkn-008) | Tekton step script pipes remote install or disables TLS | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### ING-3: L1: Have the capability to deny-list specific vulnerable / malicious OSS { #ctrl-ing-3 }

**Evidenced by 20 checks** across 6 providers (AWS, GitHub Actions, NuGet, PyPI, maven, npm).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CA-002`](../providers/aws.md#ca-002) | CodeArtifact repository has a public external connection | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`ECR-006`](../providers/aws.md#ecr-006) | ECR pull-through cache rule uses an untrusted upstream | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GHA-040`](../providers/github.md#gha-040) | Action reference matches a known-compromised SHA or tag | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-041`](../providers/github.md#gha-041) | Action upstream repo has a single contributor | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-042`](../providers/github.md#gha-042) | Action upstream repo is newly created | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-043`](../providers/github.md#gha-043) | Low-star action runs with sensitive permissions | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-047`](../providers/github.md#gha-047) | Action ref resolves to a recently committed tag or SHA | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-056`](../providers/github.md#gha-056) | Workflow body contains a known supply-chain worm indicator | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
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

### SCA-1: L1: Scan OSS for known vulnerabilities { #ctrl-sca-1 }

**Evidenced by 12 checks** across 11 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, GitHub Actions, GitLab CI, Jenkins, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-020`](../providers/azure.md#ado-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-012`](../providers/argo.md#argo-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-015`](../providers/bitbucket.md#bb-015) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-012`](../providers/buildkite.md#bk-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CC-020`](../providers/circleci.md#cc-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`ECR-001`](../providers/aws.md#ecr-001) | Image scanning on push not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`ECR-007`](../providers/aws.md#ecr-007) | Inspector v2 enhanced scanning disabled for ECR | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`GCB-008`](../providers/cloudbuild.md#gcb-008) | No vulnerability scanning step in Cloud Build pipeline | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-020`](../providers/github.md#gha-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-019`](../providers/gitlab.md#gl-019) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-020`](../providers/jenkins.md#jf-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`TKN-012`](../providers/tekton.md#tkn-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### SCA-3: L2: Scan OSS for malware { #ctrl-sca-3 }

**Evidenced by 29 checks** across 11 providers (AWS, Azure DevOps, Bitbucket, CircleCI, GitHub Actions, GitLab CI, Jenkins, NuGet, PyPI, maven, npm).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-026`](../providers/azure.md#ado-026) | Pipeline contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`BB-025`](../providers/bitbucket.md#bb-025) | Pipeline contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-030`](../providers/bitbucket.md#bb-030) | npm install without registry-signature verification step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-031`](../providers/bitbucket.md#bb-031) | pip install without `--require-hashes` verification | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`CB-011`](../providers/aws.md#cb-011) | CodeBuild buildspec contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`CC-026`](../providers/circleci.md#cc-026) | Config contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CircleCI](../providers/circleci.md) |  |
| [`GHA-027`](../providers/github.md#gha-027) | Workflow contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-040`](../providers/github.md#gha-040) | Action reference matches a known-compromised SHA or tag | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-056`](../providers/github.md#gha-056) | Workflow body contains a known supply-chain worm indicator | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-057`](../providers/github.md#gha-057) | Secret-scanner output sent to network egress | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-058`](../providers/github.md#gha-058) | Agentic CLI invoked with permission-bypass flags | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-059`](../providers/github.md#gha-059) | npm install without registry-signature verification step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-060`](../providers/github.md#gha-060) | pip install without `--require-hashes` verification | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-025`](../providers/gitlab.md#gl-025) | Pipeline contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-034`](../providers/gitlab.md#gl-034) | npm install without registry-signature verification step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-035`](../providers/gitlab.md#gl-035) | pip install without `--require-hashes` verification | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-029`](../providers/jenkins.md#jf-029) | Jenkinsfile contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) |  |
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

### UPD-1: L1: Update vulnerable OSS manually (pin + track versions) { #ctrl-upd-1 }

**Evidenced by 61 checks** across 19 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, Drone CI, GitHub Actions, GitLab CI, Helm, Jenkins, NuGet, OCI manifest, PyPI, Tekton, maven, npm).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-001`](../providers/azure.md#ado-001) | Task reference not pinned to specific version | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-005`](../providers/azure.md#ado-005) | Container image not pinned to specific version | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-009`](../providers/azure.md#ado-009) | Container image pinned by tag rather than sha256 digest | <span class="pg-sev pg-sev--low">LOW</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-021`](../providers/azure.md#ado-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-025`](../providers/azure.md#ado-025) | Cross-repo template not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-001`](../providers/argo.md#argo-001) | Argo template container image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-001`](../providers/bitbucket.md#bb-001) | pipe: action not pinned to exact version | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-009`](../providers/bitbucket.md#bb-009) | pipe: pinned by version rather than sha256 digest | <span class="pg-sev pg-sev--low">LOW</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-021`](../providers/bitbucket.md#bb-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-029`](../providers/bitbucket.md#bb-029) | image: (step or service) not pinned by sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-001`](../providers/buildkite.md#bk-001) | Buildkite plugin not pinned to an exact version | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CB-005`](../providers/aws.md#cb-005) | Outdated managed build image | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CB-009`](../providers/aws.md#cb-009) | CodeBuild image not pinned by digest | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CC-001`](../providers/circleci.md#cc-001) | Orb not pinned to exact semver | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-003`](../providers/circleci.md#cc-003) | Docker image not pinned by digest | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-021`](../providers/circleci.md#cc-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-029`](../providers/circleci.md#cc-029) | Machine executor image not pinned | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`DF-001`](../providers/dockerfile.md#df-001) | FROM image not pinned to sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-003`](../providers/dockerfile.md#df-003) | ADD pulls remote URL without integrity verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-010`](../providers/dockerfile.md#df-010) | apt-get dist-upgrade / upgrade pulls unknown package versions | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-011`](../providers/dockerfile.md#df-011) | Package manager install without cache cleanup in same layer | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-022`](../providers/dockerfile.md#df-022) | RUN uses npm install instead of npm ci | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DR-001`](../providers/drone.md#dr-001) | Step image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-005`](../providers/drone.md#dr-005) | Plugin step uses a floating image tag | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-008`](../providers/drone.md#dr-008) | Step uses ``pull: never`` (skips registry verification) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Drone CI](../providers/drone.md) |  |
| [`ECR-002`](../providers/aws.md#ecr-002) | Image tags are mutable | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GCB-001`](../providers/cloudbuild.md#gcb-001) | Cloud Build step image not pinned by digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-001`](../providers/github.md#gha-001) | Action not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-021`](../providers/github.md#gha-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-023`](../providers/github.md#gha-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-025`](../providers/github.md#gha-025) | Reusable workflow not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-051`](../providers/github.md#gha-051) | services / container image is not pinned by digest | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-001`](../providers/gitlab.md#gl-001) | Image not pinned to specific version or digest | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-005`](../providers/gitlab.md#gl-005) | include: pulls remote / project without pinned ref | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-009`](../providers/gitlab.md#gl-009) | Image pinned to version tag rather than sha256 digest | <span class="pg-sev pg-sev--low">LOW</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-021`](../providers/gitlab.md#gl-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-028`](../providers/gitlab.md#gl-028) | services: image not pinned | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-030`](../providers/gitlab.md#gl-030) | trigger: include: pulls child pipeline without pinned ref | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`HELM-002`](../providers/helm.md#helm-002) | Chart.lock missing per-dependency digests | <span class="pg-sev pg-sev--high">HIGH</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-004`](../providers/helm.md#helm-004) | Chart dependency version is a range, not an exact pin | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Helm](../providers/helm.md) |  |
| [`HELM-008`](../providers/helm.md#helm-008) | Chart.lock generated more than 90 days ago | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Helm](../providers/helm.md) |  |
| [`JF-001`](../providers/jenkins.md#jf-001) | Shared library not pinned to a tag or commit | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-009`](../providers/jenkins.md#jf-009) | Agent docker image not pinned to sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-021`](../providers/jenkins.md#jf-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`MVN-001`](../providers/maven.md#mvn-001) | pom.xml dependency uses a floating version range | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [maven](../providers/maven.md) |  |
| [`MVN-002`](../providers/maven.md#mvn-002) | pom.xml depends on a mutable SNAPSHOT version | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [maven](../providers/maven.md) |  |
| [`MVN-004`](../providers/maven.md#mvn-004) | pom.xml dependency omits an explicit ``<version>`` | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [maven](../providers/maven.md) |  |
| [`MVN-005`](../providers/maven.md#mvn-005) | Maven repository accepts artifacts without strict checksum gating | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [maven](../providers/maven.md) |  |
| [`NPM-001`](../providers/npm.md#npm-001) | package.json dependency uses a floating version range | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [npm](../providers/npm.md) |  |
| [`NPM-002`](../providers/npm.md#npm-002) | package-lock.json entry missing integrity hash | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NPM-005`](../providers/npm.md#npm-005) | package.json git dependency uses a mutable ref | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NUGET-001`](../providers/nuget.md#nuget-001) | Floating NuGet version range | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [NuGet](../providers/nuget.md) |  |
| [`NUGET-002`](../providers/nuget.md#nuget-002) | Wildcard prerelease NuGet version | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [NuGet](../providers/nuget.md) |  |
| [`NUGET-003`](../providers/nuget.md#nuget-003) | PackageReference missing explicit version | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [NuGet](../providers/nuget.md) |  |
| [`NUGET-006`](../providers/nuget.md#nuget-006) | No NuGet lock file for reproducible restores | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [NuGet](../providers/nuget.md) |  |
| [`OCI-007`](../providers/oci.md#oci-007) | Image manifest uses legacy schemaVersion 1 (no content addressing) | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`OCI-008`](../providers/oci.md#oci-008) | Manifest references digest using unsupported hash algorithm | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`PYPI-001`](../providers/pypi.md#pypi-001) | requirements.txt entry missing an exact version pin | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [PyPI](../providers/pypi.md) |  |
| [`PYPI-002`](../providers/pypi.md#pypi-002) | requirements.txt missing hash pinning (--require-hashes / --hash=) | <span class="pg-sev pg-sev--high">HIGH</span> | [PyPI](../providers/pypi.md) |  |
| [`PYPI-004`](../providers/pypi.md#pypi-004) | requirements.txt VCS dependency uses a mutable ref | <span class="pg-sev pg-sev--high">HIGH</span> | [PyPI](../providers/pypi.md) |  |
| [`TKN-001`](../providers/tekton.md#tkn-001) | Tekton step image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |

### UPD-2: L3: Enable automated OSS updates (Dependabot / Renovate) { #ctrl-upd-2 }

**Evidenced by 6 checks** across 6 providers (Azure DevOps, Bitbucket, CircleCI, GitHub Actions, GitLab CI, Jenkins).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-022`](../providers/azure.md#ado-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-022`](../providers/bitbucket.md#bb-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-022`](../providers/circleci.md#cc-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-022`](../providers/github.md#gha-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-022`](../providers/gitlab.md#gl-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-022`](../providers/jenkins.md#jf-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### ENF-1: L2: Enforce security policy of OSS usage (block on violation) { #ctrl-enf-1 }

**Evidenced by 13 checks** across 8 providers (AWS, Azure DevOps, Bitbucket, Buildkite, CircleCI, GitHub Actions, GitLab CI, Jenkins).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-004`](../providers/azure.md#ado-004) | Deployment job missing environment binding | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`BB-004`](../providers/bitbucket.md#bb-004) | Deploy step missing `deployment:` environment gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-007`](../providers/buildkite.md#bk-007) | Deploy step not gated by a manual block / input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-013`](../providers/buildkite.md#bk-013) | Deploy step has no branches: filter | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CB-008`](../providers/aws.md#cb-008) | CodeBuild buildspec is inline (not sourced from a protected repo) | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CC-009`](../providers/circleci.md#cc-009) | Deploy job missing manual approval gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CD-002`](../providers/aws.md#cd-002) | AllAtOnce deployment config, no canary or rolling strategy | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CP-001`](../providers/aws.md#cp-001) | No approval action before deploy stages | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CP-005`](../providers/aws.md#cp-005) | Production Deploy stage has no preceding ManualApproval | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`GHA-014`](../providers/github.md#gha-014) | Deploy job missing environment binding | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-004`](../providers/gitlab.md#gl-004) | Deploy job lacks manual approval or environment gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-005`](../providers/jenkins.md#jf-005) | Deploy stage missing manual `input` approval | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-024`](../providers/jenkins.md#jf-024) | `input` approval step missing submitter restriction | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |

### ENF-2: L2: Break the build when a violation is detected { #ctrl-enf-2 }

**Evidenced by 4 checks** across 2 providers (AWS, GitLab CI).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CP-001`](../providers/aws.md#cp-001) | No approval action before deploy stages | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CP-005`](../providers/aws.md#cp-005) | Production Deploy stage has no preceding ManualApproval | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`GL-004`](../providers/gitlab.md#gl-004) | Deploy job lacks manual approval or environment gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-029`](../providers/gitlab.md#gl-029) | Manual deploy job defaults to allow_failure: true | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |

### REB-2: L4: Digitally sign rebuilt / produced OSS artifacts { #ctrl-reb-2 }

**Evidenced by 16 checks** across 11 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, GitHub Actions, GitLab CI, Jenkins, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-006`](../providers/azure.md#ado-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-009`](../providers/argo.md#argo-009) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-006`](../providers/bitbucket.md#bb-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-009`](../providers/buildkite.md#bk-009) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CA-001`](../providers/aws.md#ca-001) | CodeArtifact domain not encrypted with customer KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CC-006`](../providers/circleci.md#cc-006) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CP-002`](../providers/aws.md#cp-002) | Artifact store not encrypted with customer-managed KMS key | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`ECR-005`](../providers/aws.md#ecr-005) | Repository encrypted with AES256 rather than KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`GCB-009`](../providers/cloudbuild.md#gcb-009) | Artifacts not signed (no cosign / sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-006`](../providers/github.md#gha-006) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-006`](../providers/gitlab.md#gl-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-006`](../providers/jenkins.md#jf-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`LMB-001`](../providers/aws.md#lmb-001) | Lambda function has no code-signing config | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`SIGN-001`](../providers/aws.md#sign-001) | No AWS Signer profile defined for Lambda deploys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`SIGN-002`](../providers/aws.md#sign-002) | AWS Signer profile is revoked or inactive | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`TKN-009`](../providers/tekton.md#tkn-009) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### REB-3: L4: Generate SBOMs for artifacts produced { #ctrl-reb-3 }

**Evidenced by 20 checks** across 12 providers (Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Dockerfile, GitHub Actions, GitLab CI, Helm, Jenkins, OCI manifest, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-007`](../providers/azure.md#ado-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-010`](../providers/argo.md#argo-010) | No SBOM generated for build artifacts | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ATTEST-003`](../providers/oci.md#attest-003) | SBOM contains floating-version dependencies | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [OCI manifest](../providers/oci.md) |  |
| [`ATTEST-004`](../providers/oci.md#attest-004) | SLSA provenance ships without a resolved-dependencies set | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [OCI manifest](../providers/oci.md) |  |
| [`ATTEST-007`](../providers/oci.md#attest-007) | SBOM packages lack supplier / originator attribution | <span class="pg-sev pg-sev--low">LOW</span> | [OCI manifest](../providers/oci.md) |  |
| [`BB-007`](../providers/bitbucket.md#bb-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-010`](../providers/buildkite.md#bk-010) | No SBOM generated for build artifacts | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CC-007`](../providers/circleci.md#cc-007) | SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`DF-016`](../providers/dockerfile.md#df-016) | Image lacks OCI provenance labels | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`GHA-007`](../providers/github.md#gha-007) | SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-007`](../providers/gitlab.md#gl-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`HELM-002`](../providers/helm.md#helm-002) | Chart.lock missing per-dependency digests | <span class="pg-sev pg-sev--high">HIGH</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-005`](../providers/helm.md#helm-005) | Chart maintainers field empty or missing chain-of-custody info | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`HELM-007`](../providers/helm.md#helm-007) | Chart.yaml description field is empty or missing | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`HELM-010`](../providers/helm.md#helm-010) | Chart.yaml appVersion field is empty or missing | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`JF-007`](../providers/jenkins.md#jf-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`OCI-001`](../providers/oci.md#oci-001) | Image manifest is missing OCI provenance annotations | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [OCI manifest](../providers/oci.md) |  |
| [`OCI-003`](../providers/oci.md#oci-003) | Image manifest is missing the ``image.created`` annotation | <span class="pg-sev pg-sev--low">LOW</span> | [OCI manifest](../providers/oci.md) |  |
| [`OCI-005`](../providers/oci.md#oci-005) | Image manifest is missing the ``image.licenses`` annotation | <span class="pg-sev pg-sev--low">LOW</span> | [OCI manifest](../providers/oci.md) |  |
| [`TKN-010`](../providers/tekton.md#tkn-010) | No SBOM generated for build artifacts | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### REB-4: L4: Digitally sign SBOMs produced (attested provenance) { #ctrl-reb-4 }

**Evidenced by 14 checks** across 10 providers (Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, GitHub Actions, GitLab CI, Jenkins, OCI manifest, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-024`](../providers/azure.md#ado-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-011`](../providers/argo.md#argo-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ATTEST-001`](../providers/oci.md#attest-001) | SLSA provenance attests an untrusted builder identity | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`ATTEST-002`](../providers/oci.md#attest-002) | SLSA provenance source-repo claim is missing or unverifiable | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`ATTEST-005`](../providers/oci.md#attest-005) | In-toto Statement subject is missing or unpinned | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`ATTEST-006`](../providers/oci.md#attest-006) | SLSA provenance lacks a meaningful buildType | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [OCI manifest](../providers/oci.md) |  |
| [`BB-024`](../providers/bitbucket.md#bb-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-011`](../providers/buildkite.md#bk-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CC-024`](../providers/circleci.md#cc-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`GHA-024`](../providers/github.md#gha-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-024`](../providers/gitlab.md#gl-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-028`](../providers/jenkins.md#jf-028) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`OCI-002`](../providers/oci.md#oci-002) | Image is missing a build attestation manifest | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`TKN-011`](../providers/tekton.md#tkn-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

---

_This page is generated. Edit `pipeline_check/core/standards/data/s2c2f.py` (mappings) or `scripts/gen_standards_docs.py` (intro / per-control prose) and run `python scripts/gen_standards_docs.py s2c2f`._
