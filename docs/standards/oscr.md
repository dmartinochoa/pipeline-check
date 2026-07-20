# OSC&R (Open Software Supply Chain Attack Reference)

- **Version:** 2024
- **URL:** <https://pbom.dev/>
- **Source of truth:** `pipeline_check/core/standards/data/oscr.py`

OSC&R (Open Software Supply Chain Attack Reference) is an open
framework that mirrors the MITRE ATT&CK matrix structure for software
supply chain attacks. Twelve tactics (Reconnaissance through Impact),
86 techniques. The matrix is maintained at
[pbom-dev/OSCAR](https://github.com/pbom-dev/OSCAR).

OSC&R fills a gap between the OWASP CI/CD Top 10 (CI/CD-specific but
only 10 items) and broader frameworks like NIST 800-53 (exhaustive
but not attack-centric). Use this page when you want to map pipeline
posture findings to a supply-chain attack taxonomy, showing which
attacker techniques your current configuration would or would not
resist.

Pair with [OWASP CI/CD Top 10](owasp_cicd_top_10.md) for the
canonical risk vocabulary and [SLSA](slsa.md) for the build-integrity
axis.

## At a glance

- **Controls in this standard:** 86
- **Controls evidenced by at least one check:** 61 / 86
- **Distinct checks evidencing this standard:** 726
- **Of those, autofixable with `--fix`:** 112

_Severity levels (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`) follow the same scale across every provider and standard. See [How to read severity](README.md#how-to-read-severity) on the standards overview for the definitions._

## Coverage by control

Click a control ID to jump to the per-control section with the full check list. The severity mix column shows the spread of evidencing checks by severity (`C`ritical / `H`igh / `M`edium / `L`ow / `I`nfo).

| Control | Title | Checks | Severity mix |
|---------|-------|-------:|--------------|
| [`REC-1`](#ctrl-rec-1) | Discover naming conventions | 0 | — |
| [`REC-2`](#ctrl-rec-2) | Scan public CI/CD configurations for secrets and vulnerable actions | 16 | 16C |
| [`REC-3`](#ctrl-rec-3) | Discover technology stacks | 0 | — |
| [`REC-4`](#ctrl-rec-4) | Active scanning | 0 | — |
| [`REC-5`](#ctrl-rec-5) | Discover used open-source dependencies | 0 | — |
| [`REC-6`](#ctrl-rec-6) | Scan public artifacts for secrets | 10 | 4C · 6H |
| [`REC-7`](#ctrl-rec-7) | Discover internal artifact names | 0 | — |
| [`REC-8`](#ctrl-rec-8) | Discover coding flaws | 0 | — |
| [`REC-9`](#ctrl-rec-9) | Accidental public disclosure of internal resources | 0 | — |
| [`REC-10`](#ctrl-rec-10) | Scan configuration on public resources | 2 | 1H · 1L |
| [`RD-1`](#ctrl-rd-1) | Malicious code contribution to an open-source repository | 6 | 3H · 3M |
| [`RD-2`](#ctrl-rd-2) | Accounts in public registry | 0 | — |
| [`RD-3`](#ctrl-rd-3) | Publish malicious artifact | 4 | 4H |
| [`RD-4`](#ctrl-rd-4) | Forge developer reputation | 4 | 1H · 3M |
| [`RD-5`](#ctrl-rd-5) | Compromised legitimate artifact | 14 | 11C · 3H |
| [`RD-6`](#ctrl-rd-6) | Advertise malicious artifact | 0 | — |
| [`IA-1`](#ctrl-ia-1) | Combosquatting | 1 | 1H |
| [`IA-2`](#ctrl-ia-2) | Malicious IDE extension | 0 | — |
| [`IA-3`](#ctrl-ia-3) | External user accounts | 1 | 1H |
| [`IA-4`](#ctrl-ia-4) | Services / servers compromise | 6 | 1H · 5M |
| [`IA-5`](#ctrl-ia-5) | Vulnerable CI/CD system | 14 | 8M · 6L |
| [`IA-6`](#ctrl-ia-6) | Exposed storage | 6 | 3C · 1H · 2M |
| [`IA-7`](#ctrl-ia-7) | Malicious module injection | 0 | — |
| [`IA-8`](#ctrl-ia-8) | Exposed webhook | 1 | 1H |
| [`IA-9`](#ctrl-ia-9) | Compromised token | 20 | 4C · 9H · 7M |
| [`IA-10`](#ctrl-ia-10) | Vulnerable CI/CD plugins | 11 | 1C · 10H |
| [`IA-11`](#ctrl-ia-11) | Vulnerable CI/CD template | 71 | 36H · 28M · 7L |
| [`IA-12`](#ctrl-ia-12) | Exposed internal API | 0 | — |
| [`IA-13`](#ctrl-ia-13) | Vulnerability in third-party dependency | 52 | 8C · 8H · 36M |
| [`IA-14`](#ctrl-ia-14) | Compromised developer workstation | 0 | — |
| [`IA-15`](#ctrl-ia-15) | Exposed database | 0 | — |
| [`IA-16`](#ctrl-ia-16) | Compromised service account | 10 | 1C · 7H · 2M |
| [`IA-17`](#ctrl-ia-17) | Dependency confusion | 8 | 6H · 2M |
| [`IA-18`](#ctrl-ia-18) | Permissive network access | 10 | 1C · 5H · 4M |
| [`IA-19`](#ctrl-ia-19) | Repojacking | 2 | 2H |
| [`IA-20`](#ctrl-ia-20) | Compromised user account | 4 | 3H · 1M |
| [`IA-21`](#ctrl-ia-21) | Typosquatting | 1 | 1H |
| [`IA-22`](#ctrl-ia-22) | Weak authentication methods | 13 | 11H · 2M |
| [`IA-23`](#ctrl-ia-23) | Brandjacking | 1 | 1H |
| [`IA-24`](#ctrl-ia-24) | Shadow IT | 2 | 1H · 1M |
| [`EX-1`](#ctrl-ex-1) | Installation scripts | 15 | 13H · 2M |
| [`EX-2`](#ctrl-ex-2) | Runtime logic bomb | 0 | — |
| [`EX-3`](#ctrl-ex-3) | IDE | 0 | — |
| [`EX-4`](#ctrl-ex-4) | Runtime backdoor | 0 | — |
| [`EX-5`](#ctrl-ex-5) | Package manager | 0 | — |
| [`EX-6`](#ctrl-ex-6) | Command injection | 84 | 8C · 69H · 6M · 1L |
| [`EX-7`](#ctrl-ex-7) | SQL injection | 0 | — |
| [`EX-8`](#ctrl-ex-8) | Cross-site scripting | 0 | — |
| [`EX-9`](#ctrl-ex-9) | Malicious artifact execution | 5 | 5C |
| [`EX-10`](#ctrl-ex-10) | Cloud workload | 0 | — |
| [`EX-11`](#ctrl-ex-11) | Auto merge rules in SCM | 2 | 1H · 1M |
| [`EX-12`](#ctrl-ex-12) | Trigger pipeline execution | 22 | 5C · 12H · 3M · 2L |
| [`PER-1`](#ctrl-per-1) | Recursive PR | 3 | 1C · 1H · 1M |
| [`PER-2`](#ctrl-per-2) | Deploy keys | 1 | 1H |
| [`PER-3`](#ctrl-per-3) | Backdoor in code | 4 | 3C · 1H |
| [`PER-4`](#ctrl-per-4) | Add user | 1 | 1H |
| [`PER-5`](#ctrl-per-5) | Untagged resources | 0 | — |
| [`PER-6`](#ctrl-per-6) | Scheduled task / job on self-hosted runner | 8 | 2H · 6M |
| [`PER-7`](#ctrl-per-7) | Implant in zombie instance | 0 | — |
| [`PER-8`](#ctrl-per-8) | Create access token | 5 | 4H · 1M |
| [`PE-1`](#ctrl-pe-1) | Inject malicious dependency to privileged user repository | 7 | 2C · 5H |
| [`PE-2`](#ctrl-pe-2) | Runners / agents running with high user privileges | 47 | 11C · 24H · 10M · 2L |
| [`DE-1`](#ctrl-de-1) | Bypass review using admin permission | 41 | 16H · 23M · 2L |
| [`DE-2`](#ctrl-de-2) | SaaS sprawl | 1 | 1M |
| [`DE-3`](#ctrl-de-3) | Misconfigured audit log settings | 33 | 3H · 6M · 8L · 16I |
| [`DE-4`](#ctrl-de-4) | Misconfiguration of security measures | 92 | 1C · 14H · 56M · 21L |
| [`DE-5`](#ctrl-de-5) | Malicious compiler / interpreter | 0 | — |
| [`DE-6`](#ctrl-de-6) | Misconfigured traffic log settings | 2 | 1M · 1L |
| [`CA-1`](#ctrl-ca-1) | Passwords in application logs | 1 | 1M |
| [`CA-2`](#ctrl-ca-2) | Dumping credentials from files | 15 | 6C · 6H · 3M |
| [`CA-3`](#ctrl-ca-3) | Harvest secrets from logs | 2 | 1C · 1H |
| [`CA-4`](#ctrl-ca-4) | Dumping short-lived token | 2 | 2M |
| [`CA-5`](#ctrl-ca-5) | Dump tokens from environment variable | 25 | 4C · 20H · 1M |
| [`CA-6`](#ctrl-ca-6) | Passwords in CI/CD logs | 42 | 19C · 19H · 4M |
| [`CA-7`](#ctrl-ca-7) | Runtime leakage of password | 0 | — |
| [`CA-8`](#ctrl-ca-8) | Steal credentials in container artifacts | 12 | 4C · 7H · 1M |
| [`LM-1`](#ctrl-lm-1) | Push implants across repositories | 1 | 1H |
| [`LM-2`](#ctrl-lm-2) | Overprivileged user account | 34 | 7C · 16H · 10M · 1L |
| [`COL-1`](#ctrl-col-1) | Unencrypted data in transit | 29 | 25H · 3M · 1L |
| [`COL-2`](#ctrl-col-2) | Unencrypted data at rest | 9 | 1C · 2H · 6M |
| [`EXF-1`](#ctrl-exf-1) | Bypass of outbound traffic control | 1 | 1C |
| [`EXF-2`](#ctrl-exf-2) | Source code | 2 | 1C · 1H |
| [`EXF-3`](#ctrl-exf-3) | Webhook | 1 | 1H |
| [`IMP-1`](#ctrl-imp-1) | Delete repositories for DoS | 2 | 2H |
| [`IMP-2`](#ctrl-imp-2) | Resource hijacking | 5 | 1H · 4M |
| [`IMP-3`](#ctrl-imp-3) | Misconfiguration of serverless workloads | 4 | 1C · 3H |

## Filter at runtime

Restrict a scan to checks that evidence this standard with `--standard oscr`:

```bash
# All providers, only checks tied to this standard
pipeline_check --standard oscr

# Compose with --pipeline to scope by provider
pipeline_check --pipeline github --standard oscr

# Compose with another standard to widen the lens
pipeline_check --pipeline aws --standard oscr --standard owasp_cicd_top_10
```

## Controls in scope

### REC-1: Discover naming conventions { #ctrl-rec-1 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### REC-2: Scan public CI/CD configurations for secrets and vulnerable actions { #ctrl-rec-2 }

**Evidenced by 16 checks** across 15 providers (Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, CloudFormation, Developer environment, Drone CI, GitHub Actions, GitLab CI, Harness CI/CD, Jenkins, Tekton, Terraform).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-008`](../providers/azure.md#ado-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ARGO-006`](../providers/argo.md#argo-006) | Literal secret value in Argo template env or parameter default | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo Workflows](../providers/argo.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-008`](../providers/bitbucket.md#bb-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-002`](../providers/buildkite.md#bk-002) | Literal secret value in pipeline env block | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-008`](../providers/circleci.md#cc-008) | Credential-shaped literal in config body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CF-002`](../providers/cloudformation.md#cf-002) | Stateful data-store resource carries a plaintext secret | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CloudFormation](../providers/cloudformation.md) |  |
| [`DEV-008`](../providers/devenv.md) | Credential-shaped literal in a developer-environment config | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Developer environment](../providers/devenv.md) |  |
| [`DR-004`](../providers/drone.md#dr-004) | Literal credential in step environment / settings | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Drone CI](../providers/drone.md) |  |
| [`GCB-012`](../providers/cloudbuild.md#gcb-012) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-008`](../providers/github.md#gha-008) | Credential-shaped literal in workflow body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-039`](../providers/github.md#gha-039) | services / container credentials embedded as literal in workflow | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-008`](../providers/gitlab.md#gl-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HARNESS-004`](../providers/harness.md#harness-004) | Literal credential in a pipeline / stage variable | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Harness CI/CD](../providers/harness.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-008`](../providers/jenkins.md#jf-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`TF-002`](../providers/terraform.md#tf-002) | Stateful data-store resource carries a plaintext secret | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Terraform](../providers/terraform.md) |  |
| [`TKN-005`](../providers/tekton.md#tkn-005) | Literal secret value in Tekton step env or param default | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Tekton](../providers/tekton.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### REC-3: Discover technology stacks { #ctrl-rec-3 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### REC-4: Active scanning { #ctrl-rec-4 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### REC-5: Discover used open-source dependencies { #ctrl-rec-5 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### REC-6: Scan public artifacts for secrets { #ctrl-rec-6 }

**Evidenced by 10 checks** across 4 providers (Dockerfile, Kubernetes, NuGet, npm).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`DF-006`](../providers/dockerfile.md#df-006) | ENV or ARG carries a credential-shaped literal value | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-019`](../providers/dockerfile.md#df-019) | COPY/ADD source path looks like a credential file | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-020`](../providers/dockerfile.md#df-020) | ARG declares a credential-named build argument | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-025`](../providers/dockerfile.md#df-025) | RUN writes a registry auth token into a Docker layer | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`K8S-017`](../providers/kubernetes.md#k8s-017) | Container env value carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-018`](../providers/kubernetes.md#k8s-018) | Secret stringData/data carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-037`](../providers/kubernetes.md#k8s-037) | ConfigMap data carries a credential-shaped literal | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`NPM-011`](../providers/npm.md#npm-011) | package.json files field includes secret-shaped paths | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NPM-013`](../providers/npm.md#npm-013) | package.json files field uses an overly broad pattern | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NUGET-010`](../providers/nuget.md#nuget-010) | NuGet.config stores a feed credential in plaintext | <span class="pg-sev pg-sev--high">HIGH</span> | [NuGet](../providers/nuget.md) |  |

### REC-7: Discover internal artifact names { #ctrl-rec-7 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### REC-8: Discover coding flaws { #ctrl-rec-8 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### REC-9: Accidental public disclosure of internal resources { #ctrl-rec-9 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### REC-10: Scan configuration on public resources { #ctrl-rec-10 }

**Evidenced by 2 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-016`](../providers/scm_github.md#scm-016) | Private vulnerability reporting is not enabled | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-026`](../providers/scm_github.md#scm-026) | Webhook ships events insecurely (HTTP / no-TLS / no-secret) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |

### RD-1: Malicious code contribution to an open-source repository { #ctrl-rd-1 }

**Evidenced by 6 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-001`](../providers/scm_github.md#scm-001) | Default branch has no protection rule | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-002`](../providers/scm_github.md#scm-002) | Default branch protection does not require pull request reviews | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-010`](../providers/scm_github.md#scm-010) | Branch protection allows administrators to bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-011`](../providers/scm_github.md#scm-011) | Default branch protection does not require CODEOWNERS reviews | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-012`](../providers/scm_github.md#scm-012) | Default branch protection keeps stale reviews after a push | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-017`](../providers/scm_github.md#scm-017) | Repository has no CODEOWNERS file | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |

### RD-2: Accounts in public registry { #ctrl-rd-2 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### RD-3: Publish malicious artifact { #ctrl-rd-3 }

**Evidenced by 4 checks** across 4 providers (NuGet, PyPI, maven, npm).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`MVN-008`](../providers/maven.md#mvn-008) | Direct dependency was published within the cooldown window | <span class="pg-sev pg-sev--high">HIGH</span> | [maven](../providers/maven.md) |  |
| [`NPM-008`](../providers/npm.md#npm-008) | Direct dependency was published within the cooldown window | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NUGET-008`](../providers/nuget.md#nuget-008) | NuGet package published within the cooldown window | <span class="pg-sev pg-sev--high">HIGH</span> | [NuGet](../providers/nuget.md) |  |
| [`PYPI-008`](../providers/pypi.md#pypi-008) | Direct dependency was published within the cooldown window | <span class="pg-sev pg-sev--high">HIGH</span> | [PyPI](../providers/pypi.md) |  |

### RD-4: Forge developer reputation { #ctrl-rd-4 }

**Evidenced by 4 checks** across GitHub Actions.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GHA-041`](../providers/github.md#gha-041) | Action upstream repo has a single contributor | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-042`](../providers/github.md#gha-042) | Action upstream repo is newly created | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-043`](../providers/github.md#gha-043) | Low-star action runs with sensitive permissions | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-047`](../providers/github.md#gha-047) | Action ref resolves to a recently committed tag or SHA | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |

### RD-5: Compromised legitimate artifact { #ctrl-rd-5 }

**Evidenced by 14 checks** across 13 providers (AWS, Azure DevOps, Bitbucket, CircleCI, Composer, GitHub Actions, GitLab CI, Jenkins, NuGet, PyPI, RubyGems, maven, npm).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-026`](../providers/azure.md#ado-026) | Pipeline contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`BB-025`](../providers/bitbucket.md#bb-025) | Pipeline contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`CB-011`](../providers/aws.md#cb-011) | CodeBuild buildspec contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`CC-026`](../providers/circleci.md#cc-026) | Config contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CircleCI](../providers/circleci.md) |  |
| [`COMPOSER-007`](../providers/composer.md) | composer.json requires a known-compromised package version | <span class="pg-sev pg-sev--high">HIGH</span> | [Composer](../providers/composer.md) |  |
| [`GEM-006`](../providers/rubygems.md) | Gemfile requires a known-compromised gem version | <span class="pg-sev pg-sev--high">HIGH</span> | [RubyGems](../providers/rubygems.md) |  |
| [`GHA-040`](../providers/github.md#gha-040) | Action reference matches a known-compromised SHA or tag | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-096`](../providers/github.md#gha-096) | Action reference has a known GHSA vulnerability | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-025`](../providers/gitlab.md#gl-025) | Pipeline contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-029`](../providers/jenkins.md#jf-029) | Jenkinsfile contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) |  |
| [`MVN-006`](../providers/maven.md#mvn-006) | pom.xml pins a known-compromised Maven Central artifact version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [maven](../providers/maven.md) |  |
| [`NPM-006`](../providers/npm.md#npm-006) | package-lock.json pins a known-compromised package version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [npm](../providers/npm.md) |  |
| [`NUGET-005`](../providers/nuget.md#nuget-005) | Known-compromised NuGet package version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [NuGet](../providers/nuget.md) |  |
| [`PYPI-006`](../providers/pypi.md#pypi-006) | requirements.txt pins a known-compromised PyPI package version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [PyPI](../providers/pypi.md) |  |

### RD-6: Advertise malicious artifact { #ctrl-rd-6 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### IA-1: Combosquatting { #ctrl-ia-1 }

**Evidenced by 1 check** across GitHub Actions.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GHA-088`](../providers/github.md#gha-088) | Action ``uses:`` slug is a near-edit of a top-traffic action | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |

### IA-2: Malicious IDE extension { #ctrl-ia-2 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### IA-3: External user accounts { #ctrl-ia-3 }

**Evidenced by 1 check** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-027`](../providers/scm_github.md#scm-027) | Outside collaborator holds write / maintain / admin access | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |

### IA-4: Services / servers compromise { #ctrl-ia-4 }

**Evidenced by 6 checks** across 5 providers (Azure DevOps, Bitbucket, CircleCI, GitHub Actions, GitLab CI).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-013`](../providers/azure.md#ado-013) | Self-hosted pool without explicit ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`BB-016`](../providers/bitbucket.md#bb-016) | Self-hosted runner without ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`CC-010`](../providers/circleci.md#cc-010) | Self-hosted runner without ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`GHA-012`](../providers/github.md#gha-012) | Self-hosted runner without ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-105`](../providers/github.md#gha-105) | Self-hosted runner reachable from an untrusted PR trigger | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-014`](../providers/gitlab.md#gl-014) | Self-managed runner without ephemeral tag | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |

### IA-5: Vulnerable CI/CD system { #ctrl-ia-5 }

**Evidenced by 14 checks** across 12 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, GitHub Actions, GitLab CI, Harness CI/CD, Jenkins, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-015`](../providers/azure.md#ado-015) | Job has no `timeoutInMinutes`, unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ARGO-007`](../providers/argo.md#argo-007) | Argo workflow has no activeDeadlineSeconds | <span class="pg-sev pg-sev--low">LOW</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-005`](../providers/bitbucket.md#bb-005) | Step has no `max-time`, unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-006`](../providers/buildkite.md#bk-006) | Step has no timeout_in_minutes | <span class="pg-sev pg-sev--low">LOW</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CB-004`](../providers/aws.md#cb-004) | Build timeout missing or at the AWS maximum (480 min) | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`CB-005`](../providers/aws.md#cb-005) | Outdated managed build image | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CC-015`](../providers/circleci.md#cc-015) | No `no_output_timeout` configured | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCB-005`](../providers/cloudbuild.md#gcb-005) | Build timeout unset or excessive | <span class="pg-sev pg-sev--low">LOW</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-015`](../providers/github.md#gha-015) | Job has no `timeout-minutes`, unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-068`](../providers/github.md#gha-068) | ``runs-on:`` targets an end-of-life hosted-runner image | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-015`](../providers/gitlab.md#gl-015) | Job has no `timeout`, unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HARNESS-019`](../providers/harness.md#harness-019) | Pipeline step lacks an explicit timeout | <span class="pg-sev pg-sev--low">LOW</span> | [Harness CI/CD](../providers/harness.md) |  |
| [`JF-015`](../providers/jenkins.md#jf-015) | Pipeline has no `timeout` wrapper, unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`TKN-006`](../providers/tekton.md#tkn-006) | Tekton run lacks an explicit timeout | <span class="pg-sev pg-sev--low">LOW</span> | [Tekton](../providers/tekton.md) |  |

### IA-6: Exposed storage { #ctrl-ia-6 }

**Evidenced by 6 checks** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CA-003`](../providers/aws.md#ca-003) | CodeArtifact domain policy allows cross-account wildcard | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`CCM-003`](../providers/aws.md#ccm-003) | CodeCommit trigger targets SNS/Lambda in a different account | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`ECR-003`](../providers/aws.md#ecr-003) | Repository policy allows public access | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`S3-001`](../providers/aws.md#s3-001) | Artifact bucket public access block not fully enabled | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`S3-002`](../providers/aws.md#s3-002) | Artifact bucket server-side encryption not configured | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`S3-003`](../providers/aws.md#s3-003) | Artifact bucket versioning not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |

### IA-7: Malicious module injection { #ctrl-ia-7 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### IA-8: Exposed webhook { #ctrl-ia-8 }

**Evidenced by 1 check** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`EB-002`](../providers/aws.md#eb-002) | EventBridge rule has a wildcard target ARN | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |

### IA-9: Compromised token { #ctrl-ia-9 }

**Evidenced by 20 checks** across 10 providers (AWS, Azure DevOps, Bitbucket, CircleCI, Cloud Build, GitHub Actions, GitLab CI, Jenkins, SCM, npm).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-014`](../providers/azure.md#ado-014) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-011`](../providers/bitbucket.md#bb-011) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-017`](../providers/bitbucket.md#bb-017) | Repository token written to persistent storage | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CB-001`](../providers/aws.md#cb-001) | Secrets in plaintext environment variables | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`CB-006`](../providers/aws.md#cb-006) | CodeBuild source auth uses long-lived token | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CC-019`](../providers/circleci.md#cc-019) | `add_ssh_keys` without fingerprint restriction | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CP-004`](../providers/aws.md#cp-004) | Legacy ThirdParty/GitHub source action (OAuth token) | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GCB-003`](../providers/cloudbuild.md#gcb-003) | Secret Manager value referenced in step args | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-018`](../providers/cloudbuild.md#gcb-018) | Legacy KMS secrets block in use (prefer availableSecrets / Secret Manager) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-005`](../providers/github.md#gha-005) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-019`](../providers/github.md#gha-019) | GITHUB_TOKEN written to persistent storage | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-037`](../providers/github.md#gha-037) | actions/checkout persists GITHUB_TOKEN into .git/config | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-054`](../providers/github.md#gha-054) | actions/checkout with ssh-key persists SSH credential in repo | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-013`](../providers/gitlab.md#gl-013) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-020`](../providers/gitlab.md#gl-020) | CI_JOB_TOKEN written to persistent storage | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`IAM-007`](../providers/aws.md#iam-007) | IAM user has access key older than 90 days | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`JF-004`](../providers/jenkins.md#jf-004) | AWS auth uses long-lived access keys via withCredentials | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-010`](../providers/jenkins.md#jf-010) | Long-lived AWS keys exposed via environment {} block | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`NPM-012`](../providers/npm.md#npm-012) | .npmrc publish token lacks IP or readonly restriction | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`SCM-049`](../providers/scm_github.md#scm-049) | Classic PAT used where a fine-grained token suffices | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |

### IA-10: Vulnerable CI/CD plugins { #ctrl-ia-10 }

**Evidenced by 11 checks** across 9 providers (Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, GitHub Actions, GitLab CI, Jenkins).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-016`](../providers/azure.md#ado-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-012`](../providers/bitbucket.md#bb-012) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-004`](../providers/buildkite.md#bk-004) | Remote script piped into shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-016`](../providers/circleci.md#cc-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-004`](../providers/dockerfile.md#df-004) | RUN executes a remote script via curl-pipe / wget-pipe | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`GCB-010`](../providers/cloudbuild.md#gcb-010) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-016`](../providers/github.md#gha-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-040`](../providers/github.md#gha-040) | Action reference matches a known-compromised SHA or tag | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-096`](../providers/github.md#gha-096) | Action reference has a known GHSA vulnerability | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-016`](../providers/gitlab.md#gl-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-016`](../providers/jenkins.md#jf-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### IA-11: Vulnerable CI/CD template { #ctrl-ia-11 }

**Evidenced by 71 checks** across 21 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, Drone CI, GitHub Actions, GitLab CI, Harness CI/CD, Helm, Jenkins, Kubernetes, Modelfile, NuGet, PyPI, Tekton, maven, npm).

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
| [`CB-009`](../providers/aws.md#cb-009) | CodeBuild image not pinned by digest | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CC-001`](../providers/circleci.md#cc-001) | Orb not pinned to exact semver | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-003`](../providers/circleci.md#cc-003) | Docker image not pinned by digest | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-021`](../providers/circleci.md#cc-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-029`](../providers/circleci.md#cc-029) | Machine executor image not pinned | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`DF-001`](../providers/dockerfile.md#df-001) | FROM image not pinned to sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-003`](../providers/dockerfile.md#df-003) | ADD pulls remote URL without integrity verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-009`](../providers/dockerfile.md#df-009) | ADD used where COPY would suffice | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-010`](../providers/dockerfile.md#df-010) | apt-get dist-upgrade / upgrade pulls unknown package versions | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-031`](../providers/dockerfile.md#df-031) | COPY --from external image not pinned to sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DR-001`](../providers/drone.md#dr-001) | Step image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-005`](../providers/drone.md#dr-005) | Plugin step uses a floating image tag | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-008`](../providers/drone.md#dr-008) | Step uses ``pull: never`` (skips registry verification) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Drone CI](../providers/drone.md) |  |
| [`ECR-002`](../providers/aws.md#ecr-002) | Image tags are mutable | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GCB-001`](../providers/cloudbuild.md#gcb-001) | Cloud Build step image not pinned by digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCB-004`](../providers/cloudbuild.md#gcb-004) | dynamicSubstitutions on with user substitutions in step args | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-001`](../providers/github.md#gha-001) | Action not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-021`](../providers/github.md#gha-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-025`](../providers/github.md#gha-025) | Reusable workflow not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-051`](../providers/github.md#gha-051) | services / container image is not pinned by digest | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-089`](../providers/github.md#gha-089) | Action upstream repo is archived | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-090`](../providers/github.md#gha-090) | Action SHA pin references a commit absent from the claimed repo | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-094`](../providers/github.md#gha-094) | Action SHA pin matches the current tip of an upstream branch | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-095`](../providers/github.md#gha-095) | Action SHA pin does not match its version comment | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-001`](../providers/gitlab.md#gl-001) | Image not pinned to specific version or digest | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-005`](../providers/gitlab.md#gl-005) | include: pulls remote / project without pinned ref | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-009`](../providers/gitlab.md#gl-009) | Image pinned to version tag rather than sha256 digest | <span class="pg-sev pg-sev--low">LOW</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-021`](../providers/gitlab.md#gl-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-028`](../providers/gitlab.md#gl-028) | services: image not pinned | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-042`](../providers/gitlab.md#gl-042) | include: component pulls a CI/CD component without a pinned version | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`HARNESS-001`](../providers/harness.md#harness-001) | Step image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Harness CI/CD](../providers/harness.md) |  |
| [`HELM-001`](../providers/helm.md#helm-001) | Chart.yaml declares legacy apiVersion: v1 | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-004`](../providers/helm.md#helm-004) | Chart dependency version is a range, not an exact pin | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Helm](../providers/helm.md) |  |
| [`HELM-008`](../providers/helm.md#helm-008) | Chart.lock generated more than 90 days ago | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Helm](../providers/helm.md) |  |
| [`JF-001`](../providers/jenkins.md#jf-001) | Shared library not pinned to a tag or commit | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-009`](../providers/jenkins.md#jf-009) | Agent docker image not pinned to sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-021`](../providers/jenkins.md#jf-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-036`](../providers/kubernetes.md#k8s-036) | ServiceAccount imagePullSecrets references missing Secret | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`MODEL-001`](../providers/modelfile.md#model-001) | Base model pulled without a pinned reference | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Modelfile](../providers/modelfile.md) |  |
| [`MODEL-002`](../providers/modelfile.md#model-002) | Base model pulled from a third-party hub | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Modelfile](../providers/modelfile.md) |  |
| [`MODEL-003`](../providers/modelfile.md#model-003) | Base model loaded from a local unverified weights blob | <span class="pg-sev pg-sev--low">LOW</span> | [Modelfile](../providers/modelfile.md) |  |
| [`MODEL-004`](../providers/modelfile.md#model-004) | LoRA adapter applied from a remote source | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Modelfile](../providers/modelfile.md) |  |
| [`MODEL-005`](../providers/modelfile.md#model-005) | Vendored model config declares custom loader code (auto_map) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Modelfile](../providers/modelfile.md) |  |
| [`MODEL-006`](../providers/modelfile.md#model-006) | Committed model weights in a code-executing serialization format | <span class="pg-sev pg-sev--low">LOW</span> | [Modelfile](../providers/modelfile.md) |  |
| [`MVN-001`](../providers/maven.md#mvn-001) | pom.xml dependency uses a floating version range | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [maven](../providers/maven.md) |  |
| [`MVN-002`](../providers/maven.md#mvn-002) | pom.xml depends on a mutable SNAPSHOT version | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [maven](../providers/maven.md) |  |
| [`MVN-004`](../providers/maven.md#mvn-004) | pom.xml dependency omits an explicit ``<version>`` | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [maven](../providers/maven.md) |  |
| [`MVN-005`](../providers/maven.md#mvn-005) | Maven repository accepts artifacts without strict checksum gating | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [maven](../providers/maven.md) |  |
| [`NPM-001`](../providers/npm.md#npm-001) | package.json dependency uses a floating version range | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [npm](../providers/npm.md) |  |
| [`NPM-002`](../providers/npm.md#npm-002) | package-lock.json entry missing integrity hash | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NUGET-001`](../providers/nuget.md#nuget-001) | Floating NuGet version range | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [NuGet](../providers/nuget.md) |  |
| [`NUGET-002`](../providers/nuget.md#nuget-002) | Wildcard prerelease NuGet version | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [NuGet](../providers/nuget.md) |  |
| [`NUGET-003`](../providers/nuget.md#nuget-003) | PackageReference missing explicit version | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [NuGet](../providers/nuget.md) |  |
| [`NUGET-006`](../providers/nuget.md#nuget-006) | No NuGet lock file for reproducible restores | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [NuGet](../providers/nuget.md) |  |
| [`PYPI-001`](../providers/pypi.md#pypi-001) | requirements.txt entry missing an exact version pin | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [PyPI](../providers/pypi.md) |  |
| [`PYPI-002`](../providers/pypi.md#pypi-002) | requirements.txt missing hash pinning (--require-hashes / --hash=) | <span class="pg-sev pg-sev--high">HIGH</span> | [PyPI](../providers/pypi.md) |  |
| [`PYPI-004`](../providers/pypi.md#pypi-004) | requirements.txt VCS dependency uses a mutable ref | <span class="pg-sev pg-sev--high">HIGH</span> | [PyPI](../providers/pypi.md) |  |
| [`PYPI-015`](../providers/pypi.md#pypi-015) | requirements.txt installs from a direct artifact URL | <span class="pg-sev pg-sev--high">HIGH</span> | [PyPI](../providers/pypi.md) |  |
| [`TKN-001`](../providers/tekton.md#tkn-001) | Tekton step image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-016`](../providers/tekton.md#tkn-016) | Remote resolver taskRef / pipelineRef not pinned to an immutable revision | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |

### IA-12: Exposed internal API { #ctrl-ia-12 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### IA-13: Vulnerability in third-party dependency { #ctrl-ia-13 }

**Evidenced by 52 checks** across 20 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Composer, Drone CI, GitHub Actions, GitLab CI, Harness CI/CD, Jenkins, NuGet, PyPI, RubyGems, SCM, Tekton, maven, npm).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-020`](../providers/azure.md#ado-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-022`](../providers/azure.md#ado-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-028`](../providers/azure.md#ado-028) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-012`](../providers/argo.md#argo-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-014`](../providers/argo.md#argo-014) | Argo template script runs unpinned package install | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-015`](../providers/bitbucket.md#bb-015) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-022`](../providers/bitbucket.md#bb-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-027`](../providers/bitbucket.md#bb-027) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-030`](../providers/bitbucket.md#bb-030) | npm install without registry-signature verification step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-031`](../providers/bitbucket.md#bb-031) | pip install without `--require-hashes` verification | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-012`](../providers/buildkite.md#bk-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-014`](../providers/buildkite.md#bk-014) | Step commands run unpinned package installs | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CC-020`](../providers/circleci.md#cc-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-022`](../providers/circleci.md#cc-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-028`](../providers/circleci.md#cc-028) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`COMPOSER-007`](../providers/composer.md) | composer.json requires a known-compromised package version | <span class="pg-sev pg-sev--high">HIGH</span> | [Composer](../providers/composer.md) |  |
| [`DR-010`](../providers/drone.md#dr-010) | Step commands run unpinned package installs | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-022`](../providers/drone.md#dr-022) | No vulnerability-scan step (trivy / grype / snyk) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Drone CI](../providers/drone.md) |  |
| [`ECR-001`](../providers/aws.md#ecr-001) | Image scanning on push not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`ECR-007`](../providers/aws.md#ecr-007) | Inspector v2 enhanced scanning disabled for ECR | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`GCB-008`](../providers/cloudbuild.md#gcb-008) | No vulnerability scanning step in Cloud Build pipeline | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GEM-006`](../providers/rubygems.md) | Gemfile requires a known-compromised gem version | <span class="pg-sev pg-sev--high">HIGH</span> | [RubyGems](../providers/rubygems.md) |  |
| [`GHA-020`](../providers/github.md#gha-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-022`](../providers/github.md#gha-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-029`](../providers/github.md#gha-029) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-059`](../providers/github.md#gha-059) | npm install without registry-signature verification step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-060`](../providers/github.md#gha-060) | pip install without `--require-hashes` verification | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-019`](../providers/gitlab.md#gl-019) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-022`](../providers/gitlab.md#gl-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-027`](../providers/gitlab.md#gl-027) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-034`](../providers/gitlab.md#gl-034) | npm install without registry-signature verification step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-035`](../providers/gitlab.md#gl-035) | pip install without `--require-hashes` verification | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`HARNESS-018`](../providers/harness.md#harness-018) | No vulnerability-scan step (trivy / grype / snyk) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Harness CI/CD](../providers/harness.md) |  |
| [`JF-020`](../providers/jenkins.md#jf-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-022`](../providers/jenkins.md#jf-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-031`](../providers/jenkins.md#jf-031) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`MVN-006`](../providers/maven.md#mvn-006) | pom.xml pins a known-compromised Maven Central artifact version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [maven](../providers/maven.md) |  |
| [`MVN-008`](../providers/maven.md#mvn-008) | Direct dependency was published within the cooldown window | <span class="pg-sev pg-sev--high">HIGH</span> | [maven](../providers/maven.md) |  |
| [`MVN-009`](../providers/maven.md#mvn-009) | Maven artifact has a known OSV advisory | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [maven](../providers/maven.md) |  |
| [`NPM-006`](../providers/npm.md#npm-006) | package-lock.json pins a known-compromised package version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [npm](../providers/npm.md) |  |
| [`NPM-008`](../providers/npm.md#npm-008) | Direct dependency was published within the cooldown window | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NPM-009`](../providers/npm.md#npm-009) | New transitive dependency added since the base ref | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NPM-010`](../providers/npm.md#npm-010) | npm package has a known OSV advisory | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [npm](../providers/npm.md) |  |
| [`NUGET-005`](../providers/nuget.md#nuget-005) | Known-compromised NuGet package version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [NuGet](../providers/nuget.md) |  |
| [`NUGET-008`](../providers/nuget.md#nuget-008) | NuGet package published within the cooldown window | <span class="pg-sev pg-sev--high">HIGH</span> | [NuGet](../providers/nuget.md) |  |
| [`NUGET-009`](../providers/nuget.md#nuget-009) | NuGet package has a known OSV advisory | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [NuGet](../providers/nuget.md) |  |
| [`PYPI-006`](../providers/pypi.md#pypi-006) | requirements.txt pins a known-compromised PyPI package version | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [PyPI](../providers/pypi.md) |  |
| [`PYPI-008`](../providers/pypi.md#pypi-008) | Direct dependency was published within the cooldown window | <span class="pg-sev pg-sev--high">HIGH</span> | [PyPI](../providers/pypi.md) |  |
| [`PYPI-009`](../providers/pypi.md#pypi-009) | PyPI package has a known OSV advisory | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [PyPI](../providers/pypi.md) |  |
| [`SCM-005`](../providers/scm_github.md#scm-005) | Dependabot security updates are not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`TKN-012`](../providers/tekton.md#tkn-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-014`](../providers/tekton.md#tkn-014) | Tekton step script runs unpinned package install | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### IA-14: Compromised developer workstation { #ctrl-ia-14 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### IA-15: Exposed database { #ctrl-ia-15 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### IA-16: Compromised service account { #ctrl-ia-16 }

**Evidenced by 10 checks** across 3 providers (AWS, Cloud Build, Terraform).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GCB-020`](../providers/cloudbuild.md#gcb-020) | serviceAccount points at the default Cloud Build service account | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`IAM-001`](../providers/aws.md#iam-001) | CI/CD role has AdministratorAccess policy attached | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`IAM-002`](../providers/aws.md#iam-002) | CI/CD role has wildcard Action in attached policy | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-003`](../providers/aws.md#iam-003) | CI/CD role has no permission boundary | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`IAM-004`](../providers/aws.md#iam-004) | CI/CD role can PassRole to any role | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-005`](../providers/aws.md#iam-005) | CI/CD role trust policy missing sts:ExternalId | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-006`](../providers/aws.md#iam-006) | Sensitive actions granted with wildcard Resource | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`IAM-008`](../providers/aws.md#iam-008) | OIDC-federated role trust policy missing audience or subject pin | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-009`](../providers/terraform.md#iam-009) | Azure federated identity credential trusts a broad GitHub subject | <span class="pg-sev pg-sev--high">HIGH</span> | [Terraform](../providers/terraform.md) |  |
| [`IAM-010`](../providers/terraform.md#iam-010) | GCP workload identity provider has no repository attribute condition | <span class="pg-sev pg-sev--high">HIGH</span> | [Terraform](../providers/terraform.md) |  |

### IA-17: Dependency confusion { #ctrl-ia-17 }

**Evidenced by 8 checks** across 5 providers (AWS, NuGet, PyPI, maven, npm).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CA-002`](../providers/aws.md#ca-002) | CodeArtifact repository has a public external connection | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`ECR-006`](../providers/aws.md#ecr-006) | ECR pull-through cache rule uses an untrusted upstream | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`MVN-007`](../providers/maven.md#mvn-007) | settings.xml mirror routes external traffic through one repo | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [maven](../providers/maven.md) |  |
| [`NPM-003`](../providers/npm.md#npm-003) | package-lock.json entry resolves from a non-registry source | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NUGET-007`](../providers/nuget.md#nuget-007) | Multiple NuGet sources without packageSourceMapping | <span class="pg-sev pg-sev--high">HIGH</span> | [NuGet](../providers/nuget.md) |  |
| [`PYPI-005`](../providers/pypi.md#pypi-005) | requirements.txt declares --extra-index-url (dependency-confusion surface) | <span class="pg-sev pg-sev--high">HIGH</span> | [PyPI](../providers/pypi.md) |  |
| [`PYPI-016`](../providers/pypi.md#pypi-016) | requirements.txt repoints the primary index at a non-PyPI host | <span class="pg-sev pg-sev--high">HIGH</span> | [PyPI](../providers/pypi.md) |  |
| [`PYPI-017`](../providers/pypi.md#pypi-017) | requirements.txt uses a remote --find-links source | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [PyPI](../providers/pypi.md) |  |

### IA-18: Permissive network access { #ctrl-ia-18 }

**Evidenced by 10 checks** across 5 providers (AWS, CloudFormation, Dockerfile, Kubernetes, Terraform).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CF-003`](../providers/cloudformation.md#cf-003) | CodeBuild project's VPC contains a public subnet | <span class="pg-sev pg-sev--high">HIGH</span> | [CloudFormation](../providers/cloudformation.md) |  |
| [`DF-013`](../providers/dockerfile.md#df-013) | EXPOSE declares sensitive remote-access port | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-026`](../providers/kubernetes.md#k8s-026) | LoadBalancer Service has no loadBalancerSourceRanges | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-027`](../providers/kubernetes.md#k8s-027) | Ingress has no TLS configuration | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-032`](../providers/kubernetes.md#k8s-032) | Namespace lacks default-deny NetworkPolicy | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-038`](../providers/kubernetes.md#k8s-038) | NetworkPolicy ingress / egress allows all sources or destinations | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-041`](../providers/kubernetes.md#k8s-041) | Service.externalIPs allows traffic interception (CVE-2020-8554) | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-043`](../providers/kubernetes.md#k8s-043) | Ingress rule has wildcard or missing host (catch-all) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`PBAC-001`](../providers/aws.md#pbac-001) | CodeBuild project has no VPC configuration | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`TF-003`](../providers/terraform.md#tf-003) | CodeBuild VPC config references a public subnet | <span class="pg-sev pg-sev--high">HIGH</span> | [Terraform](../providers/terraform.md) |  |

### IA-19: Repojacking { #ctrl-ia-19 }

**Evidenced by 2 checks** across GitHub Actions.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GHA-090`](../providers/github.md#gha-090) | Action SHA pin references a commit absent from the claimed repo | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-091`](../providers/github.md#gha-091) | Action upstream repo is missing (takeover-eligible namespace) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |

### IA-20: Compromised user account { #ctrl-ia-20 }

**Evidenced by 4 checks** across 2 providers (GitHub Actions, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GHA-034`](../providers/github.md#gha-034) | Reusable workflow called with secrets: inherit | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-116`](../providers/github.md#gha-116) | Workflow serializes the entire secrets context (toJSON(secrets)) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`SCM-020`](../providers/scm_github.md#scm-020) | Default workflow GITHUB_TOKEN has write permission | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-025`](../providers/scm_github.md#scm-025) | Repo has write-enabled deploy keys (push backdoor) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |

### IA-21: Typosquatting { #ctrl-ia-21 }

**Evidenced by 1 check** across GitHub Actions.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GHA-088`](../providers/github.md#gha-088) | Action ``uses:`` slug is a near-edit of a top-traffic action | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |

### IA-22: Weak authentication methods { #ctrl-ia-22 }

**Evidenced by 13 checks** across 5 providers (Azure DevOps, Bitbucket, CircleCI, GitHub Actions, GitLab CI).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-029`](../providers/azure.md#ado-029) | Service-connection-using job without environment or branch gate | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`BB-028`](../providers/bitbucket.md#bb-028) | OIDC step without deployment-gated environment | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`CC-031`](../providers/circleci.md#cc-031) | OIDC role assumption without branch filter or approval gate | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`GHA-030`](../providers/github.md#gha-030) | OIDC token requested without environment-protected job | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-050`](../providers/github.md#gha-050) | Publish step relies on long-lived registry token | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-062`](../providers/github.md#gha-062) | OIDC subject claim in sibling IaC grants overly broad scope | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-069`](../providers/github.md#gha-069) | ``id-token: write`` granted without an OIDC-consumer step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-113`](../providers/github.md#gha-113) | OIDC trusted-publishing job without an environment gate | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-114`](../providers/github.md#gha-114) | Package-publish workflow runs on an unrestricted push trigger | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-115`](../providers/github.md#gha-115) | ``id-token: write`` granted workflow-wide instead of job-scoped | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-031`](../providers/gitlab.md#gl-031) | id_tokens: missing audience pin or environment binding | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-040`](../providers/gitlab.md#gl-040) | CI_JOB_TOKEN used for cross-project / remote access | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-050`](../providers/gitlab.md#gl-050) | Package-publish job relies on a long-lived registry token | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |

### IA-23: Brandjacking { #ctrl-ia-23 }

**Evidenced by 1 check** across GitHub Actions.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GHA-088`](../providers/github.md#gha-088) | Action ``uses:`` slug is a near-edit of a top-traffic action | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |

### IA-24: Shadow IT { #ctrl-ia-24 }

**Evidenced by 2 checks** across 2 providers (GitHub Actions, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GHA-018`](../providers/github.md#gha-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`SCM-022`](../providers/scm_github.md#scm-022) | Repo Actions permissions allow any source (no allow-list) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |

### EX-1: Installation scripts { #ctrl-ex-1 }

**Evidenced by 15 checks** across 11 providers (Argo CD, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, GitHub Actions, GitLab CI, Jenkins, npm).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-016`](../providers/azure.md#ado-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ARGOCD-008`](../providers/argocd.md#argocd-008) | Argo CD Application invokes a config-management plugin | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo CD](../providers/argocd.md) |  |
| [`ARGOCD-015`](../providers/argocd.md#argocd-015) | Argo CD Kustomize build options enable the Helm plugin | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo CD](../providers/argocd.md) |  |
| [`BB-012`](../providers/bitbucket.md#bb-012) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-004`](../providers/buildkite.md#bk-004) | Remote script piped into shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-016`](../providers/circleci.md#cc-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-004`](../providers/dockerfile.md#df-004) | RUN executes a remote script via curl-pipe / wget-pipe | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-022`](../providers/dockerfile.md#df-022) | RUN uses npm install instead of npm ci | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-024`](../providers/dockerfile.md#df-024) | RUN npm/yarn/pnpm install runs lifecycle scripts | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`GCB-010`](../providers/cloudbuild.md#gcb-010) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-016`](../providers/github.md#gha-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-016`](../providers/gitlab.md#gl-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-016`](../providers/jenkins.md#jf-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`NPM-004`](../providers/npm.md#npm-004) | package.json declares an install-time lifecycle script | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NPM-007`](../providers/npm.md#npm-007) | .npmrc does not disable install-time lifecycle scripts | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |

### EX-2: Runtime logic bomb { #ctrl-ex-2 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### EX-3: IDE { #ctrl-ex-3 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### EX-4: Runtime backdoor { #ctrl-ex-4 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### EX-5: Package manager { #ctrl-ex-5 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### EX-6: Command injection { #ctrl-ex-6 }

**Evidenced by 84 checks** across 14 providers (Argo CD, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, Drone CI, GitHub Actions, GitLab CI, Harness CI/CD, Jenkins, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-002`](../providers/azure.md#ado-002) | Script injection via attacker-controllable context | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-012`](../providers/azure.md#ado-012) | Cache@2 key derives from $(System.PullRequest.*) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-027`](../providers/azure.md#ado-027) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-030`](../providers/azure.md#ado-030) | pool interpolates attacker-controllable value | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-034`](../providers/azure.md#ado-034) | ML model loaded with trust_remote_code (code execution) | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-035`](../providers/azure.md#ado-035) | Untrusted PR/commit context reaches an agentic AI CLI (prompt injection) | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-036`](../providers/azure.md#ado-036) | Unsafe deserialization of a fetched artifact (pickle RCE) | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-005`](../providers/argo.md#argo-005) | Argo input parameter interpolated unsafely in script / args | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-017`](../providers/argo.md#argo-017) | Argo resource template applies a manifest built from an untrusted parameter | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-019`](../providers/argo.md#argo-019) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGOCD-007`](../providers/argocd.md#argocd-007) | Argo CD Helm parameters interpolate generator output without goTemplate | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo CD](../providers/argocd.md) |  |
| [`BB-002`](../providers/bitbucket.md#bb-002) | Script injection via attacker-controllable context | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-018`](../providers/bitbucket.md#bb-018) | Cache key derives from attacker-controllable input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-026`](../providers/bitbucket.md#bb-026) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-035`](../providers/bitbucket.md#bb-035) | ML model loaded with trust_remote_code (code execution) | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-036`](../providers/bitbucket.md#bb-036) | Untrusted PR/branch context reaches an agentic AI CLI (prompt injection) | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-037`](../providers/bitbucket.md#bb-037) | Unsafe deserialization of a fetched artifact (pickle RCE) | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-003`](../providers/buildkite.md#bk-003) | Untrusted Buildkite variable interpolated in command | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-015`](../providers/buildkite.md#bk-015) | agents map interpolates attacker-controllable Buildkite variable | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-016`](../providers/buildkite.md#bk-016) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CC-002`](../providers/circleci.md#cc-002) | Script injection via untrusted environment variable | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-025`](../providers/circleci.md#cc-025) | Cache key derives from attacker-controllable input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-027`](../providers/circleci.md#cc-027) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-034`](../providers/circleci.md#cc-034) | ML model loaded with trust_remote_code (code execution) | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-036`](../providers/circleci.md#cc-036) | Unsafe deserialization of a fetched artifact (pickle RCE) | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-037`](../providers/circleci.md#cc-037) | Untrusted PR/build context reaches an agentic AI CLI (prompt injection) | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`DF-005`](../providers/dockerfile.md#df-005) | RUN uses shell-eval (eval / sh -c on a variable / backticks) | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DR-003`](../providers/drone.md#dr-003) | Untrusted Drone template variable in shell command | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-009`](../providers/drone.md#dr-009) | Cache plugin key embeds an attacker-controllable Drone variable | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-011`](../providers/drone.md#dr-011) | node map interpolates attacker-controllable Drone variable | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-017`](../providers/drone.md#dr-017) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`GCB-006`](../providers/cloudbuild.md#gcb-006) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-019`](../providers/cloudbuild.md#gcb-019) | Shell entrypoint inlines a user substitution into args | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-022`](../providers/cloudbuild.md#gcb-022) | options.substitutionOption set to ALLOW_LOOSE | <span class="pg-sev pg-sev--low">LOW</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCB-023`](../providers/cloudbuild.md#gcb-023) | Step references a user substitution not declared in substitutions: | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-002`](../providers/github.md#gha-002) | pull_request_target checks out PR head | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-003`](../providers/github.md#gha-003) | Script injection via untrusted context | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-011`](../providers/github.md#gha-011) | Cache key derives from attacker-controllable input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-027`](../providers/github.md#gha-027) | Workflow contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-028`](../providers/github.md#gha-028) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-031`](../providers/github.md#gha-031) | Workflow uses retired set-output / save-state command | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-035`](../providers/github.md#gha-035) | github-script step interpolates untrusted context | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-036`](../providers/github.md#gha-036) | runs-on interpolates untrusted context | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-038`](../providers/github.md#gha-038) | Workflow re-enables retired ::set-env / ::add-path commands | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-052`](../providers/github.md#gha-052) | actions/cache key includes untrusted PR-controllable input | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-053`](../providers/github.md#gha-053) | if: predicate evaluates attacker-controllable context as expression | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-063`](../providers/github.md#gha-063) | ``if:`` predicate gates on a spoofable bot-actor comparison | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-064`](../providers/github.md#gha-064) | ``contains()`` invoked with comma-delimited string operand | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-117`](../providers/github.md#gha-117) | IaC apply on an untrusted pull_request trigger | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-118`](../providers/github.md#gha-118) | Untrusted content written to $GITHUB_ENV / $GITHUB_PATH | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-119`](../providers/github.md#gha-119) | Untrusted context reaches an agentic AI CLI (prompt injection) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-120`](../providers/github.md#gha-120) | ML model loaded with trust_remote_code (code execution) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-122`](../providers/github.md#gha-122) | Unsafe deserialization of a fetched artifact (pickle RCE) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-002`](../providers/gitlab.md#gl-002) | Script injection via untrusted commit/MR context | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-012`](../providers/gitlab.md#gl-012) | Cache key derives from MR-controlled CI variable | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-026`](../providers/gitlab.md#gl-026) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-032`](../providers/gitlab.md#gl-032) | tags: interpolates untrusted CI variable | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-033`](../providers/gitlab.md#gl-033) | Global before_script / after_script propagates taint to every job | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-041`](../providers/gitlab.md#gl-041) | IaC apply on an untrusted merge-request trigger | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-045`](../providers/gitlab.md#gl-045) | ML model loaded with trust_remote_code (code execution) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-047`](../providers/gitlab.md#gl-047) | Unsafe deserialization of a fetched artifact (pickle RCE) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-048`](../providers/gitlab.md#gl-048) | Untrusted MR/commit context reaches an agentic AI CLI (prompt injection) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`HARNESS-002`](../providers/harness.md#harness-002) | Untrusted Harness expression interpolated into a step command | <span class="pg-sev pg-sev--high">HIGH</span> | [Harness CI/CD](../providers/harness.md) |  |
| [`HARNESS-008`](../providers/harness.md#harness-008) | Untrusted context reaches an agentic AI CLI (prompt injection) | <span class="pg-sev pg-sev--high">HIGH</span> | [Harness CI/CD](../providers/harness.md) |  |
| [`HARNESS-010`](../providers/harness.md#harness-010) | ML model loaded with trust_remote_code (code execution) | <span class="pg-sev pg-sev--high">HIGH</span> | [Harness CI/CD](../providers/harness.md) |  |
| [`HARNESS-011`](../providers/harness.md#harness-011) | Unsafe deserialization of a fetched artifact (pickle RCE) | <span class="pg-sev pg-sev--high">HIGH</span> | [Harness CI/CD](../providers/harness.md) |  |
| [`HARNESS-014`](../providers/harness.md#harness-014) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [Harness CI/CD](../providers/harness.md) |  |
| [`JF-002`](../providers/jenkins.md#jf-002) | Script step interpolates attacker-controllable env var | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-030`](../providers/jenkins.md#jf-030) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-032`](../providers/jenkins.md#jf-032) | Agent label interpolates attacker-controllable value | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-037`](../providers/jenkins.md#jf-037) | Untrusted PR/build context reaches an agentic AI CLI (prompt injection) | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-039`](../providers/jenkins.md#jf-039) | ML model loaded with trust_remote_code (code execution) | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-041`](../providers/jenkins.md#jf-041) | Unsafe deserialization of a fetched artifact (pickle RCE) | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`TAINT-001`](../providers/github.md#taint-001) | Untrusted input flows across step boundaries via step outputs | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`TAINT-002`](../providers/github.md#taint-002) | Untrusted input flows across jobs via ``jobs.<id>.outputs:`` | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`TAINT-003`](../providers/github.md#taint-003) | Untrusted input forwarded into reusable workflow ``with:`` | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`TAINT-004`](../providers/gitlab.md#taint-004) | Untrusted input flows across jobs via dotenv artifact | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`TAINT-005`](../providers/buildkite.md#taint-005) | Untrusted input flows across steps via ``buildkite-agent meta-data`` | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`TAINT-006`](../providers/tekton.md#taint-006) | Untrusted input flows across tasks via Tekton ``results`` | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |
| [`TAINT-007`](../providers/argo.md#taint-007) | Untrusted input flows across templates via Argo ``outputs.parameters`` | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`TAINT-008`](../providers/gitlab.md#taint-008) | Untrusted input flows via GitLab ``extends:`` template inheritance | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`TKN-003`](../providers/tekton.md#tkn-003) | Tekton param interpolated unsafely in step script | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-015`](../providers/tekton.md#tkn-015) | Workspace subPath interpolates a Task parameter (path traversal) | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-018`](../providers/tekton.md#tkn-018) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |

### EX-7: SQL injection { #ctrl-ex-7 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### EX-8: Cross-site scripting { #ctrl-ex-8 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### EX-9: Malicious artifact execution { #ctrl-ex-9 }

**Evidenced by 5 checks** across 5 providers (Azure DevOps, Bitbucket, GitHub Actions, GitLab CI, Jenkins).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-010`](../providers/azure.md#ado-010) | Cross-pipeline `download:` ingestion unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`BB-010`](../providers/bitbucket.md#bb-010) | Deploy step ingests pull-request artifact unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`GHA-009`](../providers/github.md#gha-009) | workflow_run downloads upstream artifact unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-010`](../providers/gitlab.md#gl-010) | Multi-project pipeline ingests upstream artifact unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-013`](../providers/jenkins.md#jf-013) | copyArtifacts ingests another job's output unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) |  |

### EX-10: Cloud workload { #ctrl-ex-10 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### EX-11: Auto merge rules in SCM { #ctrl-ex-11 }

**Evidenced by 2 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-021`](../providers/scm_github.md#scm-021) | Actions can approve pull requests (self-approval bypass) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-031`](../providers/scm_github.md#scm-031) | Repo allows auto-merge (no human-timing gate) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |

### EX-12: Trigger pipeline execution { #ctrl-ex-12 }

**Evidenced by 22 checks** across 7 providers (AWS, Argo CD, Azure DevOps, CircleCI, GitHub Actions, GitLab CI, Jenkins).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-019`](../providers/azure.md#ado-019) | `extends:` template on PR-validated pipeline points to local path | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGOCD-006`](../providers/argocd.md#argocd-006) | Argo CD ApplicationSet PR/SCM generator without project allowlist | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo CD](../providers/argocd.md) |  |
| [`CB-007`](../providers/aws.md#cb-007) | CodeBuild webhook has no filter group | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CB-008`](../providers/aws.md#cb-008) | CodeBuild buildspec is inline (not sourced from a protected repo) | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CB-010`](../providers/aws.md#cb-010) | CodeBuild webhook allows fork-PR builds without actor filtering | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CC-012`](../providers/circleci.md#cc-012) | Dynamic config via `setup: true` enables code injection | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CP-003`](../providers/aws.md#cp-003) | Source stage using polling instead of event-driven trigger | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`CP-007`](../providers/aws.md#cp-007) | CodePipeline v2 PR trigger accepts all branches | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GHA-010`](../providers/github.md#gha-010) | Local action (./path) on untrusted-trigger workflow | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-013`](../providers/github.md#gha-013) | issue_comment trigger without author guard | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-032`](../providers/github.md#gha-032) | run: invokes local script on untrusted-trigger workflow | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-044`](../providers/github.md#gha-044) | Build tool runs lifecycle scripts on untrusted-trigger workflow | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-045`](../providers/github.md#gha-045) | Caller-controlled ref input feeds actions/checkout | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-046`](../providers/github.md#gha-046) | Manual PR-head fetch on untrusted-trigger workflow | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-058`](../providers/github.md#gha-058) | Agentic CLI invoked with permission-bypass flags | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-071`](../providers/github.md#gha-071) | ``shell: pwsh`` / ``powershell`` on a Linux / macOS step | <span class="pg-sev pg-sev--low">LOW</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-102`](../providers/github.md#gha-102) | ``actions/checkout`` with submodule fetch on a PR trigger | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-103`](../providers/github.md#gha-103) | AI code-review bot on untrusted trigger without environment gate | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-104`](../providers/github.md#gha-104) | AI agent generates and pushes commits without PR review | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-011`](../providers/gitlab.md#gl-011) | include: local file pulled in MR-triggered pipeline | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-012`](../providers/jenkins.md#jf-012) | `load` step pulls Groovy from disk without integrity pin | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-019`](../providers/jenkins.md#jf-019) | Groovy sandbox escape pattern detected | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) |  |

### PER-1: Recursive PR { #ctrl-per-1 }

**Evidenced by 3 checks** across 2 providers (GitHub Actions, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GHA-048`](../providers/github.md#gha-048) | Workflow step writes a file under .github/workflows/ | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-097`](../providers/github.md#gha-097) | Recursive PR auto-merge loop | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`SCM-031`](../providers/scm_github.md#scm-031) | Repo allows auto-merge (no human-timing gate) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |

### PER-2: Deploy keys { #ctrl-per-2 }

**Evidenced by 1 check** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-025`](../providers/scm_github.md#scm-025) | Repo has write-enabled deploy keys (push backdoor) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |

### PER-3: Backdoor in code { #ctrl-per-3 }

**Evidenced by 4 checks** across GitHub Actions.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GHA-048`](../providers/github.md#gha-048) | Workflow step writes a file under .github/workflows/ | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-049`](../providers/github.md#gha-049) | Workflow step makes a privileged git write (cross-repo or actions[bot] bypass) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-056`](../providers/github.md#gha-056) | Workflow body contains a known supply-chain worm indicator | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-065`](../providers/github.md#gha-065) | Workflow body contains zero-width or bidi Unicode characters | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |

### PER-4: Add user { #ctrl-per-4 }

**Evidenced by 1 check** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-030`](../providers/scm_github.md#scm-030) | Repository ruleset has bypass actor with bypass_mode: always | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |

### PER-5: Untagged resources { #ctrl-per-5 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### PER-6: Scheduled task / job on self-hosted runner { #ctrl-per-6 }

**Evidenced by 8 checks** across 6 providers (Azure DevOps, Bitbucket, CircleCI, GitHub Actions, GitLab CI, Jenkins).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-013`](../providers/azure.md#ado-013) | Self-hosted pool without explicit ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`BB-016`](../providers/bitbucket.md#bb-016) | Self-hosted runner without ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`CC-010`](../providers/circleci.md#cc-010) | Self-hosted runner without ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`GHA-012`](../providers/github.md#gha-012) | Self-hosted runner without ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-105`](../providers/github.md#gha-105) | Self-hosted runner reachable from an untrusted PR trigger | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-112`](../providers/github.md#gha-112) | Self-hosted deploy job not gated by a protected environment | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-014`](../providers/gitlab.md#gl-014) | Self-managed runner without ephemeral tag | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-014`](../providers/jenkins.md#jf-014) | Agent label missing ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |

### PER-7: Implant in zombie instance { #ctrl-per-7 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### PER-8: Create access token { #ctrl-per-8 }

**Evidenced by 5 checks** across 2 providers (AWS, GitHub Actions).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CP-004`](../providers/aws.md#cp-004) | Legacy ThirdParty/GitHub source action (OAuth token) | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GHA-055`](../providers/github.md#gha-055) | Reusable workflow outputs derive a secret or caller-input value | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-061`](../providers/github.md#gha-061) | GitHub App token minted without a `permissions:` filter | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-106`](../providers/github.md#gha-106) | AI agent CLI runs with a write-scoped GITHUB_TOKEN | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-111`](../providers/github.md#gha-111) | AI agent generates IaC applied to the cloud in the same job | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |

### PE-1: Inject malicious dependency to privileged user repository { #ctrl-pe-1 }

**Evidenced by 7 checks** across 2 providers (Argo CD, GitHub Actions).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ARGOCD-006`](../providers/argocd.md#argocd-006) | Argo CD ApplicationSet PR/SCM generator without project allowlist | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo CD](../providers/argocd.md) |  |
| [`GHA-002`](../providers/github.md#gha-002) | pull_request_target checks out PR head | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-044`](../providers/github.md#gha-044) | Build tool runs lifecycle scripts on untrusted-trigger workflow | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-045`](../providers/github.md#gha-045) | Caller-controlled ref input feeds actions/checkout | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-046`](../providers/github.md#gha-046) | Manual PR-head fetch on untrusted-trigger workflow | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-092`](../providers/github.md#gha-092) | PR head SHA captured then re-fetched (force-push race) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-102`](../providers/github.md#gha-102) | ``actions/checkout`` with submodule fetch on a PR trigger | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |

### PE-2: Runners / agents running with high user privileges { #ctrl-pe-2 }

**Evidenced by 47 checks** across 15 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, Drone CI, GitHub Actions, GitLab CI, Harness CI/CD, Jenkins, Kubernetes, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-017`](../providers/azure.md#ado-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ARGO-002`](../providers/argo.md#argo-002) | Argo template container runs privileged or as root | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-004`](../providers/argo.md#argo-004) | Argo workflow mounts hostPath or shares host namespaces | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-013`](../providers/bitbucket.md#bb-013) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-005`](../providers/buildkite.md#bk-005) | Container started with --privileged or host-bind escalation | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CB-002`](../providers/aws.md#cb-002) | Privileged mode enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CC-014`](../providers/circleci.md#cc-014) | Job missing `resource_class` declaration | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-017`](../providers/circleci.md#cc-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-002`](../providers/dockerfile.md#df-002) | Container runs as root (missing or root USER directive) | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-008`](../providers/dockerfile.md#df-008) | RUN invokes docker --privileged or escalates capabilities | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-012`](../providers/dockerfile.md#df-012) | RUN invokes sudo | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-014`](../providers/dockerfile.md#df-014) | WORKDIR set to a system / kernel filesystem path | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-015`](../providers/dockerfile.md#df-015) | RUN grants world-writable permissions (chmod 777 / a+w) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-017`](../providers/dockerfile.md#df-017) | ENV PATH prepends a world-writable directory | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-018`](../providers/dockerfile.md#df-018) | RUN chown rewrites ownership of a system path | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DR-002`](../providers/drone.md#dr-002) | Step runs with privileged: true | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-007`](../providers/drone.md#dr-007) | Step mounts a sensitive host path | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`GCB-016`](../providers/cloudbuild.md#gcb-016) | Step dir field contains parent-directory escape (..) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-021`](../providers/cloudbuild.md#gcb-021) | No private worker pool, build runs on the shared default pool | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-017`](../providers/github.md#gha-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-026`](../providers/github.md#gha-026) | Container job disables isolation via `options:` | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-107`](../providers/github.md#gha-107) | harden-runner runs in audit mode (egress not blocked) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-108`](../providers/github.md#gha-108) | Sensitive workflow has no runtime egress control | <span class="pg-sev pg-sev--low">LOW</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-109`](../providers/github.md#gha-109) | harden-runner is not the first step in the job | <span class="pg-sev pg-sev--low">LOW</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-017`](../providers/gitlab.md#gl-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-039`](../providers/gitlab.md#gl-039) | Docker-in-Docker service exposes an unauthenticated daemon | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`HARNESS-003`](../providers/harness.md#harness-003) | Step runs with privileged: true | <span class="pg-sev pg-sev--high">HIGH</span> | [Harness CI/CD](../providers/harness.md) |  |
| [`HARNESS-007`](../providers/harness.md#harness-007) | Stage infrastructure mounts a sensitive host path | <span class="pg-sev pg-sev--high">HIGH</span> | [Harness CI/CD](../providers/harness.md) |  |
| [`JF-003`](../providers/jenkins.md#jf-003) | Pipeline uses `agent any` (no executor isolation) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-017`](../providers/jenkins.md#jf-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-025`](../providers/jenkins.md#jf-025) | Kubernetes agent pod template runs privileged or mounts hostPath | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`K8S-002`](../providers/kubernetes.md#k8s-002) | Pod hostNetwork: true | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-003`](../providers/kubernetes.md#k8s-003) | Pod hostPID: true | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-004`](../providers/kubernetes.md#k8s-004) | Pod hostIPC: true | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-005`](../providers/kubernetes.md#k8s-005) | Container securityContext.privileged: true | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-006`](../providers/kubernetes.md#k8s-006) | Container allowPrivilegeEscalation not explicitly false | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-007`](../providers/kubernetes.md#k8s-007) | Container runAsNonRoot not true / runAsUser is 0 | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-013`](../providers/kubernetes.md#k8s-013) | Pod uses a hostPath volume | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-014`](../providers/kubernetes.md#k8s-014) | Pod hostPath references a sensitive host directory | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-028`](../providers/kubernetes.md#k8s-028) | Container declares hostPort | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-030`](../providers/kubernetes.md#k8s-030) | Workload schedules onto a control-plane node | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-035`](../providers/kubernetes.md#k8s-035) | Container securityContext.runAsUser is 0 | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-039`](../providers/kubernetes.md#k8s-039) | Pod uses shareProcessNamespace: true | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-040`](../providers/kubernetes.md#k8s-040) | Container securityContext.procMount: Unmasked | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`TKN-002`](../providers/tekton.md#tkn-002) | Tekton step runs privileged or as root | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-004`](../providers/tekton.md#tkn-004) | Tekton Task mounts hostPath or shares host namespaces | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-013`](../providers/tekton.md#tkn-013) | Tekton sidecar runs privileged or as root | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |

### DE-1: Bypass review using admin permission { #ctrl-de-1 }

**Evidenced by 41 checks** across 10 providers (AWS, Azure DevOps, Bitbucket, Buildkite, CircleCI, GitHub Actions, GitLab CI, Harness CI/CD, Jenkins, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-004`](../providers/azure.md#ado-004) | Deployment job missing environment binding | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-038`](../providers/azure.md#ado-038) | Agentic CLI output lands without human review | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`BB-004`](../providers/bitbucket.md#bb-004) | Deploy step missing `deployment:` environment gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-039`](../providers/bitbucket.md#bb-039) | Agentic CLI output lands without human review | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-007`](../providers/buildkite.md#bk-007) | Deploy step not gated by a manual block / input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-013`](../providers/buildkite.md#bk-013) | Deploy step has no branches: filter | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CC-009`](../providers/circleci.md#cc-009) | Deploy job missing manual approval gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-013`](../providers/circleci.md#cc-013) | Deploy job in workflow has no branch filter | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-030`](../providers/circleci.md#cc-030) | Workflow job uses context without branch filter or approval gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-038`](../providers/circleci.md#cc-038) | Agentic CLI output lands without human review | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CCM-001`](../providers/aws.md#ccm-001) | CodeCommit repository has no approval rule template attached | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CD-001`](../providers/aws.md#cd-001) | Automatic rollback on failure not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CD-002`](../providers/aws.md#cd-002) | AllAtOnce deployment config, no canary or rolling strategy | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CP-001`](../providers/aws.md#cp-001) | No approval action before deploy stages | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CP-005`](../providers/aws.md#cp-005) | Production Deploy stage has no preceding ManualApproval | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`GHA-014`](../providers/github.md#gha-014) | Deploy job missing environment binding | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-086`](../providers/github.md#gha-086) | Wildcard branch trigger gates an environment-bound deploy | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-112`](../providers/github.md#gha-112) | Self-hosted deploy job not gated by a protected environment | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-123`](../providers/github.md#gha-123) | Agentic CLI output lands without human review | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-004`](../providers/gitlab.md#gl-004) | Deploy job lacks manual approval or environment gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-029`](../providers/gitlab.md#gl-029) | Manual deploy job defaults to allow_failure: true | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-049`](../providers/gitlab.md#gl-049) | Agentic CLI output lands without human review | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`HARNESS-009`](../providers/harness.md#harness-009) | Agentic CLI output lands without human review | <span class="pg-sev pg-sev--high">HIGH</span> | [Harness CI/CD](../providers/harness.md) |  |
| [`JF-005`](../providers/jenkins.md#jf-005) | Deploy stage missing manual `input` approval | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-024`](../providers/jenkins.md#jf-024) | `input` approval step missing submitter restriction | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-026`](../providers/jenkins.md#jf-026) | `build job:` trigger ignores downstream failure | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-038`](../providers/jenkins.md#jf-038) | Agentic CLI output lands without human review | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`SCM-002`](../providers/scm_github.md#scm-002) | Default branch protection does not require pull request reviews | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-010`](../providers/scm_github.md#scm-010) | Branch protection allows administrators to bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-011`](../providers/scm_github.md#scm-011) | Default branch protection does not require CODEOWNERS reviews | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-013`](../providers/scm_github.md#scm-013) | Default branch protection does not require conversation resolution | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-014`](../providers/scm_github.md#scm-014) | Default branch protection does not require approval of the most recent push | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-018`](../providers/scm_github.md#scm-018) | Required PR reviews can be bypassed by named identities | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-019`](../providers/scm_github.md#scm-019) | Push restrictions allowlist names individual users | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-023`](../providers/scm_github.md#scm-023) | Deployment environment lacks required-reviewer protection | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-024`](../providers/scm_github.md#scm-024) | Deployment environment can deploy from any branch | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-028`](../providers/scm_github.md#scm-028) | Private repo allows forking | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-029`](../providers/scm_github.md#scm-029) | Repository ruleset is in evaluate / disabled mode (not enforced) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-030`](../providers/scm_github.md#scm-030) | Repository ruleset has bypass actor with bypass_mode: always | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-032`](../providers/scm_github.md#scm-032) | Active ruleset doesn't require a PR review (governance theater) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-044`](../providers/scm_github.md#scm-044) | Default-branch signed-commits requirement bypassed for admins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |

### DE-2: SaaS sprawl { #ctrl-de-2 }

**Evidenced by 1 check** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-022`](../providers/scm_github.md#scm-022) | Repo Actions permissions allow any source (no allow-list) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |

### DE-3: Misconfigured audit log settings { #ctrl-de-3 }

**Evidenced by 33 checks** across 7 providers (AWS, CircleCI, Cloud Build, Dockerfile, GitHub Actions, Jenkins, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CA-000`](../providers/aws.md) | CodeArtifact API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`CB-000`](../providers/aws.md) | CodeBuild API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`CB-003`](../providers/aws.md#cb-003) | Build logging not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CC-011`](../providers/circleci.md#cc-011) | No store_test_results step (test results not archived) | <span class="pg-sev pg-sev--low">LOW</span> | [CircleCI](../providers/circleci.md) |  |
| [`CCM-000`](../providers/aws.md) | CodeCommit API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`CD-000`](../providers/aws.md) | CodeDeploy API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`CD-003`](../providers/aws.md#cd-003) | No CloudWatch alarm monitoring on deployment group | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CP-000`](../providers/aws.md) | CodePipeline API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`CT-000`](../providers/aws.md) | CloudTrail API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`CT-001`](../providers/aws.md#ct-001) | No active CloudTrail trail in region | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CT-002`](../providers/aws.md#ct-002) | CloudTrail log-file validation disabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CT-003`](../providers/aws.md#ct-003) | CloudTrail trail is not multi-region | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CWL-000`](../providers/aws.md) | CloudWatch Logs API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`CWL-001`](../providers/aws.md#cwl-001) | CodeBuild log group has no retention policy | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`DF-007`](../providers/dockerfile.md#df-007) | No HEALTHCHECK directive declared | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`EB-000`](../providers/aws.md) | EventBridge API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`ECR-000`](../providers/aws.md) | ECR API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`GCB-014`](../providers/cloudbuild.md#gcb-014) | Build logging disabled (options.logging: NONE) | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCB-025`](../providers/cloudbuild.md#gcb-025) | Build has no tags for audit / discoverability | <span class="pg-sev pg-sev--low">LOW</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-087`](../providers/github.md#gha-087) | Derived value of a secret printed to the build log | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`IAM-000`](../providers/aws.md) | IAM API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`JF-011`](../providers/jenkins.md#jf-011) | Pipeline has no `buildDiscarder` retention policy | <span class="pg-sev pg-sev--low">LOW</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`KMS-000`](../providers/aws.md) | KMS API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`LMB-000`](../providers/aws.md) | Lambda API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`PBAC-000`](../providers/aws.md) | PBAC enumeration failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`S3-000`](../providers/aws.md) | S3 API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`S3-004`](../providers/aws.md#s3-004) | Artifact bucket access logging not enabled | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`SCM-003`](../providers/scm_github.md#scm-003) | GitHub default code scanning is not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-045`](../providers/scm_github.md#scm-045) | Default code scanning uses the limited query suite | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-046`](../providers/scm_github.md#scm-046) | Default code scanning has no periodic scan schedule | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-047`](../providers/scm_github.md#scm-047) | Repo language excluded from default code-scanning coverage | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SM-000`](../providers/aws.md) | Secrets Manager API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |
| [`SSM-000`](../providers/aws.md) | SSM Parameter Store API access failed | <span class="pg-sev pg-sev--info">INFO</span> | [AWS](../providers/aws.md) |  |

### DE-4: Misconfiguration of security measures { #ctrl-de-4 }

**Evidenced by 92 checks** across 19 providers (AWS, Argo CD, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, Drone CI, GitHub Actions, GitLab CI, Harness CI/CD, Helm, Jenkins, Kubernetes, OCI manifest, SCM, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-006`](../providers/azure.md#ado-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-007`](../providers/azure.md#ado-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-024`](../providers/azure.md#ado-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-009`](../providers/argo.md#argo-009) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-010`](../providers/argo.md#argo-010) | No SBOM generated for build artifacts | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-011`](../providers/argo.md#argo-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGOCD-003`](../providers/argocd.md#argocd-003) | Argo CD Application auto-sync prunes without selfHeal guardrail | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo CD](../providers/argocd.md) |  |
| [`ATTEST-001`](../providers/oci.md#attest-001) | SLSA provenance attests an untrusted builder identity | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`ATTEST-002`](../providers/oci.md#attest-002) | SLSA provenance source-repo claim is missing or unverifiable | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`ATTEST-003`](../providers/oci.md#attest-003) | SBOM contains floating-version dependencies | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [OCI manifest](../providers/oci.md) |  |
| [`ATTEST-004`](../providers/oci.md#attest-004) | SLSA provenance ships without a resolved-dependencies set | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [OCI manifest](../providers/oci.md) |  |
| [`ATTEST-005`](../providers/oci.md#attest-005) | In-toto Statement subject is missing or unpinned | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`ATTEST-006`](../providers/oci.md#attest-006) | SLSA provenance lacks a meaningful buildType | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [OCI manifest](../providers/oci.md) |  |
| [`ATTEST-007`](../providers/oci.md#attest-007) | SBOM packages lack supplier / originator attribution | <span class="pg-sev pg-sev--low">LOW</span> | [OCI manifest](../providers/oci.md) |  |
| [`BB-006`](../providers/bitbucket.md#bb-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-007`](../providers/bitbucket.md#bb-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-024`](../providers/bitbucket.md#bb-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-009`](../providers/buildkite.md#bk-009) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-010`](../providers/buildkite.md#bk-010) | No SBOM generated for build artifacts | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-011`](../providers/buildkite.md#bk-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CC-006`](../providers/circleci.md#cc-006) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-007`](../providers/circleci.md#cc-007) | SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-024`](../providers/circleci.md#cc-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CCM-002`](../providers/aws.md#ccm-002) | CodeCommit repository not encrypted with customer KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`DF-011`](../providers/dockerfile.md#df-011) | Package manager install without cache cleanup in same layer | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-016`](../providers/dockerfile.md#df-016) | Image lacks OCI provenance labels | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DR-019`](../providers/drone.md#dr-019) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-020`](../providers/drone.md#dr-020) | No SBOM produced (no syft / cyclonedx step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-021`](../providers/drone.md#dr-021) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Drone CI](../providers/drone.md) |  |
| [`ECR-004`](../providers/aws.md#ecr-004) | No lifecycle policy configured | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`GCB-009`](../providers/cloudbuild.md#gcb-009) | Artifacts not signed (no cosign / sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-015`](../providers/cloudbuild.md#gcb-015) | SBOM not produced (no CycloneDX / syft / Trivy-SBOM step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-017`](../providers/cloudbuild.md#gcb-017) | Image-producing build does not request SLSA provenance | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-024`](../providers/cloudbuild.md#gcb-024) | Build pushes Docker images but top-level images: is empty | <span class="pg-sev pg-sev--low">LOW</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-026`](../providers/cloudbuild.md#gcb-026) | Step waitFor: references an unknown step id | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-006`](../providers/github.md#gha-006) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-007`](../providers/github.md#gha-007) | SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-024`](../providers/github.md#gha-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-038`](../providers/github.md#gha-038) | Workflow re-enables retired ::set-env / ::add-path commands | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-098`](../providers/github.md#gha-098) | Pipeline deploys without a security scan gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-100`](../providers/github.md#gha-100) | ``cosign verify`` without certificate identity binding | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-006`](../providers/gitlab.md#gl-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-007`](../providers/gitlab.md#gl-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-024`](../providers/gitlab.md#gl-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`HARNESS-015`](../providers/harness.md#harness-015) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Harness CI/CD](../providers/harness.md) |  |
| [`HARNESS-016`](../providers/harness.md#harness-016) | No SBOM produced (no syft / cyclonedx step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Harness CI/CD](../providers/harness.md) |  |
| [`HARNESS-017`](../providers/harness.md#harness-017) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Harness CI/CD](../providers/harness.md) |  |
| [`HELM-002`](../providers/helm.md#helm-002) | Chart.lock missing per-dependency digests | <span class="pg-sev pg-sev--high">HIGH</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-005`](../providers/helm.md#helm-005) | Chart maintainers field empty or missing chain-of-custody info | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`HELM-006`](../providers/helm.md#helm-006) | Chart.yaml does not declare a kubeVersion compatibility range | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`HELM-007`](../providers/helm.md#helm-007) | Chart.yaml description field is empty or missing | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`HELM-010`](../providers/helm.md#helm-010) | Chart.yaml appVersion field is empty or missing | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`JF-006`](../providers/jenkins.md#jf-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-007`](../providers/jenkins.md#jf-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-027`](../providers/jenkins.md#jf-027) | `archiveArtifacts` does not record a fingerprint | <span class="pg-sev pg-sev--low">LOW</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-028`](../providers/jenkins.md#jf-028) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`K8S-015`](../providers/kubernetes.md#k8s-015) | Container missing resources.limits.memory | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-016`](../providers/kubernetes.md#k8s-016) | Container missing resources.limits.cpu | <span class="pg-sev pg-sev--low">LOW</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-022`](../providers/kubernetes.md#k8s-022) | Service exposes SSH (port 22) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-023`](../providers/kubernetes.md#k8s-023) | Namespace missing Pod Security Admission enforcement label | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-031`](../providers/kubernetes.md#k8s-031) | Namespace missing PSA warn label | <span class="pg-sev pg-sev--low">LOW</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-044`](../providers/kubernetes.md#k8s-044) | Admission webhook fails open or mutates cluster-wide unscoped | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`LMB-001`](../providers/aws.md#lmb-001) | Lambda function has no code-signing config | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`OCI-001`](../providers/oci.md#oci-001) | Image manifest is missing OCI provenance annotations | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [OCI manifest](../providers/oci.md) |  |
| [`OCI-002`](../providers/oci.md#oci-002) | Image is missing a build attestation manifest | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`OCI-003`](../providers/oci.md#oci-003) | Image manifest is missing the ``image.created`` annotation | <span class="pg-sev pg-sev--low">LOW</span> | [OCI manifest](../providers/oci.md) |  |
| [`OCI-005`](../providers/oci.md#oci-005) | Image manifest is missing the ``image.licenses`` annotation | <span class="pg-sev pg-sev--low">LOW</span> | [OCI manifest](../providers/oci.md) |  |
| [`OCI-006`](../providers/oci.md#oci-006) | Image has an excessive layer count | <span class="pg-sev pg-sev--low">LOW</span> | [OCI manifest](../providers/oci.md) |  |
| [`OCI-007`](../providers/oci.md#oci-007) | Image manifest uses legacy schemaVersion 1 (no content addressing) | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`OCI-008`](../providers/oci.md#oci-008) | Manifest references digest using unsupported hash algorithm | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`OCI-009`](../providers/oci.md#oci-009) | Image manifest is missing OCI base-image annotations | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [OCI manifest](../providers/oci.md) |  |
| [`SCM-006`](../providers/scm_github.md#scm-006) | Default branch protection does not require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-007`](../providers/scm_github.md#scm-007) | Default branch protection allows force-pushes | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-008`](../providers/scm_github.md#scm-008) | Default branch protection does not require status checks | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-009`](../providers/scm_github.md#scm-009) | Default branch protection allows branch deletion | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-029`](../providers/scm_github.md#scm-029) | Repository ruleset is in evaluate / disabled mode (not enforced) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-033`](../providers/scm_github.md#scm-033) | Active ruleset doesn't require status checks | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-034`](../providers/scm_github.md#scm-034) | Active ruleset doesn't block force-push | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-035`](../providers/scm_github.md#scm-035) | Active ruleset doesn't block branch deletion | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-036`](../providers/scm_github.md#scm-036) | Active ruleset doesn't require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-037`](../providers/scm_github.md#scm-037) | Active ruleset's pull_request rule doesn't dismiss stale reviews | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-038`](../providers/scm_github.md#scm-038) | Active ruleset doesn't require linear history | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-039`](../providers/scm_github.md#scm-039) | Active ruleset doesn't pin a required workflow | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-040`](../providers/scm_github.md#scm-040) | Active ruleset doesn't gate on code scanning results | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-041`](../providers/scm_github.md#scm-041) | Active ruleset doesn't gate on a deployment environment | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-042`](../providers/scm_github.md#scm-042) | Active ruleset doesn't require merge queue | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-043`](../providers/scm_github.md#scm-043) | Tag-targeted ruleset doesn't require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SIGN-001`](../providers/aws.md#sign-001) | No AWS Signer profile defined for Lambda deploys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`SIGN-002`](../providers/aws.md#sign-002) | AWS Signer profile is revoked or inactive | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`TKN-009`](../providers/tekton.md#tkn-009) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-010`](../providers/tekton.md#tkn-010) | No SBOM generated for build artifacts | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-011`](../providers/tekton.md#tkn-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### DE-5: Malicious compiler / interpreter { #ctrl-de-5 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### DE-6: Misconfigured traffic log settings { #ctrl-de-6 }

**Evidenced by 2 checks** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CW-001`](../providers/aws.md#cw-001) | No CloudWatch alarm on CodeBuild FailedBuilds metric | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`EB-001`](../providers/aws.md#eb-001) | No EventBridge rule for CodePipeline failure notifications | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |

### CA-1: Passwords in application logs { #ctrl-ca-1 }

**Evidenced by 1 check** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-012`](../providers/kubernetes.md#k8s-012) | Pod automountServiceAccountToken not false | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |

### CA-2: Dumping credentials from files { #ctrl-ca-2 }

**Evidenced by 15 checks** across 6 providers (AWS, Argo CD, Cloud Build, CloudFormation, Jenkins, Terraform).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ARGOCD-005`](../providers/argocd.md#argocd-005) | Argo CD repository entry stores plaintext credentials | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo CD](../providers/argocd.md) |  |
| [`CB-001`](../providers/aws.md#cb-001) | Secrets in plaintext environment variables | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`CF-001`](../providers/cloudformation.md#cf-001) | Template declares AWS::IAM::AccessKey (long-lived credential) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CloudFormation](../providers/cloudformation.md) |  |
| [`CF-002`](../providers/cloudformation.md#cf-002) | Stateful data-store resource carries a plaintext secret | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CloudFormation](../providers/cloudformation.md) |  |
| [`GCB-003`](../providers/cloudbuild.md#gcb-003) | Secret Manager value referenced in step args | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-018`](../providers/cloudbuild.md#gcb-018) | Legacy KMS secrets block in use (prefer availableSecrets / Secret Manager) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`JF-033`](../providers/jenkins.md#jf-033) | withCredentials secret leaked via Groovy ${...} interpolation in sh step | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-034`](../providers/jenkins.md#jf-034) | Pipeline declares a password() build parameter | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`KMS-001`](../providers/aws.md#kms-001) | KMS customer-managed key has rotation disabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`SM-001`](../providers/aws.md#sm-001) | Secrets Manager secret has no rotation configured | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`SM-002`](../providers/aws.md#sm-002) | Secrets Manager resource policy allows wildcard principal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`SSM-001`](../providers/aws.md#ssm-001) | SSM Parameter with secret-like name is not a SecureString | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`SSM-002`](../providers/aws.md#ssm-002) | SSM SecureString uses the default AWS-managed key | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`TF-001`](../providers/terraform.md#tf-001) | Plan declares aws_iam_access_key (long-lived credential) | <span class="pg-sev pg-sev--high">HIGH</span> | [Terraform](../providers/terraform.md) |  |
| [`TF-002`](../providers/terraform.md#tf-002) | Stateful data-store resource carries a plaintext secret | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Terraform](../providers/terraform.md) |  |

### CA-3: Harvest secrets from logs { #ctrl-ca-3 }

**Evidenced by 2 checks** across GitHub Actions.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GHA-057`](../providers/github.md#gha-057) | Secret-scanner output sent to network egress | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-093`](../providers/github.md#gha-093) | Living-off-the-Pipeline indicators (workflow-command abuse) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |

### CA-4: Dumping short-lived token { #ctrl-ca-4 }

**Evidenced by 2 checks** across GitHub Actions.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GHA-069`](../providers/github.md#gha-069) | ``id-token: write`` granted without an OIDC-consumer step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-115`](../providers/github.md#gha-115) | ``id-token: write`` granted workflow-wide instead of job-scoped | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |

### CA-5: Dump tokens from environment variable { #ctrl-ca-5 }

**Evidenced by 25 checks** across 13 providers (Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Drone CI, GitHub Actions, GitLab CI, Harness CI/CD, Jenkins, SCM, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-031`](../providers/azure.md#ado-031) | Secret variable echoed / printed in a script step | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-032`](../providers/azure.md#ado-032) | checkout persistCredentials leaves the pipeline token in .git/config | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-018`](../providers/argo.md#argo-018) | Secret-named variable echoed / printed in a template script | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-017`](../providers/bitbucket.md#bb-017) | Repository token written to persistent storage | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-019`](../providers/bitbucket.md#bb-019) | after-script references secrets | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-032`](../providers/bitbucket.md#bb-032) | Secret-named variable echoed / printed in a script block | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-017`](../providers/buildkite.md#bk-017) | Secret-named variable echoed / printed in a step command | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CC-032`](../providers/circleci.md#cc-032) | Secret-named variable echoed / printed in a run step | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`DR-018`](../providers/drone.md#dr-018) | Secret-named variable echoed / printed in a step command | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`GCB-028`](../providers/cloudbuild.md#gcb-028) | Secret-named variable echoed / printed in a build step | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-019`](../providers/github.md#gha-019) | GITHUB_TOKEN written to persistent storage | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-033`](../providers/github.md#gha-033) | Secret value echoed / printed in a run: block | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-037`](../providers/github.md#gha-037) | actions/checkout persists GITHUB_TOKEN into .git/config | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-054`](../providers/github.md#gha-054) | actions/checkout with ssh-key persists SSH credential in repo | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-055`](../providers/github.md#gha-055) | Reusable workflow outputs derive a secret or caller-input value | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-072`](../providers/github.md#gha-072) | Secret in env: at a wider scope than its consumer | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-073`](../providers/github.md#gha-073) | Reusable workflow declares an unused ``workflow_call`` secret | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-020`](../providers/gitlab.md#gl-020) | CI_JOB_TOKEN written to persistent storage | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-036`](../providers/gitlab.md#gl-036) | Secret-named variable echoed / printed in a script block | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-038`](../providers/gitlab.md#gl-038) | CI_DEBUG_TRACE / debug logging dumps secrets to the job log | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`HARNESS-013`](../providers/harness.md#harness-013) | Secret-named variable echoed / printed in a step command | <span class="pg-sev pg-sev--high">HIGH</span> | [Harness CI/CD](../providers/harness.md) |  |
| [`JF-042`](../providers/jenkins.md#jf-042) | Secret-named variable echoed / printed in a build step | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`SCM-048`](../providers/scm_github.md#scm-048) | Org codespace secret scoped to all repos | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`TAINT-009`](../providers/github.md#taint-009) | Environment-protected secret flows to unprotected job | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`TKN-017`](../providers/tekton.md#tkn-017) | Secret-named variable echoed / printed in a step script | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |

### CA-6: Passwords in CI/CD logs { #ctrl-ca-6 }

**Evidenced by 42 checks** across 14 providers (Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Developer environment, Drone CI, GitHub Actions, GitLab CI, Harness CI/CD, Jenkins, SCM, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-003`](../providers/azure.md#ado-003) | Variables contain literal secret values | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-008`](../providers/azure.md#ado-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-031`](../providers/azure.md#ado-031) | Secret variable echoed / printed in a script step | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-032`](../providers/azure.md#ado-032) | checkout persistCredentials leaves the pipeline token in .git/config | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-006`](../providers/argo.md#argo-006) | Literal secret value in Argo template env or parameter default | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo Workflows](../providers/argo.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ARGO-018`](../providers/argo.md#argo-018) | Secret-named variable echoed / printed in a template script | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-003`](../providers/bitbucket.md#bb-003) | Variables contain literal secret values | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-008`](../providers/bitbucket.md#bb-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-032`](../providers/bitbucket.md#bb-032) | Secret-named variable echoed / printed in a script block | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-002`](../providers/buildkite.md#bk-002) | Literal secret value in pipeline env block | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-017`](../providers/buildkite.md#bk-017) | Secret-named variable echoed / printed in a step command | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CC-004`](../providers/circleci.md#cc-004) | Secret-like environment variable not managed via context | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-005`](../providers/circleci.md#cc-005) | AWS auth uses long-lived access keys in environment block | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-008`](../providers/circleci.md#cc-008) | Credential-shaped literal in config body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-032`](../providers/circleci.md#cc-032) | Secret-named variable echoed / printed in a run step | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`DEV-008`](../providers/devenv.md) | Credential-shaped literal in a developer-environment config | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Developer environment](../providers/devenv.md) |  |
| [`DR-004`](../providers/drone.md#dr-004) | Literal credential in step environment / settings | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-018`](../providers/drone.md#dr-018) | Secret-named variable echoed / printed in a step command | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`GCB-007`](../providers/cloudbuild.md#gcb-007) | availableSecrets references ``versions/latest`` | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCB-012`](../providers/cloudbuild.md#gcb-012) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCB-028`](../providers/cloudbuild.md#gcb-028) | Secret-named variable echoed / printed in a build step | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-008`](../providers/github.md#gha-008) | Credential-shaped literal in workflow body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-033`](../providers/github.md#gha-033) | Secret value echoed / printed in a run: block | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-039`](../providers/github.md#gha-039) | services / container credentials embedded as literal in workflow | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-066`](../providers/github.md#gha-066) | ``actions/upload-artifact`` path is a workspace wildcard | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-067`](../providers/github.md#gha-067) | ``actions/cache`` writes credential-shaped paths | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-087`](../providers/github.md#gha-087) | Derived value of a secret printed to the build log | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-093`](../providers/github.md#gha-093) | Living-off-the-Pipeline indicators (workflow-command abuse) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-099`](../providers/github.md#gha-099) | Deployment job has a secret-shaped plaintext env var | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-003`](../providers/gitlab.md#gl-003) | Variables contain literal secret values | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-008`](../providers/gitlab.md#gl-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-036`](../providers/gitlab.md#gl-036) | Secret-named variable echoed / printed in a script block | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-038`](../providers/gitlab.md#gl-038) | CI_DEBUG_TRACE / debug logging dumps secrets to the job log | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`HARNESS-004`](../providers/harness.md#harness-004) | Literal credential in a pipeline / stage variable | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Harness CI/CD](../providers/harness.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HARNESS-013`](../providers/harness.md#harness-013) | Secret-named variable echoed / printed in a step command | <span class="pg-sev pg-sev--high">HIGH</span> | [Harness CI/CD](../providers/harness.md) |  |
| [`JF-004`](../providers/jenkins.md#jf-004) | AWS auth uses long-lived access keys via withCredentials | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-008`](../providers/jenkins.md#jf-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-042`](../providers/jenkins.md#jf-042) | Secret-named variable echoed / printed in a build step | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`SCM-004`](../providers/scm_github.md#scm-004) | GitHub secret scanning is not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-015`](../providers/scm_github.md#scm-015) | Secret scanning push protection is not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`TKN-005`](../providers/tekton.md#tkn-005) | Literal secret value in Tekton step env or param default | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Tekton](../providers/tekton.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`TKN-017`](../providers/tekton.md#tkn-017) | Secret-named variable echoed / printed in a step script | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |

### CA-7: Runtime leakage of password { #ctrl-ca-7 }

_No checks in this scanner currently evidence this control. Open an issue if your team would value coverage._

### CA-8: Steal credentials in container artifacts { #ctrl-ca-8 }

**Evidenced by 12 checks** across 4 providers (Dockerfile, Kubernetes, NuGet, npm).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`DF-006`](../providers/dockerfile.md#df-006) | ENV or ARG carries a credential-shaped literal value | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-019`](../providers/dockerfile.md#df-019) | COPY/ADD source path looks like a credential file | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-020`](../providers/dockerfile.md#df-020) | ARG declares a credential-named build argument | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-023`](../providers/dockerfile.md#df-023) | ENV sets a dynamic-loader hijack variable | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-025`](../providers/dockerfile.md#df-025) | RUN writes a registry auth token into a Docker layer | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-030`](../providers/dockerfile.md#df-030) | ENV NODE_OPTIONS preloads code or opens an inspector | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`K8S-017`](../providers/kubernetes.md#k8s-017) | Container env value carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-018`](../providers/kubernetes.md#k8s-018) | Secret stringData/data carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-037`](../providers/kubernetes.md#k8s-037) | ConfigMap data carries a credential-shaped literal | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`NPM-011`](../providers/npm.md#npm-011) | package.json files field includes secret-shaped paths | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NPM-013`](../providers/npm.md#npm-013) | package.json files field uses an overly broad pattern | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NUGET-010`](../providers/nuget.md#nuget-010) | NuGet.config stores a feed credential in plaintext | <span class="pg-sev pg-sev--high">HIGH</span> | [NuGet](../providers/nuget.md) |  |

### LM-1: Push implants across repositories { #ctrl-lm-1 }

**Evidenced by 1 check** across GitHub Actions.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GHA-049`](../providers/github.md#gha-049) | Workflow step makes a privileged git write (cross-repo or actions[bot] bypass) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |

### LM-2: Overprivileged user account { #ctrl-lm-2 }

**Evidenced by 34 checks** across 8 providers (AWS, Argo CD, Argo Workflows, Cloud Build, GitHub Actions, Kubernetes, SCM, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ARGO-003`](../providers/argo.md#argo-003) | Argo workflow uses the default ServiceAccount | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-013`](../providers/argo.md#argo-013) | Argo workflow does not opt out of SA token automount | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-016`](../providers/argo.md#argo-016) | Workflow bound to a cluster-admin / over-privileged ServiceAccount | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGOCD-001`](../providers/argocd.md#argocd-001) | Argo CD AppProject permits any source repository | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo CD](../providers/argocd.md) |  |
| [`ARGOCD-002`](../providers/argocd.md#argocd-002) | Argo CD AppProject permits any destination cluster or namespace | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo CD](../providers/argocd.md) |  |
| [`ARGOCD-004`](../providers/argocd.md#argocd-004) | Argo CD RBAC policy grants wildcard authority | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo CD](../providers/argocd.md) |  |
| [`ARGOCD-009`](../providers/argocd.md#argocd-009) | Argo CD anonymous access enabled | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo CD](../providers/argocd.md) |  |
| [`ARGOCD-011`](../providers/argocd.md#argocd-011) | Argo CD AppProject cluster-resource whitelist is wide open | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo CD](../providers/argocd.md) |  |
| [`ARGOCD-014`](../providers/argocd.md#argocd-014) | Argo CD web terminal enabled via exec.enabled | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo CD](../providers/argocd.md) |  |
| [`CA-004`](../providers/aws.md#ca-004) | CodeArtifact repo policy grants ``codeartifact:*`` with ``Resource '*'`` | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CB-002`](../providers/aws.md#cb-002) | Privileged mode enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GCB-002`](../providers/cloudbuild.md#gcb-002) | Cloud Build uses the default service account | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-004`](../providers/github.md#gha-004) | Workflow permissions block missing or overprovisioned | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-061`](../providers/github.md#gha-061) | GitHub App token minted without a `permissions:` filter | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-106`](../providers/github.md#gha-106) | AI agent CLI runs with a write-scoped GITHUB_TOKEN | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-111`](../providers/github.md#gha-111) | AI agent generates IaC applied to the cloud in the same job | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`IAM-001`](../providers/aws.md#iam-001) | CI/CD role has AdministratorAccess policy attached | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`IAM-002`](../providers/aws.md#iam-002) | CI/CD role has wildcard Action in attached policy | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-004`](../providers/aws.md#iam-004) | CI/CD role can PassRole to any role | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-006`](../providers/aws.md#iam-006) | Sensitive actions granted with wildcard Resource | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`K8S-011`](../providers/kubernetes.md#k8s-011) | Pod serviceAccountName unset or 'default' | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-019`](../providers/kubernetes.md#k8s-019) | Workload deployed in the 'default' namespace | <span class="pg-sev pg-sev--low">LOW</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-020`](../providers/kubernetes.md#k8s-020) | ClusterRoleBinding grants cluster-admin or system:masters | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-021`](../providers/kubernetes.md#k8s-021) | Role or ClusterRole grants wildcard verbs+resources | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-025`](../providers/kubernetes.md#k8s-025) | System priority class used outside kube-system | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-029`](../providers/kubernetes.md#k8s-029) | RoleBinding grants permissions to the default ServiceAccount | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-034`](../providers/kubernetes.md#k8s-034) | ServiceAccount automountServiceAccountToken not explicitly false | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-042`](../providers/kubernetes.md#k8s-042) | RoleBinding grants access to system:anonymous / system:unauthenticated | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`PBAC-002`](../providers/aws.md#pbac-002) | CodeBuild service role shared across multiple projects | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`PBAC-003`](../providers/aws.md#pbac-003) | CodeBuild security group allows 0.0.0.0/0 all-port egress | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`PBAC-005`](../providers/aws.md#pbac-005) | CodePipeline stage action roles mirror the pipeline role | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`SCM-020`](../providers/scm_github.md#scm-020) | Default workflow GITHUB_TOKEN has write permission | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-027`](../providers/scm_github.md#scm-027) | Outside collaborator holds write / maintain / admin access | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`TKN-007`](../providers/tekton.md#tkn-007) | Tekton run uses the default ServiceAccount | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### COL-1: Unencrypted data in transit { #ctrl-col-1 }

**Evidenced by 29 checks** across 20 providers (Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, Drone CI, GitHub Actions, GitLab CI, Harness CI/CD, Helm, Jenkins, Kubernetes, NuGet, OCI manifest, PyPI, Tekton, maven, npm).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-023`](../providers/azure.md#ado-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ARGO-008`](../providers/argo.md#argo-008) | Argo script source pipes remote install or disables TLS | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ARGO-015`](../providers/argo.md#argo-015) | Input artifact pulls from an insecure (non-HTTPS) URL | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-023`](../providers/bitbucket.md#bb-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-008`](../providers/buildkite.md#bk-008) | TLS verification disabled in step command | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-023`](../providers/circleci.md#cc-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-021`](../providers/dockerfile.md#df-021) | RUN pip install bypasses TLS or uses an HTTP index | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-026`](../providers/dockerfile.md#df-026) | ENV disables Node.js TLS certificate verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-027`](../providers/dockerfile.md#df-027) | ENV disables Python HTTPS certificate verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-028`](../providers/dockerfile.md#df-028) | ENV disables Git TLS certificate verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-029`](../providers/dockerfile.md#df-029) | ENV neuters Python requests CA bundle | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DR-006`](../providers/drone.md#dr-006) | TLS verification disabled in step commands | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCB-011`](../providers/cloudbuild.md#gcb-011) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-023`](../providers/github.md#gha-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-070`](../providers/github.md#gha-070) | ``ssh-keyscan`` / disabled host-key check trust-on-first-use | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-023`](../providers/gitlab.md#gl-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HARNESS-006`](../providers/harness.md#harness-006) | TLS verification disabled in step commands | <span class="pg-sev pg-sev--high">HIGH</span> | [Harness CI/CD](../providers/harness.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-003`](../providers/helm.md#helm-003) | Chart dependency declared on a non-HTTPS repository | <span class="pg-sev pg-sev--high">HIGH</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-009`](../providers/helm.md#helm-009) | Chart home / sources URL uses a non-HTTPS scheme | <span class="pg-sev pg-sev--low">LOW</span> | [Helm](../providers/helm.md) |  |
| [`JF-023`](../providers/jenkins.md#jf-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-035`](../providers/jenkins.md#jf-035) | httpRequest step disables SSL verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`K8S-027`](../providers/kubernetes.md#k8s-027) | Ingress has no TLS configuration | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`MVN-003`](../providers/maven.md#mvn-003) | pom.xml declares a plaintext-HTTP Maven repository | <span class="pg-sev pg-sev--high">HIGH</span> | [maven](../providers/maven.md) |  |
| [`NPM-005`](../providers/npm.md#npm-005) | package.json git dependency uses a mutable ref | <span class="pg-sev pg-sev--high">HIGH</span> | [npm](../providers/npm.md) |  |
| [`NUGET-004`](../providers/nuget.md#nuget-004) | HTTP-only NuGet package source | <span class="pg-sev pg-sev--high">HIGH</span> | [NuGet](../providers/nuget.md) |  |
| [`OCI-004`](../providers/oci.md#oci-004) | Image layer references an arbitrary URL (foreign layer) | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`PYPI-003`](../providers/pypi.md#pypi-003) | requirements.txt uses an HTTP index or disables TLS verification | <span class="pg-sev pg-sev--high">HIGH</span> | [PyPI](../providers/pypi.md) |  |
| [`PYPI-018`](../providers/pypi.md#pypi-018) | requirements.txt forces source builds via --no-binary | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [PyPI](../providers/pypi.md) |  |
| [`TKN-008`](../providers/tekton.md#tkn-008) | Tekton step script pipes remote install or disables TLS | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### COL-2: Unencrypted data at rest { #ctrl-col-2 }

**Evidenced by 9 checks** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CA-001`](../providers/aws.md#ca-001) | CodeArtifact domain has no KMS encryptionKey configured | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CP-002`](../providers/aws.md#cp-002) | Artifact store not encrypted with customer-managed KMS key | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CWL-002`](../providers/aws.md#cwl-002) | CodeBuild log group not KMS-encrypted | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`ECR-005`](../providers/aws.md#ecr-005) | Repository encrypted with AES256 rather than KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`KMS-002`](../providers/aws.md#kms-002) | KMS key policy grants wildcard KMS actions | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`S3-001`](../providers/aws.md#s3-001) | Artifact bucket public access block not fully enabled | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`S3-002`](../providers/aws.md#s3-002) | Artifact bucket server-side encryption not configured | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`S3-003`](../providers/aws.md#s3-003) | Artifact bucket versioning not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`S3-005`](../providers/aws.md#s3-005) | Artifact bucket missing aws:SecureTransport deny | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |

### EXF-1: Bypass of outbound traffic control { #ctrl-exf-1 }

**Evidenced by 1 check** across GitHub Actions.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GHA-057`](../providers/github.md#gha-057) | Secret-scanner output sent to network egress | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |

### EXF-2: Source code { #ctrl-exf-2 }

**Evidenced by 2 checks** across GitHub Actions.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GHA-019`](../providers/github.md#gha-019) | GITHUB_TOKEN written to persistent storage | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-066`](../providers/github.md#gha-066) | ``actions/upload-artifact`` path is a workspace wildcard | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |

### EXF-3: Webhook { #ctrl-exf-3 }

**Evidenced by 1 check** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-026`](../providers/scm_github.md#scm-026) | Webhook ships events insecurely (HTTP / no-TLS / no-secret) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |

### IMP-1: Delete repositories for DoS { #ctrl-imp-1 }

**Evidenced by 2 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-007`](../providers/scm_github.md#scm-007) | Default branch protection allows force-pushes | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-009`](../providers/scm_github.md#scm-009) | Default branch protection allows branch deletion | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |

### IMP-2: Resource hijacking { #ctrl-imp-2 }

**Evidenced by 5 checks** across Kubernetes.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`K8S-008`](../providers/kubernetes.md#k8s-008) | Container readOnlyRootFilesystem not true | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-009`](../providers/kubernetes.md#k8s-009) | Container capabilities not dropping ALL / adding dangerous caps | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-010`](../providers/kubernetes.md#k8s-010) | Container seccompProfile not RuntimeDefault or Localhost | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-024`](../providers/kubernetes.md#k8s-024) | Container missing both livenessProbe and readinessProbe | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-033`](../providers/kubernetes.md#k8s-033) | Namespace lacks ResourceQuota or LimitRange | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Kubernetes](../providers/kubernetes.md) |  |

### IMP-3: Misconfiguration of serverless workloads { #ctrl-imp-3 }

**Evidenced by 4 checks** across AWS.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`LMB-001`](../providers/aws.md#lmb-001) | Lambda function has no code-signing config | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`LMB-002`](../providers/aws.md#lmb-002) | Lambda function URL has AuthType=NONE | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`LMB-003`](../providers/aws.md#lmb-003) | Lambda function env vars may contain plaintext secrets | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`LMB-004`](../providers/aws.md#lmb-004) | Lambda resource policy allows wildcard principal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |

## Not covered

Several OSC&R techniques describe attacker-side actions that a CI/CD
configuration scanner cannot detect:

- **Reconnaissance** (REC-1, REC-3, REC-4, REC-5, REC-7, REC-8, REC-9):
  discovering naming conventions, technology stacks, coding flaws,
  and internal artifact names are attacker-side information gathering.
- **Resource Development** (RD-2, RD-6): creating registry accounts
  and advertising malicious artifacts are attacker-side prep.
- **Initial Access** (IA-2, IA-12, IA-14, IA-15): malicious IDE
  extensions, exposed internal APIs, compromised developer workstations,
  and exposed databases require runtime or network telemetry.
- **Execution** (EX-2, EX-3, EX-4, EX-5, EX-7, EX-8, EX-10):
  runtime logic bombs, IDE execution, runtime backdoors, package-manager
  exploitation, SQL injection, XSS, and cloud workload abuse are
  application-security or runtime concerns.
- **Persistence** (PER-5, PER-7): untagged cloud resources and zombie
  instances require cloud-inventory introspection.
- **Credential Access** (CA-1, CA-7): application-level password
  logging and runtime credential leakage require runtime telemetry.
- **Defense Evasion** (DE-2, DE-5): SaaS sprawl and malicious
  compilers require asset-inventory and build-tool-chain introspection.
- **Exfiltration** (EXF-1): outbound traffic bypass requires network
  telemetry.
- **Impact** (IMP-1 partial): repository deletion is partially
  covered via SCM branch-protection rules.

---

_This page is generated. Edit `pipeline_check/core/standards/data/oscr.py` (mappings) or `scripts/gen_standards_docs.py` (intro / per-control prose) and run `python scripts/gen_standards_docs.py oscr`._
