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
- **Distinct checks evidencing this standard:** 138
- **Of those, autofixable with `--fix`:** 17

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
| [`1.5.2`](#ctrl-1-5-2) | Ensure scanners are in place to secure CI/CD pipeline instructions | 64 | 12C · 42H · 9M · 1L |
| [`1.5.3`](#ctrl-1-5-3) | Ensure scanners are in place to secure IaC instructions | 26 | 7C · 19H |
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
| [`SCM-002`](../providers/scm_github.md#scm-002) | Default branch protection does not require pull request reviews | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-011`](../providers/scm_github.md#scm-011) | Default branch protection does not require CODEOWNERS reviews | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-014`](../providers/scm_github.md#scm-014) | Default branch protection does not require approval of the most recent push | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-023`](../providers/scm_github.md#scm-023) | Deployment environment lacks required-reviewer protection | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-032`](../providers/scm_github.md#scm-032) | Active ruleset doesn't require a PR review (governance theater) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |

### 1.1.4: Ensure previous approvals are dismissed when updates are introduced { #ctrl-1-1-4 }

**Evidenced by 3 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-012`](../providers/scm_github.md#scm-012) | Default branch protection keeps stale reviews after a push | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-014`](../providers/scm_github.md#scm-014) | Default branch protection does not require approval of the most recent push | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-037`](../providers/scm_github.md#scm-037) | Active ruleset's pull_request rule doesn't dismiss stale reviews | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |

### 1.1.5: Ensure there are restrictions on who can dismiss code change reviews { #ctrl-1-1-5 }

**Evidenced by 3 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-018`](../providers/scm_github.md#scm-018) | Required PR reviews can be bypassed by named identities | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-021`](../providers/scm_github.md#scm-021) | Actions can approve pull requests (self-approval bypass) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-031`](../providers/scm_github.md#scm-031) | Repo allows auto-merge (no human-timing gate) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |

### 1.1.6: Ensure code owners are set for extra sensitive code or configuration { #ctrl-1-1-6 }

**Evidenced by 2 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-011`](../providers/scm_github.md#scm-011) | Default branch protection does not require CODEOWNERS reviews | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-017`](../providers/scm_github.md#scm-017) | Repository has no CODEOWNERS file | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |

### 1.1.7: Ensure code owner's review is required when a change affects owned code { #ctrl-1-1-7 }

**Evidenced by 2 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-011`](../providers/scm_github.md#scm-011) | Default branch protection does not require CODEOWNERS reviews | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-017`](../providers/scm_github.md#scm-017) | Repository has no CODEOWNERS file | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |

### 1.1.9: Ensure all checks have passed before merging new code { #ctrl-1-1-9 }

**Evidenced by 3 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-008`](../providers/scm_github.md#scm-008) | Default branch protection does not require status checks | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-033`](../providers/scm_github.md#scm-033) | Active ruleset doesn't require status checks | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-039`](../providers/scm_github.md#scm-039) | Active ruleset doesn't pin a required workflow | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm_github.md) |  |

### 1.1.10: Ensure open Git branches are up to date before they can be merged { #ctrl-1-1-10 }

**Evidenced by 2 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-008`](../providers/scm_github.md#scm-008) | Default branch protection does not require status checks | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-042`](../providers/scm_github.md#scm-042) | Active ruleset doesn't require merge queue | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm_github.md) |  |

### 1.1.11: Ensure all open comments are resolved before merging code { #ctrl-1-1-11 }

**Evidenced by 1 check** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-013`](../providers/scm_github.md#scm-013) | Default branch protection does not require conversation resolution | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm_github.md) |  |

### 1.1.12: Ensure verification of signed commits for new changes { #ctrl-1-1-12 }

**Evidenced by 5 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-006`](../providers/scm_github.md#scm-006) | Default branch protection does not require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-030`](../providers/scm_github.md#scm-030) | Repository ruleset has bypass actor with bypass_mode: always | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-036`](../providers/scm_github.md#scm-036) | Active ruleset doesn't require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-043`](../providers/scm_github.md#scm-043) | Tag-targeted ruleset doesn't require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-044`](../providers/scm_github.md#scm-044) | Default-branch signed-commits requirement bypassed for admins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |

### 1.1.13: Ensure linear history is required { #ctrl-1-1-13 }

**Evidenced by 2 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-030`](../providers/scm_github.md#scm-030) | Repository ruleset has bypass actor with bypass_mode: always | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-038`](../providers/scm_github.md#scm-038) | Active ruleset doesn't require linear history | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm_github.md) |  |

### 1.1.14: Ensure branch protection rules are enforced for administrators { #ctrl-1-1-14 }

**Evidenced by 3 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-010`](../providers/scm_github.md#scm-010) | Branch protection allows administrators to bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-030`](../providers/scm_github.md#scm-030) | Repository ruleset has bypass actor with bypass_mode: always | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-044`](../providers/scm_github.md#scm-044) | Default-branch signed-commits requirement bypassed for admins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |

### 1.1.15: Ensure pushing/merging on default branches is restricted { #ctrl-1-1-15 }

**Evidenced by 4 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-001`](../providers/scm_github.md#scm-001) | Default branch has no protection rule | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-019`](../providers/scm_github.md#scm-019) | Push restrictions allowlist names individual users | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-024`](../providers/scm_github.md#scm-024) | Deployment environment can deploy from any branch | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-029`](../providers/scm_github.md#scm-029) | Repository ruleset is in evaluate / disabled mode (not enforced) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |

### 1.1.16: Ensure force push is denied { #ctrl-1-1-16 }

**Evidenced by 3 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-007`](../providers/scm_github.md#scm-007) | Default branch protection allows force-pushes | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-030`](../providers/scm_github.md#scm-030) | Repository ruleset has bypass actor with bypass_mode: always | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-034`](../providers/scm_github.md#scm-034) | Active ruleset doesn't block force-push | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |

### 1.1.17: Ensure branch deletion is denied { #ctrl-1-1-17 }

**Evidenced by 4 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-009`](../providers/scm_github.md#scm-009) | Default branch protection allows branch deletion | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-030`](../providers/scm_github.md#scm-030) | Repository ruleset has bypass actor with bypass_mode: always | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-035`](../providers/scm_github.md#scm-035) | Active ruleset doesn't block branch deletion | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-043`](../providers/scm_github.md#scm-043) | Tag-targeted ruleset doesn't require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |

### 1.1.18: Ensure any merging of code is automatically scanned for security { #ctrl-1-1-18 }

**Evidenced by 6 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-003`](../providers/scm_github.md#scm-003) | GitHub default code scanning is not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-039`](../providers/scm_github.md#scm-039) | Active ruleset doesn't pin a required workflow | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-040`](../providers/scm_github.md#scm-040) | Active ruleset doesn't gate on code scanning results | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-045`](../providers/scm_github.md#scm-045) | Default code scanning uses the limited query suite | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-046`](../providers/scm_github.md#scm-046) | Default code scanning is configured but paused | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-047`](../providers/scm_github.md#scm-047) | Repo language excluded from default code-scanning coverage | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |

### 1.1.19: Ensure any merging of code is automatically scanned for vulnerabilities { #ctrl-1-1-19 }

**Evidenced by 1 check** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-005`](../providers/scm_github.md#scm-005) | Dependabot security updates are not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |

### 1.1.20: Ensure any merging of code is automatically scanned for secrets { #ctrl-1-1-20 }

**Evidenced by 2 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-004`](../providers/scm_github.md#scm-004) | GitHub secret scanning is not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-015`](../providers/scm_github.md#scm-015) | Secret scanning push protection is not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |

### 1.2.5: Ensure all copies (forks) of code are tracked and accounted for { #ctrl-1-2-5 }

**Evidenced by 1 check** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-028`](../providers/scm_github.md#scm-028) | Private repo allows forking | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |

### 1.2.6: Ensure all code projects are tracked for changes in dependents/dependencies { #ctrl-1-2-6 }

**Evidenced by 2 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-005`](../providers/scm_github.md#scm-005) | Dependabot security updates are not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-016`](../providers/scm_github.md#scm-016) | Private vulnerability reporting is not enabled | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm_github.md) |  |

### 1.3.8: Ensure strict base permissions are set for repositories { #ctrl-1-3-8 }

**Evidenced by 1 check** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-027`](../providers/scm_github.md#scm-027) | Outside collaborator holds write / maintain / admin access | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |

### 1.3.10: Ensure SCM administrators control contribution access (deploy keys, write) { #ctrl-1-3-10 }

**Evidenced by 2 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-025`](../providers/scm_github.md#scm-025) | Repo has write-enabled deploy keys (push backdoor) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-027`](../providers/scm_github.md#scm-027) | Outside collaborator holds write / maintain / admin access | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |

### 1.4.1: Ensure administrator approval is required for every installed application { #ctrl-1-4-1 }

**Evidenced by 2 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-021`](../providers/scm_github.md#scm-021) | Actions can approve pull requests (self-approval bypass) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-022`](../providers/scm_github.md#scm-022) | Repo Actions permissions allow any source (no allow-list) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |

### 1.4.3: Ensure the access granted to each installed application is limited { #ctrl-1-4-3 }

**Evidenced by 2 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-020`](../providers/scm_github.md#scm-020) | Default workflow GITHUB_TOKEN has write permission | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-022`](../providers/scm_github.md#scm-022) | Repo Actions permissions allow any source (no allow-list) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |

### 1.4.4: Ensure only secured webhooks are used { #ctrl-1-4-4 }

**Evidenced by 1 check** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-026`](../providers/scm_github.md#scm-026) | Webhook ships events insecurely (HTTP / no-TLS / no-secret) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |

### 1.5.1: Ensure scanners are in place to identify and prevent sensitive data in code { #ctrl-1-5-1 }

**Evidenced by 16 checks** across 6 providers (CloudFormation, Dockerfile, GitHub Actions, Kubernetes, SCM, Terraform).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CF-002`](../providers/cloudformation.md#cf-002) | Stateful data-store resource carries a plaintext secret | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CloudFormation](../providers/cloudformation.md) |  |
| [`DF-006`](../providers/dockerfile.md#df-006) | ENV or ARG carries a credential-shaped literal value | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-019`](../providers/dockerfile.md#df-019) | COPY/ADD source path looks like a credential file | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-020`](../providers/dockerfile.md#df-020) | ARG declares a credential-named build argument | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-005`](../providers/github.md#gha-005) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-033`](../providers/github.md#gha-033) | Secret value echoed / printed in a run: block | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-039`](../providers/github.md#gha-039) | services / container credentials embedded as literal in workflow | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-055`](../providers/github.md#gha-055) | Reusable workflow outputs derive a secret or caller-input value | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-057`](../providers/github.md#gha-057) | Secret-scanner output sent to network egress | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`K8S-017`](../providers/kubernetes.md#k8s-017) | Container env value carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-018`](../providers/kubernetes.md#k8s-018) | Secret stringData/data carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-037`](../providers/kubernetes.md#k8s-037) | ConfigMap data carries a credential-shaped literal | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`SCM-004`](../providers/scm_github.md#scm-004) | GitHub secret scanning is not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-015`](../providers/scm_github.md#scm-015) | Secret scanning push protection is not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-016`](../providers/scm_github.md#scm-016) | Private vulnerability reporting is not enabled | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm_github.md) |  |
| [`TF-002`](../providers/terraform.md#tf-002) | Stateful data-store resource carries a plaintext secret | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Terraform](../providers/terraform.md) |  |

### 1.5.2: Ensure scanners are in place to secure CI/CD pipeline instructions { #ctrl-1-5-2 }

**Evidenced by 64 checks** across 6 providers (Argo Workflows, Buildkite, GitHub Actions, GitLab CI, SCM, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`GHA-001`](../providers/github.md#gha-001) | Action not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-002`](../providers/github.md#gha-002) | pull_request_target checks out PR head | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-003`](../providers/github.md#gha-003) | Script injection via untrusted context | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-004`](../providers/github.md#gha-004) | Workflow permissions block missing or overprovisioned | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-005`](../providers/github.md#gha-005) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-019`](../providers/github.md#gha-019) | GITHUB_TOKEN written to persistent storage | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-030`](../providers/github.md#gha-030) | OIDC token requested without environment-protected job | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-031`](../providers/github.md#gha-031) | Workflow uses retired set-output / save-state command | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-032`](../providers/github.md#gha-032) | run: invokes local script on untrusted-trigger workflow | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-033`](../providers/github.md#gha-033) | Secret value echoed / printed in a run: block | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-034`](../providers/github.md#gha-034) | Reusable workflow called with secrets: inherit | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-035`](../providers/github.md#gha-035) | github-script step interpolates untrusted context | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-036`](../providers/github.md#gha-036) | runs-on interpolates untrusted context | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-037`](../providers/github.md#gha-037) | actions/checkout persists GITHUB_TOKEN into .git/config | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-038`](../providers/github.md#gha-038) | Workflow re-enables retired ::set-env / ::add-path commands | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-039`](../providers/github.md#gha-039) | services / container credentials embedded as literal in workflow | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-040`](../providers/github.md#gha-040) | Action reference matches a known-compromised SHA or tag | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-041`](../providers/github.md#gha-041) | Action upstream repo has a single contributor | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-042`](../providers/github.md#gha-042) | Action upstream repo is newly created | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-043`](../providers/github.md#gha-043) | Low-star action runs with sensitive permissions | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-044`](../providers/github.md#gha-044) | Build tool runs lifecycle scripts on untrusted-trigger workflow | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-045`](../providers/github.md#gha-045) | Caller-controlled ref input feeds actions/checkout | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-046`](../providers/github.md#gha-046) | Manual PR-head fetch on untrusted-trigger workflow | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-047`](../providers/github.md#gha-047) | Action ref resolves to a recently committed tag or SHA | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-048`](../providers/github.md#gha-048) | Workflow step writes a file under .github/workflows/ | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-049`](../providers/github.md#gha-049) | Workflow step makes a privileged git write (cross-repo or actions[bot] bypass) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-050`](../providers/github.md#gha-050) | Publish step relies on long-lived registry token | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-051`](../providers/github.md#gha-051) | services / container image is not pinned by digest | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-052`](../providers/github.md#gha-052) | actions/cache key includes untrusted PR-controllable input | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-053`](../providers/github.md#gha-053) | if: predicate evaluates attacker-controllable context as expression | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-054`](../providers/github.md#gha-054) | actions/checkout with ssh-key persists SSH credential in repo | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-055`](../providers/github.md#gha-055) | Reusable workflow outputs derive a secret or caller-input value | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-056`](../providers/github.md#gha-056) | Workflow body contains a known supply-chain worm indicator | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-057`](../providers/github.md#gha-057) | Secret-scanner output sent to network egress | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-058`](../providers/github.md#gha-058) | Agentic CLI invoked with permission-bypass flags | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-059`](../providers/github.md#gha-059) | npm install without registry-signature verification step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-060`](../providers/github.md#gha-060) | pip install without `--require-hashes` verification | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-061`](../providers/github.md#gha-061) | GitHub App token minted without a `permissions:` filter | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-062`](../providers/github.md#gha-062) | OIDC subject claim in sibling IaC grants overly broad scope | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-092`](../providers/github.md#gha-092) | PR head SHA captured then re-fetched (force-push race) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-093`](../providers/github.md#gha-093) | Living-off-the-Pipeline indicators (workflow-command abuse) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-105`](../providers/github.md#gha-105) | Self-hosted runner reachable from an untrusted PR trigger | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-106`](../providers/github.md#gha-106) | AI agent CLI runs with a write-scoped GITHUB_TOKEN | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-110`](../providers/github.md#gha-110) | Workflow disables Go module checksum / sum-db verification | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-111`](../providers/github.md#gha-111) | AI agent generates IaC applied to the cloud in the same job | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-112`](../providers/github.md#gha-112) | Self-hosted deploy job not gated by a protected environment | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-113`](../providers/github.md#gha-113) | OIDC trusted-publishing job without an environment gate | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-114`](../providers/github.md#gha-114) | Package-publish workflow runs on an unrestricted push trigger | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-116`](../providers/github.md#gha-116) | Workflow serializes the entire secrets context (toJSON(secrets)) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-117`](../providers/github.md#gha-117) | IaC apply on an untrusted pull_request trigger | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-118`](../providers/github.md#gha-118) | Untrusted content written to $GITHUB_ENV / $GITHUB_PATH | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-119`](../providers/github.md#gha-119) | Untrusted context reaches an agentic AI CLI (prompt injection) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-120`](../providers/github.md#gha-120) | ML model loaded with trust_remote_code (code execution) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-122`](../providers/github.md#gha-122) | Unsafe deserialization of a fetched artifact (pickle RCE) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`SCM-020`](../providers/scm_github.md#scm-020) | Default workflow GITHUB_TOKEN has write permission | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-041`](../providers/scm_github.md#scm-041) | Active ruleset doesn't gate on a deployment environment | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm_github.md) |  |
| [`TAINT-001`](../providers/github.md#taint-001) | Untrusted input flows across step boundaries via step outputs | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`TAINT-002`](../providers/github.md#taint-002) | Untrusted input flows across jobs via ``jobs.<id>.outputs:`` | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`TAINT-003`](../providers/github.md#taint-003) | Untrusted input forwarded into reusable workflow ``with:`` | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`TAINT-004`](../providers/gitlab.md#taint-004) | Untrusted input flows across jobs via dotenv artifact | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`TAINT-005`](../providers/buildkite.md#taint-005) | Untrusted input flows across steps via ``buildkite-agent meta-data`` | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`TAINT-006`](../providers/tekton.md#taint-006) | Untrusted input flows across tasks via Tekton ``results`` | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |
| [`TAINT-007`](../providers/argo.md#taint-007) | Untrusted input flows across templates via Argo ``outputs.parameters`` | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`TAINT-008`](../providers/gitlab.md#taint-008) | Untrusted input flows via GitLab ``extends:`` template inheritance | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |

### 1.5.3: Ensure scanners are in place to secure IaC instructions { #ctrl-1-5-3 }

**Evidenced by 26 checks** across 4 providers (CloudFormation, Dockerfile, Kubernetes, Terraform).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`CF-001`](../providers/cloudformation.md#cf-001) | Template declares AWS::IAM::AccessKey (long-lived credential) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CloudFormation](../providers/cloudformation.md) |  |
| [`CF-002`](../providers/cloudformation.md#cf-002) | Stateful data-store resource carries a plaintext secret | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CloudFormation](../providers/cloudformation.md) |  |
| [`CF-003`](../providers/cloudformation.md#cf-003) | CodeBuild project's VPC contains a public subnet | <span class="pg-sev pg-sev--high">HIGH</span> | [CloudFormation](../providers/cloudformation.md) |  |
| [`DF-001`](../providers/dockerfile.md#df-001) | FROM image not pinned to sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-005`](../providers/dockerfile.md#df-005) | RUN uses shell-eval (eval / sh -c on a variable / backticks) | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-006`](../providers/dockerfile.md#df-006) | ENV or ARG carries a credential-shaped literal value | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-008`](../providers/dockerfile.md#df-008) | RUN invokes docker --privileged or escalates capabilities | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-019`](../providers/dockerfile.md#df-019) | COPY/ADD source path looks like a credential file | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-020`](../providers/dockerfile.md#df-020) | ARG declares a credential-named build argument | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-021`](../providers/dockerfile.md#df-021) | RUN pip install bypasses TLS or uses an HTTP index | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-024`](../providers/dockerfile.md#df-024) | RUN npm/yarn/pnpm install runs lifecycle scripts | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-026`](../providers/dockerfile.md#df-026) | ENV disables Node.js TLS certificate verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-027`](../providers/dockerfile.md#df-027) | ENV disables Python HTTPS certificate verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-028`](../providers/dockerfile.md#df-028) | ENV disables Git TLS certificate verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-029`](../providers/dockerfile.md#df-029) | ENV neuters Python requests CA bundle | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-031`](../providers/dockerfile.md#df-031) | COPY --from external image not pinned to sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`K8S-001`](../providers/kubernetes.md#k8s-001) | Container image not pinned by sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-002`](../providers/kubernetes.md#k8s-002) | Pod hostNetwork: true | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-005`](../providers/kubernetes.md#k8s-005) | Container securityContext.privileged: true | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-013`](../providers/kubernetes.md#k8s-013) | Pod uses a hostPath volume | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`K8S-017`](../providers/kubernetes.md#k8s-017) | Container env value carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-018`](../providers/kubernetes.md#k8s-018) | Secret stringData/data carries a credential-shaped literal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`K8S-037`](../providers/kubernetes.md#k8s-037) | ConfigMap data carries a credential-shaped literal | <span class="pg-sev pg-sev--high">HIGH</span> | [Kubernetes](../providers/kubernetes.md) |  |
| [`TF-001`](../providers/terraform.md#tf-001) | Plan declares aws_iam_access_key (long-lived credential) | <span class="pg-sev pg-sev--high">HIGH</span> | [Terraform](../providers/terraform.md) |  |
| [`TF-002`](../providers/terraform.md#tf-002) | Stateful data-store resource carries a plaintext secret | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Terraform](../providers/terraform.md) |  |
| [`TF-003`](../providers/terraform.md#tf-003) | CodeBuild VPC config references a public subnet | <span class="pg-sev pg-sev--high">HIGH</span> | [Terraform](../providers/terraform.md) |  |

### 1.5.4: Ensure scanners are in place to identify and confirm presence of vulnerabilities { #ctrl-1-5-4 }

**Evidenced by 8 checks** across 3 providers (AWS, GitHub Actions, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ECR-001`](../providers/aws.md#ecr-001) | Image scanning on push not enabled | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`ECR-007`](../providers/aws.md#ecr-007) | Inspector v2 enhanced scanning disabled for ECR | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`GHA-020`](../providers/github.md#gha-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`SCM-003`](../providers/scm_github.md#scm-003) | GitHub default code scanning is not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-005`](../providers/scm_github.md#scm-005) | Dependabot security updates are not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-045`](../providers/scm_github.md#scm-045) | Default code scanning uses the limited query suite | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-046`](../providers/scm_github.md#scm-046) | Default code scanning is configured but paused | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |
| [`SCM-047`](../providers/scm_github.md#scm-047) | Repo language excluded from default code-scanning coverage | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm_github.md) |  |

## Not covered

Org-admin controls that require account-level audit endpoints, MFA
enforcement (1.3.4), member inventories (1.3.1), installed-app lists
(1.4.2), and similar — are listed in the benchmark but not yet
evidenced by an `SCM-*` rule. Open an issue if your team would value
coverage; the GitHub Admin API surface is the next planned expansion
of the SCM provider.

---

_This page is generated. Edit `pipeline_check/core/standards/data/cis_github.py` (mappings) or `scripts/gen_standards_docs.py` (intro / per-control prose) and run `python scripts/gen_standards_docs.py cis_github`._
