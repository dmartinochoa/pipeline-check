# Azure DevOps Pipelines provider

Parses an `azure-pipelines.yml` from disk — no network calls, no ADO
personal access token.

## Producer workflow

```bash
# --azure-path is auto-detected when azure-pipelines.yml is present at cwd;
# the CLI announces the pick on stderr.
pipeline_check --pipeline azure

# …or pass it explicitly.
pipeline_check --pipeline azure --azure-path azure-pipelines.yml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Shape coverage

The walker handles every layout ADO supports:

- Flat single-job pipeline — top-level `steps:`
- Single-stage multi-job — top-level `jobs:`
- Multi-stage — `stages: → jobs: → steps:`
- Deployment jobs — steps under
  `strategy.{runOnce|rolling|canary}.{preDeploy|deploy|routeTraffic|postRouteTraffic}.steps`
  and `strategy.*.on.{success|failure}.steps`.

## What it covers

| Check    | Title                                                   | Severity |
|----------|---------------------------------------------------------|----------|
| ADO-001  | Task reference not pinned to specific version           | HIGH     |
| ADO-002  | Script injection via attacker-controllable context      | HIGH     |
| ADO-003  | Variables contain literal secret values                 | CRITICAL |
| ADO-004  | Deployment job missing environment binding              | MEDIUM   |
| ADO-005  | Container image not pinned to specific version          | HIGH     |
| ADO-006  | Artifacts not signed                                    | MEDIUM   |
| ADO-007  | SBOM not produced                                       | MEDIUM   |
| ADO-008  | Credential-shaped literal in pipeline body              | CRITICAL |
| ADO-009  | Container image pinned by tag rather than sha256 digest | LOW      |
| ADO-010  | Cross-pipeline `download:` ingestion unverified         | CRITICAL |
| ADO-011  | `template: <local-path>` on PR-validated pipeline       | HIGH     |
| ADO-012  | Cache@2 key derives from `$(System.PullRequest.*)`      | MEDIUM   |
| ADO-013  | Self-hosted pool without explicit ephemeral marker      | MEDIUM   |

---

## ADO-001 — Task reference not pinned to specific version
**Severity:** HIGH · CICD-SEC-3 Dependency Chain Abuse

`- task: DownloadSecureFile@1` pins only the major version; the publisher
can roll forward minor releases under the pipeline. Full semver
(`@1.2.3`) or the extension's published-version build is pinned.

**Recommended actions**
- Replace `@N` references with `@N.M.P`.
- Track updates explicitly via Azure DevOps extension settings.

## ADO-002 — Script injection via attacker-controllable context
**Severity:** HIGH · CICD-SEC-4 Poisoned Pipeline Execution

ADO expands `$(Variable)` macros *before* shell quoting. Variables
derived from push / PR metadata — `$(Build.SourceBranch)`,
`$(Build.SourceBranchName)`, `$(Build.SourceVersionMessage)`,
`$(System.PullRequest.SourceBranch)`, `$(System.PullRequest.PullRequestId)`
— can be crafted by any contributor. Inline use in `script`/`bash`/`pwsh`
/`powershell` bodies is flagged.

**Recommended actions**
- Read the value into an intermediate variable and reference it through
  the shell's env-var mechanism rather than the macro.
- Quoted assignment (`VAR="$(Build.SourceBranch)"`) is exempt — the
  value is captured but not executed.

## ADO-003 — Variables contain literal secret values
**Severity:** CRITICAL for AWS keys, else HIGH · CICD-SEC-6

Scans both mapping form (`variables: {KEY: value}`) and list form
(`variables: [{name: KEY, value: ...}]`), at top level and per-job.
Flags `AKIA…` keys and string values on `password` / `secret` / `token`
/ `api_key` / `private_key` keys.

**Recommended actions**
- Use an Azure Key Vault task or a Library variable group with the
  *secret* flag; reference `$(SECRET_NAME)` at runtime.
- Prefer workload identity federation for cloud access over long-lived
  secrets.

## ADO-004 — Deployment job missing environment binding
**Severity:** MEDIUM · CICD-SEC-1 Insufficient Flow Control

A `- deployment: <name>` job without `environment: <name>` can't be
gated by approvals, required branches, or business-hours checks — ADO
only enforces these on named Environments.

**Recommended actions**
- Add `environment: <name>` to every `deployment:` job.
- Configure the matching Environment in the ADO UI with the required
  approvers and check policy.

## ADO-005 — Container image not pinned to specific version
**Severity:** HIGH · CICD-SEC-3 Dependency Chain Abuse

Checks both `resources.containers[].image` and per-job `container:` /
`container.image` references. `python:latest` / `python` (no tag) fail;
`python:3.12.1` / `python@sha256:…` pass.

**Recommended actions**
- Reference images by `@sha256:<digest>` or full immutable version tag.
- Avoid `:latest` and bare-name refs.

---

## Adding a new Azure Pipelines check

1. Add a method to `pipeline_check/core/checks/azure/pipelines.py`
   returning a `Finding` with ID `ADO-<NNN>`; register the call in
   `_check_doc`.
2. Add mappings for the new ID in the relevant standards under
   `pipeline_check/core/standards/data/*.py`.
3. Add tests under `tests/azure/test_pipelines.py` plus an insecure /
   secure fixture pair under `tests/fixtures/workflows/azure/` and an
   expected-ID entry in `tests/test_workflow_fixtures.py`.
