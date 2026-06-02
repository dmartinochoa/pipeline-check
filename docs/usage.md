# Usage

Quick-reference task-oriented guide. For deep dives, follow the links at
the bottom of each section.

## Install

```bash
pip install pipeline-check       # package name: hyphenated
pipeline_check --version         # command name: underscored
```

Python 3.11+ is required. `pipx install pipeline-check` also works and
keeps the CLI out of your project environment.

### Container image

Every release also publishes a multi-arch (`linux/amd64` +
`linux/arm64`) image to Docker Hub and GHCR, with SLSA build
provenance and an SBOM attached to the manifest:

```bash
docker run --rm -v "$PWD:/scan" dmartinochoa/pipeline-check
docker run --rm -v "$PWD:/scan" ghcr.io/dmartinochoa/pipeline-check
```

Both registries publish the same digest; pick whichever your platform
already pulls from. Tag flavors are `:<version>` (e.g. `:1.0.4`),
`:sha-<short>` for a commit-specific *tag* (mutable: still resolves
through Docker Hub / GHCR), and `:latest` on master. For true
*immutable* pinning, append the manifest digest:
`dmartinochoa/pipeline-check@sha256:<full-digest>`. `docker buildx
imagetools inspect dmartinochoa/pipeline-check:<version>` prints the
digest. `/scan` is the image working directory, so a `-v
"$PWD:/scan"` bind mount makes the auto-detect walk Just Work.
Append CLI flags after the image reference:

```bash
docker run --rm -v "$PWD:/scan" dmartinochoa/pipeline-check \
  --pipeline github --output json
```

For air-gapped or supply-chain-locked environments, pin the image by
digest (`@sha256:…`) rather than tag. The digest for each release is
visible on the [Docker Hub tags page](https://hub.docker.com/r/dmartinochoa/pipeline-check/tags)
and on the [GHCR package page](https://github.com/dmartinochoa/pipeline-check/pkgs/container/pipeline-check).

## In-terminal help

`--help` covers every flag. For deeper topic walk-throughs without
leaving the terminal, `--man <topic>` ships expanded prose on the
sub-systems people most often need to look up:

```bash
pipeline_check --man              # list topics
pipeline_check --man gate         # CI gate flags, baselines, ignore files
pipeline_check --man autofix      # which rules have --fix, what they emit
pipeline_check --man secrets      # entropy + custom-pattern secret detection
pipeline_check --man standards    # compliance mappings, --standard filtering
```

The same prose is mirrored on this site, e.g.
[ci_gate.md](ci_gate.md), but `--man` is the offline / no-browser
copy.

## First scan (auto-detect)

Run with no flags in any supported repo, the working directory is
walked for every supported provider's canonical file:

```bash
cd your-repo
pipeline_check
```

Auto-detect looks for: `.github/workflows/`, `.gitlab-ci.yml`,
`bitbucket-pipelines.yml`, `azure-pipelines.yml`, `Jenkinsfile`,
`.circleci/config.yml`, `cloudbuild.yaml`, `.buildkite/pipeline.yml`,
`.drone.yml` / `.drone.yaml`, `Dockerfile`/`Containerfile`,
CloudFormation templates (`*.yml`, `*.yaml`, `*.json` at repo root),
a `kubernetes/` / `k8s/` / `manifests/` directory of K8s manifests,
and Helm `Chart.yaml`. When nothing matches, the CLI exits with a
usage error rather than scanning silently; pass `--pipeline aws`
explicitly to scan a live AWS account. OCI manifests (`index.json`)
are also not auto-detected because the filename is too generic; pass
`--pipeline oci` or `--pipelines github,oci` explicitly.

A single match runs through `Scanner` unchanged. Two or more matches
automatically switch to `MultiScanner` (the same engine
`--pipelines github,oci` activates) so cross-provider attack chains
in the `XPC-NNN` family fire on the union of every sub-scan's
findings. The routing decision is announced on stderr so it stays
visible in CI logs:

```text
[auto] detected providers: github, dockerfile (running --pipelines github,dockerfile)
```

When `Chart.yaml` is present alongside a `kubernetes/` /
`k8s/` / `manifests/` directory the Kubernetes provider is dropped,
helm renders the templates and feeds them to the K8s rule pack
already, so scanning both would double-count.

## Scan a specific provider

```bash
pipeline_check -p github                        # short flag
pipeline_check --pipeline github

pipeline_check --pipeline gitea --gitea-path .gitea/workflows/
pipeline_check --pipeline gitlab --gitlab-path path/to/.gitlab-ci.yml
pipeline_check --pipeline azure  --azure-path  azure-pipelines.yml
pipeline_check --pipeline jenkins --jenkinsfile-path Jenkinsfile
pipeline_check --pipeline circleci --circleci-path .circleci/config.yml
pipeline_check --pipeline bitbucket --bitbucket-path bitbucket-pipelines.yml
pipeline_check --pipeline cloudbuild --cloudbuild-path cloudbuild.yaml
pipeline_check --pipeline buildkite --buildkite-path .buildkite/pipeline.yml
pipeline_check --pipeline tekton --tekton-path tekton/
pipeline_check --pipeline argo --argo-path workflows/
pipeline_check --pipeline argocd --argocd-path argocd/
pipeline_check --pipeline dockerfile --dockerfile-path Dockerfile
pipeline_check --pipeline kubernetes --k8s-path manifests/
pipeline_check --pipeline helm --helm-path charts/myapp/

pipeline_check --pipeline drone --drone-path .drone.yml
pipeline_check --pipeline oci --oci-manifest index.json

# Developer-environment configs that auto-execute on repo open
# (.vscode/tasks.json, devcontainer.json, .claude/settings.json).
pipeline_check --pipeline devenv --devenv-path ./

pipeline_check --pipeline npm --npm-path ./
pipeline_check --pipeline pypi --pypi-path ./
pipeline_check --pipeline maven --maven-path ./
pipeline_check --pipeline nuget --nuget-path ./
pipeline_check --pipeline gomod --gomod-path ./
pipeline_check --pipeline cargo --cargo-path ./
pipeline_check --pipeline composer --composer-path ./
pipeline_check --pipeline rubygems --rubygems-path ./

pipeline_check --pipeline cloudformation --cfn-template template.yml
pipeline_check --pipeline terraform --tf-plan plan.json
pipeline_check --pipeline terraform --tf-source ./infra/   # direct HCL, no terraform binary
pipeline_check --pipeline pulumi --pulumi-path ./infra/Pulumi.yaml
pipeline_check --pipeline aws --region eu-west-1 --profile prod
pipeline_check --pipeline azure_cloud --subscription-id 00000000-0000-0000-0000-000000000000
pipeline_check --pipeline gcp --gcp-project my-project-id

# SCM posture (GitHub repo governance via the REST API).
# Token comes from --gh-token or $GITHUB_TOKEN. Without admin
# scope on the repo, the ``security_and_analysis``-driven rules
# (SCM-004 / -005 / -015 / -016) cannot tell ``disabled`` from
# ``unknown`` -- re-run with admin scope to confirm those
# rules' verdicts.
pipeline_check --pipeline scm --scm-platform github \
    --scm-repo octocat/hello-world

# Hermetic mode: read SCM API responses from JSON fixtures
# under DIR. Useful for offline tests and CI runs that don't
# hold a token.
pipeline_check --pipeline scm --scm-platform github \
    --scm-repo octocat/hello-world \
    --scm-fixture-dir ./scm-fixtures/
```

Full per-provider reference: [providers/](providers/README.md).

## Scan multiple providers in one run

Cross-provider attack chains (the `XPC-NNN` family) only fire when the
engine sees findings from more than one provider in the same scan. Use
`--pipelines` (plural, comma-separated) to opt in:

```bash
# Pull GitHub Actions + OCI manifest into one report; XPC-001 (deploy
# without verifiable provenance) fires when both legs are missing.
pipeline_check --pipelines github,oci

# Per-provider auto-detection still applies; override any single
# provider's path with its companion flag the same way as in
# single-provider mode.
pipeline_check --pipelines dockerfile,kubernetes \
    --dockerfile-path Dockerfile --k8s-path manifests/
```

`--pipelines` is mutually exclusive with the single-valued `--pipeline`.

## Set up the repo: `init`

```bash
pipeline_check init                 # smart init: scan + baseline + tuned gate
pipeline_check init --no-scan       # static scaffold only (legacy behavior)
pipeline_check init --path infra/   # redirect output
pipeline_check init --force         # overwrite existing
```

By default `init` runs one scan against whatever pipeline files it
auto-detects, writes `.pipeline-check-baseline.json` capturing the
current failing findings, and emits `.pipeline-check.yml` with a
recommended `gate.fail_on` plus a baseline pointer so future CI runs
only block on *new* regressions. A "top 5 to fix" summary lands on
stderr so the operator has a starting point.

The recommendation logic is intentionally conservative:

- Any CRITICAL failure → `fail_on: HIGH` (criticals are baselined; new
  highs still block).
- Grade A or B → `fail_on: MEDIUM` (you already have the bar — hold it).
- Otherwise → `fail_on: HIGH` (most common first-scan case on a legacy
  repo).

Pass `--no-scan` to skip the scan and write the bare commented-out
scaffold (the pre-1.x behavior). `--baseline-path PATH` redirects the
baseline file.

Config file reference: [config.md](config.md).

## Explain a single check: `explain`

```bash
pipeline_check explain GHA-001      # severity, recommendation, controls, fixers
pipeline_check explain ZZZ-9999     # unknown → exit 3 + "did you mean" list
```

Equivalent to `pipeline_check --explain CHECK_ID` (which still works);
the subcommand form is more discoverable and is what the smart-init
top-5 summary and the gate-failure trailer point users at.

## Gate a CI build on results

```bash
# Fail the build if any HIGH or CRITICAL finding exists
pipeline_check --fail-on HIGH

# Fail if grade drops below B
pipeline_check --min-grade B

# Fail only on new findings vs a committed baseline
pipeline_check --fail-on HIGH --baseline-from-git origin/main:baseline.json

# Snapshot today's findings so future runs gate only on new issues
pipeline_check --write-baseline baseline.json

# Cap total failures
pipeline_check --max-failures 10
```

For multi-lane CI (pre-commit / PR / release-gate), bundle the gate
flags into a named policy file under `policies/<name>.yml`:

```bash
# Pre-commit lane uses a HIGH-only profile
pipeline_check --policy pre-commit

# Release lane uses MEDIUM-fail + attestation rules forced
pipeline_check --policy release-gate

# Enumerate every discoverable policy
pipeline_check --list-policies
```

Gate details: [ci_gate.md](ci_gate.md). Policy schema:
[config.md](config.md#named-scan-profiles).

## AWS live scans: credentials

The AWS provider uses the standard boto3 credential chain. Any of these
work:

```bash
# Named AWS CLI profile
pipeline_check --pipeline aws --profile prod

# Environment variables
AWS_PROFILE=prod pipeline_check --pipeline aws
AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... pipeline_check --pipeline aws

# SSO / assume-role
aws sso login --profile prod && pipeline_check --pipeline aws --profile prod

# LocalStack (for testing)
AWS_ENDPOINT_URL=http://localhost:4566 pipeline_check --pipeline aws
```

Required IAM permissions for a full scan, with a copy-paste IAM policy:
see [providers/aws.md#required-iam-permissions](providers/aws.md#required-iam-permissions).

## Output formats

```bash
pipeline_check --output terminal                   # default (rich table)
pipeline_check --output json                       # machine-parseable
pipeline_check --output html -O report.html        # self-contained file
pipeline_check --output sarif -O scan.sarif        # GitHub/GitLab SAST
pipeline_check --output markdown                   # PR comments
pipeline_check --output junit -O junit.xml         # test-runner UIs
pipeline_check --output codequality -O gl-code-quality-report.json  # GitLab MR annotations
pipeline_check --output threatmodel -O tm.json     # MITRE ATT&CK threat model
pipeline_check --output cyclonedx -O sbom.json     # CycloneDX 1.6 build SBOM
pipeline_check --output both                       # terminal→stderr, JSON→stdout
```

`--inline-explain` surfaces each rule's recorded `exploit_example` so
operators see a concrete attack scenario without piping the check ID
through `pipeline_check explain`. It is honored by `terminal` / `both`
(under the Recommendation block), `sarif` (rule `help`), `junit`
(`<failure>` body), `markdown` (a collapsible Proof-of-exploit
section), and `codequality` (issue `description`). `json` and `html`
carry the field unconditionally. See [output.md](output.md) for the
per-format detail.

Format schemas: [output.md](output.md).

## Filter what gets scanned

```bash
# Only run specific checks
pipeline_check --checks GHA-001 --checks GHA-003

# Glob patterns
pipeline_check --checks 'GHA-*' --checks '*-008'

# Only files changed in this branch
pipeline_check --diff-base origin/main

# Suppress noisy findings (per-repo .pipelinecheckignore)
echo "GHA-019" > .pipelinecheckignore
```

## Auto-fix findings

```bash
pipeline_check --fix              # print unified-diff patches to stdout
pipeline_check --fix --apply      # write patches in place
pipeline_check --fix | git apply  # review first, then apply
```

111 fixers cover pinning, secrets, timeouts, TLS bypass, script
injection, Docker flags, Kubernetes securityContext, and more. See individual check pages under
[providers/](providers/README.md) for which have autofix support.

To see the whole set without scanning, use `--list-fixers`. It prints
one line per check ID (`ID  SEVERITY  TIER  TITLE`) and exits, so you
can tell at a glance which rules have a fixer and which tier it belongs
to. Narrow the listing with `--safety`:

```bash
pipeline_check --list-fixers                 # all 111, grouped by ID
pipeline_check --list-fixers --safety safe   # only the default --fix tier
pipeline_check --list-fixers --safety unsafe # inference-dependent fixers
pipeline_check --list-fixers | grep '^GHA-'  # one provider's fixers
```

A rule that lists here can still emit no patch on a given run: the
fixer is idempotent (skips an already-remediated finding) and bails
when its edit wouldn't round-trip as valid YAML.

## Fix and open a PR: `fix-pr`

```bash
pipeline_check fix-pr --dry-run   # preview the patch + planned actions
pipeline_check fix-pr             # fix, commit to a branch, push, open the PR
pipeline_check fix-pr --no-push   # stop after the local commit
pipeline_check fix-pr --safety all --base main
```

`fix-pr` runs a scan, applies the autofixers of the chosen `--safety`
tier (`safe` default / `unsafe` / `all`, the same vocabulary as
`--list-fixers`), commits the changed files to a fresh branch
(`pipeline-check/autofix`, auto-suffixed if it already exists), pushes,
and opens the request:

- **GitHub** — `gh pr create` (falls back to printing the compare URL
  when the `gh` CLI isn't installed).
- **GitLab** — the MR is created by the push itself via
  `-o merge_request.*` push options, so no token or `glab` is needed.
- **Other hosts** — the branch is pushed and you're told to open the
  request by hand.

It refuses a dirty working tree by default so the commit never sweeps in
unrelated edits; `--allow-dirty` overrides that but still stages only the
autofix edits. `--base` sets the target branch (defaults to the current
one), `--branch` / `--remote` / `--title` / `--body` / `--checks` tune
the rest.

## Compliance annotations

Every finding carries control IDs from every enabled standard. Filter:

```bash
# Annotate with a single standard
pipeline_check --standard owasp_cicd_top_10

# Multiple standards
pipeline_check --standard nist_ssdf --standard soc2

# List all registered standards
pipeline_check --list-standards

# Print the control-to-check matrix for one standard
pipeline_check --standard-report slsa
```

Standards reference: [standards/](standards/README.md).

## Attack chains

The scanner correlates independent findings into MITRE ATT&CK-mapped
kill chains (e.g. "unpinned action + overpermissive token + no approval
gate = full-pipeline takeover"). Chains are on by default and print
after the findings section.

```bash
pipeline_check --list-chains              # one line per registered chain
pipeline_check --explain-chain AC-001     # full reference card

pipeline_check --fail-on-chain AC-001     # gate on a named chain
pipeline_check --fail-on-any-chain        # gate on any matched chain
pipeline_check --no-chains                # disable correlation entirely
```

Chain gates **bypass baseline and ignore-file filtering**, a correlated
attack path is intrinsically a new finding even when its constituent
legs were baselined separately.

Chain reference: [attack_chains.md](attack_chains.md).

## Cross-provider dataflow taint analysis

The `TAINT-NNN` family is a workflow-wide / pipeline-wide
taint engine that follows attacker-controllable input across
step, job, template, and reusable-workflow boundaries. Each
provider gets its own engine port routed through the host's
native cross-step propagation channel:

| Rule         | Provider     | Channel                                                                       |
|--------------|--------------|-------------------------------------------------------------------------------|
| `TAINT-001`  | GHA          | `${{ github.event.* }}` flowing through `$GITHUB_OUTPUT` to a same-job step  |
| `TAINT-002`  | GHA          | The same flow crossing a `jobs.<id>.outputs.*` boundary into another job     |
| `TAINT-003`  | GHA          | Untrusted input forwarded into a reusable-workflow `with:` input             |
| `TAINT-004`  | GitLab CI    | `$CI_COMMIT_*` / `$CI_MERGE_REQUEST_*` flowing through `artifacts.reports.dotenv` to a downstream `needs:` job |
| `TAINT-005`  | Buildkite    | `$BUILDKITE_*` flowing through the per-build `buildkite-agent meta-data` store to a downstream step |
| `TAINT-006`  | Tekton       | `$(params.<X>)` flowing into `$(results.<Y>.path)` then read via `$(tasks.<producer>.results.<Y>)` in a consumer task's script |
| `TAINT-007`  | Argo Workflows | `{{inputs.parameters.<X>}}` flowing through `outputs.parameters` then read via `{{tasks.<producer>.outputs.parameters.<X>}}` in a consumer template |
| `TAINT-008`  | GitLab CI    | `extends:` job-template inheritance carrying tainted `variables:` into a consumer job's scripts. Quote-state aware; transitive across the extends chain with cycle detection. |

Each finding carries the full source-to-sink chain in its
description. Single-rule scanners stop at the producer's
direct-interpolation finding (GHA-003 / GL-002 / BK-003 /
TKN-003 / ARGO-005) and miss the actual injection sink one
step (or one job, or one template) later. The TAINT family
is what catches the cross-boundary flow.

## What `--resolve-remote` unlocks

`--resolve-remote` is off by default to keep scans network-free.
Turning it on lets the scanner fetch external metadata and remote
includes, enabling detection that static analysis alone cannot provide.
The following checks are degraded or silent without it:

**GitHub Actions:**

| Area | Without flag | With flag |
|------|-------------|-----------|
| **Action reputation** (GHA-041, GHA-042, GHA-043) | Pass silently with a nudge | Fetch contributor count, repo age, star count from the GitHub API |
| **Reusable workflow permissions** (GHA-004) | Reusable-workflow callers are skipped because their step list is empty | Callee resolved, permissions verified end-to-end |
| **Known-vulnerable actions** (GHA-096) | GHSA advisory lookup skipped | Live GHSA check against referenced action versions |
| **Impostor commit detection** (GHA-090) | Commit-SHA provenance check skipped | Verifies commit belongs to the claimed repository |
| **Taint propagation** (TAINT-\*) | Same-document scope only | Follows cross-document `include:` references |

**GitLab CI:**

| Area | Without flag | With flag |
|------|-------------|-----------|
| **Remote includes** | `include: project/remote/template/component` directives not resolved | Fetches and merges remote includes before rules run |
| **Taint propagation** (TAINT-004, TAINT-008) | Cannot see jobs/templates from remote includes | Full cross-document taint resolution |

**Dependency providers (npm, PyPI, Maven, NuGet):**

| Area | Without flag | With flag |
|------|-------------|-----------|
| **OSV advisories** (NPM-010, PYPI-009, MVN-009, NUGET-009) | Skipped | Live lookup against the OSV batch API |
| **npm publish-time metadata** (NPM-008) | Cooldown check skipped | Fetches publish timestamps to detect recently-published versions |

**Secret verification:**

| Area | Without flag | With flag |
|------|-------------|-----------|
| **Live probes** (all `--verify-secrets` rules) | No verification | Probes leaked credentials against issuing APIs (GitHub, GitLab, npm, Slack, etc.) |

For teams that want the broadest coverage, `--resolve-remote` is
recommended. The tradeoff is scan speed (network calls add latency) and
the need for API tokens (`--gh-token`, `--gitlab-token`) for higher rate
limits.

## Dataflow secret detection

`--detect-entropy` adds a Shannon-entropy pass to the secret detector.
It catches custom org tokens with no public prefix (an internal
Snowflake token, a custom JWT issuer secret, an opaque session token)
that the deterministic prefix-shape catalog can't match:

```bash
pipeline_check --detect-entropy
```

Off by default, turning it on can introduce new findings on
previously-clean scans. Layered FP suppression (key-context match,
length floor, token shape, deterministic-detector overlap, placeholder
markers) keeps signal high; hits are labeled `entropy:<redacted>` so
operators can write targeted ignore rules per-class.

## AI-augmented `--explain`

`--ai-explain CHECK_ID` prints the deterministic `--explain` body,
then a banner-prefixed AI section that grounds an LLM remediation
paragraph in the project's README and an optional context file. The
banner makes the generated text visually distinct from the
deterministic body so readers can tell at a glance which lines came
from a model. Three providers supported, all opt-in:

```bash
pip install pipeline-check[ai-anthropic]   # or [ai-openai]
ANTHROPIC_API_KEY=... pipeline_check --ai-explain GHA-016 \
    --ai-context-file docs/security-model.md
```

Default models: `claude-sonnet-4-6` (Anthropic), `gpt-4o-mini`
(OpenAI), `llama3.2` (Ollama, stdlib HTTP, no Python dep). The
deterministic surfaces (`--explain`, `--list-checks`,
`--list-standards`, JSON / SARIF / scoring / gating, attack chains)
are unaffected, no AI call fires unless `--ai-explain` is passed.

## Inventory

Emit the list of resources / workflows / templates the scanner
discovered, with per-type metadata:

```bash
pipeline_check --inventory                       # alongside findings
pipeline_check --inventory-only                   # skip checks entirely
pipeline_check --inventory-type 'AWS::IAM::*'     # glob filter (repeatable)
```

## Multi-scanner SARIF ingest

`--ingest <file>.sarif` (repeatable) absorbs findings from any
SARIF 2.1.0-conformant scanner (Trivy, Checkov, Snyk, KICS,
CodeQL, …) into the same scan output as pipeline-check's native
findings. External rules become `INGEST-<tool>-<rule-id>`
`Finding` rows; the chain engine then re-evaluates over the union,
so cross-tool chains (e.g. `XPC-009`, an ingested CVE finding plus
`DF-001` mutable runtime image) fire on compositions no
individual scanner would surface alone.

```bash
# Run pipeline-check natively + ingest a Trivy report
trivy fs --format sarif --output trivy.sarif ./
pipeline_check --pipeline auto --ingest trivy.sarif --output sarif \
    --output-file combined.sarif

# Multiple feeds compose cleanly
pipeline_check --ingest trivy.sarif --ingest checkov.sarif \
    --ingest snyk.sarif

# Ingest-only (pipe one tool's output through pipeline-check's
# correlation engine without running any native rules):
pipeline_check --pipeline auto --checks 'INGEST-*' --ingest trivy.sarif
```

Severity reads from `properties.security-severity` (the
GitHub-Code-Scanning CVSS-like 0..10 score) when present,
falling back to the SARIF `level` enum (`error` -> HIGH,
`warning` -> MEDIUM, `note` -> LOW, otherwise INFO). Failures
to parse a feed surface as warnings on stderr; the rest of the
scan keeps going. Caps: 25 MiB per file, 5,000 results per file
(both configurable via the public Python API in
`pipeline_check.core.sarif_ingest`).

## Vulnerable-by-design benchmark

`bench/` ships intentionally-vulnerable fixture sets (one folder
per attack pattern, anchored to a real-world incident) plus a
runner that asserts pipeline-check fires on every expected check
ID for each case. Used as a CI regression gate AND as
verifiable coverage proof for adopters.

```bash
# Run all cases, recall table to stdout
python bench/run.py

# One case
python bench/run.py --case unpinned-supply-chain

# Machine-readable JSON
python bench/run.py --json

# Pre-populate expected.txt for a new case from current scan output
python bench/run.py --case <slug> --suggest
```

Exit code is zero only when every case hits 100 % recall.
`tests/test_bench.py` runs the harness as part of the CI suite.
The eventual cross-scanner comparison matrix (vs Zizmor /
Poutine / Checkov / KICS / Trivy) is tracked under
`bench/COMPARISON.md` with the trade-offs that justify deferring
its build.

## Environment variables

The common CLI flags have env-var equivalents: `PIPELINE_CHECK_<FLAG>`
with dashes converted to underscores. Gate flags nest under `GATE`.
The supported keys are the allowlist `_TOPLEVEL_KEYS` / `_GATE_KEYS`
in `pipeline_check/core/config.py` (provider-specific path flags and
many of the newer flags are CLI-only):

```bash
PIPELINE_CHECK_PIPELINE=github \
PIPELINE_CHECK_GATE_FAIL_ON=HIGH \
pipeline_check
```

Precedence: CLI > env > config file > defaults.

## Exit codes

This is the canonical table. Other pages link here rather than
restating it.

| Code | Meaning |
|------|---------|
| `0` | Scan completed; gate passed. |
| `1` | Scan completed; gate failed (any of `--fail-on`, `--min-grade`, `--max-failures`, `--fail-on-check`, `--fail-on-chain`, `--fail-on-any-chain` tripped). |
| `2` | Bad invocation or unexpected scan exception. Click `UsageError` (invalid flag, missing required path, mutually-exclusive flags) and uncaught scanner exceptions both surface here. The error and any traceback are on stderr. |
| `3` | Operational failure on a non-scan action: `--list-checks` / `--explain` for an unknown ID, `--apply` without `--fix`, MCP support not installed, malformed `--ignore-file` or `--baseline`. |
| `4` | `--ai-explain` request failure (missing SDK, missing API key, unknown provider, request error). |

Code `1` is what CI runs gate on. Codes `2`, `3`, `4` mean the scan
didn't complete usefully; treating them as failures in CI is the safe
default but distinct semantically from `1`.

## Verbose and quiet modes

```bash
pipeline_check -v       # debug logs to stderr (per-check timing, API calls)
pipeline_check -q       # suppress all output, rely on the exit code
```

## Editor integration

A VS Code extension drives the same rule registry as the CLI and
surfaces findings inline as you edit workflow files. Gutter
diagnostics, a Findings activity-bar panel, a status-bar tally, a
per-file CodeLens summary, and `Alt+F8` navigation all hang off the
same engine, so what you see in the editor matches what the gate will
report in CI. Full reference: [vscode.md](vscode.md).

- VS Code Marketplace: <https://marketplace.visualstudio.com/items?itemName=greylag-ci.pipeline-check>
- Open VSX (VSCodium, Cursor, Windsurf): <https://open-vsx.org/extension/greylag-ci/pipeline-check>
- Source: <https://github.com/greylag-ci/pipeline-check-vscode>

To run the LSP standalone (for a non-VS Code editor that speaks LSP):

```bash
pip install 'pipeline-check[lsp]'
python -m pipeline_check.lsp
```

## See also

- [providers/](providers/README.md): per-provider check reference
- [standards/](standards/README.md): compliance mappings
- [config.md](config.md): full config-file schema
- [ci_gate.md](ci_gate.md): gate logic and baselines
- [output.md](output.md): output format schemas
- [history.md](history.md): findings-history HTML dashboard (`pipeline_check history`)
- [attack_chains.md](attack_chains.md): chain detection
- [scoring_model.md](scoring_model.md): how grades are computed
