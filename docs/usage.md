# Usage

Quick-reference task-oriented guide. For deep dives, follow the links at
the bottom of each section.

## Install

```bash
pip install pipeline-check       # package name: hyphenated
pipeline_check --version         # command name: underscored
```

Python 3.10+ is required. `pipx install pipeline-check` also works and
keeps the CLI out of your project environment.

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
Helm `Chart.yaml`, and falls back to `aws` (live account scan) when
nothing matches. OCI manifests (`index.json`) are not auto-detected
because the filename is too generic; pass `--pipeline oci` or
`--pipelines github,oci` explicitly.

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

pipeline_check --pipeline gitlab --gitlab-path path/to/.gitlab-ci.yml
pipeline_check --pipeline azure  --azure-path  azure-pipelines.yml
pipeline_check --pipeline jenkins --jenkinsfile-path Jenkinsfile
pipeline_check --pipeline circleci --circleci-path .circleci/config.yml
pipeline_check --pipeline bitbucket --bitbucket-path bitbucket-pipelines.yml
pipeline_check --pipeline cloudbuild --cloudbuild-path cloudbuild.yaml
pipeline_check --pipeline buildkite --buildkite-path .buildkite/pipeline.yml
pipeline_check --pipeline tekton --tekton-path tekton/
pipeline_check --pipeline argo --argo-path workflows/
pipeline_check --pipeline dockerfile --dockerfile-path Dockerfile
pipeline_check --pipeline kubernetes --k8s-path manifests/
pipeline_check --pipeline helm --helm-path charts/myapp/

pipeline_check --pipeline drone --drone-path .drone.yml
pipeline_check --pipeline oci --oci-manifest index.json

pipeline_check --pipeline cloudformation --cfn-template template.yml
pipeline_check --pipeline terraform --tf-plan plan.json
pipeline_check --pipeline aws --region eu-west-1 --profile prod
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

## Scaffold a config file

```bash
pipeline_check init                 # writes .pipeline-check.yml in cwd
pipeline_check init --path infra/   # redirect output
pipeline_check init --force         # overwrite existing
```

The `init` subcommand pre-fills the `pipeline:` key based on what it
finds in the working directory.

Config file reference: [config.md](config.md).

## Gate a CI build on results

```bash
# Fail the build if any HIGH or CRITICAL finding exists
pipeline_check --fail-on HIGH

# Fail if grade drops below B
pipeline_check --min-grade B

# Fail only on new findings vs a committed baseline
pipeline_check --fail-on HIGH --baseline-from-git origin/main:baseline.json

# Cap total failures
pipeline_check --max-failures 10
```

Gate details: [ci_gate.md](ci_gate.md).

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
pipeline_check --output both                       # terminal→stderr, JSON→stdout
```

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

Each finding carries the full source-to-sink chain in its
description. Single-rule scanners stop at the producer's
direct-interpolation finding (GHA-003 / GL-002 / BK-003 /
TKN-003 / ARGO-005) and miss the actual injection sink one
step (or one job, or one template) later. The TAINT family
is what catches the cross-boundary flow.

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

`--ai-explain CHECK_ID` prints the deterministic `--explain` body and
appends a clearly-banner-framed AI-generated remediation paragraph
grounded in the project's README and an optional context file. Three
providers supported, all opt-in:

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

## Environment variables

Every CLI flag has an env-var equivalent: `PIPELINE_CHECK_<FLAG>` with
dashes converted to underscores. Gate flags nest under `GATE`:

```bash
PIPELINE_CHECK_PIPELINE=github \
PIPELINE_CHECK_GATE_FAIL_ON=HIGH \
pipeline_check
```

Precedence: CLI > env > config file > defaults.

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | Gate passed |
| 1    | Gate failed |
| 2    | Scanner error (e.g. AWS API failure, malformed config file) |
| 3    | Usage / config error (unknown flag, missing required path, bad YAML) |
| 4    | `--ai-explain` request failure (missing SDK, missing key, unknown provider, request error) |

## Verbose and quiet modes

```bash
pipeline_check -v       # debug logs to stderr (per-check timing, API calls)
pipeline_check -q       # suppress all output, rely on the exit code
```

## Extended manual pages

Topic-specific help without leaving the terminal:

```bash
pipeline_check --man              # list topics
pipeline_check --man gate
pipeline_check --man autofix
pipeline_check --man secrets
pipeline_check --man standards
```

## See also

- [providers/](providers/README.md): per-provider check reference
- [standards/](standards/README.md): compliance mappings
- [config.md](config.md): full config-file schema
- [ci_gate.md](ci_gate.md): gate logic and baselines
- [output.md](output.md): output format schemas
- [attack_chains.md](attack_chains.md): chain detection
- [scoring_model.md](scoring_model.md): how grades are computed
