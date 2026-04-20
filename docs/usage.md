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

Run with no flags in any supported repo — the working directory is
inspected and the matching provider is selected:

```bash
cd your-repo
pipeline_check
```

Auto-detect looks for, in order: `.github/workflows/`, `.gitlab-ci.yml`,
`bitbucket-pipelines.yml`, `azure-pipelines.yml`, `Jenkinsfile`,
`.circleci/config.yml`, `cloudbuild.yaml`, CloudFormation templates
(`*.yml`, `*.yaml`, `*.json` at repo root), Terraform plan JSON, and
falls back to `aws` (live account scan) when nothing matches.

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

pipeline_check --pipeline cloudformation --cfn-template template.yml
pipeline_check --pipeline terraform --tf-plan plan.json
pipeline_check --pipeline aws --region eu-west-1 --profile prod
```

Full per-provider reference: [providers/](providers/).

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

## AWS live scans — credentials

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

Required IAM permissions for a full scan: see [providers/aws.md](providers/aws.md).

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

68 fixers cover pinning, secrets, timeouts, TLS bypass, script
injection, Docker flags, and more. See individual check pages under
[providers/](providers/) for which have autofix support.

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

Standards reference: [standards/](standards/).

## Attack chains

The scanner correlates independent findings into MITRE ATT&CK-mapped
kill chains (e.g. "unpinned action + overpermissive token + no approval
gate = full-pipeline takeover"). Chains are on by default and print
after the findings section.

Chain reference: [attack_chains.md](attack_chains.md).

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

## Verbose and quiet modes

```bash
pipeline_check -v       # debug logs to stderr (per-check timing, API calls)
pipeline_check -q       # suppress all output — rely on the exit code
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

- [providers/](providers/) — per-provider check reference
- [standards/](standards/) — compliance mappings
- [config.md](config.md) — full config-file schema
- [ci_gate.md](ci_gate.md) — gate logic and baselines
- [output.md](output.md) — output format schemas
- [attack_chains.md](attack_chains.md) — chain detection
- [scoring_model.md](scoring_model.md) — how grades are computed
