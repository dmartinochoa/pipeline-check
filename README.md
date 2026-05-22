<div align="center">

<img src="https://raw.githubusercontent.com/dmartinochoa/pipeline-check/master/docs/logo.svg" alt="Pipeline-Check logo" width="160">

# [Pipeline-Check](https://dmartinochoa.github.io/pipeline-check/)

[![CI](https://github.com/dmartinochoa/pipeline-check/actions/workflows/python-app.yml/badge.svg)](https://github.com/dmartinochoa/pipeline-check/actions/workflows/python-app.yml)
[![GOAT bench](https://github.com/dmartinochoa/pipeline-check/actions/workflows/goat-bench.yml/badge.svg)](https://github.com/dmartinochoa/pipeline-check/actions/workflows/goat-bench.yml)
[![PyPI](https://img.shields.io/pypi/v/pipeline-check?logo=pypi&logoColor=white&label=pypi)](https://pypi.org/project/pipeline-check/)
[![Docker Hub](https://img.shields.io/docker/v/dmartinochoa/pipeline-check?logo=docker&logoColor=white&label=docker&sort=semver)](https://hub.docker.com/r/dmartinochoa/pipeline-check)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) ![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/dmartinochoa/pipeline-check?utm_source=oss&utm_medium=github&utm_campaign=dmartinochoa%2Fpipeline-check&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)
[![Socket Badge](https://badge.socket.dev/pypi/package/pipeline-check/1.0.1?artifact_id=tar-gz)](https://badge.socket.dev/pypi/package/pipeline-check/1.0.1?artifact_id=tar-gz)
[![SLSA Build L3](https://img.shields.io/badge/SLSA-Build_L3-22c55e?logo=slsa)](#-verifying-a-release)
[![Sigstore signed](https://img.shields.io/badge/Sigstore-signed-orange?logo=sigstore)](#-verifying-a-release)

### **Find security risks in your CI/CD pipelines before attackers do.**

#### Full documentation: [https://dmartinochoa.github.io/pipeline-check/](https://dmartinochoa.github.io/pipeline-check/)

Pipeline-Check is a security scanner for GitHub Actions, GitLab CI, Jenkins, CircleCI, Azure DevOps, Bitbucket Pipelines, Buildkite, Drone, Tekton, Argo Workflows, and Google Cloud Build, plus Terraform, CloudFormation, Kubernetes, Helm, Dockerfile, OCI image manifests, and live AWS accounts. It maps every finding to the [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/), SLSA, NIST SSDF, PCI DSS, SOC 2, the CIS GitHub Benchmark, and nine other frameworks, and scores each scan A through D so you can gate merges on the result.

**840+ checks** across **23 providers**, mapped to **15 compliance standards**, with **111 autofixers**, plus **41 attack chains** correlating findings into MITRE ATT&CK-mapped kill chains. A dataflow taint engine catches multi-step and cross-job propagation that single-rule scanners miss.

[Quick start](#-quick-start) |
[Usage guide](docs/usage.md) |
[Providers](#-supported-providers) |
[How it works](#-how-it-works) |
[CI integration](#-ci-integration) |
[Compliance](#-compliance-standards) |
[vs. Checkov / KICS / Semgrep](docs/comparison.md) |
[Docs](https://dmartinochoa.github.io/pipeline-check/)

</div>

---

## 🚀 Quick start

```bash
pip install pipeline-check          # Python >= 3.11

pipeline_check                      # auto-detects every provider in cwd
pipeline_check init                 # scan + baseline + tuned config (smart init)
pipeline_check explain GHA-001      # full per-check reference (severity, fix, controls)
pipeline_check -p github -o json    # short flags work too
pipeline_check --pipeline aws       # force the live-AWS scan
```

> 🔐 Want to verify the wheel was built by this repo in CI before
> installing it? Every tagged release ships SLSA Build L3 provenance
> and PEP 740 attestations. See [Verifying a release](#-verifying-a-release).

Or run from the published container image (no Python install needed):

```bash
# Docker Hub
docker run --rm -v "$PWD:/scan" dmartinochoa/pipeline-check

# GHCR (same image, different registry)
docker run --rm -v "$PWD:/scan" ghcr.io/dmartinochoa/pipeline-check
```

The image is multi-arch (`linux/amd64` + `linux/arm64`), ships with
SLSA build provenance and an SBOM attached to the manifest, and is
tagged per release (`:1.0.4`), per commit (`:sha-<short>`), and
`:latest` on master. `/scan` is the image working directory, so
mounting your repo there lets auto-detect Just Work.

Run `pipeline_check` with no flags in any supported repo. It walks
the working directory for every supported provider's canonical file
(`.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`,
`cloudbuild.yaml`, `Chart.yaml`, `template.yml`, `Dockerfile`, …).
One match runs a single-provider scan; two or more matches
automatically switch to multi-provider mode (equivalent to
`--pipelines X,Y,Z`) so cross-provider attack chains (`XPC-NNN`)
fire. When nothing matches, the CLI exits with a usage error; pass
`--pipeline aws` explicitly to scan a live AWS account.

No API tokens required. CI configs are parsed from disk; AWS uses the
standard boto3 credential chain. The GitHub Actions provider can
*optionally* follow remote reusable-workflow refs over HTTPS via
`--resolve-remote` (off by default; see [docs/providers/github.md](docs/providers/github.md)
for the full opt-in surface).

### PR review comments

Pipe findings into pull-request review comments on the changed lines
via the bundled composite action:

```yaml
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dmartinochoa/pipeline-check/.github/actions/pipeline-check-pr@v1
        with:
          severity-threshold: MEDIUM
```

Each finding lands as a review comment on its precise line (when the
rule emits a `Location`); everything else goes into a single PR-level
summary comment. See [.github/actions/pipeline-check-pr/README.md](.github/actions/pipeline-check-pr/README.md)
for inputs, idempotency, and fork-PR fallback behavior.

---

## 🧩 Supported providers

| Provider | Input | Auto-detect | Checks |
|----------|-------|-------------|--------|
| **AWS** | Live account via boto3 | `--region` | 71 checks (CodeBuild, CodePipeline, CodeDeploy, ECR, IAM, PBAC, S3, CloudTrail, CloudWatch Logs, Secrets Manager, CodeArtifact, CodeCommit, Lambda, KMS, SSM, EventBridge, Signer) |
| **Terraform** | `terraform show -json` plan | `--tf-plan` | AWS-parity shift-left checks, pre-provisioning |
| **CloudFormation** | YAML or JSON template | `--cfn-template` | ~63 AWS-parity shift-left checks; handles `!Ref`/`!Sub`/`!GetAtt` intrinsics (treats unresolved values as strict) |
| **GitHub Actions** | `.github/workflows/*.yml` | `--gha-path` | 70 checks (`GHA-001`--`065`, `GHA-086`, `GHA-087`, plus `TAINT-001..003`). `GHA-040` consults a curated registry of known-compromised action refs (CVE-2025-30066 et al.). `GHA-041..043` form the action-reputation pack: single-maintainer / very-young repo / low-star + sensitive-permission detection behind `--resolve-remote`. `GHA-044..046` catch build-tool lifecycle script execution (npm / yarn / pnpm / bun / deno install), caller-controlled `ref` into `actions/checkout`, and manual PR-head fetches on untrusted-trigger workflows. `GHA-047` flags action pins to refs committed within a cooldown window. `GHA-048..050` are the npm-worm propagation pack: workflow self-mutation, cross-repo push, and publish-without-OIDC. `GHA-051..055` cover advanced PPE / credential-leak surface: services/container image unpinned, `actions/cache` key from untrusted PR input, `if:` predicate evaluating untrusted context, `actions/checkout` SSH-key persistence, reusable workflow outputs leaking a secret. `GHA-056..058` are the worm-IOC pack: workflow body matches a curated Shai-Hulud / s1ngularity IOC registry (`_worm_indicators.py`), secret-scanner output (TruffleHog / gitleaks) piped to network egress on an untrusted trigger, and agentic CLI (`claude` / `gemini` / `q` / `cursor-agent` / `aider` / `openhands` / `goose`) invoked with permission-bypass flags (`--dangerously-skip-permissions`, `--yolo`, `--trust-all-tools`). `GHA-059` flags ``npm`` / ``pnpm`` install steps that don't pair with an ``npm audit signatures`` verification step, closing the lockfile-pinning-without-trusted-publisher gap the Shai-Hulud / TanStack / axios worms exploited. `GHA-060` is the PyPI analog: flags ``pip install`` invocations that don't use ``--require-hashes`` and aren't replaced by a hash-pinning manager (``uv sync`` / ``poetry install`` / ``pipenv install --deploy``). `GHA-061` flags App-token mint steps (``actions/create-github-app-token`` and siblings) that omit a ``permissions:`` scope filter. `GHA-062` walks the workflow's containing repo for sibling IaC (AWS trust policies, GCP WIF Terraform) and flags OIDC subject claims that match more than one repo. |
| **GitLab CI** | `.gitlab-ci.yml` | `--gitlab-path` | 37 checks (`GL-001`--`035`, plus `TAINT-004` and `TAINT-008`) |
| **Bitbucket Pipelines** | `bitbucket-pipelines.yml` | `--bitbucket-path` | 31 checks (`BB-001`--`031`) |
| **Azure DevOps** | `azure-pipelines.yml` | `--azure-path` | 30 checks (`ADO-001`--`030`) |
| **Jenkins** | `Jenkinsfile` (Declarative/Scripted) | `--jenkinsfile-path` | 35 checks (`JF-001`--`035`) |
| **CircleCI** | `.circleci/config.yml` | `--circleci-path` | 31 checks (`CC-001`--`031`) |
| **Google Cloud Build** | `cloudbuild.yaml` | `--cloudbuild-path` | 26 checks (`GCB-001`--`026`) |
| **Buildkite** | `.buildkite/pipeline.yml` | `--buildkite-path` | 16 checks (`BK-001`--`015`, plus `TAINT-005`) |
| **Drone CI** | `.drone.yml` / `.drone.yaml` | `--drone-path` | 11 checks (`DR-001`--`011`): image / plugin pinning, privileged steps, ${DRONE_*} injection, literal secrets, TLS bypass, sensitive host-path mount, `pull: never` policy, tainted cache key, unpinned package install, runner-targeting node map |
| **Tekton** | `Task` / `Pipeline` / `*Run` YAML | `--tekton-path` | 16 checks (`TKN-001`--`015`, plus `TAINT-006`) |
| **Argo Workflows** | `Workflow` / `WorkflowTemplate` YAML | `--argo-path` | 16 checks (`ARGO-001`--`015`, plus `TAINT-007`) |
| **Argo CD** | `Application` / `ApplicationSet` / `AppProject` YAML + `argocd-cm` / `argocd-rbac-cm` ConfigMaps | `--argocd-path` | 9 checks (`ARGOCD-001`--`009`) — AppProject sourceRepo / destination wildcards, auto-sync prune without selfHeal, RBAC wildcard policies, repo plaintext credentials, ApplicationSet PR/SCM generators without project allowlist, Helm generator interpolation without `goTemplate`, CMP plugin invocations, anonymous access |
| **Dockerfile** | `Dockerfile` / `Containerfile` | `--dockerfile-path` | 30 checks (`DF-001`--`030`). `DF-021`/`DF-024`/`DF-025` cover the lifecycle-scripts / npmrc-token / pip-TLS-bypass primitives the npm-worm pack relies on. `DF-026`..`030` extend DF-023's loader-hijack detection to the language-runtime TLS bypass surface (Node `NODE_TLS_REJECT_UNAUTHORIZED`, Python `PYTHONHTTPSVERIFY` / `REQUESTS_CA_BUNDLE`, Git `GIT_SSL_NO_VERIFY`) plus `NODE_OPTIONS` preload / debugger flags. |
| **Kubernetes** | Manifest YAML (`Deployment`, `Pod`, …) | `--k8s-path` | 43 checks (`K8S-001`--`043`) |
| **Helm** | Chart directory (`Chart.yaml`) or `.tgz` | `--helm-path` | Renders via `helm template`, runs the 43 K8S-* rules on the result, plus 10 chart-supply-chain rules (`HELM-001`--`010`) read straight off `Chart.yaml` / `Chart.lock`. Requires `helm` (Helm 3) on PATH. |
| **OCI image manifest** | `docker buildx imagetools inspect --raw <ref>` JSON | `--oci-manifest` | 15 checks (`OCI-001`--`008` plus `ATTEST-001..007`): provenance annotations, build attestations (SLSA / SBOM), `image.created` timestamp, foreign-layer URL refs, license annotation, layer-count hygiene, legacy schemaVersion 1, weak (non-sha256) digest, builder identity, source-repo claim, SBOM floating versions, resolved-dependencies coverage, in-toto Statement subject binding, meaningful SLSA `buildType`, SBOM package supplier / originator attribution |
| **SCM (GitHub / GitLab / Bitbucket)** | Platform REST API (`--scm-platform github\|gitlab\|bitbucket --scm-repo …`) | `--scm-repo` | 47 checks (`SCM-001`--`047`). GitHub: full pack — branch protection presence / required reviews / required status checks / signed commits / force-push denial / deletion denial / admin enforcement; CODEOWNERS reviews + file presence / stale-review dismissal / conversation resolution / last-push approval; default code scanning, secret scanning + push protection, Dependabot security updates, private vulnerability reporting; PR-review bypass allowance + push-restriction allowlist auditing; Actions governance (default workflow token scope, self-approval, allowed-actions allowlist); deployment-environment protection (required reviewers, branch policy); write-enabled deploy keys; webhook security (HTTP transport, TLS verification, HMAC secret); outside-collaborator elevated-permissions audit; private-repo fork-policy; ruleset enforcement / always-bypass / PR-review-presence / status-checks / force-push denial / deletion / signed-commits / stale-review dismissal / linear-history / required-workflows / code-scanning-gate / deployment-env-gate (full ruleset analog of legacy branch protection plus history-shape hygiene, scan-removal-resistant CI gating, code-scanning-results merge gating, and per-PR deployment-env smoke-test gating); auto-merge enabled. GitLab and Bitbucket: 7-rule universal subset (`SCM-001/002/006/007/008/009/017`). Hermetic mode: `--scm-fixture-dir DIR` reads JSON responses from disk instead of hitting the network. |
| **Package registries (npm / pypi)** | **npm:** `package.json` / `package-lock.json` / `npm-shrinkwrap.json` / `.npmrc`. **pypi:** `requirements*.txt` / `*.in`. | `--npm-path` / `--pypi-path` | **npm: 10 checks (`NPM-001`--`009` plus `NPM-011`)** — floating version ranges, lockfile entries missing `integrity`, non-registry sources (git+ssh, http://, git+https without 40-char SHA pin), install-time lifecycle scripts (`preinstall` / `install` / `postinstall` / `prepare`), git deps using mutable refs, known-compromised package versions (curated `_compromised_packages.py` registry seeded with event-stream / ua-parser-js / coa / rc / node-ipc), `.npmrc` missing or disabling `ignore-scripts=true` (the file-side complement to DF-024), cooldown gate for direct deps published within the last N days (opt-in via `--resolve-remote`, catches Shai-Hulud-style takedown-window attacks), new transitive dependency added since `--npm-base-ref` (catches axios → plain-crypto-js-style payload sneaked into a patch bump), and `package.json` `files` field listing secret-shaped paths (`.env`, `.npmrc`, `*.pem`, SSH keys, AWS credentials). Skips `node_modules/`. **pypi: 7 checks (`PYPI-001`--`006` plus `PYPI-008`)** — requirements lines missing `==` pin, files missing `--require-hashes` / per-line `--hash=`, HTTP indexes (`-i http://`, `--trusted-host`), VCS deps without 40-char commit SHA, `--extra-index-url` (dependency-confusion vector), known-compromised package versions (curated registry seeded with ctx 0.2.2-0.2.8 / requests-darwin-lite 2.27.1), and cooldown gate for direct exact-pin requirements published within the last N days (opt-in via `--resolve-remote`). `*.in` (pip-tools input) exempt from PYPI-001/002 since hashing lives in the compiled output. |
| **Maven** | `pom.xml` / `settings.xml` | `--maven-path` | 8 checks (`MVN-001`--`008`) — floating Maven version ranges (`[1.0,2.0)`, `LATEST`, `RELEASE`), mutable `-SNAPSHOT` dependencies, plaintext-HTTP repository URLs, dependencies missing `<version>` (silently resolved by parent BOMs), lax `<checksumPolicy>` on non-Central repositories (Maven's default `warn` continues on tampered jars), known-compromised Maven Central versions (curated registry seeded with Log4Shell / Spring4Shell / Text4Shell), `<settings.xml>` `<mirrorOf>*</mirrorOf>` wildcard mirrors, and cooldown gate for direct deps published within the last N days (opt-in via `--resolve-remote`). `<dependencyManagement>` entries are surfaced separately from real consumption so version-management blocks don't trigger consumption-side rules. Property substitution (`${log4j.version}`) is resolved against the POM's `<properties>` before each rule evaluates. Skips `target/` and `.m2/`. |

Each CI provider checks for: dependency pinning, script injection, credential
leaks, deploy approval gates, artifact signing, SBOM generation, Docker
security, package integrity, timeout enforcement, vulnerability scanning, TLS
verification, and more. The Kubernetes provider focuses on workload posture
(image digest pinning, securityContext, hostPath / host-namespace exposure,
RBAC blast radius, Secret hygiene). The Helm provider renders charts via
`helm template` and runs the Kubernetes rule pack on the result, plus ten
chart-supply-chain rules (`HELM-001`--`010`: legacy `apiVersion: v1`,
missing `Chart.lock` digests, non-HTTPS dependency / home / sources URLs,
non-pinned dependency versions, missing maintainers / description /
appVersion, missing `kubeVersion` range, stale `Chart.lock` > 90 days)
read straight off the on-disk chart files. See [docs/providers/](docs/providers/)
for the full per-check reference.

---

## ⚙️ How it works

```
                 +-----------+
  Config files   |  Scanner  |   840+ checks across 23 providers
  or live APIs ---->         +---> Findings (check_id, severity, resource)
                 +-----------+
                       |
                 +-----------+
                 |  Scorer   |   Severity-weighted: CRITICAL=20, HIGH=10, MED=5, LOW=2
                 |           +---> Score 0-100, Grade A/B/C/D
                 +-----------+
                       |
                 +-----------+
                 |   Gate    |   --fail-on, --min-grade, --max-failures, --baseline
                 |           +---> Exit 0 (pass) or 1 (fail)
                 +-----------+
                       |
                 +-----------+
                 | Reporter  |   Terminal, JSON, HTML, SARIF 2.1.0
                 +-----------+
```

Every finding is annotated with compliance controls from all enabled
standards, so a single scan satisfies multiple audit frameworks.

---

## ⭐ Key features

| Feature | Description |
|---------|-------------|
| **Autofix** | `--fix` emits unified-diff patches; `--fix --apply` writes in place. 111 fixers cover script injection, secrets, timeouts, pinning, Docker flags, TLS, Kubernetes securityContext, Cloud Build options, Helm chart-supply-chain TODOs, and more. |
| **CI gate** | `--fail-on HIGH`, `--min-grade B`, `--max-failures 5`, `--fail-on-check GHA-002`. Any condition trips exit 1. |
| **Baselines** | `--baseline prior.json` or `--baseline-from-git origin/main:report.json`. Only gate on *new* findings. |
| **Diff-mode** | `--diff-base origin/main` scans only files changed by the branch. |
| **PR diff** | `--pr-diff origin/main` re-scans both sides and emits a Markdown PR-comment summarizing which findings the branch introduced, resolved, or preserved. Multiset fingerprint on `(check_id, resource)` so line shifts on unchanged code don't surface as new. Combine with `--fail-on HIGH` to gate the PR on *introduced* findings only. See [docs/pr_diff.md](docs/pr_diff.md). |
| **Suppressions** | `.pipelinecheckignore` (flat or YAML with `expires:` dates). |
| **Custom secrets** | `--secret-pattern '^acme_[a-f0-9]{32}$'` extends the credential scanner. |
| **Glob selection** | `--checks 'GHA-*'` or `--checks '*-008'` to scope checks. |
| **Standard audit** | `--standard-report nist_ssdf` prints the control-to-check matrix and coverage gaps. |
| **Custom rule DSL** | `--custom-rules PATH` loads YAML-defined rules that run alongside the built-in catalog. Supports GHA, GitLab, Bitbucket, Azure, CircleCI, Cloud Build, Kubernetes, and Helm. Rule shape: `for_each:` jsonpath + `assert:` predicate (`eq` / `regex` / `exists` / `len_gt` / `all_of` / `not` / …). Findings flow through the same scoring, gating, and SARIF as built-ins. See [docs/writing_a_custom_rule.md](docs/writing_a_custom_rule.md). |
| **Component inventory** | `--inventory` emits the list of resources / workflows / templates the scanner discovered, with per-type metadata (encryption, runtime, tags, lifecycle policies). Filter with `--inventory-type 'AWS::IAM::*'`; skip checks entirely with `--inventory-only`. Feeds asset-register dashboards and drift detectors. |
| **STRIDE threat model** | `--output threatmodel` emits a self-contained Markdown threat-model document populated from the scan + inventory: assets, trust boundaries, findings grouped by STRIDE category, implemented controls, top-25 risk register. Mapping is derived from each rule's existing OWASP / CWE tags so re-policing is one table swap. Shaped for SOC 2 / PCI / NIST SSDF evidence packages. |
| **MCP server** | `pipeline_check --serve` runs as a Model Context Protocol server on stdio so AI clients (Claude Desktop, Claude Code, Cursor, Continue, Zed) can drive scans and introspect the rule catalog directly. Ten tools advertised: scan / inventory / explain_check / list_chains / threat_model / etc. The `mcp` SDK is an optional `[mcp]` extra so the default install stays slim. See [docs/mcp.md](docs/mcp.md). |
| **Editor diagnostics (LSP)** | `python -m pipeline_check.lsp` is the Language Server backing the Pipeline-Check VS Code extension ([source](https://github.com/greylag-ci/pipeline-check-vscode) · [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=greylag-ci.pipeline-check) · [Open VSX](https://open-vsx.org/extension/greylag-ci/pipeline-check)). Same rule registry the CLI uses, surfaced inline as you edit `.github/workflows/`, `.gitlab-ci.yml`, `azure-pipelines.yml`, `bitbucket-pipelines.yml`, `.circleci/`, `cloudbuild.yaml`, `.buildkite/`, `.drone.yml`, `Jenkinsfile`, and `Dockerfile`. Each diagnostic carries the rule ID, severity, the dynamic recommendation, and a `codeDescription` link straight to the per-rule docs page. `pygls` is an optional `[lsp]` extra so the default install stays slim. |
| **Multi-scanner SARIF ingest** | `--ingest <file>.sarif` (repeatable) absorbs findings from Trivy / Checkov / Snyk / KICS / CodeQL / any conformant scanner. External rules become `INGEST-<tool>-<rule-id>` `Finding` rows; the chain engine RE-EVALUATES over the union, so cross-tool chains (e.g. `XPC-009` — ingested CVE finding + `DF-001` mutable runtime image) fire on compositions no individual scanner would surface. Caps: 25 MiB / 5,000 results per file. |
| **Vulnerable-by-design benchmark** | Two complementary regression gates. `bench/cases/` is a synthetic set (one minimal fixture per attack pattern, gated at 100% recall in CI). `bench/goats/` is the real-world phase: pinned clones of [cicd-goat](https://github.com/cider-security-research/cicd-goat) (GHA + 7 Jenkinsfiles), [cfngoat](https://github.com/bridgecrewio/cfngoat), and [kubernetes-goat](https://github.com/madhuakula/kubernetes-goat), scanned via the same CLI a user runs, with hand-curated `expected.txt` locking **42 check IDs** across the three goats — each tied to a documented challenge or CIS benchmark control. The bench workflow runs nightly on master and on every PR that touches the rule pack; uploads a `goat-bench-report` artifact and posts a sticky PR comment. `python bench/goat_runner.py --markdown` reproduces locally. See [docs/goat_bench.md](docs/goat_bench.md). |

---

## 📤 Output formats

```bash
pipeline_check --output terminal            # rich table to stdout (default)
pipeline_check --output json                # machine-readable JSON
pipeline_check --output html --output-file report.html       # self-contained HTML
pipeline_check --output sarif --output-file scan.sarif       # SARIF 2.1.0 for GitHub/GitLab
pipeline_check --output junit --output-file junit.xml        # JUnit XML for test-runner UIs
pipeline_check --output markdown            # PR-comment shape (GFM)
pipeline_check --output threatmodel --output-file threats.md # STRIDE threat model
pipeline_check --output both                # terminal on stderr + JSON on stdout
```

---

## 🔁 CI integration

### GitHub Actions

The marketplace action wraps install, scan, gate, and SARIF upload in
one step. Findings show up in the GitHub Security tab.

```yaml
permissions:
  contents: read
  security-events: write   # required by upload-sarif

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dmartinochoa/pipeline-check@v1
        with:
          pipeline: auto       # or: github, gitlab, terraform, k8s, ...
          fail-on: HIGH
```

Inputs (all optional): `pipeline`, `path`, `fail-on`, `min-grade`,
`max-failures`, `severity-threshold`, `baseline`, `baseline-from-git`,
`diff-base`, `standard`, `output`, `output-file`, `upload-sarif`,
`pipeline-check-version`, `python-version`, `resolve-remote`,
`extra-args`. Outputs: `exit-code`, `findings-count`, `failed-count`,
`score`, `grade`, `sarif-file`. See [`action.yml`](action.yml) for the
full surface.

For PR review comments on the changed lines, see the companion
[pipeline-check-pr action](.github/actions/pipeline-check-pr/README.md).
For a single delta-shaped PR comment ("this branch added 3 HIGH
findings, resolved 1, preserved 12"), use
[`--pr-diff`](docs/pr_diff.md).

For finer control, the manual three-step form still works:

```yaml
- run: pip install pipeline-check
- run: pipeline_check --pipeline github --output sarif --output-file pipeline-check.sarif --fail-on HIGH
- if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: pipeline-check.sarif
```

### GitLab CI

```yaml
security-scan:
  script:
    - pip install pipeline-check
    - pipeline_check --pipeline gitlab --fail-on HIGH --output json > report.json
  artifacts:
    reports:
      sast: report.json
```

### Any CI system

```bash
# Gate on grade
pipeline_check --pipeline github --min-grade B

# Gate on new findings only (baseline diff)
pipeline_check --pipeline github --fail-on HIGH \
  --baseline-from-git origin/main:baseline.json
```

Exit codes: `0` = pass, `1` = gate failed, `2` = scanner error, `3` = config error.

### Pre-commit

`pipeline_check` ships hook definitions for the [pre-commit](https://pre-commit.com)
framework. Each hook is scoped to one provider so a Dockerfile change
doesn't run the GitHub Actions scanner. Enable just the hooks for the
providers your repo ships through:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/dmartinochoa/pipeline-check
    rev: v1.0.4   # pin to a release tag
    hooks:
      - id: pipeline-check-github
      - id: pipeline-check-dockerfile
```

All hooks default to `--fail-on HIGH`. Override with `args:` for a softer
gate (e.g. `args: [--fail-on, CRITICAL]`).

---

## 🛠️ Configuration

Every CLI flag can be set in `pyproject.toml`, `.pipeline-check.yml`, or
environment variables. Precedence: CLI > env > file > defaults.

```toml
# pyproject.toml
[tool.pipeline_check]
pipeline = "github"
severity_threshold = "MEDIUM"

[tool.pipeline_check.gate]
fail_on = "HIGH"
baseline = "artifacts/baseline.json"
ignore_file = ".pipelinecheckignore"
```

Full reference: [docs/config.md](docs/config.md).

---

## 📋 Compliance standards

Each finding is tagged with controls from all enabled frameworks. One scan
covers multiple audits.

| Standard | Version | Coverage |
|----------|---------|----------|
| [OWASP Top 10 CI/CD Security Risks](docs/standards/owasp_cicd_top_10.md) | 2022 | 10/10 risks |
| [SLSA Build Track](docs/standards/slsa.md) | 1.0 | 6/7 levels (413 check mappings) |
| [NIST SSDF (SP 800-218)](docs/standards/nist_ssdf.md) | v1.1 | CI/CD subset |
| [NIST SP 800-53](docs/standards/nist_800_53.md) | Rev. 5 | CI/CD subset |
| [NIST SP 800-190](docs/standards/nist_800_190.md) | 2017 | Container CI/CD subset |
| [NIST CSF 2.0](docs/standards/nist_csf_2.md) | 2.0 | CI/CD subset |
| [CIS Software Supply Chain](docs/standards/cis_supply_chain.md) | 1.0 | CI/CD subset |
| [CIS AWS Foundations](docs/standards/cis_aws_foundations.md) | 3.0.0 | CI/CD subset |
| [CIS Kubernetes Benchmark](docs/standards/cis_kubernetes.md) | 1.10 | Section 5 (Policies) |
| [CIS GitHub Benchmark](docs/standards/cis_github.md) | 1.1.0 | Sections 1.1, 1.4, 1.5 |
| [PCI DSS v4.0](docs/standards/pci_dss_v4.md) | 4.0 | CI/CD subset |
| [SOC 2 Trust Services Criteria](docs/standards/soc2.md) | 2017 (rev. 2022) | CC6/CC7/CC8 subset |
| [NSA/CISA ESF Supply Chain](docs/standards/esf_supply_chain.md) | 2022 | CI/CD subset |
| [OpenSSF Scorecard](docs/standards/openssf_scorecard.md) | v5 | CI/CD subset |
| [Microsoft S2C2F](docs/standards/s2c2f.md) | 2024-05 | CI/CD subset |

```bash
# Explore a standard's control-to-check matrix
pipeline_check --standard-report slsa

# Restrict a scan to specific standards
pipeline_check --standard owasp_cicd_top_10 --standard nist_ssdf
```

Standards are pure data. Adding SOC 2 or an internal policy is one Python module.
See [docs/standards/](docs/standards/).

---

## 💻 CLI reference

| Flag | Default | Description |
|------|---------|-------------|
| `--pipeline` / `-p` | `auto` | `auto` (detect from cwd), `aws`, `terraform`, `cloudformation`, `github`, `gitlab`, `bitbucket`, `azure`, `jenkins`, `circleci`, `cloudbuild`, `buildkite`, `drone`, `tekton`, `argo`, `dockerfile`, `kubernetes`, `helm`, `oci`, `scm`, `npm`, `pypi`, `maven` |
| `--pipelines` | | Comma-separated multi-provider list (e.g. `--pipelines github,oci`). Mutually exclusive with `--pipeline`. Activates cross-provider attack chains (`XPC-NNN`) by evaluating the chain engine over the union of every sub-scan's findings. |
| `--output` / `-o` | `terminal` | `terminal`, `json`, `html`, `sarif`, `junit`, `markdown`, `threatmodel`, `both` |
| `--output-file` / `-O` | | Required with `html`; optional with `sarif` / `junit` / `markdown` / `threatmodel` |
| `--fail-on` / `-f` | | Fail if any finding >= severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) |
| `--min-grade` | | Fail if grade worse than `A`/`B`/`C`/`D` |
| `--max-failures` | | Fail if > N effective findings |
| `--fail-on-check` | | Fail if named check fails (repeat for multiple) |
| `--baseline` | | Prior JSON report; existing findings don't gate |
| `--baseline-from-git` | | `REF:PATH`. Resolves baseline via `git show` |
| `--write-baseline` | | Write the current scan's failing findings to PATH as JSON. Pair with `--baseline PATH` on subsequent runs to gate only on new issues. |
| `--policy` | | Load a named scan profile from `./policies/<NAME>.yml` (or `./.pipeline-check/policies/<NAME>.yml`). Bundles a rule filter, standards filter, gate thresholds, and per-rule severity overrides into one file. CLI flags and config keep overriding policy values. |
| `--list-policies` | | List every discoverable policy file and exit. |
| `--ignore-file` | `.pipelinecheckignore` | Suppressions (flat or YAML with `expires:`) |
| `--diff-base` | | Only scan files changed vs this git ref |
| `--fix` | | Emit unified-diff patches to stdout |
| `--apply` | | With `--fix`, write patches in place |
| `--checks` / `-c` | all | Check ID(s) or globs (`GHA-*`, `*-008`) |
| `--severity-threshold` | `INFO` | Minimum severity to display |
| `--secret-pattern` | | Extra regex for credential scanning (repeat) |
| `--custom-rules` | | YAML rule file or directory of rule files; loaded alongside the built-in catalog (repeatable) |
| `--standard` | all | Standard(s) to annotate findings with |
| `--standard-report` | | Print control-to-check matrix and exit |
| `--inventory` | | Emit scanned-component inventory alongside findings |
| `--inventory-type` | | Glob pattern to scope inventory by type (repeatable, implies `--inventory`) |
| `--inventory-only` | | Skip checks; emit inventory only (implies `--inventory`) |
| `--ingest` | | SARIF 2.1.0 file from another scanner (Trivy, Checkov, Snyk, KICS, CodeQL, …). External rules become `INGEST-<tool>-<rule-id>` findings; chain engine re-evaluates over the union. Repeatable. |
| `--scm-platform` | | SCM platform for `--pipeline scm`: `github` (full 47-rule pack), `gitlab`, or `bitbucket` (each gets a 7-rule universal subset) |
| `--scm-repo` | | Repository to scan: `owner/name` (GitHub), `group/subgroup/project` (GitLab — nested subgroups OK), or `workspace/repo_slug` (Bitbucket Cloud) |
| `--scm-fixture-dir` | | Read SCM API responses from JSON files under DIR instead of hitting the network. Useful for offline tests / CI runs without a token. |
| `--gh-token` | `$GITHUB_TOKEN` | Token for the GHA reusable-workflow resolver and the SCM provider's REST API calls |
| `--resolve-remote` | | Follow remote `uses:` refs (reusable workflows + composite actions) over HTTPS. Off by default; opt in to take on the network surface. |
| `--config` | auto | Config file path (TOML or YAML) |
| `--config-check` | | Validate config, exit non-zero on unknown keys |
| `--man [TOPIC]` | | Extended docs (`gate`, `autofix`, `diff`, `secrets`, `standards`, `config`, `output`, `inventory`, `lambda`, `recipes`, `explain`) |
| `--region` / `-r` | `us-east-1` | AWS region |
| `--profile` | | AWS CLI named profile |
| `--verbose` / `-v` | | Debug output to stderr |
| `--quiet` / `-q` | | Suppress all output; exit code only |
| `--no-group` | | Render every finding on its own row. By default the terminal table collapses repeated `(check_id, resource)` failures into one row plus a `+N similar` summary line. JSON / SARIF / JUnit outputs always carry every finding regardless. |
| `--version` | | Print version |

Provider-specific path flags (`--gha-path`, `--gitlab-path`, `--bitbucket-path`, `--cfn-template`,
`--azure-path`, `--jenkinsfile-path`, `--circleci-path`, `--tf-plan`,
`--cloudbuild-path`, `--buildkite-path`, `--drone-path`, `--tekton-path`, `--argo-path`,
`--dockerfile-path`, `--k8s-path`, `--helm-path`, `--oci-manifest`) are
auto-detected from the working directory when omitted. The Helm provider also
takes `--helm-values FILE` and `--helm-set KEY=VALUE` (both repeatable),
forwarded to `helm template`. The SCM provider is API-only and takes
`--scm-platform github --scm-repo owner/name` (plus `--gh-token` or
`$GITHUB_TOKEN`); no on-disk path flag.

Subcommands:

- **`pipeline_check init`** runs one scan against the auto-detected
  pipeline, writes `.pipeline-check-baseline.json` capturing current
  failing findings, and emits `.pipeline-check.yml` with a recommended
  `gate.fail_on` and a baseline pointer so future CI runs only block on
  *new* regressions. Prints a "top 5 to fix" summary to stderr. Pass
  `--no-scan` for the legacy commented-out scaffold, `--path PATH` to
  redirect the output, or `--force` to overwrite an existing file.
- **`pipeline_check explain CHECK_ID`** prints the full per-check
  reference (severity, recommendation, controls, autofix availability,
  related rules, attack chains). Equivalent to
  `pipeline_check --explain CHECK_ID`; the subcommand form is more
  discoverable and is what the smart-init top-5 summary and the
  gate-failure trailer point users at. Exit code `0` on a known ID,
  `3` on an unknown ID with a "did you mean" list.

---

## 🏛️ Architecture

```
pipeline_check/
├── cli.py                     # Click CLI
├── lambda_handler.py          # AWS Lambda entry point
└── core/
    ├── scanner.py             # Provider-agnostic orchestrator
    ├── scorer.py              # Severity-weighted scoring (A/B/C/D)
    ├── gate.py                # CI gate (pass/fail thresholds + baselines)
    ├── autofix/               # 111 fixers (text-based, comment-preserving)
    ├── reporter.py            # Terminal + JSON
    ├── html_reporter.py       # Self-contained HTML
    ├── sarif_reporter.py      # SARIF 2.1.0
    ├── config.py              # TOML/YAML/env config loader
    ├── providers/             # One module per provider (register + go)
    ├── standards/data/        # One module per compliance standard
    └── checks/
        ├── base.py            # Finding, Severity, shared detection patterns
        ├── aws/rules/         # 71 rule-based checks (CB, CP, CD, ECR, IAM, PBAC, S3, CT, CWL, SM, CA, CCM, LMB, KMS, SSM, EB, SIGN, CW)
        ├── terraform/         # AWS-parity checks against plan JSON
        ├── cloudformation/    # AWS-parity checks against CFN templates (YAML/JSON)
        ├── github/rules/      # GHA-001 .. GHA-065, GHA-086..087 + TAINT-001..003
        ├── gitlab/rules/      # GL-001 .. GL-035 + TAINT-004 / TAINT-008
        ├── bitbucket/rules/   # BB-001 .. BB-031
        ├── azure/rules/       # ADO-001 .. ADO-030
        ├── jenkins/rules/     # JF-001 .. JF-035
        ├── circleci/rules/    # CC-001 .. CC-031
        ├── cloudbuild/rules/  # GCB-001 .. GCB-026
        ├── buildkite/rules/   # BK-001 .. BK-015 + TAINT-005
        ├── drone/rules/       # DR-001 .. DR-011
        ├── tekton/rules/      # TKN-001 .. TKN-015 + TAINT-006
        ├── argo/rules/        # ARGO-001 .. ARGO-015 + TAINT-007
        ├── argocd/rules/      # ARGOCD-001 .. ARGOCD-009
        ├── oci/rules/         # OCI-001 .. OCI-008 + ATTEST-001..007
        ├── dockerfile/rules/  # DF-001 .. DF-030
        ├── kubernetes/rules/  # K8S-001 .. K8S-043
        ├── helm/rules/        # HELM-001 .. HELM-010 + renders charts so the K8S rule pack also applies
        ├── scm/rules/         # SCM-001 .. SCM-047 — repo governance via the platform REST API (GitHub full pack incl. Actions governance + environment protection + deploy-keys + webhook security + outside-collaborator audit + private-repo fork policy + ruleset enforcement / always-bypass / PR-review / status-checks / force-push / deletion / signed-commits / stale-review dismissal / linear-history / required-workflows / code-scanning-gate / deployment-env-gate / merge-queue + auto-merge audit + tag-ruleset signing + admin-bypass-on-signing + default-scanning query-suite / paused / language-coverage; GitLab + Bitbucket universal subset)
        ├── npm/rules/         # NPM-001 .. NPM-008 + NPM-011 — package.json + package-lock.json + .npmrc supply-chain hygiene + curated compromised-package registry + files-field secret-leak detector + cooldown gate
        ├── pypi/rules/        # PYPI-001 .. PYPI-008 — requirements.txt supply-chain hygiene + curated compromised-package registry + cooldown gate
        ├── maven/rules/       # MVN-001 .. MVN-008 — pom.xml + settings.xml supply-chain hygiene + curated compromised-package registry (Log4Shell / Spring4Shell / Text4Shell) + cooldown gate
        └── custom/            # YAML rule loader + predicate engine
```

Adding a new check is a one-file change. Adding a new provider is three files.
See [docs/providers/](docs/providers/) for the full pattern.

---

## 🐍 Python API

Embed pipeline-check in your own tooling without `subprocess` + JSON
parsing. The top-level surface is small and stable across minor
releases:

```python
from pipeline_check import Scanner, Severity, score

scanner = Scanner(pipeline="github", gha_path=".github/workflows")
findings = scanner.run()

critical = [
    f for f in findings
    if not f.passed and f.severity is Severity.CRITICAL
]
result = score(findings)
print(f"score={result['score']} grade={result['grade']}")
```

Public surface: `Scanner`, `Finding`, `Severity`, `Confidence`,
`ControlRef`, `score`, `ScoreResult`, `Chain`, `ChainRule`,
`evaluate_chains`, `list_chain_rules`, `available_providers()`,
`available_standards()`, `load_custom_rules()`, `LoadedCustomRules`,
`CustomRuleError`, `__version__`. Anything reached through
`pipeline_check.core.*` is internal and may move between releases.

---

## ☁️ Lambda deployment

Pipeline-Check can run as an AWS Lambda for scheduled scans.
Run `pipeline_check --man lambda` for packaging, IAM permissions, event
payload shapes, and SNS alerting.

---

## 🔌 Extending

**New check:** Drop a module in `checks/<provider>/rules/` exporting `RULE`
and `check()`. The orchestrator auto-discovers it.

**New provider:** Subclass `BaseProvider`, register in `providers/__init__.py`.
Available via `--pipeline <name>` immediately.

**New standard:** Add a Python module under `standards/data/` with a
`STANDARD` object. The CLI and reporters pick it up automatically.

See [docs/providers/README.md](docs/providers/README.md) for the full contract.

---

## 🔐 Verifying a release

Every tagged release publishes two attestations.

**PyPI PEP 740 attestations** are produced at publish time and
visible on the project's PyPI page (`pypi.org/project/pipeline-check/`).
`pip install` and recent `uv` versions pick these up automatically;
no extra tooling needed. This is the recommended surface for most
users.

**SLSA Build L3 provenance** is generated by the
`slsa-framework/slsa-github-generator` reusable workflow running in
GitHub's isolated builder, signed via Sigstore using a short-lived
OIDC token. Starting with v1.0.4 the provenance file
(`pipeline-check.intoto.jsonl`) is uploaded as a workflow run
artifact rather than attached to the GitHub release (the repo runs
with immutable releases on, which the SLSA generator's release-asset
upload step can't co-exist with). Use this path when you need the
stronger build-time guarantee that the wheel came from this repo at
the tagged commit, in CI, by this project's workflow.

```bash
# 1. Install slsa-verifier (one-off).
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@v2.7.0

# 2. Find the release.yml workflow run that built the version you want.
TAG=v1.0.4
RUN_ID=$(gh run list \
  --repo dmartinochoa/pipeline-check \
  --workflow release.yml \
  --status success \
  --json databaseId,headBranch,event,headSha \
  --jq "first(.[] | select(.headBranch == \"$TAG\" or .event == \"workflow_dispatch\")).databaseId")

# 3. Download the wheel and the matching provenance file.
gh run download "$RUN_ID" \
  --repo dmartinochoa/pipeline-check \
  --name dist \
  --name pipeline-check.intoto.jsonl

# 4. Verify. slsa-verifier checks the attestation's Sigstore
#    signature, the source repo, and the source tag against the
#    builder's claims.
slsa-verifier verify-artifact dist/pipeline_check-*.whl \
  --provenance-path pipeline-check.intoto.jsonl \
  --source-uri github.com/dmartinochoa/pipeline-check \
  --source-tag "$TAG"

# 5. Once verification passes, install the verified wheel directly.
pip install dist/pipeline_check-*.whl
```

A passing verification means: the wheel was built by this project's
own `release.yml` workflow, at the tagged commit, in GitHub's
isolated SLSA builder, and the bytes you have on disk match the
ones the builder signed. Skip this step and you trust PyPI, the
network, and every cache in between.

---

## 🤝 Contributing

PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup,
the test / lint / mypy commands CI runs, the rule-addition
workflow, and the commit / PR conventions. Project-wide conventions
(American English, generated docs, release process) live in
[CLAUDE.md](CLAUDE.md). Security issues: follow
[SECURITY.md](SECURITY.md), not the public issue tracker.

---

## 📜 License

MIT. See [LICENSE](LICENSE).


