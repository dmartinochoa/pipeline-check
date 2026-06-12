# GitHub Actions provider

Parses workflow YAML files under a `.github/workflows` directory. No
GitHub API token or installed Actions runner is required by default;
the scanner stays read-from-disk-only unless `--resolve-remote` opts
in to fetching reusable-workflow callees over HTTPS.

## Producer workflow

```bash
# --gha-path is auto-detected when .github/workflows exists at cwd;
# the CLI announces the pick on stderr.
pipeline_check --pipeline github

# …or pass it explicitly.
pipeline_check --pipeline github --gha-path .github/workflows
```

A single workflow file can also be passed directly:

```bash
pipeline_check --pipeline github --gha-path .github/workflows/release.yml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the AWS and Terraform providers.

## Reusable workflow resolution

`jobs.<id>.uses: owner/repo/.github/workflows/x.yml@<sha>` references
a workflow body that runs with the *caller's* `GITHUB_TOKEN` and
secrets. By default the scanner stops at the call site (it flags the
ref via `GHA-025` when unpinned and emits a one-line nudge listing
how many remote refs were skipped); `--resolve-remote` opts in to
fetching the called body and running the full GHA rule pack against
it with the caller's permissions context.

```bash
# Fetch via raw.githubusercontent.com (works for public repos).
pipeline_check --pipeline github --resolve-remote

# Private callees: pass a token, or set $GITHUB_TOKEN.
pipeline_check --pipeline github --resolve-remote --gh-token "$GH_PAT"

# Fully offline: search a sibling on-disk checkout instead.
pipeline_check --pipeline github --resolve-remote \
    --gha-search-path ../shared-workflows
```

Resolution rules:

- **Only SHA-pinned refs are fetched.** A tag-pinned ref (`@v1`,
  `@main`) is skipped with a warning, resolution against a movable
  upstream tag would defeat `GHA-025`'s value.
- **Recursion** follows transitive `uses:` calls to a depth of 3
  (configurable with `--gha-resolve-depth`; hard ceiling 10). Cycles
  are detected.
- **Cache.** Fetched bodies live under
  `~/.cache/pipeline-check/gha-resolver/` for 7 days. Use `--no-cache`
  to bypass.
- **Failure mode.** Network errors, 404s, and malformed YAML never
  abort the scan. They land in the context's warnings stream.
- **Attribution.** Findings on a resolved callee carry a synthetic
  `<caller-path> -> <owner>/<repo>/<path>@<ref>` resource string so
  the report points at both the call site and the upstream body.
- **Permissions inheritance.** A callee without its own
  `permissions:` runs with the caller's; `GHA-004` doesn't fire on a
  callee whose caller declared one.
- **`secrets: inherit`.** When the call site passes
  `secrets: inherit`, `GHA-019` annotates findings with the inherit
  note so report readers see the full credential surface.

## What it covers

114 checks · 20 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [GHA-001](#gha-001) | Action not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-002](#gha-002) | pull_request_target checks out PR head | <span class="pg-sev pg-sev--critical">CRITICAL</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-003](#gha-003) | Script injection via untrusted context | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-004](#gha-004) | Workflow permissions block missing or overprovisioned | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-005](#gha-005) | AWS auth uses long-lived access keys | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-006](#gha-006) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-007](#gha-007) | SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-008](#gha-008) | Credential-shaped literal in workflow body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-009](#gha-009) | workflow_run downloads upstream artifact unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GHA-010](#gha-010) | Local action (./path) on untrusted-trigger workflow | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-011](#gha-011) | Cache key derives from attacker-controllable input | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-012](#gha-012) | Self-hosted runner without ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-013](#gha-013) | issue_comment trigger without author guard | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-014](#gha-014) | Deploy job missing environment binding | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-015](#gha-015) | Job has no `timeout-minutes`, unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-016](#gha-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-017](#gha-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-018](#gha-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-019](#gha-019) | GITHUB_TOKEN written to persistent storage | <span class="pg-sev pg-sev--critical">CRITICAL</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-020](#gha-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-021](#gha-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-022](#gha-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-023](#gha-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-024](#gha-024) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-025](#gha-025) | Reusable workflow not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-026](#gha-026) | Container job disables isolation via `options:` | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-027](#gha-027) | Workflow contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GHA-028](#gha-028) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-029](#gha-029) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-030](#gha-030) | OIDC token requested without environment-protected job | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-031](#gha-031) | Workflow uses retired set-output / save-state command | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-032](#gha-032) | run: invokes local script on untrusted-trigger workflow | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GHA-033](#gha-033) | Secret value echoed / printed in a run: block | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GHA-034](#gha-034) | Reusable workflow called with secrets: inherit | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-035](#gha-035) | github-script step interpolates untrusted context | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-036](#gha-036) | runs-on interpolates untrusted context | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-037](#gha-037) | actions/checkout persists GITHUB_TOKEN into .git/config | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-038](#gha-038) | Workflow re-enables retired ::set-env / ::add-path commands | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GHA-039](#gha-039) | services / container credentials embedded as literal in workflow | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GHA-040](#gha-040) | Action reference matches a known-compromised SHA or tag | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GHA-041](#gha-041) | Action upstream repo has a single contributor | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-042](#gha-042) | Action upstream repo is newly created | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-043](#gha-043) | Low-star action runs with sensitive permissions | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-044](#gha-044) | Build tool runs lifecycle scripts on untrusted-trigger workflow | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-045](#gha-045) | Caller-controlled ref input feeds actions/checkout | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-046](#gha-046) | Manual PR-head fetch on untrusted-trigger workflow | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GHA-047](#gha-047) | Action ref resolves to a recently committed tag or SHA | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-048](#gha-048) | Workflow step writes a file under .github/workflows/ | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GHA-049](#gha-049) | Workflow step makes a privileged git write (cross-repo or actions[bot] bypass) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-050](#gha-050) | Publish step relies on long-lived registry token | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-051](#gha-051) | services / container image is not pinned by digest | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-052](#gha-052) | actions/cache key includes untrusted PR-controllable input | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-053](#gha-053) | if: predicate evaluates attacker-controllable context as expression | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-054](#gha-054) | actions/checkout with ssh-key persists SSH credential in repo | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-055](#gha-055) | Reusable workflow outputs derive a secret or caller-input value | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-056](#gha-056) | Workflow body contains a known supply-chain worm indicator | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GHA-057](#gha-057) | Secret-scanner output sent to network egress | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GHA-058](#gha-058) | Agentic CLI invoked with permission-bypass flags | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-059](#gha-059) | npm install without registry-signature verification step | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-060](#gha-060) | pip install without `--require-hashes` verification | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-061](#gha-061) | GitHub App token minted without a `permissions:` filter | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-062](#gha-062) | OIDC subject claim in sibling IaC grants overly broad scope | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-063](#gha-063) | ``if:`` predicate gates on a spoofable bot-actor comparison | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-064](#gha-064) | ``contains()`` invoked with comma-delimited string operand | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-065](#gha-065) | Workflow body contains zero-width or bidi Unicode characters | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GHA-066](#gha-066) | ``actions/upload-artifact`` path is a workspace wildcard | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-067](#gha-067) | ``actions/cache`` writes credential-shaped paths | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-068](#gha-068) | ``runs-on:`` targets an end-of-life hosted-runner image | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-069](#gha-069) | ``id-token: write`` granted without an OIDC-consumer step | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-070](#gha-070) | ``ssh-keyscan`` / disabled host-key check trust-on-first-use | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-071](#gha-071) | ``shell: pwsh`` / ``powershell`` on a Linux / macOS step | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [GHA-072](#gha-072) | Secret in env: at a wider scope than its consumer | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-073](#gha-073) | Reusable workflow declares an unused ``workflow_call`` secret | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-086](#gha-086) | Wildcard branch trigger gates an environment-bound deploy | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-087](#gha-087) | Derived value of a secret printed to the build log | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-088](#gha-088) | Action ``uses:`` slug is a near-edit of a top-traffic action | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-089](#gha-089) | Action upstream repo is archived | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-090](#gha-090) | Action SHA pin references a commit absent from the claimed repo | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-091](#gha-091) | Action upstream repo is missing (takeover-eligible namespace) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-092](#gha-092) | PR head SHA captured then re-fetched (force-push race) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-093](#gha-093) | Living-off-the-Pipeline indicators (workflow-command abuse) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-094](#gha-094) | Action SHA pin matches the current tip of an upstream branch | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-095](#gha-095) | Action SHA pin does not match its version comment | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-096](#gha-096) | Action reference has a known GHSA vulnerability | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-097](#gha-097) | Recursive PR auto-merge loop | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-098](#gha-098) | Pipeline deploys without a security scan gate | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-099](#gha-099) | Deployment job has a secret-shaped plaintext env var | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GHA-100](#gha-100) | ``cosign verify`` without certificate identity binding | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-102](#gha-102) | ``actions/checkout`` with submodule fetch on a PR trigger | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-103](#gha-103) | AI code-review bot on untrusted trigger without environment gate | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GHA-104](#gha-104) | AI agent generates and pushes commits without PR review | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-105](#gha-105) | Self-hosted runner reachable from an untrusted PR trigger | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-106](#gha-106) | AI agent CLI runs with a write-scoped GITHUB_TOKEN | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-107](#gha-107) | harden-runner runs in audit mode (egress not blocked) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-108](#gha-108) | Sensitive workflow has no runtime egress control | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [GHA-109](#gha-109) | harden-runner is not the first step in the job | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [GHA-110](#gha-110) | Workflow disables Go module checksum / sum-db verification | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-111](#gha-111) | AI agent generates IaC applied to the cloud in the same job | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-112](#gha-112) | Self-hosted deploy job not gated by a protected environment | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-113](#gha-113) | OIDC trusted-publishing job without an environment gate | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-114](#gha-114) | Package-publish workflow runs on an unrestricted push trigger | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-115](#gha-115) | ``id-token: write`` granted workflow-wide instead of job-scoped | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-116](#gha-116) | Workflow serializes the entire secrets context (toJSON(secrets)) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-117](#gha-117) | IaC apply on an untrusted pull_request trigger | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GHA-118](#gha-118) | Untrusted content written to $GITHUB_ENV / $GITHUB_PATH | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-119](#gha-119) | Untrusted context reaches an agentic AI CLI (prompt injection) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-120](#gha-120) | ML model loaded with trust_remote_code (code execution) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-121](#gha-121) | AI model pulled without a pinned revision | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-122](#gha-122) | Unsafe deserialization of a fetched artifact (pickle RCE) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-123](#gha-123) | Agentic CLI output lands without human review | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [TAINT-001](#taint-001) | Untrusted input flows across step boundaries via step outputs | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [TAINT-002](#taint-002) | Untrusted input flows across jobs via ``jobs.<id>.outputs:`` | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [TAINT-003](#taint-003) | Untrusted input forwarded into reusable workflow ``with:`` | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [TAINT-009](#taint-009) | Environment-protected secret flows to unprotected job | <span class="pg-sev pg-sev--high">HIGH</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## GHA-001: Action not pinned to commit SHA { #gha-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Every `uses:` reference should pin a specific 40-char commit SHA. Tag and branch refs (`@v4`, `@main`) can be silently moved to malicious commits by whoever controls the upstream repository, a third-party action compromise will propagate into the pipeline on the next run.

**Seen in the wild**

- tj-actions/changed-files compromise ([CVE-2025-30066](https://www.cve.org/CVERecord?id=CVE-2025-30066), March 2025): a malicious commit retagged behind ``@v1`` / ``@v45`` shipped CI-secret exfiltration to roughly 23,000 repos that had pinned the action to a mutable tag instead of a commit SHA.
- reviewdog/action-setup compromise ([CVE-2025-30154](https://www.cve.org/CVERecord?id=CVE-2025-30154), March 2025): same week, similar mechanism. Tag-pinned consumers auto-pulled the malicious version; SHA-pinned consumers were unaffected.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace tag/branch references (`@v4`, `@main`) with the full 40-char commit SHA. Use Dependabot or StepSecurity to keep the pins fresh.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GHA-002: pull_request_target checks out PR head { #gha-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--cwe">CWE-78</span>
</div>

`pull_request_target` runs with a write-scope GITHUB_TOKEN and access to repository secrets, deliberately so, since it's how labeling and comment-bot workflows work. When the same workflow then explicitly checks out the PR head (`ref: ${{ github.event.pull_request.head.sha }}` or `.ref`) it executes attacker-controlled code with those privileges.

**Seen in the wild**

- GitHub Security Lab: [Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/) (2020), the canonical write-up. Demonstrates how a fork PR that lands in a ``pull_request_target`` workflow with the PR head checked out runs in the base repo's privileged context.
- [Keeping your GitHub Actions and workflows secure: Untrusted input](https://securitylab.github.com/resources/github-actions-untrusted-input/) (GitHub Security Lab, 2020): cataloged real-world Actions carrying the same primitive. The fix pattern (split the workflow into a privileged labeler + an unprivileged builder) is now standard guidance.

<div class="pg-rule__rec" markdown>

**Recommended action**

Use `pull_request` instead of `pull_request_target` for any workflow that must run untrusted code. If you need write scope, split the workflow: a `pull_request_target` job that labels the PR, and a separate `pull_request`-triggered job that builds it with read-only secrets.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-003: Script injection via untrusted context { #gha-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-78</span>
</div>

Interpolating attacker-controlled context fields (PR title/body, issue body, comment body, commit message, discussion body, head branch name, `github.ref_name`, `inputs.*`, release metadata, deployment payloads) directly into a `run:` block is shell injection. GitHub expands `${{ ... }}` BEFORE shell quoting, so any backtick, `$()`, or `;` in the source field executes.

**Seen in the wild**

- [GitHub Security Lab disclosure](https://securitylab.github.com/research/github-actions-untrusted-input/) (2020): a sweep of public Actions found dozens of widely-used workflows interpolating ``github.event.issue.title`` / ``pull_request.title`` directly into shell. Any commenter or PR author could run arbitrary commands in the maintainer's CI.
- [Keeping your GitHub Actions and workflows secure: Preventing pwn requests](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/) (GitHub Security Lab, 2020): the same primitive against ``pull_request_target`` workflows where the runner has secrets and a write-scope token; one fork PR exfiltrates every secret the workflow can see. Mitigation: never interpolate context into shell, route through ``env:``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pass untrusted values through an intermediate `env:` variable and reference that variable from the shell script. GitHub's expression evaluation happens before shell quoting, so inline `${{ github.event.* }}` is always unsafe.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-004: Workflow permissions block missing or overprovisioned { #gha-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-C-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Without an explicit `permissions:` block (either top-level or per-job), the GITHUB_TOKEN inherits the repository's default scope, typically `write`. A compromised step receives far more privilege than it needs.

Beyond the missing-block case, the rule also flags over-grants: a job that declares ``packages: write`` but never runs ``docker push`` / ``npm publish`` / ``gh release upload``, a job that declares ``issues: write`` but never calls ``gh issue ...``, a job that declares ``security-events: write`` but never invokes a SARIF uploader, etc. Wildcard consumers (``actions/github-script``) suppress the flag because they can reach any scope through the GitHub API.

The rule also aggregates at the workflow level: when a top-level ``permissions:`` block grants a write scope that no inheriting job (a job without its own permissions override) actually consumes, the workflow is handing every inheriting job more privilege than its steps need. Move the scope to the specific job that needs it, or drop it entirely.

**Known false-positive modes**

- Read-only / lint-only workflows that do not call any write-scoped API often pass without an explicit block because the default token scope on public repos is read. The rule defaults to MEDIUM confidence to reflect this. For the overprovisioned-scope case, false positives can appear when a workflow consumes a scope through a third-party action this rule's consumer list doesn't recognize yet, file an issue to extend the catalog when discovered.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a top-level `permissions:` block (start with `contents: read`) and grant additional scopes only on the specific jobs that need them. For job-level blocks, prune any write scope no step in the job actually uses, the rule names the specific scopes the job's steps don't justify.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-005: AWS auth uses long-lived access keys { #gha-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-TOKEN-HYGIENE</span> <span class="pg-tag pg-tag--cwe">CWE-522</span>
</div>

Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` secrets in GitHub Actions can't be rotated on a fine-grained schedule and remain valid until manually revoked. OIDC with `role-to-assume` yields short-lived credentials per workflow run.

**Known false-positive modes**

- LocalStack and Moto integration tests set ``AWS_ENDPOINT_URL`` to a localhost address and use the sentinel ``test`` / ``test`` access keys (the LocalStack convention). Those values can't authenticate against real AWS, so the rule auto-suppresses an env block that pairs a localhost endpoint with sentinel keys.

<div class="pg-rule__rec" markdown>

**Recommended action**

Use `aws-actions/configure-aws-credentials` with `role-to-assume` + `permissions: id-token: write` to obtain short-lived credentials via OIDC. Remove the static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY secrets.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-006: Artifacts not signed (no cosign/sigstore step) { #gha-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-SIGN-ARTIFACTS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Unsigned artifacts cannot be verified downstream, so a tampered build is indistinguishable from a legitimate one. The check recognizes cosign, sigstore, slsa-github-generator, slsa-framework, and notation-sign as signing tools.

**Seen in the wild**

- [SolarWinds Orion compromise](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a) (December 2020): SUNBURST trojanized builds shipped to ~18,000 customers because no post-build signature could be checked against a trusted signing identity. Cryptographic signing on every release would have given downstream consumers a verifiable break with the upstream key, the absence of which was the ambient signal of compromise.
- [PyTorch nightly compromise](https://pytorch.org/blog/compromised-nightly-dependency/) (December 2022): the ``torchtriton`` dependency was hijacked via PyPI dependency-confusion. Sigstore-style attestation tied to the official publisher would have made the impostor build fail verification rather than silently install.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a signing step, e.g. `sigstore/cosign-installer` followed by `cosign sign`, or `slsa-framework/slsa-github-generator` for keyless SLSA provenance. Publish the signature alongside the artifact and verify it at consumption time.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-007: SBOM not produced (no CycloneDX/syft/Trivy-SBOM step) { #gha-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-SBOM</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Without an SBOM, downstream consumers cannot audit the exact set of dependencies shipped in the artifact, delaying vulnerability response when a transitive dep is disclosed. The check recognizes CycloneDX, syft, Anchore SBOM action, spdx-sbom-generator, Microsoft sbom-tool, and Trivy in SBOM mode.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add an SBOM generation step, `anchore/sbom-action`, `syft . -o cyclonedx-json`, Trivy with `--format cyclonedx`, or Microsoft's `sbom-tool`. Attach the SBOM to the release so consumers can ingest it into their vuln-management pipeline.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GHA-008: Credential-shaped literal in workflow body { #gha-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Every string in the workflow is scanned against a set of credential patterns (AWS access keys, GitHub tokens, Slack tokens, JWTs, Stripe, Google, Anthropic, etc., see `--man secrets` for the full catalog). A match means a secret was pasted into YAML, the value is visible in every fork and every build log and must be treated as compromised.

A second key-context pass also fires on a 40-character lowercase-hex value bound to a credential-named YAML key (``API_TOKEN: deadbeef...0ddf00d``). Covers the legacy unprefixed-vendor-token family (Datadog, GitLab v1 PATs, Codecov v3, AppVeyor, CircleCI v1, pre-``ghp_`` GitHub PATs) where the bare hex shape carries no vendor prefix. The credential-key gate keeps commit SHAs and SHA-256 digests out of the false-positive bucket: a 40-hex value in ``deploy_commit:`` doesn't fire.

**Known false-positive modes**

- Test fixtures and documentation blobs sometimes embed credential-shaped strings (JWT samples, vendor example keys). Well-known vendor example tokens (``AKIAIOSFODNN7EXAMPLE``, Stripe ``sk_test_`` docs keys) are suppressed via the ``VENDOR_EXAMPLE_TOKENS`` allowlist. Defaults to LOW confidence.

**Seen in the wild**

- Uber 2016 GitHub leak: an AWS access key embedded in a private GitHub repo was reachable to attackers who got at the repo and used it to download driver / rider PII for 57 million accounts. Credential-shaped literals in any source control system (public or private) are one credential-leak away from the same outcome.
- GitGuardian's annual State of Secrets Sprawl reports consistently find millions of fresh credential leaks per year across public commits, with a median time-to-revocation after disclosure of days, not minutes. Pinning secrets to ``${{ secrets.* }}`` removes the artifact from source control entirely.

<div class="pg-rule__rec" markdown>

**Recommended action**

Rotate the exposed credential immediately. Move the value to an encrypted repository or environment secret and reference it via `${{ secrets.NAME }}`. For cloud access, prefer OIDC federation over long-lived keys.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GHA-009: workflow_run downloads upstream artifact unverified { #gha-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

`on: workflow_run` runs in the privileged context of the default branch (write GITHUB_TOKEN, secrets accessible) but consumes artifacts produced by the triggering workflow, which is often a fork PR with no trust boundary. Classic PPE: a malicious PR uploads a tampered artifact, the privileged workflow_run downloads and executes it.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a verification step BEFORE consuming the artifact: `cosign verify-attestation --type slsaprovenance ...`, `gh attestation verify --owner $OWNER ./artifact`, or publish a checksum manifest from the trusted producer and `sha256sum -c` it. Treat any download from a fork as untrusted input.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-010: Local action (./path) on untrusted-trigger workflow { #gha-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

`uses: ./path/to/action` resolves the action against the CHECKED-OUT workspace. On `pull_request_target` / `workflow_run`, that workspace can be PR-controlled, meaning the attacker supplies the `action.yml` that runs with default-branch privilege.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move the action to a separate repo under your control and reference it by SHA-pinned `uses: org/repo@<sha>`, or split the workflow so the privileged work runs only on `pull_request` (read-only token, no secrets) where PR-controlled action.yml can't escalate.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-011: Cache key derives from attacker-controllable input { #gha-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

`actions/cache` restores by key (and falls through `restore-keys` on miss). When the key includes a value the attacker controls (PR title, head ref, workflow_dispatch input), an attacker can plant a poisoned cache entry that a later default-branch run restores and treats as a clean build cache.

<div class="pg-rule__rec" markdown>

**Recommended action**

Build the cache key from values the attacker can't control: `${{ runner.os }}`, `${{ hashFiles('**/*.lock') }}` (only when the lockfile is enforced by branch protection), and the workflow file path. Never include `github.event.*` PR/issue fields, `github.head_ref`, or `inputs.*` in the key namespace.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-012: Self-hosted runner without ephemeral marker { #gha-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--esf">ESF-D-PRIV-BUILD</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Self-hosted runners that don't tear down between jobs leak filesystem and process state. A PR-triggered job writes to `/tmp`; a subsequent prod-deploy job on the same runner reads it. The mitigation is the runner's `--ephemeral` mode, the runner exits after one job and re-registers fresh. The check looks for an `ephemeral` label on the `runs-on` value; without one, the runner is presumed reusable. Recognizes all three `runs-on` shapes: string, list, and `{ group, labels }` dict form.

**Known false-positive modes**

- Organizations using actions-runner-controller (ARC), autoscaled pools, or vendor runner fleets often use labels like ``arc-*``, ``autoscaled-*``, or ``ephemeral-pool-*`` instead of a bare ``ephemeral`` label. The check only matches the literal ``ephemeral`` token on ``runs-on``; extend via a custom allow-prefix config if your fleet uses a different naming convention. Defaults to MEDIUM confidence.

<div class="pg-rule__rec" markdown>

**Recommended action**

Configure the self-hosted runner to register with `--ephemeral` (the runner exits after one job and is freshly registered), and add an `ephemeral` label so this check can verify it. Consider actions-runner-controller for ephemeral pools.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-013: issue_comment trigger without author guard { #gha-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-78</span>
</div>

`on: issue_comment` (and `discussion_comment`) fires for every comment on every issue or discussion in the repository. On public repos this means any GitHub user can trigger workflow execution. If the workflow runs commands, deploys, or accesses secrets, the attacker controls timing and can inject payloads through the comment body.

**Known false-positive modes**

- Guard detection runs against the whole workflow as text rather than against parsed ``if:`` expressions, so a guard token appearing in an unrelated context (a comment, a step name, a description field) reads as satisfying the rule. Conversely, guards expressed via alternative author-association idioms the regex doesn't recognize (``github.event.issue.user.login``, an org-membership API check inside a script) leave the rule firing even though the workflow is safely gated. Suppress per-workflow via ``--ignore-file`` once you've verified the gate logic; tighten the guard expression to use the recognized tokens if possible.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add an `if:` condition that checks `github.event.comment.author_association` (e.g. `contains('OWNER MEMBER COLLABORATOR', ...)`), `github.event.sender.login`, or `github.actor` against an allowlist. Without a guard, any GitHub user can trigger the workflow by posting a comment.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-014: Deploy job missing environment binding { #gha-014 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-C-APPROVAL</span> <span class="pg-tag pg-tag--esf">ESF-C-ENV-SEP</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Without an `environment:` binding, a deploy job can't be gated by required reviewers, deployment-branch policies, or wait timers. Any push to the triggering branch will deploy immediately.

**Known false-positive modes**

- Integration-test jobs that run ``terraform apply`` or ``kubectl apply`` against a local mock (LocalStack, Moto, kind, k3d) aren't real deploys. The rule auto-suppresses a step whose env carries ``AWS_ENDPOINT_URL`` or ``KUBE_API_URL`` pointing at a localhost address.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add `environment: <name>` to jobs that deploy. Configure required reviewers, wait timers, and branch-protection rules on the matching GitHub environment.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-015: Job has no `timeout-minutes`, unbounded build { #gha-015 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-TIMEOUT</span> <span class="pg-tag pg-tag--cwe">CWE-400</span>
</div>

Without `timeout-minutes`, the job runs until GitHub's 6-hour default kills it. Explicit timeouts cap blast radius, cost, and the window during which a compromised step has access to secrets.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add `timeout-minutes:` to each job, sized to the 95th percentile of historical runtime plus margin. GitHub's default is 360 minutes, an explicitly shorter value limits blast radius and runner cost.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-016: Remote script piped to shell interpreter { #gha-016 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Two shapes fire:

1. **Curl-pipe.** ``curl | bash``, ``wget | sh``, and the shell-subshell / python-inline / download-exec / PowerShell variants documented in ``_primitives/remote_script_exec``. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the CI runner.
2. **Trusted-installer (Codecov 2021 shape).** A job downloads an executable from a non-vendor host (``curl -o``, ``wget -O``, ``curl > file``) AND any subsequent step in the same job runs that file (``./file`` invocation or ``chmod +x`` setup). Fires even when the body verifies a SHA256 checksum or GPG signature, because the original Codecov compromise modified the uploader BEFORE the publisher's CI signed it. The carve-out is an upstream-attested provenance reference in the same job: ``slsa-verifier``, ``gh attestation verify``, or ``cosign verify-attestation``. Vendor-allowlisted hosts (``rustup.rs``, ``get.docker.com``, etc.) are skipped here the same way the curl-pipe pass skips them.

**Known false-positive modes**

- Established vendor installers (get.docker.com, sh.rustup.rs, bun.sh/install, awscli.amazonaws.com, cli.github.com, ...) ship via HTTPS from their own CDN and are idiomatic. This rule defaults to LOW confidence so CI gates can ignore them with --min-confidence MEDIUM; the finding still surfaces so teams that want cryptographic verification can audit.

**Seen in the wild**

- [Codecov Bash uploader compromise](https://about.codecov.io/security-update/) (April 2021): an attacker modified the codecov.io/bash uploader script (commonly fetched via ``curl -s codecov.io/bash | bash``) to exfiltrate environment variables from CI runners (AWS keys, GitHub tokens, signing keys) at thousands of customers for over two months before discovery.
- [event-stream](https://github.com/dominictarr/event-stream/issues/116) (November 2018) and the [ua-parser-js compromise](https://github.com/faisalman/ua-parser-js/issues/536) (October 2021): npm-side examples of the same primitive. When the CI runner executes bytes a third party can swap out (via `curl | bash`, an unpinned `npm install`, or a compromised maintainer account), the attacker controls what runs with the runner's credentials in scope. Pinning a digest or vendoring a frozen copy turns a perpetual ambient risk into a one-time review.

<div class="pg-rule__rec" markdown>

**Recommended action**

Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository. For third-party installers (Codecov / similar), a SHA256 check + GPG signature is NOT enough on its own — the Codecov 2021 incident shipped a malicious uploader that was signed by the publisher's own (compromised) CI pipeline. Pin the binary to an upstream-attested provenance reference (``slsa-verifier verify-artifact``, ``gh attestation verify``, ``cosign verify-attestation``) or pin a specific release digest, not just any signature.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GHA-017: Docker run with insecure flags (privileged/host mount) { #gha-017 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Flags like `--privileged`, `--cap-add`, `--net=host`, or host-root volume mounts (`-v /:/`) in a workflow give the container full access to the runner, enabling container escape and lateral movement.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove --privileged and --cap-add flags. Use minimal volume mounts. Prefer rootless containers.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-018: Package install from insecure source { #gha-018 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a workflow. These patterns allow man-in-the-middle injection of malicious packages.

Carve-out: third-party binary installers that download over HTTPS (no insecure registry, no TLS bypass) are GHA-016's trusted-installer shape, not GHA-018's. ``greylag-ci/cicd-goat`` scenario 19 fetches a Codecov-style uploader from a non-vendor HTTPS endpoint, verifies a SHA256 checksum and GPG signature, and runs the binary; GHA-018 deliberately doesn't fire (the source is HTTPS), GHA-016 does (the Codecov-2021 lesson).

<div class="pg-rule__rec" markdown>

**Recommended action**

Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GHA-019: GITHUB_TOKEN written to persistent storage { #gha-019 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-522</span>
</div>

Two shapes are flagged:

1. **Direct.** ``run:`` body writes ``GITHUB_TOKEN`` (or any ``${{ secrets.* }}`` value) to a file, ``$GITHUB_ENV``, ``$GITHUB_OUTPUT``, or ``$GITHUB_STATE``, or pipes it through ``tee``.
2. **ArtiPACKED (Palo Alto Unit 42, 2024).** Pairs ``actions/checkout`` (default ``persist-credentials: true``, or explicitly set to true) with a downstream ``actions/upload-artifact`` whose ``path:`` covers the repo root (``.``, ``./``, ``${{ github.workspace }}``, or an explicit ``.git/`` reference). The checkout writes the runtime ``GITHUB_TOKEN`` into ``.git/config`` via ``extraheader``; the upload step bundles the whole working directory including ``.git/``, so anyone with read access to the run can ``gh run download`` the artifact and read the token out of ``.git/config``. The rule fires once per offending job; the per-finding location points at the upload step.

Carve-out: secrets leaked to the workflow log (via ``set -x`` shell trace, ``echo $TOKEN``, or URL-embedded credentials that a process tool logs) are GHA-033's domain, not GHA-019's. ``greylag-ci/cicd-goat`` scenario 27 fires GHA-033 only — the secret leaks to log via ``set -x`` but no token persists to file / ``$GITHUB_ENV`` / artifact, which is the persistence shape GHA-019 covers.

<div class="pg-rule__rec" markdown>

**Recommended action**

Never write GITHUB_TOKEN to files, artifacts, or GITHUB_ENV. Use the token inline via ${{ secrets.GITHUB_TOKEN }} in the step that needs it.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-020: No vulnerability scanning step { #gha-020 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VULN-MGMT</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-021: Package install without lockfile enforcement { #gha-021 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Detects package-manager install commands that do not enforce a lockfile or hash verification. Without lockfile enforcement the resolver pulls whatever version is currently latest, exactly the window a supply-chain attacker exploits.

<div class="pg-rule__rec" markdown>

**Recommended action**

Use lockfile-enforcing install commands: `npm ci` instead of `npm install`, `pip install --require-hashes -r requirements.txt`, `yarn install --frozen-lockfile`, `bundle install --frozen`, and `go install tool@v1.2.3`.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-022: Dependency update command bypasses lockfile pins { #gha-022 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`, `pip install -U poetry`, `pip install --upgrade black`, etc.) are exempted.

**Known false-positive modes**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``), security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``), and quality-tool installs (``pip install --upgrade black / ruff / pytest / pre-commit``) are exempted by the tooling allowlist. Package-manager self-upgrades (``npm install -g npm``, ``corepack enable``) are also exempted. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR workflow (e.g. Dependabot, Renovate).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-023: TLS / certificate verification bypass { #gha-023 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-295</span>
</div>

Detects patterns that disable TLS certificate verification: `git config http.sslVerify false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `npm config set strict-ssl false`, `curl -k`, `wget --no-check-certificate`, `PYTHONHTTPSVERIFY=0`, and `GOINSECURE=`. Disabling TLS verification allows MITM injection of malicious packages, repositories, or build tools.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove TLS verification bypasses. Fix certificate issues at the source (install CA certificates, configure proper trust stores) instead of disabling verification.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-024: No SLSA provenance attestation produced { #gha-024 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Provenance generation is distinct from signing. A signed artifact proves ``who`` published it; a provenance attestation proves ``where/how`` it was built. Consumers can then verify the build happened on a trusted runner, from a specific source commit, with known parameters. Without it, a leaked signing key forges identity but a leaked build environment also forges provenance. You need both for the SLSA L3 non-falsifiability guarantee.

<div class="pg-rule__rec" markdown>

**Recommended action**

Call ``slsa-framework/slsa-github-generator`` or ``actions/attest-build-provenance`` after the build step to emit an in-toto attestation alongside the artifact. ``cosign sign`` alone (covered by GHA-006) signs the artifact but doesn't record *how* it was built. SLSA Build L3 requires the provenance statement.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-025: Reusable workflow not pinned to commit SHA { #gha-025 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

A reusable workflow runs with the caller's ``GITHUB_TOKEN`` and secrets by default. If ``uses: org/repo/.github/workflows/release.yml@v1`` resolves to an attacker-modified commit, their code executes with your repository's permissions. This is the same threat model as unpinned step actions (GHA-001) but over a different ``uses:`` surface.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every ``jobs.<id>.uses:`` reference to a 40-char commit SHA (``owner/repo/.github/workflows/foo.yml@<sha>``). Tag refs (``@v1``, ``@main``) can be silently repointed by whoever controls the callee repository.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-026: Container job disables isolation via `options:` { #gha-026 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--esf">ESF-D-PRIV-BUILD</span> <span class="pg-tag pg-tag--cwe">CWE-250</span> <span class="pg-tag pg-tag--cwe">CWE-276</span>
</div>

GitHub-hosted runners execute ``container:`` jobs inside a Docker container the runner itself manages, normally a hardened, network-namespaced sandbox. ``options:`` is a free-text passthrough to ``docker run``; a flag that breaks the sandbox (shares host network/PID, runs privileged, maps the Docker socket) turns the job into an RCE on the runner VM.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove ``--network host``, ``--privileged``, ``--cap-add``, ``--user 0``/``--user root``, ``--pid host``, ``--ipc host``, and host ``-v`` bind-mounts from ``container.options`` and ``services.*.options``. If a build genuinely needs one of these, move it to a dedicated self-hosted pool with branch protection so the flag doesn't reach PR runs.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GHA-027: Workflow contains indicators of malicious activity { #gha-027 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-506</span> <span class="pg-tag pg-tag--cwe">CWE-913</span>
</div>

Distinct from the hygiene checks. GHA-016 flags ``curl | bash`` as a risky default; this rule fires only on concrete indicators, reverse shells, base64-decoded execution, known miner binaries or pool URLs, exfil-channel domains, credential-dump pipes, history-erasure commands. Categories reported: ``obfuscated-exec``, ``reverse-shell``, ``crypto-miner``, ``exfil-channel``, ``credential-exfil``, ``audit-erasure``.

**Known false-positive modes**

- Security-training repositories, CTF challenges, and red-team exercise workflows legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production workflow still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

<div class="pg-rule__rec" markdown>

**Recommended action**

Treat this as a potential pipeline compromise. Inspect the matching step(s), identify the author and the PR that introduced them, rotate any credentials the workflow has access to, and audit CloudTrail/AuditLogs for exfil. If the match is a legitimate red-team exercise, whitelist via ``.pipelinecheckignore`` with an ``expires:`` date, never a permanent suppression.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-028: Dangerous shell idiom (eval, sh -c variable, backtick exec) { #gha-028 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-95</span>
</div>

``eval``, ``sh -c "$X"``, and `` `$X` `` all re-parse the variable's value as shell syntax. If the value contains ``;``, ``&&``, ``|``, backticks, or ``$()``, those metacharacters execute. Even when the variable source looks controlled today, relocating the script or adding a new caller can silently expose it to untrusted input.

**Known false-positive modes**

- ``eval "$(ssh-agent -s)"`` and similar ``eval "$(<literal-tool> <literal-args>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd. The rule only fires when the substituted command references a variable.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec of variables with direct command invocation. If the command really must be dynamic, pass arguments as array members (``"${ARGS[@]}"``) or validate the input against an allow-list before invocation.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-029: Package install bypasses registry integrity (git / path / tarball source) { #gha-029 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Package installs that pull from ``git+…`` without a pinned commit, from a local path (``./dir``, ``file:…``, absolute paths), or from a direct tarball URL are invisible to the normal lockfile integrity controls. A moving branch head, a sibling checkout the build assumes exists, or a tarball whose hash isn't verified all give an attacker who controls any of those surfaces the ability to substitute code into the build.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin git dependencies to a commit SHA (``pip install git+https://…/repo@<sha>``, ``cargo install --git … --rev <sha>``). Publish private packages to an internal registry instead of installing from a filesystem path or tarball URL.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-030: OIDC token requested without environment-protected job { #gha-030 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Pairs with IAM-008. IAM-008 verifies the AWS-side trust policy pins audience + subject; this rule verifies the GitHub-side workflow can't request the token from any branch without a deployment gate. A misconfiguration on either side defeats the OIDC story.

<div class="pg-rule__rec" markdown>

**Recommended action**

Bind every job that exchanges the GHA OIDC token for cloud credentials to a protected ``environment:`` (e.g. ``environment: production``). Environment protections layer in branch restrictions, required reviewers, and deployment windows that the IdP-side trust policy cannot enforce alone.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-031: Workflow uses retired set-output / save-state command { #gha-031 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-77</span>
</div>

GitHub deprecated ``::set-output::`` and ``::save-state::`` in October 2022 because they read from the runner's stdout as a control channel. Any tool whose output happens to contain ``::set-output…`` (a CI job's own diagnostic, a downloaded log, an upstream test framework) silently sets a step output. The replacement workflow commands (``$GITHUB_OUTPUT`` / ``$GITHUB_STATE`` files) close that injection channel. Workflows still using the retired commands also depend on a deprecation timer that GitHub has extended several times. They will eventually break.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``echo "::set-output name=X::$VALUE"`` with ``echo "X=$VALUE" >> "$GITHUB_OUTPUT"`` and ``echo "::save-state name=X::$VALUE"`` with ``echo "X=$VALUE" >> "$GITHUB_STATE"``. The old commands stream through the runner's stdout, which lets any log line that happens to start with ``::`` inject into the command channel. The file-redirect forms write to a private file the runner reads after the step exits, no log-line interleaving, no injection.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GHA-032: run: invokes local script on untrusted-trigger workflow { #gha-032 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-94</span>
</div>

GHA-010 flags ``uses: ./action``, the *action* form of the same threat. This rule extends to direct shell invocation: ``run: ./scripts/setup.sh`` / ``run: bash scripts/setup.sh`` / ``run: python tools/build.py`` resolve against the checked-out workspace, which on ``pull_request_target`` / ``workflow_run`` is PR-controlled. The attacker ships an edited script and gets a default-branch-privileged shell.

**Known false-positive modes**

- Workflows that explicitly checkout a *trusted* ref (``ref: ${{ github.event.pull_request.base.sha }}`` or the default branch) before invoking the local script land the trusted bytes on disk, so the script body the PR ships is never executed. The rule has no checkout-graph analysis, it fires on any ``run: ./script`` under an untrusted trigger. Suppress per-workflow via ``--ignore-file`` once you've verified the checkout ref is anchored to a base-branch SHA; the safer pattern is still to split the workflow so secrets aren't in scope during the build half.

<div class="pg-rule__rec" markdown>

**Recommended action**

Either don't run the script under an untrusted trigger, or split the workflow: keep the privileged work on the default branch (``push`` / ``release`` triggers, no PR fork content), and run untrusted-trigger steps in a separate workflow with no secrets and a minimal ``GITHUB_TOKEN`` scope. Pinning the script via ``uses: org/repo@<sha>`` from a separate trusted repo is the canonical fix.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GHA-033: Secret value echoed / printed in a run: block { #gha-033 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-532</span> <span class="pg-tag pg-tag--cwe">CWE-200</span>
</div>

Three shapes are flagged:

1. **Direct.** A printed argument references a secret context expression, e.g. ``echo "${{ secrets.X }}"`` or ``cat <<<${{ secrets.X }}``.
2. **Indirect env var.** A step ``env:`` block resolves a secret into the env (``X: ${{ secrets.X }}``) and the same step's ``run:`` echoes the env var (``echo "$X"``). Catches the lint-evading form where no ``${{ secrets...}}`` literal appears in the run body.
3. **Shell trace.** The step enables ``set -x`` / ``set -o xtrace`` AND references a secret-bound env var anywhere in the body. Shell trace mode dumps every command with arguments expanded before execution, so a ``curl -H "Bearer $TOKEN"`` line that would normally stay out of the log lands in the log verbatim. The rule fires once per step even though many lines may leak.

Out of scope (deliberate carve-out): inline secret references in a command's *arguments* without shell trace enabled. ``curl --header "Authorization: Bearer ${{ secrets.X }}"`` doesn't echo the header to stdout — the value goes to the network, not the log. That class of leak is covered by GHA-008 (literal credential in YAML) and the network-egress shape of GHA-057, not GHA-033. ``greylag-ci/cicd-goat`` scenario 15 sits squarely in this carve-out: a literal hex token in workflow ``env:`` plus a GET ``curl`` carrying the credential in an ``Authorization:`` header. GHA-008 fires on the literal; GHA-033 deliberately does not.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't print secret values from a script. GitHub's log redaction is a best-effort string match. It doesn't catch base64 / urlencoded / partial substrings, and any caller that retrieves the raw log via the API gets the unredacted stream. If you need to confirm the secret exists, log a boolean (``[ -n "$X" ] && echo set || echo unset``), never the value itself. Note: a SHA-256 fingerprint or a ``${X:0:N}`` prefix is not a safe substitute either, those shapes still slip past the masker and are flagged by GHA-087 separately.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-034: Reusable workflow called with secrets: inherit { #gha-034 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-LEAST-PRIV</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-272</span>
</div>

Fires on a ``jobs.<id>.uses: ...`` reference whose sibling ``secrets:`` value is the literal string ``inherit``. This is distinct from GHA-025 (which gates on the *pin* of the called workflow): inheritance is a problem even when the call is SHA-pinned, because the surface a compromised callee sees is every caller secret instead of just the named ones. Explicit lists also document the contract, reviewers see exactly which secrets cross the workflow boundary.

**Known false-positive modes**

- Single-tenant repos that share their entire secrets set with every reusable workflow by policy. Rare in practice, explicit lists make the secret flow visible and don't add much typing. Suppress with ``.pipelinecheckignore`` and a rationale rather than disabling the rule everywhere.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``secrets: inherit`` with an explicit list of just the secrets the called workflow actually needs (``secrets: { NPM_TOKEN: ${{ secrets.NPM_TOKEN }} }``). ``inherit`` passes every secret the caller can see, including ones the downstream workflow has no business reading. A compromised or buggy reusable workflow can then exfiltrate credentials the caller never intended to share.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-035: github-script step interpolates untrusted context { #gha-035 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-94</span>
</div>

GHA-003 covers ``run:`` blocks where shell expansion is the injection surface. ``actions/github-script@<ref>`` runs the ``script:`` input as Node.js inside an authenticated Octokit context, same threat model, different language. The rule fires when ``script:`` (or the legacy ``previews:`` companion for inline JS) contains a ``${{ github.event.* }}``, ``${{ inputs.* }}``, ``${{ github.head_ref }}``, ``${{ github.ref_name }}``, or any other untrusted context expression, exactly the same catalog GHA-003 uses.

**Known false-positive modes**

- Scripts that interpolate ``${{ steps.*.outputs.* }}`` from a trusted upstream step are out of scope (the rule only matches the curated untrusted-context regex). If you intentionally rely on a non-curated context, suppress with a brief ``.pipelinecheckignore`` rationale.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pass attacker-controllable values through ``env:`` and read them inside the script via ``process.env.X`` instead of interpolating ``${{ ... }}`` directly into the script body. GitHub expands the expression *before* the JavaScript engine parses the source, so backticks, quotes, and ``${...}`` characters in the source field break out of the surrounding string and execute as JavaScript with the workflow's GITHUB_TOKEN in scope.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-036: runs-on interpolates untrusted context { #gha-036 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--esf">ESF-D-PRIV-BUILD</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

GHA-012 catches self-hosted runners that aren't ephemeral; this rule catches the upstream targeting choice. When ``runs-on`` is computed from an untrusted expression, the caller picks where the workflow runs, including any self-hosted label the org owns. A reusable workflow that declares ``runs-on: ${{ inputs.runner }}`` lets a downstream caller route the job onto the production-deploy fleet (or any other privileged label) and execute arbitrary code with the privileges that fleet inherits. The same surface exists via ``workflow_dispatch`` inputs and any ``${{ github.event.* }}`` field that an attacker can populate. The rule walks all three ``runs-on`` shapes, string scalar, list of labels, and the long-form ``{ group, labels }`` dict, and matches the same untrusted-context regex GHA-003 / GHA-035 use.

**Known false-positive modes**

- Workflows that intentionally select runners by environment via a vetted matrix (``runs-on: ${{ matrix.os }}`` where ``matrix.os`` is a hard-coded list inside the workflow) are out of scope, the matrix values are author-controlled, not caller-controlled. The rule only matches the catalog of untrusted contexts (``inputs.*``, ``github.event.*``, ``github.head_ref``, …); ``matrix.*`` and ``env.*`` references are intentionally not flagged.

<div class="pg-rule__rec" markdown>

**Recommended action**

Hard-code ``runs-on:`` to a specific runner label or list of labels. If the choice has to be parameterized across callers, validate the input against an allowlist of known-good labels before the job runs (a small ``if:`` guard at job level), and never accept ``${{ inputs.* }}`` or any ``${{ github.event.* }}`` field as the ``runs-on`` value directly.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-037: actions/checkout persists GITHUB_TOKEN into .git/config { #gha-037 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--esf">ESF-D-CODE-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-522</span> <span class="pg-tag pg-tag--cwe">CWE-552</span>
</div>

Detection fires on any step whose ``uses:`` starts with ``actions/checkout@`` and whose ``with:`` block either omits ``persist-credentials`` (the unsafe default) or sets it to ``true`` explicitly.

This is the failure pattern Zizmor calls *Artipacked* and the StepSecurity / harden-runner audit set tracks as ``persist-credentials``-default. Real-world exploit chains (the ``ultralytics`` 2024 RCE, multiple Mend / Snyk advisories) exploit exactly this primitive: a first checkout step persists the token, a later ``run:`` step (often a build script the attacker can influence via PR contents) reads ``.git/config`` and ships the token out.

Sister rule: GHA-019 catches the explicit ``echo $GITHUB_TOKEN > file`` shape; GHA-037 catches the implicit checkout-default that doesn't go through a ``run:`` line at all.

**Known false-positive modes**

- Workflows that genuinely need ``persist-credentials: true`` to push back to the repo (a release-tag bot, a docs-deploy job, ``stefanzweifel/git-auto-commit-action``) shouldn't suppress this rule globally; instead, scope ``persist-credentials: true`` to a named step, then run the push immediately, then use a fresh ``actions/checkout`` with ``persist-credentials: false`` so the token doesn't leak into later steps. Suppress on the specific step name only when the scoped pattern is in place.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``persist-credentials: false`` on every ``actions/checkout`` step that doesn't need to push back to the repo. The default in v3 / v4 is ``true``, which writes the GITHUB_TOKEN into ``.git/config`` as an ``http.https://github.com/.extraheader`` line. Any subsequent ``run:`` step in the same job can read it with ``git config --get http.https://github.com/.extraheader`` and exfiltrate the token to a remote endpoint, even if that step's own scope is read-only. If the workflow genuinely needs to push (release publishing, doc-site deploys), do the push as the very next step and immediately follow with a checkout that sets ``persist-credentials: false`` so the token doesn't leak into later, less-trusted steps.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GHA-038: Workflow re-enables retired ::set-env / ::add-path commands { #gha-038 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-77</span> <span class="pg-tag pg-tag--cwe">CWE-77</span>
</div>

Detection fires when ``ACTIONS_ALLOW_UNSECURE_COMMANDS`` is set to any truthy value at the workflow ``env:`` level, the job ``env:`` level, or any step's ``env:`` block. Accepted truthy spellings: ``true`` / ``1`` / ``yes`` / ``on`` (including quoted forms like ``"true"`` and case-insensitive variants like ``YES`` / ``On``).

Sister rule GHA-031 catches direct uses of ``::set-output::`` / ``::save-state::`` in step scripts. GHA-038 catches the explicit re-enable flag, which is the strictly worse case: it implicitly accepts every ``::set-env::`` / ``::add-path::`` line that lands on the runner's stdout from any tool the step invokes, not just the workflow author's own ``echo`` commands. A downloaded build log, a container's startup banner, an upstream test runner's output, all become injection vectors.

**Known false-positive modes**

- Some legacy actions (last-updated pre-2020) still emit ``::set-env::`` lines and rely on the override to be set. Replace the action rather than suppressing this rule, the security exposure outweighs the cost of an alternative action.

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop the ``ACTIONS_ALLOW_UNSECURE_COMMANDS`` env definition entirely, then migrate any leftover ``::set-env::`` / ``::add-path::`` workflow commands to the file-redirect form (``echo "X=$VAL" >> "$GITHUB_ENV"`` and ``echo "$DIR" >> "$GITHUB_PATH"``). GitHub disabled the legacy commands in 2020 specifically because they share the runner's stdout as a control channel: any log line starting with ``::`` could inject environment variables, prepend to PATH, or set step outputs. Setting the override flag back to ``true`` re-opens that injection channel for the entire workflow scope.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GHA-039: services / container credentials embedded as literal in workflow { #gha-039 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span> <span class="pg-tag pg-tag--cwe">CWE-522</span>
</div>

GitHub Actions accepts a ``credentials:`` map on both the job-level ``container:`` block (the runner image) and on each ``services.<name>:`` entry (sidecar containers). The map is the documented way to pull a private image from a registry that requires auth, and it expects ``${{ secrets.* }}`` references for both fields.

GHA-008 scans the workflow for credential **patterns** (AWS access keys, JWTs, Slack tokens, etc.) but doesn't trip on a plain password like ``hunter2`` or a registry username like ``ci-deploy-bot``. GHA-039 catches them by **position**: any literal value in a ``credentials.username`` / ``credentials.password`` field is by definition a leaked credential, regardless of its shape. Closes parity with Zizmor's ``hardcoded-container-credentials`` rule.

**Known false-positive modes**

- Workflows that legitimately use a public anonymous registry mirror occasionally hardcode ``username: anonymous`` / ``password: ""`` for clarity. Both shapes are filtered out automatically (empty / whitespace-only values, plus the literal ``anonymous`` username), but if your fixture uses another sentinel for anonymous access, suppress the specific job/service in the ignore-file rather than the rule globally.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move every ``services.<name>.credentials.username`` / ``credentials.password`` value (and the same field on a job-level ``container:`` block) out of the workflow YAML and into a repository or environment secret. Reference the secret via ``${{ secrets.NAME }}`` from the same credentials block. Anything written as a literal is permanently visible in every fork of the repo, every build log that prints the runner's start banner, and every cached job summary, so the credential must be treated as compromised on the spot. The fix is the rotation, plus the secret reference, plus a check that no other workflow keeps the literal pattern.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GHA-040: Action reference matches a known-compromised SHA or tag { #gha-040 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-506</span>
</div>

Walks every workflow's ``steps[].uses:`` and ``jobs.<id>.uses:`` references against the curated compromised-action registry in ``pipeline_check.core.checks.github._compromised_actions``. Match is case-insensitive on owner / repo and exact on the ``ref`` value (commit SHA or tag name). Registry is deliberately small and append-only — refresh by PR with the citing advisory in the commit message; no fetch-from-network registry to avoid taking on a telemetry surface.

**Known false-positive modes**

- The registry covers only public, advisory-confirmed compromises. Pre-disclosure compromises and yet-unpublished maintainer-account takeovers do not land until the citing CVE / GHSA exists. Pair with GHA-001 (SHA pinning) and GHA-025 (tag-rewrite detection) for the prevention angle.

**Seen in the wild**

- tj-actions/changed-files compromise ([CVE-2025-30066](https://www.cve.org/CVERecord?id=CVE-2025-30066), March 2025): the canonical case the registry was built for. Roughly 23,000 tag-pinned repos shipped CI secrets to an exfiltration endpoint over a ~24-hour window before GitHub blocked the malicious commits.
- reviewdog/action-setup compromise ([CVE-2025-30154](https://www.cve.org/CVERecord?id=CVE-2025-30154), March 2025): same week as tj-actions; smaller blast radius but identical mechanism. Tag-pinned consumers were affected; SHA-pinned consumers who happened to match the malicious commit were also affected.

<div class="pg-rule__rec" markdown>

**Recommended action**

Rotate every secret that may have been reachable to a workflow run that hit the compromised reference, then update the ``uses:`` reference to a known-clean SHA published by the upstream maintainer post-incident (usually announced in the advisory body). Audit CI logs for the affected window for any sign that the malicious payload ran against this repo.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-041: Action upstream repo has a single contributor { #gha-041 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Reads the contributor count from ``ctx.action_metadata[owner/repo].contributor_count`` (populated by the ``--resolve-remote`` path; the GitHub REST ``/contributors`` endpoint, capped at two entries — the rule only cares about == 1). When the fetch failed or the flag is off, the rule passes silently. Forks and archived repos that ALSO have a single contributor fire the rule; the fork / archived state is part of the same supply-chain risk story.

**Known false-positive modes**

- Some well-maintained single-author actions (high-quality personal-account repos that the maintainer simply hasn't open-sourced governance for) are not actually compromised. Suppress via ignore-file when a security review has confirmed the maintainer's identity and 2FA posture.

**Seen in the wild**

- tj-actions / reviewdog March 2025 compromises (CVE-2025-30066 / CVE-2025-30154): both upstream repos had a single primary contributor at the time of compromise. The single-maintainer pattern was central to the blast radius (no second pair of eyes on the malicious commit, no auto-rollback when the tag move landed).

<div class="pg-rule__rec" markdown>

**Recommended action**

Audit the action repo's contributor list. If the repo genuinely has one maintainer, pin to a vendored fork under your org's control (so a future compromise on the upstream doesn't reach your build runtime) or move to a first-party action covering the same surface. The single-maintainer pattern is what made tj-actions / reviewdog one-day compromises so widely-blast.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-042: Action upstream repo is newly created { #gha-042 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Reads ``created_at`` from ``ctx.action_metadata[owner/repo]`` (populated by the ``--resolve-remote`` path). Fires when the repo's age in days is below ``MIN_AGE_DAYS`` (90). Without the opt-in flag the rule passes silently with a nudge.

**Known false-positive modes**

- Newly-released first-party actions from a trusted org (say, a freshly-launched ``actions/foo`` rolled out by GitHub itself) fire while they're still young. Suppress via ignore-file with a dated note; the entry expires naturally once the repo crosses the age threshold.

**Seen in the wild**

- GitGuardian / StepSecurity typosquat reports (2023-2024) document several action-naming impersonations that appeared as newly-registered repos and reached production CI before the legitimate owner was notified.

<div class="pg-rule__rec" markdown>

**Recommended action**

Verify the action repo is the real upstream and not a typosquat. Compare the spelling and owner against the intended action (``actions/checkout`` vs ``actoins/checkout``); check the repo description, stars, and prior releases. If the action is genuinely new but trusted, suppress via ignore-file with a dated note; the suppression decays naturally as the repo ages past the 90-day threshold.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-043: Low-star action runs with sensitive permissions { #gha-043 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-C-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Reads ``stargazers_count`` from ``ctx.action_metadata[owner/repo]`` and the effective ``permissions:`` block (job-level wins; falls back to workflow-top-level; falls back to the caller's inherited block for resolved reusable workflows). Fires when stars < ``MAX_STARS`` (25) AND any of 'contents', 'packages', 'id-token', 'actions', 'deployments' is set to ``write`` on the calling job. ``permissions: write-all`` is treated as all scopes set to write.

**Known false-positive modes**

- Internal first-party actions hosted in a private org repo legitimately have low public star counts; their threat model is different and the rule does not distinguish internal from third-party. Suppress via ignore-file when the action is in-org and trusted.

**Seen in the wild**

- GitGuardian 2023 supply-chain audit: a handful of low-popularity actions with ``contents: write`` were weaponized via single-PR maintainer-impersonation compromises; the elevated permission was the privilege amplifier that let the attacker push code back to the victim's default branch on the same workflow run.

<div class="pg-rule__rec" markdown>

**Recommended action**

Either narrow the calling job's ``permissions:`` to the minimum the action actually needs (drop ``contents: write`` / ``id-token: write`` / ``packages: write`` / ``actions: write`` / ``deployments: write`` unless the action's documented surface requires them), or replace the action with a community-reviewed alternative. The rule fires the COMBINATION of low community review and elevated permissions; either side alone is fine.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-044: Build tool runs lifecycle scripts on untrusted-trigger workflow { #gha-044 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-94</span>
</div>

Package managers and build tools execute code by design. ``npm install`` / ``pnpm install`` / ``yarn`` / ``bun install`` run ``preinstall`` / ``install`` / ``postinstall`` / ``prepare`` from the PR's ``package.json``; ``deno install`` resolves the PR's ``deno.json`` / ``package.json`` and (when ``--allow-scripts`` opts in) runs the same npm lifecycle hooks; ``pip install .`` runs the PR's ``setup.py``; ``make`` runs the PR's ``Makefile``; ``mvn`` / ``gradle`` load plugins declared in the PR's ``pom.xml`` / ``build.gradle``; ``cargo build`` runs ``build.rs``; ``docker build`` / ``docker/build-push-action`` execute the PR's ``Dockerfile`` (its ``RUN`` instructions) against the checked-out build context. Under ``pull_request_target`` / ``workflow_run``, the surrounding context already has secrets and a write-scope token, so the lifecycle hook is the entire attack.

**Known false-positive modes**

- Workflows that pin the workspace to a trusted ref before invoking the build tool (``actions/checkout`` with no ``ref:`` override on ``pull_request_target``, or a fresh checkout of a default-branch SHA) aren't actually exposed. The rule fires on the build-tool invocation alone; suppress with a ``.pipelinecheckignore`` rationale when the workspace is provably clean.

**Seen in the wild**

- Trail of Bits ``Public PPE`` write-up (2022): demonstrated the primitive against ``pull_request_target`` workflows that ran ``npm install`` after checking out PR content. The PR-supplied ``preinstall`` script ran with the base repo's secrets in scope. Same shape with ``pip install -e .`` (setup.py) and ``make`` (Makefile).
- Cycode / Legit Security ``Poisoned Pipeline Execution`` research (2022-2023) cataloged dozens of OSS repos where a privileged-trigger workflow's build step executed PR-controlled config: ``setup.py``'s ``cmdclass``, ``build.gradle``'s ``init.gradle``, ``pom.xml``'s ``<build><plugins>``. The fix pattern is always: don't build untrusted code with secrets in scope.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't run install / build commands under ``pull_request_target`` or ``workflow_run`` against a tree that may be PR-controlled. Split the workflow: keep the privileged work on ``push`` / ``release`` (no fork content), and run untrusted builds in a separate ``pull_request`` workflow with no secrets and a read-only ``GITHUB_TOKEN``. If you must build PR code with secrets, do it inside a container with no network egress and a minimal filesystem, never directly on the runner.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-045: Caller-controlled ref input feeds actions/checkout { #gha-045 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-940</span>
</div>

``workflow_dispatch`` / ``workflow_call`` inputs land in ``${{ inputs.<name> }}``. Feeding that directly into the ``ref:`` of ``actions/checkout`` means the caller picks which commit runs in this workflow's privileged context (secrets, ``GITHUB_TOKEN``, environment approvals already satisfied). The callee can't tell whether the ref points at a vetted branch, a private fork's tip, or an attacker-controlled SHA. The rule fires on ``ref:`` values whose expression resolves to an ``inputs.*`` reference, walking any ``${{ ... }}`` expression that names an input field.

**Known false-positive modes**

- Reusable workflows that ARE the trust boundary (the callee is documented as the authoritative checkout entrypoint and every caller is internal / pinned by SHA) accept this shape by design. The rule still surfaces these so the author can document the contract in a ``.pipelinecheckignore`` rationale; suppress with the caller-list cite.

**Seen in the wild**

- Snyk ``GitHub Actions abuse via workflow_dispatch`` research (2023) showed reusable build workflows that accepted a ``ref`` input and checked it out without validation. An attacker with workflow_dispatch permission (commonly granted to broader sets of actors than push) pointed the checkout at a fork SHA and exfiltrated the production deploy credentials.

<div class="pg-rule__rec" markdown>

**Recommended action**

Validate the ``ref`` input against an allow-list (a regex for ``refs/heads/release-*``, an explicit set of permitted tags, or a 40-char SHA match) BEFORE passing it to ``actions/checkout``. If the workflow only needs to build release tags, hard-code the ref or derive it from ``github.event.release.tag_name`` (still attacker-influenced, but at least scoped to a release event). For reusable workflows, document that the callee assumes callers have already validated the ref, and pin every caller to a known list of refs.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GHA-046: Manual PR-head fetch on untrusted-trigger workflow { #gha-046 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

GHA-002 catches ``actions/checkout`` with ``ref: ${{ github.event.pull_request.head.sha }}``. The same primitive shows up as ``gh pr checkout``, ``git fetch origin pull/<N>/head``, and ``git checkout`` of an attacker-controlled SHA expression inside a ``run:`` block. They all land the same bytes in the workspace with the same privileged context active, so they get the same severity.

**Known false-positive modes**

- Workflows that fetch the PR head purely to *inspect metadata* (``git fetch origin pull/N/head && git log -1 FETCH_HEAD --format=%s``) and never run code from the fetched tree still trigger the rule, because the fetch primitive is the structural signal. The rule has no way to confirm the workspace bytes are never executed. Suppress per-workflow via ``--ignore-file`` once you've verified no ``run:`` / ``uses: ./`` step consumes the checked-out tree; the safer pattern is still to read PR metadata via the GitHub API rather than materializing the head ref.

**Seen in the wild**

- GitHub Security Lab: [Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/) (2020) listed manual ``git fetch pull/<N>/head`` as one of the equivalent ways teams shoot themselves in the foot. Auditors checking only ``actions/checkout`` miss the shell-level variants entirely.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't materialize the PR head in a ``pull_request_target`` or ``workflow_run`` job. If you need to inspect PR content, split the workflow: a privileged half (with secrets) that uses metadata only (PR number, base ref, label) and an unprivileged ``pull_request`` half that builds the code with no secrets in scope.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-047: Action ref resolves to a recently committed tag or SHA { #gha-047 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Reads ``ref_committed_at`` from ``ctx.action_metadata[owner/repo]`` (populated by the ``--resolve-remote`` path via ``GET /repos/{owner}/{repo}/commits/{ref}``). Fires when the referenced ref's commit date is younger than ``MIN_REF_AGE_DAYS`` (7). Trusted publishers (``actions``, ``aws-actions``, ``azure``, ...) are skipped by default to avoid firing on legitimate retags of floating majors; pin to a SHA to opt those back in. Without ``--resolve-remote`` the rule passes silently with a discovery nudge.

**Known false-positive modes**

- A legitimate first-party action that's outside the default trusted-publisher allowlist (a small vendor org that publishes a real action; you'd like it included) will fire after every release for the cooldown window. Either pin to a SHA (preferred) or suppress via ignore-file with a dated note; the suppression decays once the ref ages past the threshold.

**Seen in the wild**

- Multiple action-tag compromises (ua-parser-js npm 2021, tj-actions/changed-files 2025) followed the same shape: a tag was re-pointed at a malicious commit and consumers pulling on the next CI run executed the payload. Cooldown gating turns the community-detection window into a defense.

<div class="pg-rule__rec" markdown>

**Recommended action**

Wait until the referenced tag or commit has had time to be reviewed by the upstream community before pulling it into CI. The default cooldown is seven days. Either bump the pinned ref to an older release, or wait 7 days and re-run. If the action is internal / first-party and the freshness gate is unwanted, pin to a 40-char commit SHA — SHA pins don't move under a retag and are the preferred long-term mitigation.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GHA-048: Workflow step writes a file under .github/workflows/ { #gha-048 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-CODE-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-94</span> <span class="pg-tag pg-tag--cwe">CWE-913</span>
</div>

Fires when a ``run:`` body writes a file path containing ``.github/workflows/`` via shell redirect (``>``, ``>>``), ``tee``, ``cp`` / ``mv``, heredoc, ``cat <<EOF >``, or a templating tool (``envsubst``, ``yq -i``, ``sed -i``). The rule also fires on a ``uses:`` of a third-party action whose documented behavior is workflow file generation (anything matching ``stefanzweifel/git-auto-commit`` paired with a ``.github/workflows`` argument). The single Shai-Hulud worm (2026) propagated via this exact pattern: a postinstall script wrote ``.github/workflows/shai-hulud-workflow.yml`` into every repo the stolen ``GITHUB_TOKEN`` could push to.

Distinct from GHA-019 (token-to-file persistence) and GHA-049 (cross-repo push): GHA-048 catches the *content* (a workflow file is written somewhere on the runner), GHA-049 catches the *push* (the runner's git remote is a repo other than the one under test).

**Known false-positive modes**

- Workflow-bootstrap repos (``cookiecutter-gh-action``, internal scaffolding for new microservices) legitimately scaffold ``.github/workflows/`` files. The right scope is a single, well-named step in an environment-gated job; suppress on that specific step with a rationale that names the destination repo and the gating environment.
- Bot accounts that legitimately republish workflow files (``release-please-action`` updating its own manifest) are narrow allow-list candidates rather than blanket suppression targets.

**Seen in the wild**

- Shai-Hulud npm worm (2026): the malicious postinstall script in compromised packages used the runner's GITHUB_TOKEN to push ``.github/workflows/shai-hulud-workflow.yml`` into the victim's repos. On the next push trigger the worm ran with fresh token scope, repeating the propagation step against every repo the token could reach.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove the step that writes into ``.github/workflows/``. A workflow that authors a sibling workflow is the canonical worm-propagation primitive: the new file runs on the next matching trigger with the repo's GITHUB_TOKEN. There is no legitimate non-automation reason for an in-CI step to write workflow YAML; bot-style automation (release-please, Renovate) should be moved to an external account whose token is scoped, audited, and not the runner's ``GITHUB_TOKEN``. If the write is a templated scaffold (``cookiecutter`` for a new repo), do it in a separate, environment-gated job and ensure the target is never the same repo's workflows dir.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-049: Workflow step makes a privileged git write (cross-repo or actions[bot] bypass) { #gha-049 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-CODE-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-913</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Four shapes are detected in ``run:`` bodies:

1. ``git push`` to a remote whose URL is interpolated from an expression (``${{ ... }}``), an env var (``$VAR``), or is not the canonical ``origin`` / ``upstream``;
2. ``gh repo create`` / ``gh repo edit`` / ``gh repo transfer`` / ``gh api /repos/...`` whose target owner is parameterized;
3. ``gh release create`` / ``gh release upload`` against a repo specified via ``-R <owner>/<repo>`` where the value is parameterized rather than a literal allow-list entry;
4. ``git config user.name 'github-actions[bot]'`` (or ``actions-user`` / ``41898282+github-actions[bot]``) co-occurring with any ``git push`` in the same job. The combination is the canonical branch-protection bypass-abuse shape: GitHub's documented operational convenience is to list ``github-actions[bot]`` in ``Allow specified actors to bypass required pull requests`` on the default branch, after which any workflow that assumes that identity can push to ``main`` without review. The SCM provider's SCM-018 catches the branch-protection side; this leg catches the workflow that's pre-positioned to exploit it.

Pairs with GHA-048 (self-mutation, which catches the *write* into ``.github/workflows/`` of a sibling workflow): GHA-049 catches the *push* primitive that lets a worm leave the current repo. Together they cover both halves of the Shai-Hulud propagation step.

**Known false-positive modes**

- Mirror jobs (push to ``github.com/<our-org>/<mirror>``), monorepo release jobs that push to a publishing org, and release-please-style automation legitimately push to a different repo. Suppress on the specific step name with a rationale that names the literal target. The rule does NOT fire on ``git push origin <ref>`` or ``git push upstream <ref>`` where the remote URL is otherwise unspecified.

**Seen in the wild**

- Shai-Hulud npm worm (2026): the propagation loop combined a stolen GITHUB_TOKEN with ``gh repo create`` plus ``git push`` to seed ``shai-hulud-workflow.yml`` into every repo the token could reach. Without the cross-repo push primitive the worm cannot leave the first infected runner.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't push from CI to a repository whose owner is supplied by an unvetted source (an env var, a workflow input, an interpolated PR field, or a step output). Cross-repo writes from CI are the second leg of the Shai-Hulud propagation loop, the worm uses the runner's GITHUB_TOKEN (or a stolen PAT) to ``git push`` or ``gh repo create`` against every repo the token can reach. If the workflow truly needs to push to an external repo, bind the step to a protected ``environment:`` and pin the destination to a literal ``owner/repo`` string.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-050: Publish step relies on long-lived registry token { #gha-050 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Fires when a step matches a known package-publish primitive AND the job has no protected ``environment:`` AND the step references a long-lived registry secret. Publish primitives covered:

- ``run: npm publish`` / ``pnpm publish`` / ``yarn publish``
- ``run: twine upload`` / ``run: poetry publish`` / ``run: uv publish``
- ``run: gem push`` / ``run: cargo publish``
- ``uses: pypa/gh-action-pypi-publish`` with a ``password`` input (the trusted-publisher path leaves ``password`` unset);
- ``uses: JS-DevTools/npm-publish`` with a ``token`` input.

Long-lived secret heuristic: the step's ``env:`` or ``with:`` block references ``NPM_TOKEN``, ``NODE_AUTH_TOKEN``, ``PYPI_TOKEN``, ``TWINE_PASSWORD``, ``POETRY_PYPI_TOKEN``, ``RUBYGEMS_API_KEY``, or ``CARGO_REGISTRY_TOKEN`` from ``secrets.*``. A job that already binds to a protected ``environment:`` passes regardless, because the environment's required-reviewers / branch-rule controls compensate for the static credential.

Pairs with GHA-030 (cloud OIDC trust). GHA-030 covers the cloud-credentials exchange; GHA-050 covers the package registry side.

**Known false-positive modes**

- Private / internal registries that don't support OIDC (legacy Artifactory, self-hosted Nexus without OIDC broker) require a static token. The right response is ``environment:`` gating with required reviewers on the publish job; suppress this rule with a rationale that names the protected environment.
- First-publish bootstrap of a new package (npm and PyPI both require an initial manual publish before trusted-publisher can be wired). The rule fires; suppress on the specific step until the trusted-publisher record is in place.

**Seen in the wild**

- Shai-Hulud npm worm (2026): the worm's self-propagation step scraped ``NPM_TOKEN`` from runner env / ``~/.npmrc`` and used it to ``npm publish`` patch versions of other packages the maintainer's account owned. Provenance + OIDC + environment gating turn that step into a no-op: the OIDC token doesn't survive the run, and an environment-gated publish requires a human reviewer.
- TanStack / Mistral compromises (May 2026): same shape, mass publish of poisoned versions using maintainer credentials. An environment gate on the publish job would have stopped the unattended release.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace long-lived publish tokens with OIDC trusted-publisher flows and bind the publish job to a protected ``environment:``. Concretely:

- **PyPI**: use ``pypa/gh-action-pypi-publish`` with PEP 740 trusted publishing (no ``password`` input); the GHA OIDC token is exchanged at PyPI for a short-lived upload token.
- **npm**: use ``--provenance`` on ``npm publish`` from a job that requests ``id-token: write`` (npm provenance, GA 2024); drop ``NODE_AUTH_TOKEN`` / ``NPM_TOKEN`` from the env block where possible.
- **GHCR / ECR / GAR**: prefer ``configure-aws-credentials`` with ``role-to-assume`` (or the Azure / GCP equivalent), not static registry passwords.
- Add ``environment: <protected-name>`` to the publish job so branch restrictions and required reviewers apply.

A long-lived ``NPM_TOKEN`` is the fuel a Shai-Hulud-shaped worm needs: once stolen from any runner it can publish more compromised packages on the org's behalf. OIDC tokens expire in minutes and are scoped to the run that requested them.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-051: services / container image is not pinned by digest { #gha-051 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Walks ``jobs.<id>.services.<name>.image`` and ``jobs.<id>.container.image`` (the two places a GitHub-hosted runner pulls a third-party image at job start). Flags any reference that isn't pinned by ``@sha256:<digest>``: bare tags (``postgres:16``), ``latest``, no-tag (``redis``), and ``mcr.microsoft.com/dotnet/sdk:8.0``-style tag pins all fail.

Complements DF-001 (Dockerfile ``FROM`` pinning), GHA-001 (action ``uses:`` pinning), and GHA-040 (known-compromised action refs). Where those catch your own code pulling a third party, GHA-051 catches the *runner* pulling a third-party image to host the workflow alongside your code — same trust shape, different ingress.

**Known false-positive modes**

- Workflows that pull from an org-internal private registry where the registry itself enforces image immutability sometimes pin by tag deliberately. The safer pattern is still ``@sha256:``: the registry's immutability is a separate trust boundary you'd need to audit, while a digest pin is self-verifying. Suppress with a rationale that names the registry and the audit channel.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace every ``services.<name>.image:`` (and the same field on a job-level ``container:`` block) with a ``<image>@sha256:<digest>`` reference. The services / container runs alongside the workflow on the same runner and sees the same secret environment, so a swapped sidecar image is the same shape of attack as a swapped action: arbitrary code on the runner under the workflow's identity. Use a registry that returns immutable digests (``docker buildx imagetools inspect`` resolves a tag to a digest), pin to that digest, then re-pin on the next intentional upgrade — exactly the workflow GHA-001 already documents for ``uses: actions/...@<sha>``.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-052: actions/cache key includes untrusted PR-controllable input { #gha-052 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-CODE-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-345</span> <span class="pg-tag pg-tag--cwe">CWE-353</span>
</div>

Walks every step using ``actions/cache@*`` (or the ``cache-save`` / ``cache-restore`` variants) and checks ``with.key:`` (plus ``with.restore-keys:``) for references to attacker-controllable expression contexts: ``github.head_ref``, ``github.event.pull_request.*``, ``github.event.issue.*``, ``github.event.comment.*``, and the actor / sender fields when used in a key.

Pairs with GHA-027 (``pull_request_target`` on untrusted input) and GHA-046 (manual PR-head fetches on untrusted triggers): the same set of expression contexts that flow into a shell are also the contexts that flow into cache key construction. References to ``github.ref`` / ``github.ref_name`` / ``runner.os`` / ``hashFiles(...)`` are safe and pass.

**Known false-positive modes**

- Some workflows legitimately scope cache keys per feature branch by including ``github.head_ref`` in a ``pull_request`` workflow where the cache is segmented by ref (so cross-branch poisoning is impossible). The right pattern is to prefix the key with a non-attacker-controllable namespace AND rely on ``restore-keys`` only for read-fallback. Suppress on the specific step with a rationale that documents the namespacing.

<div class="pg-rule__rec" markdown>

**Recommended action**

Build the cache key from values an attacker cannot control. ``hashFiles('**/package-lock.json')`` and the like are safe — the hash changes only when the tracked files change, which is itself the trust signal. Avoid ``github.head_ref``, ``github.event.pull_request.*``, ``github.event.issue.*``, and any ``inputs.*`` whose value can be set by a ``workflow_dispatch`` from an untrusted actor.

The attack is cache poisoning: an attacker opens a PR whose branch name (``head_ref``) is crafted so that ``actions/cache`` stores a malicious payload under a key that a subsequent privileged run (e.g., on ``main``) consumes. The next run hits the poisoned cache, executes the attacker's code under the trusted workflow's permissions, and the original PR never has to be merged. Pin keys to ``hashFiles`` of lockfiles or branch-restricted ``github.ref_name`` (post-checkout, only commits already in the trusted branch generate that ref name).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-053: if: predicate evaluates attacker-controllable context as expression { #gha-053 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-CODE-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-94</span> <span class="pg-tag pg-tag--cwe">CWE-1336</span>
</div>

Scans every job-level and step-level ``if:`` for references to attacker-controllable expression contexts: ``github.event.head_commit.message``, ``github.event.pull_request.title``, ``...body``, ``...head.ref``, ``github.head_ref`` (the top-level shorthand for the same PR source-branch name), ``github.event.issue.title`` / ``...body``, ``github.event.comment.body``, ``github.event.review_comment.body``, ``github.event.review.body``.

Safe contexts (``github.ref``, ``github.ref_name``, ``github.actor``, ``github.repository``, ``github.event_name``) are not flagged — those are set by GitHub, not by the actor. ``inputs.*`` references are also safe by convention; the trigger channel that supplies them is a separate trust boundary the workflow author controls.

Complements GHA-002 (``run:`` body interpolating untrusted context — same source set, shell sink) and GHA-052 (cache key derived from untrusted context — same source set, cache sink). GHA-053 closes the third sink: the expression evaluator itself.

**Known false-positive modes**

- A workflow that legitimately gates on the existence of certain text in the commit message (release automation) and is invoked only via ``workflow_dispatch`` from a trusted actor isn't exposed to the attack. The right pattern is still to route through a step output for clarity; suppress on the specific job/step when the trigger channel itself enforces the trust boundary.

<div class="pg-rule__rec" markdown>

**Recommended action**

Compare against safe context keys (``github.ref``, ``github.actor``, ``github.repository``) and check the untrusted input via a step output rather than a direct ``if:`` reference. Concretely: read the attacker-controllable field into a step output first, then use ``if: steps.gate.outputs.is_release == 'true'`` rather than ``if: contains(github.event.head_commit.message, '[release]')``. The shape difference is subtle but decisive: GitHub passes the ``if:`` string through its expression evaluator, which means certain payloads in the untrusted value (single-quote injection, nested ``${{ }}``) execute as expression syntax rather than matching as a literal. Routing through a step output forces the value to land in a shell variable first, where the runner's normal quoting protects it.

Documented attack: a PR title of ``${{ secrets.X }}`` inside an ``if: contains(github.event.pull_request.title, ...)`` predicate evaluates the ``secrets.X`` reference instead of comparing it as a literal, exfiltrating the secret into the workflow's conditional decision and from there into logs.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-054: actions/checkout with ssh-key persists SSH credential in repo { #gha-054 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-522</span> <span class="pg-tag pg-tag--cwe">CWE-538</span>
</div>

Walks every step with ``uses: actions/checkout@*`` and checks the ``with:`` block. Fires when both:

* ``with.ssh-key`` is set (any value — ``${{ secrets.  X }}`` is the typical shape), AND
* ``with.persist-credentials`` is not explicitly set   to ``false`` (the default behavior is ``true``).

Complements GHA-037 (ArtiPacked / persist-credentials on token-based checkouts). Where GHA-037 catches the ``GITHUB_TOKEN`` persistence shape, GHA-054 catches the SSH-deploy-key persistence shape — same risk, different credential type.

**Known false-positive modes**

- Workflows that genuinely need the SSH key to remain available in the repo (a single-job pipeline that clones, builds, and pushes back to the same repo using the same key) sometimes set ``persist-credentials: true`` deliberately. The safer pattern is to split the push into a separate job whose ``actions/checkout`` re-clones with the same key but without persist; or use a fine-grained PAT for the push step. Suppress with a rationale that names the single-job constraint.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``with: persist-credentials: false`` on every ``actions/checkout`` step that also passes ``ssh-key:`` from a secret. With ``persist-credentials: true`` (the default), the checkout action writes the SSH key into ``.git/config`` of the checked-out repo and configures the local repo to use that key for subsequent ``git`` invocations. Any later step in the same job that runs untrusted code (a build script, a test fixture, a postinstall) inherits the credential via the repo's git config — same shape as the ``ArtiPacked`` family GHA-037 catches for ``GITHUB_TOKEN``.

The safe pattern: ``actions/checkout@<sha>`` with ``ssh-key: ${{ secrets.DEPLOY_KEY }}`` AND ``persist-credentials: false``. The action uses the key for the initial clone, then unsets it; subsequent steps don't have access. If you actually need to ``git push`` later in the job using the same key, re-configure with ``GIT_SSH_COMMAND`` in just that step rather than globally.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-055: Reusable workflow outputs derive a secret or caller-input value { #gha-055 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-200</span> <span class="pg-tag pg-tag--cwe">CWE-532</span>
</div>

Scans ``on.workflow_call.outputs.<name>.value:`` for ``${{ secrets.* }}`` references (and also the ``${{ inputs.* }}`` shape when the caller can pass secrets through). Skips workflows that don't declare ``on.workflow_call`` — only reusable workflows have outputs that propagate across the workflow boundary.

Complements GHA-019 (token-to-file persistence) and GHA-033 (secret echoed in ``run:``) — both catch a secret leaking via the *log* surface. GHA-055 closes the third surface: the workflow boundary itself, where a reusable workflow's outputs cross into the caller's context without masking.

**Known false-positive modes**

- A reusable workflow that emits a *hash* of a secret (``sha256(secret)``) as an output is not the same risk shape — the original secret is not recoverable. The rule errs on the side of flagging any direct ``${{ secrets.* }}`` / ``${{ inputs.* }}`` substring in the output value; suppress when the value is provably a one-way transform.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove every ``${{ secrets.* }}`` and ``${{ inputs.* }}`` reference from the ``on.workflow_call.outputs.<name>.value:`` field. A reusable workflow's outputs are visible to the caller as ordinary job outputs (``needs.<job>.outputs.*``), which means: the secret value gets written into the caller's build log when the caller references the output, it gets persisted to the workflow run's summary, and any cross-job ``needs`` chain in the caller propagates it further. GitHub's secret-masking layer only redacts the value in the *defining* workflow's logs; once the value crosses the workflow boundary via ``outputs:``, the masking doesn't follow. The ``inputs.*`` route is the indirect form: a caller wires ``with: x: ${{ secrets.X }}`` into one of the reusable workflow's inputs, and re-emitting that input as an output crosses the same boundary with the same loss-of-masking outcome.

If the caller genuinely needs information derived from a secret (e.g., a build artifact name incorporating a tenant id), derive the non-secret transform on the callee side first (``echo "name=$(echo \$SECRET | sha256sum | cut -d' ' -f1)" >> $GITHUB_OUTPUT``) and emit only the transformed value. The reusable workflow's outputs should never contain raw secret bytes or caller-controlled input bytes.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GHA-056: Workflow body contains a known supply-chain worm indicator { #gha-056 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-CODE-INTEGRITY</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-506</span> <span class="pg-tag pg-tag--cwe">CWE-913</span>
</div>

Distinct from GHA-027 (which fires on behavioral primitives, reverse shells, base64-decoded exec, exfil-channel domains) and from GHA-048 / GHA-049 (which fire on the *write* or *push* primitives). GHA-056 fires on the *literal IOC* — the filenames, repo names, and webhook UUIDs that surfaced in the published worm payloads. Currently covers:

* ``shai-hulud-workflow.yml`` — the workflow file the Shai-Hulud worm dropped into every writable repo.
* Webhook UUID ``bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`` — the Shai-Hulud webhook.site collector path.
* ``Shai-Hulud`` / ``Shai-Hulud Migration`` — the public exfil repo names the worm created under each victim's account.
* ``s1ngularity-repository*`` — the Nx-attack public exfil repo name pattern.

The IOC list is curated and append-only, mirroring the shape of ``_compromised_actions.py`` / ``_compromised_packages.py``. Refresh by PR with the vendor advisory cited in the commit.

**Known false-positive modes**

- Security-training repositories, CTF challenges, and red-team exercise workflows legitimately carry these IOC strings as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare literals in a production workflow still fire.
- Detection / threat-intel repos that maintain IOC lists in checked-in YAML are the expected source of legitimate hits. Suppress on the specific file with a rationale that names the repo's purpose.

**Seen in the wild**

- Shai-Hulud npm worm (Sept 2025): the worm wrote ``.github/workflows/shai-hulud-workflow.yml`` into every repo the stolen GITHUB_TOKEN could reach; the dropped workflow then POSTed harvested secrets to ``webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`` and pushed a sibling copy into a public ``Shai-Hulud`` repo under the victim's account.
- Nx s1ngularity compromise (Aug 2025): the malicious postinstall pushed harvested secrets to public ``s1ngularity-repository*`` repos created under the victim's account via ``gh repo create``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Treat this workflow as already-compromised, not at-risk. A literal worm IOC in the YAML means either the file was written by a worm payload (Shai-Hulud / s1ngularity), or someone hard-coded the IOC for a reason that needs a paper trail. Required steps: (1) preserve the file, do not just revert it; (2) rotate every credential the runner can reach (GITHUB_TOKEN-scoped + every secret referenced anywhere in ``.github/``); (3) audit GitHub audit log for the time window between the IOC appearing and the rotation completing; (4) check the org for sibling repos with the same IOC (the worm propagated). If the literal is intentional (a detection fixture, a red-team exercise), suppress with ``.pipelinecheckignore`` carrying an ``expires:`` date — never permanently.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GHA-057: Secret-scanner output sent to network egress { #gha-057 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-CODE-INTEGRITY</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-200</span> <span class="pg-tag pg-tag--cwe">CWE-552</span>
</div>

Three shapes fire:

1. ``trufflehog`` / ``gitleaks`` invocation in a ``run:`` block whose stdout pipes to ``curl`` / ``wget`` / ``nc`` / ``gh api -X POST`` — this is the harvest leg of the Shai-Hulud worm postinstall and any similar credential-stealer primitive.
2. ``trufflehog`` / ``gitleaks`` invoked unconditionally on a workflow whose triggers include ``pull_request_target``, ``issue_comment``, or ``workflow_run`` — the scanner is running with privileged secrets on an attacker-influenced trigger, so even if the output isn't piped to egress today, the next person editing the workflow can land that change via a PR comment.
3. ``curl`` / ``wget`` / ``httpie`` POST/PUT/PATCH (or ``--data`` upload) to a non-GitHub host whose payload references ``${{ secrets.* }}``, a credential-named env var (``$GITHUB_TOKEN``, ``$NPM_TOKEN``, ``$AWS_*`` keys, etc.), or dumps the runner env (``$(env)``, ``$(printenv)``, ``env > ...``). Catches the third-party-webhook exfil shape where the scanner doesn't run at all — the workflow simply POSTs a build-telemetry payload to an external service that, if the domain lapses or the service is breached, leaks every downstream build's env (which includes ``GITHUB_TOKEN`` always, plus any mapped ``${{ secrets.* }}``). GitHub-owned hosts are allow-listed (``github.com``, ``api.github.com``, ``*.githubusercontent.com``, ``codecov.io`` for the canonical upload path).

Legitimate uses pass: scanner output written to ``${{ github.workspace }}`` or a file under the repo, output uploaded via ``github/codeql-action/upload-sarif`` (CodeQL API, not raw HTTP), and any invocation gated by a ``push``-to-default-branch ``if:`` predicate.

**Known false-positive modes**

- Security teams that run secret scanners and POST results to their own internal SOAR / ticketing system trip the egress leg of this rule. Suppress on the specific step with a rationale that names the destination host; the rule's default posture is that any scanner-to-network pipe is credential-exfil-shaped.

**Seen in the wild**

- Shai-Hulud npm worm (Sept 2025): the postinstall payload ran TruffleHog against the filesystem and cloud metadata endpoints, then POSTed the discovered secrets to ``webhook.site/<uuid>`` and a public GitHub repo created by the worm. The TruffleHog leg is what made the secrets worth stealing; without it the worm would have nothing to exfiltrate.

<div class="pg-rule__rec" markdown>

**Recommended action**

Stop piping secret-scanner output to a network egress tool. Legitimate scans write their findings to the workspace, the Code Scanning API (SARIF upload), or the workflow log — none of which involve ``curl`` / ``wget`` / ``nc`` / ``gh api POST``. If the scanner is run on a fork-PR-style trigger (``pull_request_target`` / ``issue_comment`` / ``workflow_run``), move it to a vanilla ``pull_request`` trigger so an attacker can't supply the scanner's configuration or scan path. Pin the scanner action to a commit SHA, not a tag, and gate the upload step behind a protected environment.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-058: Agentic CLI invoked with permission-bypass flags { #gha-058 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-CODE-INTEGRITY</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-269</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Two detections feed the rule. Either is enough for the finding to fire.

**A. Bypass-flag shape.** A ``run:`` body invokes one of the following CLIs with the matching permission-bypass flag:

* ``claude … --dangerously-skip-permissions``
* ``gemini … --yolo``
* ``q chat … --trust-all-tools``
* ``cursor-agent …`` (any unprotected invocation; the CLI's default mode is the unsafe one)
* any of the above with ``--allowedTools '*'`` / ``--allowedTools '.*'`` / ``--allowedTools all``
* ``aider`` / ``openhands`` / ``goose`` with equivalent ``--auto`` / ``--no-confirm`` / ``--full-auto`` flags.

Does NOT fire on a clearly-scoped invocation, e.g. ``claude --allowedTools 'Read,Grep'`` with a literal allow-list, or ``q chat --trust-tools 'fs_read'``.

**B. PR-checkout topology** (zizmor proposal #1605 / #1607). Step-order traversal within a job. Fires when an agentic CLI (any of the names above) runs in a step *after* a step that checked out a PR head (``actions/checkout`` with ``ref:`` interpolating ``github.event.pull_request.head.*``, ``github.head_ref``, or a ``refs/pull/*/head`` literal) AND a write-scope token is in scope for the job (job-level ``permissions: write-all``, any token granted ``write``, ``id-token: write``, or no ``permissions:`` block declared anywhere, since the runtime default carries ``contents: write`` on most triggers). Pairs with GHA-045 (caller-controlled ref) and GHA-046 (manual PR-head fetch), the agentic-CLI primitive turns a contributor-controlled tree into a token-exfil tool, no bypass flag needed.

**Known false-positive modes**

- Internal tooling that legitimately runs an agentic CLI in CI (e.g. a doc-generation job) might pass a bypass flag for convenience. The right fix is to scope the allow-list rather than suppress the rule. If suppression is truly the only path, do it on the specific step with a rationale that names which tools the agent is allowed to invoke.

**Seen in the wild**

- Nx s1ngularity compromise (Aug 2025): the malicious postinstall payload looked for ``claude``, ``gemini``, and ``q`` on PATH and invoked them with ``--dangerously-skip-permissions`` / ``--yolo`` / ``--trust-all-tools`` plus a prompt that walked the filesystem and emitted any secret-shaped values. The same primitive in a CI workflow turns the runner's secrets into an open buffet for whoever can land a PR. https://nx.dev/blog/s1ngularity-postmortem

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't run an agentic CLI (claude / gemini / q / cursor-agent / aider / openhands / goose) with its safety flags disabled inside CI. The flags ``--dangerously-skip-permissions``, ``--yolo``, ``--trust-all-tools``, ``--allowedTools "*"`` let the agent shell out, read arbitrary files, and post to arbitrary HTTP endpoints with no per-action prompt — under the runner's identity. In CI that means it can read every ``${{ secrets.* }}`` value the workflow has access to and POST them anywhere. Either drop the bypass flag (and accept the manual confirmation prompts CI can't satisfy, so don't run it in CI at all), or gate the step behind a protected ``environment:`` and pre-vet the prompt that's being fed to the agent.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-059: npm install without registry-signature verification step { #gha-059 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Fires once per workflow when:

1. The workflow runs at least one npm / pnpm install command (``npm ci``, ``npm install``, ``npm i``, ``pnpm install``, ``pnpm i``, ``pnpm ci``);
2. No step anywhere in the workflow runs ``npm audit signatures`` or ``pnpm audit signatures``.

Yarn / Bun-only workflows pass silently because the ``audit signatures`` primitive is npm-CLI-specific (Yarn Berry's equivalent ``yarn npm audit`` does not yet verify registry trusted-publisher signatures; Bun has no equivalent step). The rule pairs with NPM-002 (lockfile entry missing integrity hash) and NPM-006 (known-compromised package version): NPM-002 / NPM-006 verify *what* the lockfile pinned, and GHA-059 verifies the lockfile pinned what the maintainer actually signed.

**Known false-positive modes**

- Workflows that build and test against a private registry without trusted-publisher records (legacy Artifactory, self-hosted Verdaccio without sigstore integration) cannot run ``npm audit signatures`` meaningfully — the registry has no signatures to verify against. Suppress this rule on the specific workflow with a rationale that names the private registry; revisit when the registry adds trusted-publisher support.
- Workflows whose only install command is ``npm install --no-save`` for a one-off tool (linter, doc generator) without a lockfile in the repo. Suppress if signature verification adds no signal because nothing is pinned in the first place; the right fix is usually to add the lockfile, not suppress the rule.

**Seen in the wild**

- Shai-Hulud npm worm (2026) / TanStack / axios patch-release compromises: each abused the gap between lockfile-pinned integrity and registry-signed-publisher provenance. The lockfile faithfully pinned what the maintainer's account published; ``npm audit signatures`` would have flagged that the bytes weren't signed by the trusted-publisher record on file with the registry.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add an ``npm audit signatures`` step (or ``pnpm audit signatures``) after the install step. Lockfile pinning guarantees installed bytes match what the lockfile recorded; ``audit signatures`` verifies those bytes were signed by the registry-trusted publisher for the package. Without it, a compromised maintainer account can publish a malicious version that the next lockfile refresh will pin and install without complaint, because integrity-only checks have no view into who actually signed the bytes. Place the step after ``npm ci`` / ``pnpm install`` and before any code from ``node_modules/`` runs (``npm run build``, test, publish).

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-060: pip install without `--require-hashes` verification { #gha-060 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Fires once per workflow when:

1. The workflow runs a real ``pip install`` invocation (``pip install``, ``pip3 install``, ``python -m pip install``, ``python3 -m pip install``) that isn't a tooling-bootstrap exempted by the allowlist;
2. No invocation in the workflow passes ``--require-hashes`` AND no step uses a lockfile-consuming manager (``uv sync`` / ``uv pip sync``, ``poetry install``, ``pipenv install --deploy`` / ``pipenv sync``).

Tooling-bootstrap allowlist (silent-passes): ``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``, ``pip install --upgrade pip-tools``, ``pip install pipx``, ``pip install pip-audit / cyclonedx-bom / semgrep``. These are the same shapes GL-022 / BB-022 exempt for the dep-update rule.

Pairs with the per-file PYPI-002 rule (lockfile hash pin presence) on the package-side: PYPI-002 verifies *what* the requirements file pinned, GHA-060 verifies the install command actually consumes those pins.

**Known false-positive modes**

- Pipelines that build against a private index without SHA-256 hash records (legacy DevPI, self-hosted simple indexes without per-file hashes) cannot run ``--require-hashes`` meaningfully. Suppress on the specific workflow with a rationale that names the private index.
- One-off tool installs that aren't on the allowlist but are genuinely bootstrap-only (e.g. ``pip install some-niche-linter``). The right fix is usually to install via the lockfile-managed venv; if not feasible, suppress on the specific step.

**Seen in the wild**

- PyPI maintainer-account compromises (ctx 2022, requests-darwin-lite 2024) shipped malicious sdists / wheels under existing version pins. ``--require-hashes`` would have refused the swapped artifact because the recorded SHA-256 wouldn't match the malicious tarball.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every dependency with a SHA-256 hash and install with ``pip install -r requirements.txt --require-hashes``. The hash-pinned mode refuses to install any package whose downloaded tarball doesn't match a recorded SHA-256, which is the equivalent of npm's lockfile-integrity guarantee for PyPI. Generate the hashes with ``pip-compile --generate-hashes`` (from ``pip-tools``) or migrate to a package manager that hash-pins by default: ``uv sync`` (reads ``uv.lock``), ``poetry install`` (reads ``poetry.lock``), or ``pipenv install --deploy`` (reads ``Pipfile.lock``). The rule silent-passes when any of those managers runs in the same workflow.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-061: GitHub App token minted without a `permissions:` filter { #gha-061 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--esf">ESF-C-LEAST-PRIV</span> <span class="pg-tag pg-tag--esf">ESF-D-TOKEN-HYGIENE</span> <span class="pg-tag pg-tag--cwe">CWE-250</span> <span class="pg-tag pg-tag--cwe">CWE-732</span>
</div>

Fires when a step uses one of the known App-token minting actions without a ``with.permissions`` input:

- ``actions/create-github-app-token`` (the official action; the canonical pattern documented on the GitHub Apps + Actions page).
- ``tibdex/github-app-token`` (the older community action that the official one replaced; many workflows still pin it).
- ``peter-murray/workflow-application-token-action`` (similar shape, older.)

The rule is shape-only and doesn't inspect what the App is actually installed with. That's intentional: the scanner can't see the org-side install record, so the right contract is 'always declare the scopes you need at mint time'. Pairs with GHA-050 (publish without OIDC) on the long-lived-credential axis: GHA-050 covers static registry tokens minted by the operator, GHA-061 covers short-lived App tokens that nonetheless carry org-wide scope.

**Known false-positive modes**

- A workflow that genuinely needs every scope the App carries (rare; usually a release-orchestrator job that writes ``contents`` + ``packages`` + ``deployments`` + ``actions``). The right response is still to list those scopes explicitly so the breadth is documented, not to suppress the rule.
- First-publish bootstrap on a brand-new App install where the available scopes haven't been finalized yet. Suppress on the specific step until the App install settles.

**Seen in the wild**

- zizmor's ``github-app`` audit (2025) flagged this shape after multiple incident reviews showed Apps installed with broad scopes minting full-scope tokens for jobs that only needed ``contents: write``. The runtime cost of one missing ``permissions:`` line is the same as a PAT with all those scopes leaked into the runner.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pass an explicit ``permissions:`` filter when minting a GitHub App installation token. The minted token will then carry only the requested scopes even if the App's install grants more. Example:

    - id: app-token
      uses: actions/create-github-app-token@<sha>
      with:
        app-id: ${{ secrets.RELEASE_APP_ID }}
        private-key: ${{ secrets.RELEASE_APP_KEY }}
        permissions: >-
          {"contents":"write"}

List every scope the consuming steps actually need; a future reader (and an attacker who lands a step in this job) can then see exactly what the token can do. Apps are commonly installed with broad org-wide scopes (``contents: write, packages: write, actions: write, pull-requests: write, ...``) because granular per-install permissions are tedious; without the filter the runner token inherits every one of them.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-062: OIDC subject claim in sibling IaC grants overly broad scope { #gha-062 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-C-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-284</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Walks the workflow's containing repo (depth-bounded, skipping ``node_modules`` / ``vendor`` / ``.git`` / build dirs) for two sidecar IaC file shapes when the workflow uses an OIDC cloud-credentials action:

1. **AWS trust policy.** Any ``*.json`` whose body parses to an IAM trust document that references ``token.actions.githubusercontent.com`` as a Federated principal AND whose ``Condition.StringLike`` ``...:sub`` value contains ``*`` in the ``repo:`` or ``repo:<org>/`` segment (``repo:*``, ``repo:<org>/*``, ``repo:<org>/*:*``). The branch / environment / ref segment may legitimately carry ``*``; only the org/repo segment is flagged.
2. **GCP Workload Identity Federation.** Any ``*.tf`` containing a ``google_iam_workload_identity_pool_provider`` block whose ``attribute_condition`` is a ``startsWith`` or ``matches`` predicate against ``attribute.repository`` with a value that ends in a ``/`` slash (org prefix, no specific repo). Tighter conditions (``attribute.repository == 'myorg/myrepo'``) are skipped.

Fires once per offending IaC file with a finding location pointing at the file. The walk is cached per scan so adding this rule doesn't compound the cost of GHA-030 / IAM-008. Pairs with GHA-030 (workflow-side environment binding) and IAM-008 (live AWS IAM audit); this leg covers the static IaC checked into the repo.

**Known false-positive modes**

- Test fixtures and documentation samples that intentionally embed permissive trust policies (e.g. cicd-goat's ``scenarios/10-oidc-aws-wildcard-sub/trust-policy.json`` itself, when scanned in-place). Suppress with a path filter on the specific test directory. The rule is intentionally broad on file-name match so a renamed ``my-prod-trust-policy.json`` still surfaces.

**Seen in the wild**

- Multiple post-disclosure writeups of GitHub-to-AWS OIDC misconfigurations (Cider Security 2022, Datadog 2023, AquaSec 2024) traced the issue to a ``repo:*`` or ``repo:org/*`` ``StringLike`` subject pattern that was kept as a stop-gap during initial onboarding and never tightened. Any fork PR or any newly-created org repo could mint a production-role token until the policy was edited.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin the OIDC subject claim to a specific repository (and ideally a specific branch / environment ref). For AWS IAM trust policies, replace ``StringLike`` ``token.actions.githubusercontent.com:sub`` values like ``repo:*`` or ``repo:<org>/*`` with ``repo:<org>/<repo>:ref:refs/heads/main`` (or ``:environment:<name>`` for environment-scoped tokens). For GCP Workload Identity Federation, replace ``attribute_condition`` predicates that only check the org prefix (``attribute.repository.startsWith('myorg/')``) with an equality on the exact ``<org>/<repo>`` plus branch / environment attributes.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-063: ``if:`` predicate gates on a spoofable bot-actor comparison { #gha-063 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-290</span>
</div>

Fires when a job-level or step-level ``if:`` expression compares one of the three actor-side context fields (``github.actor``, ``github.triggering_actor``, ``github.event.sender.login``) to a bot login. Three spelling variations are detected:

1. Equality against a literal ``*[bot]`` string:
   ``github.actor == 'dependabot[bot]'``.
2. ``contains(github.actor, 'bot')`` and the related ``endsWith(github.actor, '[bot]')`` shortcut.
3. Inequality used as a gate (``!= 'dependabot[bot]'``) is also flagged because the inverted form has the same spoofability surface.

Out of scope (deliberate carve-out): predicates that pair the actor check with ``github.event.pull_request.user.type == 'Bot'`` are not flagged. The ``type`` field is set by GitHub from the account's registration record, not from the trigger, and a re-run can't forge it. The rule fires only when the actor comparison stands alone.

**Known false-positive modes**

- A workflow that legitimately wants to display a different log message when re-run by the bot (e.g. for human-readable triage) and isn't using the predicate as a security gate. Suppress per-step via ignore-file. Note that ``${{ github.actor != 'dependabot[bot]' }}`` as a *display* condition is still flagged because the rule can't tell display from gate; in practice the same expression is reused for both.

**Seen in the wild**

- zizmor v1.25.2 ``bot-conditions`` audit: https://docs.zizmor.sh/audits/#bot-conditions

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't gate on ``github.actor`` / ``github.triggering_actor`` / ``github.event.sender.login``. Any maintainer with write access can re-run a workflow, which sets those fields to the re-runner's login, and on a PR they were merging the bot's side-effects can ride along. Use authenticated signals: ``github.event.pull_request.user.type == 'Bot'`` together with a specific ``login`` check, or a maintainer-controlled label / CODEOWNERS gate.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-064: ``contains()`` invoked with comma-delimited string operand { #gha-064 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-697</span>
</div>

Fires when an ``if:`` expression invokes ``contains(<string-literal>, <expr>)`` where the string literal contains a comma. The comma is the author's tell, they meant the literal to be a list. Substring matches on a no-comma literal (``contains('refs/heads/release', github.ref)``) are not flagged, they're often intentional prefix / suffix checks. Both single and double quote styles are detected.

Argument-order matters: ``contains(<haystack>, <needle>)``. Only the left operand (haystack) is checked; the right operand can be any expression.

**Known false-positive modes**

- A literal that happens to contain a comma but is genuinely meant as a single search string (a free-form PR title fragment, e.g. ``contains('feat:, fix:', github.event.pull_request.title)``). These are rare; almost every comma-in-literal is a list-confusion bug. Suppress per-step via ignore-file when audited.

**Seen in the wild**

- zizmor v1.25.2 ``unsound-contains`` audit: https://docs.zizmor.sh/audits/#unsound-contains

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace the string left operand with an explicit array. ``contains(fromJSON('["main", "develop"]'), github.ref_name)`` is the canonical fix. For very short lists, fan out: ``github.ref_name == 'main' || github.ref_name == 'develop'``. Avoid relying on the string form being substring-matched, both because it's rarely the intent and because a substring match across an attacker-controlled context (``github.head_ref`` etc.) is itself a foot-gun (see GHA-053).

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GHA-065: Workflow body contains zero-width or bidi Unicode characters { #gha-065 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-1007</span>
</div>

Walks every string value in the parsed workflow document (``run:`` bodies, ``with:`` values, ``env:`` values, ``if:`` expressions, etc.) for any of the following Unicode codepoints:

* **Zero-width:** ``U+200B`` (zero-width space), ``U+200C`` (zero-width non-joiner), ``U+200D`` (zero-width joiner), ``U+FEFF`` (zero-width no-break space / BOM).
* **Bidi controls:** ``U+200E`` (LRM), ``U+200F`` (RLM), ``U+202A``-``U+202E`` (LRE / RLE / PDF / LRO / RLO), ``U+2066``-``U+2069`` (LRI / RLI / FSI / PDI).

Any single occurrence fires the rule. Reports the containing key path and codepoint count so the offender can be located in a possibly-large body. The rule is deliberately strict: no carve-out for ``# UTF-8 BOM`` at the start of the file (a BOM in YAML is treated as an opaque character by every parser; reject it). No carve-out for ``zero-width joiner`` in a comment because comments aren't preserved through PyYAML parsing, the visible string values are.

**Known false-positive modes**

- Workflows that legitimately echo internationalized text in a release-notes pipeline. Audit each occurrence; almost every case is unintentional or actively malicious. Suppress per-step via ignore-file when the presence is documented and the surrounding code has been reviewed against the visual-vs-parsed shape question.

**Seen in the wild**

- Boucher & Anderson, ``Trojan Source: Invisible Vulnerabilities`` (2021): https://trojansource.codes/
- zizmor proposal #914 (workflow-bidi-unicode audit): https://github.com/zizmorcore/zizmor/issues/914

<div class="pg-rule__rec" markdown>

**Recommended action**

Strip zero-width and bidi characters from the workflow. Then enforce a PR check that rejects any newly-introduced occurrence: ``rg --no-pcre2 '[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}\x{FEFF}]' .github/`` should match no files. CI workflows don't need any of these characters for legitimate purposes.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-066: ``actions/upload-artifact`` path is a workspace wildcard { #gha-066 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-200</span> <span class="pg-tag pg-tag--cwe">CWE-538</span>
</div>

Fires when a step's ``uses:`` matches ``actions/upload-artifact`` (any major version) AND its ``with.path:`` value is one of:

* ``**/*`` (recursive everything),
* ``.`` (current directory),
* ``/`` or ``./`` (root),
* ``${{ github.workspace }}`` (the entire workspace),
* ``${{ github.workspace }}/**`` and similar suffixes.

Multi-line ``path:`` values (a YAML scalar block listing multiple paths) are scanned line by line; one wildcard line is enough to fire. The rule pairs with GHA-019 (the credential-persistence side: an unconstrained upload after an unconstrained checkout is the full ArtiPACKED chain).

**Known false-positive modes**

- A workflow that genuinely wants to archive the whole build output as a release artifact in a job whose GITHUB_TOKEN was already minimized (``persist-credentials: false`` on the checkout step, no ``id-token: write``) and where ``.git/`` isn't checked out (or was removed). Suppress per-step via ignore-file when the operator has audited that the archive doesn't carry credential-shaped files. Note that an ``id-token: write``-scoped workflow is never safe to wildcard-upload from.

**Seen in the wild**

- ArtiPACKED (Palo Alto Unit 42, 2024): https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/
- zizmor proposal #195 (artifact-poisoning audit): https://github.com/zizmorcore/zizmor/issues/195

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace the wildcard with a minimal allowlist of artifact paths. ``path: build/`` (or ``path: |\n  dist/\n  coverage.xml``) keeps the artifact bounded to the build output the downstream consumer actually needs. If you need a debug dump of the workspace, scope it to a temporary directory the workflow assembles, then upload that. Always explicitly exclude ``.git/`` and any ``node_modules`` / ``vendor`` trees from a wildcard upload.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-067: ``actions/cache`` writes credential-shaped paths { #gha-067 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-200</span> <span class="pg-tag pg-tag--cwe">CWE-524</span>
</div>

Fires when an ``actions/cache`` step's ``path:`` value (single line, multi-line YAML scalar block, or YAML list) contains any of the following:

* The full home directory (``~``, ``~/``, ``$HOME``, ``${HOME}``).
* A credential-shaped dotfile or dotdir under the home directory: ``~/.npmrc``, ``~/.docker``, ``~/.aws``, ``~/.azure``, ``~/.gcloud``, ``~/.kube``, ``~/.ssh``, ``~/.gnupg``, ``~/.netrc``.
* A build-tool config that carries credentials: ``~/.gradle/gradle.properties``, ``~/.m2/settings.xml``.

Pairs with GHA-052 (cache key derives from PR input) and GHA-011 (cache key untrusted). The triple (``cache-sensitive-files`` + ``cache-untrusted-key`` + ``cache-poisoning-restore``) is the full cache-as-leak chain. Each rule fires independently so a workflow that carries any one leg gets the corresponding finding.

**Known false-positive modes**

- Self-hosted runners with carefully-scoped HOME directories where the credential-shaped paths are intentionally empty (initialized fresh per job). Suppress per-step via ignore-file when the runner provisioning model is documented. GitHub-hosted runners reset between jobs but the cache content persists across jobs / runs.

**Seen in the wild**

- zizmor proposal #723 (cache-sensitive-files audit): https://github.com/zizmorcore/zizmor/issues/723

<div class="pg-rule__rec" markdown>

**Recommended action**

Cache only the build artifacts that are actually cacheable. Don't cache ``~`` (the whole home dir), don't cache credential-shaped dotfiles (``~/.npmrc``, ``~/.docker``, ``~/.aws``, ``~/.ssh``, ``~/.gnupg``, ``~/.netrc``, ``~/.gradle/gradle.properties``, ``~/.m2/settings.xml``). Scope ``path:`` to the package-cache subdirectory only (``~/.cache/pip``, ``~/.npm``, ``~/.cargo/registry``) and let credentials live in the workflow's secrets context, never on disk in a path the cache restorer touches.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-068: ``runs-on:`` targets an end-of-life hosted-runner image { #gha-068 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Fires when a job's ``runs-on:`` (or any matrix-expanded value of it) names a retired or imminently-retired hosted runner image:

* **Ubuntu retired:** ``ubuntu-18.04``, ``ubuntu-20.04``.
* **macOS retired:** ``macos-10.15``, ``macos-11``, ``macos-12``.
* **Windows retired:** ``windows-2016``, ``windows-2019``.

Self-hosted labels (any value that doesn't match a hosted image label) are not flagged here, GHA-012 covers the self-hosted-runner risk separately. List-shaped ``runs-on:`` values (``[self-hosted, linux, x64]``) are treated as self-hosted and skipped.

**Known false-positive modes**

- A repository that intentionally pins to an older image for archive-build reproducibility (rare, but valid). Suppress per-job via ignore-file when the operator has documented the trade-off. Note that GitHub may stop serving the image entirely at some point; the suppression should be re-audited annually.

**Seen in the wild**

- GitHub Actions runner-images retirement schedule: https://github.com/actions/runner-images
- zizmor proposal #260 / #827 (deprecated runner audit): https://github.com/zizmorcore/zizmor/issues/260

<div class="pg-rule__rec" markdown>

**Recommended action**

Bump to a supported image label. ``ubuntu-latest`` /``ubuntu-24.04``, ``macos-latest`` / ``macos-14``, ``windows-latest`` / ``windows-2022``. Pin to a specific major when reproducibility matters (``ubuntu-24.04``); use ``-latest`` only when the workflow tolerates drift. GitHub publishes the retirement schedule at https://github.com/actions/runner-images?tab=readme-ov-file#available-images, audit the matrix periodically as new images deprecate.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-069: ``id-token: write`` granted without an OIDC-consumer step { #gha-069 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-C-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-272</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Fires when both conditions hold:

1. The job has ``id-token: write`` (either declared on the job's own ``permissions:`` block, or inherited from a workflow-level block that the job didn't override).
2. None of the job's steps invokes a known OIDC-token consumer (see ``_OIDC_CONSUMER_PREFIXES`` below).

The consumer list covers the canonical cloud-credentials actions (``aws-actions/configure-aws-credentials``, ``azure/login``, ``google-github-actions/auth``), the trusted-publishing pack (``pypa/gh-action-pypi-publish``, ``rubygems/release-gem``, ``crates-io/publish-action``), and the Sigstore signing pack (``sigstore/cosign-installer``, ``sigstore/gh-action-sigstore-python``,
``slsa-framework/slsa-github-generator``,
``actions/attest-build-provenance``,
``actions/attest-sbom``, and the
``docker/build-push-action`` with ``provenance:`` /
``sbom:`` / ``attestations:`` set). When a workflow adds a new consumer not in this list, file an issue so the rule can recognize it.

**Known false-positive modes**

- Composite actions whose body consumes the OIDC token but whose entry point is named in a workflow that wouldn't otherwise match the consumer list. The local composite-action discovery path (``GitHubContext.from_path``) synthesizes those bodies as ``__composite__`` jobs, so the rule sees the inner steps. Suppress per-job via ignore-file when a workflow consumes the OIDC token via a third-party action this rule's consumer list doesn't name yet.

**Seen in the wild**

- zizmor proposal #1968 (orphan-id-token audit): https://github.com/zizmorcore/zizmor/issues/1968

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop ``id-token: write`` from the job's ``permissions:`` block when no step exchanges the OIDC token for cloud credentials, signs an artifact, or publishes with attestation. If the workflow gains an OIDC consumer later (a new ``aws-actions/configure-aws-credentials`` step, a ``pypa/gh-action-pypi-publish`` upgrade), restore the scope at the job level rather than the workflow level. Job-level grants minimize the window in which the scope is in effect.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-070: ``ssh-keyscan`` / disabled host-key check trust-on-first-use { #gha-070 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-322</span>
</div>

Fires on any ``run:`` body containing one of:

* ``ssh-keyscan ... >> <known_hosts>`` (or ``>`` for overwrite).
* ``-o StrictHostKeyChecking=no`` (single or double quoted) on ``ssh`` / ``scp`` / ``rsync`` / ``sftp``.
* ``-o UserKnownHostsFile=/dev/null`` (the inverse shape: don't persist any host key check).
* ``-o StrictHostKeyChecking=accept-new`` (TOFU mode, accepts the first key seen).

The rule pairs with GHA-023 (TLS / cert verify bypass) on the HTTPS side and with GHA-054 (checkout SSH-key persistence) on the credentials side. All three describe the same threat shape: turning off authentication primitives that defend against MITM on a runner whose network the workflow doesn't fully control.

**Known false-positive modes**

- First-time bootstrap of a self-hosted runner where the runner image's host-key store is intentionally empty and ssh-keyscan is the bootstrap step. Suppress per-step via ignore-file when the bootstrap step is bounded by a post-bootstrap key-validation check (compare the ingested key against a known-good fingerprint stored in a secret). Without that follow-up validation the suppression isn't safe.

**Seen in the wild**

- zizmor proposal #2012 (ssh-keyscan audit): https://github.com/zizmorcore/zizmor/issues/2012
- GitHub Docs - SSH key fingerprints: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin the SSH host keys explicitly. For GitHub's ``github.com`` host, ship the published fingerprints (see ``github.com/.well-known/ssh-fingerprints``) in a ``known_hosts`` file that the workflow installs. Never call ``ssh-keyscan`` from a workflow, every invocation is trust-on-first-use against whatever the network returns. Same applies to ``StrictHostKeyChecking=no`` / ``UserKnownHostsFile=/dev/null`` on ``ssh`` / ``scp`` / ``rsync``, those flags accept any host key the first (and every subsequent) connection presents.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## GHA-071: ``shell: pwsh`` / ``powershell`` on a Linux / macOS step { #gha-071 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-704</span>
</div>

Fires when a ``run:`` step (job-level or workflow-level default) declares ``shell: pwsh`` / ``shell: powershell`` while the job's ``runs-on:`` is a Linux or macOS image. Three sources are considered:

1. ``jobs.<id>.steps[].shell:`` (step-level override).
2. ``jobs.<id>.defaults.run.shell:`` (job-level default).
3. ``defaults.run.shell:`` (workflow-level default).

Out of scope: ``shell: bash`` / ``shell: sh`` on a Windows runner. Bash is preinstalled on every GitHub-hosted Windows image and the cross-shell language drift goes in the other direction (Windows-only built-ins missing). The risk-asymmetry is intentional: pwsh on Linux is the canonical zizmor advisory; the inverse is covered by reviewer attention rather than a rule.

**Known false-positive modes**

- PowerShell-heavy organizations standardizing on pwsh across all OS targets for tooling consistency. Suppress per-step via ignore-file when the operator has audited the workflow's escaping conventions against the pwsh tokenizer. The rule is LOW severity and advisory, the FP rate is acceptable for a default-fire posture.

**Seen in the wild**

- zizmor proposal #288 (powershell-on-linux audit): https://github.com/zizmorcore/zizmor/issues/288

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop the explicit ``shell:`` on non-Windows runners so GitHub's default (``bash``) is used. If multiline PowerShell work is genuinely needed on Linux / macOS, isolate it in a separate job that pins ``runs-on:`` to a Windows image, OR name the shell explicitly per-step so the reviewer can confirm the language match. Mixing pwsh and bash semantics inside the same workflow is a low-impact-but-real source of escaping bugs.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-072: Secret in env: at a wider scope than its consumer { #gha-072 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--esf">ESF-C-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-200</span> <span class="pg-tag pg-tag--cwe">CWE-272</span>
</div>

Fires in two shapes:

1. **Job-level over-provisioning.** A ``jobs.<id>.env`` entry's value references ``${{ secrets.* }}`` AND no more than one step in that job references the env var. The other steps inherit the secret in their process env without using it.
2. **Workflow-level over-provisioning.** A workflow-level ``env:`` entry's value references ``${{ secrets.* }}`` AND no more than one job in the workflow references the env var. The other jobs' processes carry the secret without using it.

A step's ``env:`` block at the step level is the safe default and stays silent. The rule is name-aware: a job that defines ``DEPLOY_TOKEN`` and ``BUILD_TOKEN`` at the job level, with only one step using each, fires twice (one finding per overprovisioned var).

**Known false-positive modes**

- Composite steps that consume the env var internally and would need ``env:`` block forwarding to see the value scoped at step level. The local composite-action discovery path synthesizes those bodies as ``__composite__`` jobs; the env-var reference shows up there. If it doesn't (a remote composite not loaded by ``--resolve-remote``), suppress per-step via ignore-file with a note pointing at the composite action.

**Seen in the wild**

- zizmor v1.25.2 ``overprovisioned-secrets`` audit: https://docs.zizmor.sh/audits/#overprovisioned-secrets

<div class="pg-rule__rec" markdown>

**Recommended action**

Move the ``env:`` block carrying the secret to the step that consumes it. When two or more steps in the same job need the value, surface it on each step's ``env:`` (or compute it once via ``echo "name=..." >> $GITHUB_OUTPUT`` from a dedicated minimal step). Avoid workflow-level ``env:`` for secrets, every job in the workflow then inherits the value.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-073: Reusable workflow declares an unused ``workflow_call`` secret { #gha-073 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-1100</span>
</div>

Fires on a workflow whose ``on.workflow_call.secrets`` block declares a name (``token`` / ``required: true`` / ``required: false`` / inline shorthand) that the body never references via ``${{ secrets.<name> }}`` interpolation. The body scan covers every string value in the parsed document (``run:`` bodies, ``env:`` entries, ``with:`` values, ``if:`` expressions, and the workflow's top-level ``env``).

Out of scope (deliberate carve-out): secret names that appear only inside ``secrets:`` blocks on a nested ``jobs.<id>.uses:`` reusable-workflow call. Those are forward (the secret flows to a downstream callee that consumes it). Such forward references count as consumers for this rule, the leak surface is bounded by the downstream's declaration.

**Known false-positive modes**

- Workflows that declare a secret to enforce a contract across an organization's reusable-workflow library, even when the current body doesn't read the value. Suppress per-secret-name via ignore-file when the operator has documented the contract reason in a workflow-level comment.

**Seen in the wild**

- zizmor proposal #1044 (unused-secrets audit): https://github.com/zizmorcore/zizmor/issues/1044

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop the unused ``on.workflow_call.secrets.<name>:`` declaration. If the caller's pipeline relies on the name being forced (a contract enforcement), document that intent in a workflow-level comment so the next refactor doesn't delete it silently. When the secret actually does get consumed later, add the ``${{ secrets.<name> }}`` reference back.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-086: Wildcard branch trigger gates an environment-bound deploy { #gha-086 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-C-APPROVAL</span> <span class="pg-tag pg-tag--esf">ESF-C-ENV-SEP</span> <span class="pg-tag pg-tag--cwe">CWE-284</span> <span class="pg-tag pg-tag--cwe">CWE-863</span>
</div>

Fires when both conditions hold:

1. The workflow's ``on: push: branches:`` filter contains at least one wildcard pattern (``*``, ``?``, ``+``, ``[...]``). ``branches: [main]`` is exact-match and stays silent; ``branches: ['main*']``, ``branches: ['release/*']``, and ``branches: ['*']`` all fire.
2. At least one job in the workflow binds ``environment: <name>`` (either the short string form or the long ``environment: {name: <name>, url: ...}`` mapping).

The combination is the canonical deployment-branches-rule-bypass topology: the trigger accepts every branch matching the pattern, the environment gate fires on the deployment, but the reviewer prompt does not surface the diff. A branch named ``main-anything`` matches and the reviewer is asked to approve a generic ``production`` deploy.

Branch wildcards in ``branches-ignore:`` are not flagged (they restrict triggers rather than expand them). Tag filters (``tags:``) are not flagged because tag creation is generally a higher-privilege operation than branch creation.

**Known false-positive modes**

- Internal-only environments scoped to a release-branch convention (``release/*``) where the protection rule is intentionally configured to allow any branch matching the convention. The bypass surface is real but the operator has accepted it. Suppress per-workflow via ignore-file when the convention is documented and the environment's protection rule is audited.

**Seen in the wild**

- OWASP CICD-SEC-1 (Insufficient Flow Control Mechanisms): https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-01-Insufficient-Flow-Control-Mechanisms

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin ``on: push: branches:`` to the exact branch names that should be allowed to deploy (``branches: [main]``, not ``branches: ['main*']``). Configure the matching GitHub environment's ``Deployment branches and tags`` rule with ``Selected branches and tags`` -> exact match. For high-blast-radius environments, require deployment from a protected tag rather than a branch, tags are immutable in a way branches are not.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-087: Derived value of a secret printed to the build log { #gha-087 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-532</span> <span class="pg-tag pg-tag--cwe">CWE-200</span>
</div>

Fires on a single ``run:`` line that combines all three of the following:

1. A reference to a secret, either a ``${{ secrets.* }}`` context expression or a ``$NAME`` / ``${NAME}`` expansion of a step ``env:`` value bound to ``secrets.*``.
2. A transform applied to that reference:
   * **Hash:** ``sha256sum``, ``sha1sum``, ``md5sum``, ``sha512sum``, ``shasum``, ``openssl dgst``.
   * **Encoding:** ``base64``, ``base32``.
   * **Truncation:** ``cut -c<n>``, ``head -c<n>``.
   * **Bash parameter expansion:** ``${VAR:0:N}``, ``${VAR::N}``, ``${VAR:N:M}`` (substring slice).
3. A print sink on the same line: ``echo`` / ``printf`` / ``tee`` at the head, or a redirect to ``$GITHUB_OUTPUT`` / ``$GITHUB_STEP_SUMMARY`` / an ordinary file.

Pairs with GHA-033 (which covers ``set -x`` shell-trace leaks and direct ``echo ${{ secrets.X }}`` shapes). The two rules are deliberately disjoint: a step that hits both shapes fires both findings rather than one. Out of scope (deliberate carve-out): multi-line shape where the transformation lands in an intermediate variable on one line and the variable is printed on another. Detecting that needs cross-line dataflow; the single-line scope captures the canonical foot-guns from the field without over-firing on legitimate verification-then-discard patterns.

**Known false-positive modes**

- Steps that explicitly want a non-reversible secret fingerprint for cross-run identification (rare; the rotation-status use case is the only legitimate one). Suppress per-step via ignore-file when the operator has audited that the entropy of the secret makes the fingerprint genuinely unguessable. A boolean ``set / unset`` print is always safer and is what the recommendation steers toward.

**Seen in the wild**

- OWASP CICD-SEC-10 (Insufficient Logging and Visibility): https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-10-Insufficient-Logging-and-Visibility

<div class="pg-rule__rec" markdown>

**Recommended action**

Never print anything derived from a secret. Not the SHA-256, not the first eight characters, not the base64 wrapper, not the length. GitHub's log redaction only matches the exact registered secret value, every derived form lands in the (world-readable) log unmasked. If you genuinely need to compare secrets across runs, do the comparison inside a step and report a boolean (``[ -n "$X" ] && echo set || echo unset``). If you need to confirm rotation worked, run the downstream check against the secret rather than echo a fingerprint.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-088: Action ``uses:`` slug is a near-edit of a top-traffic action { #gha-088 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Edit-distance check over the parsed ``owner/repo`` slug of every ``uses:`` reference in the workflow, against the curated list in ``pipeline_check.core.checks._primitives.top_actions``. Both step-level ``uses:`` (action references) and job-level ``uses:`` (reusable workflow references) are covered, slug comparison is case-insensitive, and Damerau-Levenshtein (transposition counts as one edit) handles ``actions/cehckout`` alongside ``actions/check0ut``. Distance ceiling is 2 by design, distance-3 false-positives are common on legitimate forks. Exact matches against any list entry never fire, so the rule is silent on canonical references. Refresh the list by PR with a citing public-stats source. Local refs (``./.github/...``) and docker step refs (``docker://...``) are out of scope.

**Known false-positive modes**

- Legitimate forks or community variants that intentionally carry a near-miss name (e.g., an internal fork named ``acme/checkout`` mirroring ``actions/checkout``). Suppress per-finding with a rationale that names the fork and links the source. The rule cannot distinguish a well-known fork from a typosquat; intentional naming collisions are the operator's call.

**Seen in the wild**

- OWASP CICD-SEC-3 (Dependency Chain Abuse) lists action-namespace squatting as a canonical attack shape; the curated industry examples (``actons/checkout``, ``actions/check0ut``) appear in red-team reports and honey-action research from Aikido, Wiz, and JFrog Security Research.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin the intended action. If the ``uses:`` slug above is what you meant, ignore this finding with a rationale; if it isn't, replace it with the canonical owner / repo named in the description, then pin to a 40-char commit SHA (GHA-001 covers the pin) and confirm the SHA is not on the curated compromised list (GHA-040). Typosquat actions are usually long-lived clones with a single modification, the exfiltration step the attacker added; the file count and lineage tell you which workflow primitive was substituted.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-089: Action upstream repo is archived { #gha-089 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Reads the archived bit from ``ctx.action_metadata[owner/repo].archived`` (populated by ``--resolve-remote``; the same per-action repo fetch the GHA-041..043 reputation rules consume). When the metadata is empty (flag off, fetch failed, private repo with no token), the rule passes silently with a one-line nudge pointing at the flag. Covers both step-level ``uses:`` (action references) and job-level ``uses:`` (reusable workflow references); MEDIUM severity, the archived bit alone is not an exploit primitive but it is a documented precondition for the takeover shapes GHA-091 and GHA-040 catch.

**Known false-positive modes**

- An action that an upstream maintainer archived because a first-party replacement ships (e.g., a legacy migration helper deprecated in favor of a built-in feature) is archived for legitimate reasons, not abandonment. The fork-and-vendor recommendation is still the right call for security posture, but suppress per-finding with a rationale once the operator has confirmed the migration path is on a roadmap.

**Seen in the wild**

- tj-actions / reviewdog March 2025 (CVE-2025-30066 / CVE-2025-30154): both action namespaces were briefly archived during the compromise window; pinned consumers ran the malicious tag on the next sync. Archived state is one of the pre-conditions the post-incident timelines highlight.

<div class="pg-rule__rec" markdown>

**Recommended action**

Migrate to an actively-maintained action covering the same surface. Archived upstreams stop receiving security patches the day the archive bit lands; vulnerabilities discovered afterward stay unpatched, and the namespace is eligible to be reclaimed by anyone once the original owner deletes or transfers the repo (the repojacking shape, see also GHA-091). If a fork under your org's control is the only path forward, vendor the action and pin to your fork's SHA, so an upstream takeover can't reach your build runtime.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-090: Action SHA pin references a commit absent from the claimed repo { #gha-090 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-506</span>
</div>

Reads the per-SHA membership probe from ``ctx.action_metadata[owner/repo].sha_membership`` (populated by ``--resolve-remote``; the same per-action metadata pass the GHA-041..043 reputation rules ride on). A False value means ``GET /repos/{o}/{r}/commits/{sha}`` ran and came back empty (most commonly a 404, the SHA is not in the repo's commit graph). When every SHA probed for an action came back False the rule treats that as rate-limit noise rather than impostor-commit and passes silently with a one-line nudge; an attacker has no way to make every legitimate pin fail at once, so unanimous failure is a configuration signal, not an attack.

**Known false-positive modes**

- Force-pushed branches whose old SHA you pinned at can drop out of the reachability set even though the SHA was once legitimate. Re-pin to a SHA that's currently reachable. Suppress per-finding only after confirming through git log / the upstream tag history that the SHA wasn't introduced by a fork.

**Seen in the wild**

- Synacktiv / Octoscan write-ups document impostor-commit as the next-step refinement after SHA pinning becomes table-stakes. The attack reuses the canonical PR-fork shape: a contributor fork has commit X that head doesn't, X gets referenced via ``uses: org/repo@X`` somewhere downstream, and runtime fetches X over GitHub's per-fork object pool.

<div class="pg-rule__rec" markdown>

**Recommended action**

Verify the action's expected SHA via the upstream repo's release / tag history. If the SHA exists only in a fork, either pin to a canonical SHA on the head repository or fork the action under your org's control so the network you depend on is not the attacker's. The impostor-commit shape was popularized by red-team write-ups, the SHA pin passes review eyes because reviewers don't query the network for membership.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-091: Action upstream repo is missing (takeover-eligible namespace) { #gha-091 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Reads from ``ctx.action_fetch_failures``, the set of ``owner/repo`` slugs whose ``GET /repos/{o}/{r}`` fetch returned no payload during the ``--resolve-remote`` pass. Unanimous-failure shape (every referenced action's fetch failed) is treated as rate-limit / resolver noise rather than repojacking, the rule passes silently with a one-line nudge so the operator surfaces the network issue. Single-action failures are real signals because all the other actions in the same scan fetched fine, the infrastructure is up and the 404 is specifically this namespace. Both step-level and reusable-workflow ``uses:`` are covered. HIGH severity, the takeover-eligibility window opens the moment the namespace flips and stays open until the workflow no longer references the slug.

**Known false-positive modes**

- Private upstreams that pipeline-check can't see without a token may show up here. Confirm the 404 by hitting the URL from a browser with the appropriate auth; if the repo is private but reachable for your org, the resolver's unauthenticated probe is the false positive and ``--gh-token`` fixes it. Persistent / by-design private actions should be suppressed per-finding with a rationale that names the access boundary.

**Seen in the wild**

- rentbcn / tj-actions namespace-deletion incidents (2024-2025): the upstream owner deleted the org and the name became registrable. Any workflow that re-resolved a non-SHA ref afterward ran the new owner's code. The shape is the canonical example for repojacking write-ups from Aikido, Wiz, and Snyk Research.

<div class="pg-rule__rec" markdown>

**Recommended action**

Confirm the upstream namespace status. If the owner / repo was genuinely deleted (the resolver returns 404 while the workflow still references it), vendor the action under your org's control immediately, pin to your fork's SHA, and audit any prior workflow runs that used a non-SHA ref (``@v1`` / ``@main``). If the owner was renamed and the new name carries the canonical project, update the ``uses:`` slug. Pairs with the no-name-squatting posture, every external action your CI runs should resolve to a namespace your org controls or one the upstream maintainer still owns.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-092: PR head SHA captured then re-fetched (force-push race) { #gha-092 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-CODE-REVIEW</span> <span class="pg-tag pg-tag--cwe">CWE-367</span> <span class="pg-tag pg-tag--cwe">CWE-362</span>
</div>

Within a single job, step-order traversal looks for:

1. A **capture** step, any step that reads ``github.event.pull_request.head.sha`` (either as a ``${{ }}`` interpolation in a ``run:`` body, in a step or job ``env:`` block, or via a ``run:`` body containing ``git rev-parse HEAD`` after an earlier checkout).
2. A **fetch** step that follows it, an ``actions/checkout`` whose ``with.ref:`` contains the same ``${{ github.event.pull_request.head.sha }}`` expression.

The fire condition is the *order*, capture-then-fetch with no intervening lock on the ref. Workflows that do the fetch FIRST (and only read the SHA after) are not TOCTOU-shaped because there's only one read; pipeline-check stays silent. Cross-job state isn't covered because GitHub-Actions doesn't share a filesystem between jobs by default; ``needs:`` data passing via ``outputs:`` is a separate shape (TAINT-002 territory).

**Known false-positive modes**

- If the workflow genuinely wants to track HEAD-of-PR over time (e.g., a long-running review session that picks up additional commits between gate and merge), the TOCTOU shape isn't the bug, the design is. Suppress per-step with a rationale that explains the contract; pair with a branch-protection rule on the contributor side that blocks force-pushes to PR branches so the race window stays closed in practice.

**Seen in the wild**

- GitHub Security Lab "checkout-after-rev-parse" research (2024) and zizmor proposal #935: red-team demonstrations of contributor force-pushes landing un-reviewed code between a workflow's two reads of the PR head SHA. The attack works against PR-review gates, labeler gates, and any approval-by-SHA workflow that uses the snapshot value for the decision and a live re-read for the build.

<div class="pg-rule__rec" markdown>

**Recommended action**

Read the PR head SHA once and reuse the captured value for the actual checkout. ``actions/checkout`` accepts a ``ref:`` the workflow already resolved (``ref: ${{ steps.snap.outputs.sha }}`` after a ``steps.snap`` that captures the SHA from the event payload), so the same atom drives both the gate decision and the fetch. If a re-read is genuinely needed (you want the latest commit, accepting the race), drop the gate logic that depends on the earlier snapshot, the two are not the same primitive.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-093: Living-off-the-Pipeline indicators (workflow-command abuse) { #gha-093 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-532</span> <span class="pg-tag pg-tag--cwe">CWE-117</span> <span class="pg-tag pg-tag--cwe">CWE-200</span>
</div>

Three independent failure shapes, the rule fires on any of them:

1. **STEP_SUMMARY exfil.** A ``run:`` line that combines a secret reference (``${{ secrets.* }}`` context or a ``$NAME`` / ``${NAME}`` expansion of a step ``env:`` value bound to ``secrets.*``) with a redirect to ``$GITHUB_STEP_SUMMARY``. Disjoint from GHA-087: that rule fires on transform-then-sink; this one fires on the no-transform shape.
2. **Workflow-command log injection.** A ``::warning::`` / ``::notice::`` / ``::error::`` directive whose message interpolates one of the attacker-controlled context expressions (PR title / body / labels / branch name, comment body, head_ref, etc.).
3. **``::add-mask::`` after print.** Within the same ``run:`` block, a print of a variable (``echo $X`` / ``echo "$X"`` / ``printf`` / ``$X`` on its own line) preceded by no ``::add-mask::$X`` directive AND a later line that calls ``::add-mask::`` on the same variable. The directive applies to future log lines only; the earlier print already shipped to the log unmasked.

Pairs with GHA-033 (secret echoed in shell trace) and GHA-087 (derived-value of a secret printed).

**Known false-positive modes**

- STEP_SUMMARY is the legitimate sink for human-readable build digest content; the rule only flags secret-shaped references written there. If you need to surface a non-secret value that happens to share a name with a secret-bound env var, rename the env var. Workflow-command log-injection can be suppressed when the interpolation is into a value that's been sanitized upstream (a step that resolved the PR title through a literal-escape step), with a rationale that names the sanitizer.

**Seen in the wild**

- LOTP (Living-off-the-Pipeline) research: collected from red-team write-ups demonstrating that built-in workflow primitives can act as untraced exfil channels (Trail of Bits 2024 LOTP series, Synacktiv Octoscan paper). The Summary tab and the typed workflow-command directives are the canonical examples; the add-mask ordering bug appears in GitHub's own field reports.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't route secret-shaped values through the Summary tab and don't interpolate PR-controlled text into workflow commands. ``$GITHUB_STEP_SUMMARY`` is rendered to anyone with read access to the workflow run; treat it like a public-readable surface. ``::warning::`` / ``::notice::`` / ``::error::`` are typed log-line directives; interpolate only trusted values into them (or quote the untrusted value through an env var and let the shell escape it). Always ``::add-mask::`` *before* the first time the value could appear in a log line, the order matters.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-094: Action SHA pin matches the current tip of an upstream branch { #gha-094 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Reads the branch-tip set from ``ctx.action_metadata[owner/repo].branch_head_shas`` (populated by ``--resolve-remote``; one ``/branches?per_page=100`` call per action with at least one SHA-shaped ``uses: owner/repo@<sha>``). For each SHA pin, fires when ``<sha>`` is the tip of any branch in the snapshot. Repos with more than 100 branches are an edge case; the rule skips additional pages. Tag-pinned refs (``@v4``, ``@main``) are out of scope, they don't carry the in-network mutability surface this rule targets. Both step-level and reusable-workflow ``uses:`` are covered, case-insensitive matching against the lower-cased SHA snapshot. MEDIUM severity, the maintainer's ability to re-point the branch is a latent risk rather than an in-progress exploit; pair with GHA-047 to escalate when the branch tip is also freshly committed.

**Known false-positive modes**

- An action whose tagged-release flow lags real activity (maintainers push to ``main`` continuously but tag rarely) shows every recent SHA as a branch tip. The right fix is upstream: ask the maintainer to tag, or pin to a tagged ancestor SHA. If suppression is the only path, do it per-finding with a rationale that names the specific SHA and the audit you did against the upstream release notes.

**Seen in the wild**

- GitHub Security Lab + Boost Security "unsigned-tag" research (2024-2025) documenting the re-pointed-branch shape, several supply-chain compromises landed by advancing a ``main`` branch under a SHA that consumers had pinned to. The SHA pin's audit value evaporates the moment the maintainer's next push moves the tip and a consumer team's automation reaches for "latest."

<div class="pg-rule__rec" markdown>

**Recommended action**

Re-pin to a SHA that's tagged in the upstream repo (a release commit) rather than the current tip of an active branch. Branch HEADs are mutable, the maintainer's next push can move the tip even when your pin stays still, and anyone re-pinning to "latest" picks up unaudited code. A SHA that lives only at a tag (``v4.1.7`` -> commit X) is a stable target: re-tagging is a louder, more visible action than a normal push, and a release-flavored tag implies a review pass the maintainer staged. If the action has no tagged releases at all, vendor the action under your org's control or accept the inherent drift risk by suppressing this finding with a rationale.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-095: Action SHA pin does not match its version comment { #gha-095 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Walks each workflow's raw text (``Workflow.raw_text``, populated by ``GitHubContext.from_path``) for lines of the shape ``uses: owner/repo@<40-hex-sha>  # <comment>`` and extracts a version-shaped token (``v4``, ``v4.1.1``, ``1.0-beta``) from the comment body. Looks the token up in ``ctx.action_metadata[owner/repo].tag_shas`` (populated by ``--resolve-remote``; one ``/commits/{tag}`` call per distinct comment-mentioned tag). Fires when the resolved tag SHA differs from the pin. Tags that don't resolve (404, deleted tag, internal alias the comment names that the upstream repo never published) pass silently — the rule treats unverifiable comments as benign rather than guessing. ``v``-prefix variants (``v4`` vs ``4``) are tried both ways so a comment convention swap doesn't false-fire.

**Known false-positive modes**

- A comment that pins to a synthetic tag (``# internal-release-2024-Q4``) the upstream repo doesn't carry resolves to nothing and passes silently, no FP. Genuine false positives appear when the upstream maintainer re-points an existing tag (a force-push to the tag ref) to a different SHA after the consumer pinned, the consumer's pin is now correct and the comment is stale relative to the moved tag. Update the comment (or repin) once the audit establishes the tag-move was legitimate. Suppress per-finding only after that audit.

**Seen in the wild**

- zizmor ``ref-version-mismatch`` audit (https://docs.zizmor.sh/audits/#ref-version-mismatch). Synacktiv / Octoscan supply-chain write-ups consistently highlight comment-vs-SHA drift as the cheapest cross-check to add once SHA pinning becomes table stakes — the SHA passes review eyes because reviewers anchor on the human-readable annotation.

<div class="pg-rule__rec" markdown>

**Recommended action**

Re-resolve the comment-named tag against the upstream repo and update either the SHA pin or the comment so they agree. ``gh api repos/<owner>/<repo>/commits/<tag> --jq .sha`` returns the canonical SHA the comment claims; substitute it into the ``@`` slot, or fix the comment to name the tag the SHA actually belongs to. Pin-maintenance tools (Dependabot, Renovate) write both halves atomically; drift between them is either tool misconfiguration or an attacker hoping reviewers skim the human-readable side rather than the machine-readable one.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-096: Action reference has a known GHSA vulnerability { #gha-096 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-1395</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Queries the GitHub Advisory Database (``GET /advisories?type=reviewed&ecosystem=actions``) for each action referenced by the loaded workflows. Gated on ``--resolve-remote``; the offline default stays no-network. Version matching compares the tag-extracted version against each advisory's ``vulnerable_version_range``. SHA-pinned or major-tag refs fire at MEDIUM confidence when the action has any advisory, since the exact version cannot be confirmed. Pairs with GHA-040 (curated compromised-SHA list, fires on active compromises rather than CVE-tracked vulnerabilities).

**Known false-positive modes**

- Major-version tags (``@v4``) fire at MEDIUM confidence because the rule cannot resolve which patch level the tag currently points at. If the tag follows the latest release and the advisory is already patched, suppress per-finding with a rationale noting the tag is current. SHA pins with no version comment also fire conservatively; adding a ``# vX.Y.Z`` comment lets the rule match precisely.

**Seen in the wild**

- actions/download-artifact path traversal ([CVE-2024-42471](https://www.cve.org/CVERecord?id=CVE-2024-42471), August 2024): versions < 4.1.7 allowed a malicious artifact to write files outside the intended directory, reachable via any workflow that downloads untrusted artifacts. Fixed in 4.1.7.

<div class="pg-rule__rec" markdown>

**Recommended action**

Update the ``uses:`` reference to a version at or above the first patched version listed in the advisory. If no patch is available, evaluate whether the vulnerability is reachable in your workflow's context and consider vendoring a fork with the fix applied. Pin to the patched SHA so a tag rewrite can't walk you back into the vulnerable range.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-097: Recursive PR auto-merge loop { #gha-097 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-D-CODE-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-674</span>
</div>

Fires when a workflow that triggers on ``pull_request`` or ``pull_request_target`` also contains a step that creates or updates a PR (``gh pr create``, ``peter-evans/create-pull-request``, or similar) AND a step that enables auto-merge (``gh pr merge --auto``, ``pascalgn/automerge-action``, or the repo-level ``auto_merge`` API call).

The topology creates a persistence loop: the workflow's own PR triggers the workflow again on the next cycle, allowing an attacker who controls the PR content to maintain code injection across merges without further interaction. This is the OSC&R PER-1 (Recursive PR) attack pattern.

**Known false-positive modes**

- Dependency-update bots (Renovate, Dependabot) sometimes create and auto-merge PRs in a single workflow. If the PR targets a non-default branch or requires human approval via an environment gate, the loop is broken and the rule is a false positive. Suppress with a rationale naming the gating mechanism.

<div class="pg-rule__rec" markdown>

**Recommended action**

Break the loop by removing the auto-merge call from the same workflow that creates the PR, or by gating the merge on a separate approval-required environment. If the automation genuinely needs both create and merge (e.g. a dependency-update bot), ensure the created PR targets a non-default branch that does not re-trigger the same workflow, and require at least one human reviewer before the merge completes.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-098: Pipeline deploys without a security scan gate { #gha-098 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-CODE-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-693</span>
</div>

Walks each workflow's job graph looking for jobs that contain deploy-shaped steps (``kubectl apply``, ``terraform apply``, ``docker push``, ``helm upgrade``, ``aws ecs update-service``, ``gcloud run deploy``, environment-gated jobs, or jobs whose name matches a deploy/release/publish pattern). For each deploy job, checks whether any predecessor in the ``needs:`` DAG or any earlier step in the same job invokes a recognized security scanner (SAST, SCA, container scan, or secret scan).

Fires when a deploy job has zero security-scan predecessors. Severity is MEDIUM (advisory) because the scanner catalog is not exhaustive and some organizations run scans in separate pipelines.

**Known false-positive modes**

- Organizations that run security scans in a separate pipeline or CI system (e.g. a nightly scan job, a third-party SaaS scanner) will see this rule fire on deploy workflows that rely on external gating. Suppress with a rationale naming the external scanner.
- Test/staging deploy jobs that target ephemeral environments may not warrant a scan gate. Suppress per-job.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a security scanning step (SAST, SCA, container scan, or secret scan) upstream of every deploy job. Either add the scan as an earlier step in the same job, or run it in a separate job and add the scan job to the deploy job's ``needs:`` list. Recognized scanners include ``trivy``, ``grype``, ``snyk test``, ``semgrep``, ``bandit``, ``npm audit``, ``pip-audit``, ``gitleaks``, and their corresponding GitHub Actions.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GHA-099: Deployment job has a secret-shaped plaintext env var { #gha-099 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Complements GHA-008 (credential-shaped literal anywhere in a workflow) by focusing on the deploy-job subset with an elevated severity rationale. GHA-008 fires on every credential literal; GHA-099 fires only when the literal appears in a job that also has an ``environment:`` binding or whose name / id matches a deploy / release / publish pattern. The overlap is intentional: the deploy context raises the blast radius from 'CI runner compromise' to 'production compromise', justifying a distinct finding in the report.

Detection reuses the same credential-pattern catalog as GHA-008 (``find_secret_values``), scoped to the ``env:`` block of the deploy job and its steps.

**Known false-positive modes**

- Test fixtures with example credentials (``AKIAIOSFODNN7EXAMPLE``) in a deploy-named job will fire. Suppress with a rationale confirming the value is a non-functional example.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move the credential to an encrypted repository or environment secret and reference it via ``${{ secrets.NAME }}``. For cloud access, prefer OIDC federation (``id-token: write`` + the provider's configure-credentials action) over any static key. A plaintext credential in a deploy job is doubly dangerous: it's visible in every fork and build log AND it has production-level blast radius.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-100: ``cosign verify`` without certificate identity binding { #gha-100 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Scans ``run:`` blocks for ``cosign verify`` and ``cosign verify-blob`` invocations. Flags when either ``--certificate-identity`` / ``--certificate-identity-regexp`` or ``--certificate-oidc-issuer`` / ``--certificate-oidc-issuer-regexp`` is absent from the command line.

The ``cosign verify-attestation`` subcommand is also checked because it shares the same identity-binding requirement.

Multi-line ``run:`` blocks (``|`` / ``>`` YAML scalars) are handled by scanning the full scalar value. Backslash continuations are collapsed before matching so a split invocation like ``cosign verify \\\n  --key ...`` is still detected.

This rule is the consumer-side complement of GHA-006 (missing artifact signing) and GHA-024 (missing SLSA provenance). GHA-100 catches the case where signing exists but the verification step doesn't bind the signer's identity.

**Known false-positive modes**

- Key-based verification (``--key``) doesn't use certificate identity flags. The rule checks for ``--key`` and suppresses the finding when present.

**Seen in the wild**

- https://docs.sigstore.dev/cosign/verifying/verify/
- https://blog.sigstore.dev/cosign-2-0-released/

<div class="pg-rule__rec" markdown>

**Recommended action**

Add both ``--certificate-identity`` (or ``--certificate-identity-regexp``) AND ``--certificate-oidc-issuer`` (or ``--certificate-oidc-issuer-regexp``) to every ``cosign verify`` / ``cosign verify-blob`` invocation. Pin the identity to the expected build pipeline's workflow ref and the issuer to ``https://token.actions.githubusercontent.com`` (for GitHub Actions OIDC). Without both flags, any Sigstore signer's certificate satisfies the verification.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-102: ``actions/checkout`` with submodule fetch on a PR trigger { #gha-102 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires on workflows triggered by ``pull_request`` or ``pull_request_target`` when any ``actions/checkout`` step sets ``with.submodules`` to ``true`` or ``recursive``. The rule does not require a subsequent build step: the submodule clone itself is the risk surface (lifecycle scripts, hooks, and build files execute during or immediately after the clone).

``submodules: false`` (the default) is safe and does not fire.

**Known false-positive modes**

- Workflows that intentionally clone submodules on PRs for monorepo builds where all submodule URLs point at repos within the same organization. Suppress per-step if the submodule origin is validated before the build.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove ``submodules: true`` / ``submodules: recursive`` from checkout steps in PR-triggered workflows. If submodules are genuinely needed for the PR build, pin submodule URLs to trusted repositories in a ``.gitmodules`` file that lives on a protected branch and validate submodule origins before the build step runs. Alternatively, split the workflow: use a low-privilege ``pull_request`` job for code review checks (no submodules) and a ``push``-triggered job for builds that need submodule content.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GHA-103: AI code-review bot on untrusted trigger without environment gate { #gha-103 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-CODE-INTEGRITY</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-94</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Detects AI code-review actions and CLIs running on ``pull_request_target`` or ``issue_comment`` triggers with write permissions and no ``environment:`` gate.

**Known AI review actions** (owner/repo prefix match):
``coderabbitai/ai-pr-reviewer``, ``codiumai/pr-agent``, ``sourcery-ai/action``, ``sturdy-dev/codeball-action``, ``github/copilot-*``, ``autofix-ci/*``.

**CLI detection:** same agentic CLI list as GHA-058 (claude, gemini, q, cursor-agent, aider, openhands, goose) when invoked in a ``run:`` step.

The rule does NOT fire when the job declares an ``environment:`` (the approval gate breaks the attack chain) or when the job's permissions are strictly read-only.

**Known false-positive modes**

- A workflow that triggers on ``pull_request_target`` solely to label or triage (not to review code) may use an AI bot with write permissions. If the bot's prompt never includes attacker-controlled content (diff, PR body, commit messages), suppress with a rationale explaining the prompt source.

**Seen in the wild**

- HackerBot-Claw campaign (February 2026): prompt injection via PR descriptions hijacked Claude-based code reviewers running on ``pull_request_target``. The injected prompt instructed the bot to approve the PR and post secrets in review comments.

<div class="pg-rule__rec" markdown>

**Recommended action**

Gate AI code-review jobs behind a protected ``environment:`` that requires manual approval. This forces a human to verify the PR content before the AI bot processes it, blocking prompt-injection payloads embedded in diffs, PR descriptions, or commit messages. If the bot only needs read access, drop ``pull-requests: write`` and ``contents: write`` from the job's ``permissions:`` block. Consider moving to a ``pull_request`` trigger (which runs on the merge base, not the attacker's HEAD) when write permissions aren't needed.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-104: AI agent generates and pushes commits without PR review { #gha-104 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-CODE-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-345</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Detects the combination of an agentic CLI invocation followed by a direct push in the same job.

**Push patterns detected:**
* ``git push`` in a ``run:`` step
* ``stefanzweifel/git-auto-commit-action``
* ``EndBug/add-and-commit``
* ``actions-js/push``
* ``ad-m/github-push-action``

**Excluded (safe):** ``peter-evans/create-pull-request`` and ``repo-sync/pull-request`` route changes through a PR review cycle and do not trigger this rule.

The rule does NOT fire when the job has an ``environment:`` gate (human approval breaks the attack chain).

**Known false-positive modes**

- Auto-formatting bots that run an AI linter and push the result may trigger this rule. If the formatting changes are deterministic and the branch is protected with required reviews, suppress with a rationale naming the review gate.

<div class="pg-rule__rec" markdown>

**Recommended action**

Route AI-generated changes through a pull request instead of pushing directly. Replace ``git push`` or auto-commit actions with ``peter-evans/create-pull-request`` (or equivalent) so a human reviewer sees the AI's output before it lands on a protected branch. If direct push is genuinely needed (e.g. auto-formatting), gate the job behind a protected ``environment:`` that requires manual approval.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-105: Self-hosted runner reachable from an untrusted PR trigger { #gha-105 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--esf">ESF-D-PRIV-BUILD</span> <span class="pg-tag pg-tag--cwe">CWE-94</span>
</div>

Fires when a workflow's `on:` includes `pull_request` or `pull_request_target` AND at least one job's `runs-on:` names a self-hosted runner. Recognizes all three `runs-on` shapes: the bare `self-hosted` string, a list that contains `self-hosted` (`[self-hosted, linux, x64]`), and the long-form `{ group, labels }` dict (a `group:` selector is always a self-hosted runner group; a `labels:` list is matched for `self-hosted`). A `runs-on:` that resolves to a GitHub-hosted image, or to a `${{ }}` expression the scanner can't resolve, is not flagged here.

**Known false-positive modes**

- A private repository with no external forks, where every PR comes from a trusted internal branch, carries less risk: the code reaching the runner is already trusted. The check can't tell public from private, so it fires regardless. Suppress per-job via the ignore-file once the team has confirmed the repo is private and fork PRs can't run. Defaults to MEDIUM confidence for this reason.

**Seen in the wild**

- GitHub docs, Self-hosted runner security: https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security ("we recommend that you only use self-hosted runners with private repositories").
- PostHog disclosure (2024): a fork PR on a self-hosted runner let researchers run code on internal CI infrastructure and reach production credentials.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't run fork / pull-request code on self-hosted runners. Validate PRs on ephemeral GitHub-hosted runners (`runs-on: ubuntu-latest`); reserve self-hosted runners for `push` / `workflow_dispatch` jobs on trusted refs. If a self-hosted runner is unavoidable on a PR (a private repo with no external forks), gate the job behind a job-level `if:` that checks the actor or author association (`github.event.pull_request.author_association == 'OWNER'`), require manual approval via a protected `environment:`, and run the runner with `--ephemeral` so it can't carry state or an implant into the next job (GHA-012).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-106: AI agent CLI runs with a write-scoped GITHUB_TOKEN { #gha-106 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--esf">ESF-C-LEAST-PRIV</span> <span class="pg-tag pg-tag--esf">ESF-D-TOKEN-HYGIENE</span> <span class="pg-tag pg-tag--cwe">CWE-269</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Fires when a job both (1) invokes an agentic CLI in a `run:` step (`claude` / `gemini` / `q chat` / `cursor-agent` / `aider` / `openhands` / `goose`) and (2) has an effective `permissions:` grant of `write-all`, the legacy global `write`, or any of `contents` / `packages` / `actions` / `deployments` set to `write`. Job-level `permissions:` override the workflow-level block (GitHub's runtime semantics), and the job-level value is used when present.

Lower-impact write scopes (`pull-requests`, `issues`, `checks`) and `id-token` are not flagged, comment / label bots legitimately hold them. A job with no `permissions:` block at all is not flagged here either (GHA-004 covers the missing-block case); the default token scope depends on org / repo settings the scanner can't see.

**Known false-positive modes**

- An agent workflow that genuinely needs `contents: write` (e.g. an auto-formatter that commits its own output to a protected branch behind required reviews). The least-privilege fix is still to move the write into a separate, narrowly-scoped step rather than grant it to the agent's job; suppress with a rationale naming the review gate if the split isn't practical. Defaults to MEDIUM confidence.

**Seen in the wild**

- HackerBot-Claw campaign (February 2026): prompt-injection against Claude-based reviewers in CI. The injected agent acted with the job's GITHUB_TOKEN, so the damage scaled with the token's scope.
- GitHub docs, Automatic token authentication: a job's `permissions:` define the GITHUB_TOKEN scope every step (including an agent CLI) inherits.

<div class="pg-rule__rec" markdown>

**Recommended action**

Scope the agent's job to the minimum its non-agent steps need, usually `permissions: contents: read`. If the agent's output must land in the repo, route it through a reviewable PR (`peter-evans/create-pull-request`) from a separate job, or mint a narrowly-scoped token (`actions/create-github-app-token` with an explicit `permissions:` filter, see GHA-061) for just the write step rather than handing the agent a broad `GITHUB_TOKEN`. Never run an agent under `write-all`.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-107: harden-runner runs in audit mode (egress not blocked) { #gha-107 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--cwe">CWE-693</span>
</div>

step-security/harden-runner runs as a runtime agent on the runner. With `egress-policy: audit` (also the default when the input is omitted) it logs outbound traffic but lets every connection through. Only `egress-policy: block` enforces the allowlist and drops connections to hosts outside `allowed-endpoints`. A workflow that adopts harden-runner but leaves it in audit mode gets visibility, not prevention: the exfiltration path the agent exists to close stays open.

Fires for each job whose harden-runner step sets `egress-policy: audit` or omits the input entirely. A step pinned to `block` passes. A value the scanner can't resolve (a `${{ }}` expression) is not flagged.

**Known false-positive modes**

- A deliberate audit-only rollout, the recommended first phase before turning on block, will fire here. Suppress per-job with a rationale while you collect the egress baseline, then switch to block and remove the suppression.

**Seen in the wild**

- StepSecurity, tj-actions/changed-files compromise (2025): the injected payload exfiltrated runner secrets over the network. harden-runner in block mode drops that connection; audit mode only records it after the fact. https://www.stepsecurity.io/blog/popular-github-action-tj-actions-changed-files-is-compromised

<div class="pg-rule__rec" markdown>

**Recommended action**

Set `egress-policy: block` on the harden-runner step and list every host the job legitimately reaches under `allowed-endpoints`. In audit mode harden-runner only records outbound connections; it does not stop a compromised dependency or action from exfiltrating `GITHUB_TOKEN`, OIDC credentials, or secrets. Run once in audit mode to learn the baseline, then switch to block.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## GHA-108: Sensitive workflow has no runtime egress control { #gha-108 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--cwe">CWE-693</span>
</div>

Advisory rule. Fires when a workflow mints an OIDC token (`id-token: write`, at workflow or job scope) or gates a job on a deployment `environment:`, AND no job in the workflow uses an egress-control agent (step-security/harden-runner). Those are the jobs with credentials worth stealing and no runtime guard against a dependency or action exfiltrating them.

Scoped deliberately to OIDC and environment-gated jobs to keep the signal targeted; it does not fire on every job that merely references a secret. Severity is LOW because many teams accept this risk or enforce egress at the infrastructure layer, which the workflow YAML can't express.

Scope note: the harden-runner check is workflow-level. If any job uses harden-runner, the rule passes for the whole workflow, even when a sensitive job (one that mints an OIDC token or deploys through an environment) runs with no harden-runner step of its own. Each GitHub Actions job gets a fresh runner, so a harden-runner step in one job protects only that job; an unprotected sibling job is not flagged.

**Known false-positive modes**

- Egress controlled outside the workflow (self-hosted runners behind a firewall or forward proxy, an org-wide network policy) gives the same protection without a harden-runner step. The scanner only sees the YAML, so it fires anyway. Suppress with a rationale naming the external control.
- A workflow that uses OIDC only to read public data, or an environment with no real secrets, carries less exfiltration risk. Suppress per-workflow.

**Seen in the wild**

- StepSecurity, tj-actions/changed-files compromise (2025): a popular action was backdoored to exfiltrate CI secrets over the network. A runtime egress allowlist drops the connection the payload depends on. https://www.stepsecurity.io/blog/popular-github-action-tj-actions-changed-files-is-compromised

<div class="pg-rule__rec" markdown>

**Recommended action**

Add step-security/harden-runner as the first step of jobs that authenticate via OIDC or deploy through a protected environment, and set `egress-policy: block` with an `allowed-endpoints` allowlist. A static scan can't see what a compromised dependency or action does at runtime; an egress allowlist is the defense-in-depth layer that stops it from shipping the OIDC credential or deploy secret off the runner. If egress is already constrained at the network layer (self-hosted runners behind a firewall or forward proxy), suppress this advisory with that rationale.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## GHA-109: harden-runner is not the first step in the job { #gha-109 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--cwe">CWE-696</span>
</div>

Fires when a job uses `step-security/harden-runner` but the step is not first: at least one step precedes it. Those earlier steps run before the egress monitor is up, so their outbound traffic is neither recorded nor filtered.

Passes when harden-runner is the first step, and is not applicable (passes) when the job doesn't use harden-runner at all. Severity is LOW because the most common shape (a checkout placed first) is a small gap and the fix is a one-line move.

**Known false-positive modes**

- A `checkout` placed before harden-runner is a minor gap: the checkout reaches GitHub, which is allowed regardless. If your pre-harden-runner steps provably make no network calls, the exposure is negligible. Suppress per-job once confirmed.

**Seen in the wild**

- StepSecurity docs, harden-runner usage: the action is documented to run as the first step of the job so the egress baseline covers the whole run. https://github.com/step-security/harden-runner

<div class="pg-rule__rec" markdown>

**Recommended action**

Move the `step-security/harden-runner` step to the top of the job, before `actions/checkout` and any `run:` or setup step. harden-runner only monitors (and in block mode filters) traffic that happens after it starts, so any step that runs before it egresses unwatched. StepSecurity's guidance is that harden-runner is always the first step.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-110: Workflow disables Go module checksum / sum-db verification { #gha-110 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-353</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Walks the workflow / job / step ``env:`` blocks and every ``run:`` step (for inline ``export GOSUMDB=off`` / ``GOFLAGS=-insecure go build`` assignments) and flags the Go integrity-disabling settings via the shared ``_primitives/go_insecure_env`` detector: ``GOFLAGS`` with ``-insecure``, ``GOSUMDB=off``, truthy ``GONOSUMCHECK``, any ``GOINSECURE``, and a broad ``GOPRIVATE`` / ``GONOSUMDB`` glob (``*`` / public TLD / whole host).

Scoped ``GOPRIVATE`` (an internal org namespace) and ``GOPROXY=off`` / ``GOPROXY=direct`` (still checksum-verified) are not flagged. The env-var face of the verification-bypass surface GOMOD-001 warns about; shipped here (and in GL-037 / CC-033) rather than the gomod loader because the setting lives in the CI config, not ``go.mod``.

**Known false-positive modes**

- A workflow that builds only against an internal module proxy on a trusted network may set a scoped ``GOINSECURE`` for one internal host deliberately. Suppress per workflow with a rationale naming the host; the safer path is a TLS-terminating internal proxy that preserves checksum verification.

**Seen in the wild**

- Verification-bypass class: a runner told to skip the Go checksum database / sum file can be served a substituted module (a MITM on an insecure fetch, a poisoned proxy) without ``go mod verify`` catching it, the same gap GOMOD-001 flags from the ``go.sum`` side.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove the Go toolchain environment settings that turn off module integrity verification, so ``go build`` keeps checking every downloaded module against ``go.sum`` and the checksum transparency database. Specifically: drop ``GOFLAGS=-insecure`` (it fetches modules over plain HTTP with TLS validation off), ``GOSUMDB=off`` and legacy ``GONOSUMCHECK`` (they disable the checksum DB / sum check), and any ``GOINSECURE`` entry; and scope ``GOPRIVATE`` / ``GONOSUMDB`` to the exact internal namespace that needs it (``corp.example.com/team/*``) instead of a broad ``*`` or a whole public host. This is the CI-env twin of GOMOD-001: committing a ``go.sum`` doesn't help if the runner is configured to ignore it. For private modules, prefer a trusted internal proxy (``GOPROXY``) that still enforces checksums over disabling verification.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-111: AI agent generates IaC applied to the cloud in the same job { #gha-111 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-C-LEAST-PRIV</span> <span class="pg-tag pg-tag--esf">ESF-D-PRIV-BUILD</span> <span class="pg-tag pg-tag--cwe">CWE-94</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Fires when one job contains both (1) a `run:` step invoking an agentic CLI (`claude` / `gemini` / `q chat` / `cursor-agent` / `aider` / `openhands` / `goose`) and (2) a `run:` step issuing an unattended IaC apply / deploy (`terraform apply`, `terragrunt apply`, `aws cloudformation deploy` / `create-stack` / `update-stack` / `execute-change-set`, `cdk deploy`, `pulumi up`, `sam deploy`). The two can be the same step. Comment-only / echoed occurrences are ignored (shared `find_run_command` chunking).

Distinct from GHA-104 (agent pushes to the repo) and GHA-106 (agent holds a write-scoped GITHUB_TOKEN): here the agent's output reaches the cloud account, not the repository. The rule does not try to prove the agent edits the exact files the apply consumes; co-location in one job (shared workspace + cloud credentials) is the risk. The canonical shape is an agent step followed by an apply step.

**Known false-positive modes**

- A job that runs an agent purely for an unrelated read-only task (summarizing logs, drafting a comment) next to an apply that consumes only committed, reviewed IaC. The fix is still to separate the agent from the privileged apply; suppress with a rationale if the split isn't practical. Defaults to MEDIUM confidence because the rule asserts co-location, not a proven dataflow from the agent to the applied plan.

**Seen in the wild**

- HackerBot-Claw campaign (February 2026): prompt-injection against Claude-based agents in CI. A redirected agent acts with whatever the job can reach, here the cloud account the apply step targets.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't run an agentic CLI in the same job that applies infrastructure. Split the pipeline: let the agent only propose changes into a reviewable PR (`peter-evans/create-pull-request`), and run the `terraform apply` / `cloudformation deploy` from a separate job on the merged, human-reviewed plan, ideally behind a protected `environment:` with required reviewers. If an agent must run next to infra tooling, keep it to read-only commands (`terraform plan`, `cdk diff`) and never let an agent-influenced job reach an unattended apply.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-112: Self-hosted deploy job not gated by a protected environment { #gha-112 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-C-APPROVAL</span> <span class="pg-tag pg-tag--esf">ESF-D-PRIV-BUILD</span> <span class="pg-tag pg-tag--cwe">CWE-284</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Fires when a job (1) runs on a self-hosted runner (the `self-hosted` label on any `runs-on` shape: string, list, or `{ group, labels }` dict), (2) is a deploy, by job-name (`deploy` / `release` / `publish` / `promote`) or by a deploy command in a `run:` step (`kubectl apply`, `terraform apply`, `helm upgrade`, `aws ... deploy`, `gcloud ... deploy`, etc.), and (3) has no `environment:` binding. A job whose deploy commands all target a local mock (LocalStack / kind via `AWS_ENDPOINT_URL` / `KUBE_API_URL` at a localhost address) is treated as a test, not a deploy. Overlaps GHA-014 on the missing-environment axis but is scoped to the higher-severity self-hosted case; the same `environment:` fix clears both.

**Known false-positive modes**

- A self-hosted job named `release` (or running a deploy command) that targets a staging / preview account where an approval gate is intentionally skipped. Bind a separate `environment:` for non-prod with no required reviewers so the intent is explicit in the workflow, or suppress with a rationale. Defaults to MEDIUM confidence because deploy detection is a name / command heuristic.

**Seen in the wild**

- OWASP CICD-SEC-1 (Insufficient Flow Control Mechanisms) and CICD-SEC-7 (Insecure System Configuration): persistent self-hosted runners that deploy without an approval gate let a single low-privilege trigger reach production infrastructure.

<div class="pg-rule__rec" markdown>

**Recommended action**

Bind the deploy job to a protected `environment:` with required reviewers and a deployment-branch policy, and prefer ephemeral self-hosted runners (actions-runner-controller, `--ephemeral`) so a job can't inherit state or credentials from a previous one. Best: run the deploy from a dedicated, minimally-scoped runner pool that only the gated job can reach, and keep untrusted-trigger jobs (fork PRs) off the self-hosted fleet entirely (see GHA-105).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-113: OIDC trusted-publishing job without an environment gate { #gha-113 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-D-TOKEN-HYGIENE</span> <span class="pg-tag pg-tag--esf">ESF-C-APPROVAL</span> <span class="pg-tag pg-tag--cwe">CWE-284</span> <span class="pg-tag pg-tag--cwe">CWE-862</span>
</div>

Fires when a single job satisfies all three:

1. It effectively has ``id-token: write`` (declared on the job's own ``permissions:`` block, inherited from a workflow-level block it didn't override, or via ``permissions: write-all``).
2. It runs a package-publish step. Run-based: ``npm`` / ``pnpm`` / ``yarn publish``, ``twine upload``, ``poetry publish``, ``uv publish``, ``gem push``, ``cargo publish``. Action-based trusted publishers: ``pypa/gh-action-pypi-publish``, ``rubygems/release-gem``, ``crates-io/publish-action``.
3. It binds no ``environment:`` (neither the short string form nor the long ``{name: ...}`` mapping).

The conjunction is the trusted-publishing-without-a-trusted-ref shape: an OIDC token mintable from any branch that runs the workflow, gating publication on nothing the registry checks. A job that binds a protected ``environment:`` passes regardless, because the environment's deployment-branch rule and required reviewers constrain which ref can mint the token. A job with no ``id-token: write`` is the long-lived-token lane GHA-050 covers, not this one.

Defaults to MEDIUM confidence: the rule infers the OIDC trusted-publishing path from the co-occurrence of ``id-token: write`` and a publish step, not from a proven token exchange. A job that mints the OIDC token for signing or cloud credentials and publishes on a long-lived token, or a first-publish bootstrap before the trusted-publisher record exists, can over-flag.

**Known false-positive modes**

- First-publish bootstrap of a new package. npm and PyPI both require an initial manual publish before a trusted-publisher record exists; the workflow may carry ``id-token: write`` ahead of that. Suppress on the specific job until the trusted-publisher + environment are wired.
- A job that mints the OIDC token for signing / cloud credentials (cosign, configure-aws-credentials) and happens to also run a publish step on a long-lived token. GHA-050 is the more precise finding there, but the environment-gate recommendation still applies: an ungated publish job that can mint an OIDC token from any branch is the risk either way.

**Seen in the wild**

- Red Hat npm compromise (BoostSecurity, 'Trusted Publishing, Untrusted Branch', 2026): a counterfeit ``ci.yml`` on a throwaway ``oidc-*`` branch minted an OIDC token that npm trusted publishing accepted, because it validates only org + repo + workflow filename and no GitHub Environment was configured. An environment with a deployment-branch rule would have refused to mint the token from the throwaway branch: https://labs.boostsecurity.io/articles/trusted-publishing-untrusted-branch-red-hat-npm/

<div class="pg-rule__rec" markdown>

**Recommended action**

Bind every package-publish job that mints an OIDC token to a protected ``environment:`` (e.g. ``environment: npm-publish``), then configure that environment's ``Deployment branches and tags`` rule to allow only the release ref (a protected branch or, better, a tag). Concretely:

- Add ``environment: <name>`` to the publish job and set the environment's branch policy to ``Selected branches and tags`` -> the exact release ref. The OIDC token then mints only when the run targets that ref, so a counterfeit workflow on a throwaway branch can't publish.
- Prefer a tag trigger (``on: push: tags:``) or ``workflow_dispatch`` for the release workflow over a branch ``push`` (see GHA-114).
- Keep ``id-token: write`` scoped to the publish job, not the whole workflow.
- For high-blast-radius packages, enable the registry's staged-publishing-with-2FA flow so a human approves the release even after the token is minted.

Trusted publishing alone validates only org + repo + workflow filename; the environment gate is what binds publication to a trusted ref.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-114: Package-publish workflow runs on an unrestricted push trigger { #gha-114 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--esf">ESF-C-APPROVAL</span> <span class="pg-tag pg-tag--esf">ESF-D-TOKEN-HYGIENE</span> <span class="pg-tag pg-tag--cwe">CWE-284</span> <span class="pg-tag pg-tag--cwe">CWE-863</span>
</div>

Fires when both hold:

1. The workflow runs a package-publish step in some job, run-based (``npm`` / ``pnpm`` / ``yarn publish``, ``twine upload``, ``poetry`` / ``uv publish``, ``gem push``, ``cargo publish``) or a trusted-publisher action (``pypa/gh-action-pypi-publish`` / ``rubygems/release-gem`` / ``crates-io/publish-action``). Same publish surface as GHA-113.
2. The workflow is reachable from an unrestricted ``push``: a wildcard ``branches:`` pattern (``*``, ``?``, ``+``, ``[``), or no ``branches:`` filter at all (bare ``on: push`` / ``push: {}`` fires on every branch).

Restricted triggers pass: a tag-only push (``push: {tags: ['v*']}`` with no ``branches:``), an exact branch list (``branches: [main]``), ``workflow_dispatch``-only, or ``release``-only. When ``push`` carries both an exact branch list and tags it stays silent; a wildcard or unfiltered branch push fires even if a tag filter is also present, because the branch path still runs the publish. ``branches-ignore`` without ``branches:`` is unrestricted (every non-ignored branch fires). Emits ``job_anchors`` for the publish jobs so AC-038 can intersect with GHA-113 on the same job.

Defaults to MEDIUM confidence: an internal continuous-delivery pipeline may intentionally publish a snapshot to a private registry on every branch push, so an unrestricted-trigger publish is not always a public-release exposure.

**Known false-positive modes**

- Internal continuous-delivery pipelines that intentionally publish a snapshot / pre-release artifact on every push to a development branch (the publish target is a private staging registry, not the public index). The unrestricted trigger is by design there; suppress per-workflow via ``--ignore-file`` once the publish target is confirmed non-public.
- A workflow whose only ``push`` trigger is an exact protected branch is not flagged, but the writeup still recommends a tag or dispatch trigger over a branch push for public releases.

**Seen in the wild**

- Red Hat npm compromise (BoostSecurity, 'Trusted Publishing, Untrusted Branch', 2026): a counterfeit ``ci.yml`` on a throwaway ``oidc-*`` branch, triggered by a plain ``push``, minted an OIDC token and published 30+ packages. A tag-only or dispatch-gated trigger would not have run from the throwaway branch: https://labs.boostsecurity.io/articles/trusted-publishing-untrusted-branch-red-hat-npm/

<div class="pg-rule__rec" markdown>

**Recommended action**

Trigger a publish workflow only from a ref an attacker cannot cheaply create:

- Prefer ``on: push: tags: ['v*']`` (or ``on: release: types: [published]``) so only a tag/release, not an arbitrary branch, runs the publish path. Tags are a higher-privilege operation than branch creation.
- Or gate the release behind ``on: workflow_dispatch`` so a human starts it.
- If a branch ``push`` trigger is unavoidable, pin ``branches:`` to the exact protected release branch (``branches: [main]``, never ``branches: ['*']`` / ``['release/*']`` / no filter), and pair it with a protected ``environment:`` whose deployment-branch rule enforces the same ref (see GHA-113).

A publish workflow runnable by ``push`` to any branch is the untrusted-branch half of the trusted-publishing attack: a counterfeit workflow on a throwaway branch publishes as the real release.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-115: ``id-token: write`` granted workflow-wide instead of job-scoped { #gha-115 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-C-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-272</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Fires when all three hold:

1. The workflow's **top-level** ``permissions:`` block grants ``id-token: write`` (or ``permissions: write-all``).
2. At least one job consumes the OIDC token (a known consumer step, the same list GHA-069 uses: cloud-credentials actions, trusted-publisher actions, the Sigstore signing pack, ``docker/build-push-action`` with provenance / sbom).
3. At least one job inherits the workflow-level grant (it declares no ``permissions:`` block of its own, so the job-level block does not REPLACE the inherited one) AND does NOT consume the token.

The conjunction is the granted-too-broadly shape: the scope is used somewhere, so dropping it entirely (GHA-069) is wrong, but the workflow-level grant hands a publish-capable mint right to jobs that don't need it. When NO job consumes the token, GHA-069 covers the orphan case instead. When every inheriting job consumes it, the grant is not over-broad and the rule stays silent. A consuming job that declares its own ``id-token: write`` does not need the workflow-level grant, so the workflow-level grant is still flagged if any other job inherits it without consuming.

Defaults to MEDIUM confidence: the over-broad determination depends on recognizing every job's OIDC consumer, and a consumer reached through an action the shared consumer list doesn't name yet can make a consuming job look non-consuming.

**Known false-positive modes**

- A workflow where every inheriting job legitimately consumes the OIDC token (e.g. a matrix of publish jobs) is not flagged. A consumer reached through a third-party action this rule's list doesn't recognize yet can make a consuming job look non-consuming, over-flagging it as over-broad. Extend the consumer list (shared with GHA-069) or suppress per-workflow via ``--ignore-file``.

**Seen in the wild**

- Red Hat npm compromise (BoostSecurity, 'Trusted Publishing, Untrusted Branch', 2026), defense-in-depth item: scope ``id-token: write`` to the publish job so a compromised sibling job cannot mint a publish-capable token: https://labs.boostsecurity.io/articles/trusted-publishing-untrusted-branch-red-hat-npm/

<div class="pg-rule__rec" markdown>

**Recommended action**

Move ``id-token: write`` off the workflow-level ``permissions:`` block and onto only the job(s) that consume the OIDC token (the publish / cloud-credentials job):

- Set the workflow-level ``permissions:`` to what the other jobs actually need (often ``contents: read``), and add a job-level ``permissions: { id-token: write, ... }`` to the consuming job only.
- A workflow-level grant gives every job that doesn't override its permissions the right to mint an OIDC token, so a compromised build / test / lint job can request a publish-capable token it never needed and relay it.
- Job-level grants also minimize the window in which the mint right is in effect (see GHA-069).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-116: Workflow serializes the entire secrets context (toJSON(secrets)) { #gha-116 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-522</span>
</div>

Fires when ``toJSON(secrets)`` appears in any string the workflow evaluates: a step ``run:`` body, a step / job / workflow ``env:`` value, or a step ``with:`` input (the wrappers ``fromJSON(toJSON(secrets))`` and ``format(..., toJSON(secrets))`` match too, since they contain the same substring). HIGH severity, HIGH confidence: serializing the entire secrets context has no benign per-secret use, so the false-positive rate is low. The rare legitimate case (handing every secret to a trusted internal aggregator action) is still an anti-pattern that defeats per-secret scoping and log redaction; suppress it per-resource with a rationale. Distinct from GHA-033 (echoes a named secret), GHA-034 (``secrets: inherit``), and GHA-057 (secret-scanner output to egress).

**Known false-positive modes**

- A workflow that deliberately passes the full secrets context to a trusted, audited internal action (a secrets-sync or vault-bootstrap step) will fire. That is still a broad-surface anti-pattern, but if the receiving action is vetted, suppress per-resource with a rationale naming the action.

**Seen in the wild**

- tj-actions/changed-files + reviewdog supply-chain attack (CVE-2025-30066, March 2025): a compromised action dumped the runner's secrets to the workflow log, affecting 23,000+ repos. The GhostAction campaign (GitGuardian, September 2025) pushed malicious workflows that serialized every repository secret and POSTed them to an attacker endpoint, stealing 3,325 secrets. ``toJSON(secrets)`` is the in-YAML primitive both classes rely on to grab everything at once: https://blog.gitguardian.com/ghostaction-campaign-3-325-secrets-stolen/

<div class="pg-rule__rec" markdown>

**Recommended action**

Never materialize the whole secrets object. ``toJSON(secrets)`` puts every credential the job can see into one string, so a single log line or outbound request exfiltrates all of them at once (the tj-actions / GhostAction 2025 payload pattern). Reference only the specific secrets a step needs by name (``${{ secrets.NPM_TOKEN }}``), bind each to a narrowly-scoped step ``env:``, and prefer short-lived OIDC tokens over long-lived secrets. If a downstream action genuinely needs several secrets, pass them individually rather than the full context.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## GHA-117: IaC apply on an untrusted pull_request trigger { #gha-117 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-94</span> <span class="pg-tag pg-tag--cwe">CWE-78</span>
</div>

Fires when a workflow is triggered by ``pull_request`` or ``pull_request_target`` AND a ``run:`` step invokes an unattended IaC apply (``terraform``/``terragrunt apply`` or ``destroy``, ``aws cloudformation deploy``/``create-stack``/``update-stack``/``execute-change-set``, ``cdk deploy``, ``pulumi up``, ``sam deploy``). Applying attacker-controlled IaC is the plan/apply-on-untrusted-input RCE class. Distinct from GHA-111, which requires an agentic CLI in the loop; here the untrusted input is the PR's own IaC.

<div class="pg-rule__rec" markdown>

**Recommended action**

Never run ``terraform apply`` (or ``cloudformation deploy`` / ``cdk deploy`` / ``pulumi up`` / ``sam deploy``) on a ``pull_request`` or ``pull_request_target`` trigger. Apply executes the PR's IaC, an ``external`` data source, a ``local-exec`` provisioner, or a hijacked provider runs arbitrary code on the runner with whatever cloud credentials (often an OIDC ``id-token``) the apply uses. On PRs run a read-only ``plan`` and post it for review; gate the apply on a separate ``push`` / ``workflow_dispatch`` trigger against the merged, reviewed code, behind a protected ``environment:``.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-118: Untrusted content written to $GITHUB_ENV / $GITHUB_PATH { #gha-118 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-94</span> <span class="pg-tag pg-tag--cwe">CWE-77</span>
</div>

Fires when a workflow reachable from ``pull_request`` / ``pull_request_target`` / ``workflow_run`` / ``issue_comment`` has a ``run:`` step that redirects into ``$GITHUB_ENV`` / ``$GITHUB_PATH`` AND the written content is either (a) file / command output (``cat`` / ``sed`` / ``jq`` / a ``$(...)`` subshell of one, etc.), which is repo / artifact content the trigger lets an attacker control, or (b) a process-hijack key (``LD_PRELOAD`` / ``NODE_OPTIONS`` / ``BASH_ENV`` / ``PYTHONPATH`` / ...) set from a dynamic value. A fixed literal ``echo "KEY=value" >> $GITHUB_ENV`` passes, as does ``$(git describe)`` into a benign key. Distinct from GHA-038 (legacy ``ACTIONS_ALLOW_UNSECURE_COMMANDS`` stdout channel), GHA-019 (a token written OUT of the env file), and GHA-003 / TAINT (``${{ }}`` expression / ``$GITHUB_OUTPUT`` channels), none of which watch attacker content written INTO the env-control file.

<div class="pg-rule__rec" markdown>

**Recommended action**

Never write file content, command output, or any attacker-influenceable value into ``$GITHUB_ENV`` / ``$GITHUB_PATH`` on an untrusted trigger. GitHub sets those vars (and prepends those PATH entries) for every later step, so a single injected line sets ``LD_PRELOAD`` / ``NODE_OPTIONS`` / ``PATH`` and turns a benign later step (which may hold secrets and a write token) into arbitrary code execution. Write only fixed, literal ``KEY=value`` pairs; if a value must be dynamic, validate it against an allowlist first, and never set a process-hijack key from a computed value. This is the file-channel successor to the retired ``::set-env::`` command (GHA-038 covers that legacy stdout channel).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-119: Untrusted context reaches an agentic AI CLI (prompt injection) { #gha-119 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--cwe">CWE-94</span> <span class="pg-tag pg-tag--cwe">CWE-77</span>
</div>

The AI analog of GHA-003 (script injection). Fires when a ``run:`` step invokes an agentic CLI (claude / gemini / cursor-agent / aider / openhands / goose) AND attacker-controllable context reaches that step, either interpolated directly or via an ``env:`` variable the command references. Unlike a shell, an LLM ingests an env-routed value as prompt text, so the GHA-003 mitigation (route through env) does not apply, which is why this is a separate rule.

<div class="pg-rule__rec" markdown>

**Recommended action**

Do not place attacker-controllable context (PR / issue / comment bodies, branch names) in an agentic CLI's prompt. Env-var indirection does NOT sanitize a prompt the way it does a shell command, the model still reads the value. If the agent must see PR content, run it with no write token and no tool / shell access on a sandboxed job behind an environment gate, and treat its output as untrusted.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-120: ML model loaded with trust_remote_code (code execution) { #gha-120 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--cwe">CWE-494</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires on ``trust_remote_code=True`` / ``--trust-remote-code`` in a ``run:`` step. The transformers / huggingface_hub loader executes the model repo's own Python at load time, so an untrusted or unpinned model is arbitrary code execution in CI with the job's secrets and token.

<div class="pg-rule__rec" markdown>

**Recommended action**

Load models with ``trust_remote_code=False`` (the library default). If a model genuinely needs custom code, vet it and pin an exact revision (a commit SHA, not a tag or branch), run the load in a sandboxed job with no production secrets, and prefer safetensors weights over pickle.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## GHA-121: AI model pulled without a pinned revision { #gha-121 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires on a ``run:`` step that fetches a model by a mutable registry reference and supplies no revision pin. Detected fetch forms: ``from_pretrained("org/model")``, ``hf_hub_download`` / ``snapshot_download`` with a ``org/model`` repo id, and ``huggingface-cli download org/model`` / ``hf download org/model``. A finding requires the fetch call and the repo id to sit in the same step (a two-line window absorbs shell continuations).

Does NOT fire when a revision is pinned in the same step (``revision='<sha>'`` / ``--revision <sha>``), when the reference is a local path (``./model``, ``/models/x``) or a variable / ``${{ }}`` interpolation (the value can't be judged statically), or on a bare single-segment canonical hub name (``bert-base-uncased``) that has no ``org/`` namespace, since those are first-party and the org-scoped third-party models are the higher-risk surface.

**Known false-positive modes**

- A team that re-pulls its own org's model on every run may treat the latest revision as intentional. The right fix is still to pin the revision (it makes an upstream compromise visible); if a rolling pull is genuinely wanted, suppress on the specific step with a rationale naming the model and who controls it.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin the model to an immutable revision. Pass an exact commit ``revision=`` to ``from_pretrained`` / ``hf_hub_download`` / ``snapshot_download`` (a 40-char commit SHA, not a branch or a tag, both of which the owner can move), or ``--revision <sha>`` to ``huggingface-cli download``. A pinned revision is what makes a swapped-weights or swapped-loader-code attack show up as a diff in your repo instead of silently landing on the next build. Pair with ``trust_remote_code=False`` (GHA-120) and prefer safetensors weights over pickle.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-122: Unsafe deserialization of a fetched artifact (pickle RCE) { #gha-122 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--cwe">CWE-502</span> <span class="pg-tag pg-tag--cwe">CWE-494</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires per ``run:`` step in two shapes. **(A) Explicit unsafe opt-in**, always: ``weights_only=False`` on a load, or ``allow_pickle=True`` on ``numpy.load`` / ``np.load``. **(B) Fetch + unpickle**, only when both appear in the same step: a remote fetch (``curl`` / ``wget`` / ``hf_hub_download`` / ``snapshot_download`` / ``huggingface-cli download`` / ``hf download`` / ``requests.get`` / ``urlretrieve`` / ``urlopen``) alongside a pickle-backed loader (``torch.load`` / ``pickle.load`` / ``pickle.loads`` / ``joblib.load``).

Does NOT fire when the step takes the safe path (``weights_only=True``, or safetensors via ``safe_open`` / ``load_file``), nor on a bare ``torch.load`` / ``pickle.load`` with no remote fetch in the same step (a load of a locally produced, trusted artifact). The fetch-and-unpickle coupling is what raises it from a hygiene nudge to a code-execution finding.

**Known false-positive modes**

- A step that downloads a non-pickle file for one purpose and separately unpickles a trusted local file for another would match shape B by co-location. Split the two concerns into separate steps, or suppress on the specific step with a rationale naming the artifact's verified source.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't deserialize a downloaded artifact through pickle. Load weights with safetensors, or pass ``weights_only=True`` to ``torch.load`` (the PyTorch 2.6+ default) so only tensors, not arbitrary Python, are unpickled. Drop ``allow_pickle=True`` from ``numpy.load``. If a pickle / joblib artifact is unavoidable, pin and verify its source (a pinned model revision, a checksum, or a signature) and load it in a sandboxed job with no production secrets, not on the default runner with the workflow token in scope.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-123: Agentic CLI output lands without human review { #gha-123 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--cwe">CWE-94</span> <span class="pg-tag pg-tag--cwe">CWE-693</span>
</div>

Fires when one job both invokes an agentic CLI (``claude`` / ``gemini`` / ``cursor-agent`` / ``aider`` / ``openhands`` / ``goose`` / ``q chat``) and, in the same job, lands the result with no review gate. The landing step is one of: ``uses: stefanzweifel/git-auto-commit-action``, ``uses: ad-m/github-push-action``, ``uses: peter-evans/enable-pull-request-automerge``, or a ``run:`` step with ``gh pr merge`` plus ``--auto`` / ``--admin`` / ``--merge`` / ``--squash`` / ``--rebase``.

Does NOT fire when the agent only opens a pull request for review (a bare ``peter-evans/create-pull-request`` with no auto-merge), nor on an auto-commit / auto-merge job that does not run an agent (ordinary formatting / generated-file bots). The agent-plus-auto-land coupling is the signal.

**Known false-positive modes**

- A job that runs an agent for a read-only task (triage, labeling) but also auto-commits an unrelated generated file would match by co-location. Split the agent and the auto-commit into separate jobs, or suppress on the job with a rationale noting the agent does not write the committed paths.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't let an agentic CLI's output reach a branch or a merge without a human review gate. Have the agent open a normal pull request (no auto-merge) so a person reviews the diff before it lands; drop ``peter-evans/enable-pull-request-automerge`` and ``gh pr merge --auto`` from the agent's job, and don't pair the agent with ``git-auto-commit-action`` / ``github-push-action`` that push straight to a branch. If the agent's prompt can be influenced by untrusted input (a PR body, an issue comment, a fetched page), treat the committed result as attacker-controlled.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## TAINT-001: Untrusted input flows across step boundaries via step outputs { #taint-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-78</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

GHA-003 detects the *direct* interpolation case (``${{ github.event.* }}`` inside a ``run:`` body) and the *single-step* env-inheritance case. TAINT-001 fills the cross-step gap: a producer step sets a tainted step output, and a consumer step (in the same job) interpolates it via ``${{ steps.<id>.outputs.<name> }}``. The producer's interpolation is GHA-003's finding; TAINT-001's finding lives at the consumer (the actual injection sink) and carries the full chain in its description so a reader sees both sides at once.

v1 limitations: only same-job step outputs are tracked; ``jobs.<id>.outputs.*`` (cross-job propagation) and reusable-workflow input/output forwarding are tracked as future work in ``ROADMAP.md``. The producer pass matches the canonical ``echo "name=..." >> $GITHUB_OUTPUT`` shape and the legacy ``::set-output name=...::`` workflow-command form.

**Known false-positive modes**

- If the producer step deliberately runs a sanitizer between the interpolation and the ``$GITHUB_OUTPUT`` write (``echo "$TITLE" | tr -dc 'a-zA-Z0-9 ' >> $GITHUB_OUTPUT``), the consumer is no longer exploitable. The rule's regex doesn't model that transformation and will still fire; suppress via ignore-file scoped to the consumer step name when this is the deliberate shape. The producer's GHA-003 finding then carries the residual signal that the sanitizer is load-bearing.

<div class="pg-rule__rec" markdown>

**Recommended action**

Sanitize the value at the step that *writes* the ``$GITHUB_OUTPUT`` entry. The canonical pattern is to interpolate the untrusted source into an ``env:`` variable on the producer step and reference the env var in the ``echo``: ``env: TITLE: ${{ github.event.issue.title }}`` then ``echo "title=$TITLE" >> $GITHUB_OUTPUT``. After that, downstream steps reading ``steps.<id>.outputs.title`` see a string-typed value with no GitHub-expression evaluation pass left to exploit. Removing the source entirely is the safest fix; if the value genuinely needs to flow downstream, round-trip it through an env var the way GHA-003 recommends so the shell quoting still applies.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## TAINT-002: Untrusted input flows across jobs via ``jobs.<id>.outputs:`` { #taint-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-78</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

TAINT-001 catches step-output flow within a single job; TAINT-002 catches the cross-job transition. Engine shape: walk every job's ``outputs:`` mapping looking for values that interpolate either a tainted step output or a direct ``${{ github.event.* }}`` source. Tainted job outputs are matched against every ``${{ needs.<job>.outputs.<name> }}`` reference in any downstream job's ``run:`` / ``with:`` body. Each match emits a TAINT-002 finding with the full chain in the description.

Two propagation hops the engine tracks beyond the obvious ``${{ ... }}`` interpolation:

1. **Step env-var binding.** A producer step with ``env: { LABELS: "${{ toJSON(github.event.pull_request.labels.*.name) }}" }`` and a run body that writes ``echo "targets=$LABELS" >> $GITHUB_OUTPUT`` propagates taint from the env binding into the output, even though the run body's RHS doesn't contain a literal ``${{ ... }}`` token. Catches the indirect-env shape GHA-003 deliberately treats as safe (quoted shell) but that still flows into downstream sinks.
2. **Matrix expansion via ``fromJSON``.** ``strategy.matrix.<axis>: ${{ fromJSON(needs.<job>.outputs.<name>) }}`` paired with ``${{ matrix.<axis> }}`` in a downstream ``run:`` body. Every matrix value the expansion produces lands in the consumer's shell template. This is the GitHub Security Lab matrix-expansion-injection writeup shape that closed several public bug bounties.

Same-step interpolations (the producer's own use of ``${{ github.event.* }}`` inside its ``run:``) are still GHA-003's responsibility; TAINT-002's value is the cross-job hop the single-step rule can't see.

**Known false-positive modes**

- Sanitization between the source interpolation and the $GITHUB_OUTPUT write isn't modeled. If the producer step runs ``echo "$TITLE" | tr -dc 'a-zA-Z0-9 '`` before redirecting to GITHUB_OUTPUT, the consumer is no longer exploitable but TAINT-002 will still fire; suppress via ignore-file scoped to the consumer job's workflow file when this is the deliberate shape.

<div class="pg-rule__rec" markdown>

**Recommended action**

Sanitize the value at the producer step *before* it lands in ``$GITHUB_OUTPUT``. Once the value is in a job output the consuming job has no expression-level escaping pass left, ``${{ needs.<job>.outputs.<name> }}`` substitutes the string verbatim into the consumer's shell. The canonical safe pattern is to copy the untrusted source into the producer step's ``env:`` block, reference the env var quoted in ``echo "name=$VAR" >> $GITHUB_OUTPUT``, and only then surface it through the job output. The consuming job should still treat the value as tainted (use it in env-var form, not interpolated directly into shell).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## TAINT-003: Untrusted input forwarded into reusable workflow ``with:`` { #taint-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-78</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Detection walks every ``jobs.<id>.uses: <callee>`` reference, finds every ``with:`` value that interpolates an attacker-controllable source (direct ``${{ github.event.* }}``, a tainted step output via ``${{ steps.<id>.outputs.<name> }}``, or a cross-job ``${{ needs.<job>.outputs.<name> }}``), and flags the forward.

When the callee body is loaded into the same scan (local ``./.github/workflows/<file>.yml`` references via ``--gha-path``, or remote refs fetched by ``--resolve-remote``), the rule also checks whether the callee references ``${{ inputs.<name> }}`` unquoted in a sink. Confirmed end-to-end paths get HIGH confidence; caller-side-only forward stay at MEDIUM (still a risk surface, but a future change to the callee could expose it).

**Known false-positive modes**

- Callees that wrap the input safely (immediately copy into env, sanitize before use) make the caller-side forward harmless. When the callee body is loaded into the scan, the rule downgrades to MEDIUM confidence on those paths; suppress via ignore-file when the callee's handling is audited and sound. Without ``--resolve-remote`` the rule can't see remote callee bodies and every forward stays at MEDIUM, the right default for unverifiable cross-repo flow.

<div class="pg-rule__rec" markdown>

**Recommended action**

Sanitize the value at the caller before forwarding it across the reusable-workflow boundary. The canonical safe pattern is to copy the untrusted source into a step's ``env:`` block, run a sanitizer (``tr -dc 'a-zA-Z0-9 '`` is enough for a freeform title), surface the sanitized result via ``echo "name=$VAR" >> $GITHUB_OUTPUT``, then forward ``${{ steps.<id>.outputs.<name> }}`` as the ``with:`` input. The callee then sees a string-typed value with no expression-evaluation pass left to exploit. If the callee is under your control, also handle the input via env in the callee's ``run:`` body (not direct ``${{ inputs.<name> }}`` interpolation).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## TAINT-009: Environment-protected secret flows to unprotected job { #taint-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-863</span>
</div>

Detects the pattern where a ``jobs.<id>.outputs:`` mapping interpolates ``${{ secrets.* }}`` (or a step output that was populated from a secret) and the producing job has an ``environment:`` binding while at least one consuming job (via ``needs:``) does not.

The rule performs a conservative check: it flags when the output *value expression* directly references ``${{ secrets.* }}`` or when a step output referenced by the job output was set from a ``${{ secrets.* }}`` context in the step's ``run:`` or ``env:`` block. Indirect flows through multiple env-var hops within the same job are not tracked (the TAINT-002 engine handles general taint propagation).

The ``needs:`` graph is walked transitively: if job A (environment-bound, secret in outputs) feeds job B (no environment) which feeds job C (no environment), both B and C are flagged if they reference the tainted output.

**Known false-positive modes**

- Workflows that intentionally pass non-sensitive environment-specific values (e.g. a deployment URL) through outputs from an environment-bound job. The rule fires on any ``${{ secrets.* }}`` reference in the output value, which may include non-sensitive configuration stored in environment secrets for convenience.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add an ``environment:`` binding to every job that consumes outputs carrying secret-derived values. If the downstream job needs the secret but should not go through the same review gate, create a separate environment with appropriate protection rules. Alternatively, restructure the workflow so the secret never leaves the environment-bound job's boundary: perform the deploy or credential-consuming operation in the same protected job instead of passing the secret through outputs.

</div>

</div>

---

## Adding a new GitHub Actions check

1. Create a new module at
   `pipeline_check/core/checks/github/rules/ghaNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the parsed YAML document.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/github/GHA-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py github
   ```
