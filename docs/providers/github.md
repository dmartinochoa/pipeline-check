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

64 checks · 17 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [GHA-001](#gha-001) | Action not pinned to commit SHA | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-002](#gha-002) | pull_request_target checks out PR head | <span class="pg-sev pg-sev--critical">CRITICAL</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-003](#gha-003) | Script injection via untrusted context | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-004](#gha-004) | Workflow has no explicit permissions block | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
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
| [GHA-031](#gha-031) | Workflow uses retired set-output / save-state command | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-032](#gha-032) | run: invokes local script on untrusted-trigger workflow | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GHA-033](#gha-033) | Secret value echoed / printed in a run: block | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GHA-034](#gha-034) | Reusable workflow called with secrets: inherit | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-035](#gha-035) | github-script step interpolates untrusted context | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-036](#gha-036) | runs-on interpolates untrusted context | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [GHA-037](#gha-037) | actions/checkout persists GITHUB_TOKEN into .git/config | <span class="pg-sev pg-sev--high">HIGH</span> |  |
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
| [GHA-049](#gha-049) | Workflow step pushes to a repo outside the current owner | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-050](#gha-050) | Publish step relies on long-lived registry token | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-051](#gha-051) | services / container image is not pinned by digest | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-052](#gha-052) | actions/cache key includes untrusted PR-controllable input | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-053](#gha-053) | if: predicate evaluates attacker-controllable context as expression | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-054](#gha-054) | actions/checkout with ssh-key persists SSH credential in repo | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-055](#gha-055) | Reusable workflow outputs derive a secret or caller-input value | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-056](#gha-056) | Workflow body contains a known supply-chain worm indicator | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GHA-057](#gha-057) | Secret-scanner output sent to network egress | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [GHA-058](#gha-058) | Agentic CLI invoked with permission-bypass flags | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [GHA-059](#gha-059) | npm install without registry-signature verification step | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-060](#gha-060) | pip install without `--require-hashes` verification | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [GHA-061](#gha-061) | GitHub App token minted without a `permissions:` filter | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [TAINT-001](#taint-001) | Untrusted input flows across step boundaries via step outputs | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [TAINT-002](#taint-002) | Untrusted input flows across jobs via ``jobs.<id>.outputs:`` | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [TAINT-003](#taint-003) | Untrusted input forwarded into reusable workflow ``with:`` | <span class="pg-sev pg-sev--high">HIGH</span> |  |

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
- [Keeping your GitHub Actions and workflows secure: Untrusted input](https://securitylab.github.com/resources/github-actions-untrusted-input/) (GitHub Security Lab, 2020): catalogued real-world Actions carrying the same primitive. The fix pattern (split the workflow into a privileged labeler + an unprivileged builder) is now standard guidance.

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

## GHA-004: Workflow has no explicit permissions block { #gha-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-C-LEAST-PRIV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Without an explicit `permissions:` block (either top-level or per-job), the GITHUB_TOKEN inherits the repository's default scope, typically `write`. A compromised step receives far more privilege than it needs.

**Known false-positive modes**

- Read-only / lint-only workflows that do not call any write-scoped API often pass without an explicit block because the default token scope on public repos is read. The rule defaults to MEDIUM confidence to reflect this.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a top-level `permissions:` block (start with `contents: read`) and grant additional scopes only on the specific jobs that need them.

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

- Test fixtures and documentation blobs sometimes embed credential-shaped strings (JWT samples, AKIAI... examples). The AWS canonical example ``AKIAIOSFODNN7EXAMPLE`` is deliberately NOT suppressed, if it appears in a real workflow it almost always means a copy-paste from docs was never substituted. Defaults to LOW confidence.

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

- Organisations using actions-runner-controller (ARC), autoscaled pools, or vendor runner fleets often use labels like ``arc-*``, ``autoscaled-*``, or ``ephemeral-pool-*`` instead of a bare ``ephemeral`` label. The check only matches the literal ``ephemeral`` token on ``runs-on``; extend via a custom allow-prefix config if your fleet uses a different naming convention. Defaults to MEDIUM confidence.

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

Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Known false-positive modes**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

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
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-77</span>
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

Don't print secret values from a script. GitHub's log redaction is a best-effort string match. It doesn't catch base64 / urlencoded / partial substrings, and any caller that retrieves the raw log via the API gets the unredacted stream. If you need to confirm the secret exists, log a boolean (``[ -n "$X" ] && echo set || echo unset``) or a fingerprint (``echo "$X" | sha256sum | head -c8``), never the value itself.

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

Hard-code ``runs-on:`` to a specific runner label or list of labels. If the choice has to be parameterised across callers, validate the input against an allowlist of known-good labels before the job runs (a small ``if:`` guard at job level), and never accept ``${{ inputs.* }}`` or any ``${{ github.event.* }}`` field as the ``runs-on`` value directly.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## GHA-037: actions/checkout persists GITHUB_TOKEN into .git/config { #gha-037 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--esf">ESF-D-CODE-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-522</span> <span class="pg-tag pg-tag--cwe">CWE-552</span>
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

Package managers and build tools execute code by design. ``npm install`` / ``pnpm install`` / ``yarn`` / ``bun install`` run ``preinstall`` / ``install`` / ``postinstall`` / ``prepare`` from the PR's ``package.json``; ``deno install`` resolves the PR's ``deno.json`` / ``package.json`` and (when ``--allow-scripts`` opts in) runs the same npm lifecycle hooks; ``pip install .`` runs the PR's ``setup.py``; ``make`` runs the PR's ``Makefile``; ``mvn`` / ``gradle`` load plugins declared in the PR's ``pom.xml`` / ``build.gradle``; ``cargo build`` runs ``build.rs``. Under ``pull_request_target`` / ``workflow_run``, the surrounding context already has secrets and a write-scope token, so the lifecycle hook is the entire attack.

**Known false-positive modes**

- Workflows that pin the workspace to a trusted ref before invoking the build tool (``actions/checkout`` with no ``ref:`` override on ``pull_request_target``, or a fresh checkout of a default-branch SHA) aren't actually exposed. The rule fires on the build-tool invocation alone; suppress with a ``.pipelinecheckignore`` rationale when the workspace is provably clean.

**Seen in the wild**

- Trail of Bits ``Public PPE`` write-up (2022): demonstrated the primitive against ``pull_request_target`` workflows that ran ``npm install`` after checking out PR content. The PR-supplied ``preinstall`` script ran with the base repo's secrets in scope. Same shape with ``pip install -e .`` (setup.py) and ``make`` (Makefile).
- Cycode / Legit Security ``Poisoned Pipeline Execution`` research (2022-2023) catalogued dozens of OSS repos where a privileged-trigger workflow's build step executed PR-controlled config: ``setup.py``'s ``cmdclass``, ``build.gradle``'s ``init.gradle``, ``pom.xml``'s ``<build><plugins>``. The fix pattern is always: don't build untrusted code with secrets in scope.

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

## GHA-049: Workflow step pushes to a repo outside the current owner { #gha-049 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-CODE-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-913</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

Three shapes are detected in ``run:`` bodies:

1. ``git push`` to a remote whose URL is interpolated from an expression (``${{ ... }}``), an env var (``$VAR``), or is not the canonical ``origin`` / ``upstream``;
2. ``gh repo create`` / ``gh repo edit`` / ``gh repo transfer`` / ``gh api /repos/...`` whose target owner is parameterized;
3. ``gh release create`` / ``gh release upload`` against a repo specified via ``-R <owner>/<repo>`` where the value is parameterized rather than a literal allow-list entry.

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

<div class="pg-rule pg-rule--medium" markdown>

## GHA-051: services / container image is not pinned by digest { #gha-051 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-8</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
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
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-522</span> <span class="pg-tag pg-tag--cwe">CWE-538</span>
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

Fires on a ``run:`` body invoking any of the following CLIs with the matching permission-bypass flag:

* ``claude … --dangerously-skip-permissions``
* ``gemini … --yolo``
* ``q chat … --trust-all-tools``
* ``cursor-agent …`` (any unprotected invocation; the CLI's default mode is the unsafe one)
* any of the above with ``--allowedTools '*'`` / ``--allowedTools '.*'`` / ``--allowedTools all``
* ``aider`` / ``openhands`` / ``goose`` with equivalent ``--auto`` / ``--no-confirm`` / ``--full-auto`` flags.

Does NOT fire on a clearly-scoped invocation, e.g. ``claude --allowedTools 'Read,Grep'`` with a literal allow-list, or ``q chat --trust-tools 'fs_read'``.

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

## TAINT-001: Untrusted input flows across step boundaries via step outputs { #taint-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-78</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

GHA-003 detects the *direct* interpolation case (``${{ github.event.* }}`` inside a ``run:`` body) and the *single-step* env-inheritance case. TAINT-001 fills the cross-step gap: a producer step sets a tainted step output, and a consumer step (in the same job) interpolates it via ``${{ steps.<id>.outputs.<name> }}``. The producer's interpolation is GHA-003's finding; TAINT-001's finding lives at the consumer (the actual injection sink) and carries the full chain in its description so a reader sees both sides at once.

v1 limitations: only same-job step outputs are tracked; ``jobs.<id>.outputs.*`` (cross-job propagation) and reusable-workflow input/output forwarding are tracked as future work in ``ROADMAP.md``. The producer pass matches the canonical ``echo "name=..." >> $GITHUB_OUTPUT`` shape and the legacy ``::set-output name=...::`` workflow-command form.

**Known false-positive modes**

- If the producer step deliberately runs a sanitiser between the interpolation and the ``$GITHUB_OUTPUT`` write (``echo "$TITLE" | tr -dc 'a-zA-Z0-9 ' >> $GITHUB_OUTPUT``), the consumer is no longer exploitable. The rule's regex doesn't model that transformation and will still fire; suppress via ignore-file scoped to the consumer step name when this is the deliberate shape. The producer's GHA-003 finding then carries the residual signal that the sanitiser is load-bearing.

<div class="pg-rule__rec" markdown>

**Recommended action**

Sanitise the value at the step that *writes* the ``$GITHUB_OUTPUT`` entry. The canonical pattern is to interpolate the untrusted source into an ``env:`` variable on the producer step and reference the env var in the ``echo``: ``env: TITLE: ${{ github.event.issue.title }}`` then ``echo "title=$TITLE" >> $GITHUB_OUTPUT``. After that, downstream steps reading ``steps.<id>.outputs.title`` see a string-typed value with no GitHub-expression evaluation pass left to exploit. Removing the source entirely is the safest fix; if the value genuinely needs to flow downstream, round-trip it through an env var the way GHA-003 recommends so the shell quoting still applies.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## TAINT-002: Untrusted input flows across jobs via ``jobs.<id>.outputs:`` { #taint-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-78</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

TAINT-001 catches step-output flow within a single job; TAINT-002 catches the cross-job transition. Engine shape: walk every job's ``outputs:`` mapping looking for values that interpolate either a tainted step output or a direct ``${{ github.event.* }}`` source. Tainted job outputs are matched against every ``${{ needs.<job>.outputs.<name> }}`` reference in any downstream job's ``run:`` / ``with:`` body. Each match emits a TAINT-002 finding with the full chain in the description.

Same-step interpolations (the producer's own use of ``${{ github.event.* }}`` inside its ``run:``) are still GHA-003's responsibility; TAINT-002's value is the cross-job hop the single-step rule can't see.

**Known false-positive modes**

- Sanitisation between the source interpolation and the $GITHUB_OUTPUT write isn't modeled. If the producer step runs ``echo "$TITLE" | tr -dc 'a-zA-Z0-9 '`` before redirecting to GITHUB_OUTPUT, the consumer is no longer exploitable but TAINT-002 will still fire; suppress via ignore-file scoped to the consumer job's workflow file when this is the deliberate shape.

<div class="pg-rule__rec" markdown>

**Recommended action**

Sanitise the value at the producer step *before* it lands in ``$GITHUB_OUTPUT``. Once the value is in a job output the consuming job has no expression-level escaping pass left, ``${{ needs.<job>.outputs.<name> }}`` substitutes the string verbatim into the consumer's shell. The canonical safe pattern is to copy the untrusted source into the producer step's ``env:`` block, reference the env var quoted in ``echo "name=$VAR" >> $GITHUB_OUTPUT``, and only then surface it through the job output. The consuming job should still treat the value as tainted (use it in env-var form, not interpolated directly into shell).

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

- Callees that wrap the input safely (immediately copy into env, sanitise before use) make the caller-side forward harmless. When the callee body is loaded into the scan, the rule downgrades to MEDIUM confidence on those paths; suppress via ignore-file when the callee's handling is audited and sound. Without ``--resolve-remote`` the rule can't see remote callee bodies and every forward stays at MEDIUM, the right default for unverifiable cross-repo flow.

<div class="pg-rule__rec" markdown>

**Recommended action**

Sanitise the value at the caller before forwarding it across the reusable-workflow boundary. The canonical safe pattern is to copy the untrusted source into a step's ``env:`` block, run a sanitiser (``tr -dc 'a-zA-Z0-9 '`` is enough for a freeform title), surface the sanitised result via ``echo "name=$VAR" >> $GITHUB_OUTPUT``, then forward ``${{ steps.<id>.outputs.<name> }}`` as the ``with:`` input. The callee then sees a string-typed value with no expression-evaluation pass left to exploit. If the callee is under your control, also handle the input via env in the callee's ``run:`` body (not direct ``${{ inputs.<name> }}`` interpolation).

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
