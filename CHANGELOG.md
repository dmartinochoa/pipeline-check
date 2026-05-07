# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

PRs landing on `dev` between releases append entries below. The
release commit collapses this section into `## [X.Y.Z] - <date>`.

### Added

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
  `_service_role_key` value-key helpers. Eight of nine strict
  mypy flags now on; only `disallow_any_generics` (~210 bare-
  `dict` / `list` annotations) remains.

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
  unparameterised `dict`. Closes a real type-inference gap that
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
