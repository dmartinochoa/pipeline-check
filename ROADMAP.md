# Roadmap

What's planned, what's shipped, and what's deliberately out of scope.

## Shipped

- v0.3.x — Kubernetes provider, docs site, attack chains engine, English
  variant enforcement, doc-claim drift guards, MANIFEST sdist filter,
  GitHub Actions workflow audit.
- v0.2.x — Cloud Build, Jenkins, Terraform, CloudFormation, JUnit and
  Markdown reporters, 13-standard mapping, autofix engine, HTML report
  interactivity.

## v0.4.0 (in progress)

A "hardening" release. Closes structural gaps that the rule-count race
of v0.2.x to v0.3.x left behind.

### Landed on `dev`

- **STRIDE threat-model generator (`--output threatmodel`).** New
  output format that emits a self-contained Markdown threat model
  from the same scan output the JSON / HTML / SARIF reporters
  consume. Sections: Scope, Trust boundaries (heuristics), Assets
  (the inventory), STRIDE analysis (failing findings grouped),
  Implemented controls (passing-check counts per STRIDE bucket),
  Risk register (top 25), Methodology footer. OWASP-to-STRIDE
  mapping plus a CWE prepend table for finer-grained
  classification. Selecting `--output threatmodel` auto-runs the
  inventory pass. Output shaped for SOC 2 / PCI / NIST SSDF
  evidence packages and architecture-review docs. No rule
  registry changes; STRIDE classification is a pure function of
  each finding's existing OWASP / CWE tags. See
  [docs/output.md#threat-model](docs/output.md).
- **MCP (Model Context Protocol) server (`--serve`).** Locally-
  running MCP server lets AI clients (Claude Desktop, Claude
  Code, Cursor, Continue, Zed) drive scans and introspect the
  catalog directly. Stdio transport, ten tools advertised:
  `scan`, `inventory`, `explain_check`, `list_chains`,
  `threat_model`, etc. The `mcp` SDK is an optional `[mcp]` extra
  so the default install stays slim. Architecture splits
  `tools.py` (pure functions, no SDK import) from `server.py`
  (binds to MCP types, runs asyncio loop) so future transports
  (HTTP+SSE, streamable-http) reuse the same tool surface. See
  [docs/mcp.md](docs/mcp.md).
- **Peer-tool gap closure** — audited Zizmor / Checkov /
  StepSecurity / Poutine / KICS rule packs against
  pipeline-check's catalog and shipped the four highest-value
  gaps: `GHA-037` Artipacked (`actions/checkout`
  persist-credentials), `GHA-038` `ACTIONS_ALLOW_UNSECURE_COMMANDS`
  override, `GHA-039` hardcoded services / container credentials,
  `GL-033` global `before_script` taint propagation. Plus
  cross-provider parity adds: `DR-008/009/010/011`,
  `BK-014/015`, `TKN-014/015`, `ARGO-014/015`, `OCI-007/008`.
- **Three new attack chains** — `AC-009` Supply Chain Repo Poisoning
  (GHA-001 + GHA-002 + GHA-008 on the same workflow), `AC-010`
  Self-Hosted Runner Environment Exfiltration (GHA-012 plus GHA-016
  or GHA-019), and `AC-011` Kubernetes Cluster Takeover via hostPath
  + cluster-admin (K8S-013 + K8S-020). Catalog goes from 8 chains
  to 11.
- **Autofixer expansion** — 19 new fixers across two waves, lifting
  the catalog from 68 to 87. First wave: K8s drop-line / flip-value
  / comment-only TODOs and Cloud Build timeout / logging / pinning /
  TLS-bypass. Second wave: comment-only TODOs for the previously-
  empty Dockerfile catalog (`DF-001` digest pinning, `DF-002` USER,
  `DF-007` HEALTHCHECK, `DF-013` EXPOSE 22, `DF-017` PATH prefix)
  plus `GCB-007` (Secret Manager `versions/<N>` instead of `latest`).
  Dockerfile no longer has zero autofixers.
- **Six new rules across thin providers** — Kubernetes K8S-023..026
  (Pod Security Admission label, missing health probes, system-*
  priority class outside kube-system, LoadBalancer without source
  ranges) and Dockerfile DF-015..016 (chmod 777 / a+w; missing OCI
  provenance labels). K8s 22 -> 26, Dockerfile 14 -> 16.
- **Doc version templating** — `docs/index.md` reads
  `pipeline_check.__version__` via a mkdocs hook
  (`hooks/mkdocs_version.py`). The hardcoded `v0.3.0` and `v0.3.3`
  literals had drifted across release cycles.
- **Issue templates and an `[Unreleased]` CHANGELOG section.** Bug,
  feature, and false-positive forms under `.github/ISSUE_TEMPLATE/`.
  CLAUDE.md documents the `[Unreleased]` collapse-on-release
  convention.
- **Per-rule unit tests for CI providers.** 100% positive / negative
  rule-test coverage across `github`, `gitlab`, `bitbucket`,
  `circleci`, `jenkins`, `azure`, `kubernetes`, `dockerfile`,
  `cloudbuild`. `tests/test_rule_test_coverage.py` floors every
  provider at 100% so a new rule without a `Test<RULE_ID>` class
  trips the meta-test.
- **Standards densification.** `cis_aws_foundations` doubled to 22
  mappings (1.14 / 3.2 / 3.7 controls, IAM-007, KMS, CT, CWL, ECR-007).
  `nist_800_53` regenerated to 165 rows including the AU-11 family.
  OWASP CICD Top 10 restructured into Controls + Coverage summary +
  330-row per-check table.
- **Performance smoke gate.** `tests/perf/test_smoke.py` scans a
  synthetic 500-job GHA workflow and 500 K8s manifests with
  generously-padded ceilings. Catches catastrophic regressions
  (O(n) → O(n²)) without taking on a `pytest-benchmark` dep.

### Closed out for v0.4.0

- **Thin provider expansion.** Third wave
  added Kubernetes `K8S-029` (RoleBinding to a namespace's
  `default` ServiceAccount) and `K8S-030` (workload schedules onto
  the control-plane node via `nodeSelector` or `tolerations`);
  Dockerfile `DF-019` (`COPY` / `ADD` of a credential-shaped file
  like `id_rsa` / `.npmrc` / `.aws/credentials`) and `DF-020`
  (`ARG` declares a credential-named build argument that
  `--build-arg` records into image history). Fourth wave added
  Cloud Build `GCB-020` (explicit `serviceAccount:` still resolves
  to the default Cloud Build SA email) and `GCB-021` (no private
  worker pool — build runs on Google's shared default with public
  egress, blocking VPC-SC / egress-filtering perimeter controls).
  Catalog totals: Kubernetes 28 to 30, Dockerfile 18 to 20, Cloud
  Build 19 to 22 (fifth-wave addition: `GCB-022` flags
  `options.substitutionOption: ALLOW_LOOSE`, the silent-empty-
  string opt-in that masks undefined refs). Earlier waves had
  landed `K8S-027` / `K8S-028` / `DF-017` / `DF-018` / `GCB-019`.
- **Real performance benchmark.**
  `tests/perf/test_benchmark.py` replaces the smoke gate with a
  ``pytest-benchmark`` run on a 1000-line synthetic GHA workflow
  and a 5000-line CFN template, asserting absolute median ceilings
  (sized for slow CI, ~5s GHA / ~8s CFN; locally each scan is
  ~17ms / ~2ms). Statistical aggregation comes from the
  ``benchmark`` fixture (warmup + multiple rounds + median).
  Developers can save a per-machine baseline with
  ``--benchmark-autosave`` and gate against it with
  ``--benchmark-compare --benchmark-compare-fail=median:25%`` to
  detect regressions; CI doesn't save baselines (they'd flap as
  GitHub-hosted runner hardware shifts) and relies on the
  ceilings instead.
- **Strict mypy (full).** All nine
  strict flags landed across the release: `no_implicit_optional`,
  `warn_redundant_casts`, `warn_unused_ignores`, `strict_equality`,
  `check_untyped_defs`, `disallow_subclassing_any` (with two narrow
  per-module overrides for `yaml.SafeLoader` subclasses),
  `disallow_untyped_calls` (after annotating five helpers across
  the AWS / Terraform / CloudFormation / Bitbucket rule packs),
  `disallow_untyped_defs` (after a 89 → 0 annotation pass across
  phase modules, every YAML-provider orchestrator, the Click
  callbacks, the YAML loader helpers, and the iter-* generators),
  and `disallow_any_generics` (226 → 0 annotation pass; most call
  sites resolved to `dict[str, Any]`, `click.Choice` became
  `Choice[str]`, and the four AWS modules already in the boto3
  override block now also disable `type-arg` since boto3 paginator
  output is untyped at the source). Zero user-visible change.

## v0.5.0 candidates

Not committed yet. Scoping is open. Listed in rough impact order
(top first).

- **Helm chart provider.** *Landed on dev.* `--pipeline helm
  --helm-path <chart>` shells out to `helm template` (Helm 3) and
  runs the existing 30 K8S-* rules on the rendered manifests.
  `--helm-values FILE` and `--helm-set KEY=VALUE` (both repeatable)
  are forwarded to helm verbatim. Auto-detects `./Chart.yaml` and
  `./charts/`. The provider is a thin shim — `HelmContext`
  subclasses `KubernetesContext`, the same `KubernetesManifestChecks`
  orchestrator runs, no rule-pack duplication. Source-template
  attribution: `# Source:` headers helm injects above each
  rendered doc are parsed and stored on `Manifest.source_template`,
  surfacing in inventory output. Helm-native rules — chart
  `apiVersion: v1` legacy (`HELM-001`), missing `Chart.lock`
  digests (`HELM-002`), non-HTTPS dependency repos (`HELM-003`) —
  *landed on dev* via a separate `HelmChartChecks` orchestrator
  that walks `Chart.yaml` / `Chart.lock` while the K8s pack
  continues to score the rendered manifests. Provider catalog: 12
  to 13.
- **Custom rule DSL.** *Landed on dev.* `--custom-rules PATH`
  (repeatable, also a `custom_rules:` config key) loads YAML rules
  that plug into the existing orchestrator — same `Finding` shape,
  same scoring/gating/SARIF/`--explain` plumbing, no special-casing.
  Predicates compose via `eq` / `ne` / `regex` / `not_regex` / `in` /
  `not_in` / `exists` / `missing` / `gt` / `lt` / `gte` / `lte` /
  `len_*` leaves, plus `all_of` / `any_of` / `not` boolean glue. A
  small jsonpath subset (`$`, `.field`, `['key']`, `[N]`, `[*]`,
  `.*`) walks the parsed pipeline document; recursive descent and
  filters are deliberately out — write Python when you need them.
  Description templates use `{{ name }}` placeholders. Supported
  providers: `github`, `gitlab`, `bitbucket`, `azure`, `circleci`,
  `cloudbuild`, `kubernetes` (Helm rules ride on K8s via the
  synthesized `$.workloads[*]` view). AWS / Terraform / CFN /
  Dockerfile excluded — their shapes don't fit the dict-tree DSL.
  Authoring guide at `docs/writing_a_custom_rule.md`. Phase 1 ships
  loader + evaluator + provider runners; inline tests, the `rules
  check` subcommand, and standards-mapping for user rules are
  deferred to v0.5.x.
- **OCI artifact provider.** *Landed on dev.* `--pipeline oci
  --oci-manifest <file>` parses an OCI image manifest / image-index
  JSON captured via ``docker buildx imagetools inspect --raw <ref>``
  (or equivalent ``oras manifest fetch`` / ``crane manifest``).
  Pure parser, no registry pull, no daemon access; auto-detects
  ``./index.json``. Three rules: ``OCI-001`` flags missing
  ``org.opencontainers.image.source`` / ``image.revision``
  annotations (mirrors DF-016 at the image-manifest layer);
  ``OCI-002`` flags an image index with no BuildKit-style
  attestation manifest (``vnd.docker.reference.type:
  attestation-manifest``), where SLSA provenance and SBOM data
  live; ``OCI-003`` flags a missing
  ``org.opencontainers.image.created`` timestamp. Provider
  catalog: 16 to 17.
- **SaaS API.** *Deferred to v0.6.0+.* Hosted scan endpoint with
  auth and history. Scope is large (auth, multi-tenancy, history
  DB) and blurs OSS positioning. Revisit after v0.5.0 ships and
  user demand is clearer.

### Newly proposed for v0.5.0

Items not in the original list but ranked higher than several of
the candidates above. Grouped by priority within v0.5.0.

#### High impact, low effort

- **Pre-commit hook integration.** *Landed early.* Ships
  `.pre-commit-hooks.yaml` with one hook per provider, scoped by
  `files:` regex so a Dockerfile change doesn't run the GitHub
  Actions scanner. README has the opt-in snippet. Default gate is
  `--fail-on HIGH` — overridable via `args:`.
- **`pipeline_check --explain <CHECK_ID>`.** *Landed early.* Prints
  a rule's title, severity, confidence, every standards mapping,
  CWE, the `docs_note`, the `recommendation`, and any
  `known_fp` modes — all sourced from the live registry. Suggests
  near-matches on an unknown ID. Implemented as a flag on the main
  scan command (not a subcommand).
- **Architecture and contributor docs.** *Landed early.* Three new
  pages under `docs/`: `architecture.md` (scan flow + layer map),
  `writing_a_rule.md` (`RULE` + `check` module contract for an
  existing provider), `writing_a_provider.md` (full new-provider
  walkthrough). Wired into the mkdocs nav under a "Contributing"
  section.
- **Auto-baseline / SARIF differential mode.** `--baseline PATH`
  (or `--baseline auto` to read `.pipeline-check-baseline.sarif`)
  suppresses any finding present in the baseline so the gate only
  fails on new issues. `--write-baseline` snapshots current
  findings on first run. Solves the "scanner adopted on a
  5-year-old repo returns 800 findings" problem that keeps every
  comparable tool on the shelf for legacy codebases. Same idea
  ruff used to make noqa migrations bearable; mostly absent from
  the CI/CD-scanner peer set.
- **Auto-detect / no-args mode.** *Landed on dev.* `pipeline-check`
  with no flags walks cwd for every provider's canonical file
  (``.github/workflows``, ``.gitlab-ci.yml``, ``Jenkinsfile``,
  ``Dockerfile``, ``Chart.yaml``, etc.) and routes one match to a
  single-provider :class:`Scanner`, two or more matches to
  :class:`MultiScanner` so cross-provider chains (``XPC-NNN``)
  fire automatically. Explicit ``--pipeline`` / ``--pipelines``
  flags stay for power users. Helm + Kubernetes disambiguation:
  when ``Chart.yaml`` is present alongside a ``kubernetes/`` /
  ``k8s/`` / ``manifests/`` directory the Kubernetes provider is
  dropped (helm renders templates and feeds them to the K8s rule
  pack already, scanning both would double-count). OCI is
  deliberately omitted from the table because ``index.json`` is
  too generic a filename to promote on presence alone; users who
  want OCI in scope pass ``--pipeline oci`` (single) or
  ``--pipelines github,oci`` (multi) explicitly. True manifest-
  shape detection (parse ``apiVersion:`` + ``kind:`` headers) is
  deferred; canonical-path detection covers the common case at
  zero parse cost.
- **Per-finding real-world incident references.** *Landed on dev.*
  Each rule gains an optional ``incident_refs: tuple[str, ...]``
  field. ``--explain``, the HTML report drawer, and the
  auto-generated provider reference doc all render a "Seen in
  the wild" section linking to CVEs and breach postmortems
  where the same pattern caused damage. Initial population
  covers five marquee rules: ``GHA-001`` (tj-actions /
  reviewdog 2025 compromises), ``GHA-008`` (Uber 2016 GitHub
  leak + GitGuardian sprawl reports), ``GHA-016`` (Codecov
  2021 Bash uploader), ``K8S-013`` (CVE-2021-25741 +
  TeamTNT/Kinsing), ``DF-002`` (CVE-2019-5736 runC escape +
  CVE-2022-0492 release_agent escape). Mechanically the
  ``Finding`` dataclass mirrors the field and every provider
  orchestrator backfills it from the rule, the same way
  ``cwe`` is backfilled. Anchors abstract security debt to a
  concrete cost the operator's manager has already heard of.
- **Close the two known taint resolver gaps.** GitLab ``include:``
  *landed on dev*: local ``include:`` directives are followed at
  load time, jobs and variables from included files merge into the
  parent pipeline, TAINT-008 (``extends:`` taint) now walks chains
  across the boundary. Cycle detection + 10-level depth cap; parent
  wins on conflict; remote / project / template / component forms
  emit a warning (no network fetch). Tekton ``taskRef:`` cross-
  document resolution (already flagged as the next gap in the
  TAINT-006 description) still open. Both lift existing TAINT
  rules from single-document to multi-document, which is where
  most real CI repos sit. Highest detection-power gain per line
  of code on the table.
- **Suppression-with-expiry on `--ignore-file`.** *Landed on dev.*
  YAML ignore-file entries carry an ``expires: YYYY-MM-DD`` field;
  past the date the suppression no longer applies and a ``[gate]
  ignore rule expired on …`` line surfaces in the gate summary.
  ``GateResult`` also exposes ``expiring_soon`` for entries within
  ``EXPIRY_WARNING_DAYS`` (14 by default), rendered as ``[gate]
  ignore rule expires in N day(s) on …`` so the operator gets a
  forewarning before the gate flips. Forces revisit instead of
  letting one-off "ignore for the demo" entries calcify into
  permanent blind spots.

#### Medium impact

- **Severity / per-rule overrides in config.** *Landed early.*
  Adds `overrides:` to `.pipeline-check.yml` (and the equivalent
  `[tool.pipeline_check.overrides.<id>]` block in
  `pyproject.toml`). Today only `severity` is supported per
  rule; the schema is shaped to grow other knobs (confidence
  override, per-rule recommendation tweak) without breaking
  existing configs. Suppression stays the job of `--ignore-file`.
- **Programmatic Python API.** *Landed early.* `pipeline_check`
  now re-exports `Scanner`, `Finding`, `Severity`, `Confidence`,
  `score`, `Chain`, the registry queries, and a few rank helpers.
  `tests/test_public_api.py` locks the surface — adding a name is
  routine, removing one breaks the test. Anything reached via
  `pipeline_check.core.*` stays internal.
- **GitHub Actions reusable workflow analysis.** *Landed on dev.*
  `--resolve-remote` follows ``jobs.<id>.uses:`` to the called body
  and runs the full GHA rule pack against it with the caller's
  permissions / secrets-inherit context. Default off (preserves the
  "no telemetry" promise); a one-line stderr nudge lists skipped
  remote refs so the flag is discoverable. Fetches via
  ``raw.githubusercontent.com`` with optional ``--gh-token`` (or
  ``$GITHUB_TOKEN``); on-disk fallback via ``--gha-search-path`` for
  monorepos. Per-ref cache, depth cap, cycle detection, parallel
  fetches. Only SHA-pinned refs are followed (tag refs would defeat
  GHA-025). ``GHA-004`` and ``GHA-019`` updated to read inheritance
  metadata.
- **Distribution beyond `pip install`.** A standalone shiv or
  PyInstaller binary attached to every GitHub release plus a
  `ghcr.io/<owner>/pipeline-check` container image. Removes the
  Python-install friction for shops whose CI containers don't
  ship Python (Go-shop CI, JVM-shop CI, container-only build
  environments). Pure packaging move, no rule code change. The
  marketplace `action.yml` already shipped is the GHA half of
  this; the binary + container image cover every other CI.
- **Reproducible build with SLSA provenance on the wheel.**
  Releases ship via `slsa-github-generator`, with a verification
  snippet in the README showing how to confirm the wheel's
  provenance before installing. The scanner that flags missing
  SLSA provenance shipping its own attested wheel is the
  cheapest trust signal available, costs roughly a day of CI
  plumbing, and gives the README a live screenshot of what good
  looks like.
- **Rule-pack confidence calibration loop.** `--annotate-fp
  <CHECK_ID> <PATH>` records a confirmed false positive into a
  per-repo learn file. On subsequent runs the same rule firing
  on the same file shape (hashed AST anchor, not literal text)
  drops one confidence rung. Optional `pipeline-check fp-stats`
  surfaces which rules accumulate the most FP votes across a
  repo, feeding rule-author triage. Keeps the no-telemetry
  promise (file is local) while still building a feedback loop.

#### Landed early

- **Tekton, Argo Workflows, Buildkite providers.** All three
  landed on `dev`. `--pipeline buildkite` (8 rules, ``BK-001`` ..
  ``BK-008``), `--pipeline tekton` (8 rules, ``TKN-001`` ..
  ``TKN-008``), `--pipeline argo` (8 rules, ``ARGO-001`` ..
  ``ARGO-008``). Provider catalog 13 to 16. Buildkite is a YAML
  pipeline parser; Tekton and Argo are CRD parsers filtered to
  ``tekton.dev/*`` and ``argoproj.io/*`` respectively. The Tekton
  and Argo orchestrators follow the K8s shape (rule receives the
  full context, emits one aggregated Finding) so a rule that only
  applies to ``Task`` / ``Workflow`` kinds can co-exist with a
  rule that only applies to ``*Run`` kinds in the same scan.

#### Lower priority (v0.6.0+)

- **VS Code extension or LSP.** Adoption multiplier in the style
  of `ruff` / `black`, but a new surface to maintain. Worth
  scoping, not v0.5.0.
- **GitHub App.** *Eventually, low priority.* PR-comment
  integration with diff-level finding placement instead of the
  current SARIF-into-code-scanning flow. SARIF already reaches
  the GitHub Code Scanning UI on every push, so a separate App
  duplicates a path that mostly exists, takes on ongoing review
  surface, and competes with native SARIF for adoption attention.
  Revisit if SARIF feedback proves consistently inadequate in
  practice or if multiple users explicitly ask for inline diff
  comments.

## v0.6.0 vision

Bigger architectural moves that change what the scanner can find,
not just how it's presented. Listed in priority order; landing
order is open.

### Dataflow / taint-path engine

Today every rule is local: one workflow, one job, one step,
one regex. Real attackers pivot through chains of innocuous-
looking primitives. The taint engine generalizes the existing
attack-chain idea from hand-coded rule pairs (`AC-001`...`AC-027`)
to an emergent path-finder over a per-pipeline dataflow graph.

- **Sources** — author-controllable inputs per provider:
  ``${{ github.event.issue.title }}`` / ``pull_request.title``
  / ``head_ref``, ``${DRONE_PULL_REQUEST_TITLE}`` /
  ``DRONE_COMMIT_*`` / ``DRONE_BRANCH``,
  ``$CI_COMMIT_TITLE`` / ``CI_MERGE_REQUEST_TITLE``,
  ``$(params.*)`` (Tekton fork-PR), ``{{inputs.parameters.*}}``
  (Argo), webhook payloads, registry-pulled image tags.
- **Propagators** — pipeline shapes that move data without
  modifying it: ``env:`` blocks, step outputs
  (``steps.<id>.outputs.*``), reusable-workflow inputs / secrets,
  Drone ``from_secret``, Tekton param passing, K8s
  ``valueFrom``, Helm value flow.
- **Sinks** — security-critical operations: shell commands
  (``run:`` / ``commands:``), deploy steps, secret access,
  registry pushes, ``kubectl apply``, ``helm upgrade``.
- **Engine** — build a per-pipeline DAG, compute every
  source-to-sink path, emit one finding per path with the
  full chain in the description. Reuses the existing
  ``Chain`` data type for inventory output.
- **Output** — new ``TAINT-NNN`` rule family, one per
  recognized source-sink pattern. ``--explain TAINT-001``
  shows the canonical attack sequence; the per-finding
  description carries the *concrete* path detected on this
  scan.

Pilot scope: GitHub Actions and GitLab CI.

  * ``TAINT-001`` (GHA, *landed*) — same-job step-output flow
    via ``$GITHUB_OUTPUT``.
  * ``TAINT-002`` (GHA, *landed*) — cross-job flow via
    ``jobs.<id>.outputs:`` declarations.
  * ``TAINT-003`` (GHA, *landed*) — caller-side reusable-
    workflow input forwarding via ``jobs.<id>.uses:`` +
    ``with:``.
  * ``TAINT-004`` (GitLab, *landed*) — cross-job flow via
    ``artifacts.reports.dotenv`` auto-import. Validates the
    engine's portability across provider shapes; the
    producer/consumer pattern is identical, only the
    propagation channel differs.
  * ``TAINT-005`` (Buildkite, *landed*) — cross-step flow via
    ``buildkite-agent meta-data set / get`` per-build store.
    Confirms the engine extends to non-file-based propagation
    channels, the meta-data CLI talks to a server-side key/
    value store rather than an artifact path. Buildkite's
    meta-data is per-build (not per-step) so the engine
    skips temporal ordering and fires on any pipeline that
    contains both a tainted set and a get on the same key.
  * ``TAINT-006`` (Tekton, *landed*) — cross-task flow via
    ``$(tasks.<task>.results.<output>)`` substitution in a
    Pipeline document. Producer task writes a tainted
    ``$(params.X)`` into ``$(results.Y.path)``; consumer task
    receives the result through its own param via
    ``$(tasks.<producer>.results.Y)`` and references the param
    unquoted in its script. Inline ``taskSpec:`` only;
    ``taskRef:`` cross-document resolution is the next gap.
  * ``TAINT-007`` (Argo Workflows, *landed*) — cross-template
    flow via ``{{tasks.<task>.outputs.parameters.<output>}}``.
    Producer template interpolates ``{{inputs.parameters.X}}``
    into an output path; downstream task forward the output
    via the cross-task substitution; consumer template
    references the value unquoted. Both ``dag:`` and
    ``steps:`` orchestrators covered. The ``TAINT-NNN`` family
    now spans 5 providers and 5 distinct cross-step
    propagation channels — engine portability fully
    validated.

End-to-end coupling between the ``--resolve-remote`` resolver
and the GHA pass-4 forward detection (so a tainted ``with:``
paired with a callee whose ``inputs.<name>`` lands in a sink
emits a high-confidence finding) *landed on dev*: TAINT-003
now walks the callee body when it's available in
``ctx.workflows`` (local refs via ``--gha-path``, remote refs
via ``--resolve-remote``), tags each path as Confirmed or
Unconfirmed, and locks the per-finding confidence to HIGH /
MEDIUM accordingly. The orchestrator gained a 4-arg rule
signature so future rules needing cross-workflow analysis can
opt in the same way.

GitLab ``extends:`` job-template inheritance *landed on dev*
as ``TAINT-008``. The rule resolves each non-hidden job's
extends chain (transitive, cycle-safe), gathers tainted
variables from every link's ``variables:`` block, and walks
the consuming job's scripts for unquoted references. Quote-
state aware. Remaining gaps: GitLab ``include:`` cross-
pipeline file inclusion isn't tracked yet (would need cross-
document machinery similar to the GHA ``--resolve-remote``
flow). The TAINT engine spans 8 rules across 5 providers.

This is the move that distinguishes pipeline-check from the
common per-rule local matching that mainstream commercial CI/CD
scanners (Trivy, Checkov, KICS, Snyk) emphasize today. The 27
hand-coded attack chains today become a calibration set for the
engine, not the ceiling on what gets detected.

### Cross-provider correlation engine

Generalize the chain engine to compose findings across
provider boundaries. The chains today match within a single
provider's findings list; this extends matching to the union
across every provider scanned in the same run.

- **XPC-001** *deploy without verifiable provenance*. **Landed
  on dev** alongside multi-provider scan mode (below). Fires
  when ``GHA-006`` (workflow doesn't emit SLSA provenance) and
  ``OCI-002`` (image ships without attestation manifest) both
  fail in the same scan.
- **XPC-002** *tag mutability across pipeline + runtime*.
  **Landed on dev**. Fires when ``DF-001`` (Dockerfile floating
  ``FROM`` tag) and ``K8S-001`` (Kubernetes workload uses a
  floating-tag image) both fail in a multi-provider run. One
  chain instance per ``(dockerfile, manifest)`` cross-product
  pair so the operator can audit each producer-consumer link
  individually.
- **XPC-003** *unverified Helm release flow*. **Landed on
  dev**. Fires when ``HELM-002`` (Chart.lock missing
  per-dependency digests) and ``OCI-002`` (image manifest
  lacks attestation manifest) both fail in a multi-provider
  run. The composite says: chart contents AND image bytes
  are independently mutable; consumers running ``helm
  install`` have no signed chain of custody at either
  boundary. (The roadmap originally proposed pairing
  HELM-002 with a "helm-upgrade step" rule that doesn't
  exist; OCI-002 turned out to be the cleaner second leg
  because both rules are squarely about provenance gaps.)

Each composite carries its own severity (often higher than
its parts because the cross-cut means there's no
compensating control elsewhere) and its own ``--explain``
prose. Engine reuses the existing
``pipeline_check.core.chains`` machinery; the only new piece
is a chain rule that takes findings from multiple providers'
result sets.

### Multi-provider scan mode

*Landed on dev.* New ``--pipelines github,oci`` (plural,
comma-separated) scans every named provider in one
invocation and evaluates the chain engine once over the
union of all findings. That's what activates cross-provider
chains (the ``XPC-NNN`` family) — single-provider runs of
``--pipeline github`` or ``--pipeline oci`` alone never see
both check IDs in the chain engine's input. Mutually
exclusive with the single-valued ``--pipeline`` flag;
backward-compatible (existing ``--pipeline X`` invocations
behave unchanged). Each provider's path flag (``--gha-path``,
``--oci-manifest``, etc.) is auto-detected the same way as
in single-provider mode. Implementation: a new
:class:`MultiScanner` in ``pipeline_check.core.scanner`` that
delegates per-provider sub-scans to :class:`Scanner` (with
each sub-scanner's chain pass suppressed), then runs the
chain engine once on the unified findings list. Aggregate
``ScanMetadata`` and ``inventory()`` are exposed on the
multi-scanner so reporters consume the same shape regardless
of single- vs multi-mode.

### Pipeline graph visualization in HTML report

**v1 — blast-radius heatmap.** *Landed on dev.* A grid of
inline-SVG tiles between the attack-chains panel and the
findings table, one tile per resource carrying at least one
failing finding. Tile color encodes worst severity, tile
size scales with the resource's total failing count
(sqrt-scaled so a 50-finding resource doesn't dwarf a
5-finding one). Hovering a tile reveals the per-severity
breakdown via the SVG ``<title>`` element. Sorted
CRITICAL-first, then desc-by-count, then resource name.
Pure inline SVG so the report stays a single offline HTML
file (no CDN, no JS framework). Reuses the existing
severity color tokens so the visual matches the findings
table.

**v2 — true pipeline DAG.** *Deferred.* Lifts the heatmap to
step-level granularity: steps as nodes, ``needs:`` /
``depends_on:`` / sequence as edges, findings rendered as
severity-colored badges on each node. Steps with
attestation attached show a small chain icon; steps that
are taint-engine sinks (TAINT-NNN family) get a flame icon
when an active path lands on them. Requires extending the
Scanner-to-reporter API so the parsed pipeline structure
flows through; the v1 heatmap intentionally avoids that
plumbing change.

Doesn't change *what* the scanner finds; changes *how
clearly* the operator sees the blast radius. Adds a real
"wow" factor for executive-level reports without diluting
the no-telemetry / no-SaaS posture.

### Attestation content checks (not just presence)

`OCI-002` today flags missing attestation manifests. The next
layer parses the manifest content: SLSA provenance JSON,
in-toto envelopes, SPDX / CycloneDX SBOMs.

- Builder identity verification. Does the `builder.id` claim
  resolve to a trusted endpoint (`https://github.com/actions/
  runner` etc.) or an unknown one?
- Source-repo claim consistency. Does `materials[].uri` match
  the repository the operator believes built the image, or has
  drift snuck in?
- SBOM integrity. Are declared dependencies digest-pinned, or
  are floating versions sitting inside a signed envelope that
  makes the rot look authoritative?

New rule family `ATTEST-NNN`. First three rules:
`ATTEST-001` (untrusted builder identity), `ATTEST-002`
(source-repo mismatch), `ATTEST-003` (SBOM contains
floating-version dependencies).

No OSS scanner does pipeline-side attestation content analysis
today; they verify *something* was attested, not *what* was
attested. Strong differentiator and a natural extension of the
OCI provider work already on dev.

### Reachability-aware attack chains

The chain engine today fires on co-occurrence: an `AC-NNN`
chain emits when both anchor rules emit findings, regardless
of whether the same execution path connects them. The next
iteration walks the dataflow graph between the two anchor
findings and only fires when an executable connection exists.

Cuts the chain-engine false-positive rate, promotes confidence
on every path that does fire to HIGH, and reuses the v0.6.0
taint DAG once it's built (no separate machinery). Closes the
biggest legitimate criticism of the AC-* family: that
co-occurrence is a weaker claim than reachability.

### Vulnerable-by-design benchmark suite

A companion `pipeline-check-bench` repo holding intentionally-
vulnerable pipeline configs, one folder per CVE / risk class.
Every release runs a comparison harness (pipeline-check vs.
Checkov, Trivy, Zizmor, Poutine, KICS) and publishes a
confusion matrix per scanner. Reproducible, public,
citation-safe.

The "this scanner finds more than its peers" claim becomes a
``make bench`` away rather than a marketing sentence. Likely
the single biggest credibility move available to a low-
popularity OSS scanner: adopters can verify the wedge claim
themselves before installing, and the matrix gives reviewers
something concrete to cite.

### Pluggable LLM-assisted triage (opt-in, local)

A `--triage` flag pipes each finding through a local-only LLM
(Ollama, llama.cpp, LM Studio) plus the surrounding pipeline
snippet, asking for a short "is this actually exploitable in
this repo's context" verdict. Three labels: `confirmed`,
`needs_review`, `likely_fp`. Strict no-network default; remote
endpoints require an explicit `--triage-endpoint URL` flag and
print a one-line warning before sending. Output is advisory,
never gates the build, and is rendered as a separate column
beside the rule-engine confidence so the two signals stay
distinguishable.

Opt-in by design: keeps the no-telemetry promise intact,
gives users with already-running local LLMs a high-leverage
adoption hook, and stays out of the rule-engine path so a
hallucinating model can't change a HIGH into a LOW.

### Per-rule policy-as-code overlay

Beyond the v0.5.0 severity / confidence overrides: a `policies/`
directory of YAML files that compose rule subsets into named
policies (`pci-only.yml`, `pre-merge.yml`, `release-gate.yml`)
with their own gating thresholds and standards filters.
`--policy pre-merge` runs that subset; `--list-policies` prints
the catalog. Lets a single repo wire up different scan profiles
for pre-commit (fast, HIGH-only), PR (full pack, HIGH-fail), and
release (full pack, MEDIUM-fail with attestation rules forced
on) without flag soup in the CI YAML.

Costs nothing in detection power but makes the scanner
deployable in the way real teams deploy linters: tiered, named,
reviewed.

## Non-goals

Things that have come up but aren't planned. Stating them here saves
discussion later.

- **IaC autofix beyond comment-only TODOs.** Text patching Terraform
  HCL or CloudFormation YAML can't see the resource graph. Risk of
  silently breaking cross-resource references is too high. Comment-
  only TODOs are fine; transformative fixes aren't.
- **Generic SAST.** Pipeline-Check scans pipeline definitions, not
  application source. Bandit, Semgrep, CodeQL already do SAST well.
- **Telemetry or phone-home.** Not now, not later. The "no telemetry"
  promise on the landing page is load-bearing.
- **Vendoring rules from other tools.** No checkov / kics / trivy
  rule imports. Every rule here is hand-written so the recommendation
  prose, severity, and standards mapping all reflect the same point
  of view.

## How to propose changes

Open an issue with the `feature_request` template. For new providers
or attack chains, include a short rationale and 2 to 3 example
findings the rule would catch. For new rules within an existing
provider, an OWASP CICD-SEC or CIS Benchmark citation helps.
