# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

PRs landing on `dev` between releases append entries below. The
release commit collapses this section into `## [X.Y.Z] - <date>`.

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
  is set so the centralised confidence demoter doesn't flatten
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
  generalises the existing GHA-003 single-step interpolation
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
- **``produces_artifacts`` heuristic recognises GitHub Pages
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
