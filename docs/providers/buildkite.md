# Buildkite provider

Parses `.buildkite/pipeline.yml` (or any user-named pipeline file) on
disk, no Buildkite API token, no agent install required. Each
document must declare a top-level `steps:` list; files without it are
skipped by the loader.

## Producer workflow

```bash
# --buildkite-path is auto-detected when .buildkite/pipeline.yml
# exists at cwd.
pipeline_check --pipeline buildkite

# …or pass it explicitly.
pipeline_check --pipeline buildkite --buildkite-path .buildkite/pipeline.yml
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

### Buildkite-specific checks

- **BK-001**, plugin refs must be pinned to an exact tag
  (`docker-compose#v4.13.0`) or a 40-char SHA. Branch refs (`#main`)
  and bare names float and let a compromised plugin release execute
  in the pipeline.
- **BK-007**, every step that looks like a deploy (label / command
  matches `deploy`, `kubectl apply`, `terraform apply`, `helm
  upgrade`, …) must be preceded by a `block:` or `input:` step in
  the same pipeline file. Buildkite waits for a human to click
  *Unblock* before the gated steps run.

## What it covers

16 checks · 4 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [BK-001](#bk-001) | Buildkite plugin not pinned to an exact version | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [BK-002](#bk-002) | Literal secret value in pipeline env block | <span class="pg-sev pg-sev--critical">CRITICAL</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [BK-003](#bk-003) | Untrusted Buildkite variable interpolated in command | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [BK-004](#bk-004) | Remote script piped into shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [BK-005](#bk-005) | Container started with --privileged or host-bind escalation | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [BK-006](#bk-006) | Step has no timeout_in_minutes | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [BK-007](#bk-007) | Deploy step not gated by a manual block / input | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [BK-008](#bk-008) | TLS verification disabled in step command | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [BK-009](#bk-009) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [BK-010](#bk-010) | No SBOM generated for build artifacts | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [BK-011](#bk-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [BK-012](#bk-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [BK-013](#bk-013) | Deploy step has no branches: filter | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [BK-014](#bk-014) | Step commands run unpinned package installs | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [BK-015](#bk-015) | agents map interpolates attacker-controllable Buildkite variable | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [TAINT-005](#taint-005) | Untrusted input flows across steps via ``buildkite-agent meta-data`` | <span class="pg-sev pg-sev--high">HIGH</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## BK-001: Buildkite plugin not pinned to an exact version { #bk-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Buildkite resolves plugin refs at agent boot. ``foo#v1.2.3`` locks the version; ``foo#main`` / ``foo`` does not. Detection fires on bare names, branch keywords, and partial-semver pins (``v4``, ``v4.13``).

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every plugin reference to an exact tag (``docker-compose#v4.13.0``) or a 40-char commit SHA. Bare references (``docker-compose``), branch refs (``#main`` / ``#master``), and major-only floats (``#v4``) resolve to whatever is current at agent start time, which lets a compromised plugin release execute inside the pipeline.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## BK-002: Literal secret value in pipeline env block { #bk-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span> <span class="pg-tag pg-tag--cwe">CWE-532</span>
</div>

Detection fires on values that look like AWS access keys, GitHub PATs, OpenAI keys, JWTs, or generic high-entropy tokens, plus on env-var names that imply a secret (``*_TOKEN``, ``*_KEY``, ``*PASSWORD``, ``*SECRET``) when the value is a non-empty literal rather than an interpolation (``$SECRET_FROM_AGENT_HOOK``).

<div class="pg-rule__rec" markdown>

**Recommended action**

Move the value out of the pipeline file. Use Buildkite's agent secrets hooks (``secrets/`` directory or ``BUILDKITE_PLUGIN_AWS_SSM_*``), the ``aws-ssm`` / ``vault-secrets`` plugins, or the ``BUILDKITE_PIPELINE_DEFAULT_BRANCH`` env var pulled from a secret manager. The pipeline.yml is committed to the repo and visible to anyone with read access.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## BK-003: Untrusted Buildkite variable interpolated in command { #bk-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-CODE-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-78</span>
</div>

Buildkite passes branch / tag / message metadata as environment variables. Putting them inside ``$(...)`` or shelling out with the value unquoted is a classic command-injection vector. The detection fires on the unquoted interpolation form and on use inside ``eval`` / ``$(...)``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't interpolate ``$BUILDKITE_BRANCH``, ``$BUILDKITE_TAG``, ``$BUILDKITE_MESSAGE``, ``$BUILDKITE_PULL_REQUEST_*``, or ``$BUILDKITE_BUILD_AUTHOR*`` directly into shell commands. These come from the pull request / branch and are attacker-controllable. Quote them and assign to a local variable first (``branch="$BUILDKITE_BRANCH"; ./script --branch "$branch"``), or pass them as arguments to a script you own.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## BK-004: Remote script piped into shell interpreter { #bk-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

The detection fires on ``curl|bash``, ``curl|sh``, ``wget|bash``, ``iex (iwr ...)``, and the corresponding ``Invoke-WebRequest|Invoke-Expression`` PowerShell forms. Use ``curl -fsSLO <url>; sha256sum -c install.sh.sha256; bash install.sh`` instead.

<div class="pg-rule__rec" markdown>

**Recommended action**

Download the installer to disk, verify a checksum or signature, then execute it. ``curl ... | sh`` lets the remote host change what runs in your pipeline at any time, and any TLS / DNS error during download silently feeds a partial script to the shell.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## BK-005: Container started with --privileged or host-bind escalation { #bk-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-D-RUNTIME-HARDENING</span> <span class="pg-tag pg-tag--cwe">CWE-269</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Detection fires on ``--privileged``, ``--cap-add=SYS_ADMIN``, ``--pid=host`` / ``--ipc=host`` / ``--userns=host``, and explicit mounts of the host Docker socket (``/var/run/docker.sock``).

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop ``--privileged``, ``--cap-add=SYS_ADMIN``, ``--pid=host``, and ``-v /var/run/docker.sock`` from container invocations. If the workload needs Docker-in-Docker, use a build-specific rootless option (``buildx``, ``kaniko``, ``buildah --isolation=chroot``) instead of opening the host kernel and the agent's Docker socket to the build script.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## BK-006: Step has no timeout_in_minutes { #bk-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-RUNTIME-HARDENING</span> <span class="pg-tag pg-tag--cwe">CWE-400</span>
</div>

Buildkite has no implicit timeout; agents will wait forever. Set ``timeout_in_minutes:`` per step. The pipeline-level default counts, a global ``steps:`` block with ``timeout_in_minutes:`` is fine, since Buildkite copies it to each step.

**Known false-positive modes**

- Steps that genuinely need >24h (rare; database migrations, ML training jobs), set ``timeout_in_minutes: 1440`` explicitly so the absence of a timeout is intentional.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``timeout_in_minutes:`` on every command step. A compromised dependency or a hung test can otherwise hold an agent indefinitely, blocking parallel pipelines and running up self-hosted-runner cost. Pick a value generous enough for the slowest legitimate run (e.g. 30 for a typical build, 90 for an integration suite).

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BK-007: Deploy step not gated by a manual block / input { #bk-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-CHANGE-MGMT</span> <span class="pg-tag pg-tag--cwe">CWE-285</span>
</div>

A step is treated as a deploy when its label, key, or any command line contains a deploy keyword (``deploy``, ``ship``, ``release``, ``promote``, ``apply``, ``rollout``, ``terraform apply``, ``kubectl apply``, ``helm upgrade``, ``aws ecs update-service``). The check passes when at least one preceding step in the same pipeline file is a ``block:`` or ``input:`` flow-control step.

**Known false-positive modes**

- Pipelines where the deploy gate lives in a triggered pipeline rather than the local file, the local pipeline looks ungated even though the actual deploy is gated downstream. Add a no-op ``block:`` to silence.

<div class="pg-rule__rec" markdown>

**Recommended action**

Insert a ``- block: "Deploy?"`` (or ``- input:`` step) in front of every deploy step. Buildkite waits for a human to click *Unblock* before the gated steps run, which prevents an unreviewed merge from auto-deploying to production. Combine with ``branches: main`` so the gate only appears on release branches.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BK-008: TLS verification disabled in step command { #bk-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-D-COMMS-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-295</span>
</div>

Detection fires on the canonical bypass flags across curl, wget, git, npm, pip, gcloud, and openssl. The check is deliberately conservative, partial-word matches (``--insecure-protocols``) are excluded.

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop ``curl -k`` / ``--insecure``, ``wget --no-check-certificate``, ``git -c http.sslVerify=false``, and ``pip install --trusted-host``. If a CA isn't trusted, install it into the agent's trust store (``update-ca-certificates``) rather than disabling validation pipeline-wide. A compromised intermediate that strips TLS gets a free hand with every fetch the step performs.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BK-009: Artifacts not signed (no cosign/sigstore step) { #bk-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-SIGN-ARTIFACTS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Unsigned artifacts can't be verified downstream, a tampered build is indistinguishable from a legitimate one. The check recognises cosign, sigstore, slsa-github-generator, slsa-framework, and notation-sign as signing tools, matching the shared signing-token catalog used by the other CI packs.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a signing step, install cosign once (``brew install cosign`` in the agent image, or a ``cosign-install`` plugin) and call ``cosign sign --yes <ref>`` after the build. For container images pushed to ECR / GCR / GHCR, the same call signs by digest. Publish the signature alongside the artifact and verify it at consumption time.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BK-010: No SBOM generated for build artifacts { #bk-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-SBOM</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

An SBOM (CycloneDX or SPDX) records every component baked into the build. Without one, post-incident triage can't answer ``did this CVE ship?`` for a given artifact. Detection uses the shared SBOM-token catalog, syft, cyclonedx, cdxgen, spdx-tools, microsoft/sbom-tool.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add an SBOM-generation step. ``syft <artifact> -o cyclonedx-json > sbom.json`` runs in any standard agent image; ``cyclonedx-cli`` and ``cdxgen`` are alternative producers. Upload the SBOM via ``buildkite-agent artifact upload`` so downstream consumers (and incident-response tooling) can match deployed artifacts to the components they were built from.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BK-011: No SLSA provenance attestation produced { #bk-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Provenance generation is distinct from signing. A signed artifact proves *who* published it; a provenance attestation proves *where / how* it was built. Without it, a leaked signing key forges identity but a leaked build environment also forges provenance. You need both for the SLSA L3 non-falsifiability guarantee. Detection uses the shared provenance-token catalog (``slsa-framework``, ``cosign attest``, ``in-toto``, ``attest-build-provenance``).

<div class="pg-rule__rec" markdown>

**Recommended action**

Run ``cosign attest --predicate slsa.json`` (or the SLSA-framework generator from a build-time step) after the build completes. The predicate records the build inputs and the agent that produced the artifact. Publish the attestation alongside the artifact so consumers can verify *how* it was built, not just *who* signed it.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BK-012: No vulnerability scanning step { #bk-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-VULN-SCAN</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Vulnerability scanning sits at a different layer from signing and SBOM. It answers ``does this artifact ship a known CVE?`` rather than ``can we verify what it is?``. Detection uses the shared vuln-scan-token catalog: trivy, grype, snyk, npm-audit, pip-audit, anchore, dependency-check, checkov, semgrep.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a vulnerability scanner, ``trivy fs .`` for source / filesystem, ``trivy image <ref>`` for container images, ``grype`` and ``snyk`` for either. Add ``npm audit`` / ``pip-audit`` for language-specific dep audits. Fail the step on findings above a chosen severity so a regression blocks the merge instead of shipping.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BK-013: Deploy step has no branches: filter { #bk-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-C-ENV-SEP</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

A step is treated as a deploy when its label, key, or any command line contains a deploy keyword (``deploy``, ``ship-it``, ``release``, ``promote``, ``rollout``, ``helm upgrade``, ``kubectl apply``, ``terraform apply``, ``aws ecs update-service``, ``aws lambda update-function-code``, ``gcloud run deploy``). The check passes when the step declares ``branches:`` with at least one literal branch name (a wildcard like ``"*"`` is treated as an explicit opt-out, not a passing filter, and still trips). The pipeline-level default also counts, top-level ``steps:`` with ``branches:`` propagates.

**Known false-positive modes**

- Trunk-based teams that branch-protect ``main`` and treat every merge as a deploy candidate may not use ``branches:``. Add ``branches: main`` to make the policy explicit, or ignore BK-013 in ``.pipeline-check-ignore.yml`` with a scope of ``main``-only repos.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add ``branches: "main release/*"`` (or your release branch glob) to every deploy step. Buildkite skips the step on any other branch, which prevents a feature-branch PR from accidentally promoting code to production. Combine with BK-007's manual ``block:`` so a release branch *plus* a human approval is the path to deploy.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BK-014: Step commands run unpinned package installs { #bk-014 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Detection reuses the cross-provider primitives ``PKG_INSECURE_RE`` and ``PKG_NO_LOCKFILE_RE`` from ``checks/base.py``. Same rule pack already exists for GHA (``GHA-021`` / ``GHA-022``), GitLab (``GL-021`` / ``GL-022``), Bitbucket / Azure DevOps / Jenkins / CircleCI / Cloud Build / Drone. Buildkite was a gap; this closes it.

Insecure variants (``PKG_INSECURE_RE``): ``pip --index-url http://``, ``pip --trusted-host``, ``npm --registry http://``, ``gem --source http://``, ``nuget --Source http://``, ``cargo --index http://``. Lockfile-bypass variants (``PKG_NO_LOCKFILE_RE``): ``npm install`` (should be ``npm ci``), bare ``pip install <pkg>`` without ``-r`` or ``--require-hashes``, ``yarn install`` without ``--frozen-lockfile``, ``bundle install`` without ``--frozen``, ``cargo install``, ``go install`` without an ``@vN.N`` pin, ``poetry install`` without ``--no-update``.

**Known false-positive modes**

- Bootstrap-stage installs that intentionally pull latest (``apt-get install -y curl`` for a tooling image rebuild) sometimes legitimately bypass the lockfile. Suppress via ignore-file scoped to the specific step label when this is the deliberate shape; the broader pinning policy still covers the rest of the pipeline.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every package install to a lockfile or a checksum-verified version. ``npm ci`` (not ``npm install``), ``yarn install --frozen-lockfile``, ``pip install -r requirements.txt --require-hashes``, ``bundle install --frozen``. Don't use ``--trusted-host`` / ``--no-verify`` / a non-HTTPS index URL — those bypass TLS or trust validation entirely (BK-008 covers the TLS subset; this rule covers the lockfile subset).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## BK-015: agents map interpolates attacker-controllable Buildkite variable { #bk-015 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-D-CODE-INTEGRITY</span> <span class="pg-tag pg-tag--esf">ESF-S-RUNNER-ISOLATION</span> <span class="pg-tag pg-tag--cwe">CWE-78</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

Buildkite uses an ``agents:`` map to route a step to a specific runner pool. Both the top-level ``agents:`` and the per-step override are scanned. Detection mirrors BK-003's tainted-variable list (``$BUILDKITE_BRANCH``, ``$BUILDKITE_TAG``, ``$BUILDKITE_MESSAGE``, ``$BUILDKITE_PULL_REQUEST_*``, ``$BUILDKITE_BUILD_AUTHOR*``, ``$BUILDKITE_COMMIT``). The pattern matches what GHA-036, GL-032, JF-032, ADO-030, and CC-031 already enforce on the other CI providers; closes parity for Buildkite.

Quote-state aware in the same way BK-003 is. ``"$BUILDKITE_BRANCH"`` doesn't fire (Buildkite doesn't shell-eval the agents map anyway, but the value still substitutes), only the unquoted single-token interpolation does.

**Known false-positive modes**

- Some teams use a static prefix plus a CI-controlled tail (``queue: build-$BUILDKITE_PIPELINE_SLUG``) to share an agent pool across pipelines. ``BUILDKITE_PIPELINE_SLUG`` is not pusher-controllable so it isn't on the tainted list, but if your team has its own conventions for trusted Buildkite vars, suppress on the specific step.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every ``agents:`` map entry to a static literal that matches your runner targeting policy. ``queue: linux-amd64`` or ``os: linux`` is fine; ``queue: $BUILDKITE_BRANCH`` is not, because the pusher can route their build to whichever agent pool they want, including a privileged pool reserved for the deploy step. Production runner pools should also carry a tag the agent itself enforces (e.g. ``buildkite-agent start --tags 'queue=production'`` plus a queue-allow-list on the API token), so the rule is one layer of a defense-in-depth posture.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## TAINT-005: Untrusted input flows across steps via ``buildkite-agent meta-data`` { #taint-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-78</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Detection is a two-pass walk over the pipeline. Pass 1 looks for ``buildkite-agent meta-data set <key> <value>`` invocations whose ``<value>`` interpolates an attacker-controllable Buildkite predefined variable (the same ``BUILDKITE_*`` vocabulary BK-003 uses). Pass 2 walks every step for ``buildkite-agent meta-data get <key>`` invocations and matches against the producer keys recorded in pass 1.

Buildkite meta-data is per-build, not per-step; any step in the same build can read what any earlier step wrote regardless of ``depends_on:``. The detector doesn't model temporal ordering and fires whenever both a tainted set and a get of the same key exist in the same pipeline file. v1 limitations: ``meta-data exists`` (returns 0/1 status) and the ``--default`` form aren't tracked; plugins providing their own meta-data abstraction (e.g. ``cattle-ops/github-merged-pr``) aren't introspected.

**Known false-positive modes**

- If the producer step runs a sanitiser between the tainted source interpolation and the ``meta-data set`` call (``echo "$BUILDKITE_PULL_REQUEST_TITLE" | tr -dc 'a-zA-Z0-9 ' | xargs -I{} buildkite-agent meta-data set title {}``), the consumer is no longer exploitable but TAINT-005 still fires. Suppress via ignore-file scoped to the consumer step's pipeline file when this is the deliberate shape; the sanitiser is then load-bearing and any future regression in it would re-expose the consumer.

<div class="pg-rule__rec" markdown>

**Recommended action**

Sanitise the value at the producer step before it lands in the meta-data store. The canonical safe pattern is to copy the ``$BUILDKITE_PULL_REQUEST_*`` / ``$BUILDKITE_MESSAGE`` / branch / commit / author source into an intermediate shell variable, run a sanitiser (``tr -dc 'a-zA-Z0-9 '`` is enough for a freeform title), and only then call ``buildkite-agent meta-data set``. The consuming step should still reference the ``$(buildkite-agent meta-data get ...)`` value quoted (``"$TITLE"``) and never inline into a command without re-quoting. Removing the meta-data flow entirely is the strongest fix; if the value genuinely needs to flow downstream, validate the sanitiser is doing what you think before relying on it.

</div>

</div>

---

## Adding a new Buildkite check

1. Create a new module at
   `pipeline_check/core/checks/buildkite/rules/bkNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the parsed YAML document.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/buildkite/BK-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py buildkite
   ```
