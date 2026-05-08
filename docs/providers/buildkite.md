# Buildkite provider

Parses `.buildkite/pipeline.yml` (or any user-named pipeline file) on
disk — no Buildkite API token, no agent install required. Each
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

- **BK-001** — plugin refs must be pinned to an exact tag
  (`docker-compose#v4.13.0`) or a 40-char SHA. Branch refs (`#main`)
  and bare names float and let a compromised plugin release execute
  in the pipeline.
- **BK-007** — every step that looks like a deploy (label / command
  matches `deploy`, `kubectl apply`, `terraform apply`, `helm
  upgrade`, …) must be preceded by a `block:` or `input:` step in
  the same pipeline file. Buildkite waits for a human to click
  *Unblock* before the gated steps run.

## What it covers

13 checks · 0 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [BK-001](#bk-001) | Buildkite plugin not pinned to an exact version | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [BK-002](#bk-002) | Literal secret value in pipeline env block | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [BK-003](#bk-003) | Untrusted Buildkite variable interpolated in command | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [BK-004](#bk-004) | Remote script piped into shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [BK-005](#bk-005) | Container started with --privileged or host-bind escalation | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [BK-006](#bk-006) | Step has no timeout_in_minutes | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [BK-007](#bk-007) | Deploy step not gated by a manual block / input | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [BK-008](#bk-008) | TLS verification disabled in step command | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [BK-009](#bk-009) | Artifacts not signed (no cosign/sigstore step) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [BK-010](#bk-010) | No SBOM generated for build artifacts | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [BK-011](#bk-011) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [BK-012](#bk-012) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [BK-013](#bk-013) | Deploy step has no branches: filter | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## BK-001 — Buildkite plugin not pinned to an exact version { #bk-001 }

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

## BK-002 — Literal secret value in pipeline env block { #bk-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span> <span class="pg-tag pg-tag--cwe">CWE-532</span>
</div>

Detection fires on values that look like AWS access keys, GitHub PATs, OpenAI keys, JWTs, or generic high-entropy tokens, plus on env-var names that imply a secret (``*_TOKEN``, ``*_KEY``, ``*PASSWORD``, ``*SECRET``) when the value is a non-empty literal rather than an interpolation (``$SECRET_FROM_AGENT_HOOK``).

<div class="pg-rule__rec" markdown>

**Recommended action**

Move the value out of the pipeline file. Use Buildkite's agent secrets hooks (``secrets/`` directory or ``BUILDKITE_PLUGIN_AWS_SSM_*``), the ``aws-ssm`` / ``vault-secrets`` plugins, or the ``BUILDKITE_PIPELINE_DEFAULT_BRANCH`` env var pulled from a secret manager. The pipeline.yml is committed to the repo and visible to anyone with read access.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## BK-003 — Untrusted Buildkite variable interpolated in command { #bk-003 }

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

## BK-004 — Remote script piped into shell interpreter { #bk-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

The detection fires on ``curl|bash``, ``curl|sh``, ``wget|bash``, ``iex (iwr ...)``, and the corresponding ``Invoke-WebRequest|Invoke-Expression`` PowerShell forms. Use ``curl -fsSLO <url>; sha256sum -c install.sh.sha256; bash install.sh`` instead.

<div class="pg-rule__rec" markdown>

**Recommended action**

Download the installer to disk, verify a checksum or signature, then execute it. ``curl ... | sh`` lets the remote host change what runs in your pipeline at any time, and any TLS / DNS error during download silently feeds a partial script to the shell.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## BK-005 — Container started with --privileged or host-bind escalation { #bk-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-D-RUNTIME-HARDENING</span> <span class="pg-tag pg-tag--cwe">CWE-269</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Detection fires on ``--privileged``, ``--cap-add=SYS_ADMIN``, ``--pid=host`` / ``--ipc=host`` / ``--userns=host``, and explicit mounts of the host Docker socket (``/var/run/docker.sock``).

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop ``--privileged``, ``--cap-add=SYS_ADMIN``, ``--pid=host``, and ``-v /var/run/docker.sock`` from container invocations. If the workload needs Docker-in-Docker, use a build-specific rootless option (``buildx``, ``kaniko``, ``buildah --isolation=chroot``) instead of opening the host kernel and the agent's Docker socket to the build script.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## BK-006 — Step has no timeout_in_minutes { #bk-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-RUNTIME-HARDENING</span> <span class="pg-tag pg-tag--cwe">CWE-400</span>
</div>

Buildkite has no implicit timeout; agents will wait forever. Set ``timeout_in_minutes:`` per step. The pipeline-level default counts — a global ``steps:`` block with ``timeout_in_minutes:`` is fine, since Buildkite copies it to each step.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``timeout_in_minutes:`` on every command step. A compromised dependency or a hung test can otherwise hold an agent indefinitely, blocking parallel pipelines and running up self-hosted-runner cost. Pick a value generous enough for the slowest legitimate run (e.g. 30 for a typical build, 90 for an integration suite).

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BK-007 — Deploy step not gated by a manual block / input { #bk-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-2</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-CHANGE-MGMT</span> <span class="pg-tag pg-tag--cwe">CWE-285</span>
</div>

A step is treated as a deploy when its label, key, or any command line contains a deploy keyword (``deploy``, ``ship``, ``release``, ``promote``, ``apply``, ``rollout``, ``terraform apply``, ``kubectl apply``, ``helm upgrade``, ``aws ecs update-service``). The check passes when at least one preceding step in the same pipeline file is a ``block:`` or ``input:`` flow-control step.

<div class="pg-rule__rec" markdown>

**Recommended action**

Insert a ``- block: "Deploy?"`` (or ``- input:`` step) in front of every deploy step. Buildkite waits for a human to click *Unblock* before the gated steps run, which prevents an unreviewed merge from auto-deploying to production. Combine with ``branches: main`` so the gate only appears on release branches.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BK-008 — TLS verification disabled in step command { #bk-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-D-COMMS-INTEGRITY</span> <span class="pg-tag pg-tag--cwe">CWE-295</span>
</div>

Detection fires on the canonical bypass flags across curl, wget, git, npm, pip, gcloud, and openssl. The check is deliberately conservative — partial-word matches (``--insecure-protocols``) are excluded.

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop ``curl -k`` / ``--insecure``, ``wget --no-check-certificate``, ``git -c http.sslVerify=false``, and ``pip install --trusted-host``. If a CA isn't trusted, install it into the agent's trust store (``update-ca-certificates``) rather than disabling validation pipeline-wide. A compromised intermediate that strips TLS gets a free hand with every fetch the step performs.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BK-009 — Artifacts not signed (no cosign/sigstore step) { #bk-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-SIGN-ARTIFACTS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Unsigned artifacts can't be verified downstream — a tampered build is indistinguishable from a legitimate one. The check recognises cosign, sigstore, slsa-github-generator, slsa-framework, and notation-sign as signing tools, matching the shared signing-token catalog used by the other CI packs.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a signing step — install cosign once (``brew install cosign`` in the agent image, or a ``cosign-install`` plugin) and call ``cosign sign --yes <ref>`` after the build. For container images pushed to ECR / GCR / GHCR, the same call signs by digest. Publish the signature alongside the artifact and verify it at consumption time.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BK-010 — No SBOM generated for build artifacts { #bk-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-SBOM</span> <span class="pg-tag pg-tag--cwe">CWE-1357</span>
</div>

An SBOM (CycloneDX or SPDX) records every component baked into the build. Without one, post-incident triage can't answer ``did this CVE ship?`` for a given artifact. Detection uses the shared SBOM-token catalog — syft, cyclonedx, cdxgen, spdx-tools, microsoft/sbom-tool.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add an SBOM-generation step. ``syft <artifact> -o cyclonedx-json > sbom.json`` runs in any standard agent image; ``cyclonedx-cli`` and ``cdxgen`` are alternative producers. Upload the SBOM via ``buildkite-agent artifact upload`` so downstream consumers (and incident-response tooling) can match deployed artifacts to the components they were built from.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BK-011 — No SLSA provenance attestation produced { #bk-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Provenance generation is distinct from signing. A signed artifact proves *who* published it; a provenance attestation proves *where / how* it was built. Without it, a leaked signing key forges identity but a leaked build environment also forges provenance — you need both for the SLSA L3 non-falsifiability guarantee. Detection uses the shared provenance-token catalog (``slsa-framework``, ``cosign attest``, ``in-toto``, ``attest-build-provenance``).

<div class="pg-rule__rec" markdown>

**Recommended action**

Run ``cosign attest --predicate slsa.json`` (or the SLSA-framework generator from a build-time step) after the build completes. The predicate records the build inputs and the agent that produced the artifact. Publish the attestation alongside the artifact so consumers can verify *how* it was built, not just *who* signed it.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BK-012 — No vulnerability scanning step { #bk-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-VULN-SCAN</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Vulnerability scanning sits at a different layer from signing and SBOM — it answers ``does this artifact ship a known CVE?`` rather than ``can we verify what it is?``. Detection uses the shared vuln-scan-token catalog: trivy, grype, snyk, npm-audit, pip-audit, anchore, dependency-check, checkov, semgrep.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a vulnerability scanner — ``trivy fs .`` for source / filesystem, ``trivy image <ref>`` for container images, ``grype`` and ``snyk`` for either. Add ``npm audit`` / ``pip-audit`` for language-specific dep audits. Fail the step on findings above a chosen severity so a regression blocks the merge instead of shipping.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## BK-013 — Deploy step has no branches: filter { #bk-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-C-ENV-SEP</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

A step is treated as a deploy when its label, key, or any command line contains a deploy keyword (``deploy``, ``ship-it``, ``release``, ``promote``, ``rollout``, ``helm upgrade``, ``kubectl apply``, ``terraform apply``, ``aws ecs update-service``, ``aws lambda update-function-code``, ``gcloud run deploy``). The check passes when the step declares ``branches:`` with at least one literal branch name (a wildcard like ``"*"`` is treated as an explicit opt-out, not a passing filter, and still trips). The pipeline-level default also counts — top-level ``steps:`` with ``branches:`` propagates.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add ``branches: "main release/*"`` (or your release branch glob) to every deploy step. Buildkite skips the step on any other branch, which prevents a feature-branch PR from accidentally promoting code to production. Combine with BK-007's manual ``block:`` so a release branch *plus* a human approval is the path to deploy.

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
