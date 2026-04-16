# Jenkins provider

Parses Jenkinsfile text — Declarative or Scripted Pipeline — without
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

The loader recognises files named `Jenkinsfile` exactly, plus anything
ending in `.jenkinsfile` or `.groovy`. It treats every file as text —
no Groovy parsing — and applies the same regex-driven heuristics the
other workflow providers use for `run:` blocks. False positives are
intentional: better to flag and let the operator suppress than to
miss a real injection because the parser couldn't follow a dynamic
expression.

## What it covers

| Check | Title | Severity |
|-------|-------|----------|
| JF-001 | Shared library not pinned to a tag or commit | HIGH |
| JF-002 | Script step interpolates attacker-controllable env var | HIGH |
| JF-003 | Pipeline uses `agent any` (no executor isolation) | MEDIUM |
| JF-004 | AWS auth uses long-lived access keys via withCredentials | MEDIUM |
| JF-005 | Deploy stage missing manual `input` approval | MEDIUM |
| JF-006 | Artifacts not signed | MEDIUM |
| JF-007 | SBOM not produced | MEDIUM |
| JF-008 | Credential-shaped literal in pipeline body | CRITICAL |
| JF-009 | Agent docker image not pinned to sha256 digest | HIGH |
| JF-010 | Long-lived AWS keys exposed via environment {} block | HIGH |
| JF-011 | Pipeline has no `buildDiscarder` retention policy | LOW |
| JF-012 | `load` step pulls Groovy from disk without integrity pin | MEDIUM |
| JF-013 | copyArtifacts ingests another job's output unverified | CRITICAL |
| JF-014 | Agent label missing ephemeral marker | MEDIUM |
| JF-015 | Pipeline has no `timeout` wrapper — unbounded build | MEDIUM |
| JF-016 | Remote script piped to shell interpreter | HIGH |
| JF-017 | Docker run with insecure flags (privileged/host mount) | CRITICAL |
| JF-018 | Package install from insecure source | HIGH |
| JF-019 | Groovy sandbox escape pattern detected | CRITICAL |
| JF-020 | No vulnerability scanning step | MEDIUM |

---

## JF-001 — Shared library not pinned to a tag or commit
**Severity:** HIGH · OWASP CICD-SEC-3 · ESF ESF-S-PIN-DEPS, ESF-S-VERIFY-DEPS

`@main`, `@master`, `@develop`, no-`@ref`, and any non-semver / non-SHA ref are floating. Whoever controls the upstream library can ship code into your build by pushing to that branch.

**Recommended action**

Pin every `@Library('name@<ref>')` to a release tag (e.g. `@v1.4.2`) or a 40-char commit SHA. Configure the library in Jenkins with 'Allow default version to be overridden' disabled so a pipeline can't escape the pin.

## JF-002 — Script step interpolates attacker-controllable env var
**Severity:** HIGH · OWASP CICD-SEC-4 · ESF ESF-D-INJECTION

$BRANCH_NAME / $GIT_BRANCH / $TAG_NAME / $CHANGE_* are populated from SCM event metadata the attacker controls. Single-quoted Groovy strings don't interpolate so they're safe; only double-quoted / triple-double-quoted bodies are flagged.

**Recommended action**

Switch the affected `sh`/`bat`/`powershell` step to a single-quoted string (Groovy doesn't interpolate single quotes), and pass values through a quoted shell variable (`sh 'echo "$BRANCH"'` after `withEnv([...])`).

## JF-003 — Pipeline uses `agent any` (no executor isolation)
**Severity:** MEDIUM · OWASP CICD-SEC-5 · ESF ESF-D-BUILD-ENV, ESF-D-PRIV-BUILD

`agent any` is the broadest possible executor scope — any registered executor can be picked, including ones with broader IAM / file-system access than this build needs. A compromise of one job blast-radiates across every pool.

**Recommended action**

Replace `agent any` with `agent { label 'build-pool' }` (targeting a labelled pool) or `agent { docker { image '...' } }` (ephemeral container). Reserve broad-access agents for jobs that genuinely need them.

## JF-004 — AWS auth uses long-lived access keys via withCredentials
**Severity:** MEDIUM · OWASP CICD-SEC-6 · ESF ESF-D-TOKEN-HYGIENE

Fires when BOTH a credentialsId containing `aws` is referenced AND an AWS key variable name appears. Requires both so an OIDC role binding (which doesn't use key variables) doesn't false-positive.

**Recommended action**

Switch to the AWS plugin's IAM-role / OIDC binding (e.g. `withAWS(role: 'arn:aws:iam::…:role/jenkins')`) so each build assumes a short-lived role. Remove the static AWS_ACCESS_KEY_ID secret from the Jenkins credentials store once the role is in place.

## JF-005 — Deploy stage missing manual `input` approval
**Severity:** MEDIUM · OWASP CICD-SEC-1 · ESF ESF-C-APPROVAL

A stage named `deploy` / `release` / `publish` / `promote` should either use the declarative `input { ... }` directive or call `input message: ...` somewhere in its body. Without one, any push that triggers the pipeline ships to the target with no human review.

**Recommended action**

Add an `input` step to every deploy-like stage (e.g. `input message: 'Promote to prod?', submitter: 'releasers'`). Combine with a Jenkins folder-scoped permission so only release engineers see the prompt.

## JF-006 — Artifacts not signed
**Severity:** MEDIUM · OWASP CICD-SEC-9 · ESF ESF-D-SIGN-ARTIFACTS

Passes when cosign / sigstore / slsa-* / notation-sign appears in the raw Jenkinsfile text.

**Recommended action**

Add a `sh 'cosign sign --yes …'` step (the cosign-installer Jenkins plugin handles binary install). Publish the signature next to the artifact and verify it at deploy.

## JF-007 — SBOM not produced
**Severity:** MEDIUM · OWASP CICD-SEC-9 · ESF ESF-D-SBOM

Passes when a direct SBOM tool token (CycloneDX, syft, anchore, spdx-sbom-generator, sbom-tool) appears, or when Trivy is paired with `sbom` / `cyclonedx` in the same file.

**Recommended action**

Add a `sh 'syft . -o cyclonedx-json > sbom.json'` step (or Trivy with `--format cyclonedx`) and archive the result with `archiveArtifacts`.

## JF-008 — Credential-shaped literal in pipeline body
**Severity:** CRITICAL · OWASP CICD-SEC-6 · ESF ESF-D-SECRETS

Scans the raw Jenkinsfile text against the cross-provider credential-pattern catalogue. Secrets committed to Groovy source are visible in every fork and every build log.

**Recommended action**

Rotate the exposed credential. Move the value to a Jenkins credential and reference it via `withCredentials([string(credentialsId: '…', variable: '…')])`.

## JF-009 — Agent docker image not pinned to sha256 digest
**Severity:** HIGH · OWASP CICD-SEC-3 · ESF ESF-S-PIN-DEPS, ESF-S-IMMUTABLE

`agent { docker { image 'name:tag' } }` is not digest-pinned, so a repointed registry tag silently swaps the executor under every subsequent build. Unlike the YAML providers, Jenkins has no separate tag-pinning check — so this one fires at HIGH regardless of whether the tag is floating or immutable.

**Recommended action**

Resolve each image to its current digest (`docker buildx imagetools inspect <ref>` prints it) and reference it via `image '<repo>@sha256:<digest>'`. Automate refreshes with Renovate.

## JF-010 — Long-lived AWS keys exposed via environment {} block
**Severity:** HIGH · OWASP CICD-SEC-6 · ESF ESF-D-SECRETS, ESF-D-TOKEN-HYGIENE

Flags `environment { AWS_ACCESS_KEY_ID = '...' }` when the value is a literal or plain variable reference. Skips `credentials('id')` helpers and `${env.X}` that resolve at runtime. Matches both multiline and inline `environment { ... }` forms.

**Recommended action**

Replace the literal with a credentials-store reference: `AWS_ACCESS_KEY_ID = credentials('aws-prod-key')`. Better: switch to the AWS plugin's role binding (`withAWS(role: 'arn:…')`) so the build assumes a short-lived role per run.

## JF-011 — Pipeline has no `buildDiscarder` retention policy
**Severity:** LOW · OWASP CICD-SEC-10 · ESF ESF-D-BUILD-LOGS, ESF-C-AUDIT

Without a retention policy, build logs accumulate indefinitely; a secret that once leaked into a log stays visible to anyone who can read jobs. Recognises declarative `options { buildDiscarder(...) }`, scripted `properties([buildDiscarder(...)])`, and bare `logRotator(...)`.

**Recommended action**

Add `options { buildDiscarder(logRotator(numToKeepStr: '30', daysToKeepStr: '90')) }` (declarative) or the `properties([buildDiscarder(...)])` equivalent in scripted pipelines. Tune the numbers to your retention policy.

## JF-012 — `load` step pulls Groovy from disk without integrity pin
**Severity:** MEDIUM · OWASP CICD-SEC-3 · ESF ESF-S-PIN-DEPS, ESF-S-VERIFY-DEPS

`load 'foo.groovy'` evaluates whatever exists at the path when the build runs — there's no integrity check, so a workspace mutation can swap the loaded code between runs.

**Recommended action**

Move shared Groovy into a Jenkins shared library (`@Library('name@<sha>')`) — those are version-pinned and JF-001 audits them. Reserve `load` for one-off development experiments.

## JF-013 — copyArtifacts ingests another job's output unverified
**Severity:** CRITICAL · OWASP CICD-SEC-4 · ESF ESF-D-INJECTION, ESF-S-VERIFY-DEPS

Recognises both `copyArtifacts(projectName: ...)` and the older `step([$class: 'CopyArtifact', ...])` form. If the upstream job accepts multibranch or PR builds, the artifact may have been produced by attacker-controlled code.

**Recommended action**

Add a verification step before consuming the artifact: `sh 'sha256sum -c manifest.sha256'` against a manifest the producer signed, or `cosign verify` over the artifact directly. Restrict the upstream job to non-PR builds via branch protection if verification isn't feasible.

## JF-014 — Agent label missing ephemeral marker
**Severity:** MEDIUM · OWASP CICD-SEC-7 · ESF ESF-D-BUILD-ENV, ESF-D-PRIV-BUILD

Static Jenkins agents that persist between builds leak workspace files and process state. The check looks for an `ephemeral` substring in `agent { label '...' }` blocks.

**Recommended action**

Register Jenkins agents with ephemeral lifecycle (e.g. Kubernetes pod templates or EC2 Fleet plugin) and include `ephemeral` in the label string so the pipeline declares its expectation.

## JF-015 — Pipeline has no `timeout` wrapper — unbounded build
**Severity:** MEDIUM · OWASP CICD-SEC-7 · ESF ESF-D-BUILD-TIMEOUT

Without a `timeout()` wrapper, the pipeline runs until the Jenkins controller's global timeout (or indefinitely if none is configured). Explicit timeouts cap blast radius and the window during which a compromised step has workspace access.

**Recommended action**

Wrap the pipeline body or individual stages with `timeout(time: N, unit: 'MINUTES') { … }`. Without an explicit timeout, the build runs until the Jenkins global default (or indefinitely).

## JF-016 — Remote script piped to shell interpreter
**Severity:** HIGH · OWASP CICD-SEC-3 · ESF ESF-S-VERIFY-DEPS

Detects `curl | bash`, `wget | sh`, and similar patterns that pipe remote content directly into a shell interpreter inside a Jenkinsfile. An attacker who controls the remote endpoint (or poisons DNS / CDN) gains arbitrary code execution in the build agent.

**Recommended action**

Download the script to a file, verify its checksum, then execute it. Or vendor the script into the repository.

## JF-017 — Docker run with insecure flags (privileged/host mount)
**Severity:** CRITICAL · OWASP CICD-SEC-7 · ESF ESF-D-BUILD-ENV

Flags like `--privileged`, `--cap-add`, `--net=host`, or host-root volume mounts (`-v /:/`) in a Jenkinsfile give the container full access to the build agent, enabling container escape and lateral movement.

**Recommended action**

Remove --privileged and --cap-add flags. Use minimal volume mounts. Prefer rootless containers.

## JF-018 — Package install from insecure source
**Severity:** HIGH · OWASP CICD-SEC-3 · ESF ESF-S-VERIFY-DEPS

Detects package-manager invocations that use plain HTTP registries (`--index-url http://`, `--registry=http://`) or disable TLS verification (`--trusted-host`, `--no-verify`) in a Jenkinsfile. These patterns allow man-in-the-middle injection of malicious packages.

**Recommended action**

Use HTTPS registry URLs. Remove --trusted-host and --no-verify flags. Pin to a private registry with TLS.

## JF-019 — Groovy sandbox escape pattern detected
**Severity:** CRITICAL · OWASP CICD-SEC-4 · ESF ESF-D-INJECTION

Detects Groovy patterns that bypass the Jenkins script security sandbox: `Runtime.getRuntime()`, `Class.forName()`, `.classLoader`, `ProcessBuilder`, and `@Grab`. These give the pipeline (or an attacker who controls its source) unrestricted access to the Jenkins controller JVM — full RCE.

**Recommended action**

Remove direct Runtime/ClassLoader calls. Use Jenkins pipeline steps instead. Avoid @Grab for untrusted dependencies.

## JF-020 — No vulnerability scanning step
**Severity:** MEDIUM · OWASP CICD-SEC-3 · ESF ESF-S-VULN-MGMT

Without a vulnerability scanning step, known-vulnerable dependencies ship to production undetected. The check recognises trivy, grype, snyk, npm audit, yarn audit, safety check, pip-audit, osv-scanner, and govulncheck.

**Recommended action**

Add a vulnerability scanning step — trivy, grype, snyk test, npm audit, pip-audit, or osv-scanner. Publish results so vulnerabilities surface before deployment.

---

## Adding a new Jenkins check

1. Create a new module at
   `pipeline_check/core/checks/jenkins/rules/jfNNN_<name>.py`
   exporting a top-level `RULE = Rule(...)` and a `check(path, doc) ->
   Finding` function. The orchestrator auto-discovers it.
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
