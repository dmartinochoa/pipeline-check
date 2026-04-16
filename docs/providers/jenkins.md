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

| Check    | Title                                                          | Severity |
|----------|----------------------------------------------------------------|----------|
| JF-001   | Shared library not pinned to a tag or commit                    | HIGH     |
| JF-002   | Script step interpolates attacker-controllable env var          | HIGH     |
| JF-003   | Pipeline uses `agent any` (no executor isolation)               | MEDIUM   |
| JF-004   | AWS auth uses long-lived access keys via `withCredentials`      | MEDIUM   |
| JF-005   | Deploy stage missing manual `input` approval                    | MEDIUM   |
| JF-006   | Artifacts not signed                                            | MEDIUM   |
| JF-007   | SBOM not produced                                               | MEDIUM   |
| JF-008   | Credential-shaped literal in pipeline body                      | CRITICAL |
| JF-009   | Agent docker image not pinned to sha256 digest                  | HIGH     |
| JF-010   | Long-lived AWS keys exposed via `environment { … }`             | HIGH     |
| JF-011   | Pipeline has no `buildDiscarder` retention policy               | LOW      |
| JF-012   | `load` step pulls Groovy from disk without integrity pin        | MEDIUM   |
| JF-013   | `copyArtifacts` ingests another job's output unverified         | CRITICAL |

---

## JF-001 — Shared library not pinned to a tag or commit
**Severity:** HIGH · CICD-SEC-3 Dependency Chain Abuse

Every `@Library('name@<ref>')` reference should pin a release tag
(`@v1.4.2`, `@1.4.2`) or a 40-char commit SHA. References without an
`@ref` use the library's *default* version (typically the
controller-configured branch), and references like `@main` /
`@master` / `@develop` follow whoever holds push access on the
upstream repo.

**Recommended actions**
- Pin every `@Library` to a tag or commit SHA.
- In Jenkins → Manage Jenkins → System → Global Pipeline Libraries,
  uncheck **Allow default version to be overridden** so a pipeline
  can't escape the pin at runtime.

## JF-002 — Script step interpolates attacker-controllable env var
**Severity:** HIGH · CICD-SEC-4 Poisoned Pipeline Execution

Multibranch and PR-source plugins set Jenkins env vars
(`BRANCH_NAME`, `GIT_BRANCH`, `TAG_NAME`, `CHANGE_TITLE`,
`CHANGE_BRANCH`, `CHANGE_AUTHOR_DISPLAY_NAME`) directly from values
the SCM event author controls. Interpolating them into a
double-quoted shell step (`sh "echo ${env.BRANCH_NAME}"`) lets a
crafted ref name execute as part of the build.

**Recommended actions**
- Use single-quoted Groovy strings (`sh 'echo "$BRANCH"'`) — they
  don't interpolate at the Groovy layer; the value reaches the
  shell where it can be properly quoted.
- Stage the value through `withEnv(["BRANCH=${env.BRANCH_NAME}"])`
  so the shell, not Groovy, expands it.

## JF-003 — Pipeline uses `agent any` (no executor isolation)
**Severity:** MEDIUM · CICD-SEC-5 Insufficient PBAC

`agent any` lets the build land on any registered executor. If one of
those executors has broader IAM, file-system, or network access than
this build needs, a compromise blast-radiates across pools.

**Recommended actions**
- Replace with a labelled pool: `agent { label 'build-pool' }`.
- Or use an ephemeral container per build:
  `agent { docker { image 'maven:3.9' } }`.

## JF-004 — AWS auth uses long-lived access keys via `withCredentials`
**Severity:** MEDIUM · CICD-SEC-6 Insufficient Credential Hygiene

Long-lived `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` values
bound through `withCredentials` can't be rotated on a fine-grained
schedule and remain valid until manually revoked.

**Recommended actions**
- Use the AWS plugin's role binding:
  `withAWS(role: 'arn:aws:iam::…:role/jenkins') { … }`.
- Or stand up an OIDC trust between the Jenkins controller and
  AWS so each build assumes a short-lived role.
- Remove the static credentials from the Jenkins credentials store
  once the role is in place.

## JF-005 — Deploy stage missing manual `input` approval
**Severity:** MEDIUM · CICD-SEC-1 Insufficient Flow Control Mechanisms

A stage named (or doing) `deploy` / `release` / `publish` / `promote`
with no `input` step ships to the target on every pipeline run.
Adding an `input` step makes the gate explicit and lets you scope
who can approve via Jenkins folder-level permissions.

**Recommended actions**
- `input message: 'Promote to prod?', submitter: 'releasers'` at the
  top of the stage.
- For declarative pipelines, the `input { … }` directive is the
  canonical form.

## JF-006 / JF-007 — Signing & SBOM
**Severity:** MEDIUM · ESF-D-SIGN-ARTIFACTS / ESF-D-SBOM

These mirror the equivalent checks across the other workflow
providers. Pass by invoking cosign / sigstore / notation
(JF-006) and a CycloneDX/SPDX-producing tool (JF-007) somewhere
in the pipeline body. The check looks at the raw text, so a
`sh 'cosign sign ...'` step is enough; you don't need a specific
plugin.

## JF-008 — Credential-shaped literal in pipeline body
**Severity:** CRITICAL · CICD-SEC-6 Insufficient Credential Hygiene

Every string in the Jenkinsfile is scanned against the
cross-provider credential-pattern catalogue (AWS access keys,
GitHub tokens, Slack tokens, JWTs, plus any patterns added via
`--secret-pattern`). A match means a secret was committed to
Groovy source — visible in every fork and every build log,
treat as compromised.

**Recommended actions**
- Rotate immediately.
- Move the value to a Jenkins credential and reference it via
  `withCredentials([string(credentialsId: 'foo', variable: 'FOO')]) { … }`.

## JF-009 — Agent docker image not pinned to sha256 digest
**Severity:** HIGH · CICD-SEC-3 Dependency Chain Abuse

`agent { docker { image '…' } }` references a registry image. Floating
tags (`:latest`, no tag at all, or major-only `:3`) and even immutable-
looking version tags (`:3.9.6`) can be repointed to a different
manifest by registry operators or by anyone who compromises the
namespace. Only sha256 digest pins are tamper-evident.

**Recommended actions**
- Resolve each ref to its current digest:
  `docker buildx imagetools inspect maven:3.9.6` prints the digest line.
- Rewrite as `image 'maven@sha256:<digest>'`.
- Schedule digest refreshes via Renovate so the pin stays current
  with upstream patch releases.

## JF-010 — Long-lived AWS keys exposed via `environment { … }`
**Severity:** HIGH · CICD-SEC-6 Insufficient Credential Hygiene

`environment { AWS_ACCESS_KEY_ID = "AKIA…" }` bakes a long-lived
credential into the Jenkinsfile. Beyond the obvious "now in source
control" problem, anything in scope of the block (every `sh` /
`bat`, every nested stage) can read it, and any debug print emits it
into the build log. The `credentials('id')` helper reads from the
Jenkins credentials store at runtime and is the safe pattern.

**Recommended actions**
- Replace the literal with `AWS_ACCESS_KEY_ID = credentials('aws-prod-key')`.
- For prod workloads, switch to the AWS plugin's role binding —
  `withAWS(role: 'arn:aws:iam::…:role/jenkins') { … }` — and remove
  the static credential from the Jenkins store entirely.

## JF-011 — Pipeline has no `buildDiscarder` retention policy
**Severity:** LOW · CICD-SEC-10 Insufficient Logging and Visibility

Without a retention policy, build logs accumulate indefinitely.
That sounds harmless — it is, until the day a secret leaks (an
unmasked output, a stack trace, a debug print). After that, the
secret is visible to anyone with read access to the job, in every
historical run, until the controller's disk fills up. A bounded
retention window means the blast radius of an accidental log leak
is bounded too.

**Recommended actions**
- Declarative pipelines:
  `options { buildDiscarder(logRotator(numToKeepStr: '30', daysToKeepStr: '90')) }`.
- Scripted pipelines: `properties([buildDiscarder(...)])` at the top.
- Tune the numbers to match your retention policy — there's no
  universally-correct value, but unlimited is the wrong one.

## JF-012 — `load` step pulls Groovy from disk without integrity pin
**Severity:** MEDIUM · CICD-SEC-3 Dependency Chain Abuse

`load 'ci/helpers.groovy'` evaluates whatever exists at that path
when the build runs. There's no integrity check — a workspace
mutation (a stash restore, an archived-artifact unpack, or a
sibling step writing to the same path) can swap the loaded code
between the `load` call and the next pipeline run.

**Recommended actions**
- Move the helpers into a Jenkins shared library and reference it
  via `@Library('helpers@<sha>')` — those refs are version-pinned
  and JF-001 audits them.
- Reserve `load` for one-off development experimentation, never
  for production pipelines.

---

## Adding a new Jenkins check

1. Add a check method to
   `pipeline_check/core/checks/jenkins/jenkinsfile.py` returning a
   `Finding`. Give it an ID of the form `JF-<NNN>` and register the
   call in `_check_file`.
2. Add a mapping for the new ID in
   `pipeline_check/core/standards/data/owasp_cicd_top_10.py` (and any
   other standard that applies).
3. Update both fixtures under `tests/fixtures/workflows/jenkins/` so
   the new check fails on `Jenkinsfile.insecure` and passes on
   `Jenkinsfile.secure`.
4. Update the `EXPECTED_IDS` set in
   `tests/test_workflow_fixtures.py::TestJenkinsFixtures`.
