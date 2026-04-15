# GitLab CI provider

Parses a `.gitlab-ci.yml` (or directory containing one) from disk — no
network calls, no GitLab API token, no runner required.

## Producer workflow

```bash
# --gitlab-path is auto-detected when .gitlab-ci.yml is present at cwd;
# the CLI announces the pick on stderr ("[auto] using --gitlab-path …").
pipeline_check --pipeline gitlab

# …or pass it explicitly.
pipeline_check --pipeline gitlab --gitlab-path .gitlab-ci.yml
```

A directory is also accepted; the loader prefers a literal
`.gitlab-ci.yml` / `.gitlab-ci.yaml` file, and falls back to parsing every
`.yml` / `.yaml` under the directory (useful for scanning included
pipeline fragments):

```bash
pipeline_check --pipeline gitlab --gitlab-path ci/
```

All other flags (`--output`, `--severity-threshold`, `--checks`,
`--standard`, …) behave the same as with the other providers.

## What it covers

| Check   | Title                                                   | Severity |
|---------|---------------------------------------------------------|----------|
| GL-001  | Image not pinned to specific version or digest          | HIGH     |
| GL-002  | Script injection via untrusted commit/MR context        | HIGH     |
| GL-003  | Variables contain literal secret values                 | CRITICAL |
| GL-004  | Deploy job lacks manual approval or environment gate    | MEDIUM   |
| GL-005  | `include:` pulls remote / project without pinned ref    | HIGH     |
| GL-006  | Artifacts not signed                                    | MEDIUM   |
| GL-007  | SBOM not produced                                       | MEDIUM   |

---

## GL-001 — Image not pinned to specific version or digest
**Severity:** HIGH · CICD-SEC-3 Dependency Chain Abuse

`image: python:latest` (or a bare `image: python` with no tag) lets the
upstream registry swap the runtime under the job. Specific version tags
are good; digest pins (`@sha256:…`) are best.

**Recommended actions**
- Reference images by full immutable tag (`python:3.12.1-slim`) or, for
  high-assurance pipelines, by `@sha256:…` digest.
- Avoid `:latest` and major-only (`:3`) tags.
- Check top-level `image:` and every per-job `image:` — both are scanned.

## GL-002 — Script injection via untrusted commit/MR context
**Severity:** HIGH · CICD-SEC-4 Poisoned Pipeline Execution

GitLab interpolates predefined CI variables *before* shell quoting —
meaning `echo $CI_COMMIT_MESSAGE` is shell injection if any contributor
can craft a commit message with backticks or `$()`. Attacker-controllable
variables flagged: `CI_COMMIT_MESSAGE`, `CI_COMMIT_DESCRIPTION`,
`CI_COMMIT_TITLE`, `CI_COMMIT_REF_NAME`, `CI_COMMIT_BRANCH`,
`CI_COMMIT_TAG`, `CI_COMMIT_AUTHOR`, `CI_MERGE_REQUEST_TITLE`,
`CI_MERGE_REQUEST_DESCRIPTION`, `CI_MERGE_REQUEST_SOURCE_BRANCH_NAME`.

**Recommended actions**
- Read these into intermediate `variables:` entries or shell variables
  and quote them (`"$BRANCH"`) when used.
- Never inline `$CI_COMMIT_MESSAGE` / `$CI_MERGE_REQUEST_TITLE` into a
  command. Quoted assignment (`TITLE="$CI_MERGE_REQUEST_TITLE"`) is
  exempt — the variable is captured but not executed.

## GL-003 — Variables contain literal secret values
**Severity:** CRITICAL if an AWS access key pattern is found, else HIGH
·  CICD-SEC-6 Insufficient Credential Hygiene

Scans top-level and per-job `variables:` for literal credentials. Flags
AWS access keys (`AKIA…`) and string values assigned to keys named
`password`, `secret`, `token`, `api_key`, `apikey`, `private_key`, etc.

**Recommended actions**
- Store credentials as **protected + masked** CI/CD variables under the
  project or group settings, referenced by name from the YAML.
- For cloud access prefer short-lived OIDC tokens
  (`id_tokens:` with `aud:` + `role_arn:`).

## GL-004 — Deploy job lacks manual approval or environment gate
**Severity:** MEDIUM · CICD-SEC-1 Insufficient Flow Control

A job whose stage or name matches `deploy / release / publish / promote`
is flagged unless it has `when: manual`, a matching `rules: when:
manual`, or an `environment:` binding. Auto-deploy on push is rarely
desired for prod.

**Recommended actions**
- Add `when: manual` or `rules:` guarding the deploy to a protected
  branch.
- Bind the job to `environment: { name: production }` so GitLab enforces
  approvals and surfaces deployment history.

## GL-005 — `include:` pulls remote / project without pinned ref
**Severity:** HIGH · CICD-SEC-3 Dependency Chain Abuse

Supply-chain integrity of shared pipeline fragments:
- `include: project:` without `ref:` — latest commit of the default
  branch runs in your pipeline.
- `include: project: … ref: main` — floating branch, same problem.
- `include: remote: 'https://…'` — cannot be cryptographically pinned
  over HTTP(S); flagged unconditionally.
- `include: local: …` and shorthand string locals are always safe.

**Recommended actions**
- Pin `include: project:` entries with `ref:` set to a tag or commit SHA.
- Mirror any `remote:` content into a trusted project and pin it.

---

## Adding a new GitLab CI check

1. Add a method to `pipeline_check/core/checks/gitlab/pipelines.py`
   returning a `Finding` with ID `GL-<NNN>`; register the call in
   `_check_pipeline`.
2. Add mappings for the new ID in the relevant standards under
   `pipeline_check/core/standards/data/*.py`.
3. Add tests under `tests/gitlab/test_pipelines.py` plus an insecure /
   secure fixture pair under `tests/fixtures/workflows/gitlab/` and an
   expected-ID entry in `tests/test_workflow_fixtures.py`.
