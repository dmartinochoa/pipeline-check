# Configuration file

Every CLI flag can be set in a config file so CI invocations stay short
and repo policy lives alongside the code. Both TOML (inside
`pyproject.toml`) and YAML (`.pipeline-check.yml`) are supported.

## Precedence

Highest wins — matches every standard tool (ruff, mypy, pytest):

1. **CLI flags** — `--pipeline aws --fail-on HIGH`
2. **Environment variables** — `PIPELINE_CHECK_PIPELINE=aws`, `PIPELINE_CHECK_GATE_FAIL_ON=HIGH`
3. **Config file** — `.pipeline-check.yml` or `[tool.pipeline_check]` in `pyproject.toml`
4. **Built-in defaults**

## File discovery

Without `--config`, the first file that exists wins:

1. `.pipeline-check.yml` / `.pipeline-check.yaml` at the current working directory
2. `pyproject.toml` at the cwd, `[tool.pipeline_check]` table

Pass `--config PATH` to select an explicit file (a missing path raises
a UsageError — no silent fallback).

## Schema

Every CLI flag maps to a key with `-` → `_`. Gate settings live under a
nested `gate` sub-section.

### `pyproject.toml`

```toml
[tool.pipeline_check]
pipeline = "aws"
region = "eu-west-1"
profile = "prod"
standards = ["owasp_cicd_top_10", "nist_ssdf"]
severity_threshold = "MEDIUM"
output = "sarif"
output_file = "pipeline-check.sarif"

# Provider-specific paths (auto-detected if omitted and a canonical
# file exists at cwd).
gha_path = ".github/workflows"
gitlab_path = ".gitlab-ci.yml"
bitbucket_path = "bitbucket-pipelines.yml"
tf_plan = "plan.json"

# Extra credential patterns for the secret-scanning checks
# (GHA-008, GL-008, BB-008, ADO-008). Python regex syntax; anchor
# with ^...$ for whole-token matches.
secret_patterns = [
    '^acme_[a-f0-9]{32}$',     # internal service token
    '^xoxo-[A-Z0-9]{20,}$',    # vendor-specific API key
]

[tool.pipeline_check.gate]
fail_on = "HIGH"
min_grade = "B"
max_failures = 10
fail_on_checks = ["GHA-002", "CB-002"]
baseline = "artifacts/baseline.json"
ignore_file = ".pipelinecheckignore"
```

### `.pipeline-check.yml`

Same keys, YAML shape:

```yaml
pipeline: aws
region: eu-west-1
standards:
  - owasp_cicd_top_10
  - nist_ssdf
severity_threshold: MEDIUM

secret_patterns:
  - '^acme_[a-f0-9]{32}$'
  - '^xoxo-[A-Z0-9]{20,}$'

gate:
  fail_on: HIGH
  min_grade: B
  max_failures: 10
  fail_on_checks:
    - GHA-002
    - CB-002
  baseline: artifacts/baseline.json
  ignore_file: .pipelinecheckignore
```

## Environment variables

Upper-snake-case of the option name, prefixed with `PIPELINE_CHECK_`.
Gate settings use the `PIPELINE_CHECK_GATE_` prefix.

```bash
export PIPELINE_CHECK_PIPELINE=aws
export PIPELINE_CHECK_SEVERITY_THRESHOLD=HIGH
export PIPELINE_CHECK_STANDARDS=owasp_cicd_top_10,nist_ssdf
export PIPELINE_CHECK_GATE_FAIL_ON=HIGH
export PIPELINE_CHECK_GATE_MAX_FAILURES=5
```

Multi-value flags (`standards`, `checks`, `fail_on_checks`,
`secret_patterns`) are comma-separated in env vars.

Env vars override config-file values for the same key — useful in CI
where the file encodes repo policy but a specific job (e.g. a nightly
deep scan) needs to tighten a single setting.

## Unknown keys

Unknown top-level or gate keys are **ignored with a stderr warning**
rather than raising:

```
[config] ignoring 'max_faillures' from pyproject.toml: unknown key
```

Typos still surface, but a config written for a newer version keeps
working on an older install.

## Tips

- Keep `pyproject.toml` as the single source of truth for Python projects;
  it's already the standard place to find `[tool.ruff]` / `[tool.mypy]`.
- Use `.pipeline-check.yml` for non-Python repos (scanning a `.gitlab-ci.yml`
  from inside a Go or TypeScript project, for instance).
- Commit the file — it encodes team policy; diffs to it are diffs to your
  security posture.
- Use env vars sparingly: they make CI logs harder to reproduce locally.
  Reserve them for secrets (`--profile`) and per-job overrides.
