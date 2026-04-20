"""Starter ``.pipeline-check.yml`` template used by ``pipeline_check init``.

Keep the keys in sync with ``pipeline_check.core.config._TOPLEVEL_KEYS``
and ``_GATE_KEYS`` — every key shown here is also a legal config-file
key. Values are commented out so the generated file is a no-op until
the user edits it.
"""
from __future__ import annotations


def render(detected_pipeline: str | None = None) -> str:
    """Return the YAML scaffold, pre-filling ``pipeline:`` when known."""
    pipeline_line = (
        f"pipeline: {detected_pipeline}"
        if detected_pipeline
        else (
            "# pipeline: github    # aws | github | gitlab | bitbucket | azure"
            " | jenkins | circleci | cloudbuild | cloudformation | terraform"
        )
    )
    return f"""# .pipeline-check.yml — configuration for pipeline_check
# Keys mirror CLI flags (hyphens -> underscores). Env vars
# PIPELINE_CHECK_* override this file; CLI flags override both.
# Run `pipeline_check --config-check` to validate after editing.

{pipeline_line}

# ── Filtering ──────────────────────────────────────────────────────────────
# checks:                    # run only these check IDs
#   - GHA-001
#   - CB-003
# severity_threshold: INFO   # CRITICAL | HIGH | MEDIUM | LOW | INFO
# secret_patterns:           # extra regexes for secret scanning
#   - "^sk_live_[A-Za-z0-9]{{24,}}$"

# ── Output ─────────────────────────────────────────────────────────────────
# output: terminal           # terminal | json | html | sarif | junit | markdown | both
# output_file: report.json
# standards:                 # annotate findings with these standards
#   - owasp_cicd_top_10

# ── Provider path hints (only used by their matching pipeline) ────────────
# tf_plan: plan.json
# gha_path: .github/workflows
# gitlab_path: .gitlab-ci.yml
# bitbucket_path: bitbucket-pipelines.yml
# azure_path: azure-pipelines.yml
# circleci_path: .circleci/config.yml

# ── CI gate ────────────────────────────────────────────────────────────────
gate:
  # fail_on: HIGH             # fail if any finding is >= this severity
  # min_grade: B              # fail if overall grade is worse than this
  # max_failures: 5           # fail when more than N findings fail
  # fail_on_checks:           # always fail when these check IDs fail
  #   - IAM-001
  # baseline: baseline.json
  # ignore_file: .pipelinecheckignore
"""
