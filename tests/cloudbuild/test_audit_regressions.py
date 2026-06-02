"""Regression tests from the rule audit (batch 4 - false positives)."""
from __future__ import annotations

from .conftest import run_check

# ── GCB-004 env-remediation false positive ────────────────────────────────


class TestGCB004DynamicSubstitutionsEnvRemediation:
    """The documented env: remediation must clear the finding; args must fire."""

    # --- FP case: user sub in env: only (the recommended safe pattern) ---

    def test_passes_user_sub_in_env_only(self):
        # dynamicSubstitutions is on but $_TAG only appears in env:, not in
        # args or entrypoint.  This is the remediation the rule recommends,
        # so it must not fire.
        f = run_check("""
        substitutions:
          _TAG: v1.0
        options:
          dynamicSubstitutions: true
        steps:
          - name: gcr.io/cloud-builders/docker@sha256:abc123
            entrypoint: bash
            env:
              - TAG=$_TAG
            args:
              - -c
              - docker build -t "image:$TAG" .
        """, "GCB-004")
        assert f.passed, f"Expected pass (env-only remediation), got: {f.description}"

    def test_passes_user_sub_in_secret_env_only(self):
        # secretEnv is also excluded from the scan; a pipeline that names a
        # user sub in secretEnv but not in args/entrypoint must not fire.
        f = run_check("""
        substitutions:
          _SECRET_NAME: my-secret
        options:
          dynamicSubstitutions: true
        steps:
          - name: gcr.io/cloud-builders/gcloud@sha256:abc123
            secretEnv:
              - SECRET_VAL=$_SECRET_NAME
            args:
              - -c
              - echo "running"
        """, "GCB-004")
        assert f.passed, f"Expected pass (secretEnv-only), got: {f.description}"

    # --- TP cases: user sub in args or entrypoint must still fire ---

    def test_fires_user_sub_in_args(self):
        # $_TAG directly in args is the canonical injection vector.
        f = run_check("""
        substitutions:
          _TAG: v1.0
        options:
          dynamicSubstitutions: true
        steps:
          - name: gcr.io/cloud-builders/docker@sha256:abc123
            args: [build, -t, "image:${_TAG}", .]
        """, "GCB-004")
        assert not f.passed, "Expected fail (user sub in args)"

    def test_fires_user_sub_in_entrypoint(self):
        # A user sub embedded in the entrypoint string is also a violation.
        f = run_check("""
        substitutions:
          _RUNNER: bash
        options:
          dynamicSubstitutions: true
        steps:
          - name: gcr.io/cloud-builders/gcloud@sha256:abc123
            entrypoint: $_RUNNER
            args: [-c, "echo hello"]
        """, "GCB-004")
        assert not f.passed, "Expected fail (user sub in entrypoint)"

    # --- Baseline: dynamicSubstitutions off must always pass ---

    def test_passes_when_dynamic_subs_disabled(self):
        # Without dynamicSubstitutions: true, bash re-evaluation does not
        # apply, so the rule must not fire regardless of where $_FOO appears.
        f = run_check("""
        substitutions:
          _TAG: v1.0
        steps:
          - name: gcr.io/cloud-builders/docker@sha256:abc123
            args: [build, -t, "image:${_TAG}", .]
        """, "GCB-004")
        assert f.passed, f"Expected pass (dynamicSubstitutions off), got: {f.description}"

    def test_passes_when_dynamic_subs_explicitly_false(self):
        f = run_check("""
        substitutions:
          _TAG: v1.0
        options:
          dynamicSubstitutions: false
        steps:
          - name: gcr.io/cloud-builders/docker@sha256:abc123
            args: [build, -t, "image:${_TAG}", .]
        """, "GCB-004")
        assert f.passed, f"Expected pass (dynamicSubstitutions: false), got: {f.description}"
