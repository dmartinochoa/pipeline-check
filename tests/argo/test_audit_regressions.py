"""Regression tests from the rule audit (Argo batch 3 — example fixes)."""
from __future__ import annotations

from pipeline_check.core.checks.argo.rules import argo001_image_pinning as argo001
from pipeline_check.core.checks.argo.rules import (
    argo006_literal_secrets as argo006,
)

from .conftest import argo_ctx


class TestARGO001ImagePinning:
    def test_exploit_example_strong_check(self):
        # Safe fragment previously used ``@sha256:abc123...``, which is not a
        # valid 64-char lowercase-hex digest, so the check fired instead of
        # passing. Replaced with the full 64-char digest so the Safe fragment
        # actually passes.
        vuln, safe = argo001.RULE.exploit_example.split("\n\n", 1)
        assert argo001.check(argo_ctx(vuln)).passed is False
        assert argo001.check(argo_ctx(safe)).passed is True


class TestARGO006LiteralSecretsFP:
    """ARGO-006 false-positive regressions.

    Before the fix, _SECRET_KEY_RE matched KEY/TOKEN/SECRET anywhere inside
    an env var name, so CACHE_KEY and SSH_PRIVATE_KEY_PATH with a literal
    value >= 8 chars triggered the weak-match path incorrectly.
    """

    def test_cache_key_with_literal_value_passes(self):
        # CACHE_KEY is a build-cache lookup key, not a credential.
        # The value is a literal cache hash string — not a secret.
        ctx = argo_ctx("""
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          serviceAccountName: ci
          templates:
            - name: main
              container:
                image: alpine:3
                env:
                  - name: CACHE_KEY
                    value: "my-build-cache-v1-abcdef12"
        """)
        f = argo006.check(ctx)
        assert f.passed, (
            f"CACHE_KEY with a literal cache identifier should pass; got: {f.description}"
        )

    def test_ssh_private_key_path_with_path_value_passes(self):
        # SSH_PRIVATE_KEY_PATH carries a filesystem path, not a key material.
        ctx = argo_ctx("""
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          serviceAccountName: ci
          templates:
            - name: main
              container:
                image: alpine:3
                env:
                  - name: SSH_PRIVATE_KEY_PATH
                    value: "/home/runner/.ssh/id_rsa"
        """)
        f = argo006.check(ctx)
        assert f.passed, (
            f"SSH_PRIVATE_KEY_PATH with a path value should pass; got: {f.description}"
        )

    def test_ssh_private_key_path_with_literal_string_passes(self):
        # The _PATH suffix in the name is the key indicator; even a non-path
        # literal value should not fire because the name pattern is excluded.
        ctx = argo_ctx("""
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          serviceAccountName: ci
          templates:
            - name: main
              container:
                image: alpine:3
                env:
                  - name: SSH_PRIVATE_KEY_PATH
                    value: "some-reference-string-here"
        """)
        f = argo006.check(ctx)
        assert f.passed, (
            "SSH_PRIVATE_KEY_PATH name is excluded by the _PATH suffix rule; "
            f"got: {f.description}"
        )

    def test_s3_key_prefix_with_literal_passes(self):
        # S3_KEY_PREFIX describes a storage path prefix, not a secret.
        ctx = argo_ctx("""
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          serviceAccountName: ci
          templates:
            - name: main
              container:
                image: alpine:3
                env:
                  - name: S3_KEY_PREFIX
                    value: "artifacts/builds/main/"
        """)
        f = argo006.check(ctx)
        assert f.passed, (
            f"S3_KEY_PREFIX is not a credential name and should pass; got: {f.description}"
        )

    # ── True-positive guard: real secrets must still fire ─────────────────

    def test_api_key_with_literal_value_fires(self):
        # API_KEY with a short opaque literal value is a genuine secret.
        ctx = argo_ctx("""
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          serviceAccountName: ci
          templates:
            - name: main
              container:
                image: alpine:3
                env:
                  - name: API_KEY
                    value: "abcdef1234567890"
        """)
        f = argo006.check(ctx)
        assert not f.passed, (
            "API_KEY with a literal value must fire; got passed=True"
        )

    def test_aws_secret_access_key_fires(self):
        # AWS credentials must always be detected by the weak-match path.
        ctx = argo_ctx("""
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          serviceAccountName: ci
          templates:
            - name: main
              container:
                image: alpine:3
                env:
                  - name: AWS_SECRET_ACCESS_KEY
                    value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        """)
        f = argo006.check(ctx)
        assert not f.passed, (
            "AWS_SECRET_ACCESS_KEY with a literal value must fire; "
            f"got passed=True, description={f.description}"
        )

    def test_strong_pattern_aws_access_key_fires_regardless_of_name(self):
        # A strong-pattern match (AKIA... prefix) fires even for benign-looking
        # env var names because it matches the value directly.
        ctx = argo_ctx("""
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          serviceAccountName: ci
          templates:
            - name: main
              container:
                image: alpine:3
                env:
                  - name: CACHE_KEY
                    value: "AKIAZ3MHALF2TESTHIJK"
        """)
        f = argo006.check(ctx)
        assert not f.passed, (
            "An AKIA-pattern value must fire via the strong-match path even "
            "when the env var is named CACHE_KEY; got passed=True"
        )

    def test_my_token_with_literal_fires(self):
        ctx = argo_ctx("""
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          serviceAccountName: ci
          templates:
            - name: main
              container:
                image: alpine:3
                env:
                  - name: MY_TOKEN
                    value: "s3cr3tTokenValue!"
        """)
        f = argo006.check(ctx)
        assert not f.passed, (
            "MY_TOKEN with a literal value must fire; got passed=True"
        )

    def test_db_password_fires(self):
        ctx = argo_ctx("""
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          serviceAccountName: ci
          templates:
            - name: main
              container:
                image: alpine:3
                env:
                  - name: DB_PASSWORD
                    value: "hunter2hunter2"
        """)
        f = argo006.check(ctx)
        assert not f.passed, (
            "DB_PASSWORD with a literal value must fire; got passed=True"
        )
