"""Tests for GHA-100: cosign verify without certificate identity binding."""
from __future__ import annotations

from .conftest import run_check


class TestGHA100:
    def test_fires_on_bare_cosign_verify(self) -> None:
        wf = """
        name: verify
        on: push
        jobs:
          verify:
            runs-on: ubuntu-latest
            steps:
              - run: cosign verify ghcr.io/org/app:latest
        """
        f = run_check(wf, "GHA-100")
        assert not f.passed
        assert "certificate" in f.description.lower() or "identity" in f.description.lower()

    def test_fires_on_verify_blob(self) -> None:
        wf = """
        name: verify
        on: push
        jobs:
          verify:
            runs-on: ubuntu-latest
            steps:
              - run: cosign verify-blob artifact.tar.gz --signature sig.b64
        """
        f = run_check(wf, "GHA-100")
        assert not f.passed

    def test_fires_on_verify_attestation(self) -> None:
        wf = """
        name: verify
        on: push
        jobs:
          verify:
            runs-on: ubuntu-latest
            steps:
              - run: cosign verify-attestation ghcr.io/org/app@sha256:abc123
        """
        f = run_check(wf, "GHA-100")
        assert not f.passed

    def test_fires_missing_oidc_issuer_only(self) -> None:
        wf = """
        name: verify
        on: push
        jobs:
          verify:
            runs-on: ubuntu-latest
            steps:
              - run: cosign verify --certificate-identity 'https://github.com/org/app' ghcr.io/org/app:latest
        """
        f = run_check(wf, "GHA-100")
        assert not f.passed
        assert "issuer" in f.description.lower()

    def test_fires_missing_identity_only(self) -> None:
        wf = """
        name: verify
        on: push
        jobs:
          verify:
            runs-on: ubuntu-latest
            steps:
              - run: cosign verify --certificate-oidc-issuer https://token.actions.githubusercontent.com ghcr.io/org/app:latest
        """
        f = run_check(wf, "GHA-100")
        assert not f.passed
        assert "identity" in f.description.lower()

    def test_passes_with_both_flags(self) -> None:
        wf = """
        name: verify
        on: push
        jobs:
          verify:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  cosign verify ghcr.io/org/app:latest \\
                    --certificate-identity-regexp 'https://github.com/org/app/.*' \\
                    --certificate-oidc-issuer https://token.actions.githubusercontent.com
        """
        f = run_check(wf, "GHA-100")
        assert f.passed

    def test_passes_with_key_based_verify(self) -> None:
        wf = """
        name: verify
        on: push
        jobs:
          verify:
            runs-on: ubuntu-latest
            steps:
              - run: cosign verify --key cosign.pub ghcr.io/org/app:latest
        """
        f = run_check(wf, "GHA-100")
        assert f.passed

    def test_passes_when_no_cosign(self) -> None:
        wf = """
        name: ci
        on: push
        jobs:
          test:
            runs-on: ubuntu-latest
            steps:
              - run: make test
        """
        f = run_check(wf, "GHA-100")
        assert f.passed

    def test_handles_multiline_run_block(self) -> None:
        wf = """
        name: verify
        on: push
        jobs:
          verify:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  cosign verify \\
                    ghcr.io/org/app:latest
        """
        f = run_check(wf, "GHA-100")
        assert not f.passed

    def test_regexp_variants_accepted(self) -> None:
        wf = """
        name: verify
        on: push
        jobs:
          verify:
            runs-on: ubuntu-latest
            steps:
              - run: |
                  cosign verify ghcr.io/org/app:latest \\
                    --certificate-identity-regexp 'https://github\\.com/org/.*' \\
                    --certificate-oidc-issuer-regexp 'https://token\\.actions\\..*'
        """
        f = run_check(wf, "GHA-100")
        assert f.passed
