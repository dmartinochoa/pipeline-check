"""Per-rule tests for the Azure DevOps supply-chain rules:
ADO-006 (signing), ADO-007 (SBOM), ADO-008 (literal secrets,
full text scan), ADO-016 (curl-pipe), ADO-017 (docker insecure
flags), ADO-018 (insecure package source), ADO-021 (lockfile
enforcement), ADO-022 (dependency-update commands),
ADO-023 (TLS bypass).

Mirrors the GHA / GL / CC / BB / JF supply-chain matrix for the
Azure provider so cross-provider primitives stay in sync.
"""
from __future__ import annotations

from .conftest import run_check

# ── ADO-006 signing ─────────────────────────────────────────────────


class TestADO006Signing:
    def test_fails_when_artifacts_produced_without_signing(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: docker build -t registry.example.com/app:v1 .
          - script: docker push registry.example.com/app:v1
        """
        f = run_check(cfg, "ADO-006")
        assert not f.passed

    def test_passes_with_cosign_signing(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: docker build -t registry.example.com/app:v1 .
          - script: cosign sign --yes registry.example.com/app@sha256:abc
          - script: docker push registry.example.com/app:v1
        """
        f = run_check(cfg, "ADO-006")
        assert f.passed


# ── ADO-007 SBOM ────────────────────────────────────────────────────


class TestADO007SBOM:
    def test_fails_when_artifacts_produced_without_sbom(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: docker build -t registry.example.com/app:v1 .
          - script: docker push registry.example.com/app:v1
        """
        f = run_check(cfg, "ADO-007")
        assert not f.passed

    def test_passes_with_syft_sbom(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: docker build -t registry.example.com/app:v1 .
          - script: syft registry.example.com/app:v1 -o cyclonedx-json > sbom.json
          - script: docker push registry.example.com/app:v1
        """
        f = run_check(cfg, "ADO-007")
        assert f.passed


# ── ADO-008 literal secrets (full text scan) ────────────────────────


class TestADO008LiteralSecrets:
    def test_fails_on_aws_access_key_in_variables(self):
        cfg = """
        variables:
          AWS_ACCESS_KEY_ID: AKIAZ3MHALF2TESTHIJK
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: aws s3 ls
        """
        f = run_check(cfg, "ADO-008")
        assert not f.passed

    def test_passes_when_secrets_resolved_via_macro(self):
        cfg = """
        variables:
          - group: aws-prod
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: aws s3 ls
        """
        f = run_check(cfg, "ADO-008")
        assert f.passed


# ── ADO-016 curl-pipe ───────────────────────────────────────────────


class TestADO016CurlPipe:
    def test_fails_on_curl_piped_to_bash(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: curl -fsSL https://example.com/install.sh | bash
        """
        f = run_check(cfg, "ADO-016")
        assert not f.passed

    def test_passes_with_checksum_verified_install(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: |
              curl -fsSL https://example.com/install.sh -o install.sh
              sha256sum -c install.sh.sha256
              bash install.sh
        """
        f = run_check(cfg, "ADO-016")
        assert f.passed


# ── ADO-017 docker insecure flags ───────────────────────────────────


class TestADO017DockerInsecure:
    def test_fails_on_privileged_flag(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: docker run --privileged builder make all
        """
        f = run_check(cfg, "ADO-017")
        assert not f.passed

    def test_passes_with_minimal_flags(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: docker run --rm -v /tmp:/work builder make all
        """
        f = run_check(cfg, "ADO-017")
        assert f.passed


# ── ADO-018 insecure package source ─────────────────────────────────


class TestADO018PackageInsecure:
    def test_fails_on_pip_index_url_http(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: pip install --index-url http://example.com/simple/ requests
        """
        f = run_check(cfg, "ADO-018")
        assert not f.passed

    def test_passes_with_default_https_sources(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: pip install --require-hashes -r requirements.txt
        """
        f = run_check(cfg, "ADO-018")
        assert f.passed


# ── ADO-021 lockfile enforcement ────────────────────────────────────


class TestADO021Lockfile:
    def test_fails_on_npm_install(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: npm install
        """
        f = run_check(cfg, "ADO-021")
        assert not f.passed

    def test_passes_on_npm_ci(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: npm ci
        """
        f = run_check(cfg, "ADO-021")
        assert f.passed


# ── ADO-022 dependency-update commands ──────────────────────────────


class TestADO022DepUpdate:
    def test_fails_on_npm_update(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: npm update
        """
        f = run_check(cfg, "ADO-022")
        assert not f.passed

    def test_passes_when_no_update_command(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: pip install --require-hashes -r requirements.txt
        """
        f = run_check(cfg, "ADO-022")
        assert f.passed


# ── ADO-023 TLS bypass ──────────────────────────────────────────────


class TestADO023TLSBypass:
    def test_fails_on_curl_insecure_flag(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: curl -k https://internal.example.com/secret
        """
        f = run_check(cfg, "ADO-023")
        assert not f.passed

    def test_fails_on_npm_strict_ssl_false(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: npm config set strict-ssl false
        """
        f = run_check(cfg, "ADO-023")
        assert not f.passed

    def test_passes_when_no_tls_bypass(self):
        cfg = """
        pool: {vmImage: ubuntu-latest}
        steps:
          - script: curl -fsSL https://example.com/data
        """
        f = run_check(cfg, "ADO-023")
        assert f.passed
