"""Per-rule tests for every BK-* check."""
from __future__ import annotations

from .conftest import run_check

# ── BK-001 plugin pinning ──────────────────────────────────────────────


class TestBK001PluginPinning:
    def test_passes_with_exact_semver_plugin(self):
        cfg = """
        steps:
          - command: build
            plugins:
              - docker-compose#v4.13.0:
                  run: app
        """
        f = run_check(cfg, "BK-001")
        assert f.passed

    def test_fails_with_branch_pin(self):
        cfg = """
        steps:
          - command: build
            plugins:
              - docker-compose#main:
                  run: app
        """
        f = run_check(cfg, "BK-001")
        assert not f.passed
        assert "main" in f.description

    def test_fails_with_bare_reference(self):
        cfg = """
        steps:
          - command: build
            plugins:
              - docker-login
        """
        f = run_check(cfg, "BK-001")
        assert not f.passed

    def test_fails_with_partial_semver(self):
        cfg = """
        steps:
          - command: build
            plugins:
              - docker-compose#v4
        """
        f = run_check(cfg, "BK-001")
        assert not f.passed


# ── BK-002 literal secrets ─────────────────────────────────────────────


class TestBK002LiteralSecrets:
    def test_passes_with_no_secret_keys(self):
        cfg = """
        env:
          AWS_REGION: us-east-1
        steps:
          - command: build
        """
        f = run_check(cfg, "BK-002")
        assert f.passed

    def test_fails_with_aws_access_key_pattern(self):
        cfg = """
        env:
          AWS_ACCESS_KEY_ID: "AKIAIOSFODNN7EXAMPLE"
        steps:
          - command: build
        """
        f = run_check(cfg, "BK-002")
        assert not f.passed

    def test_fails_with_secret_named_key_and_long_literal(self):
        cfg = """
        env:
          DEPLOY_API_KEY: "supersecret-prod-key-please-rotate-me"
        steps:
          - command: build
        """
        f = run_check(cfg, "BK-002")
        assert not f.passed

    def test_passes_when_value_is_an_interpolation(self):
        cfg = """
        env:
          DEPLOY_API_KEY: "$VAULT_KEY"
        steps:
          - command: build
        """
        f = run_check(cfg, "BK-002")
        assert f.passed


# ── BK-003 untrusted interpolation ─────────────────────────────────────


class TestBK003UntrustedInterpolation:
    def test_fails_with_unquoted_branch(self):
        cfg = """
        steps:
          - command: echo Building branch $BUILDKITE_BRANCH
        """
        f = run_check(cfg, "BK-003")
        assert not f.passed
        assert "BUILDKITE_BRANCH" in f.description

    def test_passes_with_quoted_branch(self):
        cfg = """
        steps:
          - command: |
              branch="$BUILDKITE_BRANCH"
              ./run --branch "$branch"
        """
        f = run_check(cfg, "BK-003")
        assert f.passed

    def test_fails_with_pull_request_message(self):
        cfg = """
        steps:
          - command: echo $BUILDKITE_MESSAGE > /tmp/m
        """
        f = run_check(cfg, "BK-003")
        assert not f.passed


# ── BK-004 curl-pipe ───────────────────────────────────────────────────


class TestBK004CurlPipe:
    def test_fails_with_curl_pipe_bash(self):
        cfg = """
        steps:
          - command: curl https://example.com/install.sh | bash
        """
        f = run_check(cfg, "BK-004")
        assert not f.passed

    def test_passes_with_download_then_execute(self):
        cfg = """
        steps:
          - command: |
              curl -fsSLO https://example.com/install.sh
              sha256sum -c install.sh.sha256
              bash install.sh
        """
        f = run_check(cfg, "BK-004")
        assert f.passed


# ── BK-005 docker --privileged ─────────────────────────────────────────


class TestBK005DockerPrivileged:
    def test_fails_with_privileged_flag(self):
        cfg = """
        steps:
          - command: docker run --privileged myorg/app:latest npm test
        """
        f = run_check(cfg, "BK-005")
        assert not f.passed

    def test_passes_with_normal_run(self):
        cfg = """
        steps:
          - command: docker run myorg/app:latest npm test
        """
        f = run_check(cfg, "BK-005")
        assert f.passed


# ── BK-006 timeout_in_minutes ──────────────────────────────────────────


class TestBK006Timeout:
    def test_passes_with_timeout(self):
        cfg = """
        steps:
          - command: make build
            timeout_in_minutes: 30
        """
        f = run_check(cfg, "BK-006")
        assert f.passed

    def test_fails_when_timeout_missing(self):
        cfg = """
        steps:
          - command: make build
        """
        f = run_check(cfg, "BK-006")
        assert not f.passed

    def test_passes_when_step_has_no_command(self):
        # Plugin-only or block/input steps with no command should not
        # trigger this rule.
        cfg = """
        steps:
          - block: "ok?"
        """
        f = run_check(cfg, "BK-006")
        assert f.passed


# ── BK-007 deploy gating ───────────────────────────────────────────────


class TestBK007DeployBlock:
    def test_passes_with_block_before_deploy(self):
        cfg = """
        steps:
          - command: build
            timeout_in_minutes: 10
          - block: "Deploy?"
          - label: deploy
            command: kubectl apply -f deploy/
            timeout_in_minutes: 5
        """
        f = run_check(cfg, "BK-007")
        assert f.passed

    def test_fails_when_deploy_step_lacks_block(self):
        cfg = """
        steps:
          - command: build
            timeout_in_minutes: 10
          - label: deploy production
            command: kubectl apply -f deploy/
            timeout_in_minutes: 5
        """
        f = run_check(cfg, "BK-007")
        assert not f.passed

    def test_passes_when_no_deploy_step_present(self):
        cfg = """
        steps:
          - command: make test
            timeout_in_minutes: 10
        """
        f = run_check(cfg, "BK-007")
        assert f.passed


# ── BK-008 TLS bypass ──────────────────────────────────────────────────


class TestBK008TlsBypass:
    def test_fails_with_curl_insecure(self):
        cfg = """
        steps:
          - command: curl -k https://internal/api
        """
        f = run_check(cfg, "BK-008")
        assert not f.passed

    def test_fails_with_curl_insecure_long_form(self):
        cfg = """
        steps:
          - command: curl --insecure https://internal/api
        """
        f = run_check(cfg, "BK-008")
        assert not f.passed

    def test_passes_without_bypass_flags(self):
        cfg = """
        steps:
          - command: curl https://example.com
        """
        f = run_check(cfg, "BK-008")
        assert f.passed


# ── BK-009 signing ─────────────────────────────────────────────────────


class TestBK009Signing:
    def test_passes_with_cosign_step(self):
        cfg = """
        steps:
          - command: |
              docker build -t app:${BUILDKITE_COMMIT} .
              cosign sign --yes app:${BUILDKITE_COMMIT}
        """
        f = run_check(cfg, "BK-009")
        assert f.passed

    def test_fails_when_artifact_built_without_signing(self):
        cfg = """
        steps:
          - command: docker build -t app:${BUILDKITE_COMMIT} .
        """
        f = run_check(cfg, "BK-009")
        assert not f.passed

    def test_passes_when_no_artifacts_produced(self):
        cfg = """
        steps:
          - command: pytest tests/
        """
        f = run_check(cfg, "BK-009")
        assert f.passed


# ── BK-010 SBOM ────────────────────────────────────────────────────────


class TestBK010SBOM:
    def test_passes_with_syft_step(self):
        cfg = """
        steps:
          - command: |
              docker build -t app:${BUILDKITE_COMMIT} .
              syft app:${BUILDKITE_COMMIT} -o cyclonedx-json > sbom.json
        """
        f = run_check(cfg, "BK-010")
        assert f.passed

    def test_fails_when_artifact_built_without_sbom(self):
        cfg = """
        steps:
          - command: docker build -t app:${BUILDKITE_COMMIT} .
        """
        f = run_check(cfg, "BK-010")
        assert not f.passed

    def test_passes_when_no_artifacts_produced(self):
        cfg = """
        steps:
          - command: pytest tests/
        """
        f = run_check(cfg, "BK-010")
        assert f.passed


# ── BK-011 SLSA provenance ─────────────────────────────────────────────


class TestBK011SLSAProvenance:
    def test_passes_with_cosign_attest(self):
        cfg = """
        steps:
          - command: |
              docker build -t app:${BUILDKITE_COMMIT} .
              cosign attest --predicate provenance.json --type slsaprovenance app:${BUILDKITE_COMMIT}
        """
        f = run_check(cfg, "BK-011")
        assert f.passed

    def test_fails_when_artifact_built_without_provenance(self):
        cfg = """
        steps:
          - command: docker build -t app:${BUILDKITE_COMMIT} .
        """
        f = run_check(cfg, "BK-011")
        assert not f.passed

    def test_passes_when_no_artifacts_produced(self):
        cfg = """
        steps:
          - command: pytest tests/
        """
        f = run_check(cfg, "BK-011")
        assert f.passed


# ── BK-012 vuln scanning ───────────────────────────────────────────────


class TestBK012VulnScanning:
    def test_passes_with_trivy_step(self):
        cfg = """
        steps:
          - command: |
              trivy fs --severity HIGH,CRITICAL --exit-code 1 .
        """
        f = run_check(cfg, "BK-012")
        assert f.passed

    def test_passes_with_grype_step(self):
        cfg = """
        steps:
          - command: grype dir:.
        """
        f = run_check(cfg, "BK-012")
        assert f.passed

    def test_passes_with_npm_audit(self):
        cfg = """
        steps:
          - command: npm audit --audit-level=high
        """
        f = run_check(cfg, "BK-012")
        assert f.passed

    def test_fails_when_no_scanner_invoked(self):
        cfg = """
        steps:
          - command: |
              docker build -t app .
              cosign sign app
        """
        f = run_check(cfg, "BK-012")
        assert not f.passed


# ── BK-013 deploy branches: filter ─────────────────────────────────────


class TestBK013DeployBranchFilter:
    def test_passes_with_branches_on_deploy_step(self):
        cfg = """
        steps:
          - command: build
          - block: "Deploy?"
          - label: deploy
            branches: "main release/*"
            command: kubectl apply -f deploy/
        """
        f = run_check(cfg, "BK-013")
        assert f.passed

    def test_passes_with_pipeline_level_branches_default(self):
        # Pipeline-level branches: applies to every step.
        cfg = """
        branches: "main"
        steps:
          - command: build
          - label: deploy
            command: kubectl apply -f deploy/
        """
        f = run_check(cfg, "BK-013")
        assert f.passed

    def test_fails_when_deploy_step_has_no_branches(self):
        cfg = """
        steps:
          - command: build
          - label: deploy production
            command: kubectl apply -f deploy/
        """
        f = run_check(cfg, "BK-013")
        assert not f.passed

    def test_fails_when_branches_is_wildcard_only(self):
        cfg = """
        steps:
          - label: deploy
            branches: "*"
            command: kubectl apply -f deploy/
        """
        f = run_check(cfg, "BK-013")
        assert not f.passed

    def test_passes_when_branches_list_with_real_entries(self):
        cfg = """
        steps:
          - label: deploy
            branches: ["main", "release/*"]
            command: kubectl apply -f deploy/
        """
        f = run_check(cfg, "BK-013")
        assert f.passed

    def test_passes_when_no_deploy_step_present(self):
        cfg = """
        steps:
          - command: pytest tests/
        """
        f = run_check(cfg, "BK-013")
        assert f.passed
