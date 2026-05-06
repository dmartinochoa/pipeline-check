"""Per-rule tests for Bitbucket Pipelines runner / injection rules:
BB-015 (vulnerability scanning),
BB-016 (self-hosted runner ephemeral marker),
BB-026 (dangerous shell idiom).

Pushes Bitbucket per-rule coverage past the 60% threshold.
"""
from __future__ import annotations

from .conftest import run_check

# ── BB-015 vulnerability scanning ───────────────────────────────────


class TestBB015VulnScanning:
    def test_fails_when_artifact_built_without_scan(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                image: docker:24-cli
                script:
                  - docker build -t registry.example.com/app:v1 .
                  - docker push registry.example.com/app:v1
        """
        f = run_check(cfg, "BB-015")
        assert not f.passed

    def test_passes_with_trivy_scan(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                image: docker:24-cli
                script:
                  - docker build -t registry.example.com/app:v1 .
                  - trivy image --severity HIGH,CRITICAL registry.example.com/app:v1
                  - docker push registry.example.com/app:v1
        """
        f = run_check(cfg, "BB-015")
        assert f.passed


# ── BB-016 self-hosted runner ephemeral marker ──────────────────────


class TestBB016SelfHostedRunner:
    def test_fails_when_self_hosted_lacks_ephemeral(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                runs-on: [self.hosted, linux]
                script:
                  - make
        """
        f = run_check(cfg, "BB-016")
        assert not f.passed

    def test_passes_with_ephemeral_label(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                runs-on: [self.hosted, linux, ephemeral]
                script:
                  - make
        """
        f = run_check(cfg, "BB-016")
        assert f.passed

    def test_passes_with_atlassian_hosted_runner(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                image: atlassian/default-image:4
                script:
                  - make
        """
        f = run_check(cfg, "BB-016")
        assert f.passed


# ── BB-026 dangerous shell idiom ────────────────────────────────────


class TestBB026ShellEval:
    def test_fails_on_eval_of_variable(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                script:
                  - eval "$BUILD_CMD"
        """
        f = run_check(cfg, "BB-026")
        assert not f.passed

    def test_fails_on_sh_dash_c_with_variable(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                script:
                  - sh -c "$USER_CMD"
        """
        f = run_check(cfg, "BB-026")
        assert not f.passed

    def test_passes_when_clean(self):
        cfg = """
        pipelines:
          default:
            - step:
                max-time: 30
                script:
                  - make test
        """
        f = run_check(cfg, "BB-026")
        assert f.passed
