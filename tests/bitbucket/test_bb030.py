"""Per-rule tests for BB-030 (npm install without `npm audit signatures`)."""
from __future__ import annotations

from .conftest import run_check


class TestBB030NpmAuditSignatures:
    def test_fails_when_npm_ci_without_audit_signatures(self):
        cfg = """
        pipelines:
          default:
            - step:
                image: node:20
                script:
                  - npm ci
                  - npm run build
        """
        f = run_check(cfg, "BB-030")
        assert not f.passed

    def test_fails_when_pnpm_install_without_audit_signatures(self):
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - pnpm install
        """
        f = run_check(cfg, "BB-030")
        assert not f.passed

    def test_passes_when_npm_audit_signatures_runs(self):
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - npm ci
                  - npm audit signatures
        """
        f = run_check(cfg, "BB-030")
        assert f.passed

    def test_passes_silently_with_no_install(self):
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - pre-commit run --all-files
        """
        f = run_check(cfg, "BB-030")
        assert f.passed

    def test_passes_silently_on_yarn_only(self):
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - yarn install
                  - yarn build
        """
        f = run_check(cfg, "BB-030")
        assert f.passed

    def test_passes_when_audit_signatures_in_separate_step(self):
        cfg = """
        pipelines:
          default:
            - step:
                name: install
                script:
                  - npm ci
            - step:
                name: verify
                script:
                  - npm audit signatures
        """
        f = run_check(cfg, "BB-030")
        assert f.passed

    def test_does_not_match_npm_pack(self):
        cfg = """
        pipelines:
          default:
            - step:
                script:
                  - npm pack
                  - npm test
        """
        f = run_check(cfg, "BB-030")
        assert f.passed
