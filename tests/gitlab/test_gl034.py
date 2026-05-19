"""Per-rule tests for GL-034 (npm install without `npm audit signatures`)."""
from __future__ import annotations

from .conftest import run_check


class TestGL034NpmAuditSignatures:
    def test_fails_when_npm_ci_without_audit_signatures(self):
        cfg = """
        build:
          stage: build
          image: node:20
          script:
            - npm ci
            - npm run build
        """
        f = run_check(cfg, "GL-034")
        assert not f.passed
        assert "audit signatures" in f.description.lower() or "signature" in f.description.lower()

    def test_fails_when_pnpm_install_without_audit_signatures(self):
        cfg = """
        build:
          stage: build
          script:
            - pnpm install
        """
        f = run_check(cfg, "GL-034")
        assert not f.passed

    def test_passes_when_npm_ci_followed_by_audit_signatures(self):
        cfg = """
        build:
          stage: build
          script:
            - npm ci
            - npm audit signatures
            - npm run build
        """
        f = run_check(cfg, "GL-034")
        assert f.passed

    def test_passes_when_audit_signatures_runs_in_separate_job(self):
        cfg = """
        install:
          stage: build
          script:
            - npm ci

        verify:
          stage: test
          needs: [install]
          script:
            - npm audit signatures
        """
        f = run_check(cfg, "GL-034")
        assert f.passed

    def test_passes_silently_with_no_install(self):
        cfg = """
        lint:
          stage: test
          script:
            - pre-commit run --all-files
        """
        f = run_check(cfg, "GL-034")
        assert f.passed

    def test_passes_silently_on_yarn_only_pipeline(self):
        cfg = """
        build:
          stage: build
          script:
            - yarn install
            - yarn build
        """
        f = run_check(cfg, "GL-034")
        assert f.passed

    def test_recognizes_top_level_before_script_install(self):
        cfg = """
        before_script:
          - npm ci

        build:
          stage: build
          script:
            - npm run build
        """
        f = run_check(cfg, "GL-034")
        assert not f.passed

    def test_recognizes_top_level_before_script_audit_signatures(self):
        # Verification in the document-level before_script counts
        # for every job that doesn't override it.
        cfg = """
        before_script:
          - npm ci
          - npm audit signatures

        build:
          stage: build
          script:
            - npm run build
        """
        f = run_check(cfg, "GL-034")
        assert f.passed

    def test_does_not_match_npm_pack(self):
        cfg = """
        build:
          stage: build
          script:
            - npm pack
            - npm test
        """
        f = run_check(cfg, "GL-034")
        assert f.passed
