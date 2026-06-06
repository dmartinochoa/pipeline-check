"""Tests for GL-043 (GitLab native security scanner disabled)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


class TestGL043SecurityScannerDisabled:
    def test_metadata(self):
        f = run_check("build:\n  script: [make]\n", "GL-043")
        assert f.check_id == "GL-043"
        assert f.severity == Severity.MEDIUM

    def test_fails_on_secret_detection_disabled(self):
        cfg = """
        variables:
          SECRET_DETECTION_DISABLED: "true"
        build:
          script: [make]
        """
        f = run_check(cfg, "GL-043")
        assert not f.passed
        assert "Secret Detection" in f.description

    def test_fails_on_multiple_scanners_disabled(self):
        cfg = """
        variables:
          SAST_DISABLED: "1"
          DEPENDENCY_SCANNING_DISABLED: "true"
        build:
          script: [make]
        """
        f = run_check(cfg, "GL-043")
        assert not f.passed

    def test_fails_on_typed_variable_form(self):
        cfg = """
        variables:
          DAST_DISABLED:
            value: "true"
            description: turn off DAST
        build:
          script: [make]
        """
        f = run_check(cfg, "GL-043")
        assert not f.passed

    def test_fails_on_job_level_disable(self):
        cfg = """
        scan:
          variables:
            CONTAINER_SCANNING_DISABLED: "yes"
          script: [scan]
        """
        f = run_check(cfg, "GL-043")
        assert not f.passed

    def test_passes_when_not_disabled(self):
        cfg = """
        variables:
          SAST_DISABLED: "false"
          SAST_EXCLUDED_PATHS: "spec, test"
        build:
          script: [make]
        """
        f = run_check(cfg, "GL-043")
        assert f.passed
