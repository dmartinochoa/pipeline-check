"""Tests for JF-039 (model loaded with trust_remote_code)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


class TestJF039ModelTrustRemoteCode:
    def test_metadata(self):
        f = run_check(
            "pipeline { agent any\n stages { stage('b') { steps {\n"
            " sh 'make build' } } } }",
            "JF-039",
        )
        assert f.check_id == "JF-039"
        assert f.severity == Severity.HIGH

    def test_fails_on_trust_remote_code_true(self):
        gf = """
        pipeline {
          agent any
          stages {
            stage('load') {
              steps {
                sh "python -c 'AutoModel.from_pretrained(\\"x/y\\", trust_remote_code=True)'"
              }
            }
          }
        }
        """
        f = run_check(gf, "JF-039")
        assert not f.passed

    def test_fails_on_cli_flag(self):
        gf = """
        pipeline {
          agent any
          stages {
            stage('load') {
              steps {
                sh 'huggingface-cli download x/y --trust-remote-code'
              }
            }
          }
        }
        """
        f = run_check(gf, "JF-039")
        assert not f.passed

    def test_passes_without_trust_remote_code(self):
        gf = """
        pipeline {
          agent any
          stages {
            stage('load') {
              steps {
                sh "python -c 'AutoModel.from_pretrained(\\"x/y\\")'"
              }
            }
          }
        }
        """
        f = run_check(gf, "JF-039")
        assert f.passed

    def test_passes_on_trust_remote_code_false(self):
        gf = """
        pipeline {
          agent any
          stages {
            stage('load') {
              steps {
                sh "python -c 'AutoModel.from_pretrained(\\"x/y\\", trust_remote_code=False)'"
              }
            }
          }
        }
        """
        f = run_check(gf, "JF-039")
        assert f.passed
