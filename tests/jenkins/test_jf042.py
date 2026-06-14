"""Tests for JF-042 (secret-named / bound variable echoed to the log)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


class TestJF042LogLeak:
    def test_metadata(self):
        f = run_check(
            "pipeline { agent any\n stages { stage('b') { steps {\n"
            " sh 'make build' } } } }",
            "JF-042",
        )
        assert f.check_id == "JF-042"
        assert f.severity == Severity.HIGH

    def test_fails_on_echo_secret_named_var(self):
        gf = """
        pipeline {
          agent any
          stages {
            stage('deploy') {
              steps {
                sh 'echo "key is $AWS_SECRET_ACCESS_KEY"'
              }
            }
          }
        }
        """
        f = run_check(gf, "JF-042")
        assert not f.passed

    def test_fails_on_bound_credential_even_if_name_innocuous(self):
        # withCredentials binds GH; echoing $GH leaks it even though "GH"
        # does not match the secret-name heuristic.
        gf = """
        pipeline {
          agent any
          stages {
            stage('deploy') {
              steps {
                withCredentials([string(credentialsId: 'gh', variable: 'GH')]) {
                  sh 'echo "token $GH"'
                }
              }
            }
          }
        }
        """
        f = run_check(gf, "JF-042")
        assert not f.passed

    def test_fails_on_env_dump(self):
        gf = """
        pipeline {
          agent any
          stages {
            stage('debug') {
              steps {
                sh 'printenv'
              }
            }
          }
        }
        """
        f = run_check(gf, "JF-042")
        assert not f.passed

    def test_passes_on_safe_existence_check(self):
        gf = """
        pipeline {
          agent any
          stages {
            stage('deploy') {
              steps {
                withCredentials([string(credentialsId: 'prod', variable: 'TOKEN')]) {
                  sh '[ -n "$TOKEN" ] && echo set || echo unset'
                }
              }
            }
          }
        }
        """
        f = run_check(gf, "JF-042")
        assert f.passed

    def test_passes_on_plain_build(self):
        gf = """
        pipeline {
          agent any
          stages {
            stage('build') {
              steps {
                sh 'make build'
              }
            }
          }
        }
        """
        f = run_check(gf, "JF-042")
        assert f.passed
