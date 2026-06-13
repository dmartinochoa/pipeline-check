"""Tests for JF-038 (agentic CLI output lands without human review)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


class TestJF038AiOutputAutoland:
    def test_metadata(self):
        f = run_check(
            "pipeline { agent any\n stages { stage('b') { steps {\n"
            " sh 'make build' } } } }",
            "JF-038",
        )
        assert f.check_id == "JF-038"
        assert f.severity == Severity.HIGH

    def test_fails_on_agent_then_git_push(self):
        gf = """
        pipeline {
          agent any
          stages {
            stage('ai') {
              steps {
                sh "claude -p 'Fix the failing test and commit'"
              }
            }
            stage('publish') {
              steps {
                sh "git push origin HEAD"
              }
            }
          }
        }
        """
        f = run_check(gf, "JF-038")
        assert not f.passed

    def test_passes_when_agent_only(self):
        gf = """
        pipeline {
          agent any
          stages {
            stage('ai') {
              steps {
                sh "aider --message 'open a PR with the fix'"
              }
            }
          }
        }
        """
        f = run_check(gf, "JF-038")
        assert f.passed

    def test_passes_on_git_push_without_agent(self):
        gf = """
        pipeline {
          agent any
          stages {
            stage('publish') {
              steps {
                sh "npm run format"
                sh "git push origin HEAD"
              }
            }
          }
        }
        """
        f = run_check(gf, "JF-038")
        assert f.passed

    def test_passes_on_dry_run_push(self):
        gf = """
        pipeline {
          agent any
          stages {
            stage('ai') {
              steps {
                sh "claude -p 'Suggest a fix'"
                sh "git push --dry-run origin HEAD"
              }
            }
          }
        }
        """
        f = run_check(gf, "JF-038")
        assert f.passed
