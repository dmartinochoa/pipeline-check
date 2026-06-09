"""Tests for JF-037 (untrusted context reaches an agentic AI CLI)."""
from __future__ import annotations

from pipeline_check.core.checks.base import Severity

from .conftest import run_check


class TestJF037AiPromptInjection:
    def test_metadata(self):
        f = run_check(
            "pipeline { agent any\n stages { stage('b') { steps {\n"
            " sh 'make build' } } } }",
            "JF-037",
        )
        assert f.check_id == "JF-037"
        assert f.severity == Severity.HIGH

    def test_fails_on_agent_with_change_title(self):
        gf = """
        pipeline {
          agent any
          stages {
            stage('triage') {
              steps {
                sh "claude -p 'Triage this PR titled ${env.CHANGE_TITLE}'"
              }
            }
          }
        }
        """
        f = run_check(gf, "JF-037")
        assert not f.passed

    def test_fails_on_agent_with_build_parameter(self):
        gf = """
        pipeline {
          agent any
          parameters { string(name: 'TASK', defaultValue: 'x') }
          stages {
            stage('ai') {
              steps {
                sh "aider --message 'Do ${params.TASK}'"
              }
            }
          }
        }
        """
        f = run_check(gf, "JF-037")
        assert not f.passed

    def test_fails_even_in_single_quoted_body(self):
        # Single-quoting is the SAFE form for JF-002 (command injection) but
        # not for an LLM prompt: the shell still expands $CHANGE_BRANCH and
        # passes it to the agent as prompt text.
        gf = """
        pipeline {
          agent any
          stages {
            stage('ai') {
              steps {
                sh 'gemini -p "Summarize $CHANGE_BRANCH"'
              }
            }
          }
        }
        """
        f = run_check(gf, "JF-037")
        assert not f.passed

    def test_passes_on_static_prompt(self):
        gf = """
        pipeline {
          agent any
          stages {
            stage('ai') {
              steps {
                sh "claude -p 'Summarize the build log and suggest fixes'"
              }
            }
          }
        }
        """
        f = run_check(gf, "JF-037")
        assert f.passed

    def test_passes_on_untrusted_env_without_agent(self):
        # Untrusted env in a plain shell step is JF-002 territory, not JF-037.
        gf = """
        pipeline {
          agent any
          stages {
            stage('build') {
              steps {
                sh "echo Building ${env.CHANGE_TITLE}"
              }
            }
          }
        }
        """
        f = run_check(gf, "JF-037")
        assert f.passed
