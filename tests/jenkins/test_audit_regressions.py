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
