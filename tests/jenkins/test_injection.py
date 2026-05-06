"""Per-rule tests for Jenkins shell-injection family rules:
JF-002 (script step interpolating attacker-controllable env var),
JF-030 (dangerous shell idiom — eval, ``sh -c "$VAR"``, backtick exec).

Both rules guard against shell-injection escape paths, which is the
single highest-leverage attack vector in a Jenkins pipeline that
runs untrusted PR code.
"""
from __future__ import annotations

from .conftest import run_check

# ── JF-002 script-step interpolation ────────────────────────────────


class TestJF002ScriptInjection:
    def test_fails_when_branch_name_in_double_quoted_sh(self):
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('build') {
                    steps {
                        sh "echo Building branch $BRANCH_NAME"
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-002")
        assert not f.passed

    def test_passes_when_branch_name_in_single_quoted_sh(self):
        # Groovy single-quoted strings don't interpolate; the env var
        # is expanded by the shell at run time, which is the safe form.
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('build') {
                    steps {
                        sh 'echo "Building branch $BRANCH_NAME"'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-002")
        assert f.passed

    def test_passes_when_no_untrusted_var_referenced(self):
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('build') {
                    steps {
                        sh "make test"
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-002")
        assert f.passed


# ── JF-030 dangerous shell idiom ────────────────────────────────────


class TestJF030ShellEval:
    def test_fails_on_eval_of_variable(self):
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('run') {
                    steps {
                        sh 'eval "$BUILD_CMD"'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-030")
        assert not f.passed

    def test_fails_on_sh_dash_c_with_variable(self):
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('run') {
                    steps {
                        sh 'sh -c "$USER_CMD"'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-030")
        assert not f.passed

    def test_passes_when_shell_idiom_clean(self):
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('run') {
                    steps {
                        sh 'make test'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-030")
        assert f.passed
