"""Per-rule tests for Jenkins JF-033..035.

JF-033 (withCredentials binding leaked via Groovy ${...} in sh),
JF-034 (password() build parameter declared),
JF-035 (httpRequest step disables SSL verification).
"""
from __future__ import annotations

from .conftest import run_check


# ── JF-033 withCredentials Groovy-interpolation leak ─────────────────


class TestJF033WithCredentialsInterpolation:
    def test_fails_on_double_quoted_interpolation(self):
        # ${TOKEN} inside a double-quoted Groovy string is substituted
        # before Jenkins' masker sees the command, so ``set -x`` prints
        # the literal secret to the build log.
        groovy = """
        pipeline {
            agent any
            stages {
                stage('Deploy') {
                    steps {
                        withCredentials([string(credentialsId: 'tok',
                                                variable: 'TOKEN')]) {
                            sh "curl -H 'Authorization: Bearer ${TOKEN}'"
                        }
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-033")
        assert not f.passed
        assert "TOKEN" in f.description

    def test_fails_on_triple_double_quoted_body(self):
        groovy = '''
        pipeline {
            agent any
            stages {
                stage('Deploy') {
                    steps {
                        withCredentials([string(credentialsId: 'tok',
                                                variable: 'TOKEN')]) {
                            sh """
                            curl -H "Authorization: Bearer ${TOKEN}" https://api
                            """
                        }
                    }
                }
            }
        }
        '''
        f = run_check(groovy, "JF-033")
        assert not f.passed

    def test_passes_with_single_quoted_body(self):
        # Groovy doesn't interpolate single-quoted strings; ``$TOKEN``
        # is resolved by the shell, which Jenkins masks.
        groovy = """
        pipeline {
            agent any
            stages {
                stage('Deploy') {
                    steps {
                        withCredentials([string(credentialsId: 'tok',
                                                variable: 'TOKEN')]) {
                            sh 'curl -H "Authorization: Bearer $TOKEN"'
                        }
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-033")
        assert f.passed

    def test_passes_when_no_withcredentials_block(self):
        # No bindings declared, no leak possible — out of scope.
        groovy = """
        pipeline {
            agent any
            stages {
                stage('Build') {
                    steps {
                        sh "echo ${env.JOB_NAME}"
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-033")
        assert f.passed

    def test_passes_when_double_quoted_does_not_reference_binding(self):
        # Double-quoted strings inside a withCredentials block are
        # safe as long as they don't reference any bound variable.
        groovy = """
        pipeline {
            agent any
            stages {
                stage('Deploy') {
                    steps {
                        withCredentials([string(credentialsId: 'tok',
                                                variable: 'TOKEN')]) {
                            sh "ls -la ${env.WORKSPACE}"
                        }
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-033")
        assert f.passed

    def test_fails_on_username_password_binding(self):
        groovy = """
        pipeline {
            agent any
            stages {
                stage('Deploy') {
                    steps {
                        withCredentials([usernamePassword(
                            credentialsId: 'creds',
                            usernameVariable: 'USER',
                            passwordVariable: 'PASS')]) {
                            sh "curl -u ${USER}:${PASS} https://api"
                        }
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-033")
        assert not f.passed

    def test_fails_on_multiple_bindings_in_one_block(self):
        # Each ``variable: '...'`` entry in the list is treated as a
        # separate binding; an interpolation matching ANY of them
        # should fire.
        groovy = """
        pipeline {
            agent any
            stages {
                stage('Deploy') {
                    steps {
                        withCredentials([
                            string(credentialsId: 'tok-a', variable: 'TOKEN_A'),
                            string(credentialsId: 'tok-b', variable: 'TOKEN_B'),
                        ]) {
                            // Only TOKEN_B is interpolated — must fire
                            // even though TOKEN_A is the first listed.
                            sh "curl -H 'X-B: ${TOKEN_B}'"
                        }
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-033")
        assert not f.passed
        assert "TOKEN_B" in f.description

    def test_fails_on_sh_nested_inside_script_block(self):
        # withCredentials -> script -> sh: the offending sh is two
        # closures deep. The block walker has to track nested braces.
        groovy = """
        pipeline {
            agent any
            stages {
                stage('Deploy') {
                    steps {
                        withCredentials([string(credentialsId: 'tok',
                                                variable: 'TOKEN')]) {
                            script {
                                if (env.BRANCH_NAME == 'main') {
                                    sh "curl -H 'X-Token: ${TOKEN}'"
                                }
                            }
                        }
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-033")
        assert not f.passed


# ── JF-034 password() build parameter ────────────────────────────────


class TestJF034PasswordParameter:
    def test_fails_when_password_parameter_declared(self):
        groovy = """
        pipeline {
            agent any
            parameters {
                password(name: 'API_TOKEN',
                         defaultValue: '',
                         description: 'API token for deploy')
            }
            stages { stage('Deploy') { steps { sh 'make deploy' } } }
        }
        """
        f = run_check(groovy, "JF-034")
        assert not f.passed
        assert "API_TOKEN" in f.description

    def test_passes_with_string_parameter(self):
        # ``string(name: ..)`` is not a credential type — out of scope.
        groovy = """
        pipeline {
            agent any
            parameters {
                string(name: 'TARGET', defaultValue: 'prod')
            }
            stages { stage('Build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-034")
        assert f.passed

    def test_passes_when_no_parameters_block(self):
        groovy = """
        pipeline {
            agent any
            stages { stage('Build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-034")
        assert f.passed

    def test_fails_with_multiple_password_parameters(self):
        groovy = """
        pipeline {
            agent any
            parameters {
                password(name: 'TOKEN_A', defaultValue: '')
                password(name: 'TOKEN_B', defaultValue: '')
            }
            stages { stage('Deploy') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-034")
        assert not f.passed
        assert "TOKEN_A" in f.description
        assert "TOKEN_B" in f.description

    def test_offender_carries_correct_line_number(self):
        # Pin line-number accuracy explicitly — the rule maps the
        # in-block match offset back to an absolute file line, which is
        # easy to off-by-one.
        groovy = "\n".join([
            "pipeline {",
            "    agent any",
            "    parameters {",
            "        password(name: 'API_TOKEN', defaultValue: '')",
            "    }",
            "    stages { stage('Deploy') { steps { sh 'make' } } }",
            "}",
        ])
        f = run_check(groovy, "JF-034")
        assert not f.passed
        # password() is on the 4th line (1-based).
        assert "L4:" in f.description


# ── JF-035 httpRequest ignoreSslErrors ───────────────────────────────


class TestJF035HttpRequestInsecure:
    def test_fails_when_ignoresslerrors_true(self):
        groovy = """
        pipeline {
            agent any
            stages {
                stage('Notify') {
                    steps {
                        httpRequest url: 'https://internal.example.com/notify',
                                    ignoreSslErrors: true
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-035")
        assert not f.passed

    def test_passes_when_ignoresslerrors_false(self):
        groovy = """
        pipeline {
            agent any
            stages {
                stage('Notify') {
                    steps {
                        httpRequest url: 'https://internal.example.com/notify',
                                    ignoreSslErrors: false
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-035")
        assert f.passed

    def test_passes_when_no_httprequest_call(self):
        groovy = """
        pipeline {
            agent any
            stages { stage('Build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-035")
        assert f.passed

    def test_passes_when_flag_lives_in_a_comment(self):
        # Comments are stripped before the regex runs.
        groovy = """
        pipeline {
            agent any
            stages {
                stage('Notify') {
                    steps {
                        // historical: httpRequest url: 'x', ignoreSslErrors: true
                        httpRequest url: 'https://api.example.com'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-035")
        assert f.passed
