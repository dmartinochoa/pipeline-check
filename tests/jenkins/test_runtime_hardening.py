"""Per-rule tests for Jenkins JF-015 (timeout), JF-016 (curl-pipe),
JF-023 (TLS bypass), JF-003 (agent any).

These four rules cover the everyday hardening for any Jenkinsfile:
bound the build, verify what you download, don't disable TLS,
don't pin to the unrestricted ``agent any`` pool.
"""
from __future__ import annotations

from .conftest import run_check


# ── JF-015 timeout wrapper ──────────────────────────────────────────


class TestJF015Timeout:
    def test_fails_when_no_timeout_wrapper(self):
        groovy = """
        pipeline {
            agent any
            stages { stage('build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-015")
        assert not f.passed

    def test_passes_with_pipeline_level_timeout(self):
        groovy = """
        pipeline {
            agent any
            options { timeout(time: 30, unit: 'MINUTES') }
            stages { stage('build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-015")
        assert f.passed

    def test_passes_with_stage_level_timeout(self):
        groovy = """
        pipeline {
            agent any
            stages {
                stage('build') {
                    steps {
                        timeout(time: 10, unit: 'MINUTES') {
                            sh 'make'
                        }
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-015")
        assert f.passed


# ── JF-016 curl-pipe ────────────────────────────────────────────────


class TestJF016CurlPipe:
    def test_fails_on_curl_piped_to_bash(self):
        groovy = """
        pipeline {
            agent any
            options { timeout(time: 10, unit: 'MINUTES') }
            stages {
                stage('install') {
                    steps {
                        sh 'curl -fsSL https://example.com/install.sh | bash'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-016")
        assert not f.passed

    def test_fails_on_wget_piped_to_sh(self):
        groovy = """
        pipeline {
            agent any
            options { timeout(time: 10, unit: 'MINUTES') }
            stages {
                stage('install') {
                    steps { sh 'wget -O - https://example.com/install.sh | sh' }
                }
            }
        }
        """
        f = run_check(groovy, "JF-016")
        assert not f.passed

    def test_passes_with_checksum_verified_install(self):
        groovy = """
        pipeline {
            agent any
            options { timeout(time: 10, unit: 'MINUTES') }
            stages {
                stage('install') {
                    steps {
                        sh '''
                            curl -fsSL https://example.com/install.sh -o install.sh
                            sha256sum -c install.sh.sha256
                            bash install.sh
                        '''
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-016")
        assert f.passed


# ── JF-023 TLS bypass ───────────────────────────────────────────────


class TestJF023TLSBypass:
    def test_fails_on_curl_insecure_flag(self):
        groovy = """
        pipeline {
            agent any
            options { timeout(time: 10, unit: 'MINUTES') }
            stages {
                stage('fetch') {
                    steps { sh 'curl -k https://internal.example.com/secret' }
                }
            }
        }
        """
        f = run_check(groovy, "JF-023")
        assert not f.passed

    def test_fails_on_npm_strict_ssl_false(self):
        groovy = """
        pipeline {
            agent any
            options { timeout(time: 10, unit: 'MINUTES') }
            stages {
                stage('install') {
                    steps { sh 'npm config set strict-ssl false' }
                }
            }
        }
        """
        f = run_check(groovy, "JF-023")
        assert not f.passed

    def test_passes_when_no_tls_bypass(self):
        groovy = """
        pipeline {
            agent any
            options { timeout(time: 10, unit: 'MINUTES') }
            stages {
                stage('fetch') {
                    steps { sh 'curl -fsSL https://example.com/data' }
                }
            }
        }
        """
        f = run_check(groovy, "JF-023")
        assert f.passed


# ── JF-003 agent any ────────────────────────────────────────────────


class TestJF003AgentAny:
    def test_fails_on_top_level_agent_any(self):
        groovy = """
        pipeline {
            agent any
            options { timeout(time: 10, unit: 'MINUTES') }
            stages { stage('build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-003")
        assert not f.passed

    def test_passes_with_labeled_agent(self):
        groovy = """
        pipeline {
            agent { label 'build-ephemeral' }
            options { timeout(time: 10, unit: 'MINUTES') }
            stages { stage('build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-003")
        assert f.passed

    def test_passes_with_docker_agent(self):
        groovy = """
        pipeline {
            agent {
                docker {
                    image 'cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001'
                }
            }
            options { timeout(time: 10, unit: 'MINUTES') }
            stages { stage('build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-003")
        assert f.passed
