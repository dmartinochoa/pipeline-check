"""Per-rule tests for Jenkins load / approval / build-trigger / package
source rules:
JF-012 (``load`` step pulls Groovy from disk without integrity pin),
JF-024 (``input`` approval missing submitter restriction),
JF-026 (``build job:`` trigger ignores downstream failure),
JF-031 (package install from git URL / local path / tarball URL).

JF-005 catches deploy stages without an ``input``; JF-024 covers the
subtler case where the gate exists but anyone can approve.
JF-026 catches the inverse hazard at the cross-job seam: a fire-and-
forget trigger that ignores downstream failure. JF-012 / JF-031 close
the registry-integrity surface around dynamic Groovy and package sources.
"""
from __future__ import annotations

from .conftest import run_check

# ── JF-012 dynamic Groovy load ──────────────────────────────────────


class TestJF012LoadStep:
    def test_fails_on_load_step(self):
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('build') {
                    steps {
                        script {
                            def utils = load 'shared/utils.groovy'
                            utils.deploy()
                        }
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-012")
        assert not f.passed

    def test_passes_when_no_load_step(self):
        groovy = """
        @Library('shared@aabbccddeeff00112233445566778899aabbccdd') _
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('build') {
                    steps { sh 'make' }
                }
            }
        }
        """
        f = run_check(groovy, "JF-012")
        assert f.passed


# ── JF-024 input submitter restriction ──────────────────────────────


class TestJF024InputSubmitter:
    def test_fails_when_input_lacks_submitter(self):
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('deploy') {
                    steps {
                        input message: 'Promote to prod?'
                        sh 'deploy.sh production'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-024")
        assert not f.passed

    def test_passes_with_submitter_restriction(self):
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('deploy') {
                    steps {
                        input message: 'Promote to prod?', submitter: 'releasers,sre'
                        sh 'deploy.sh production'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-024")
        assert f.passed

    def test_passes_when_no_deploy_stage(self):
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('build') {
                    steps { sh 'make' }
                }
            }
        }
        """
        f = run_check(groovy, "JF-024")
        assert f.passed


# ── JF-026 build job downstream failure handling ────────────────────


class TestJF026BuildJobUnchecked:
    def test_fails_when_build_job_uses_wait_false(self):
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('publish') {
                    steps {
                        build job: 'downstream', wait: false
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-026")
        assert not f.passed

    def test_fails_when_build_job_uses_propagate_false(self):
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('publish') {
                    steps {
                        build job: 'downstream', propagate: false
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-026")
        assert not f.passed

    def test_passes_with_default_wait_and_propagate(self):
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('publish') {
                    steps {
                        build job: 'downstream'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-026")
        assert f.passed


# ── JF-031 package source integrity ─────────────────────────────────


class TestJF031PackageSourceIntegrity:
    def test_fails_on_pip_install_git_url(self):
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('install') {
                    steps {
                        sh 'pip install git+https://github.com/example/tool.git'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-031")
        assert not f.passed

    def test_passes_with_lockfile_install(self):
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('install') {
                    steps {
                        sh 'pip install --require-hashes -r requirements.txt'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-031")
        assert f.passed
