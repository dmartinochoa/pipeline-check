"""Per-rule tests for the Jenkins supply-chain rules:
JF-006 (signing), JF-007 (SBOM), JF-017 (docker insecure flags),
JF-018 (insecure package source), JF-020 (vulnerability scanning),
JF-021 (lockfile enforcement), JF-022 (dependency-update commands).

Mirrors the GHA / GL / CC / BB supply-chain matrix for the Jenkins
provider. Jenkinsfile is Groovy so the helper builds an inline
``Jenkinsfile`` rather than parsing YAML.
"""
from __future__ import annotations

from .conftest import run_check

# ── JF-006 signing ──────────────────────────────────────────────────


class TestJF006Signing:
    def test_fails_when_artifacts_produced_without_signing(self):
        groovy = """
        pipeline {
            agent { label 'linux' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('build') {
                    steps {
                        sh 'docker build -t registry.example.com/app:v1 .'
                        sh 'docker push registry.example.com/app:v1'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-006")
        assert not f.passed

    def test_passes_with_cosign_signing(self):
        groovy = """
        pipeline {
            agent { label 'linux' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('build-sign') {
                    steps {
                        sh 'docker build -t registry.example.com/app:v1 .'
                        sh 'cosign sign --yes registry.example.com/app@sha256:abc'
                        sh 'docker push registry.example.com/app:v1'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-006")
        assert f.passed


# ── JF-007 SBOM ─────────────────────────────────────────────────────


class TestJF007SBOM:
    def test_fails_when_artifacts_produced_without_sbom(self):
        groovy = """
        pipeline {
            agent { label 'linux' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('build') {
                    steps {
                        sh 'docker build -t registry.example.com/app:v1 .'
                        sh 'docker push registry.example.com/app:v1'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-007")
        assert not f.passed

    def test_passes_with_syft_sbom(self):
        groovy = """
        pipeline {
            agent { label 'linux' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('build-sbom') {
                    steps {
                        sh 'docker build -t registry.example.com/app:v1 .'
                        sh 'syft registry.example.com/app:v1 -o cyclonedx-json > sbom.json'
                        sh 'docker push registry.example.com/app:v1'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-007")
        assert f.passed


# ── JF-020 vulnerability scanning ───────────────────────────────────


class TestJF020VulnScanning:
    def test_fails_when_artifact_built_without_vuln_scan(self):
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('build') {
                    steps {
                        sh 'docker build -t registry.example.com/app:v1 .'
                        sh 'docker push registry.example.com/app:v1'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-020")
        assert not f.passed

    def test_passes_with_trivy_scan(self):
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('build') {
                    steps {
                        sh 'docker build -t registry.example.com/app:v1 .'
                        sh 'trivy image --severity HIGH,CRITICAL registry.example.com/app:v1'
                        sh 'docker push registry.example.com/app:v1'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-020")
        assert f.passed


# ── JF-017 docker insecure flags ────────────────────────────────────


class TestJF017DockerInsecure:
    def test_fails_on_privileged_flag(self):
        groovy = """
        pipeline {
            agent { label 'linux' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('x') {
                    steps {
                        sh 'docker run --privileged builder make all'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-017")
        assert not f.passed

    def test_passes_with_minimal_flags(self):
        groovy = """
        pipeline {
            agent { label 'linux' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('x') {
                    steps {
                        sh 'docker run --rm -v /tmp:/work builder make all'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-017")
        assert f.passed


# ── JF-018 insecure package source ──────────────────────────────────


class TestJF018PackageInsecure:
    def test_fails_on_pip_index_url_http(self):
        groovy = """
        pipeline {
            agent { label 'linux' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('install') {
                    steps {
                        sh 'pip install --index-url http://example.com/simple/ requests'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-018")
        assert not f.passed

    def test_passes_with_default_https_sources(self):
        groovy = """
        pipeline {
            agent { label 'linux' }
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
        f = run_check(groovy, "JF-018")
        assert f.passed


# ── JF-021 lockfile enforcement ─────────────────────────────────────


class TestJF021Lockfile:
    def test_fails_on_npm_install(self):
        groovy = """
        pipeline {
            agent { label 'linux' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('install') {
                    steps {
                        sh 'npm install'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-021")
        assert not f.passed

    def test_passes_on_npm_ci(self):
        groovy = """
        pipeline {
            agent { label 'linux' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('install') {
                    steps {
                        sh 'npm ci'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-021")
        assert f.passed


# ── JF-022 dependency-update commands ───────────────────────────────


class TestJF022DepUpdate:
    def test_fails_on_npm_update(self):
        groovy = """
        pipeline {
            agent { label 'linux' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('update') {
                    steps {
                        sh 'npm update'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-022")
        assert not f.passed

    def test_passes_when_no_update_command(self):
        groovy = """
        pipeline {
            agent { label 'linux' }
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
        f = run_check(groovy, "JF-022")
        assert f.passed
