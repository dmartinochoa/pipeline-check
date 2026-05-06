"""Per-rule tests for Jenkins JF-001 (library pinning) and JF-008
(literal secrets).

Both rules are about supply-chain integrity: a Jenkinsfile pulling
a shared library from a floating branch or carrying credentials in
plaintext is the highest-leverage entry point an attacker has into
a Jenkins build.
"""
from __future__ import annotations

from .conftest import run_check

# ── JF-001 library pinning ───────────────────────────────────────────


class TestJF001LibraryPinning:
    def test_passes_with_semver_tag_pin(self):
        groovy = """
        @Library('shared@v1.4.2') _

        pipeline {
            agent any
            stages { stage('build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-001")
        assert f.passed

    def test_passes_with_commit_sha_pin(self):
        groovy = """
        @Library('shared@aabbccddeeff00112233445566778899aabbccdd') _
        pipeline { agent any; stages { stage('x') { steps {} } } }
        """
        f = run_check(groovy, "JF-001")
        assert f.passed

    def test_fails_when_library_pinned_to_main_branch(self):
        groovy = """
        @Library('shared@main') _
        pipeline { agent any; stages { stage('x') { steps {} } } }
        """
        f = run_check(groovy, "JF-001")
        assert not f.passed
        assert "main" in f.description

    def test_fails_when_library_has_no_at_ref(self):
        groovy = """
        @Library('shared') _
        pipeline { agent any; stages { stage('x') { steps {} } } }
        """
        f = run_check(groovy, "JF-001")
        assert not f.passed

    def test_fails_when_library_pinned_to_develop(self):
        groovy = """
        @Library('shared@develop') _
        pipeline { agent any; stages { stage('x') { steps {} } } }
        """
        f = run_check(groovy, "JF-001")
        assert not f.passed

    def test_passes_when_no_libraries_referenced(self):
        groovy = """
        pipeline {
            agent any
            stages { stage('build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-001")
        assert f.passed


# ── JF-008 literal secrets ──────────────────────────────────────────


class TestJF008LiteralSecrets:
    def test_fails_on_aws_access_key_literal(self):
        groovy = """
        pipeline {
            agent any
            environment {
                AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'
            }
            stages { stage('x') { steps { sh 'aws s3 ls' } } }
        }
        """
        f = run_check(groovy, "JF-008")
        assert not f.passed

    def test_fails_on_github_token_literal(self):
        groovy = """
        pipeline {
            agent any
            environment {
                GH_TOKEN = 'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
            }
            stages { stage('x') { steps { sh 'gh release view' } } }
        }
        """
        f = run_check(groovy, "JF-008")
        assert not f.passed

    def test_passes_when_secret_resolved_via_with_credentials(self):
        # Real-world idiom: secret is referenced via withCredentials,
        # the value injected at build time. The literal string in the
        # Groovy is the credentialsId, not the secret value itself.
        groovy = """
        pipeline {
            agent any
            stages {
                stage('deploy') {
                    steps {
                        withCredentials([string(credentialsId: 'aws-key', variable: 'AWS_KEY')]) {
                            sh 'aws s3 cp build/ s3://bucket/'
                        }
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-008")
        assert f.passed

    def test_passes_with_no_credential_shaped_strings(self):
        groovy = """
        pipeline {
            agent any
            stages { stage('build') { steps { sh 'make test' } } }
        }
        """
        f = run_check(groovy, "JF-008")
        assert f.passed
