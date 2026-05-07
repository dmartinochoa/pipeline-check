"""Per-rule tests for Jenkins agent/runner config and pipeline options:
JF-004 (long-lived AWS keys via ``withCredentials`` / ``withAWS``),
JF-009 (docker agent image not digest-pinned),
JF-011 (no ``buildDiscarder`` retention policy),
JF-014 (agent label missing the ``ephemeral`` marker).

These rules govern *how* the pipeline runs — which credentials it
binds, which image executes the work, how long logs are retained,
whether the runner persists between jobs.
"""
from __future__ import annotations

from .conftest import run_check

# ── JF-004 long-lived AWS via withCredentials / withAWS ─────────────


class TestJF004AwsLongLived:
    def test_fails_when_with_aws_uses_static_credentials_id(self):
        # ``withAWS(credentials: '...')`` binds a stored access-key
        # secret. The safe alternative is ``withAWS(role: '...')``,
        # which assumes a short-lived IAM role at build time.
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('deploy') {
                    steps {
                        withAWS(credentials: 'aws-prod-key', region: 'us-east-1') {
                            sh 'aws s3 cp build/ s3://bucket/'
                        }
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-004")
        assert not f.passed

    def test_passes_when_with_aws_uses_role(self):
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('deploy') {
                    steps {
                        withAWS(role: 'arn:aws:iam::1:role/jenkins', region: 'us-east-1') {
                            sh 'aws s3 cp build/ s3://bucket/'
                        }
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-004")
        assert f.passed


# ── JF-009 docker agent image pinning ───────────────────────────────


class TestJF009DockerImagePinning:
    def test_passes_with_digest_pinned_image(self):
        groovy = """
        pipeline {
            agent {
                docker {
                    image 'cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001'
                }
            }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages { stage('build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-009")
        assert f.passed

    def test_fails_with_tag_pinned_image(self):
        groovy = """
        pipeline {
            agent {
                docker { image 'cimg/base:stable' }
            }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages { stage('build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-009")
        assert not f.passed

    def test_fails_with_no_tag(self):
        groovy = """
        pipeline {
            agent {
                docker { image 'cimg/base' }
            }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages { stage('build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-009")
        assert not f.passed


# ── JF-011 buildDiscarder retention ─────────────────────────────────


class TestJF011BuildDiscarder:
    def test_fails_when_no_build_discarder_set(self):
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages { stage('build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-011")
        assert not f.passed

    def test_passes_with_build_discarder_in_options(self):
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options {
                timeout(time: 30, unit: 'MINUTES')
                buildDiscarder(logRotator(numToKeepStr: '30', daysToKeepStr: '90'))
            }
            stages { stage('build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-011")
        assert f.passed


# ── JF-014 ephemeral agent marker ───────────────────────────────────


class TestJF014EphemeralAgent:
    def test_fails_when_label_lacks_ephemeral_marker(self):
        groovy = """
        pipeline {
            agent { label 'linux-builder' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages { stage('build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-014")
        assert not f.passed

    def test_passes_when_label_includes_ephemeral(self):
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages { stage('build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-014")
        assert f.passed


# ── JF-032 agent label injection ────────────────────────────────────


class TestJF032AgentLabelInjection:
    def test_fails_on_params_in_label(self):
        # Build parameters are set by whoever queues the build —
        # parity with GHA-036's reusable-workflow caller scenario.
        groovy = """
        pipeline {
            parameters {
                string(name: 'NODE_LABEL', defaultValue: 'linux-ephemeral')
            }
            agent { label "${params.NODE_LABEL}" }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages { stage('build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-032")
        assert not f.passed
        assert "params.NODE_LABEL" in f.description

    def test_fails_on_branch_name_env_in_label(self):
        # ${env.BRANCH_NAME} is the SCM branch the build is for —
        # the pusher controls that string through branch naming.
        groovy = """
        pipeline {
            agent { label "deploy-${env.BRANCH_NAME}-ephemeral" }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages { stage('build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-032")
        assert not f.passed

    def test_fails_on_change_branch_in_node_form(self):
        # ``agent { node { label "..." } }`` is an alternate shape
        # for the same targeting choice — must also be walked.
        groovy = """
        pipeline {
            agent {
                node {
                    label "${env.CHANGE_BRANCH}-ephemeral"
                }
            }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages { stage('build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-032")
        assert not f.passed

    def test_fails_on_label_in_docker_form(self):
        # ``agent { docker { label "..." image "..." } }`` lets the
        # docker plugin pick which executor pulls the image — same
        # injection surface.
        groovy = """
        pipeline {
            agent {
                docker {
                    image 'maven:3.9.6-eclipse-temurin-21@sha256:0000000000000000000000000000000000000000000000000000000000000000'
                    label "${params.RUNNER}"
                }
            }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages { stage('build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-032")
        assert not f.passed

    def test_passes_on_static_label(self):
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages { stage('build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-032")
        assert f.passed

    def test_passes_on_author_controlled_env(self):
        # ``${env.JOB_NAME}`` and ``${env.BUILD_NUMBER}`` come from
        # Jenkins itself — author-controlled, not triggerer-
        # controlled. Out of scope for this rule.
        groovy = """
        pipeline {
            agent { label "build-${env.JOB_NAME}-${env.BUILD_NUMBER}-ephemeral" }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages { stage('build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-032")
        assert f.passed

    def test_passes_when_no_agent_label(self):
        # ``agent any`` and ``agent none`` have no ``label "..."`` to
        # interpolate — out of scope (JF-003 covers ``agent any``).
        groovy = """
        pipeline {
            agent any
            options { timeout(time: 30, unit: 'MINUTES') }
            stages { stage('build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-032")
        assert f.passed

    def test_passes_when_label_interpolation_is_in_a_groovy_comment(self):
        # The rule reads ``text_no_comments`` so a commented-out
        # interpolation example doesn't trip it.
        groovy = """
        pipeline {
            // agent { label "${params.RUNNER}" }
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages { stage('build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-032")
        assert f.passed
