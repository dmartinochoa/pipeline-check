"""Per-rule tests for Jenkins deploy-gating and Kubernetes-agent rules:
JF-005 (deploy stage missing manual ``input`` approval),
JF-010 (long-lived AWS keys in ``environment {}`` block),
JF-025 (Kubernetes agent pod template runs privileged or mounts hostPath).

JF-005 sits next to JF-024 (input submitter) at the deploy-gating
seam. JF-010 covers the second long-lived-AWS path (the
``environment {}`` form, distinct from JF-004's
``withCredentials``/``withAWS`` form). JF-025 is the K8s-pod-template
analog of JF-017's inline-docker-privileged check.
"""
from __future__ import annotations

from .conftest import run_check

# ── JF-005 deploy stage approval ────────────────────────────────────


class TestJF005DeployInput:
    def test_fails_when_deploy_stage_lacks_input(self):
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('deploy') {
                    steps {
                        sh 'deploy.sh production'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-005")
        assert not f.passed

    def test_passes_with_input_step_inside_deploy_stage(self):
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages {
                stage('deploy') {
                    steps {
                        input message: 'Promote to prod?', submitter: 'releasers'
                        sh 'deploy.sh production'
                    }
                }
            }
        }
        """
        f = run_check(groovy, "JF-005")
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
        f = run_check(groovy, "JF-005")
        assert f.passed


# ── JF-010 long-lived AWS keys via environment block ────────────────


class TestJF010EnvAwsKeys:
    def test_fails_on_environment_aws_key_literal(self):
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            environment {
                AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'
                AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
            }
            stages {
                stage('deploy') {
                    steps { sh 'aws s3 ls' }
                }
            }
        }
        """
        f = run_check(groovy, "JF-010")
        assert not f.passed

    def test_passes_with_credentials_helper(self):
        # ``credentials('id')`` resolves to a stored credential at
        # build time; the literal in the YAML is the credentialsId,
        # not the secret value.
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            environment {
                AWS_ACCESS_KEY_ID = credentials('aws-prod-key')
            }
            stages {
                stage('deploy') {
                    steps { sh 'aws s3 ls' }
                }
            }
        }
        """
        f = run_check(groovy, "JF-010")
        assert f.passed

    def test_passes_when_no_environment_block(self):
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages { stage('build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-010")
        assert f.passed


# ── JF-025 Kubernetes agent privileged / hostPath ───────────────────


class TestJF025KubernetesAgent:
    def test_fails_when_pod_yaml_runs_privileged(self):
        groovy = """
        pipeline {
            agent {
                kubernetes {
                    yaml '''
                        apiVersion: v1
                        kind: Pod
                        spec:
                          containers:
                            - name: build
                              image: cimg/base:stable
                              securityContext:
                                privileged: true
                    '''
                }
            }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages { stage('build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-025")
        assert not f.passed

    def test_fails_when_pod_yaml_mounts_host_path(self):
        groovy = """
        pipeline {
            agent {
                kubernetes {
                    yaml '''
                        apiVersion: v1
                        kind: Pod
                        spec:
                          containers:
                            - name: build
                              image: cimg/base:stable
                          volumes:
                            - name: dock
                              hostPath:
                                path: /var/run/docker.sock
                    '''
                }
            }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages { stage('build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-025")
        assert not f.passed

    def test_passes_with_minimal_pod_template(self):
        groovy = """
        pipeline {
            agent {
                kubernetes {
                    yaml '''
                        apiVersion: v1
                        kind: Pod
                        spec:
                          containers:
                            - name: build
                              image: cimg/base@sha256:0000000000000000000000000000000000000000000000000000000000000001
                              securityContext:
                                runAsNonRoot: true
                                readOnlyRootFilesystem: true
                    '''
                }
            }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages { stage('build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-025")
        assert f.passed

    def test_passes_when_no_kubernetes_agent(self):
        groovy = """
        pipeline {
            agent { label 'linux-ephemeral' }
            options { timeout(time: 30, unit: 'MINUTES') }
            stages { stage('build') { steps { sh 'make' } } }
        }
        """
        f = run_check(groovy, "JF-025")
        assert f.passed
