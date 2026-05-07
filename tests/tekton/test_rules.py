"""Per-rule tests for every TKN-* check."""
from __future__ import annotations

from .conftest import run_check


# ── TKN-001 image pinning ──────────────────────────────────────────────


class TestTKN001ImagePinning:
    def test_passes_with_digest_pinned_image(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: t
        spec:
          steps:
            - name: build
              image: alpine@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b
              script: echo
        """
        f = run_check(cfg, "TKN-001")
        assert f.passed

    def test_fails_with_tag_only_image(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: t
        spec:
          steps:
            - name: build
              image: alpine:3.18
              script: echo
        """
        f = run_check(cfg, "TKN-001")
        assert not f.passed


# ── TKN-002 privileged step ────────────────────────────────────────────


class TestTKN002PrivilegedStep:
    def test_passes_with_hardened_context(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: t
        spec:
          steps:
            - name: build
              image: alpine@sha256:0123456789012345678901234567890123456789012345678901234567890123
              securityContext:
                privileged: false
                runAsNonRoot: true
                allowPrivilegeEscalation: false
              script: echo
        """
        f = run_check(cfg, "TKN-002")
        assert f.passed

    def test_fails_when_privileged_true(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: t
        spec:
          steps:
            - name: build
              image: alpine:3
              securityContext:
                privileged: true
              script: echo
        """
        f = run_check(cfg, "TKN-002")
        assert not f.passed

    def test_fails_when_no_security_context(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: t
        spec:
          steps:
            - name: build
              image: alpine:3
              script: echo
        """
        f = run_check(cfg, "TKN-002")
        assert not f.passed


# ── TKN-003 param injection ────────────────────────────────────────────


class TestTKN003ParamInjection:
    def test_fails_when_param_unquoted_in_script(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: t
        spec:
          steps:
            - name: build
              image: alpine:3
              script: |
                echo Building $(params.ref)
        """
        f = run_check(cfg, "TKN-003")
        assert not f.passed

    def test_passes_when_param_passed_via_env(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: t
        spec:
          steps:
            - name: build
              image: alpine:3
              env:
                - name: REF
                  value: $(params.ref)
              script: |
                echo "Building $REF"
        """
        f = run_check(cfg, "TKN-003")
        assert f.passed


# ── TKN-004 host namespace ─────────────────────────────────────────────


class TestTKN004HostNamespace:
    def test_fails_with_host_path_volume(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: t
        spec:
          volumes:
            - name: dock
              hostPath:
                path: /var/run/docker.sock
          steps:
            - name: build
              image: alpine:3
              script: echo
        """
        f = run_check(cfg, "TKN-004")
        assert not f.passed

    def test_fails_with_host_network_pod_template(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: t
        spec:
          podTemplate:
            hostNetwork: true
          steps:
            - name: build
              image: alpine:3
              script: echo
        """
        f = run_check(cfg, "TKN-004")
        assert not f.passed

    def test_passes_with_emptydir_workspace(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: t
        spec:
          workspaces:
            - name: src
          steps:
            - name: build
              image: alpine:3
              script: echo
        """
        f = run_check(cfg, "TKN-004")
        assert f.passed


# ── TKN-005 literal secrets ────────────────────────────────────────────


class TestTKN005LiteralSecrets:
    def test_fails_with_aws_key_in_step_env(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: t
        spec:
          steps:
            - name: build
              image: alpine:3
              env:
                - name: AWS_ACCESS_KEY_ID
                  value: "AKIAIOSFODNN7EXAMPLE"
              script: echo
        """
        f = run_check(cfg, "TKN-005")
        assert not f.passed

    def test_passes_with_secret_ref(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: t
        spec:
          steps:
            - name: build
              image: alpine:3
              env:
                - name: TOKEN
                  valueFrom:
                    secretKeyRef:
                      name: deploy
                      key: token
              script: echo
        """
        f = run_check(cfg, "TKN-005")
        assert f.passed


# ── TKN-006 timeout ────────────────────────────────────────────────────


class TestTKN006Timeout:
    def test_passes_with_timeouts_block(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: PipelineRun
        metadata:
          name: pr
        spec:
          pipelineRef:
            name: p
          serviceAccountName: ci-runner
          timeouts:
            pipeline: "1h"
        """
        f = run_check(cfg, "TKN-006")
        assert f.passed

    def test_fails_when_no_timeout(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: PipelineRun
        metadata:
          name: pr
        spec:
          pipelineRef:
            name: p
          serviceAccountName: ci-runner
        """
        f = run_check(cfg, "TKN-006")
        assert not f.passed


# ── TKN-007 default service account ────────────────────────────────────


class TestTKN007DefaultServiceAccount:
    def test_fails_when_sa_missing(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: PipelineRun
        metadata:
          name: pr
        spec:
          pipelineRef:
            name: p
        """
        f = run_check(cfg, "TKN-007")
        assert not f.passed

    def test_fails_when_sa_is_default(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: TaskRun
        metadata:
          name: tr
        spec:
          taskRef:
            name: t
          serviceAccountName: default
        """
        f = run_check(cfg, "TKN-007")
        assert not f.passed

    def test_passes_with_explicit_sa(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: TaskRun
        metadata:
          name: tr
        spec:
          taskRef:
            name: t
          serviceAccountName: ci-runner
        """
        f = run_check(cfg, "TKN-007")
        assert f.passed


# ── TKN-008 curl pipe / TLS bypass ─────────────────────────────────────


class TestTKN008CurlPipe:
    def test_fails_with_curl_pipe(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: t
        spec:
          steps:
            - name: install
              image: alpine:3
              script: |
                curl https://example.com/install.sh | sh
        """
        f = run_check(cfg, "TKN-008")
        assert not f.passed

    def test_passes_with_verify_then_run(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: t
        spec:
          steps:
            - name: install
              image: alpine:3
              script: |
                curl -fsSLO https://example.com/install.sh
                sha256sum -c install.sh.sha256
                bash install.sh
        """
        f = run_check(cfg, "TKN-008")
        assert f.passed
