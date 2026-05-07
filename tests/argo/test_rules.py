"""Per-rule tests for every ARGO-* check."""
from __future__ import annotations

from .conftest import run_check


# ── ARGO-001 image pinning ─────────────────────────────────────────────


class TestARGO001ImagePinning:
    def test_passes_with_digest_pinned_image(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: w
        spec:
          entrypoint: main
          serviceAccountName: ci
          activeDeadlineSeconds: 600
          templates:
            - name: main
              container:
                image: alpine@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b
        """
        f = run_check(cfg, "ARGO-001")
        assert f.passed

    def test_fails_with_tag_only_image(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: w
        spec:
          entrypoint: main
          templates:
            - name: main
              container:
                image: alpine:3.18
        """
        f = run_check(cfg, "ARGO-001")
        assert not f.passed


# ── ARGO-002 privileged container ──────────────────────────────────────


class TestARGO002PrivilegedContainer:
    def test_fails_when_privileged_true(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: w
        spec:
          entrypoint: main
          templates:
            - name: main
              container:
                image: alpine:3
                securityContext:
                  privileged: true
        """
        f = run_check(cfg, "ARGO-002")
        assert not f.passed

    def test_passes_with_hardened_context(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: w
        spec:
          entrypoint: main
          templates:
            - name: main
              container:
                image: alpine:3
                securityContext:
                  privileged: false
                  runAsNonRoot: true
                  allowPrivilegeEscalation: false
        """
        f = run_check(cfg, "ARGO-002")
        assert f.passed


# ── ARGO-003 default SA ────────────────────────────────────────────────


class TestARGO003DefaultServiceAccount:
    def test_fails_when_sa_missing(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: w
        spec:
          entrypoint: main
          templates:
            - name: main
              container: {image: alpine:3}
        """
        f = run_check(cfg, "ARGO-003")
        assert not f.passed

    def test_fails_when_sa_default(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: w
        spec:
          entrypoint: main
          serviceAccountName: default
          templates:
            - name: main
              container: {image: alpine:3}
        """
        f = run_check(cfg, "ARGO-003")
        assert not f.passed

    def test_passes_with_explicit_sa(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: w
        spec:
          entrypoint: main
          serviceAccountName: ci-runner
          templates:
            - name: main
              container: {image: alpine:3}
        """
        f = run_check(cfg, "ARGO-003")
        assert f.passed


# ── ARGO-004 host namespace ────────────────────────────────────────────


class TestARGO004HostNamespace:
    def test_fails_with_host_path_volume(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: w
        spec:
          entrypoint: main
          serviceAccountName: ci
          volumes:
            - name: dock
              hostPath:
                path: /var/run/docker.sock
          templates:
            - name: main
              container: {image: alpine:3}
        """
        f = run_check(cfg, "ARGO-004")
        assert not f.passed

    def test_passes_without_host_volumes(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: w
        spec:
          entrypoint: main
          serviceAccountName: ci
          volumes:
            - name: scratch
              emptyDir: {}
          templates:
            - name: main
              container: {image: alpine:3}
        """
        f = run_check(cfg, "ARGO-004")
        assert f.passed


# ── ARGO-005 param injection ───────────────────────────────────────────


class TestARGO005ParamInjection:
    def test_fails_when_input_param_unquoted_in_script(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: w
        spec:
          entrypoint: main
          serviceAccountName: ci
          templates:
            - name: main
              inputs:
                parameters: [{name: ref}]
              script:
                image: alpine:3
                command: [bash]
                source: |
                  echo Building {{inputs.parameters.ref}}
        """
        f = run_check(cfg, "ARGO-005")
        assert not f.passed

    def test_passes_when_param_via_env_quoted(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: w
        spec:
          entrypoint: main
          serviceAccountName: ci
          templates:
            - name: main
              inputs:
                parameters: [{name: ref}]
              script:
                image: alpine:3
                command: [bash]
                env:
                  - name: REF
                    value: "{{inputs.parameters.ref}}"
                source: |
                  echo "Building $REF"
        """
        f = run_check(cfg, "ARGO-005")
        assert f.passed


# ── ARGO-006 literal secrets ───────────────────────────────────────────


class TestARGO006LiteralSecrets:
    def test_fails_with_aws_key_in_template_env(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: w
        spec:
          entrypoint: main
          serviceAccountName: ci
          templates:
            - name: main
              container:
                image: alpine:3
                env:
                  - name: AWS_ACCESS_KEY_ID
                    value: "AKIAIOSFODNN7EXAMPLE"
        """
        f = run_check(cfg, "ARGO-006")
        assert not f.passed

    def test_passes_with_secret_ref(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: w
        spec:
          entrypoint: main
          serviceAccountName: ci
          templates:
            - name: main
              container:
                image: alpine:3
                env:
                  - name: TOKEN
                    valueFrom:
                      secretKeyRef:
                        name: deploy
                        key: token
        """
        f = run_check(cfg, "ARGO-006")
        assert f.passed


# ── ARGO-007 activeDeadlineSeconds ────────────────────────────────────


class TestARGO007NoDeadline:
    def test_fails_when_deadline_absent(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: w
        spec:
          entrypoint: main
          serviceAccountName: ci
          templates:
            - name: main
              container: {image: alpine:3}
        """
        f = run_check(cfg, "ARGO-007")
        assert not f.passed

    def test_passes_with_workflow_level_deadline(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: w
        spec:
          entrypoint: main
          serviceAccountName: ci
          activeDeadlineSeconds: 3600
          templates:
            - name: main
              container: {image: alpine:3}
        """
        f = run_check(cfg, "ARGO-007")
        assert f.passed


# ── ARGO-008 curl-pipe / TLS bypass ────────────────────────────────────


class TestARGO008CurlPipe:
    def test_fails_with_curl_pipe(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: w
        spec:
          entrypoint: main
          serviceAccountName: ci
          templates:
            - name: main
              script:
                image: alpine:3
                command: [bash]
                source: |
                  curl https://example.com/install.sh | sh
        """
        f = run_check(cfg, "ARGO-008")
        assert not f.passed

    def test_passes_with_verify_then_run(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: w
        spec:
          entrypoint: main
          serviceAccountName: ci
          templates:
            - name: main
              script:
                image: alpine:3
                command: [bash]
                source: |
                  curl -fsSLO https://example.com/install.sh
                  sha256sum -c install.sh.sha256
                  bash install.sh
        """
        f = run_check(cfg, "ARGO-008")
        assert f.passed
