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

    def test_taskrun_passes_with_timeout(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: TaskRun
        metadata:
          name: tr
        spec:
          taskRef:
            name: t
          serviceAccountName: ci-runner
          timeout: "30m"
        """
        f = run_check(cfg, "TKN-006")
        assert f.passed

    def test_pipeline_fails_when_mixed_task_timeouts(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Pipeline
        metadata:
          name: p
        spec:
          tasks:
            - name: build
              timeout: "10m"
              taskRef:
                name: build-task
            - name: deploy
              taskRef:
                name: deploy-task
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


# ── TKN-009 signing ────────────────────────────────────────────────────


class TestTKN009Signing:
    def test_passes_with_cosign_step(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: build
        spec:
          steps:
            - name: build
              image: alpine:3
              script: |
                docker build -t app:latest .
                cosign sign --yes app:latest
                docker push app:latest
        """
        f = run_check(cfg, "TKN-009")
        assert f.passed

    def test_fails_when_artifact_built_without_signing(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: build
        spec:
          steps:
            - name: build
              image: alpine:3
              script: |
                docker build -t app:latest .
                docker push app:latest
        """
        f = run_check(cfg, "TKN-009")
        assert not f.passed

    def test_passes_when_no_artifacts_produced(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: lint
        spec:
          steps:
            - name: test
              image: alpine:3
              script: |
                pytest tests/
        """
        f = run_check(cfg, "TKN-009")
        assert f.passed


# ── TKN-010 SBOM ───────────────────────────────────────────────────────


class TestTKN010SBOM:
    def test_passes_with_syft_step(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: build
        spec:
          steps:
            - name: build
              image: alpine:3
              script: |
                docker build -t app:latest .
                syft app:latest -o cyclonedx-json > sbom.json
                docker push app:latest
        """
        f = run_check(cfg, "TKN-010")
        assert f.passed

    def test_fails_when_artifact_built_without_sbom(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: build
        spec:
          steps:
            - name: build
              image: alpine:3
              script: |
                docker build -t app:latest .
                docker push app:latest
        """
        f = run_check(cfg, "TKN-010")
        assert not f.passed

    def test_passes_when_no_artifacts_produced(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: lint
        spec:
          steps:
            - name: test
              image: alpine:3
              script: pytest tests/
        """
        f = run_check(cfg, "TKN-010")
        assert f.passed


# ── TKN-011 SLSA provenance ────────────────────────────────────────────


class TestTKN011SLSAProvenance:
    def test_passes_with_cosign_attest(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: build
        spec:
          steps:
            - name: build
              image: alpine:3
              script: |
                docker build -t app:latest .
                cosign attest --predicate provenance.json --type slsaprovenance app:latest
                docker push app:latest
        """
        f = run_check(cfg, "TKN-011")
        assert f.passed

    def test_fails_when_artifact_built_without_provenance(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: build
        spec:
          steps:
            - name: build
              image: alpine:3
              script: |
                docker build -t app:latest .
                docker push app:latest
        """
        f = run_check(cfg, "TKN-011")
        assert not f.passed


# ── TKN-012 vuln scanning ──────────────────────────────────────────────


class TestTKN012VulnScanning:
    def test_passes_with_trivy_step(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: build
        spec:
          steps:
            - name: scan
              image: aquasec/trivy:latest
              script: |
                trivy fs --severity HIGH,CRITICAL --exit-code 1 .
        """
        f = run_check(cfg, "TKN-012")
        assert f.passed

    def test_passes_with_grype_step(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: build
        spec:
          steps:
            - name: scan
              image: anchore/grype:latest
              script: grype dir:.
        """
        f = run_check(cfg, "TKN-012")
        assert f.passed

    def test_fails_when_no_scanner_invoked(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: build
        spec:
          steps:
            - name: build
              image: alpine:3
              script: |
                docker build -t app .
                cosign sign app
        """
        f = run_check(cfg, "TKN-012")
        assert not f.passed


# ── TKN-013 sidecar privilege escalation ───────────────────────────────


class TestTKN013SidecarPrivileged:
    def test_fails_with_privileged_sidecar(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: build
        spec:
          sidecars:
            - name: docker-daemon
              image: docker:24-dind
              securityContext:
                privileged: true
                runAsNonRoot: false
          steps:
            - name: build
              image: alpine:3
              securityContext:
                privileged: false
                runAsNonRoot: true
                allowPrivilegeEscalation: false
              script: docker build -t app .
        """
        f = run_check(cfg, "TKN-013")
        assert not f.passed
        assert "privileged: true" in f.description

    def test_fails_with_sidecar_no_security_context(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: build
        spec:
          sidecars:
            - name: redis
              image: redis:7
          steps:
            - name: build
              image: alpine:3
              script: ls
        """
        f = run_check(cfg, "TKN-013")
        assert not f.passed

    def test_passes_with_hardened_sidecar(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: build
        spec:
          sidecars:
            - name: redis
              image: redis:7
              securityContext:
                privileged: false
                runAsNonRoot: true
                allowPrivilegeEscalation: false
          steps:
            - name: build
              image: alpine:3
              script: ls
        """
        f = run_check(cfg, "TKN-013")
        assert f.passed

    def test_passes_when_no_sidecars_declared(self):
        # TKN-002 already covers steps; TKN-013 should not fire on a
        # Task that doesn't declare any sidecars at all.
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: build
        spec:
          steps:
            - name: build
              image: alpine:3
              script: ls
        """
        f = run_check(cfg, "TKN-013")
        assert f.passed


# ── TKN-014 unpinned package install ───────────────────────────────────


class TestTKN014PkgUnpinned:
    def test_passes_with_npm_ci(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: build
        spec:
          steps:
            - name: build
              image: alpine:3
              script: |
                npm ci
                npm test
        """
        f = run_check(cfg, "TKN-014")
        assert f.passed

    def test_fails_on_bare_npm_install(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: build
        spec:
          steps:
            - name: build
              image: alpine:3
              script: npm install
        """
        f = run_check(cfg, "TKN-014")
        assert not f.passed
        assert "unpinned" in f.description

    def test_fails_on_pip_trusted_host(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: build
        spec:
          steps:
            - name: build
              image: alpine:3
              script: pip install --trusted-host pypi.local pkg
        """
        f = run_check(cfg, "TKN-014")
        assert not f.passed

    def test_passes_with_pip_lockfile(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: build
        spec:
          steps:
            - name: build
              image: alpine:3
              script: pip install -r requirements.txt
        """
        f = run_check(cfg, "TKN-014")
        assert f.passed

    def test_passes_when_no_task_documents(self):
        # PipelineRun-only doc has no Task / ClusterTask, so TKN-014
        # has nothing to scan.
        cfg = """
        apiVersion: tekton.dev/v1
        kind: PipelineRun
        metadata:
          name: r
        spec:
          pipelineRef:
            name: p
        """
        f = run_check(cfg, "TKN-014")
        assert f.passed


# ── TKN-015 workspace subPath param injection ──────────────────────────


class TestTKN015WorkspaceSubpathInjection:
    def test_passes_with_static_subpath(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: t
        spec:
          steps:
            - name: build
              image: alpine
              workspaces:
                - name: source
                  subPath: build/output
              script: echo ok
        """
        f = run_check(cfg, "TKN-015")
        assert f.passed

    def test_fails_when_subpath_uses_params(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: t
        spec:
          params:
            - name: target
          steps:
            - name: build
              image: alpine
              workspaces:
                - name: source
                  subPath: $(params.target)
              script: echo ok
        """
        f = run_check(cfg, "TKN-015")
        assert not f.passed
        assert "params.target" in f.description

    def test_fails_when_subpath_concats_param(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: t
        spec:
          params:
            - name: ref
          steps:
            - name: build
              image: alpine
              workspaces:
                - name: source
                  subPath: build/$(params.ref)
              script: echo ok
        """
        f = run_check(cfg, "TKN-015")
        assert not f.passed
        assert "params.ref" in f.description

    def test_passes_when_subpath_uses_workspace_path(self):
        # ``$(workspaces.X.path)`` is server-controlled; not on the
        # tainted list. Only ``$(params.X)`` references fire.
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: t
        spec:
          steps:
            - name: build
              image: alpine
              workspaces:
                - name: source
                  subPath: $(workspaces.source.path)/build
              script: echo ok
        """
        f = run_check(cfg, "TKN-015")
        assert f.passed

    def test_passes_when_no_workspaces_block(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: Task
        metadata:
          name: t
        spec:
          steps:
            - name: build
              image: alpine
              script: echo ok
        """
        f = run_check(cfg, "TKN-015")
        assert f.passed

    def test_passes_on_pipelinerun_only_doc(self):
        cfg = """
        apiVersion: tekton.dev/v1
        kind: PipelineRun
        metadata:
          name: r
        spec:
          pipelineRef:
            name: p
        """
        f = run_check(cfg, "TKN-015")
        assert f.passed
