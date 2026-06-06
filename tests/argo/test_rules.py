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

    def test_fails_when_podspecpatch_json_sets_host_network(self):
        # podSpecPatch as a JSON-merge-patch string. The dict branch
        # of _scan_pod_spec_patch parses it and trips on the truthy
        # ``hostNetwork`` key.
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: w
        spec:
          entrypoint: main
          serviceAccountName: ci
          podSpecPatch: '{"hostNetwork": true, "hostPID": true}'
          templates:
            - name: main
              container: {image: alpine:3}
        """
        f = run_check(cfg, "ARGO-004")
        assert not f.passed
        assert "hostNetwork" in f.description
        assert "hostPID" in f.description

    def test_fails_when_podspecpatch_json_carries_hostpath(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: w
        spec:
          entrypoint: main
          serviceAccountName: ci
          podSpecPatch: '{"hostPath": {"path": "/"}}'
          templates:
            - name: main
              container: {image: alpine:3}
        """
        f = run_check(cfg, "ARGO-004")
        assert not f.passed
        assert "hostPath" in f.description

    def test_fails_when_podspecpatch_regex_catches_host_namespace(self):
        # YAML-flavored podSpecPatch that doesn't parse as JSON falls
        # through to the regex branch. ``hostIPC: true`` must still fire.
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: w
        spec:
          entrypoint: main
          serviceAccountName: ci
          podSpecPatch: |
            hostIPC: true
            containers:
              - name: side
                image: alpine:3
          templates:
            - name: main
              container: {image: alpine:3}
        """
        f = run_check(cfg, "ARGO-004")
        assert not f.passed
        assert "hostIPC" in f.description

    def test_fails_when_podspecpatch_regex_catches_hostpath(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: w
        spec:
          entrypoint: main
          serviceAccountName: ci
          podSpecPatch: |
            volumes:
              - name: root
                hostPath:
                  path: /
          templates:
            - name: main
              container: {image: alpine:3}
        """
        f = run_check(cfg, "ARGO-004")
        assert not f.passed
        assert "hostPath" in f.description

    def test_passes_when_podspecpatch_is_benign(self):
        # podSpecPatch that doesn't mention any host-* keys must not
        # FP via the regex fallback.
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: w
        spec:
          entrypoint: main
          serviceAccountName: ci
          podSpecPatch: |
            containers:
              - name: side
                image: alpine:3
                resources:
                  limits: {memory: 256Mi}
          templates:
            - name: main
              container: {image: alpine:3}
        """
        f = run_check(cfg, "ARGO-004")
        assert f.passed

    def test_passes_with_no_argo_documents(self):
        # ARGO-004 silent-passes when the context loader didn't find
        # any Argo documents (the no-docs early-return at line 89).
        from pipeline_check.core.checks.argo.base import ArgoContext
        from pipeline_check.core.checks.argo.rules.argo004_host_namespace import (
            check,
        )
        f = check(ArgoContext(docs=[]))
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
                    value: "AKIAZ3MHALF2TESTHIJK"
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

    def test_fails_with_modern_token_under_innocuous_name(self):
        # A GitLab PAT under a non-credential-looking env name, caught by
        # the shared vendor-token catalog, not the name heuristic.
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
                  - name: REGISTRY_AUTH
                    value: "glpat-abcdefghij1234567890"
        """
        f = run_check(cfg, "ARGO-006")
        assert not f.passed


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


# ── ARGO-009 signing ───────────────────────────────────────────────────


class TestARGO009Signing:
    def test_passes_with_cosign_step(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          templates:
            - name: main
              script:
                image: alpine:3
                command: [bash]
                source: |
                  docker build -t app .
                  cosign sign --yes app
                  docker push app
        """
        f = run_check(cfg, "ARGO-009")
        assert f.passed

    def test_fails_when_artifact_built_without_signing(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          templates:
            - name: main
              script:
                image: alpine:3
                command: [bash]
                source: |
                  docker build -t app .
                  docker push app
        """
        f = run_check(cfg, "ARGO-009")
        assert not f.passed

    def test_passes_when_no_artifacts_produced(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: lint
        spec:
          entrypoint: main
          templates:
            - name: main
              script:
                image: alpine:3
                command: [bash]
                source: pytest tests/
        """
        f = run_check(cfg, "ARGO-009")
        assert f.passed


# ── ARGO-010 SBOM ──────────────────────────────────────────────────────


class TestARGO010SBOM:
    def test_passes_with_syft_step(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          templates:
            - name: main
              script:
                image: alpine:3
                command: [bash]
                source: |
                  docker build -t app .
                  syft app -o cyclonedx-json > sbom.json
                  docker push app
        """
        f = run_check(cfg, "ARGO-010")
        assert f.passed

    def test_fails_when_artifact_built_without_sbom(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          templates:
            - name: main
              script:
                image: alpine:3
                command: [bash]
                source: |
                  docker build -t app .
                  docker push app
        """
        f = run_check(cfg, "ARGO-010")
        assert not f.passed


# ── ARGO-011 SLSA provenance ───────────────────────────────────────────


class TestARGO011SLSAProvenance:
    def test_passes_with_cosign_attest(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          templates:
            - name: main
              script:
                image: alpine:3
                command: [bash]
                source: |
                  docker build -t app .
                  cosign attest --predicate provenance.json --type slsaprovenance app
                  docker push app
        """
        f = run_check(cfg, "ARGO-011")
        assert f.passed

    def test_fails_when_artifact_built_without_provenance(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          templates:
            - name: main
              script:
                image: alpine:3
                command: [bash]
                source: |
                  docker build -t app .
                  docker push app
        """
        f = run_check(cfg, "ARGO-011")
        assert not f.passed


# ── ARGO-012 vuln scanning ─────────────────────────────────────────────


class TestARGO012VulnScanning:
    def test_passes_with_trivy_step(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: scan
        spec:
          entrypoint: main
          templates:
            - name: main
              script:
                image: aquasec/trivy:latest
                command: [sh]
                source: trivy fs --severity HIGH,CRITICAL --exit-code 1 .
        """
        f = run_check(cfg, "ARGO-012")
        assert f.passed

    def test_passes_with_grype_step(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: scan
        spec:
          entrypoint: main
          templates:
            - name: main
              script:
                image: anchore/grype:latest
                command: [sh]
                source: grype dir:.
        """
        f = run_check(cfg, "ARGO-012")
        assert f.passed

    def test_fails_when_no_scanner_invoked(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          templates:
            - name: main
              script:
                image: alpine:3
                command: [bash]
                source: |
                  docker build -t app .
                  cosign sign app
        """
        f = run_check(cfg, "ARGO-012")
        assert not f.passed


# ── ARGO-013 SA token automount ────────────────────────────────────────


class TestARGO013AutomountToken:
    def test_passes_with_spec_level_opt_out(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          automountServiceAccountToken: false
          templates:
            - name: main
              script:
                image: alpine:3
                command: [bash]
                source: ls
        """
        f = run_check(cfg, "ARGO-013")
        assert f.passed

    def test_passes_with_template_level_opt_out(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          templates:
            - name: main
              automountServiceAccountToken: false
              script:
                image: alpine:3
                command: [bash]
                source: ls
        """
        f = run_check(cfg, "ARGO-013")
        assert f.passed

    def test_passes_when_template_explicitly_opts_in(self):
        # Explicit opt-in is the legitimate K8s-API-using case;
        # don't fail on it. The user took an explicit decision.
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: gitops
        spec:
          entrypoint: main
          automountServiceAccountToken: false
          templates:
            - name: main
              automountServiceAccountToken: true
              script:
                image: bitnami/kubectl:latest
                command: [sh]
                source: kubectl apply -f deploy/
        """
        f = run_check(cfg, "ARGO-013")
        assert f.passed

    def test_fails_when_neither_spec_nor_template_opts_out(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          templates:
            - name: main
              script:
                image: alpine:3
                command: [bash]
                source: ls
        """
        f = run_check(cfg, "ARGO-013")
        assert not f.passed


# ── ARGO-014 unpinned package install ──────────────────────────────────


class TestARGO014PkgUnpinned:
    def test_passes_with_npm_ci(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          templates:
            - name: main
              script:
                image: alpine:3
                command: [bash]
                source: |
                  npm ci
                  npm test
        """
        f = run_check(cfg, "ARGO-014")
        assert f.passed

    def test_fails_on_bare_npm_install(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          templates:
            - name: main
              script:
                image: alpine:3
                command: [bash]
                source: npm install
        """
        f = run_check(cfg, "ARGO-014")
        assert not f.passed
        assert "unpinned" in f.description

    def test_fails_on_pip_trusted_host(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          templates:
            - name: main
              script:
                image: alpine:3
                command: [bash]
                source: pip install --trusted-host pypi.local pkg
        """
        f = run_check(cfg, "ARGO-014")
        assert not f.passed

    def test_fails_on_container_args(self):
        # Argo supports container.args plus container.command (not
        # just script.source); the joined-text walker scans both.
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          templates:
            - name: main
              container:
                image: alpine:3
                command: [sh, -c]
                args:
                  - npm install
        """
        f = run_check(cfg, "ARGO-014")
        assert not f.passed

    def test_passes_with_pip_lockfile(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          templates:
            - name: main
              script:
                image: alpine:3
                command: [bash]
                source: pip install -r requirements.txt
        """
        f = run_check(cfg, "ARGO-014")
        assert f.passed


# ── ARGO-015 insecure artifact URL ─────────────────────────────────────


class TestARGO015ArtifactInsecureURL:
    def test_passes_with_https_http_artifact(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          templates:
            - name: main
              inputs:
                artifacts:
                  - name: tarball
                    path: /tmp/x.tar
                    http:
                      url: https://example.com/x.tar
              script:
                image: alpine:3
                command: [sh]
                source: ls
        """
        f = run_check(cfg, "ARGO-015")
        assert f.passed

    def test_fails_on_http_url(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          templates:
            - name: main
              inputs:
                artifacts:
                  - name: tarball
                    path: /tmp/x.tar
                    http:
                      url: http://internal/x.tar
              script:
                image: alpine:3
                command: [sh]
                source: ls
        """
        f = run_check(cfg, "ARGO-015")
        assert not f.passed
        assert "http.url" in f.description

    def test_fails_on_git_protocol_repo(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          templates:
            - name: main
              inputs:
                artifacts:
                  - name: src
                    path: /src
                    git:
                      repo: git://gitserver.local/x.git
              script:
                image: alpine:3
                command: [sh]
                source: ls
        """
        f = run_check(cfg, "ARGO-015")
        assert not f.passed
        assert "git.repo" in f.description

    def test_fails_on_s3_with_insecure_true(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          templates:
            - name: main
              inputs:
                artifacts:
                  - name: data
                    path: /data
                    s3:
                      endpoint: minio.local
                      bucket: x
                      key: data.tar
                      insecure: true
              script:
                image: alpine:3
                command: [sh]
                source: ls
        """
        f = run_check(cfg, "ARGO-015")
        assert not f.passed
        assert "s3 insecure" in f.description

    def test_passes_on_https_git_repo(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          templates:
            - name: main
              inputs:
                artifacts:
                  - name: src
                    path: /src
                    git:
                      repo: https://github.com/example/x.git
              script:
                image: alpine:3
                command: [sh]
                source: ls
        """
        f = run_check(cfg, "ARGO-015")
        assert f.passed

    def test_passes_when_no_artifacts(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          templates:
            - name: main
              script:
                image: alpine:3
                command: [sh]
                source: ls
        """
        f = run_check(cfg, "ARGO-015")
        assert f.passed


class TestARGO016ClusterAdminServiceAccount:
    def test_fails_on_cluster_admin_sa(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: deploy
        spec:
          serviceAccountName: cluster-admin
          entrypoint: main
          templates:
            - name: main
              container:
                image: kubectl@sha256:0000000000000000000000000000000000000000000000000000000000000001
                args: ["kubectl get secrets -A"]
        """
        f = run_check(cfg, "ARGO-016")
        assert not f.passed
        assert "cluster-admin" in f.description

    def test_fails_on_name_containing_cluster_admin(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata: {name: d}
        spec:
          serviceAccountName: my-cluster-admin-sa
          entrypoint: main
          templates:
            - name: main
              container: {image: "x@sha256:0000000000000000000000000000000000000000000000000000000000000001"}
        """
        f = run_check(cfg, "ARGO-016")
        assert not f.passed

    def test_fails_on_admin_sa(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata: {name: d}
        spec:
          serviceAccountName: admin
          entrypoint: main
          templates:
            - name: main
              container: {image: "x@sha256:0000000000000000000000000000000000000000000000000000000000000001"}
        """
        f = run_check(cfg, "ARGO-016")
        assert not f.passed

    def test_passes_on_least_privilege_named_sa(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata: {name: d}
        spec:
          serviceAccountName: ci-deploy-sa
          entrypoint: main
          templates:
            - name: main
              container: {image: "x@sha256:0000000000000000000000000000000000000000000000000000000000000001"}
        """
        f = run_check(cfg, "ARGO-016")
        assert f.passed

    def test_passes_when_no_sa(self):
        # No serviceAccountName is ARGO-003's concern, not ARGO-016's.
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata: {name: d}
        spec:
          entrypoint: main
          templates:
            - name: main
              container: {image: "x@sha256:0000000000000000000000000000000000000000000000000000000000000001"}
        """
        f = run_check(cfg, "ARGO-016")
        assert f.passed


# ── ARGO-017 resource-template manifest injection ──────────────────────


class TestARGO017ResourceManifestInjection:
    def test_fails_when_apply_manifest_interpolates_param(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: WorkflowTemplate
        metadata: {name: provision}
        spec:
          entrypoint: apply
          templates:
            - name: apply
              inputs: {parameters: [{name: spec}]}
              resource:
                action: apply
                manifest: |
                  apiVersion: v1
                  kind: ConfigMap
                  data: {payload: "{{inputs.parameters.spec}}"}
        """
        f = run_check(cfg, "ARGO-017")
        assert not f.passed
        assert "WorkflowTemplate/provision:apply" in f.job_anchors

    def test_fails_on_create_with_workflow_param(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata: {name: w}
        spec:
          entrypoint: main
          templates:
            - name: main
              resource:
                action: create
                manifest: |
                  kind: Pod
                  metadata: {name: "{{workflow.parameters.name}}"}
        """
        f = run_check(cfg, "ARGO-017")
        assert not f.passed

    def test_fails_on_expr_template_param(self):
        # The expr-template ``{{= ... }}`` form reaches the same text sink.
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: WorkflowTemplate
        metadata: {name: provision}
        spec:
          entrypoint: apply
          templates:
            - name: apply
              inputs: {parameters: [{name: spec}]}
              resource:
                action: apply
                manifest: |
                  apiVersion: v1
                  kind: ConfigMap
                  data: {payload: "{{=inputs.parameters.spec}}"}
        """
        f = run_check(cfg, "ARGO-017")
        assert not f.passed

    def test_fails_on_bracket_index_param(self):
        # Bracket access ``parameters['spec']`` is the same sink as dotted.
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: WorkflowTemplate
        metadata: {name: provision}
        spec:
          entrypoint: apply
          templates:
            - name: apply
              inputs: {parameters: [{name: spec}]}
              resource:
                action: apply
                manifest: |
                  apiVersion: v1
                  kind: ConfigMap
                  data: {payload: "{{ inputs.parameters['spec'] }}"}
        """
        f = run_check(cfg, "ARGO-017")
        assert not f.passed

    def test_passes_on_fixed_manifest(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: WorkflowTemplate
        metadata: {name: provision}
        spec:
          entrypoint: apply
          templates:
            - name: apply
              resource:
                action: apply
                manifest: |
                  apiVersion: v1
                  kind: ConfigMap
                  data: {payload: fixed-value}
        """
        f = run_check(cfg, "ARGO-017")
        assert f.passed

    def test_passes_on_read_only_get_action(self):
        # ``get`` is read-only: a param in the selector can't create objects.
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: WorkflowTemplate
        metadata: {name: lookup}
        spec:
          templates:
            - name: get
              resource:
                action: get
                manifest: |
                  kind: Pod
                  metadata: {name: "{{inputs.parameters.x}}"}
        """
        f = run_check(cfg, "ARGO-017")
        assert f.passed

    def test_passes_when_no_resource_template(self):
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata: {name: w}
        spec:
          entrypoint: main
          templates:
            - name: main
              container: {image: "x@sha256:0000000000000000000000000000000000000000000000000000000000000001"}
        """
        f = run_check(cfg, "ARGO-017")
        assert f.passed
