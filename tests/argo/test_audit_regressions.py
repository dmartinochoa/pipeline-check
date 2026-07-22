"""Regression tests from the rule audit (Argo batch 3 — example fixes)."""
from __future__ import annotations

from pipeline_check.core.checks.argo.rules import argo001_image_pinning as argo001
from pipeline_check.core.checks.argo.rules import (
    argo006_literal_secrets as argo006,
)

from .conftest import argo_ctx, run_check


class TestARGO001ImagePinning:
    def test_exploit_example_strong_check(self):
        # Safe fragment previously used ``@sha256:abc123...``, which is not a
        # valid 64-char lowercase-hex digest, so the check fired instead of
        # passing. Replaced with the full 64-char digest so the Safe fragment
        # actually passes.
        vuln, safe = argo001.RULE.exploit_example.split("\n\n", 1)
        assert argo001.check(argo_ctx(vuln)).passed is False
        assert argo001.check(argo_ctx(safe)).passed is True


class TestARGO006LiteralSecretsFP:
    """ARGO-006 false-positive regressions.

    Before the fix, _SECRET_KEY_RE matched KEY/TOKEN/SECRET anywhere inside
    an env var name, so CACHE_KEY and SSH_PRIVATE_KEY_PATH with a literal
    value >= 8 chars triggered the weak-match path incorrectly.
    """

    def test_cache_key_with_literal_value_passes(self):
        # CACHE_KEY is a build-cache lookup key, not a credential.
        # The value is a literal cache hash string — not a secret.
        ctx = argo_ctx("""
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          serviceAccountName: ci
          templates:
            - name: main
              container:
                image: alpine:3
                env:
                  - name: CACHE_KEY
                    value: "my-build-cache-v1-abcdef12"
        """)
        f = argo006.check(ctx)
        assert f.passed, (
            f"CACHE_KEY with a literal cache identifier should pass; got: {f.description}"
        )

    def test_ssh_private_key_path_with_path_value_passes(self):
        # SSH_PRIVATE_KEY_PATH carries a filesystem path, not a key material.
        ctx = argo_ctx("""
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          serviceAccountName: ci
          templates:
            - name: main
              container:
                image: alpine:3
                env:
                  - name: SSH_PRIVATE_KEY_PATH
                    value: "/home/runner/.ssh/id_rsa"
        """)
        f = argo006.check(ctx)
        assert f.passed, (
            f"SSH_PRIVATE_KEY_PATH with a path value should pass; got: {f.description}"
        )

    def test_ssh_private_key_path_with_literal_string_passes(self):
        # The _PATH suffix in the name is the key indicator; even a non-path
        # literal value should not fire because the name pattern is excluded.
        ctx = argo_ctx("""
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          serviceAccountName: ci
          templates:
            - name: main
              container:
                image: alpine:3
                env:
                  - name: SSH_PRIVATE_KEY_PATH
                    value: "some-reference-string-here"
        """)
        f = argo006.check(ctx)
        assert f.passed, (
            "SSH_PRIVATE_KEY_PATH name is excluded by the _PATH suffix rule; "
            f"got: {f.description}"
        )

    def test_s3_key_prefix_with_literal_passes(self):
        # S3_KEY_PREFIX describes a storage path prefix, not a secret.
        ctx = argo_ctx("""
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          serviceAccountName: ci
          templates:
            - name: main
              container:
                image: alpine:3
                env:
                  - name: S3_KEY_PREFIX
                    value: "artifacts/builds/main/"
        """)
        f = argo006.check(ctx)
        assert f.passed, (
            f"S3_KEY_PREFIX is not a credential name and should pass; got: {f.description}"
        )

    # ── True-positive guard: real secrets must still fire ─────────────────

    def test_api_key_with_literal_value_fires(self):
        # API_KEY with a short opaque literal value is a genuine secret.
        ctx = argo_ctx("""
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          serviceAccountName: ci
          templates:
            - name: main
              container:
                image: alpine:3
                env:
                  - name: API_KEY
                    value: "abcdef1234567890"
        """)
        f = argo006.check(ctx)
        assert not f.passed, (
            "API_KEY with a literal value must fire; got passed=True"
        )

    def test_aws_secret_access_key_fires(self):
        # AWS credentials must always be detected by the weak-match path.
        ctx = argo_ctx("""
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          serviceAccountName: ci
          templates:
            - name: main
              container:
                image: alpine:3
                env:
                  - name: AWS_SECRET_ACCESS_KEY
                    value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        """)
        f = argo006.check(ctx)
        assert not f.passed, (
            "AWS_SECRET_ACCESS_KEY with a literal value must fire; "
            f"got passed=True, description={f.description}"
        )

    def test_strong_pattern_aws_access_key_fires_regardless_of_name(self):
        # A strong-pattern match (AKIA... prefix) fires even for benign-looking
        # env var names because it matches the value directly.
        ctx = argo_ctx("""
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          serviceAccountName: ci
          templates:
            - name: main
              container:
                image: alpine:3
                env:
                  - name: CACHE_KEY
                    value: "AKIAZ3MHALF2TESTHIJK"
        """)
        f = argo006.check(ctx)
        assert not f.passed, (
            "An AKIA-pattern value must fire via the strong-match path even "
            "when the env var is named CACHE_KEY; got passed=True"
        )

    def test_my_token_with_literal_fires(self):
        ctx = argo_ctx("""
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          serviceAccountName: ci
          templates:
            - name: main
              container:
                image: alpine:3
                env:
                  - name: MY_TOKEN
                    value: "s3cr3tTokenValue!"
        """)
        f = argo006.check(ctx)
        assert not f.passed, (
            "MY_TOKEN with a literal value must fire; got passed=True"
        )

    def test_db_password_fires(self):
        ctx = argo_ctx("""
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build
        spec:
          entrypoint: main
          serviceAccountName: ci
          templates:
            - name: main
              container:
                image: alpine:3
                env:
                  - name: DB_PASSWORD
                    value: "hunter2hunter2"
        """)
        f = argo006.check(ctx)
        assert not f.passed, (
            "DB_PASSWORD with a literal value must fire; got passed=True"
        )


# ── ARGO-009 batch-5 FN: kaniko not recognized as artifact producer ────


class TestARGO009KanikoArtifactProducer:
    """ARGO-009: a Workflow that uses kaniko to build and push an image
    must be treated as artifact-producing so the signing check fires when
    no signing tool is present."""

    _KANIKO_UNSIGNED = """
    apiVersion: argoproj.io/v1alpha1
    kind: Workflow
    metadata:
      name: kaniko-build
    spec:
      entrypoint: main
      templates:
        - name: main
          container:
            image: gcr.io/kaniko-project/executor:v1.23.0
            args:
              - --context=.
              - --destination=registry.example.com/app:latest
    """

    _KANIKO_SIGNED = """
    apiVersion: argoproj.io/v1alpha1
    kind: Workflow
    metadata:
      name: kaniko-build-signed
    spec:
      entrypoint: main
      templates:
        - name: build
          container:
            image: gcr.io/kaniko-project/executor:v1.23.0
            args:
              - --context=.
              - --destination=registry.example.com/app:latest
        - name: sign
          container:
            image: alpine:3
            command: [sh, -c]
            args: ["cosign sign --yes registry.example.com/app:latest"]
        - name: main
          steps:
            - - name: build
                template: build
            - - name: sign
                template: sign
    """

    def test_unsigned_kaniko_workflow_fires_argo009(self):
        # Previously: kaniko was absent from _ARTIFACT_TOKENS, so
        # produces_artifacts() returned False and ARGO-009 silently passed.
        f = run_check(self._KANIKO_UNSIGNED, "ARGO-009")
        assert not f.passed, (
            "ARGO-009 must fire on a kaniko workflow with no signing step"
        )

    def test_signed_kaniko_workflow_passes_argo009(self):
        # A kaniko workflow that also runs cosign must pass.
        f = run_check(self._KANIKO_SIGNED, "ARGO-009")
        assert f.passed, (
            "ARGO-009 must pass when the kaniko workflow includes cosign"
        )

    def test_lint_only_workflow_still_passes_argo009(self):
        # A workflow with no artifact-production token must still skip the check.
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: lint
        spec:
          entrypoint: main
          templates:
            - name: main
              container:
                image: golangci/golangci-lint:v1.57
                command: [golangci-lint, run]
        """
        f = run_check(cfg, "ARGO-009")
        assert f.passed, (
            "ARGO-009 must pass (no artifact) on a lint-only workflow"
        )


# ── ARGO-010 batch-5 FN: cdxgen not in SBOM_DIRECT_TOKENS ────────────


class TestARGO010CdxgenSBOM:
    """ARGO-010: cdxgen was named in the recommendation text but absent
    from SBOM_DIRECT_TOKENS, so a workflow using ``cdxgen -o sbom.json``
    was incorrectly flagged as having no SBOM."""

    def test_cdxgen_sbom_step_passes_argo010(self):
        # A kaniko build with a cdxgen SBOM step must pass ARGO-010.
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: build-with-sbom
        spec:
          entrypoint: main
          templates:
            - name: main
              container:
                image: alpine:3
                command: [sh, -c]
                args:
                  - |
                    kaniko --context=. --destination=registry.example.com/app:latest
                    cdxgen -o sbom.json .
        """
        f = run_check(cfg, "ARGO-010")
        assert f.passed, (
            "ARGO-010 must pass when cdxgen is invoked to generate an SBOM"
        )

    def test_unsigned_kaniko_no_sbom_fires_argo010(self):
        # A kaniko workflow with no SBOM generation must still fire.
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: kaniko-no-sbom
        spec:
          entrypoint: main
          templates:
            - name: main
              container:
                image: gcr.io/kaniko-project/executor:v1.23.0
                args:
                  - --context=.
                  - --destination=registry.example.com/app:latest
        """
        f = run_check(cfg, "ARGO-010")
        assert not f.passed, (
            "ARGO-010 must fire on a kaniko workflow with no SBOM step"
        )


# ── TAINT-007 steps: forwarding (STALE — already covered by batch 2) ──
#
# ``_TASKS_OUT_REF_RE`` in argo/_taint_graph.py already uses
# ``(?:tasks|steps)`` so ``{{steps.X.outputs.parameters.Y}}``
# forwarding is tracked.  No code change needed; the test below
# documents the existing behavior and pins it against regression.

class TestTAINT007StepsForwardingStale:
    def test_steps_orchestrator_taint_fires(self):
        # A steps: orchestrator that passes a tainted output param to
        # a consumer template should be detected by the existing engine.
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: Workflow
        metadata:
          name: w
        spec:
          entrypoint: main
          arguments:
            parameters:
              - name: pr-title
          templates:
            - name: main
              steps:
                - - name: extract
                    template: extract-tpl
                    arguments:
                      parameters:
                        - name: title
                          value: "{{workflow.parameters.pr-title}}"
                - - name: build
                    template: build-tpl
                    arguments:
                      parameters:
                        - name: title
                          value: "{{steps.extract.outputs.parameters.clean}}"
            - name: extract-tpl
              inputs:
                parameters:
                  - name: title
              outputs:
                parameters:
                  - name: clean
                    valueFrom:
                      path: /tmp/clean
              script:
                image: alpine:3
                command: [sh]
                source: echo '{{inputs.parameters.title}}' > /tmp/clean
            - name: build-tpl
              inputs:
                parameters:
                  - name: title
              script:
                image: alpine:3
                command: [sh]
                source: echo {{inputs.parameters.title}}
        """
        f = run_check(cfg, "TAINT-007")
        assert not f.passed


# ── ARGO-001 initContainers / sidecars image pinning ──────────────────


class TestARGO001InitContainerSidecarPinning:
    def test_unpinned_sidecar_image_fires(self):
        # A sidecar with a rolling :latest tag must be caught.
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: WorkflowTemplate
        metadata:
          name: w
        spec:
          templates:
            - name: main
              container:
                image: alpine@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b
              sidecars:
                - name: dind
                  image: docker:latest
        """
        f = run_check(cfg, "ARGO-001")
        assert not f.passed
        assert "docker:latest" in f.description

    def test_unpinned_init_container_image_fires(self):
        # An initContainer with a tag-only reference must be caught.
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: WorkflowTemplate
        metadata:
          name: w
        spec:
          templates:
            - name: main
              container:
                image: alpine@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b
              initContainers:
                - name: init
                  image: busybox:1.36
        """
        f = run_check(cfg, "ARGO-001")
        assert not f.passed
        assert "busybox:1.36" in f.description

    def test_digest_pinned_sidecar_and_init_passes(self):
        # All containers, sidecars, and initContainers digest-pinned: must pass.
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: WorkflowTemplate
        metadata:
          name: w
        spec:
          templates:
            - name: main
              container:
                image: alpine@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b
              sidecars:
                - name: dind
                  image: docker@sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
              initContainers:
                - name: init
                  image: busybox@sha256:b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3
        """
        f = run_check(cfg, "ARGO-001")
        assert f.passed

    def test_existing_container_tag_only_still_fires(self):
        # Pre-existing detection: a bare container image without a digest.
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


# ── ARGO-002 initContainers / sidecars privileged detection ───────────


class TestARGO002InitContainerSidecarPrivileged:
    def test_privileged_sidecar_fires(self):
        # A sidecar with privileged: true (docker-in-docker helper) must fire.
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: WorkflowTemplate
        metadata:
          name: w
        spec:
          templates:
            - name: main
              container:
                image: alpine:3
                securityContext:
                  privileged: false
                  runAsNonRoot: true
                  allowPrivilegeEscalation: false
              sidecars:
                - name: dind
                  image: docker:dind
                  securityContext:
                    privileged: true
        """
        f = run_check(cfg, "ARGO-002")
        assert not f.passed
        assert "privileged: true" in f.description

    def test_privileged_init_container_fires(self):
        # An initContainer with privileged: true must fire.
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: WorkflowTemplate
        metadata:
          name: w
        spec:
          templates:
            - name: main
              container:
                image: alpine:3
                securityContext:
                  privileged: false
                  runAsNonRoot: true
                  allowPrivilegeEscalation: false
              initContainers:
                - name: setup
                  image: busybox:1.36
                  securityContext:
                    privileged: true
        """
        f = run_check(cfg, "ARGO-002")
        assert not f.passed
        assert "privileged: true" in f.description

    def test_hardened_sidecar_and_init_passes(self):
        # All containers, sidecars, and initContainers hardened: must pass.
        cfg = """
        apiVersion: argoproj.io/v1alpha1
        kind: WorkflowTemplate
        metadata:
          name: w
        spec:
          templates:
            - name: main
              container:
                image: alpine:3
                securityContext:
                  privileged: false
                  runAsNonRoot: true
                  allowPrivilegeEscalation: false
              sidecars:
                - name: helper
                  image: busybox:1.36
                  securityContext:
                    privileged: false
                    runAsNonRoot: true
                    allowPrivilegeEscalation: false
              initContainers:
                - name: init
                  image: busybox:1.36
                  securityContext:
                    privileged: false
                    runAsNonRoot: true
                    allowPrivilegeEscalation: false
        """
        f = run_check(cfg, "ARGO-002")
        assert f.passed

    def test_existing_privileged_container_still_fires(self):
        # Pre-existing detection: a main container with privileged: true.
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


class TestAudit202607LowArgo:
    """2026-07 audit LOW findings on the Argo rules."""

    def test_argo005_non_shell_argv_param_not_flagged(self):
        safe = (
            "apiVersion: argoproj.io/v1alpha1\n"
            "kind: Workflow\n"
            "metadata: {name: w}\n"
            "spec:\n"
            "  templates:\n"
            "    - name: t\n"
            "      container:\n"
            "        image: myctl:1\n"
            "        command: [\"myctl\"]\n"
            "        args: [\"scale\", \"--replicas\", "
            "\"{{inputs.parameters.replicas}}\"]\n"
        )
        assert run_check(safe, "ARGO-005").passed is True
        shell = (
            "apiVersion: argoproj.io/v1alpha1\n"
            "kind: Workflow\n"
            "metadata: {name: w}\n"
            "spec:\n"
            "  templates:\n"
            "    - name: t\n"
            "      container:\n"
            "        image: alpine\n"
            "        command: [\"sh\", \"-c\"]\n"
            "        args: [\"echo {{inputs.parameters.x}}\"]\n"
        )
        assert run_check(shell, "ARGO-005").passed is False

    def test_argo004_json_nested_hostpath(self):
        wf = (
            "apiVersion: argoproj.io/v1alpha1\n"
            "kind: Workflow\n"
            "metadata: {name: w}\n"
            "spec:\n"
            "  podSpecPatch: '{\"volumes\": [{\"name\":\"r\","
            "\"hostPath\": {\"path\": \"/\"}}]}'\n"
            "  templates:\n"
            "    - name: t\n"
            "      container: {image: alpine}\n"
        )
        assert run_check(wf, "ARGO-004").passed is False

    def test_argo015_workflow_level_artifact(self):
        wf = (
            "apiVersion: argoproj.io/v1alpha1\n"
            "kind: Workflow\n"
            "metadata: {name: w}\n"
            "spec:\n"
            "  arguments:\n"
            "    artifacts:\n"
            "      - name: in\n"
            "        http: {url: \"http://internal/x.tar\"}\n"
            "  templates:\n"
            "    - name: t\n"
            "      container: {image: alpine}\n"
        )
        assert run_check(wf, "ARGO-015").passed is False

    def test_argo016_template_level_admin_sa(self):
        # A template that overrides the workflow SA to cluster-admin must
        # fire even when the spec-level SA is a least-privilege name.
        wf = (
            "apiVersion: argoproj.io/v1alpha1\n"
            "kind: Workflow\n"
            "metadata: {name: w}\n"
            "spec:\n"
            "  serviceAccountName: ci-deploy-sa\n"
            "  templates:\n"
            "    - name: main\n"
            "      serviceAccountName: cluster-admin\n"
            "      container: {image: alpine}\n"
        )
        f = run_check(wf, "ARGO-016")
        assert f.passed is False
        assert "cluster-admin" in f.description
        # A least-privilege template SA override must still pass.
        safe = (
            "apiVersion: argoproj.io/v1alpha1\n"
            "kind: Workflow\n"
            "metadata: {name: w}\n"
            "spec:\n"
            "  serviceAccountName: ci-deploy-sa\n"
            "  templates:\n"
            "    - name: main\n"
            "      serviceAccountName: ci-scoped-sa\n"
            "      container: {image: alpine}\n"
        )
        assert run_check(safe, "ARGO-016").passed is True
