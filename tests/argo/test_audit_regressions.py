"""Regression tests from the rule audit (Argo FN fixes — batch 5)."""
from __future__ import annotations

from .conftest import run_check

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
