"""Regression tests from the rule audit (Cloud Build false-negative fixes)."""
from __future__ import annotations

import yaml

from pipeline_check.core.checks.cloudbuild.rules import gcb008_vuln_scanning as gcb008
from pipeline_check.core.checks.cloudbuild.rules import (
    gcb023_undeclared_user_substitution as gcb023,
)

from .conftest import gcb_ctx

# ── GCB-023 dir/id/waitFor false-negatives ────────────────────────────


class TestGCB023DirIdWaitForFN:
    """GCB-023: ``dir:``, ``id:``, and ``waitFor:`` entries were never scanned
for ``$_USER_VAR`` tokens; an undeclared substitution referenced only in
one of those fields was silently missed.
"""

    def test_fires_undeclared_sub_in_dir(self):
        ctx = gcb_ctx("""
steps:
  - name: gcr.io/cloud-builders/docker
    dir: $_WORKSPACE/src
    args: [build, .]
""", "cb.yaml")
        f = gcb023.check("cb.yaml", ctx.pipelines[0].data)
        assert not f.passed
        assert "_WORKSPACE" in f.description

    def test_fires_undeclared_sub_in_id(self):
        ctx = gcb_ctx("""
steps:
  - name: gcr.io/cloud-builders/docker
    id: build-$_ENV
    args: [build, .]
""", "cb.yaml")
        f = gcb023.check("cb.yaml", ctx.pipelines[0].data)
        assert not f.passed

    def test_fires_undeclared_sub_in_waitfor(self):
        ctx = gcb_ctx("""
steps:
  - name: gcr.io/cloud-builders/docker
    id: setup
    args: [true]
  - name: gcr.io/cloud-builders/docker
    args: [deploy]
    waitFor: [$_GATE_STEP]
""", "cb.yaml")
        f = gcb023.check("cb.yaml", ctx.pipelines[0].data)
        assert not f.passed
        assert "_GATE_STEP" in f.description

    def test_passes_when_dir_sub_is_declared(self):
        ctx = gcb_ctx("""
substitutions:
  _WORKSPACE: /workspace/myrepo
steps:
  - name: gcr.io/cloud-builders/docker
    dir: $_WORKSPACE/src
    args: [build, .]
""", "cb.yaml")
        assert gcb023.check("cb.yaml", ctx.pipelines[0].data).passed

    def test_passes_when_id_sub_is_declared(self):
        ctx = gcb_ctx("""
substitutions:
  _ENV: staging
steps:
  - name: gcr.io/cloud-builders/docker
    id: build-$_ENV
    args: [build, .]
""", "cb.yaml")
        assert gcb023.check("cb.yaml", ctx.pipelines[0].data).passed

    def test_passes_when_waitfor_sub_is_declared(self):
        ctx = gcb_ctx("""
substitutions:
  _GATE_STEP: setup
steps:
  - name: gcr.io/cloud-builders/docker
    id: setup
    args: [true]
  - name: gcr.io/cloud-builders/docker
    args: [deploy]
    waitFor: [$_GATE_STEP]
""", "cb.yaml")
        assert gcb023.check("cb.yaml", ctx.pipelines[0].data).passed

    def test_existing_args_detection_preserved(self):
        ctx = gcb_ctx("""
steps:
  - name: gcr.io/cloud-builders/docker
    args: [push, gcr.io/$PROJECT_ID/app:$_TYPO]
substitutions:
  _REGION: us-central1
""", "cb.yaml")
        f = gcb023.check("cb.yaml", ctx.pipelines[0].data)
        assert not f.passed

    def test_existing_env_detection_preserved(self):
        ctx = gcb_ctx("""
steps:
  - name: gcr.io/cloud-builders/docker
    args: [build, .]
    env: [DEPLOY_TARGET=$_UNKNOWN]
""", "cb.yaml")
        f = gcb023.check("cb.yaml", ctx.pipelines[0].data)
        assert not f.passed
        assert "_UNKNOWN" in f.description

    def test_builtin_user_shaped_subs_in_dir_dont_fire(self):
        ctx = gcb_ctx("""
steps:
  - name: gcr.io/cloud-builders/docker
    dir: workspace/$_HEAD_BRANCH
    args: [build, .]
""", "cb.yaml")
        assert gcb023.check("cb.yaml", ctx.pipelines[0].data).passed


# ── GCB-008 batch-5 FN: scanner referenced only as step image ────────


class TestGCB008ScannerStepImage:
    """GCB-008: a step whose ``name:`` is a scanner image (e.g.
    ``aquasec/trivy``) but whose ``args:`` contain only image/subcommand
    arguments (no ``trivy `` substring in the blob) was previously missed
    because ``has_vuln_scanning`` uses trailing-space tokens."""

    def test_aquasec_trivy_name_only_passes(self):
        # Canonical Cloud Build shape: name is the scanner image; args
        # pass the target.  No ``trivy `` text in args.
        doc = yaml.safe_load("""
steps:
  - name: aquasec/trivy
    args: [image, --severity, HIGH, gcr.io/myproject/app:v1]
""")
        assert gcb008.check("cb.yaml", doc).passed is True, (
            "GCB-008 must pass when the scanner image is the step name"
        )

    def test_aquasec_trivy_with_registry_prefix_passes(self):
        # A fully-qualified image ref (with registry prefix) must also match.
        doc = yaml.safe_load("""
steps:
  - name: us-docker.pkg.dev/aquasec/trivy:0.51.0
    args: [image, gcr.io/myproject/app:v1]
""")
        assert gcb008.check("cb.yaml", doc).passed is True, (
            "GCB-008 must pass on a fully-qualified aquasec/trivy image ref"
        )

    def test_anchore_grype_name_only_passes(self):
        # anchore/grype as the step name must satisfy GCB-008.
        doc = yaml.safe_load("""
steps:
  - name: anchore/grype
    args: [gcr.io/myproject/app:v1]
""")
        assert gcb008.check("cb.yaml", doc).passed is True, (
            "GCB-008 must pass when anchore/grype is the step name"
        )

    def test_no_scanner_fires(self):
        # A build-and-push pipeline with no scanner must still fire.
        doc = yaml.safe_load("""
steps:
  - name: gcr.io/cloud-builders/docker
    args: [build, -t, gcr.io/myproject/app:v1, .]
  - name: gcr.io/cloud-builders/docker
    args: [push, gcr.io/myproject/app:v1]
""")
        assert gcb008.check("cb.yaml", doc).passed is False, (
            "GCB-008 must fire when no scanner is present"
        )

    def test_plain_docker_build_step_does_not_fp(self):
        # A plain docker build step with no scanner must not FP.
        doc = yaml.safe_load("""
steps:
  - name: gcr.io/cloud-builders/docker
    args: [build, -t, gcr.io/myproject/app:v1, .]
""")
        assert gcb008.check("cb.yaml", doc).passed is False, (
            "GCB-008 must not FP on a plain docker build step"
        )

    def test_trivy_in_args_still_passes(self):
        # The existing token-in-blob path (trivy in entrypoint/args) must
        # still work to avoid regression.
        doc = yaml.safe_load("""
steps:
  - name: gcr.io/cloud-builders/docker
    entrypoint: bash
    args: [-c, trivy image gcr.io/myproject/app:v1]
""")
        assert gcb008.check("cb.yaml", doc).passed is True, (
            "GCB-008 must still pass when trivy appears in args"
        )
