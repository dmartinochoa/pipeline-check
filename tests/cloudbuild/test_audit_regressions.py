"""Regression tests from the rule audit (Cloud Build batch 3 — example fixes)."""
from __future__ import annotations

import yaml

from pipeline_check.core.checks.cloudbuild.rules import gcb001_step_image as gcb001
from pipeline_check.core.checks.cloudbuild.rules import gcb003_secrets_in_args as gcb003
from pipeline_check.core.checks.cloudbuild.rules import gcb004_dynamic_substitutions as gcb004
from pipeline_check.core.checks.cloudbuild.rules import gcb006_shell_eval as gcb006
from pipeline_check.core.checks.cloudbuild.rules import gcb008_vuln_scanning as gcb008
from pipeline_check.core.checks.cloudbuild.rules import gcb011_tls_bypass as gcb011
from pipeline_check.core.checks.cloudbuild.rules import gcb012_literal_secrets as gcb012
from pipeline_check.core.checks.cloudbuild.rules import gcb019_shell_entrypoint_user_sub as gcb019
from pipeline_check.core.checks.cloudbuild.rules import (
    gcb023_undeclared_user_substitution as gcb023,
)

from .conftest import gcb_ctx, run_check


class TestGCB001StepImage:
    def test_exploit_example_strong_check(self):
        # Safe fragment previously used ``@sha256:abc123...``, which is not a
        # valid 64-char lowercase-hex digest, so the check never passed.
        vuln, safe = gcb001.RULE.exploit_example.split("\n\n", 1)
        assert gcb001.check("cloudbuild.yaml", yaml.safe_load(vuln)).passed is False
        assert gcb001.check("cloudbuild.yaml", yaml.safe_load(safe)).passed is True


class TestGCB003SecretsInArgs:
    def test_exploit_example_strong_check(self):
        # Vulnerable fragment previously used ``secretEnv:`` (the safe pattern),
        # so the check never fired. Rewritten to use ``gcloud secrets versions
        # access`` inline in step args.
        vuln, safe = gcb003.RULE.exploit_example.split("\n\n", 1)
        assert gcb003.check("cloudbuild.yaml", yaml.safe_load(vuln)).passed is False
        assert gcb003.check("cloudbuild.yaml", yaml.safe_load(safe)).passed is True


class TestGCB004DynamicSubstitutions:
    def test_exploit_example_strong_check(self):
        # Safe fragment had ``env: [TAG=${_TAG}]``, invalid YAML (flow sequence
        # + ``${`` opens a flow mapping). Fixed to ``env: ['TAG=${_TAG}']``.
        vuln, safe = gcb004.RULE.exploit_example.split("\n\n", 1)
        assert gcb004.check("cloudbuild.yaml", yaml.safe_load(vuln)).passed is False
        assert gcb004.check("cloudbuild.yaml", yaml.safe_load(safe)).passed is True


class TestGCB006ShellEval:
    def test_exploit_example_strong_check(self):
        # Vulnerable fragment had ``env: [BUILD_CMD=${_USER_CMD}]``, invalid YAML.
        # Fixed to ``env: ['BUILD_CMD=${_USER_CMD}']``.
        vuln, safe = gcb006.RULE.exploit_example.split("\n\n", 1)
        assert gcb006.check("cloudbuild.yaml", yaml.safe_load(vuln)).passed is False
        assert gcb006.check("cloudbuild.yaml", yaml.safe_load(safe)).passed is True


class TestGCB011TlsBypass:
    def test_exploit_example_strong_check(self):
        # Vulnerable fragment used separate args (``[-k, -O, ...]``). The
        # blob_lower scanner joins args on separate lines, so ``curl ... -k``
        # could not match across the newline. Rewritten to a single bash
        # ``-c`` string containing ``curl -k``.
        vuln, safe = gcb011.RULE.exploit_example.split("\n\n", 1)
        assert gcb011.check("cloudbuild.yaml", yaml.safe_load(vuln)).passed is False
        assert gcb011.check("cloudbuild.yaml", yaml.safe_load(safe)).passed is True


class TestGCB012LiteralSecrets:
    def test_exploit_example_strong_check(self):
        # Vulnerable fragment used ``AKIAIOSFODNN7EXAMPLE`` / vendor example
        # tokens suppressed by VENDOR_EXAMPLE_TOKENS, and had invalid YAML in
        # the env entries. Fixed to a non-suppressed access key shape and
        # quoted env entries.
        vuln, safe = gcb012.RULE.exploit_example.split("\n\n", 1)
        assert gcb012.check("cloudbuild.yaml", yaml.safe_load(vuln)).passed is False
        assert gcb012.check("cloudbuild.yaml", yaml.safe_load(safe)).passed is True


class TestGCB019ShellEntrypointUserSub:
    def test_exploit_example_strong_check(self):
        # Safe fragment had ``env: [TAG=${_TAG}]``, invalid YAML (flow sequence
        # + ``${`` opens a flow mapping). Fixed to ``env: ['TAG=${_TAG}']``.
        vuln, safe = gcb019.RULE.exploit_example.split("\n\n", 1)
        assert gcb019.check("cloudbuild.yaml", yaml.safe_load(vuln)).passed is False
        assert gcb019.check("cloudbuild.yaml", yaml.safe_load(safe)).passed is True


# ── GCB-004 env-remediation false positive ────────────────────────────────


class TestGCB004DynamicSubstitutionsEnvRemediation:
    """The documented env: remediation must clear the finding; args must fire."""

    # --- FP case: user sub in env: only (the recommended safe pattern) ---

    def test_passes_user_sub_in_env_only(self):
        # dynamicSubstitutions is on but $_TAG only appears in env:, not in
        # args or entrypoint.  This is the remediation the rule recommends,
        # so it must not fire.
        f = run_check("""
        substitutions:
          _TAG: v1.0
        options:
          dynamicSubstitutions: true
        steps:
          - name: gcr.io/cloud-builders/docker@sha256:abc123
            entrypoint: bash
            env:
              - TAG=$_TAG
            args:
              - -c
              - docker build -t "image:$TAG" .
        """, "GCB-004")
        assert f.passed, f"Expected pass (env-only remediation), got: {f.description}"

    def test_passes_user_sub_in_secret_env_only(self):
        # secretEnv is also excluded from the scan; a pipeline that names a
        # user sub in secretEnv but not in args/entrypoint must not fire.
        f = run_check("""
        substitutions:
          _SECRET_NAME: my-secret
        options:
          dynamicSubstitutions: true
        steps:
          - name: gcr.io/cloud-builders/gcloud@sha256:abc123
            secretEnv:
              - SECRET_VAL=$_SECRET_NAME
            args:
              - -c
              - echo "running"
        """, "GCB-004")
        assert f.passed, f"Expected pass (secretEnv-only), got: {f.description}"

    # --- TP cases: user sub in args or entrypoint must still fire ---

    def test_fires_user_sub_in_args(self):
        # $_TAG directly in args is the canonical injection vector.
        f = run_check("""
        substitutions:
          _TAG: v1.0
        options:
          dynamicSubstitutions: true
        steps:
          - name: gcr.io/cloud-builders/docker@sha256:abc123
            args: [build, -t, "image:${_TAG}", .]
        """, "GCB-004")
        assert not f.passed, "Expected fail (user sub in args)"

    def test_fires_user_sub_in_entrypoint(self):
        # A user sub embedded in the entrypoint string is also a violation.
        f = run_check("""
        substitutions:
          _RUNNER: bash
        options:
          dynamicSubstitutions: true
        steps:
          - name: gcr.io/cloud-builders/gcloud@sha256:abc123
            entrypoint: $_RUNNER
            args: [-c, "echo hello"]
        """, "GCB-004")
        assert not f.passed, "Expected fail (user sub in entrypoint)"

    # --- Baseline: dynamicSubstitutions off must always pass ---

    def test_passes_when_dynamic_subs_disabled(self):
        # Without dynamicSubstitutions: true, bash re-evaluation does not
        # apply, so the rule must not fire regardless of where $_FOO appears.
        f = run_check("""
        substitutions:
          _TAG: v1.0
        steps:
          - name: gcr.io/cloud-builders/docker@sha256:abc123
            args: [build, -t, "image:${_TAG}", .]
        """, "GCB-004")
        assert f.passed, f"Expected pass (dynamicSubstitutions off), got: {f.description}"

    def test_passes_when_dynamic_subs_explicitly_false(self):
        f = run_check("""
        substitutions:
          _TAG: v1.0
        options:
          dynamicSubstitutions: false
        steps:
          - name: gcr.io/cloud-builders/docker@sha256:abc123
            args: [build, -t, "image:${_TAG}", .]
        """, "GCB-004")
        assert f.passed, f"Expected pass (dynamicSubstitutions: false), got: {f.description}"


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


class TestAudit202607LowCloudBuild:
    """2026-07 audit LOW findings on the Cloud Build rules."""

    @staticmethod
    def _run(text, cid):
        from tests.cloudbuild.conftest import run_check
        return run_check(text, cid)

    def test_gcb013_split_args_git_install_fires(self):
        cfg = (
            "steps:\n"
            "  - name: python:3.12\n"
            "    entrypoint: pip\n"
            "    args: [install, \"git+https://github.com/acme/helper.git\"]\n"
        )
        assert self._run(cfg, "GCB-013").passed is False
        pinned = (
            "steps:\n"
            "  - name: python:3.12\n"
            "    entrypoint: pip\n"
            "    args: [install, \"git+https://github.com/acme/helper.git@"
            "abcdef1234567890abcdef1234567890abcdef12\"]\n"
        )
        assert self._run(pinned, "GCB-013").passed is True

    def test_gcb003_metadata_describe_is_not_value_exposure(self):
        describe = (
            "steps:\n"
            "  - name: gcr.io/cloud-builders/gcloud\n"
            "    args: [secrets, versions, describe, "
            "\"projects/p/secrets/api/versions/5\"]\n"
        )
        assert self._run(describe, "GCB-003").passed is True
        access = (
            "steps:\n"
            "  - name: gcr.io/cloud-builders/gcloud\n"
            "    args: [secrets, versions, access, "
            "\"projects/p/secrets/api/versions/5\"]\n"
        )
        assert self._run(access, "GCB-003").passed is False

    def test_gcb004_escaped_and_digit_first_substitutions(self):
        escaped = (
            "options: { dynamicSubstitutions: true }\n"
            "steps:\n"
            "  - name: gcr.io/x\n"
            "    entrypoint: bash\n"
            "    args: [-c, \"echo $$_TAG\"]\n"
        )
        assert self._run(escaped, "GCB-004").passed is True
        digit_first = (
            "options: { dynamicSubstitutions: true }\n"
            "steps:\n"
            "  - name: gcr.io/x\n"
            "    entrypoint: bash\n"
            "    args: [-c, \"echo ${_1}\"]\n"
        )
        assert self._run(digit_first, "GCB-004").passed is False

    def test_gcb024_push_via_script_field_fires(self):
        # A docker push issued from the ``script:`` step form was invisible
        # to the images-missing check.
        cfg = (
            "steps:\n"
            "  - name: gcr.io/cloud-builders/docker\n"
            "    script: docker push gcr.io/foo/bar:v1\n"
        )
        assert self._run(cfg, "GCB-024").passed is False
        declared = (
            "steps:\n"
            "  - name: gcr.io/cloud-builders/docker\n"
            "    script: docker push gcr.io/foo/bar:v1\n"
            "images: [gcr.io/foo/bar:v1]\n"
        )
        assert self._run(declared, "GCB-024").passed is True

    def test_gcb023_escaped_shell_var_not_undeclared_sub(self):
        # ``$$_SHELLVAR`` is an escaped literal shell var, not a Cloud Build
        # user substitution.
        escaped = (
            "steps:\n"
            "  - name: ubuntu\n"
            "    entrypoint: bash\n"
            "    args: [-c, \"echo $$_SHELLVAR\"]\n"
        )
        assert self._run(escaped, "GCB-023").passed is True
        # a genuinely undeclared single-``$`` user sub still fires
        undeclared = (
            "steps:\n"
            "  - name: ubuntu\n"
            "    entrypoint: bash\n"
            "    args: [-c, \"echo $_UNDECLARED\"]\n"
        )
        assert self._run(undeclared, "GCB-023").passed is False
