"""Unit tests for the first-wave Cloud Build rules (GCB-001…004).

Complements the insecure/secure fixture tests with per-rule edge cases
the single paired fixture can't cover.
"""
from __future__ import annotations

import yaml

from pipeline_check.core.checks.cloudbuild.rules import (
    gcb001_step_image,
    gcb002_service_account,
    gcb003_secrets_in_args,
    gcb004_dynamic_substitutions,
    gcb005_timeout,
    gcb006_shell_eval,
    gcb007_secret_version_latest,
    gcb008_vuln_scanning,
    gcb009_signing,
)


def _doc(text: str) -> dict:
    return yaml.safe_load(text)


# ──────────────────────────────────────────────────────────────────────
# GCB-001 — step image digest pinning
# ──────────────────────────────────────────────────────────────────────

class TestGCB001:
    def test_tag_only_fails(self):
        d = _doc("""
steps:
  - name: 'gcr.io/cloud-builders/docker:latest'
    args: [version]
""")
        f = gcb001_step_image.check("<t>", d)
        assert f.passed is False
        assert "latest" in f.description

    def test_bare_name_fails(self):
        # No tag, no digest — same as :latest.
        d = _doc("""
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args: [version]
""")
        f = gcb001_step_image.check("<t>", d)
        assert f.passed is False

    def test_digest_pinned_passes(self):
        d = _doc("""
steps:
  - name: 'gcr.io/cloud-builders/docker@sha256:' + 'a' * 64
    args: [version]
""".replace("'gcr.io/cloud-builders/docker@sha256:' + 'a' * 64",
            f"'gcr.io/cloud-builders/docker@sha256:{'a' * 64}'"))
        f = gcb001_step_image.check("<t>", d)
        assert f.passed is True

    def test_no_steps_silent_pass(self):
        d = _doc("""
images: [gcr.io/example/app:v1]
""")
        # Document has no ``steps:`` — loader would skip it, but the
        # rule itself must also handle the case defensively.
        f = gcb001_step_image.check("<t>", d)
        assert f.passed is True
        assert "No build steps" in f.description


# ──────────────────────────────────────────────────────────────────────
# GCB-002 — explicit serviceAccount required
# ──────────────────────────────────────────────────────────────────────

class TestGCB002:
    def test_missing_service_account_fails(self):
        d = _doc("""
steps:
  - name: gcr.io/cloud-builders/docker
    args: [version]
""")
        f = gcb002_service_account.check("<t>", d)
        assert f.passed is False

    def test_explicit_service_account_passes(self):
        d = _doc("""
serviceAccount: projects/p/serviceAccounts/builder@p.iam.gserviceaccount.com
steps:
  - name: gcr.io/cloud-builders/docker
""")
        f = gcb002_service_account.check("<t>", d)
        assert f.passed is True

    def test_empty_string_service_account_fails(self):
        # An empty string is not a real SA reference — treat as unset.
        d = _doc("""
serviceAccount: '   '
steps:
  - name: gcr.io/cloud-builders/docker
""")
        f = gcb002_service_account.check("<t>", d)
        assert f.passed is False


# ──────────────────────────────────────────────────────────────────────
# GCB-003 — secret fetched / embedded in args
# ──────────────────────────────────────────────────────────────────────

class TestGCB003:
    def test_gcloud_secrets_access_fails(self):
        d = _doc("""
steps:
  - name: gcr.io/cloud-builders/gcloud
    entrypoint: bash
    args:
      - -c
      - 'TOKEN=$(gcloud secrets versions access latest --secret=api-token)'
""")
        f = gcb003_secrets_in_args.check("<t>", d)
        assert f.passed is False
        assert "gcloud fetch" in f.description

    def test_literal_secret_uri_fails(self):
        d = _doc("""
steps:
  - name: gcr.io/cloud-builders/curl
    args:
      - projects/123456/secrets/api-key/versions/3
""")
        f = gcb003_secrets_in_args.check("<t>", d)
        assert f.passed is False

    def test_secretenv_pattern_passes(self):
        # The official mapped-secret pattern: availableSecrets binds
        # the secret to an env var, referenced via secretEnv:. No
        # literal URI, no gcloud fetch — rule passes.
        d = _doc("""
availableSecrets:
  secretManager:
    - versionName: projects/p/secrets/api-token/versions/latest
      env: API_TOKEN
steps:
  - name: gcr.io/cloud-builders/gcloud
    entrypoint: bash
    secretEnv: ['API_TOKEN']
    args:
      - -c
      - 'curl -H "Authorization: Bearer ${API_TOKEN}" https://api.example.com'
""")
        f = gcb003_secrets_in_args.check("<t>", d)
        assert f.passed is True

    def test_no_secret_refs_silent_pass(self):
        d = _doc("""
steps:
  - name: gcr.io/cloud-builders/docker
    args: [build, -t, gcr.io/p/app:v1, .]
""")
        f = gcb003_secrets_in_args.check("<t>", d)
        assert f.passed is True


# ──────────────────────────────────────────────────────────────────────
# GCB-004 — dynamicSubstitutions + user substitutions in args
# ──────────────────────────────────────────────────────────────────────

class TestGCB004:
    def test_dynamic_sub_with_user_var_in_args_fails(self):
        d = _doc("""
options:
  dynamicSubstitutions: true
substitutions:
  _DEPLOY: prod
steps:
  - name: gcr.io/cloud-builders/gcloud
    args: [deploy, --env, '$_DEPLOY']
""")
        f = gcb004_dynamic_substitutions.check("<t>", d)
        assert f.passed is False
        assert "$_DEPLOY" in f.description

    def test_dynamic_sub_with_builtin_only_passes(self):
        # ``$PROJECT_ID`` is a Cloud Build built-in, not a user
        # substitution — not attacker-controllable via trigger edits.
        d = _doc("""
options:
  dynamicSubstitutions: true
steps:
  - name: gcr.io/cloud-builders/docker
    args: [build, -t, 'gcr.io/$PROJECT_ID/app:$COMMIT_SHA', .]
""")
        f = gcb004_dynamic_substitutions.check("<t>", d)
        assert f.passed is True

    def test_dynamic_sub_off_silent_pass(self):
        # Even with user subs in args, ``dynamicSubstitutions: false``
        # (or unset) means no bash re-evaluation is performed; the
        # injection channel isn't open.
        d = _doc("""
substitutions:
  _DEPLOY: prod
steps:
  - name: gcr.io/cloud-builders/gcloud
    args: [deploy, --env, '$_DEPLOY']
""")
        f = gcb004_dynamic_substitutions.check("<t>", d)
        assert f.passed is True

    def test_user_var_in_braces_also_detected(self):
        d = _doc("""
options:
  dynamicSubstitutions: true
steps:
  - name: gcr.io/cloud-builders/docker
    args: ['build', '-t', 'gcr.io/p/app:${_TAG}', '.']
""")
        f = gcb004_dynamic_substitutions.check("<t>", d)
        assert f.passed is False


# ──────────────────────────────────────────────────────────────────────
# GCB-005 — build timeout
# ──────────────────────────────────────────────────────────────────────

class TestGCB005:
    def test_missing_timeout_fails(self):
        d = _doc("""
steps: [{name: 'gcr.io/cloud-builders/docker', args: [version]}]
""")
        f = gcb005_timeout.check("<t>", d)
        assert f.passed is False
        assert "inherits the 10-minute" in f.description

    def test_bounded_timeout_passes(self):
        d = _doc("""
timeout: 1200s
steps: [{name: 'gcr.io/cloud-builders/docker', args: [version]}]
""")
        f = gcb005_timeout.check("<t>", d)
        assert f.passed is True

    def test_excessive_timeout_fails(self):
        d = _doc("""
timeout: 7200s
steps: [{name: 'gcr.io/cloud-builders/docker', args: [version]}]
""")
        f = gcb005_timeout.check("<t>", d)
        assert f.passed is False
        assert "7200s" in f.description

    def test_minute_suffix_is_malformed(self):
        # The Cloud Build API rejects ``30m`` — gcloud accepts it as
        # sugar. Treat as unresolvable and fail (a misconfigured build
        # file won't even run).
        d = _doc("""
timeout: 30m
steps: [{name: 'gcr.io/cloud-builders/docker', args: [version]}]
""")
        f = gcb005_timeout.check("<t>", d)
        assert f.passed is False
        assert "not a valid Cloud Build duration" in f.description

    def test_boundary_1800s_passes(self):
        d = _doc("""
timeout: 1800s
steps: [{name: 'gcr.io/cloud-builders/docker', args: [version]}]
""")
        f = gcb005_timeout.check("<t>", d)
        assert f.passed is True


# ──────────────────────────────────────────────────────────────────────
# GCB-006 — shell eval primitive
# ──────────────────────────────────────────────────────────────────────

class TestGCB006:
    def test_eval_var_fails(self):
        d = _doc("""
steps:
  - name: 'gcr.io/cloud-builders/gcloud'
    entrypoint: bash
    args: ['-c', 'eval "$BUILD_CMD"']
""")
        f = gcb006_shell_eval.check("<t>", d)
        assert f.passed is False

    def test_plain_command_passes(self):
        d = _doc("""
steps:
  - name: 'gcr.io/cloud-builders/gcloud'
    entrypoint: bash
    args: ['-c', 'deploy --env production']
""")
        f = gcb006_shell_eval.check("<t>", d)
        assert f.passed is True

    def test_eval_ssh_agent_idiom_not_flagged(self):
        # ``eval "$(ssh-agent -s)"`` is the documented known-safe
        # exception — the inner command is literal, not a variable.
        d = _doc("""
steps:
  - name: 'gcr.io/cloud-builders/gcloud'
    entrypoint: bash
    args: ['-c', 'eval "$(ssh-agent -s)"']
""")
        f = gcb006_shell_eval.check("<t>", d)
        assert f.passed is True


# ──────────────────────────────────────────────────────────────────────
# GCB-007 — availableSecrets versions/latest
# ──────────────────────────────────────────────────────────────────────

class TestGCB007:
    def test_versions_latest_fails(self):
        d = _doc("""
availableSecrets:
  secretManager:
    - versionName: projects/p/secrets/api-token/versions/latest
      env: API_TOKEN
steps: [{name: 'gcr.io/cloud-builders/gcloud', args: [version]}]
""")
        f = gcb007_secret_version_latest.check("<t>", d)
        assert f.passed is False

    def test_pinned_version_passes(self):
        d = _doc("""
availableSecrets:
  secretManager:
    - versionName: projects/p/secrets/api-token/versions/7
      env: API_TOKEN
steps: [{name: 'gcr.io/cloud-builders/gcloud', args: [version]}]
""")
        f = gcb007_secret_version_latest.check("<t>", d)
        assert f.passed is True

    def test_no_available_secrets_silent_pass(self):
        d = _doc("""
steps: [{name: 'gcr.io/cloud-builders/gcloud', args: [version]}]
""")
        f = gcb007_secret_version_latest.check("<t>", d)
        assert f.passed is True

    def test_mixed_entries_fails_on_any_latest(self):
        d = _doc("""
availableSecrets:
  secretManager:
    - versionName: projects/p/secrets/api/versions/7
      env: PINNED
    - versionName: projects/p/secrets/other/versions/latest
      env: ROLLING
steps: [{name: 'gcr.io/cloud-builders/gcloud', args: [version]}]
""")
        f = gcb007_secret_version_latest.check("<t>", d)
        assert f.passed is False
        assert "ROLLING" in f.description


# ──────────────────────────────────────────────────────────────────────
# GCB-008 — vulnerability scanning
# ──────────────────────────────────────────────────────────────────────

class TestGCB008:
    def test_no_scanner_fails(self):
        d = _doc("""
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', 'gcr.io/p/app:v1', '.']
""")
        f = gcb008_vuln_scanning.check("<t>", d)
        assert f.passed is False

    def test_trivy_step_passes(self):
        d = _doc("""
steps:
  - name: 'aquasec/trivy'
    entrypoint: bash
    args: ['-c', 'trivy image gcr.io/p/app:v1']
""")
        f = gcb008_vuln_scanning.check("<t>", d)
        assert f.passed is True


# ──────────────────────────────────────────────────────────────────────
# GCB-009 — signing / attestation
# ──────────────────────────────────────────────────────────────────────

class TestGCB009:
    def test_unsigned_build_with_images_fails(self):
        d = _doc("""
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', 'gcr.io/p/app:v1', '.']
images:
  - 'gcr.io/p/app:v1'
""")
        f = gcb009_signing.check("<t>", d)
        assert f.passed is False

    def test_cosign_step_passes(self):
        d = _doc("""
steps:
  - name: 'gcr.io/projectsigstore/cosign'
    args: ['sign', '--yes', 'gcr.io/p/app:v1']
images:
  - 'gcr.io/p/app:v1'
""")
        f = gcb009_signing.check("<t>", d)
        assert f.passed is True

    def test_no_artifacts_silent_pass(self):
        # A test-only build with no ``images:`` and no artifact-
        # producing commands — no signing expected.
        d = _doc("""
steps:
  - name: 'gcr.io/cloud-builders/gcloud'
    entrypoint: bash
    args: ['-c', 'pytest']
""")
        f = gcb009_signing.check("<t>", d)
        assert f.passed is True
