"""Regression tests from the rule audit (Cloud Build batch 3 — example fixes)."""
from __future__ import annotations

import yaml

from pipeline_check.core.checks.cloudbuild.rules import gcb001_step_image as gcb001
from pipeline_check.core.checks.cloudbuild.rules import gcb003_secrets_in_args as gcb003
from pipeline_check.core.checks.cloudbuild.rules import gcb004_dynamic_substitutions as gcb004
from pipeline_check.core.checks.cloudbuild.rules import gcb006_shell_eval as gcb006
from pipeline_check.core.checks.cloudbuild.rules import gcb011_tls_bypass as gcb011
from pipeline_check.core.checks.cloudbuild.rules import gcb012_literal_secrets as gcb012
from pipeline_check.core.checks.cloudbuild.rules import gcb019_shell_entrypoint_user_sub as gcb019


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
