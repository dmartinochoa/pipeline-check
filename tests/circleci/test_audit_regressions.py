"""Regression tests from the rule audit (CircleCI example fix)."""
from __future__ import annotations

import yaml

from pipeline_check.core.checks.circleci.rules import cc002_script_injection as cc002
from pipeline_check.core.checks.circleci.rules import cc003_docker_image_pinning as cc003
from pipeline_check.core.checks.circleci.rules import cc008_literal_secrets as cc008
from pipeline_check.core.checks.circleci.rules import cc026_malicious_activity as cc026


class TestCC008LiteralSecrets:
    def test_exploit_example_strong_check(self):
        # The Vulnerable fragment must fire; it previously used vendor
        # example tokens (AKIAIOSFODNN7EXAMPLE) that find_secret_values
        # suppresses, so the documented example passed.
        vuln, safe = cc008.RULE.exploit_example.split("\n\n", 1)
        assert cc008.check(".circleci/config.yml", yaml.safe_load(vuln)).passed is False
        assert cc008.check(".circleci/config.yml", yaml.safe_load(safe)).passed is True


class TestCC003DockerImagePinning:
    def test_exploit_example_strong_check(self):
        # Safe fragment previously used @sha256:abc123... which is only
        # 6 hex chars; DIGEST_RE requires exactly 64, so the safe config
        # was flagged. Fixed by using a full 64-hex digest.
        vuln, safe = cc003.RULE.exploit_example.split("\n\n", 1)
        assert cc003.check(".circleci/config.yml", yaml.safe_load(vuln)).passed is False
        assert cc003.check(".circleci/config.yml", yaml.safe_load(safe)).passed is True


class TestCC002ScriptInjection:
    def test_exploit_example_strong_check(self):
        # Safe fragment previously assigned $CIRCLE_BRANCH to a local
        # shell variable; UNTRUSTED_ENV_RE matches the variable name
        # regardless of quoting, so the safe config was flagged.
        # Fixed by using a CircleCI pipeline parameter instead, which
        # never contains the untrusted variable name in a run step.
        vuln, safe = cc002.RULE.exploit_example.split("\n\n", 1)
        assert cc002.check(".circleci/config.yml", yaml.safe_load(vuln)).passed is False
        assert cc002.check(".circleci/config.yml", yaml.safe_load(safe)).passed is True


class TestCC026MaliciousActivity:
    def test_exploit_example_strong_check(self):
        # Vulnerable fragment previously used a 12-char base64 blob
        # (Z2g6Li4uIA==) which is below the 30-char minimum required
        # by _B64_BLOB; the line only fired via the webhook.site
        # exfil-channel pattern, not the intended obfuscated-exec
        # pattern. Fixed with a 52-char blob that fires both detectors.
        vuln, safe = cc026.RULE.exploit_example.split("\n\n", 1)
        result = cc026.check(".circleci/config.yml", yaml.safe_load(vuln))
        assert result.passed is False
        assert "obfuscated-exec" in result.description
        assert cc026.check(".circleci/config.yml", yaml.safe_load(safe)).passed is True
