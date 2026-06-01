"""Regression tests from the rule audit (CircleCI example fix)."""
from __future__ import annotations

import yaml

from pipeline_check.core.checks.circleci.rules import cc008_literal_secrets as cc008


class TestCC008LiteralSecrets:
    def test_exploit_example_strong_check(self):
        # The Vulnerable fragment must fire; it previously used vendor
        # example tokens (AKIAIOSFODNN7EXAMPLE) that find_secret_values
        # suppresses, so the documented example passed.
        vuln, safe = cc008.RULE.exploit_example.split("\n\n", 1)
        assert cc008.check(".circleci/config.yml", yaml.safe_load(vuln)).passed is False
        assert cc008.check(".circleci/config.yml", yaml.safe_load(safe)).passed is True
