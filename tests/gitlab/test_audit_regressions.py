"""Regression tests from the rule audit (GitLab CI fixes)."""
from __future__ import annotations

from .conftest import run_check


class TestGL022PipUpgradeShortForm:
    """A5: the ``pip install -U`` short form was invisible (case-sensitive
    ``-U`` matched against a lowercased blob)."""

    def test_pip_dash_u_fires(self):
        cfg = (
            "build:\n"
            "  script:\n"
            "    - pip install -U requests\n"
        )
        assert run_check(cfg, "GL-022").passed is False

    def test_exempt_tooling_upgrade_still_passes(self):
        cfg = (
            "build:\n"
            "  script:\n"
            "    - pip install -U pip\n"
        )
        assert run_check(cfg, "GL-022").passed is True
