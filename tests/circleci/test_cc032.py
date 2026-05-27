"""Tests for CC-032 (secret-named variable echoed to log)."""
from __future__ import annotations

from .conftest import run_check


class TestCC032SecretEchoed:
    def test_fails_on_echo_secret_var(self) -> None:
        f = run_check("""
        jobs:
          deploy:
            steps:
              - run: echo "Token is $DEPLOY_TOKEN"
        """, "CC-032")
        assert not f.passed

    def test_passes_on_safe_script(self) -> None:
        f = run_check("""
        jobs:
          deploy:
            steps:
              - run: make deploy
        """, "CC-032")
        assert f.passed
