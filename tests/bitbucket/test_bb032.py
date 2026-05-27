"""Tests for BB-032 (secret-named variable echoed to log)."""
from __future__ import annotations

from .conftest import run_check


class TestBB032SecretEchoed:
    def test_fails_on_echo_secret_var(self) -> None:
        f = run_check("""
        pipelines:
          default:
            - step:
                script:
                  - echo "Key is $API_KEY"
        """, "BB-032")
        assert not f.passed

    def test_passes_on_safe_script(self) -> None:
        f = run_check("""
        pipelines:
          default:
            - step:
                script:
                  - make deploy
        """, "BB-032")
        assert f.passed
