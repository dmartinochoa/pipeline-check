"""Tests for GL-036 (secret-named variable echoed to log)."""
from __future__ import annotations

from .conftest import run_check


class TestGL036SecretEchoed:
    def test_fails_on_echo_secret_var(self) -> None:
        f = run_check("""
        deploy:
          script:
            - echo "Token is $DEPLOY_TOKEN"
        """, "GL-036")
        assert not f.passed

    def test_fails_on_printenv(self) -> None:
        f = run_check("""
        deploy:
          script:
            - printenv
        """, "GL-036")
        assert not f.passed

    def test_fails_on_set_x_with_secret(self) -> None:
        f = run_check("""
        deploy:
          script:
            - set -x
            - curl -H $API_KEY $URL
        """, "GL-036")
        assert not f.passed

    def test_passes_on_safe_script(self) -> None:
        f = run_check("""
        deploy:
          script:
            - curl -H $API_KEY $URL
        """, "GL-036")
        assert f.passed

    def test_passes_on_boolean_check(self) -> None:
        f = run_check("""
        deploy:
          script:
            - '[ -n "$TOKEN" ] && echo set'
        """, "GL-036")
        assert f.passed
