"""Tests for ADO-031 (secret variable echoed to log)."""
from __future__ import annotations

from .conftest import run_check


class TestADO031SecretEchoed:
    def test_fails_on_echo_ado_secret_var(self) -> None:
        f = run_check("""
        steps:
          - bash: echo "Token is $(DEPLOY_TOKEN)"
        """, "ADO-031")
        assert not f.passed

    def test_fails_on_issecret_var(self) -> None:
        f = run_check("""
        variables:
          - name: myvar
            value: x
            issecret: "true"
        steps:
          - bash: echo "Val is $(myvar)"
        """, "ADO-031")
        assert not f.passed

    def test_passes_on_safe_script(self) -> None:
        f = run_check("""
        steps:
          - bash: make deploy
        """, "ADO-031")
        assert f.passed
