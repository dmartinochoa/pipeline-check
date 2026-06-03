"""Tests for ADO-032 (checkout persistCredentials leaks the pipeline token)."""
from __future__ import annotations

from .conftest import run_check


class TestADO032PersistCredentials:
    def test_fails_on_persist_credentials_true(self) -> None:
        f = run_check("""
        steps:
          - checkout: self
            persistCredentials: true
          - script: git config --get http.https://dev.azure.com.extraheader
        """, "ADO-032")
        assert not f.passed
        assert "checkout" in f.description

    def test_fails_on_quoted_true(self) -> None:
        f = run_check("""
        steps:
          - checkout: self
            persistCredentials: "true"
        """, "ADO-032")
        assert not f.passed

    def test_fails_inside_job(self) -> None:
        f = run_check("""
        jobs:
          - job: build
            steps:
              - checkout: self
                persistCredentials: true
        """, "ADO-032")
        assert not f.passed

    def test_passes_when_default(self) -> None:
        f = run_check("""
        steps:
          - checkout: self
        """, "ADO-032")
        assert f.passed

    def test_passes_when_explicitly_false(self) -> None:
        f = run_check("""
        steps:
          - checkout: self
            persistCredentials: false
        """, "ADO-032")
        assert f.passed
