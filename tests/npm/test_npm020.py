"""Tests for NPM-020 (.npmrc registry repoint off canonical npm)."""
from __future__ import annotations

from .conftest import run_check_rc


class TestNPM020NpmrcRegistryRepoint:
    def test_fails_on_default_registry_repoint(self):
        f = run_check_rc("registry=https://registry.attacker.test/", "NPM-020")
        assert not f.passed
        assert "attacker" in f.description

    def test_fails_on_scoped_registry_repoint(self):
        f = run_check_rc(
            "@acme:registry=https://registry.attacker.test/", "NPM-020",
        )
        assert not f.passed

    def test_fails_on_plaintext_http_registry(self):
        f = run_check_rc("registry=http://internal-mirror/", "NPM-020")
        assert not f.passed

    def test_passes_on_canonical_npmjs(self):
        f = run_check_rc("registry=https://registry.npmjs.org/", "NPM-020")
        assert f.passed

    def test_passes_on_yarnpkg_mirror(self):
        f = run_check_rc("registry=https://registry.yarnpkg.com/", "NPM-020")
        assert f.passed

    def test_passes_when_no_registry_key(self):
        f = run_check_rc("ignore-scripts=true\n", "NPM-020")
        assert f.passed
