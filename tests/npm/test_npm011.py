"""Per-rule tests for NPM-011 (secrets in package.json files field)."""

from .conftest import run_check_manifest


class TestNPM011:
    def test_fails_on_env_file(self):
        data = {
            "name": "x", "version": "1.0.0",
            "files": ["dist/**", ".env"],
        }
        f = run_check_manifest(data, "NPM-011")
        assert not f.passed
        assert ".env" in f.description

    def test_fails_on_env_dotted_suffix(self):
        # ``.env.production`` is still a secret file.
        data = {
            "name": "x", "version": "1.0.0",
            "files": [".env.production"],
        }
        f = run_check_manifest(data, "NPM-011")
        assert not f.passed

    def test_fails_on_npmrc(self):
        data = {
            "name": "x", "version": "1.0.0",
            "files": [".npmrc", "dist/**"],
        }
        f = run_check_manifest(data, "NPM-011")
        assert not f.passed
        assert ".npmrc" in f.description

    def test_fails_on_pem_key(self):
        data = {
            "name": "x", "version": "1.0.0",
            "files": ["certs/server.pem"],
        }
        f = run_check_manifest(data, "NPM-011")
        assert not f.passed

    def test_fails_on_ssh_key(self):
        data = {
            "name": "x", "version": "1.0.0",
            "files": ["secrets/id_rsa"],
        }
        f = run_check_manifest(data, "NPM-011")
        assert not f.passed
        assert "SSH" in f.description

    def test_fails_on_ssh_dir(self):
        data = {
            "name": "x", "version": "1.0.0",
            "files": [".ssh/"],
        }
        f = run_check_manifest(data, "NPM-011")
        assert not f.passed

    def test_fails_on_aws_credentials(self):
        data = {
            "name": "x", "version": "1.0.0",
            "files": [".aws/credentials"],
        }
        f = run_check_manifest(data, "NPM-011")
        assert not f.passed

    def test_passes_on_clean_files(self):
        data = {
            "name": "x", "version": "1.0.0",
            "files": ["dist/**", "README.md", "LICENSE", "lib/"],
        }
        f = run_check_manifest(data, "NPM-011")
        assert f.passed

    def test_passes_when_files_absent(self):
        # No ``files`` field declared. NPM-011's surface is the
        # explicit positive-list shape; broad-include cases are
        # handled (or not) by other rules.
        data = {"name": "x", "version": "1.0.0"}
        f = run_check_manifest(data, "NPM-011")
        assert f.passed

    def test_passes_when_files_empty(self):
        data = {"name": "x", "version": "1.0.0", "files": []}
        f = run_check_manifest(data, "NPM-011")
        assert f.passed

    def test_my_envelope_does_not_match_env(self):
        # ``.env`` regex is anchored to a path segment, so something
        # like ``my.envelope.js`` must not trip the rule.
        data = {
            "name": "x", "version": "1.0.0",
            "files": ["src/my.envelope.js"],
        }
        f = run_check_manifest(data, "NPM-011")
        assert f.passed

    def test_normalizes_backslashes(self):
        # Windows-style paths in files entries normalize to forward
        # slashes for matching.
        data = {
            "name": "x", "version": "1.0.0",
            "files": ["secrets\\id_rsa"],
        }
        f = run_check_manifest(data, "NPM-011")
        assert not f.passed

    def test_handles_dot_slash_prefix(self):
        # ``./.env`` is the same as ``.env``.
        data = {
            "name": "x", "version": "1.0.0",
            "files": ["./.env"],
        }
        f = run_check_manifest(data, "NPM-011")
        assert not f.passed
