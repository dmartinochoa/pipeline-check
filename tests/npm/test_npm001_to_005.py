"""Per-rule tests for NPM-001..005.

NPM-001 (floating version range in package.json),
NPM-002 (lockfile entry missing integrity hash),
NPM-003 (lockfile entry from non-registry source),
NPM-004 (install-time lifecycle script in package.json),
NPM-005 (git dependency uses a mutable ref).

NPM-006 (compromised-package registry lookup) lives in
``test_npm006.py`` so the curated-list assertions stay
grouped with the registry data.
"""
from __future__ import annotations

from .conftest import run_check_lock, run_check_manifest

# ── NPM-001 floating range ─────────────────────────────────────────────


class TestNPM001:
    def test_fails_on_caret_range(self):
        data = {"name": "x", "version": "1.0.0", "dependencies": {"lodash": "^4.17.21"}}
        f = run_check_manifest(data, "NPM-001")
        assert not f.passed
        assert "lodash" in f.description

    def test_fails_on_tilde_range(self):
        data = {"name": "x", "version": "1.0.0", "dependencies": {"axios": "~1.6.0"}}
        f = run_check_manifest(data, "NPM-001")
        assert not f.passed

    def test_fails_on_latest_tag(self):
        data = {"name": "x", "version": "1.0.0", "dependencies": {"react": "latest"}}
        f = run_check_manifest(data, "NPM-001")
        assert not f.passed

    def test_fails_on_star(self):
        data = {"name": "x", "version": "1.0.0", "devDependencies": {"prettier": "*"}}
        f = run_check_manifest(data, "NPM-001")
        assert not f.passed

    def test_fails_on_minor_wildcard(self):
        # ``1.x`` is npm's wildcard form, equivalent to a caret range.
        data = {"name": "x", "version": "1.0.0", "dependencies": {"react": "1.x"}}
        f = run_check_manifest(data, "NPM-001")
        assert not f.passed
        assert "react" in f.description

    def test_fails_on_patch_wildcard(self):
        data = {"name": "x", "version": "1.0.0", "dependencies": {"react": "1.2.x"}}
        f = run_check_manifest(data, "NPM-001")
        assert not f.passed

    def test_fails_on_uppercase_wildcard(self):
        data = {"name": "x", "version": "1.0.0", "dependencies": {"react": "1.X"}}
        f = run_check_manifest(data, "NPM-001")
        assert not f.passed

    def test_fails_on_bare_x(self):
        # Bare ``x`` is shorthand for any version (equivalent to ``*``).
        data = {"name": "x", "version": "1.0.0", "dependencies": {"react": "x"}}
        f = run_check_manifest(data, "NPM-001")
        assert not f.passed

    def test_passes_on_exact_pin(self):
        data = {
            "name": "x", "version": "1.0.0",
            "dependencies": {"lodash": "4.17.21", "axios": "1.6.0"},
        }
        f = run_check_manifest(data, "NPM-001")
        assert f.passed

    def test_skips_workspace_protocol(self):
        # ``workspace:*`` is a Yarn / pnpm workspace pointer, not a
        # version range, and isn't this rule's surface.
        data = {
            "name": "monorepo", "version": "1.0.0",
            "dependencies": {"@internal/foo": "workspace:*"},
        }
        f = run_check_manifest(data, "NPM-001")
        assert f.passed

    def test_skips_file_and_git_specs(self):
        data = {
            "name": "x", "version": "1.0.0",
            "dependencies": {
                "local": "file:./packages/local",
                "fork": "git+https://github.com/o/r.git#0123456789abcdef0123456789abcdef01234567",
            },
        }
        f = run_check_manifest(data, "NPM-001")
        assert f.passed


# ── NPM-002 lock entry missing integrity ───────────────────────────────


class TestNPM002:
    def test_fails_on_missing_integrity(self):
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root", "version": "1.0.0"},
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    # no ``integrity``
                },
            },
        }
        f = run_check_lock(data, "NPM-002")
        assert not f.passed
        assert "node_modules/lodash" in f.description

    def test_passes_with_integrity(self):
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root", "version": "1.0.0"},
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-FAKE_HASH_FOR_TEST_PURPOSES_ONLY_NOT_REAL_INTEGRITY==",
                },
            },
        }
        f = run_check_lock(data, "NPM-002")
        assert f.passed

    def test_skips_link_entries(self):
        # A workspace symlink has no tarball to hash; ``link: true``
        # is the documented escape hatch.
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root", "version": "1.0.0"},
                "packages/foo": {"link": True, "resolved": "packages/foo"},
            },
        }
        f = run_check_lock(data, "NPM-002")
        assert f.passed

    def test_handles_legacy_v1_format(self):
        data = {
            "lockfileVersion": 1,
            "dependencies": {
                "lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    # no ``integrity``
                },
            },
        }
        f = run_check_lock(data, "NPM-002")
        assert not f.passed


# ── NPM-003 non-registry source ────────────────────────────────────────


class TestNPM003:
    def test_fails_on_git_ssh(self):
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root", "version": "1.0.0"},
                "node_modules/forked": {
                    "version": "0.0.0",
                    "resolved": "git+ssh://git@github.com/owner/fork.git#abcdef",
                },
            },
        }
        f = run_check_lock(data, "NPM-003")
        assert not f.passed

    def test_fails_on_http(self):
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root", "version": "1.0.0"},
                "node_modules/insecure": {
                    "version": "1.0.0",
                    "resolved": "http://internal-mirror.example.com/insecure-1.0.0.tgz",
                },
            },
        }
        f = run_check_lock(data, "NPM-003")
        assert not f.passed

    def test_fails_on_git_https_without_sha(self):
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root", "version": "1.0.0"},
                "node_modules/fork": {
                    "version": "0.0.0",
                    "resolved": "git+https://github.com/o/fork.git#main",
                },
            },
        }
        f = run_check_lock(data, "NPM-003")
        assert not f.passed

    def test_passes_on_git_https_with_sha(self):
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root", "version": "1.0.0"},
                "node_modules/fork": {
                    "version": "0.0.0",
                    "resolved": (
                        "git+https://github.com/o/fork.git#"
                        "0123456789abcdef0123456789abcdef01234567"
                    ),
                },
            },
        }
        f = run_check_lock(data, "NPM-003")
        assert f.passed

    def test_passes_on_https_registry(self):
        data = {
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root", "version": "1.0.0"},
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-XXX",
                },
            },
        }
        f = run_check_lock(data, "NPM-003")
        assert f.passed


# ── NPM-004 install-time lifecycle script ──────────────────────────────


class TestNPM004:
    def test_fails_on_postinstall(self):
        data = {
            "name": "x", "version": "1.0.0",
            "scripts": {"postinstall": "node ./harvest.js"},
        }
        f = run_check_manifest(data, "NPM-004")
        assert not f.passed
        assert "postinstall" in f.description

    def test_fails_on_preinstall(self):
        data = {
            "name": "x", "version": "1.0.0",
            "scripts": {"preinstall": "rm -rf /"},
        }
        f = run_check_manifest(data, "NPM-004")
        assert not f.passed

    def test_fails_on_prepare(self):
        data = {
            "name": "x", "version": "1.0.0",
            "scripts": {"prepare": "npm run build"},
        }
        f = run_check_manifest(data, "NPM-004")
        assert not f.passed

    def test_passes_without_install_hooks(self):
        data = {
            "name": "x", "version": "1.0.0",
            "scripts": {"build": "tsc", "test": "vitest"},
        }
        f = run_check_manifest(data, "NPM-004")
        assert f.passed

    def test_passes_without_scripts_block(self):
        data = {"name": "x", "version": "1.0.0"}
        f = run_check_manifest(data, "NPM-004")
        assert f.passed


# ── NPM-005 git dep mutable ref ────────────────────────────────────────


class TestNPM005:
    def test_fails_on_branch_ref(self):
        data = {
            "name": "x", "version": "1.0.0",
            "dependencies": {
                "fork": "git+https://github.com/o/r.git#main",
            },
        }
        f = run_check_manifest(data, "NPM-005")
        assert not f.passed
        assert "fork" in f.description

    def test_fails_on_tag_ref(self):
        data = {
            "name": "x", "version": "1.0.0",
            "dependencies": {
                "fork": "git+https://github.com/o/r.git#v1.2.3",
            },
        }
        f = run_check_manifest(data, "NPM-005")
        assert not f.passed

    def test_fails_on_github_shorthand_without_ref(self):
        data = {
            "name": "x", "version": "1.0.0",
            "dependencies": {"fork": "github:owner/repo"},
        }
        f = run_check_manifest(data, "NPM-005")
        assert not f.passed
        assert "no ref pin" in f.description

    def test_passes_with_40char_sha(self):
        data = {
            "name": "x", "version": "1.0.0",
            "dependencies": {
                "fork": "git+https://github.com/o/r.git#"
                        "0123456789abcdef0123456789abcdef01234567",
            },
        }
        f = run_check_manifest(data, "NPM-005")
        assert f.passed

    def test_passes_on_registry_spec(self):
        data = {
            "name": "x", "version": "1.0.0",
            "dependencies": {"lodash": "4.17.21"},
        }
        f = run_check_manifest(data, "NPM-005")
        assert f.passed
