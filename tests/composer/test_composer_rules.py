"""Composer rule pack: per-rule pass / fail / edge-case tests."""
from __future__ import annotations

import json
import pathlib

from pipeline_check.core.checks.composer.base import ComposerContext
from pipeline_check.core.checks.composer.pipelines import ComposerChecks


def _scan(
    tmp_path: pathlib.Path,
    manifest: dict,
    has_lock: bool = False,
) -> dict:
    (tmp_path / "composer.json").write_text(
        json.dumps(manifest), encoding="utf-8",
    )
    if has_lock:
        (tmp_path / "composer.lock").write_text(
            "{}", encoding="utf-8",
        )
    ctx = ComposerContext.from_path(str(tmp_path / "composer.json"))
    findings = ComposerChecks(ctx).run()
    return {f.check_id: f for f in findings}


# ── Parser sanity ─────────────────────────────────────────────


class TestParser:
    def test_parses_require_and_require_dev(self, tmp_path):
        manifest = {
            "name": "acme/widget",
            "require": {"monolog/monolog": "2.9.1"},
            "require-dev": {"phpunit/phpunit": "^10.5"},
        }
        (tmp_path / "composer.json").write_text(json.dumps(manifest))
        ctx = ComposerContext.from_path(
            str(tmp_path / "composer.json"),
        )
        deps = {d.name: d for d in ctx.files[0].dependencies}
        assert deps["monolog/monolog"].constraint == "2.9.1"
        assert deps["monolog/monolog"].section == "require"
        assert deps["phpunit/phpunit"].section == "require-dev"

    def test_parses_repositories_list_and_dict(self, tmp_path):
        manifest = {
            "name": "acme/widget",
            "repositories": [
                {"type": "composer", "url": "https://nexus/composer"},
            ],
        }
        (tmp_path / "composer.json").write_text(json.dumps(manifest))
        ctx = ComposerContext.from_path(
            str(tmp_path / "composer.json"),
        )
        repos = ctx.files[0].repositories
        assert len(repos) == 1
        assert repos[0].type == "composer"
        assert repos[0].url == "https://nexus/composer"

    def test_parses_scripts_string_and_array(self, tmp_path):
        manifest = {
            "name": "acme/widget",
            "scripts": {
                "post-install-cmd": "echo done",
                "post-update-cmd": ["echo a", "echo b"],
            },
        }
        (tmp_path / "composer.json").write_text(json.dumps(manifest))
        ctx = ComposerContext.from_path(
            str(tmp_path / "composer.json"),
        )
        scripts = {s.event: s for s in ctx.files[0].scripts}
        assert scripts["post-install-cmd"].commands == ("echo done",)
        assert scripts["post-update-cmd"].commands == ("echo a", "echo b")


# ── COMPOSER-001 ─────────────────────────────────────────────


class TestCOMPOSER001:
    def test_passes_with_lockfile(self, tmp_path):
        findings = _scan(
            tmp_path,
            {"name": "x", "require": {"monolog/monolog": "2.9.1"}},
            has_lock=True,
        )
        assert findings["COMPOSER-001"].passed

    def test_fails_without_lockfile(self, tmp_path):
        findings = _scan(
            tmp_path,
            {"name": "x", "require": {"monolog/monolog": "2.9.1"}},
        )
        assert not findings["COMPOSER-001"].passed

    def test_passes_when_no_deps(self, tmp_path):
        findings = _scan(tmp_path, {"name": "x"})
        assert findings["COMPOSER-001"].passed


# ── COMPOSER-002 ─────────────────────────────────────────────


class TestCOMPOSER002:
    def test_fires_on_caret(self, tmp_path):
        findings = _scan(
            tmp_path,
            {"name": "x", "require": {"monolog/monolog": "^2.9"}},
        )
        assert not findings["COMPOSER-002"].passed

    def test_fires_on_tilde(self, tmp_path):
        findings = _scan(
            tmp_path,
            {"name": "x", "require": {"monolog/monolog": "~2.9"}},
        )
        assert not findings["COMPOSER-002"].passed

    def test_fires_on_wildcard(self, tmp_path):
        findings = _scan(
            tmp_path,
            {"name": "x", "require": {"monolog/monolog": "2.9.*"}},
        )
        assert not findings["COMPOSER-002"].passed

    def test_fires_on_dev_branch(self, tmp_path):
        findings = _scan(
            tmp_path,
            {"name": "x", "require": {"monolog/monolog": "dev-main"}},
        )
        assert not findings["COMPOSER-002"].passed

    def test_passes_on_exact_pin(self, tmp_path):
        findings = _scan(
            tmp_path,
            {"name": "x", "require": {"monolog/monolog": "2.9.1"}},
        )
        assert findings["COMPOSER-002"].passed

    def test_fires_on_range(self, tmp_path):
        findings = _scan(
            tmp_path,
            {"name": "x", "require": {"monolog/monolog": ">=2.0,<3"}},
        )
        assert not findings["COMPOSER-002"].passed


# ── COMPOSER-003 ─────────────────────────────────────────────


class TestCOMPOSER003:
    def test_fires_on_http_repo(self, tmp_path):
        findings = _scan(
            tmp_path,
            {
                "name": "x",
                "repositories": [
                    {"type": "composer", "url": "http://internal/composer"},
                ],
            },
        )
        assert not findings["COMPOSER-003"].passed

    def test_passes_on_https_repo(self, tmp_path):
        findings = _scan(
            tmp_path,
            {
                "name": "x",
                "repositories": [
                    {"type": "composer", "url": "https://nexus/composer"},
                ],
            },
        )
        assert findings["COMPOSER-003"].passed

    def test_passes_with_no_repos(self, tmp_path):
        findings = _scan(tmp_path, {"name": "x"})
        assert findings["COMPOSER-003"].passed


# ── COMPOSER-004 ─────────────────────────────────────────────


class TestCOMPOSER004:
    def test_fires_on_embedded_credentials(self, tmp_path):
        findings = _scan(
            tmp_path,
            {
                "name": "x",
                "repositories": [{
                    "type": "composer",
                    "url": "https://bot:s3cr3t@nexus.corp/composer",
                }],
            },
        )
        assert not findings["COMPOSER-004"].passed
        # Secret must be redacted in the description.
        assert "s3cr3t" not in findings["COMPOSER-004"].description

    def test_passes_on_clean_url(self, tmp_path):
        findings = _scan(
            tmp_path,
            {
                "name": "x",
                "repositories": [{
                    "type": "composer",
                    "url": "https://nexus.corp/composer",
                }],
            },
        )
        assert findings["COMPOSER-004"].passed

    def test_skips_placeholder_secret(self, tmp_path):
        findings = _scan(
            tmp_path,
            {
                "name": "x",
                "repositories": [{
                    "type": "composer",
                    "url": (
                        "https://bot:${COMPOSER_TOKEN}@nexus.corp/composer"
                    ),
                }],
            },
        )
        assert findings["COMPOSER-004"].passed


# ── COMPOSER-005 ─────────────────────────────────────────────


class TestCOMPOSER005:
    def test_fires_on_dev(self, tmp_path):
        findings = _scan(
            tmp_path, {"name": "x", "minimum-stability": "dev"},
        )
        assert not findings["COMPOSER-005"].passed

    def test_fires_on_alpha(self, tmp_path):
        findings = _scan(
            tmp_path, {"name": "x", "minimum-stability": "alpha"},
        )
        assert not findings["COMPOSER-005"].passed

    def test_passes_on_stable(self, tmp_path):
        findings = _scan(
            tmp_path, {"name": "x", "minimum-stability": "stable"},
        )
        assert findings["COMPOSER-005"].passed

    def test_passes_when_unset(self, tmp_path):
        findings = _scan(tmp_path, {"name": "x"})
        assert findings["COMPOSER-005"].passed


# ── COMPOSER-006 ─────────────────────────────────────────────


class TestCOMPOSER006:
    def test_fires_on_curl_pipe_bash(self, tmp_path):
        findings = _scan(
            tmp_path,
            {
                "name": "x",
                "scripts": {
                    "post-install-cmd": [
                        "curl https://example.com/x | bash",
                    ],
                },
            },
        )
        assert not findings["COMPOSER-006"].passed

    def test_fires_on_wget_pipe_sh(self, tmp_path):
        findings = _scan(
            tmp_path,
            {
                "name": "x",
                "scripts": {
                    "post-update-cmd": [
                        "wget -qO - https://example.com/x | sh",
                    ],
                },
            },
        )
        assert not findings["COMPOSER-006"].passed

    def test_passes_when_sha_verified(self, tmp_path):
        findings = _scan(
            tmp_path,
            {
                "name": "x",
                "scripts": {
                    "post-install-cmd": [
                        "curl -fsSL -o x https://example.com/x && "
                        "echo a1b2 x | sha256sum -c && bash x",
                    ],
                },
            },
        )
        assert findings["COMPOSER-006"].passed

    def test_passes_on_local_echo(self, tmp_path):
        findings = _scan(
            tmp_path,
            {
                "name": "x",
                "scripts": {
                    "post-install-cmd": ["echo done"],
                },
            },
        )
        assert findings["COMPOSER-006"].passed


# ── COMPOSER-007 ─────────────────────────────────────────────


class TestCOMPOSER007:
    def test_fires_on_known_compromised_version(self, tmp_path):
        # Synthetic registry entry from _compromised_packages.py.
        findings = _scan(
            tmp_path,
            {
                "name": "x",
                "require": {
                    "example-vendor/example-known-bad": "1.0.0",
                },
            },
        )
        assert not findings["COMPOSER-007"].passed

    def test_passes_on_clean_pin(self, tmp_path):
        findings = _scan(
            tmp_path,
            {
                "name": "x",
                "require": {"monolog/monolog": "2.9.1"},
            },
        )
        assert findings["COMPOSER-007"].passed

    def test_strips_v_prefix(self, tmp_path):
        findings = _scan(
            tmp_path,
            {
                "name": "x",
                "require": {
                    "example-vendor/example-known-bad": "v1.0.0",
                },
            },
        )
        assert not findings["COMPOSER-007"].passed


# ── COMPOSER-008 ─────────────────────────────────────────────


class TestCOMPOSER008:
    def test_fires_on_wildcard_true(self, tmp_path):
        findings = _scan(
            tmp_path,
            {"name": "x", "config": {"allow-plugins": True}},
        )
        assert not findings["COMPOSER-008"].passed

    def test_passes_on_per_plugin_map(self, tmp_path):
        findings = _scan(
            tmp_path,
            {
                "name": "x",
                "config": {
                    "allow-plugins": {"symfony/flex": True},
                },
            },
        )
        assert findings["COMPOSER-008"].passed

    def test_passes_when_unset(self, tmp_path):
        findings = _scan(tmp_path, {"name": "x"})
        assert findings["COMPOSER-008"].passed

    def test_passes_on_false(self, tmp_path):
        findings = _scan(
            tmp_path,
            {"name": "x", "config": {"allow-plugins": False}},
        )
        assert findings["COMPOSER-008"].passed


# ── COMPOSER-011 ─────────────────────────────────────────────


class TestCOMPOSER011:
    def test_fires_on_vcs_repo(self, tmp_path):
        findings = _scan(
            tmp_path,
            {
                "name": "x",
                "repositories": [
                    {
                        "type": "vcs",
                        "url": "https://github.com/attacker/widgets",
                    },
                ],
            },
        )
        assert not findings["COMPOSER-011"].passed

    def test_fires_on_package_type(self, tmp_path):
        findings = _scan(
            tmp_path,
            {
                "name": "x",
                "repositories": [
                    {
                        "type": "package",
                        "package": {
                            "name": "acme/widgets",
                            "version": "1.0.0",
                        },
                    },
                ],
            },
        )
        assert not findings["COMPOSER-011"].passed

    def test_passes_on_path_repo(self, tmp_path):
        findings = _scan(
            tmp_path,
            {
                "name": "x",
                "repositories": [
                    {"type": "path", "url": "../local-pkg"},
                ],
            },
        )
        assert findings["COMPOSER-011"].passed

    def test_passes_with_no_repos(self, tmp_path):
        findings = _scan(tmp_path, {"name": "x"})
        assert findings["COMPOSER-011"].passed


# ── COMPOSER-012 ─────────────────────────────────────────────


class TestCOMPOSER012:
    def test_fires_on_packagist_disabled_keyed(self, tmp_path):
        findings = _scan(
            tmp_path,
            {"name": "x", "repositories": {"packagist.org": False}},
        )
        assert not findings["COMPOSER-012"].passed

    def test_fires_on_packagist_disabled_list(self, tmp_path):
        findings = _scan(
            tmp_path,
            {"name": "x", "repositories": [{"packagist.org": False}]},
        )
        assert not findings["COMPOSER-012"].passed

    def test_fires_on_canonical_repo(self, tmp_path):
        findings = _scan(
            tmp_path,
            {
                "name": "x",
                "repositories": [
                    {
                        "type": "composer",
                        "url": "https://repo.example",
                        "canonical": True,
                    },
                ],
            },
        )
        assert not findings["COMPOSER-012"].passed

    def test_passes_on_default_repositories(self, tmp_path):
        findings = _scan(
            tmp_path,
            {
                "name": "x",
                "repositories": [
                    {"type": "composer", "url": "https://repo.example"},
                ],
            },
        )
        assert findings["COMPOSER-012"].passed


# ── COMPOSER-013 ─────────────────────────────────────────────


class TestCOMPOSER013:
    def test_fires_on_disable_tls_true(self, tmp_path):
        findings = _scan(
            tmp_path,
            {"name": "x", "config": {"disable-tls": True}},
        )
        assert not findings["COMPOSER-013"].passed

    def test_passes_when_absent(self, tmp_path):
        findings = _scan(
            tmp_path,
            {"name": "x", "config": {"secure-http": True}},
        )
        assert findings["COMPOSER-013"].passed

    def test_passes_when_false(self, tmp_path):
        findings = _scan(
            tmp_path,
            {"name": "x", "config": {"disable-tls": False}},
        )
        assert findings["COMPOSER-013"].passed


# ── COMPOSER-014 ─────────────────────────────────────────────


class TestCOMPOSER014:
    def test_fires_on_dev_without_prefer_stable(self, tmp_path):
        findings = _scan(
            tmp_path,
            {"name": "x", "minimum-stability": "dev"},
        )
        assert not findings["COMPOSER-014"].passed

    def test_fires_on_beta_without_prefer_stable(self, tmp_path):
        findings = _scan(
            tmp_path,
            {"name": "x", "minimum-stability": "beta"},
        )
        assert not findings["COMPOSER-014"].passed

    def test_passes_with_prefer_stable(self, tmp_path):
        findings = _scan(
            tmp_path,
            {
                "name": "x",
                "minimum-stability": "dev",
                "prefer-stable": True,
            },
        )
        assert findings["COMPOSER-014"].passed

    def test_passes_on_stable(self, tmp_path):
        findings = _scan(
            tmp_path,
            {"name": "x", "minimum-stability": "stable"},
        )
        assert findings["COMPOSER-014"].passed

    def test_passes_when_unset(self, tmp_path):
        findings = _scan(tmp_path, {"name": "x"})
        assert findings["COMPOSER-014"].passed
