"""Per-rule tests for COMPOSER-009 and COMPOSER-010."""
from __future__ import annotations

import json
import pathlib

from pipeline_check.core.checks.composer.base import ComposerContext
from pipeline_check.core.checks.composer.pipelines import ComposerChecks


def _scan(tmp_path: pathlib.Path) -> dict:
    ctx = ComposerContext.from_path(str(tmp_path / "composer.json"))
    return {f.check_id: f for f in ComposerChecks(ctx).run()}


# ── COMPOSER-009 ─────────────────────────────────────────────


class TestCOMPOSER009:
    def test_fires_on_auth_json_with_http_basic_password(self, tmp_path):
        (tmp_path / "composer.json").write_text(
            json.dumps({"name": "x"}), encoding="utf-8",
        )
        (tmp_path / "auth.json").write_text(
            json.dumps({
                "http-basic": {
                    "nexus.corp": {
                        "username": "bot", "password": "s3cr3t",
                    },
                },
            }),
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert not findings["COMPOSER-009"].passed
        assert "s3cr3t" not in findings["COMPOSER-009"].description

    def test_fires_on_bearer_token(self, tmp_path):
        (tmp_path / "composer.json").write_text(
            json.dumps({"name": "x"}), encoding="utf-8",
        )
        (tmp_path / "auth.json").write_text(
            json.dumps({"bearer": {"api.example": "raw-token"}}),
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert not findings["COMPOSER-009"].passed

    def test_fires_on_github_oauth(self, tmp_path):
        (tmp_path / "composer.json").write_text(
            json.dumps({"name": "x"}), encoding="utf-8",
        )
        (tmp_path / "auth.json").write_text(
            json.dumps({
                "github-oauth": {"github.com": "ghp_xxx"},
            }),
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert not findings["COMPOSER-009"].passed

    def test_passes_when_no_auth_json(self, tmp_path):
        (tmp_path / "composer.json").write_text(
            json.dumps({"name": "x"}), encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert findings["COMPOSER-009"].passed

    def test_passes_when_placeholder_value(self, tmp_path):
        (tmp_path / "composer.json").write_text(
            json.dumps({"name": "x"}), encoding="utf-8",
        )
        (tmp_path / "auth.json").write_text(
            json.dumps({
                "http-basic": {
                    "nexus.corp": {
                        "username": "bot",
                        "password": "${COMPOSER_AUTH_TOKEN}",
                    },
                },
            }),
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert findings["COMPOSER-009"].passed

    def test_passes_when_empty_auth_json(self, tmp_path):
        (tmp_path / "composer.json").write_text(
            json.dumps({"name": "x"}), encoding="utf-8",
        )
        (tmp_path / "auth.json").write_text("{}", encoding="utf-8")
        findings = _scan(tmp_path)
        assert findings["COMPOSER-009"].passed


# ── COMPOSER-010 ─────────────────────────────────────────────


class TestCOMPOSER010:
    def test_fires_on_explicit_false(self, tmp_path):
        (tmp_path / "composer.json").write_text(
            json.dumps({
                "name": "x", "config": {"secure-http": False},
            }),
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert not findings["COMPOSER-010"].passed

    def test_passes_when_unset(self, tmp_path):
        (tmp_path / "composer.json").write_text(
            json.dumps({"name": "x"}), encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert findings["COMPOSER-010"].passed

    def test_passes_when_true(self, tmp_path):
        (tmp_path / "composer.json").write_text(
            json.dumps({
                "name": "x", "config": {"secure-http": True},
            }),
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert findings["COMPOSER-010"].passed

    def test_does_not_fire_on_non_boolean(self, tmp_path):
        # ``secure-http: "false"`` (a string, not a bool) shouldn't
        # trip the rule — that's a separate Composer config error.
        (tmp_path / "composer.json").write_text(
            json.dumps({
                "name": "x", "config": {"secure-http": "false"},
            }),
            encoding="utf-8",
        )
        findings = _scan(tmp_path)
        assert findings["COMPOSER-010"].passed
