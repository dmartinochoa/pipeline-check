"""Tests for the opt-in Shannon-entropy secret detector.

Covers four contracts:

1. **Off by default.** Plain ``find_secret_values(doc)`` does not
   return entropy hits unless ``enable_entropy_detection`` was
   called. This is the upgrade-friendliness guarantee, turning the
   feature on is an explicit opt-in.
2. **Math is correct.** ``shannon_entropy`` returns 0 for the
   empty / single-char case and approaches the alphabet maximum
   for random-looking inputs.
3. **Key-context gating.** A high-entropy value in a credential-
   shaped key (``API_KEY``) fires; the same value in a non-
   credential key (``commit_sha``) does not.
4. **Layered FP suppression.** Token-shape, length, placeholder
   markers, and the deterministic-detector overlap each
   independently reject candidates that would otherwise look like
   credentials.
"""
from __future__ import annotations

import math

import pytest

from pipeline_check.core.checks import _secrets as secrets_mod
from pipeline_check.core.checks._secrets import (
    _key_suggests_credential as key_suggests_credential,
)
from pipeline_check.core.checks._secrets import (
    enable_entropy_detection,
    find_secret_values,
    shannon_entropy,
)


@pytest.fixture(autouse=True)
def _reset_state():
    secrets_mod.reset_patterns()
    yield
    secrets_mod.reset_patterns()


# ── shannon_entropy math ──────────────────────────────────────────


class TestShannonEntropy:
    def test_empty_string_is_zero(self):
        assert shannon_entropy("") == 0.0

    def test_single_char_is_zero(self):
        # H = -p log2 p; with one symbol p=1 so H=0.
        assert shannon_entropy("aaaaaaa") == 0.0

    def test_uniform_two_chars_is_one_bit(self):
        # H over a 2-symbol uniform distribution = 1 bit/char.
        assert shannon_entropy("abababab") == pytest.approx(1.0)

    def test_uniform_four_chars_is_two_bits(self):
        # 4 distinct symbols, equal frequency -> log2(4) = 2.
        assert shannon_entropy("abcdabcd") == pytest.approx(2.0)

    def test_random_hex_lands_near_4_bits(self):
        # 32 chars over a 16-symbol alphabet caps at log2(16) = 4
        # bits/char. The value below is constructed to use every
        # symbol equally so it hits the theoretical max exactly.
        token = "0123456789abcdef0123456789abcdef"
        h = shannon_entropy(token)
        assert h == pytest.approx(math.log2(16), abs=0.01)

    def test_repeated_pattern_below_threshold(self):
        # A repeated short pattern has low diversity, so entropy
        # stays below the 3.5 bits/char threshold even when the
        # string is long. This is the gate that filters out things
        # like ``aaaa-bbbb-cccc-dddd-eeee`` placeholder UUIDs.
        # Short English prose, by contrast, can exceed 3.5
        # bits/char (limited symbol reuse in short strings); the
        # *token-shape* filter is what catches prose, not entropy.
        assert shannon_entropy("abcabcabcabcabcabc") < 3.5


# ── _key_suggests_credential ──────────────────────────────────────


class TestKeyHeuristic:
    @pytest.mark.parametrize("key", [
        "API_KEY", "apiKey", "api-key", "api key",
        "password", "PASSWD", "pwd",
        "secret", "SECRET_KEY",
        "token", "auth_token", "AUTH_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
        "private_key", "privateKey",
        "credentials", "credential",
        "passkey",
        "x-auth-token",
    ])
    def test_credential_shaped_keys_fire(self, key):
        assert key_suggests_credential(key), key

    @pytest.mark.parametrize("key", [
        "monkey",            # contains "key" but not as a whole part
        "filekey",           # same — would FP a substring match
        "version",
        "name",
        "id",
        "commit_sha",
        "build_number",
        "service_account",
        "host",
        "url",
        "path",
        "",
    ])
    def test_non_credential_keys_do_not_fire(self, key):
        assert not key_suggests_credential(key), key


# ── Off-by-default contract ──────────────────────────────────────


class TestOffByDefault:
    def test_high_entropy_value_does_not_fire_by_default(self):
        # Random base62-shaped value. Without entropy detection
        # enabled, ``find_secret_values`` should not flag this:
        # the deterministic catalog has no detector for the shape.
        doc = {"API_KEY": "f8e3a921bc5d7e4f0a9b8c1d2e3f4a5b"}
        assert find_secret_values(doc) == []

    def test_pem_blocks_still_fire_without_entropy(self):
        # The deterministic surface is unchanged by the entropy
        # toggle, PEM detection runs regardless.
        pem = (
            "-----BEGIN PRIVATE KEY-----\n"
            "MIIEpAIBAAKCAQEA1234567890abcdefghij\n"
            "-----END PRIVATE KEY-----\n"
        )
        hits = find_secret_values({"key": pem})
        assert any(h.startswith("private_key:") for h in hits)


# ── Opt-in fires on real-shape values ────────────────────────────


class TestOptInFires:
    def test_random_token_in_api_key_field(self):
        enable_entropy_detection(True)
        doc = {"API_KEY": "f8e3a921bc5d7e4f0a9b8c1d2e3f4a5b6c7d8e9f"}
        hits = find_secret_values(doc)
        assert any(h.startswith("entropy:") for h in hits), hits

    def test_random_token_in_camelcase_password_field(self):
        enable_entropy_detection(True)
        doc = {"dbPassword": "K7q9pL2mN4xZ8vR3yT6wB1cF5jH0gA"}
        assert any(h.startswith("entropy:") for h in find_secret_values(doc))

    def test_kubernetes_envvar_shape_uses_name_as_key_context(self):
        # Tekton / K8s / CFN envvar list:
        #   env: [{name: API_KEY, value: "<token>"}]
        # The ``value`` field's literal key is "value", but the
        # sibling ``name`` field is what a human reads as the
        # variable's identity. The walker biases toward that.
        enable_entropy_detection(True)
        doc = {
            "env": [
                {
                    "name": "DATABASE_PASSWORD",
                    "value": "K7q9pL2mN4xZ8vR3yT6wB1cF5jH0gA",
                },
            ],
        }
        hits = find_secret_values(doc)
        assert any(h.startswith("entropy:") for h in hits), hits

    def test_label_carries_redacted_token(self):
        enable_entropy_detection(True)
        token = "f8e3a921bc5d7e4f0a9b8c1d2e3f4a5b6c7d8e9f"
        hits = find_secret_values({"API_KEY": token})
        assert any(h.startswith("entropy:") for h in hits)
        # Redaction shape: never echo the full token back.
        assert all(token not in h for h in hits)


# ── Layered FP suppression ───────────────────────────────────────


class TestSuppression:
    def test_short_value_does_not_fire(self):
        # Below MIN_ENTROPY_LENGTH (20 chars).
        enable_entropy_detection(True)
        doc = {"API_KEY": "abc123XY"}
        assert all(not h.startswith("entropy:") for h in find_secret_values(doc))

    def test_low_entropy_repetition_does_not_fire(self):
        # 30 chars but only 1 unique symbol -> H = 0.
        enable_entropy_detection(True)
        doc = {"API_KEY": "a" * 30}
        assert all(not h.startswith("entropy:") for h in find_secret_values(doc))

    def test_natural_language_does_not_fire(self):
        # English-shaped value (with spaces) shouldn't match the
        # token-shape regex even if entropy were high.
        enable_entropy_detection(True)
        doc = {"description": "the quick brown fox jumps over"}
        assert all(not h.startswith("entropy:") for h in find_secret_values(doc))

    def test_non_credential_key_does_not_fire(self):
        # Same value, different key. ``commit_sha`` doesn't read
        # as a credential field, so the entropy gate skips it.
        enable_entropy_detection(True)
        doc = {"commit_sha": "f8e3a921bc5d7e4f0a9b8c1d2e3f4a5b6c7d8e9f"}
        assert all(not h.startswith("entropy:") for h in find_secret_values(doc))

    def test_placeholder_marker_does_not_fire(self):
        # ``replaceme`` is in PLACEHOLDER_MARKER_RE so it's a known
        # docs-redaction shape; entropy must not promote it.
        enable_entropy_detection(True)
        doc = {"API_KEY": "replaceme_with_a_real_key_xxxxxxxxxxxxxx"}
        assert all(not h.startswith("entropy:") for h in find_secret_values(doc))

    def test_does_not_double_emit_when_prefix_detector_caught(self):
        # An AKIA-shaped value has BOTH high entropy AND a known
        # prefix. Only the prefix label should fire, never both.
        enable_entropy_detection(True)
        doc = {"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"}
        hits = find_secret_values(doc)
        assert any(h.startswith("aws_access_key:") for h in hits)
        assert all(not h.startswith("entropy:") for h in hits), hits

    def test_yaml_path_with_separators_does_not_fire(self):
        # Token-shape regex deliberately excludes ``/``, ``:``,
        # backslashes, etc., so a path-like value can't trigger
        # entropy even in a credential-named field.
        enable_entropy_detection(True)
        doc = {"private_key_path": "/etc/secrets/key.pem"}
        assert all(not h.startswith("entropy:") for h in find_secret_values(doc))


# ── reset_patterns clears the toggle ─────────────────────────────


class TestResetClears:
    def test_reset_disables_entropy_detection(self):
        enable_entropy_detection(True)
        doc = {"API_KEY": "f8e3a921bc5d7e4f0a9b8c1d2e3f4a5b6c7d8e9f"}
        assert any(
            h.startswith("entropy:") for h in find_secret_values(doc)
        )
        secrets_mod.reset_patterns()
        # After reset, the same input goes back to producing no
        # entropy hit. Keeps Lambda containers / scanner reuse from
        # leaking the toggle across invocations.
        assert all(
            not h.startswith("entropy:") for h in find_secret_values(doc)
        )


# ── Pre-collected string list (Jenkins shape) ────────────────────


class TestPreCollectedListShape:
    def test_entropy_pass_skipped_for_string_list_input(self):
        # The Jenkins check passes ``[jf.text]``: a flat list of
        # strings without YAML key context. The entropy pass needs
        # that key context, so it's skipped for the shape; only the
        # deterministic detectors run.
        enable_entropy_detection(True)
        text = "API_KEY=f8e3a921bc5d7e4f0a9b8c1d2e3f4a5b6c7d8e9f\n"
        hits = find_secret_values([text])
        assert all(not h.startswith("entropy:") for h in hits)
