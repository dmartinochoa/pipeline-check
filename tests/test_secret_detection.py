"""Per-detector tests for the expanded secret catalog, plus the
placeholder-suppression and PEM-block-detection layers.

Each ``DETECTOR`` entry pairs a detector name with a positive token
(real-shape) and a negative token (similar but doesn't match the
contract). The negative cases protect against false positives the
loose original alternation might have produced.
"""
from __future__ import annotations

import pytest

from pipeline_check.core.checks import _secrets as secrets_mod


@pytest.fixture(autouse=True)
def _clean_user_patterns():
    secrets_mod.reset_patterns()
    yield
    secrets_mod.reset_patterns()


# ──────────────────────────────────────────────────────────────────────
# Per-detector positive cases
# ──────────────────────────────────────────────────────────────────────
#
# Each entry: (detector_name, real-shape token).
# Tokens are FAKE — chosen to match the published shape but not be a
# usable credential. They are length-correct so the pattern fires.
# Tokens use varied characters because the placeholder filter
# (intentionally) treats any run of 5+ identical letters as a doc
# redaction marker — a "real" key has more entropy than a wall of one
# character. These are still FAKE; just shaped like a real key would
# be after a vendor's RNG ran.
_FILLER = "0123456789abcdefghijABCDEFGHIJ" * 10  # plenty of variety

DETECTORS: list[tuple[str, str]] = [
    ("aws_access_key",        "AKIAZ3MHALF2TESTHIJK"),
    ("aws_access_key",        "ASIAZ3MHALF2TESTHIJK"),
    ("github_token",          "ghp_" + _FILLER[:40]),
    ("github_token",          "gho_" + _FILLER[:36]),
    # Fine-grained PAT: ``github_pat_`` + 82-char body.
    ("github_token",          "github_pat_" + _FILLER[:82]),
    ("slack_token",           "xoxb-1234567890123-1234567890123"),
    ("jwt",                   "eyJabcdefghij.eyJklmnopqrst.signaturesignaturex"),
    ("stripe_secret",         "sk_live_" + _FILLER[:30]),
    ("stripe_secret",         "sk_test_" + _FILLER[:24]),
    ("stripe_secret",         "rk_live_" + _FILLER[:26]),
    ("stripe_publishable",    "pk_live_" + _FILLER[:24]),
    ("google_api_key",        "AIza" + _FILLER[:35]),
    ("npm_token",             "npm_" + _FILLER[:36]),
    ("pypi_token",            "pypi-AgEIcHlwaS5vcmc" + _FILLER[:50]),
    ("docker_hub_pat",        "dckr_pat_" + _FILLER[:28]),
    ("gitlab_pat",            "glpat-abcdefghij1234567890"),
    ("gitlab_deploy_token",   "gldt-" + "1234567890ABCDEFghij"),
    ("sendgrid",              "SG." + _FILLER[:22] + "." + _FILLER[:43]),
    ("anthropic_api_key",     "sk-ant-api03-" + _FILLER[:95]),
    ("digitalocean_token",    "dop_v1_" + ("0123456789abcdef" * 4)),
    ("hashicorp_vault",       "hvs." + _FILLER[:30]),
    ("twilio_api_key",        "SK" + "0123456789abcdef" * 2),
    ("twilio_account_sid",    "AC" + "0123456789abcdef" * 2),
    ("mailchimp_api_key",     "0123456789abcdef" * 2 + "-us21"),
    ("shopify_token",         "shpat_" + "0123456789abcdef" * 2),
    ("shopify_token",         "shpss_" + "0123456789abcdef" * 2),
    ("databricks_token",      "dapi" + "0123456789abcdef" * 2),
    ("openai_api_key",        "sk-" + _FILLER[:20] + "T3BlbkFJ" + _FILLER[:20]),
    ("openai_api_key",        "sk-proj-" + _FILLER[:45]),
    ("huggingface_token",     "hf_" + _FILLER[:40]),
    ("age_secret_key",        "AGE-SECRET-KEY-1" + _FILLER[:58]),
    ("linear_api_key",        "lin_api_" + _FILLER[:40]),
    ("planetscale_token",     "pscale_tkn_" + _FILLER[:45]),
    ("new_relic_api_key",     "NRAK-" + _FILLER[:27]),
    ("grafana_api_key",       "glsa_" + _FILLER[:35]),
    ("telegram_bot_token",    "123456789:" + _FILLER[:35]),
    # ── New detectors (round 2) ──
    ("atlassian_api_token",   "ATATT3" + _FILLER[:55]),
    ("gitlab_runner_token",   "glrt-" + _FILLER[:25]),
    ("gitlab_ci_token",       "glcbt-" + _FILLER[:25]),
    ("supabase_key",          "sbp_" + ("0123456789abcdef" * 3)[:40]),
    ("fly_api_token",         "fo1_" + _FILLER[:45]),
    ("pulumi_access_token",   "pul-" + ("0123456789abcdef" * 3)[:40]),
    ("doppler_token",         "dp.ct." + _FILLER[:45]),
    ("doppler_token",         "dp.sa." + _FILLER[:42]),
    ("doppler_token",         "dp.scrt." + _FILLER[:44]),
    ("netlify_token",         "nfp_" + _FILLER[:45]),
    ("railway_token",         "railway_" + _FILLER[:40]),
    ("render_api_key",        "rnd_" + _FILLER[:35]),
    ("prefect_api_key",       "pnu_" + _FILLER[:40]),
    ("neon_api_key",          "neon_" + _FILLER[:40]),
    # ── New detectors (round 3) ──
    ("cohere_api_key",        "co_pat_" + _FILLER[:45]),
    ("replicate_token",       "r8_" + _FILLER[:40]),
    ("asana_pat",             "1/" + "1" * 16 + ":" + "0123456789abcdef" * 2),
    ("square_access_token",   "sq0atp-" + _FILLER[:25]),
    ("square_access_token",   "sq0csp-" + _FILLER[:25]),
    ("terraform_cloud_token", "abcdef1234567g.atlasv1." + _FILLER[:65]),
    # ── New detectors (round 4) ──
    ("openai_api_key",        "sk-svcacct-" + _FILLER[:45]),
    ("postman_api_key",       "PMAK-" + "0123456789abcdef01234567" + "-" + "0123456789abcdef0123456789abcdef01"),
    ("tailscale_key",         "tskey-auth-k1A2B3C4CNTRL-" + _FILLER[:30]),
    ("tailscale_key",         "tskey-api-k9Z8Y7X6CNTRL-" + _FILLER[:30]),
    ("sentry_auth_token",     "sntrys_" + _FILLER[:55]),
    ("sentry_auth_token",     "sntryu_" + _FILLER[:55]),
    # ── New detectors (round 5): LLM provider API keys ──
    ("groq_api_key",          "gsk_" + _FILLER[:52]),
    ("xai_api_key",           "xai-" + _FILLER[:80]),
    ("perplexity_api_key",    "pplx-" + _FILLER[:48]),
    # ── New detectors (round 6): incoming-webhook URLs ──
    ("slack_webhook",
     "https://hooks.slack.com/services/T00000000/B00000000/" + _FILLER[:24]),
    ("discord_webhook",
     "https://discord.com/api/webhooks/123456789012345678/" + _FILLER[:68]),
]


@pytest.mark.parametrize("name,token", DETECTORS, ids=[f"{n}-{i}" for i, (n, _) in enumerate(DETECTORS)])
def test_detector_fires_on_real_shape_token(name, token):
    """Every built-in detector must fire on a token matching its
    published shape, and the resulting hit must carry the detector's
    label so consumers can group by type."""
    hits = secrets_mod.find_secret_values({"k": token})
    assert hits, f"detector {name!r} did not fire on {token[:12]}…"
    assert any(h.startswith(f"{name}:") for h in hits), (
        f"hit label missing detector name {name!r}; got {hits}"
    )


# ──────────────────────────────────────────────────────────────────────
# Per-detector negative cases — values that LOOK similar but shouldn't
# match the corresponding detector. Catches loose anchoring.
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("token,reason", [
    ("AKIASHORTKEY",                       "AWS access key needs 16 trailing chars"),
    ("ghp_short",                          "GitHub PAT needs 36+ chars after prefix"),
    ("xoxb-",                              "Slack token needs payload after the dash"),
    ("eyJ.foo.bar",                        "JWT segments need 10+ chars each"),
    ("sk_live_short",                      "Stripe key needs 24+ payload chars"),
    ("AIzaTooShort",                       "Google API key requires exactly 35 trailing chars"),
    ("npm_only_24_chars_aaaaaaa",          "npm token requires exactly 36 trailing chars"),
    ("dckr_pat_short",                     "Docker Hub PAT needs 20+ chars after prefix"),
    ("glpat-tooshort",                     "GitLab PAT requires exactly 20 trailing chars"),
    ("dop_v1_short",                       "DigitalOcean token needs 64 hex chars"),
    ("hvs.x",                              "Vault token needs 24+ chars after prefix"),
    ("SKabc123",                           "Twilio API key needs exactly 32 hex after SK"),
    ("ACshort",                            "Twilio Account SID needs exactly 32 hex after AC"),
    ("0123456789abcdef-us1",               "Mailchimp key needs 32 hex chars, not 16"),
    ("shpat_tooshort",                     "Shopify token needs 32 hex after prefix"),
    ("dapishort",                          "Databricks token needs 32 hex after dapi"),
    ("sk-tooshort",                        "OpenAI key needs T3BlbkFJ marker or proj- prefix + 40"),
    ("hf_short",                           "Hugging Face token needs 34+ chars after hf_"),
    ("AGE-SECRET-KEY-1short",              "age key needs exactly 58 chars after prefix"),
    ("lin_api_short",                      "Linear key needs 40 chars after prefix"),
    ("pscale_tkn_short",                   "PlanetScale token needs 40+ chars after prefix"),
    ("NRAK-short",                         "New Relic key needs 27 chars after NRAK-"),
    ("glsa_short",                         "Grafana key needs 32+ chars after glsa_"),
    ("12345:shorttoken",                   "Telegram bot token needs 8-10 digit ID and 35-char secret"),
    # ── New detectors (round 2) ──
    ("ATATT3short",                        "Atlassian token needs 50+ chars after ATATT3"),
    ("glrt-short",                         "GitLab runner token needs 20+ chars after glrt-"),
    ("glcbt-short",                        "GitLab CI token needs 20+ chars after glcbt-"),
    ("sbp_short",                          "Supabase key needs 40 hex chars after sbp_"),
    ("fo1_short",                          "Fly.io token needs 40+ chars after fo1_"),
    ("pul-short",                          "Pulumi token needs 40 hex chars after pul-"),
    ("dp.ct.short",                        "Doppler token needs 40+ chars after scope prefix"),
    ("nfp_short",                          "Netlify token needs 40+ chars after nfp_"),
    ("railway_short",                      "Railway token needs 36+ chars after railway_"),
    ("rnd_short",                          "Render key needs 32+ chars after rnd_"),
    ("pnu_short",                          "Prefect key needs 36+ chars after pnu_"),
    ("neon_short",                         "Neon key needs 36+ chars after neon_"),
    # ── New detectors (round 3) ──
    ("co_pat_short",                       "Cohere key needs 40+ chars after co_pat_"),
    ("r8_short",                           "Replicate token needs exactly 40 chars after r8_"),
    ("1/12345:short",                      "Asana PAT needs 15-18 digit ID and 32-hex secret"),
    ("sq0atp-short",                       "Square token needs 20+ chars after sq0atp-"),
    ("abc.atlasv1.short",                  "Terraform Cloud token needs 14 alnum + .atlasv1. + 60+ chars"),
    # ── New detectors (round 4) ──
    ("sk-svcacct-short",                   "OpenAI svcacct key needs 40+ chars after prefix"),
    ("PMAK-short",                         "Postman key needs 24 hex + - + 34 hex"),
    ("tskey-auth-short",                   "Tailscale key needs <keyID>-<secret 24+>"),
    ("sntrys_short",                       "Sentry token needs 40+ chars after prefix"),
    # ── New detectors (round 5): LLM provider API keys ──
    ("gsk_short",                          "Groq key needs 48+ chars after gsk_"),
    ("xai-short",                          "xAI key needs 64+ chars after xai-"),
    ("pplx-short",                         "Perplexity key needs 40+ chars after pplx-"),
    # ── New detectors (round 6): incoming-webhook URLs ──
    ("https://hooks.slack.com/services/T0/B0/short",
     "Slack webhook needs T../B../24+ secret"),
    ("https://discord.com/api/webhooks/123/short",
     "Discord webhook needs 17-20 digit id + 60+ token"),
])
def test_detectors_reject_undersized_tokens(token, reason):
    """Loose detector regexes are a constant source of false positives.
    Each near-miss above must NOT fire any built-in detector."""
    hits = secrets_mod.find_secret_values({"k": token})
    assert hits == [], f"unexpected hit for {token!r}; reason: {reason}; hits={hits}"


# ──────────────────────────────────────────────────────────────────────
# Placeholder suppression
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("token", [
    "AKIAXXXXXXXXXXXXXXXX",        # docs redaction, AWS-shape
    "ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",  # GitHub-shape redaction
    "AKIAYOUR_KEY_HERE_ABCD",      # YOUR_KEY marker
    "ghp_replace_me_with_real_pat_aaaaaaaaaaa",  # replace_me
    "<your-aws-key-id>",            # angle-bracketed placeholder
    "AKIA_DUMMY_KEY_HERE_AB",       # dummy_key
])
def test_placeholder_tokens_are_suppressed(token):
    """Documentation placeholders that happen to match a credential
    shape must NOT be emitted as findings — they're noise."""
    hits = secrets_mod.find_secret_values({"k": token})
    assert hits == [], (
        f"placeholder {token!r} should not have produced a hit; got {hits}"
    )


def test_vendor_example_tokens_suppressed():
    """Vendor-published example keys should not produce findings."""
    stripe_key = "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc"
    doc = {
        "env": {
            "AWS_KEY": "AKIAIOSFODNN7EXAMPLE",
            "STRIPE": stripe_key,
        }
    }
    hits = secrets_mod.find_secret_values(doc)
    # Neither vendor example should fire.
    for h in hits:
        assert "AKIAIOSFODNN7EXAMPLE" not in h
        assert stripe_key not in h


def test_vendor_example_tokens_suppressed_in_classify_raw():
    """The raw classifier used by --verify-secrets also skips vendor
    example tokens so the verifier doesn't waste probes on them."""
    doc = {"k": "AKIAIOSFODNN7EXAMPLE"}
    results = secrets_mod.classify_tokens_raw(doc)
    assert all(tok != "AKIAIOSFODNN7EXAMPLE" for _, tok in results)


# ──────────────────────────────────────────────────────────────────────
# Multi-line PEM-block detection
# ──────────────────────────────────────────────────────────────────────


def test_pem_block_detection_fires_on_begin_marker():
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA1234567890abcdefghij\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    hits = secrets_mod.find_secret_values({"key": pem})
    assert any(h.startswith("private_key:") for h in hits), (
        f"PEM block did not produce a private_key hit; got {hits}"
    )


def test_pem_block_label_includes_key_kind():
    """The label embeds the BEGIN-marker kind so report consumers can
    distinguish RSA / EC / OPENSSH / etc. private keys."""
    pem_rsa = "-----BEGIN RSA PRIVATE KEY-----\nbody\n-----END RSA PRIVATE KEY-----"
    pem_ec  = "-----BEGIN EC PRIVATE KEY-----\nbody\n-----END EC PRIVATE KEY-----"
    rsa_hits = secrets_mod.find_secret_values({"k": pem_rsa})
    ec_hits  = secrets_mod.find_secret_values({"k": pem_ec})
    assert any("rsa_private_key" in h for h in rsa_hits)
    assert any("ec_private_key" in h for h in ec_hits)


def test_pem_block_detects_encrypted_pkcs8() -> None:
    """PKCS#8 password-protected private keys still need to fire — the
    encrypted body plus an offline brute-force are a credential leak,
    even though the body isn't a usable secret on its own."""
    pem = (
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
        "MIIE6TAbBgkqhkiG9w0BBQMwDgQIabc123\n"
        "-----END ENCRYPTED PRIVATE KEY-----\n"
    )
    hits = secrets_mod.find_secret_values({"k": pem})
    assert any("encrypted_private_key" in h for h in hits), (
        f"encrypted PKCS#8 block must surface a private_key hit; got {hits}"
    )


def test_pem_block_dedup_within_one_doc():
    """Two PEM blocks of the same kind in one doc collapse to a single
    hit — the operator already knows the file is leaking; spamming
    them with N hits per file isn't useful."""
    pem = "-----BEGIN PRIVATE KEY-----\nbody\n-----END PRIVATE KEY-----"
    hits = secrets_mod.find_secret_values({"k1": pem, "k2": pem})
    pk_hits = [h for h in hits if h.startswith("private_key:")]
    assert len(pk_hits) == 1


def test_pem_body_does_not_emit_token_hits():
    """The base64 body of a PEM block must NOT also trigger token
    detectors — that would double-report the same secret with noisy
    false-positive labels."""
    pem = (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA" + "x" * 200 + "\n"
        "-----END PRIVATE KEY-----\n"
    )
    hits = secrets_mod.find_secret_values({"k": pem})
    # Exactly one private_key hit; nothing else.
    assert len(hits) == 1
    assert hits[0].startswith("private_key:")


# ──────────────────────────────────────────────────────────────────────
# Hit-label format invariants
# ──────────────────────────────────────────────────────────────────────


def test_hit_label_format_is_detector_then_redacted():
    """Stable contract: ``<detector>:<redacted-value>``. Reports and
    ignore-rule tooling parse these by splitting on the first ``:``."""
    hits = secrets_mod.find_secret_values({"k": "AKIAZ3MHALF2TESTHIJK"})
    assert hits
    name, _, redacted = hits[0].partition(":")
    assert name == "aws_access_key"
    # Redaction shape: first 4 + ellipsis + last 2.
    assert redacted.startswith("AKIA")
    assert redacted.endswith("JK")
    assert "…" in redacted


def test_user_pattern_uses_custom_label():
    """User-registered patterns share a single ``custom`` label so
    operators can write a blanket ``custom:*`` ignore for all
    org-specific patterns when needed."""
    secrets_mod.register_pattern(r"^acme_[a-f0-9]{32}$")
    hits = secrets_mod.find_secret_values({
        "k": "acme_deadbeefcafebabe0123456789abcdef"
    })
    assert hits
    assert hits[0].startswith("custom:")


def test_dedup_within_doc():
    """Repeated occurrences of the same token collapse to one hit."""
    hits = secrets_mod.find_secret_values({
        "a": "AKIAZ3MHALF2TESTHIJK",
        "b": "AKIAZ3MHALF2TESTHIJK",
    })
    assert len(hits) == 1


# ──────────────────────────────────────────────────────────────────────
# Keyed 40-hex pass (always-on; narrow shape gated on credential key)
# ──────────────────────────────────────────────────────────────────────


class TestKeyedHex40:
    HEX40 = "deadbeefcafef00dfeedfacebadc0ffee0ddf00d"

    def test_fires_on_cicd_goat_scenario_15_shape(self):
        """40-char lowercase hex in an ``API_TOKEN:`` env value —
        the exact shape scenario 15 of ``greylag-ci/cicd-goat`` ships.
        """
        hits = secrets_mod.find_secret_values({
            "env": {"LEGACY_API_TOKEN": self.HEX40},
        })
        assert any(h.startswith("hex40_keyed:") for h in hits)

    def test_does_not_fire_on_commit_sha_field(self):
        """Same 40-hex shape under ``deploy_commit:`` doesn't fire —
        the key context filter keeps commit SHAs out of the bucket.
        """
        hits = secrets_mod.find_secret_values({
            "env": {"DEPLOY_COMMIT": self.HEX40},
        })
        assert not any(h.startswith("hex40_keyed:") for h in hits)

    def test_requires_exactly_40_hex(self):
        """39, 41, mixed-case, or non-hex don't fire — the shape is
        tight on purpose so the always-on detector stays narrow."""
        cases = [
            "deadbeef" * 4 + "cafe1",                     # 33
            self.HEX40[:-1],                              # 39
            self.HEX40 + "0",                             # 41
            self.HEX40[:-1] + "G",                        # non-hex
            self.HEX40.upper(),                           # mixed case rejected
        ]
        for v in cases:
            hits = secrets_mod.find_secret_values(
                {"env": {"API_TOKEN": v}},
            )
            assert not any(h.startswith("hex40_keyed:") for h in hits), v

    def test_suppressed_when_placeholder_marker_in_value(self):
        hits = secrets_mod.find_secret_values({
            "env": {"API_TOKEN": "your-api-key-replaceme-here-deadbeefcafebabe"},
        })
        assert not any(h.startswith("hex40_keyed:") for h in hits)

    def test_suppressed_when_existing_detector_matches(self):
        """A prefixed vendor token of a different shape is caught by
        the deterministic catalog instead — no double-emit."""
        hits = secrets_mod.find_secret_values({
            "env": {"API_TOKEN": "ghp_" + _FILLER[:40]},
        })
        # The 40-hex pass shouldn't add a label here; the github_token
        # detector already does.
        hex_hits = [h for h in hits if h.startswith("hex40_keyed:")]
        assert not hex_hits

    def test_skipped_for_pre_collected_string_list(self):
        """The key-context pass needs a YAML document. Jenkins-style
        flat string lists don't carry keys, so the pass is skipped."""
        hits = secrets_mod.find_secret_values([f"API_TOKEN={self.HEX40}"])
        assert not any(h.startswith("hex40_keyed:") for h in hits)
