"""Shared regex patterns and constants used by multiple check providers.

Kept in one place so AWS (live boto3) and Terraform (plan JSON) checks stay
in sync — any update to a credential detector or managed-image version
automatically applies to both.

The credential catalogue below is the authoritative list of "shape-based"
detectors. Each entry is keyed by a stable name (used as the label in
secret-scanning hits) so operators can write targeted ignore rules like
``GHA-008:stripe_live_secret`` instead of suppressing the whole check.
"""
from __future__ import annotations

import re

# Environment variable names that suggest a secret is stored in plaintext.
SECRET_NAME_RE = re.compile(
    r"(PASSWORD|PASSWD|PWD|SECRET|TOKEN|API[_\-]?KEY|ACCESS[_\-]?KEY|"
    r"SECRET[_\-]?KEY|PRIVATE[_\-]?KEY|CREDENTIAL|AUTH|AUTHORIZATION)",
    re.IGNORECASE,
)


# ──────────────────────────────────────────────────────────────────────
# Built-in credential-shape detectors
# ──────────────────────────────────────────────────────────────────────
#
# Each entry is (name, regex_body). The regex_body is anchored at use
# time — keep it WITHOUT ``^`` and ``$``. Add a new line when a new
# vendor publishes a stable token shape; only add patterns that are
# specific enough to not collide with arbitrary base64 (e.g. don't
# add a bare 40-char hex regex for "datadog API key" — too generic).
#
# Picking thresholds:
#   - Lengths come from the vendor's published spec where one exists.
#   - Where a token is "prefix + base62 of fixed length" we encode the
#     fixed length; where the prefix is the only stable thing we use
#     a permissive lower bound + ``$`` anchor at use time.
#
_BUILTIN_PATTERNS: dict[str, str] = {
    # AWS access key (standard or temporary STS credential).
    "aws_access_key":         r"A(?:KIA|SIA)[0-9A-Z]{16}",
    # GitHub PATs / OAuth / installation / refresh tokens. ``ghp_`` is
    # the user PAT; ``gho_/ghu_/ghs_/ghr_`` are the OAuth-flow shapes.
    "github_token":           r"gh[pousr]_[A-Za-z0-9]{36,}",
    # Slack workspace, bot, app-level, refresh, and granular tokens.
    "slack_token":            r"xox[abprs]-[A-Za-z0-9-]{10,}",
    # Generic JWT (header.payload.signature, all base64url).
    "jwt":                    r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
    # Stripe secret / restricted / publishable keys; live and test.
    "stripe_secret":          r"(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}",
    "stripe_publishable":     r"pk_(?:live|test)_[0-9a-zA-Z]{24,}",
    # Google Cloud API keys (universal AIza prefix, 39 chars total).
    "google_api_key":         r"AIza[0-9A-Za-z\-_]{35}",
    # npm v1+ access tokens.
    "npm_token":              r"npm_[A-Za-z0-9]{36}",
    # PyPI tokens (carry an internal JWT).
    "pypi_token":             r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{40,}",
    # Docker Hub personal-access tokens.
    "docker_hub_pat":         r"dckr_pat_[A-Za-z0-9_\-]{20,}",
    # GitLab personal / project / group access tokens.
    "gitlab_pat":             r"glpat-[0-9A-Za-z_\-]{20}",
    # GitLab deploy tokens (project-scoped).
    "gitlab_deploy_token":    r"gldt-[0-9A-Za-z_\-]{20,}",
    # SendGrid API key — ``SG.<22>.<43>``.
    "sendgrid":               r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}",
    # Anthropic API keys (current ``sk-ant-api03`` series).
    "anthropic_api_key":      r"sk-ant-api03-[A-Za-z0-9_\-]{90,}",
    # DigitalOcean v1 personal access tokens.
    "digitalocean_token":     r"dop_v1_[a-f0-9]{64}",
    # HashiCorp Vault service / batch tokens.
    "hashicorp_vault":        r"hvs\.[A-Za-z0-9_\-]{24,}",
    # Twilio API key SID (SK prefix + 32 hex = 34 chars total).
    "twilio_api_key":         r"SK[0-9a-fA-F]{32}",
    # Twilio Account SID (AC prefix + 32 hex = 34 chars total).
    "twilio_account_sid":     r"AC[0-9a-fA-F]{32}",
    # Mailchimp API key — 32 hex + datacenter suffix (-us1 through -us99).
    "mailchimp_api_key":      r"[0-9a-f]{32}-us\d{1,2}",
    # Shopify access tokens — four scoped prefixes, 32 hex chars.
    "shopify_token":          r"shp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}",
    # Databricks personal access token — dapi prefix + 32 hex.
    "databricks_token":       r"dapi[0-9a-f]{32}",
    # OpenAI API keys — legacy (sk-…T3BlbkFJ…) and new (sk-proj-…).
    "openai_api_key":         r"sk-(?:proj-[A-Za-z0-9_\-]{40,}|[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,})",
    # Hugging Face user access tokens.
    "huggingface_token":      r"hf_[A-Za-z0-9]{34,}",
    # age encryption tool secret key.
    "age_secret_key":         r"AGE-SECRET-KEY-1[0-9A-Za-z]{58}",
    # Linear issue tracker API key.
    "linear_api_key":         r"lin_api_[A-Za-z0-9]{40}",
    # PlanetScale database token.
    "planetscale_token":      r"pscale_tkn_[A-Za-z0-9_\-]{40,}",
    # New Relic user API key (NRAK prefix, 32 total).
    "new_relic_api_key":      r"NRAK-[A-Za-z0-9]{27}",
    # Grafana Cloud service account token (glsa_ prefix).
    "grafana_api_key":        r"glsa_[A-Za-z0-9_]{32,}",
    # Telegram Bot API token — numeric bot ID + alphanumeric secret.
    "telegram_bot_token":     r"\d{8,10}:[A-Za-z0-9_\-]{35}",
}


#: Public registry: ``[(name, compiled_anchored_regex), ...]``. Order
#: matches insertion order in ``_BUILTIN_PATTERNS``; iterators in the
#: scanner use this directly so the first matching detector wins.
SECRET_DETECTORS: list[tuple[str, re.Pattern[str]]] = [
    (name, re.compile(rf"^{body}$"))
    for name, body in _BUILTIN_PATTERNS.items()
]


#: Compatibility alias — a single anchored regex that fires on any
#: built-in detector. Older callers (e.g. the GHA-008 autofix and the
#: SARIF best-effort line locator) match against this directly.
SECRET_VALUE_RE = re.compile(
    r"^(?:" + "|".join(_BUILTIN_PATTERNS.values()) + r")$"
)


# ──────────────────────────────────────────────────────────────────────
# Placeholder suppression
# ──────────────────────────────────────────────────────────────────────
#
# Markers that strongly suggest the value is a documentation placeholder
# rather than a real credential. Suppressing these keeps the
# secret-scan signal focused on values an operator might actually have
# pasted by mistake.
#
# Deliberately NOT included: ``EXAMPLE`` / ``FAKE`` / ``TEST``.
#  - ``AKIAIOSFODNN7EXAMPLE`` is the canonical AWS-docs example, and
#    if that string makes it into a real workflow it usually means
#    someone copy-pasted from docs and forgot to substitute — exactly
#    the case the scanner exists to catch.
#  - Real tokens at companies often have ``test`` / ``staging`` /
#    ``fake`` substrings in their key names.
#
PLACEHOLDER_MARKER_RE = re.compile(
    r"(?:placeholder"
    r"|replace[_\-]?me"
    r"|change[_\-]?me"
    r"|your[_\-]?(?:key|token|secret|api)"
    r"|my[_\-]?(?:key|token|secret|api)"
    r"|insert[_\-]?(?:key|token|secret)"
    r"|dummy[_\-]?(?:key|token|secret)?"
    r"|XXXXX"      # 5+ Xs in a row — typical doc redaction
    r"|<[^>]*>"    # angle-bracketed placeholders like <your-key>
    r")",
    re.IGNORECASE,
)


# ──────────────────────────────────────────────────────────────────────
# Multi-line PEM private-key blocks
# ──────────────────────────────────────────────────────────────────────
#
# The token-based scanner can't catch these — a PEM block spans many
# lines and the body is base64 data that splits on whitespace. A
# separate substring scan over the joined string content fires when
# a BEGIN marker is present.
#
PEM_BLOCK_RE = re.compile(
    r"-----BEGIN (?P<kind>(?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY)-----",
    re.IGNORECASE,
)


# AWS CodeBuild standard managed image — aws/codebuild/standard:X.0.
MANAGED_IMAGE_RE = re.compile(r"aws/codebuild/standard:(\d+)\.\d+")

# Bump when AWS releases a new standard image major version.
LATEST_STANDARD_VERSION = 7
