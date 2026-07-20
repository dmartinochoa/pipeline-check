"""Shared regex patterns and constants used by multiple check providers.

Kept in one place so AWS (live boto3) and Terraform (plan JSON) checks stay
in sync, any update to a credential detector or managed-image version
automatically applies to both.

The credential catalog below is the authoritative list of "shape-based"
detectors. Each entry is keyed by a stable name (used as the label in
secret-scanning hits) so operators can write targeted ignore rules like
``GHA-008:stripe_live_secret`` instead of suppressing the whole check.
"""
from __future__ import annotations

import re

# Environment variable names that suggest a secret is stored in plaintext.
SECRET_NAME_RE = re.compile(
    # ``AUTH`` requires a secret-ish qualifier (``auth_token`` etc.) so it
    # no longer matches within ``oauth`` / ``author`` — a bare ``AUTH``
    # substring flagged benign names (an OAuth redirect URL, an "author"
    # field). ``AUTHORIZATION`` stays a standalone alternative.
    r"(PASSWORD|PASSWD|PWD|SECRET|TOKEN|API[_\-]?KEY|ACCESS[_\-]?KEY|"
    r"SECRET[_\-]?KEY|PRIVATE[_\-]?KEY|CREDENTIAL|"
    r"AUTH[_\-]?(?:TOKEN|KEY|SECRET|PASS|PASSWORD)|AUTHORIZATION)",
    re.IGNORECASE,
)


# ──────────────────────────────────────────────────────────────────────
# Built-in credential-shape detectors
# ──────────────────────────────────────────────────────────────────────
#
# Each entry is (name, regex_body). The regex_body is anchored at use
# time, keep it WITHOUT ``^`` and ``$``. Add a new line when a new
# vendor publishes a stable token shape; only add patterns that are
# specific enough to not collide with arbitrary base64 (e.g. don't
# add a bare 40-char hex regex for "datadog API key", too generic).
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
    # ``github_pat_`` is the fine-grained PAT (GitHub's recommended PAT
    # format since 2022): a 22-char prefix, ``_``, then a 59-char body.
    "github_token":           r"(?:gh[pousr]_[A-Za-z0-9]{36,}"
                              r"|github_pat_[A-Za-z0-9_]{82,})",
    # Slack workspace, bot, app-level, refresh, and granular tokens.
    # ``xox[abprs]-`` covers workspace/bot/user/refresh-legacy/granular;
    # ``xoxe-`` is the rotation refresh token and ``xapp-`` the
    # app-level token (both real credential prefixes the older charset
    # missed).
    "slack_token":            r"(?:xox[abeprs]|xapp)-[A-Za-z0-9-]{10,}",
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
    # SendGrid API key, ``SG.<22>.<43>``.
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
    # Mailchimp API key, 32 hex + datacenter suffix (-us1 through -us99).
    "mailchimp_api_key":      r"[0-9a-f]{32}-us\d{1,2}",
    # Shopify access tokens, four scoped prefixes, 32 hex chars.
    "shopify_token":          r"shp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}",
    # Databricks personal access token, dapi prefix + 32 hex.
    "databricks_token":       r"dapi[0-9a-f]{32}",
    # OpenAI API keys, legacy (sk-…T3BlbkFJ…), project (sk-proj-…) and
    # service-account (sk-svcacct-…).
    "openai_api_key":         r"sk-(?:(?:proj|svcacct)-[A-Za-z0-9_\-]{40,}|[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,})",
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
    # Telegram Bot API token, numeric bot ID + alphanumeric secret.
    "telegram_bot_token":     r"\d{8,10}:[A-Za-z0-9_\-]{35}",
    # Atlassian Cloud API tokens (Forge / Connect apps; ATATT3 prefix).
    "atlassian_api_token":    r"ATATT3[A-Za-z0-9_\-]{50,}",
    # GitLab Runner registration tokens (glrt- prefix).
    "gitlab_runner_token":    r"glrt-[0-9A-Za-z_\-]{20,}",
    # GitLab CI/CD job tokens (new format, glcbt- prefix).
    "gitlab_ci_token":        r"glcbt-[0-9A-Za-z]{20,}",
    # Supabase project API keys (sbp_ prefix).
    "supabase_key":           r"sbp_[a-f0-9]{40}",
    # Fly.io API tokens (fo1_ prefix).
    "fly_api_token":          r"fo1_[A-Za-z0-9_\-]{40,}",
    # Pulumi Cloud access tokens (pul- prefix, 40 hex).
    "pulumi_access_token":    r"pul-[a-f0-9]{40}",
    # Doppler secrets manager tokens, scoped prefixes (ct/sa/st/scrt/audit).
    "doppler_token":          r"dp\.(?:ct|sa|st|scrt|audit)\.[A-Za-z0-9]{40,}",
    # Netlify personal access tokens (nfp_ prefix).
    "netlify_token":          r"nfp_[A-Za-z0-9]{40,}",
    # Railway.app API tokens.
    "railway_token":          r"railway_[A-Za-z0-9_\-]{36,}",
    # Render API keys (rnd_ prefix).
    "render_api_key":         r"rnd_[A-Za-z0-9]{32,}",
    # Prefect Cloud API keys (pnu_ prefix).
    "prefect_api_key":        r"pnu_[A-Za-z0-9]{36,}",
    # Neon serverless Postgres API keys (neon_ prefix).
    "neon_api_key":           r"neon_[A-Za-z0-9_\-]{36,}",
    # Cohere production / API keys (co_pat_ prefix; trial keys use a
    # bare token shape that's too generic to detect by shape alone).
    "cohere_api_key":         r"co_pat_[A-Za-z0-9]{40,}",
    # Replicate API tokens (r8_ prefix + 40 alnum). Distinct enough
    # that a bare ``r8_`` substring outside this regex won't overlap.
    "replicate_token":        r"r8_[A-Za-z0-9]{40}",
    # Asana personal access tokens. Format is ``1/<account-id>:<32 hex>``
    # where account-id is the 16-digit numeric Asana user ID. The
    # leading digit-and-slash plus the colon make this much narrower
    # than a bare 32-hex shape.
    "asana_pat":              r"1/\d{15,18}:[a-f0-9]{32}",
    # Square access tokens. Two scoped prefixes (atp = access token,
    # csp = client secret) followed by URL-safe base64.
    "square_access_token":    r"sq0(?:atp|csp)-[A-Za-z0-9_\-]{20,}",
    # Terraform Cloud / Terraform Enterprise tokens. Format is
    # ``<14 alnum>.atlasv1.<base64-padded body>``. The middle
    # ``.atlasv1.`` literal makes the regex very specific.
    "terraform_cloud_token":  r"[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{60,}",
    # Postman API key: PMAK- + 24 hex + - + 34 hex (used by Newman in CI).
    "postman_api_key":        r"PMAK-[0-9a-f]{24}-[0-9a-f]{34}",
    # Tailscale auth / API / OAuth-client / webhook key:
    # tskey-<kind>-<keyID>-<secret>.
    "tailscale_key":          r"tskey-(?:auth|api|client|webhook)-[0-9A-Za-z]+-[0-9A-Za-z]{24,}",
    # Sentry auth token, org (sntrys_) and user (sntryu_) forms.
    "sentry_auth_token":      r"sntry[su]_[A-Za-z0-9+/=_\-]{40,}",
    # ── LLM provider API keys (round 5) ──
    # Groq API keys (``gsk_`` prefix + 52-char body).
    "groq_api_key":           r"gsk_[A-Za-z0-9]{48,}",
    # xAI (Grok) API keys (``xai-`` prefix + long alphanumeric body).
    "xai_api_key":            r"xai-[A-Za-z0-9]{64,}",
    # Perplexity API keys (``pplx-`` prefix + 48-char body).
    "perplexity_api_key":     r"pplx-[A-Za-z0-9]{40,}",
    # ── Incoming-webhook URLs (full credential: anyone with the URL can post) ──
    # Slack incoming webhook: hooks.slack.com/services/T<id>/B<id>/<24 secret>.
    "slack_webhook":          r"https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,}",
    # Discord webhook: discord(app).com/api/webhooks/<17-20 digit id>/<token>.
    "discord_webhook":        r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_\-]{60,}",
    # ── More SaaS / infra tokens (distinctive prefixes) ──
    # Figma personal access token (``figd_`` prefix).
    "figma_token":            r"figd_[A-Za-z0-9_\-]{40,}",
    # Notion internal-integration token (``ntn_`` prefix; the older
    # ``secret_`` shape is too generic to match safely).
    "notion_token":           r"ntn_[A-Za-z0-9]{40,}",
}


#: Public registry: ``[(name, compiled_anchored_regex), ...]``. Order
#: matches insertion order in ``_BUILTIN_PATTERNS``; iterators in the
#: scanner use this directly so the first matching detector wins.
SECRET_DETECTORS: list[tuple[str, re.Pattern[str]]] = [
    (name, re.compile(rf"^{body}$"))
    for name, body in _BUILTIN_PATTERNS.items()
]


#: Compatibility alias, a single anchored regex that fires on any
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
# Deliberately NOT included: ``EXAMPLE`` / ``FAKE`` / ``TEST`` as
# substring patterns.
#  - Real tokens at companies often have ``test`` / ``staging`` /
#    ``fake`` substrings in their key names.
#  - Specific well-known vendor example tokens (``AKIAIOSFODNN7EXAMPLE``,
#    Stripe test keys, etc.) are handled separately by the exact-match
#    ``VENDOR_EXAMPLE_TOKENS`` set below.
#
PLACEHOLDER_MARKER_RE = re.compile(
    r"(?:placeholder"
    r"|replace[_\-]?me"
    r"|change[_\-]?me"
    r"|your[_\-]?(?:key|token|secret|api)"
    r"|my[_\-]?(?:key|token|secret|api)"
    r"|insert[_\-]?(?:key|token|secret)"
    r"|dummy[_\-]?(?:key|token|secret)?"
    r"|XXXXX"      # 5+ Xs in a row, typical doc redaction
    r"|<[^>]*>"    # angle-bracketed placeholders like <your-key>
    r")",
    re.IGNORECASE,
)


# Vendor-published example / test credentials. These are documentation
# artifacts published by the vendor themselves and are never valid for
# real API calls. Unlike PLACEHOLDER_MARKER_RE (which looks at value
# substrings), these match the full token to avoid masking real
# credentials that happen to contain "example" or "test" substrings.
VENDOR_EXAMPLE_TOKENS: frozenset[str] = frozenset({
    # AWS canonical docs key pair (appears in every AWS tutorial).
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    # AWS STS example from docs.
    "ASIAIOSFODNN7EXAMPLE",
    # Stripe docs test keys (always start with sk_test_ / pk_test_
    # followed by a fixed example suffix). Concatenated to avoid
    # tripping GitHub push protection on the well-known test key.
    "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc",
    "pk_test_" + "TYooMQauvdEDq54NiTphI7jx",
    # Twilio docs examples.
    "ACXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    "SKXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    # SendGrid example from docs.
    "SG.XXXXXXXXXXXXXXXXXXXXXXXX.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
})


# ──────────────────────────────────────────────────────────────────────
# Multi-line PEM private-key blocks
# ──────────────────────────────────────────────────────────────────────
#
# The token-based scanner can't catch these, a PEM block spans many
# lines and the body is base64 data that splits on whitespace. A
# separate substring scan over the joined string content fires when
# a BEGIN marker is present.
#
PEM_BLOCK_RE = re.compile(
    r"-----BEGIN (?P<kind>"
    # "<algo> PRIVATE KEY" — typical OpenSSL output (RSA / DSA / EC),
    # OpenSSH-format keys, PGP private blocks. ``ENCRYPTED PRIVATE
    # KEY`` is the PKCS#8 password-protected form, still a credential
    # leak even though the body is encrypted (offline brute-force is
    # cheap once the file has left the perimeter).
    r"(?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED) PRIVATE KEY"
    # "PRIVATE KEY" — PKCS#8 unencrypted form, no algorithm prefix.
    r"|PRIVATE KEY"
    r")-----",
    re.IGNORECASE,
)


# AWS CodeBuild standard managed image, aws/codebuild/standard:X.0.
MANAGED_IMAGE_RE = re.compile(r"aws/codebuild/standard:(\d+)\.\d+")

# Bump when AWS releases a new standard image major version.
LATEST_STANDARD_VERSION = 7


_ARN_ACCOUNT_RE = re.compile(r"^arn:aws[a-z-]*:[^:]+:[^:]*:(\d{12}):")


def arn_account_id(arn: str) -> str:
    """Return the 12-digit AWS account id embedded in *arn*, or ``''``.

    Works across partitions (``aws``, ``aws-us-gov``, ``aws-cn``). An
    ARN whose account field is empty (e.g. an S3 bucket ARN) or a
    non-ARN string yields ``''``.
    """
    m = _ARN_ACCOUNT_RE.match(arn or "")
    return m.group(1) if m else ""


def eventbridge_target_is_wildcard(arn: str) -> bool:
    """True when an EventBridge target ARN carries a *fan-out* wildcard.

    A ``*`` in the resource segment (``function:*``, ``:my-topic-*``)
    broadens which resources receive the event and is the offending
    shape EB-002 flags.

    A CloudWatch Logs target is the documented exception: its ARN ends
    in ``:*`` (the log-stream selector,
    ``arn:aws:logs:<region>:<acct>:log-group:/name:*``). That trailing
    wildcard is mandatory for a Logs target, not a fan-out, so it must
    not be flagged. Shared by the aws / cloudformation / terraform
    EB-002 rules so the carve-out stays in one place.
    """
    if not arn or "*" not in arn:
        return False
    if ":log-group:" in arn and arn.endswith(":*"):
        # Drop the mandatory log-stream selector, then see whether any
        # other (genuine fan-out) wildcard remains, e.g. a wildcard in
        # the log-group name itself.
        arn = arn[:-2]
    return "*" in arn
