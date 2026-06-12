"""Verifiers for additional SaaS API tokens.

Covers Replicate, Cohere, Mailchimp, Square, Figma, and Notion.
Companion to ``saas_api_keys.py`` (which holds Anthropic, OpenAI, HF,
SendGrid, Stripe).
"""
from __future__ import annotations

import base64
import re

from . import SecretVerifier, VerifyOutcome, VerifyResult
from ._http import bearer_probe, http_probe

# -- Replicate -----------------------------------------------------------


class ReplicateTokenVerifier(SecretVerifier):

    _ENDPOINT = "https://api.replicate.com/v1/account"

    def probe(self, secret_value: str) -> VerifyResult:
        resp = http_probe(
            self._ENDPOINT,
            headers={"Authorization": f"Token {secret_value}"},
        )
        if resp.ok:
            try:
                data = resp.json()
                username = data.get("username", "unknown")
            except Exception:
                username = "unknown"
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity=f"replicate-user:{username}",
                reason=f"GET /v1/account returned 200 (username={username})",
            )
        if resp.auth_failure:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"GET /v1/account returned {resp.status}",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"GET /v1/account returned {resp.status}",
        )


# -- Cohere --------------------------------------------------------------


class CohereAPIKeyVerifier(SecretVerifier):

    _ENDPOINT = "https://api.cohere.com/v2/models"

    def probe(self, secret_value: str) -> VerifyResult:
        resp = bearer_probe(self._ENDPOINT, secret_value)
        if resp.ok:
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity="cohere-api-key",
                reason="GET /v2/models returned 200",
            )
        if resp.auth_failure:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"GET /v2/models returned {resp.status}",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"GET /v2/models returned {resp.status}",
        )


# -- Mailchimp -----------------------------------------------------------


class MailchimpAPIKeyVerifier(SecretVerifier):
    """Verify Mailchimp API keys.

    The datacenter is encoded in the key suffix (e.g. ``-us6``).
    """

    def probe(self, secret_value: str) -> VerifyResult:
        parts = secret_value.rsplit("-", 1)
        if len(parts) != 2:
            return VerifyResult(
                outcome=VerifyOutcome.UNKNOWN,
                reason="cannot extract datacenter from key suffix",
            )
        dc = parts[1]
        if not re.fullmatch(r"[a-z]{2}\d{1,2}", dc):
            return VerifyResult(
                outcome=VerifyOutcome.UNKNOWN,
                reason=f"datacenter suffix {dc!r} does not match expected pattern",
            )
        url = f"https://{dc}.api.mailchimp.com/3.0/"
        cred = base64.b64encode(
            f"anystring:{secret_value}".encode(),
        ).decode("ascii")
        resp = http_probe(
            url,
            headers={"Authorization": f"Basic {cred}"},
        )
        if resp.ok:
            try:
                data = resp.json()
                name = data.get("account_name", "unknown")
            except Exception:
                name = "unknown"
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity=f"mailchimp-account:{name}",
                reason=f"GET /3.0/ returned 200 (account={name})",
            )
        if resp.auth_failure:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"GET /3.0/ returned {resp.status}",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"GET /3.0/ returned {resp.status}",
        )


# -- Square --------------------------------------------------------------


class SquareAccessTokenVerifier(SecretVerifier):

    _ENDPOINT = "https://connect.squareup.com/v2/locations"

    def probe(self, secret_value: str) -> VerifyResult:
        resp = bearer_probe(self._ENDPOINT, secret_value)
        if resp.ok:
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity="square-account",
                reason="GET /v2/locations returned 200",
            )
        if resp.auth_failure:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"GET /v2/locations returned {resp.status}",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"GET /v2/locations returned {resp.status}",
        )


# -- Figma ---------------------------------------------------------------


class FigmaTokenVerifier(SecretVerifier):
    """Verify Figma personal access tokens.

    Figma authenticates with the ``X-Figma-Token`` header (not Bearer),
    and ``GET /v1/me`` returns the owning account.
    """

    _ENDPOINT = "https://api.figma.com/v1/me"

    def probe(self, secret_value: str) -> VerifyResult:
        resp = http_probe(
            self._ENDPOINT,
            headers={"X-Figma-Token": secret_value},
        )
        if resp.ok:
            try:
                data = resp.json()
                who = data.get("handle") or data.get("email") or "unknown"
            except Exception:
                who = "unknown"
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity=f"figma-user:{who}",
                reason=f"GET /v1/me returned 200 (handle={who})",
            )
        if resp.auth_failure:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"GET /v1/me returned {resp.status}",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"GET /v1/me returned {resp.status}",
        )


# -- Notion --------------------------------------------------------------


class NotionTokenVerifier(SecretVerifier):
    """Verify Notion internal-integration tokens.

    Notion requires a ``Notion-Version`` header alongside the Bearer
    token; ``GET /v1/users/me`` returns the integration's bot user.
    """

    _ENDPOINT = "https://api.notion.com/v1/users/me"
    _NOTION_VERSION = "2022-06-28"

    def probe(self, secret_value: str) -> VerifyResult:
        resp = http_probe(
            self._ENDPOINT,
            headers={
                "Authorization": f"Bearer {secret_value}",
                "Notion-Version": self._NOTION_VERSION,
            },
        )
        if resp.ok:
            try:
                data = resp.json()
                bot = data.get("bot") if isinstance(data.get("bot"), dict) else {}
                who = (
                    data.get("name")
                    or bot.get("workspace_name")
                    or "unknown"
                )
            except Exception:
                who = "unknown"
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity=f"notion-bot:{who}",
                reason=f"GET /v1/users/me returned 200 (name={who})",
            )
        if resp.auth_failure:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"GET /v1/users/me returned {resp.status}",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"GET /v1/users/me returned {resp.status}",
        )
