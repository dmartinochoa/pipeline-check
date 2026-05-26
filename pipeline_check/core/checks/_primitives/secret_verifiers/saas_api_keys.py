"""Verifiers for SaaS API keys that follow the bearer-token pattern.

Covers Anthropic, OpenAI, Hugging Face, SendGrid, and Stripe. Each
endpoint is hardcoded to the vendor's public API; no user-supplied URL
is ever constructed.
"""
from __future__ import annotations

import base64

from . import SecretVerifier, VerifyOutcome, VerifyResult
from ._http import bearer_probe, http_probe


# ── Anthropic ───────────────────────────────────────────────────────


class AnthropicKeyVerifier(SecretVerifier):

    _ENDPOINT = "https://api.anthropic.com/v1/models"

    def probe(self, secret_value: str) -> VerifyResult:
        resp = http_probe(
            self._ENDPOINT,
            headers={
                "x-api-key": secret_value,
                "anthropic-version": "2023-06-01",
            },
        )
        if resp.ok:
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity="anthropic-api-key",
                reason="GET /v1/models returned 200",
            )
        if resp.auth_failure:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"GET /v1/models returned {resp.status}",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"GET /v1/models returned {resp.status}",
        )


# ── OpenAI ──────────────────────────────────────────────────────────


class OpenAIKeyVerifier(SecretVerifier):

    _ENDPOINT = "https://api.openai.com/v1/models"

    def probe(self, secret_value: str) -> VerifyResult:
        resp = bearer_probe(self._ENDPOINT, secret_value)
        if resp.ok:
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity="openai-api-key",
                reason="GET /v1/models returned 200",
            )
        if resp.auth_failure:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"GET /v1/models returned {resp.status}",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"GET /v1/models returned {resp.status}",
        )


# ── Hugging Face ────────────────────────────────────────────────────


class HuggingFaceTokenVerifier(SecretVerifier):

    _ENDPOINT = "https://huggingface.co/api/whoami-v2"

    def probe(self, secret_value: str) -> VerifyResult:
        resp = bearer_probe(self._ENDPOINT, secret_value)
        if resp.ok:
            try:
                data = resp.json()
                name = data.get("name", "unknown")
            except Exception:
                name = "unknown"
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity=f"hf-user:{name}",
                reason=f"GET /api/whoami-v2 returned 200 (name={name})",
            )
        if resp.auth_failure:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"GET /api/whoami-v2 returned {resp.status}",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"GET /api/whoami-v2 returned {resp.status}",
        )


# ── SendGrid ────────────────────────────────────────────────────────


class SendGridKeyVerifier(SecretVerifier):

    _ENDPOINT = "https://api.sendgrid.com/v3/user/profile"

    def probe(self, secret_value: str) -> VerifyResult:
        resp = bearer_probe(self._ENDPOINT, secret_value)
        if resp.ok:
            try:
                data = resp.json()
                username = data.get("username", "unknown")
            except Exception:
                username = "unknown"
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity=f"sendgrid-user:{username}",
                reason=f"GET /v3/user/profile returned 200 (username={username})",
            )
        if resp.auth_failure:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"GET /v3/user/profile returned {resp.status}",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"GET /v3/user/profile returned {resp.status}",
        )


# ── Stripe ──────────────────────────────────────────────────────────


class StripeKeyVerifier(SecretVerifier):

    _ENDPOINT = "https://api.stripe.com/v1/balance"

    def probe(self, secret_value: str) -> VerifyResult:
        # Stripe uses HTTP Basic Auth with the API key as the username.
        cred = base64.b64encode(
            f"{secret_value}:".encode("utf-8"),
        ).decode("ascii")
        resp = http_probe(
            self._ENDPOINT,
            headers={"Authorization": f"Basic {cred}"},
        )
        if resp.ok:
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity="stripe-account",
                reason="GET /v1/balance returned 200",
            )
        if resp.auth_failure:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"GET /v1/balance returned {resp.status}",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"GET /v1/balance returned {resp.status}",
        )
