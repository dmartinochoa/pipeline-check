"""Telegram Bot API token verifier.

The token embeds the bot ID and a secret separated by a colon
(``123456789:ABCdefGHI...``). The Telegram Bot API uses the full
token in the URL path rather than in an Authorization header.
"""
from __future__ import annotations

import re

from . import SecretVerifier, VerifyOutcome, VerifyResult
from ._http import http_probe

_ENDPOINT_TEMPLATE = "https://api.telegram.org/bot{token}/getMe"
_TOKEN_RE = re.compile(r"^\d{8,10}:[A-Za-z0-9_-]{35}$")


class TelegramBotTokenVerifier(SecretVerifier):

    def probe(self, secret_value: str) -> VerifyResult:
        if not _TOKEN_RE.match(secret_value):
            return VerifyResult(
                outcome=VerifyOutcome.UNKNOWN,
                reason="token does not match expected bot-token format",
            )
        url = _ENDPOINT_TEMPLATE.format(token=secret_value)
        resp = http_probe(url)
        if resp.ok:
            try:
                data = resp.json()
                result_data = data.get("result", {})
                username = result_data.get("username", "unknown")
            except Exception:
                username = "unknown"
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity=f"telegram-bot:@{username}",
                reason=f"GET /getMe returned 200 (username={username})",
            )
        if resp.auth_failure:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"GET /getMe returned {resp.status}",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"GET /getMe returned {resp.status}",
        )
