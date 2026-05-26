"""Slack bot / user token verifier."""
from __future__ import annotations

from . import SecretVerifier, VerifyOutcome, VerifyResult
from ._http import http_probe

_ENDPOINT = "https://slack.com/api/auth.test"


class SlackTokenVerifier(SecretVerifier):

    def probe(self, secret_value: str) -> VerifyResult:
        resp = http_probe(
            _ENDPOINT,
            method="POST",
            headers={
                "Authorization": f"Bearer {secret_value}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        if not resp.ok:
            if resp.auth_failure:
                return VerifyResult(
                    outcome=VerifyOutcome.UNVERIFIED,
                    reason=f"auth.test returned HTTP {resp.status}",
                )
            return VerifyResult(
                outcome=VerifyOutcome.UNKNOWN,
                reason=f"auth.test returned HTTP {resp.status}",
            )
        try:
            data = resp.json()
        except Exception:
            return VerifyResult(
                outcome=VerifyOutcome.UNKNOWN,
                reason="auth.test returned 200 but unparseable body",
            )
        if data.get("ok"):
            user = data.get("user", "unknown")
            team = data.get("team", "unknown")
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity=f"slack:{team}/{user}",
                reason=f"auth.test ok=true (team={team}, user={user})",
            )
        # Slack API returns 200 with ok=false for invalid tokens.
        error = data.get("error", "unknown")
        if error in ("invalid_auth", "not_authed", "token_revoked"):
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"auth.test ok=false error={error}",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"auth.test ok=false error={error}",
        )
