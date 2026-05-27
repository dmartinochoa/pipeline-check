"""Google Cloud API key verifier."""
from __future__ import annotations

from . import SecretVerifier, VerifyOutcome, VerifyResult
from ._http import http_probe

_ENDPOINT = "https://www.googleapis.com/oauth2/v3/tokeninfo"


class GoogleAPIKeyVerifier(SecretVerifier):

    def probe(self, secret_value: str) -> VerifyResult:
        resp = http_probe(
            f"https://generativelanguage.googleapis.com/v1beta/models"
            f"?key={secret_value}",
        )
        if resp.ok:
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity="google-api-key:active",
                reason="GET /models?key=... returned 200 (key is active)",
            )
        if resp.status == 400:
            try:
                data = resp.json()
                error = data.get("error", {})
                status = error.get("status", "")
                if status == "INVALID_ARGUMENT":
                    return VerifyResult(
                        outcome=VerifyOutcome.VERIFIED,
                        identity="google-api-key:active",
                        reason=(
                            "API returned INVALID_ARGUMENT (key is valid "
                            "but API not enabled for this project)"
                        ),
                    )
            except Exception:
                pass
        if resp.status in (401, 403):
            try:
                data = resp.json()
                error = data.get("error", {})
                status = error.get("status", "")
                if "API_KEY_INVALID" in str(error):
                    return VerifyResult(
                        outcome=VerifyOutcome.UNVERIFIED,
                        reason="Google API returned API_KEY_INVALID",
                    )
            except Exception:
                pass
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"Google API returned {resp.status}",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"Google API returned {resp.status}",
        )
