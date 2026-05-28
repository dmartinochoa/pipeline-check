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
        # Any non-2xx response: read the structured error if present. The
        # Generative Language API returns 400 INVALID_ARGUMENT with the
        # message "API key not valid" for an *invalid* key, so a 400 is
        # never proof the key is live. Only a clear invalid-key signal
        # demotes to UNVERIFIED; anything else stays UNKNOWN. VERIFIED is
        # reserved for the 200 above so a dead key is never promoted to
        # CRITICAL.
        try:
            error = resp.json().get("error", {})
        except Exception:
            error = {}
        blob = str(error)
        if "API_KEY_INVALID" in blob or "API key not valid" in blob:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason="Google API reported the key is invalid",
            )
        if resp.auth_failure:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"Google API returned {resp.status}",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"Google API returned {resp.status}",
        )
