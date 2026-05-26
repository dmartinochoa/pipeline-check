"""NPM access-token verifier."""
from __future__ import annotations

from . import SecretVerifier, VerifyOutcome, VerifyResult
from ._http import bearer_probe

_ENDPOINT = "https://registry.npmjs.org/-/whoami"


class NpmTokenVerifier(SecretVerifier):

    def probe(self, secret_value: str) -> VerifyResult:
        resp = bearer_probe(_ENDPOINT, secret_value)
        if resp.ok:
            try:
                data = resp.json()
                username = data.get("username", "unknown")
            except Exception:
                username = "unknown"
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity=f"npm-user:{username}",
                reason=f"GET /-/whoami returned 200 (username={username})",
            )
        if resp.auth_failure:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"GET /-/whoami returned {resp.status}",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"GET /-/whoami returned {resp.status}",
        )
