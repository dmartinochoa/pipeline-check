"""Docker Hub personal-access-token verifier."""
from __future__ import annotations

from . import SecretVerifier, VerifyOutcome, VerifyResult
from ._http import bearer_probe

_ENDPOINT = "https://hub.docker.com/v2/user"


class DockerHubTokenVerifier(SecretVerifier):

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
                identity=f"docker-hub:{username}",
                reason=f"GET /v2/user returned 200 (username={username})",
            )
        if resp.auth_failure:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"GET /v2/user returned {resp.status}",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"GET /v2/user returned {resp.status}",
        )
