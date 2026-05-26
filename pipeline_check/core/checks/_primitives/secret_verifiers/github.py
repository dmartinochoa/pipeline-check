"""GitHub token verifier (PAT, fine-grained, OAuth, app-installation)."""
from __future__ import annotations

from . import SecretVerifier, VerifyOutcome, VerifyResult
from ._http import bearer_probe

_ENDPOINT = "https://api.github.com/user"


class GitHubTokenVerifier(SecretVerifier):

    def probe(self, secret_value: str) -> VerifyResult:
        resp = bearer_probe(_ENDPOINT, secret_value)
        if resp.ok:
            try:
                data = resp.json()
                login = data.get("login", "unknown")
            except Exception:
                login = "unknown"
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity=f"github-user:{login}",
                reason=f"GET /user returned 200 (login={login})",
            )
        if resp.auth_failure:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"GET /user returned {resp.status}",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"GET /user returned {resp.status}",
        )
