"""GitLab personal / project / group access-token verifier."""
from __future__ import annotations

from . import SecretVerifier, VerifyOutcome, VerifyResult
from ._http import http_probe

_ENDPOINT = "https://gitlab.com/api/v4/user"


class GitLabTokenVerifier(SecretVerifier):

    def probe(self, secret_value: str) -> VerifyResult:
        resp = http_probe(
            _ENDPOINT,
            headers={"PRIVATE-TOKEN": secret_value},
        )
        if resp.ok:
            try:
                data = resp.json()
                username = data.get("username", "unknown")
            except Exception:
                username = "unknown"
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity=f"gitlab-user:{username}",
                reason=f"GET /api/v4/user returned 200 (username={username})",
            )
        if resp.auth_failure:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"GET /api/v4/user returned {resp.status}",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"GET /api/v4/user returned {resp.status}",
        )
