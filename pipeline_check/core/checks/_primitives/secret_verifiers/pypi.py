"""PyPI upload-token verifier."""
from __future__ import annotations

from . import SecretVerifier, VerifyOutcome, VerifyResult
from ._http import bearer_probe

_ENDPOINT = "https://pypi.org/manage/account/token/"


class PyPITokenVerifier(SecretVerifier):

    def probe(self, secret_value: str) -> VerifyResult:
        resp = bearer_probe(
            "https://upload.pypi.org/legacy/",
            secret_value,
        )
        if resp.auth_failure:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"upload.pypi.org returned {resp.status}",
            )
        # A GET to /legacy/ returns 405 (Method Not Allowed) regardless
        # of whether the credential is valid, because the endpoint only
        # accepts POST and rejects the method before checking auth. So a
        # 405 is NOT proof the token is live. Without an authenticated
        # read endpoint we cannot confirm a PyPI upload token; report
        # UNKNOWN rather than a false VERIFIED that would promote a dead
        # token to CRITICAL.
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=(
                f"upload.pypi.org returned {resp.status}; PyPI upload "
                "tokens cannot be confirmed read-only"
            ),
        )
