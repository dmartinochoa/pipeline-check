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
        if resp.status == 405:
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity="pypi-token:valid",
                reason=(
                    "POST /legacy/ returned 405 (Method Not Allowed with "
                    "valid auth, the upload endpoint rejects GET but "
                    "accepts the credential)"
                ),
            )
        if resp.auth_failure:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"upload.pypi.org returned {resp.status}",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"upload.pypi.org returned {resp.status}",
        )
