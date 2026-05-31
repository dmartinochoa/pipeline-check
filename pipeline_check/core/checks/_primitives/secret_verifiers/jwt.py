"""JWT token verifier with issuer-based endpoint routing."""
from __future__ import annotations

import base64
import json
from urllib.parse import urlparse

from . import SecretVerifier, VerifyOutcome, VerifyResult
from ._http import bearer_probe


def _decode_jwt_payload(token: str) -> dict[str, object] | None:
    """Decode the JWT payload (middle segment) without verifying."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload = base64.urlsafe_b64decode(padded)
        result: dict[str, object] = json.loads(payload)
        return result
    except Exception:
        return None


# ``path`` is either a path appended to the issuer (Auth0 and Okta serve
# UserInfo under the issuer origin) or an absolute URL when the provider
# hosts UserInfo on a different host. Microsoft's identity platform serves
# it from Microsoft Graph and Google from its OIDC host, not the issuer.
_ISSUER_PROBES: list[tuple[str, str]] = [
    ("auth0.com", "/userinfo"),
    ("okta.com", "/oauth2/v1/userinfo"),
    ("login.microsoftonline.com", "https://graph.microsoft.com/oidc/userinfo"),
    ("accounts.google.com", "https://openidconnect.googleapis.com/v1/userinfo"),
    ("token.actions.githubusercontent.com", ""),
]


class JWTTokenVerifier(SecretVerifier):

    def probe(self, secret_value: str) -> VerifyResult:
        payload = _decode_jwt_payload(secret_value)
        if payload is None:
            return VerifyResult(
                outcome=VerifyOutcome.UNKNOWN,
                reason="could not decode JWT payload",
            )

        issuer = payload.get("iss")
        if not isinstance(issuer, str) or not issuer:
            return VerifyResult(
                outcome=VerifyOutcome.UNKNOWN,
                reason="JWT missing 'iss' claim",
            )

        sub = payload.get("sub", "unknown")

        host = urlparse(issuer).hostname or issuer

        _gh_oidc = "token.actions.githubusercontent.com"
        if host == _gh_oidc:
            return VerifyResult(
                outcome=VerifyOutcome.UNKNOWN,
                identity=f"github-oidc:{sub}",
                reason=(
                    "GitHub Actions OIDC token (short-lived, issuer "
                    "recognized but no live probe endpoint)"
                ),
            )

        for domain, path in _ISSUER_PROBES:
            if host == domain or host.endswith("." + domain):
                if not path:
                    return VerifyResult(
                        outcome=VerifyOutcome.UNKNOWN,
                        identity=f"jwt:{domain}:{sub}",
                        reason=f"issuer recognized ({domain}) but no userinfo endpoint",
                    )
                url = (
                    path if path.startswith("http")
                    else f"{issuer.rstrip('/')}{path}"
                )
                resp = bearer_probe(url, secret_value)
                if resp.ok:
                    identity = f"jwt:{domain}:{sub}"
                    try:
                        data = resp.json()
                        name = (
                            data.get("sub")
                            or data.get("email")
                            or data.get("name")
                            or sub
                        )
                        identity = f"jwt:{domain}:{name}"
                    except Exception:
                        pass
                    return VerifyResult(
                        outcome=VerifyOutcome.VERIFIED,
                        identity=identity,
                        reason=f"GET {path} returned 200 (issuer={domain})",
                    )
                if resp.auth_failure:
                    return VerifyResult(
                        outcome=VerifyOutcome.UNVERIFIED,
                        reason=f"GET {path} returned {resp.status} (issuer={domain})",
                    )
                return VerifyResult(
                    outcome=VerifyOutcome.UNKNOWN,
                    reason=f"GET {path} returned {resp.status} (issuer={domain})",
                )

        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            identity=f"jwt:{issuer}:{sub}",
            reason=f"unknown JWT issuer: {issuer}",
        )
