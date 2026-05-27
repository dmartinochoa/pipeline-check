"""Verifiers for cloud deployment platform tokens.

Covers DigitalOcean, Netlify, and Terraform Cloud. Each endpoint is a
fixed public URL; no user-supplied host is ever constructed.
"""
from __future__ import annotations

from . import SecretVerifier, VerifyOutcome, VerifyResult
from ._http import bearer_probe, http_probe

# -- DigitalOcean -------------------------------------------------------


class DigitalOceanTokenVerifier(SecretVerifier):

    _ENDPOINT = "https://api.digitalocean.com/v2/account"

    def probe(self, secret_value: str) -> VerifyResult:
        resp = bearer_probe(self._ENDPOINT, secret_value)
        if resp.ok:
            try:
                data = resp.json()
                email = data.get("account", {}).get("email", "unknown")
            except Exception:
                email = "unknown"
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity=f"do-account:{email}",
                reason=f"GET /v2/account returned 200 (email={email})",
            )
        if resp.auth_failure:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"GET /v2/account returned {resp.status}",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"GET /v2/account returned {resp.status}",
        )


# -- Netlify -------------------------------------------------------------


class NetlifyTokenVerifier(SecretVerifier):

    _ENDPOINT = "https://api.netlify.com/api/v1/user"

    def probe(self, secret_value: str) -> VerifyResult:
        resp = bearer_probe(self._ENDPOINT, secret_value)
        if resp.ok:
            try:
                data = resp.json()
                email = data.get("email", "unknown")
            except Exception:
                email = "unknown"
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity=f"netlify-user:{email}",
                reason=f"GET /api/v1/user returned 200 (email={email})",
            )
        if resp.auth_failure:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"GET /api/v1/user returned {resp.status}",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"GET /api/v1/user returned {resp.status}",
        )


# -- Terraform Cloud / Enterprise ----------------------------------------


class TerraformCloudTokenVerifier(SecretVerifier):

    _ENDPOINT = "https://app.terraform.io/api/v2/account/details"

    def probe(self, secret_value: str) -> VerifyResult:
        resp = http_probe(
            self._ENDPOINT,
            headers={
                "Authorization": f"Bearer {secret_value}",
                "Content-Type": "application/vnd.api+json",
            },
        )
        if resp.ok:
            try:
                data = resp.json()
                username = (
                    data.get("data", {})
                    .get("attributes", {})
                    .get("username", "unknown")
                )
            except Exception:
                username = "unknown"
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity=f"tfc-user:{username}",
                reason=(
                    "GET /api/v2/account/details returned 200 "
                    f"(username={username})"
                ),
            )
        if resp.auth_failure:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=(
                    f"GET /api/v2/account/details returned {resp.status}"
                ),
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=(
                f"GET /api/v2/account/details returned {resp.status}"
            ),
        )
