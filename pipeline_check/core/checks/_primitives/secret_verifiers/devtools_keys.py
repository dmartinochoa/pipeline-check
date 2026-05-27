"""Verifiers for developer-tooling API tokens.

Covers Linear, Atlassian (Forge/Connect), Asana, and New Relic. Each
endpoint is a fixed public URL; no user-supplied host is ever
constructed.
"""
from __future__ import annotations

import json as _json

from . import SecretVerifier, VerifyOutcome, VerifyResult
from ._http import bearer_probe, http_probe

# -- Linear --------------------------------------------------------------


class LinearAPIKeyVerifier(SecretVerifier):

    _ENDPOINT = "https://api.linear.app/graphql"

    def probe(self, secret_value: str) -> VerifyResult:
        resp = http_probe(
            self._ENDPOINT,
            method="POST",
            headers={
                "Authorization": secret_value,
                "Content-Type": "application/json",
            },
            body=_json.dumps(
                {"query": "{ viewer { id name email } }"},
            ).encode(),
        )
        if resp.ok:
            try:
                data = resp.json()
                viewer = data.get("data", {}).get("viewer", {})
                name = viewer.get("name") or viewer.get("email") or "unknown"
            except Exception:
                name = "unknown"
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity=f"linear-user:{name}",
                reason=f"POST /graphql returned 200 (viewer={name})",
            )
        if resp.auth_failure:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"POST /graphql returned {resp.status}",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"POST /graphql returned {resp.status}",
        )


# -- Atlassian (Forge / Connect) -----------------------------------------


class AtlassianTokenVerifier(SecretVerifier):

    _ENDPOINT = "https://api.atlassian.com/me"

    def probe(self, secret_value: str) -> VerifyResult:
        resp = bearer_probe(self._ENDPOINT, secret_value)
        if resp.ok:
            try:
                data = resp.json()
                name = data.get("name", "unknown")
            except Exception:
                name = "unknown"
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity=f"atlassian-user:{name}",
                reason=f"GET /me returned 200 (name={name})",
            )
        if resp.auth_failure:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"GET /me returned {resp.status}",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"GET /me returned {resp.status}",
        )


# -- Asana ----------------------------------------------------------------


class AsanaPATVerifier(SecretVerifier):

    _ENDPOINT = "https://app.asana.com/api/1.0/users/me"

    def probe(self, secret_value: str) -> VerifyResult:
        resp = bearer_probe(self._ENDPOINT, secret_value)
        if resp.ok:
            try:
                data = resp.json()
                name = data.get("data", {}).get("name", "unknown")
            except Exception:
                name = "unknown"
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity=f"asana-user:{name}",
                reason=f"GET /api/1.0/users/me returned 200 (name={name})",
            )
        if resp.auth_failure:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"GET /api/1.0/users/me returned {resp.status}",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"GET /api/1.0/users/me returned {resp.status}",
        )


# -- New Relic ------------------------------------------------------------


class NewRelicAPIKeyVerifier(SecretVerifier):

    _ENDPOINT = "https://api.newrelic.com/graphql"

    def probe(self, secret_value: str) -> VerifyResult:
        resp = http_probe(
            self._ENDPOINT,
            method="POST",
            headers={
                "API-Key": secret_value,
                "Content-Type": "application/json",
            },
            body=_json.dumps(
                {"query": "{ actor { user { name email } } }"},
            ).encode(),
        )
        if resp.ok:
            try:
                data = resp.json()
                user = (
                    data.get("data", {})
                    .get("actor", {})
                    .get("user", {})
                )
                name = user.get("name") or user.get("email") or "unknown"
            except Exception:
                name = "unknown"
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity=f"newrelic-user:{name}",
                reason=f"POST /graphql returned 200 (user={name})",
            )
        if resp.auth_failure:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"POST /graphql returned {resp.status}",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"POST /graphql returned {resp.status}",
        )
