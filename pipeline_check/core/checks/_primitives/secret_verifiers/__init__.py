"""Live secret verification: probe leaked credentials against their issuing API.

Strictly opt-in (``--verify-secrets`` + ``--resolve-remote``). When
enabled, every credential-shaped finding from the secret-detection
rules (GHA-008, GL-008, etc.) is probed against the upstream API to
determine whether the credential is currently active.

Three outcome buckets:

* **VERIFIED** — the endpoint returned an authenticated identity.
  Finding severity is promoted to CRITICAL.
* **UNVERIFIED** — the endpoint returned an explicit auth failure
  (401/403). The leaked value does not currently grant access.
  Finding severity is demoted toward LOW.
* **UNKNOWN** — ambiguous response or no verifier exists for the
  detector. Finding severity is unchanged.

Security invariants:

* Raw secret values are never stored on disk. Cache keys are the
  SHA-256 digest of the secret value.
* Identity strings are redacted in output by default;
  ``--verify-secrets-show-identity`` opts in to the full string.
* No probe runs unless both ``--resolve-remote`` and
  ``--verify-secrets`` are active; the no-network default is intact.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class VerifyOutcome(str, Enum):
    """Result bucket for a live secret probe."""

    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class VerifyResult:
    """Outcome of probing a single secret value."""

    outcome: VerifyOutcome
    identity: str | None = None
    reason: str = ""


class SecretVerifier:
    """Base class for per-detector-family verifiers.

    Subclasses implement :meth:`probe` with the detector-specific
    HTTP call. The base class owns rate-limit bookkeeping.
    """

    #: Maximum probes per second for this verifier family.
    rate_limit_rps: float = 10.0

    def __init__(self) -> None:
        self._last_probe_time: float = 0.0

    def _rate_limit(self) -> None:
        if self.rate_limit_rps <= 0:
            return
        min_interval = 1.0 / self.rate_limit_rps
        elapsed = time.monotonic() - self._last_probe_time
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self._last_probe_time = time.monotonic()

    def verify(self, secret_value: str) -> VerifyResult:
        """Rate-limited wrapper around :meth:`probe`."""
        self._rate_limit()
        try:
            return self.probe(secret_value)
        except Exception as exc:
            logger.debug("verifier %s raised: %s", type(self).__name__, exc)
            return VerifyResult(
                outcome=VerifyOutcome.UNKNOWN,
                reason=f"probe error: {type(exc).__name__}",
            )

    def probe(self, secret_value: str) -> VerifyResult:
        """Execute the live probe. Subclasses must override."""
        raise NotImplementedError


# ── Verifier registry ───────────────────────────────────────────────

#: Maps detector names (from ``_patterns.SECRET_DETECTORS``) to their
#: verifier instance. Populated by :func:`_register_builtins` on first
#: access via :func:`get_verifier`.
_REGISTRY: dict[str, SecretVerifier] = {}
_REGISTRY_LOADED = False


def _register_builtins() -> None:
    """Lazily populate the verifier registry on first use."""
    global _REGISTRY_LOADED
    if _REGISTRY_LOADED:
        return
    _REGISTRY_LOADED = True

    from .docker_hub import DockerHubTokenVerifier
    from .github import GitHubTokenVerifier
    from .gitlab import GitLabTokenVerifier
    from .google import GoogleAPIKeyVerifier
    from .jwt import JWTTokenVerifier
    from .npm import NpmTokenVerifier
    from .pypi import PyPITokenVerifier
    from .saas_api_keys import (
        AnthropicKeyVerifier,
        HuggingFaceTokenVerifier,
        OpenAIKeyVerifier,
        SendGridKeyVerifier,
        StripeKeyVerifier,
    )
    from .slack import SlackTokenVerifier

    _REGISTRY["github_token"] = GitHubTokenVerifier()
    _REGISTRY["npm_token"] = NpmTokenVerifier()
    _REGISTRY["slack_token"] = SlackTokenVerifier()
    _REGISTRY["anthropic_api_key"] = AnthropicKeyVerifier()
    _REGISTRY["openai_api_key"] = OpenAIKeyVerifier()
    _REGISTRY["huggingface_token"] = HuggingFaceTokenVerifier()
    _REGISTRY["sendgrid"] = SendGridKeyVerifier()
    _REGISTRY["stripe_secret"] = StripeKeyVerifier()
    _REGISTRY["gitlab_pat"] = GitLabTokenVerifier()
    _REGISTRY["docker_hub_pat"] = DockerHubTokenVerifier()
    _REGISTRY["pypi_token"] = PyPITokenVerifier()
    _REGISTRY["google_api_key"] = GoogleAPIKeyVerifier()
    _REGISTRY["jwt"] = JWTTokenVerifier()


def get_verifier(detector_name: str) -> SecretVerifier | None:
    """Return the verifier for *detector_name*, or ``None``."""
    _register_builtins()
    return _REGISTRY.get(detector_name)


def has_verifier(detector_name: str) -> bool:
    """True if a live-verification probe exists for *detector_name*."""
    _register_builtins()
    return detector_name in _REGISTRY


# ── Cache helpers ───────────────────────────────────────────────────


def _cache_key_for_secret(detector: str, raw_value: str) -> str:
    """SHA-256 the raw value so the cache never persists plaintext."""
    h = hashlib.sha256(raw_value.encode("utf-8")).hexdigest()
    return f"sv_{detector}_{h[:24]}"


# ── Top-level verification entry point ──────────────────────────────


def verify_token(
    detector: str,
    raw_value: str,
    *,
    cache: Any | None = None,
) -> VerifyResult:
    """Verify a single token, using the cache if available.

    Returns ``UNKNOWN`` when no verifier is registered for *detector*.
    """
    verifier = get_verifier(detector)
    if verifier is None:
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"no verifier for detector '{detector}'",
        )
    if cache is not None:
        ck = _cache_key_for_secret(detector, raw_value)
        cached = cache.get(ck)
        if cached is not None:
            try:
                d = json.loads(cached)
                return VerifyResult(
                    outcome=VerifyOutcome(d["outcome"]),
                    identity=d.get("identity"),
                    reason=d.get("reason", ""),
                )
            except (json.JSONDecodeError, KeyError, ValueError):
                pass

    result = verifier.verify(raw_value)

    if cache is not None:
        ck = _cache_key_for_secret(detector, raw_value)
        payload = json.dumps({
            "outcome": result.outcome.value,
            "identity": result.identity,
            "reason": result.reason,
        }).encode("utf-8")
        cache.put(ck, payload)

    return result


def redact_identity(identity: str | None) -> str | None:
    """Redact an identity string for default output."""
    if not identity:
        return identity
    if len(identity) <= 8:
        return identity[:2] + "***"
    return identity[:4] + "***" + identity[-2:]


__all__ = [
    "SecretVerifier",
    "VerifyOutcome",
    "VerifyResult",
    "get_verifier",
    "has_verifier",
    "redact_identity",
    "verify_token",
]
