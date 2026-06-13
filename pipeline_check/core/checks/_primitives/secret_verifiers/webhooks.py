"""Verifiers for leaked incoming-webhook URLs (Slack + Discord).

Unlike the API-token verifiers, the leaked secret here is a full webhook
URL whose embedded ID + token is itself the credential: anyone holding it
can post into the channel. Both probes are side-effect-free (no message is
ever posted).

* Discord exposes the webhook as a resource, so the live check is a
  read-only ``GET`` on the webhook URL: a live URL returns the webhook
  object (name / channel), and a deleted webhook or a rotated token
  returns 401 / 404.
* Slack has no read endpoint, so the live check ``POST``s an empty JSON
  body (``{}``). A live webhook parses it and rejects it with HTTP 400
  ``invalid_payload`` (nothing is posted, because there is no ``text``);
  a deleted webhook returns 404 ``no_service`` / ``no_team``. This is the
  standard no-message probe.
"""
from __future__ import annotations

from . import SecretVerifier, VerifyOutcome, VerifyResult
from ._http import http_probe


class DiscordWebhookVerifier(SecretVerifier):
    """Verify a Discord incoming-webhook URL via a read-only GET.

    The leaked value is the full webhook URL; GETting it returns the
    webhook object without sending anything.
    """

    def probe(self, secret_value: str) -> VerifyResult:
        resp = http_probe(secret_value)
        if resp.ok:
            try:
                data = resp.json()
                name = data.get("name") or "unknown"
                channel = data.get("channel_id") or "?"
            except Exception:
                name, channel = "unknown", "?"
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity=f"discord-webhook:{name}#{channel}",
                reason=f"GET webhook returned 200 (name={name})",
            )
        # 401 = rotated token, 404 = deleted webhook: either way it is dead.
        if resp.auth_failure or resp.status == 404:
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"GET webhook returned {resp.status}",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"GET webhook returned {resp.status}",
        )


class SlackWebhookVerifier(SecretVerifier):
    """Verify a Slack incoming-webhook URL without posting a message.

    Slack has no read endpoint for a webhook, so the probe POSTs an empty
    JSON object. A live webhook rejects it with HTTP 400 ``invalid_payload``
    (no message is posted, since there is no ``text``); a deleted webhook
    answers 404 ``no_service`` / ``no_team``.
    """

    # Slack returns one of these when the URL is live but the body is empty.
    _LIVE_MARKERS = ("invalid_payload", "missing_text", "no_text")
    # Slack returns one of these when the webhook no longer exists.
    _DEAD_MARKERS = ("no_service", "no_team")

    def probe(self, secret_value: str) -> VerifyResult:
        resp = http_probe(
            secret_value,
            method="POST",
            headers={"Content-Type": "application/json"},
            body=b"{}",
        )
        body = resp.body.decode("utf-8", "replace").strip().lower()
        if resp.ok or body == "ok":
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity="slack-webhook",
                reason=f"POST returned {resp.status} ({body or 'ok'})",
            )
        if resp.status == 404 or any(m in body for m in self._DEAD_MARKERS):
            return VerifyResult(
                outcome=VerifyOutcome.UNVERIFIED,
                reason=f"POST returned {resp.status} ({body})",
            )
        if any(m in body for m in self._LIVE_MARKERS):
            return VerifyResult(
                outcome=VerifyOutcome.VERIFIED,
                identity="slack-webhook",
                reason=f"POST returned {resp.status} ({body})",
            )
        return VerifyResult(
            outcome=VerifyOutcome.UNKNOWN,
            reason=f"POST returned {resp.status}",
        )
