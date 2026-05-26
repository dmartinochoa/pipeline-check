"""Shared HTTP probe primitives for secret verifiers."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


_PROBE_TIMEOUT = 10.0
_MAX_RESPONSE = 64 * 1024
_USER_AGENT = "pipeline-check-secret-verifier"


@dataclass(frozen=True, slots=True)
class ProbeResponse:
    """Raw HTTP probe result."""

    status: int
    body: bytes
    error: str | None = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    @property
    def auth_failure(self) -> bool:
        return self.status in (401, 403)

    def json(self) -> Any:
        return json.loads(self.body)


def http_probe(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: float = _PROBE_TIMEOUT,
) -> ProbeResponse:
    """Issue an HTTP request and return a structured result.

    Never raises on HTTP/network errors; the caller reads
    ``status`` / ``error`` to classify the outcome.
    """
    req = urllib.request.Request(url, method=method, data=body)
    req.add_header("User-Agent", _USER_AGENT)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_body: bytes = resp.read(_MAX_RESPONSE + 1)
            if len(resp_body) > _MAX_RESPONSE:
                resp_body = resp_body[:_MAX_RESPONSE]
            return ProbeResponse(status=resp.status, body=resp_body)
    except urllib.error.HTTPError as exc:
        resp_body = b""
        try:
            resp_body = exc.read(_MAX_RESPONSE)
        except Exception:
            pass
        return ProbeResponse(
            status=exc.code, body=resp_body, error=str(exc),
        )
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return ProbeResponse(status=0, body=b"", error=str(exc))


def bearer_probe(url: str, token: str) -> ProbeResponse:
    """GET with ``Authorization: Bearer <token>``."""
    return http_probe(
        url, headers={"Authorization": f"Bearer {token}"},
    )
