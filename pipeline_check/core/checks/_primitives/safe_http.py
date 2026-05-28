"""HTTP helpers that harden ``urllib`` against redirect-based SSRF.

The default ``urllib`` opener follows 3xx redirects to any scheme, so a
document fetched over HTTPS can be redirected to
``http://169.254.169.254/...`` or another internal host. The opener built
here refuses any redirect whose target is not ``https://``, closing that
downgrade for the remote-resolve fetchers (GitLab ``include:`` and the
GitHub raw fetcher) which follow attacker-controlled URLs.
"""
from __future__ import annotations

import urllib.error
import urllib.request
from http.client import HTTPMessage
from typing import IO, Any


class HTTPSOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject any redirect whose target is not ``https://``."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        if not newurl.lower().startswith("https://"):
            raise urllib.error.HTTPError(
                newurl,
                code,
                f"refusing redirect to non-https URL: {newurl}",
                headers,
                fp,
            )
        return super().redirect_request(
            req, fp, code, msg, headers, newurl,
        )


_HTTPS_ONLY_OPENER = urllib.request.build_opener(HTTPSOnlyRedirectHandler())


def urlopen_https_only(
    req: urllib.request.Request | str, *, timeout: float,
) -> Any:
    """Like ``urllib.request.urlopen`` but blocks http(s)-downgrade redirects.

    Returns the same response object ``urlopen`` would. Raises
    ``urllib.error.HTTPError`` if a redirect targets a non-https URL, so
    existing ``except HTTPError`` handlers treat the blocked redirect as a
    fetch failure.
    """
    return _HTTPS_ONLY_OPENER.open(req, timeout=timeout)
