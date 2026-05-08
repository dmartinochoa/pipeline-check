"""Detect remote scripts piped into an interpreter.

``curl <url> | bash`` and its variants execute attacker-controllable
content the moment the URL's host (or TLS / DNS / CDN path to it)
is compromised. The pattern is endemic in CI bootstrap scripts — it
fits on one line and requires no checkout step — which is exactly
why it makes such a reliable beach-head for supply-chain attacks.

Idioms detected:

1. **Direct pipe**: ``curl … | bash`` / ``wget … | sh`` (also
   ``python[23]``, ``perl``, ``ruby``, and ``sudo`` variants).
2. **Process-substitution pipe**: ``bash -c "$(curl …)"`` /
   ``sh -c "$(wget …)"`` — the shell re-enters itself on the
   downloaded content.
3. **Python inline fetcher**: ``python -c "urllib…get(url).read…"``
   and the ``requests.get`` variant, typically used to grab a
   loader on minimal images.
4. **Download-then-execute**: ``curl > x.sh && bash x.sh`` — the
   script hits disk but is still attacker-controlled.
5. **PowerShell**: ``irm <url> | iex`` / ``Invoke-WebRequest | iex``
   / ``Invoke-RestMethod | iex`` — the Windows analogue.

Vendor-trusted classification
-----------------------------

A short allowlist of well-known installer hosts (rustup.rs,
get.docker.com, bun.sh/install, cli.github.com, …) is tracked so
callers can downgrade confidence uniformly. The allowlist matches
the GHA-016 ``known_fp`` catalog — every other provider's
wrapper inherits the same distinction without re-stating it.

The primitive itself does NOT emit Findings, set severity, or
demote confidence. It surfaces ``vendor_trusted`` as a bool on
each hit and leaves presentation to the caller.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# ── Vendor allowlist ─────────────────────────────────────────────
#
# Installer endpoints operated by the language / tool vendor over
# HTTPS from their own CDN. These still carry supply-chain risk if
# the vendor's infra is compromised, but they're idiomatic bootstrap
# paths and teams that want cryptographic verification already know
# where to look. Host match is exact or subdomain-of (``foo.bun.sh``
# matches ``bun.sh``).
_VENDOR_HOSTS = frozenset({
    "rustup.rs", "sh.rustup.rs",
    "get.docker.com",
    "bun.sh",
    "cli.github.com",
    "awscli.amazonaws.com",
    "get.sdkman.io",
    "install.python-poetry.org",
    "get.helm.sh",
    "deb.nodesource.com", "rpm.nodesource.com",
    "apt.releases.hashicorp.com",
    "get.pnpm.io",
    "fnm.vercel.app",
    "nvm.sh",
    "dotnet.microsoft.com",
    "packages.microsoft.com",
    "cloud.google.com",
    "sdk.cloud.google.com",
})


# ── Pattern catalog ────────────────────────────────────────────

# A URL captured up to the first whitespace / pipe / redirect / term.
_URL = r"https?://[^\s|;&'\">`]+"

# curl/wget ... URL ... | (sudo )? bash|sh|python|perl|ruby
_PIPE_RE = re.compile(
    r"\b(?P<fetcher>curl|wget)\b[^|]*?"
    r"(?P<url>" + _URL + r")"
    r"[^|]*\|\s*(?:sudo\s+)?"
    r"(?P<interp>(?:ba)?sh|python[23]?|perl|ruby)\b",
    re.IGNORECASE,
)

# (ba)?sh -c "$(curl|wget URL)"  — re-enter the shell on fetched
# content. Single or double quotes.
_SHELL_SUBSHELL_RE = re.compile(
    r"\b(?P<interp>(?:ba)?sh)\s+-c\s+"
    r"[\"']\$\(\s*(?P<fetcher>curl|wget)\b[^)]*?"
    r"(?P<url>" + _URL + r")"
    r"[^)]*\)[\"']",
    re.IGNORECASE,
)

# python -c "… urllib|requests.get( URL ).read() …"
# Host extraction is best-effort: grab the first URL literal after
# the fetch call on the same line. Bounded by newline rather than
# quote style so single-quoted URL literals inside the double-quoted
# ``-c`` payload still match.
_PYTHON_INLINE_RE = re.compile(
    r"\bpython[23]?\s+-c\s+[\"'][^\n]*?"
    r"(?:urllib[^\n]*?\.urlopen|requests[^\n]*?\.get)"
    r"[^\n]*?(?P<url>https?://[^\s'\"()\]]+)",
    re.IGNORECASE,
)

# curl|wget URL > x.sh ; bash x.sh
# The second half only needs to show *some* interpreter invocation
# on the same line after a statement separator — capturing the exact
# filename is fragile across `&& / ; / newline` variants.
_DOWNLOAD_EXEC_RE = re.compile(
    r"\b(?P<fetcher>curl|wget)\b[^;&\n]*?"
    r"(?P<url>" + _URL + r")"
    r"[^;&\n]*>\s*\S+\.sh\s*[;&]+\s*"
    r"(?P<interp>(?:ba)?sh|python[23]?|perl|ruby)\b",
    re.IGNORECASE,
)

# PowerShell: irm <url> | iex  /  Invoke-WebRequest / Invoke-RestMethod
_POWERSHELL_RE = re.compile(
    r"\b(?P<fetcher>irm|iwr|Invoke-WebRequest|Invoke-RestMethod)\b"
    r"\s+[^|]*?(?P<url>" + _URL + r")"
    r"[^|]*\|\s*(?P<interp>iex|Invoke-Expression)\b",
    re.IGNORECASE,
)


# ── Public API ───────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class RemoteExecFinding:
    """A single remote-script-to-interpreter hit."""

    kind: str              # "curl-pipe", "shell-subshell", "python-inline",
                           # "download-exec", "powershell"
    interpreter: str       # bash / sh / python3 / perl / ruby / iex / ...
    url: str               # the fetched URL literal
    host: str              # parsed host (``""`` if URL is malformed)
    snippet: str           # trimmed match for display
    vendor_trusted: bool   # host is in the vendor allowlist


def scan(text: str) -> list[RemoteExecFinding]:
    """Return one entry per remote-exec idiom occurrence in *text*."""
    hits: list[RemoteExecFinding] = []
    seen_spans: set[tuple[int, int]] = set()

    def _emit(
        kind: str,
        m: re.Match[str],
        interp_key: str = "interp",
        *,
        interp_override: str | None = None,
        url: str | None = None,
        host: str | None = None,
    ) -> None:
        # ``interp_override`` lets a caller bypass ``m.group(interp_key)``
        # when the regex doesn't carry an ``interp`` group (the
        # python-inline pattern). ``url`` / ``host`` let a caller hand
        # in pre-computed values so ``_host_of`` isn't repeated.
        if m.span() in seen_spans:
            return
        seen_spans.add(m.span())
        if url is None:
            url = m.group("url")
        if host is None:
            host = _host_of(url)
        interpreter = (
            interp_override if interp_override is not None
            else m.group(interp_key).lower()
        )
        hits.append(RemoteExecFinding(
            kind=kind,
            interpreter=interpreter,
            url=url,
            host=host,
            snippet=_trim(m.group(0)),
            vendor_trusted=_is_vendor(host),
        ))

    # Order matters for dedup: shell-subshell and download-exec both
    # contain a raw curl/wget fragment that _PIPE_RE would also
    # claim. Match the compound forms first so the generic pipe
    # matcher only catches genuine ``curl | bash`` one-liners.
    for m in _SHELL_SUBSHELL_RE.finditer(text):
        _emit("shell-subshell", m)
    for m in _DOWNLOAD_EXEC_RE.finditer(text):
        _emit("download-exec", m)
    for m in _PIPE_RE.finditer(text):
        # Skip if this match is fully inside a previously-seen span.
        if any(s[0] <= m.start() and m.end() <= s[1] for s in seen_spans):
            continue
        _emit("curl-pipe", m)
    for m in _PYTHON_INLINE_RE.finditer(text):
        # Cache url and host so _host_of runs once per match. The
        # _PYTHON_INLINE_RE has no ``interp`` group (the regex
        # anchors on ``python[23]?`` directly), so route through
        # ``_emit`` with ``interp_override`` to get the same span
        # dedup and vendor-trusted classification the other branches
        # use.
        url = m.group("url")
        host = _host_of(url)
        _emit(
            "python-inline", m,
            interp_override="python",
            url=url, host=host,
        )
    for m in _POWERSHELL_RE.finditer(text):
        _emit("powershell", m)
    return hits


# ── Helpers ──────────────────────────────────────────────────────


_HOST_RE = re.compile(r"https?://([^/\s:?#]+)", re.IGNORECASE)


def _host_of(url: str) -> str:
    m = _HOST_RE.match(url)
    return m.group(1).lower() if m else ""


def _is_vendor(host: str) -> bool:
    """Exact-match or subdomain-of any entry in ``_VENDOR_HOSTS``."""
    if not host:
        return False
    if host in _VENDOR_HOSTS:
        return True
    return any(host.endswith("." + v) for v in _VENDOR_HOSTS)


def _trim(s: str, limit: int = 100) -> str:
    s = " ".join(s.split())
    return s if len(s) <= limit else s[: limit - 1] + "…"
