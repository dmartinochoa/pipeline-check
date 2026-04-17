"""Detect TLS / host-key verification bypasses.

CI pipelines frequently need to talk to registries, git hosts, and
cluster APIs. When certificate verification is disabled anywhere on
that path, an attacker who can MITM the connection (compromised
corporate proxy, malicious runner network, DNS poisoning) can inject
payloads into the build. This primitive catalogues the idioms that
turn verification off across the tooling commonly found in CI:

* **Package managers**: ``npm``, ``yarn``, ``pip`` trust overrides.
* **Git**: ``http.sslVerify=false`` via ``git config`` or the
  ``GIT_SSL_NO_VERIFY`` environment variable.
* **Language-runtime env vars**: ``NODE_TLS_REJECT_UNAUTHORIZED=0``,
  ``PYTHONHTTPSVERIFY=0``, ``GOINSECURE``.
* **curl / wget**: ``-k`` / ``--insecure`` / ``--no-check-certificate``.
* **Kubernetes tooling**: ``helm`` and ``kubectl`` with
  ``--insecure-skip-tls-verify`` — frequently slipped into CI
  dry-run steps as a "just make it work" shortcut.
* **SSH**: ``-o StrictHostKeyChecking=no`` /
  ``-o UserKnownHostsFile=/dev/null`` — TOFU on every connection,
  which for an unattended CI runner is effectively no verification.

The primitive is intentionally word-boundary-strict so natural-text
strings like ``"sslverify is currently false in the docs"`` don't
false-positive — it looks for the tool's invocation shape, not for
any mention of the bypass token.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# ── Pattern catalogue ────────────────────────────────────────────
#
# One regex per tool keeps the dispatch table readable and lets
# rule consumers cite the specific offender ("npm disabled strict-
# ssl" is more actionable than "TLS verification disabled").

_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    # ── Package managers ──
    ("npm-strict-ssl", "npm",
     re.compile(r"\bnpm\s+config\s+set\s+strict-ssl\s+false\b", re.IGNORECASE)),
    ("yarn-strict-ssl", "yarn",
     re.compile(r"\byarn\s+config\s+set\s+strict-ssl\s+false\b", re.IGNORECASE)),
    ("pip-trusted-host", "pip",
     re.compile(r"\bpip3?\s+config\s+set\s+global\.trusted-host\b", re.IGNORECASE)),

    # ── Git ──
    ("git-sslverify-false", "git",
     re.compile(r"\bgit\s+config\s+[^\n]*http\.sslverify\s+false\b", re.IGNORECASE)),
    # Env vars are case-insensitive in the primitive: rule callers
    # hand us lowercased blobs via ``blob_lower``, and the uppercased
    # form in raw docs also matches via IGNORECASE.
    ("git-ssl-no-verify-env", "git",
     re.compile(r"\bGIT_SSL_NO_VERIFY\s*=\s*(?:true|1)\b", re.IGNORECASE)),

    # ── Language runtimes ──
    ("node-tls-reject-unauthorized", "node",
     re.compile(r"\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0['\"]?", re.IGNORECASE)),
    ("python-https-verify", "python",
     re.compile(r"\bPYTHONHTTPSVERIFY\s*=\s*['\"]?0['\"]?", re.IGNORECASE)),
    ("goinsecure", "go",
     re.compile(r"\bGOINSECURE\s*=", re.IGNORECASE)),

    # ── curl / wget ──
    ("curl-insecure", "curl",
     re.compile(r"\bcurl\b[^\n]*(?:\s-k\b|\s--insecure\b)", re.IGNORECASE)),
    ("wget-no-check-certificate", "wget",
     re.compile(r"\bwget\s+[^\n]*--no-check-certificate\b", re.IGNORECASE)),

    # ── Kubernetes tooling ──
    # Match the flag only when it trails a helm/kubectl verb so
    # natural-text mentions aren't caught.
    ("helm-insecure", "helm",
     re.compile(r"\bhelm\s+\S+[^\n]*--insecure-skip-tls-verify\b", re.IGNORECASE)),
    ("kubectl-insecure", "kubectl",
     re.compile(r"\bkubectl\b[^\n]*--insecure-skip-tls-verify\b", re.IGNORECASE)),

    # ── SSH ──
    # StrictHostKeyChecking=no disables host-key verification; the
    # known-hosts=/dev/null idiom is the drop-in variant that writes
    # each new fingerprint into the bit-bucket instead of accepting
    # ``no`` outright. Both produce TOFU-on-every-run, which for
    # unattended CI is effectively no verification.
    ("ssh-no-hostkey", "ssh",
     re.compile(r"\bssh\b[^\n]*-o\s+StrictHostKeyChecking\s*=\s*no\b", re.IGNORECASE)),
    ("ssh-known-hosts-null", "ssh",
     re.compile(r"\bssh\b[^\n]*-o\s+UserKnownHostsFile\s*=\s*/dev/null\b", re.IGNORECASE)),
)


# ── Public API ───────────────────────────────────────────────────


@dataclass(frozen=True)
class TlsBypassFinding:
    """A single TLS / host-key verification bypass hit."""

    kind: str     # stable tag, e.g. "npm-strict-ssl", "helm-insecure"
    tool: str     # "npm" / "curl" / "helm" / "ssh" / ...
    snippet: str  # the trimmed matching fragment


def scan(text: str) -> list[TlsBypassFinding]:
    """Return one entry per verification-bypass idiom in *text*."""
    out: list[TlsBypassFinding] = []
    for kind, tool, rex in _PATTERNS:
        for m in rex.finditer(text):
            out.append(TlsBypassFinding(
                kind=kind,
                tool=tool,
                snippet=_trim(m.group(0)),
            ))
    return out


def _trim(s: str, limit: int = 100) -> str:
    s = " ".join(s.split())
    return s if len(s) <= limit else s[: limit - 1] + "…"
