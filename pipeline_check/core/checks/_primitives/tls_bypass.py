"""Detect TLS / host-key verification bypasses.

CI pipelines frequently need to talk to registries, git hosts, and
cluster APIs. When certificate verification is disabled anywhere on
that path, an attacker who can MITM the connection (compromised
corporate proxy, malicious runner network, DNS poisoning) can inject
payloads into the build. This primitive catalogs the idioms that
turn verification off across the tooling commonly found in CI:

* **Package managers**: ``npm``, ``yarn``, ``pip`` trust overrides.
* **Git**: ``http.sslVerify=false`` via ``git config`` or the
  ``GIT_SSL_NO_VERIFY`` environment variable.
* **Language-runtime env vars**: ``NODE_TLS_REJECT_UNAUTHORIZED=0``,
  ``PYTHONHTTPSVERIFY=0``, ``GOINSECURE``.
* **curl / wget**: ``-k`` / ``--insecure`` / ``--no-check-certificate``.
* **Kubernetes tooling**: ``helm`` and ``kubectl`` with
  ``--insecure-skip-tls-verify``, frequently slipped into CI
  dry-run steps as a "just make it work" shortcut.
* **SSH**: ``-o StrictHostKeyChecking=no`` /
  ``-o UserKnownHostsFile=/dev/null``. TOFU on every connection,
  which for an unattended CI runner is effectively no verification.

The primitive is intentionally word-boundary-strict so natural-text
strings like ``"sslverify is currently false in the docs"`` don't
false-positive. It looks for the tool's invocation shape, not for
any mention of the bypass token.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# ── Pattern catalog ────────────────────────────────────────────
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
    # Per-invocation inline form: ``git -c http.sslVerify=false <cmd>``.
    # This is the standard way to disable TLS verification for a single
    # git call without touching the global config; it is just as risky
    # as the ``git config`` form because it bypasses cert checking for
    # the entire duration of that invocation.
    ("git-inline-sslverify-false", "git",
     re.compile(r"\bgit\b[^\n]*-c\s+http\.sslverify\s*=\s*false\b", re.IGNORECASE)),
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
    # ``-k`` is case-sensitive: lowercase ``-k`` is ``--insecure`` while
    # uppercase ``-K`` is curl's ``--config`` flag and is unrelated to
    # TLS.  The ``k`` may sit anywhere inside a bundled short-flag
    # cluster (``curl -sk``, ``curl -fsSLk``, ``curl -kL``), the dominant
    # real-world form, so match a single-dash letter run that contains a
    # lowercase ``k``.  ``--insecure`` and other long flags begin with
    # ``--`` (an empty letter run before a second dash) and so are left
    # to the dedicated long-flag pattern below.  ``--insecure`` is kept
    # case-insensitive because it has no ambiguous uppercase sibling.
    # Both patterns share the "curl-insecure" kind tag so downstream
    # consumers get a single label.
    ("curl-insecure", "curl",
     re.compile(r"\bcurl\b[^\n]*\s-[A-Za-z]*k[A-Za-z]*\b")),  # case-sensitive
    ("curl-insecure", "curl",
     re.compile(r"\bcurl\b[^\n]*\s--insecure\b", re.IGNORECASE)),
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

    # ── Docker daemon and CLI ──
    # ``--insecure-registry`` on the daemon (or its config in
    # ``/etc/docker/daemon.json``) tells Docker to talk to a registry
    # over HTTP or with a self-signed cert — the same MITM exposure
    # the other patterns flag, but routinely overlooked because the
    # flag tends to be tucked into a ``dockerd`` startup script.
    ("docker-insecure-registry", "docker",
     re.compile(
         r"\b(?:dockerd|docker(?:\s+\S+)?)\b[^\n]*--insecure-registry\b",
         re.IGNORECASE,
     )),

    # ── JVM build tools ──
    # Maven and Gradle each have a JVM system property that disables
    # the HTTPS hostname / cert check for their dependency resolvers.
    # Both are popular shortcuts when an internal Nexus is misconfigured;
    # both turn the build into a soft target for repo poisoning.
    ("maven-insecure", "maven",
     re.compile(r"-Dmaven\.wagon\.http\.ssl\.insecure\s*=\s*true", re.IGNORECASE)),
    ("gradle-insecure", "gradle",
     re.compile(r"-Dorg\.gradle\.internal\.http\.connectionTimeout|"
                r"-Dorg\.gradle\.https\.insecure\s*=\s*true|"
                r"systemProp\.https?\.insecure\s*=\s*true", re.IGNORECASE)),

    # ── AWS CLI ──
    # ``AWS_S3_NO_VERIFY_SSL=true`` tells the boto3-backed CLI to skip
    # cert verification for S3; ``AWS_CA_BUNDLE=`` (empty) does the
    # same blanket-disable across services. ``--no-verify-ssl`` on the
    # CLI is the request-level form of the same opt-out.
    ("aws-no-verify-ssl-env", "aws",
     re.compile(r"\bAWS_S3_NO_VERIFY_SSL\s*=\s*(?:true|1)\b", re.IGNORECASE)),
    ("aws-no-verify-ssl-flag", "aws",
     re.compile(r"\baws\b[^\n]*--no-verify-ssl\b", re.IGNORECASE)),
)


# ── Public API ───────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
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
