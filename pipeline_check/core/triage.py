"""Local-LLM finding triage (opt-in, advisory).

Pipes a finding plus its surrounding pipeline snippet through a LOCAL LLM
(Ollama / llama.cpp / LM Studio, all of which expose an Ollama-style
``/api/generate`` endpoint) and asks for a context verdict:
``confirmed`` / ``needs_review`` / ``likely_fp``.

Design guarantees (see issue #167):

* **Advisory only.** A verdict never feeds back into the rule engine's
  severity or confidence, so a hallucinating model cannot turn a HIGH
  into a LOW. Callers render it in a separate channel.
* **Local by default.** :data:`DEFAULT_ENDPOINT` is loopback. A caller
  that points :func:`triage_finding` at a non-local host is doing so
  explicitly; :func:`is_local_endpoint` lets the CLI warn first.
* **Never raises on transport / parse failure.** An unreachable endpoint
  or an unparseable model reply yields a :data:`TriageLabel.UNAVAILABLE`
  verdict, never an exception that could abort the scan.

This module owns the transport, the response parsing, and the source-
snippet extraction; the prompt text lives in :mod:`.triage_prompts`.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse

from .checks.base import Finding
from .triage_prompts import build_prompt

#: Ollama's default local endpoint (llama.cpp / LM Studio expose the same
#: shape on their own ports, overridable by the caller).
DEFAULT_ENDPOINT = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "llama3.2"
_TIMEOUT = 30.0
_SNIPPET_CONTEXT = 4

#: Hostnames that count as loopback / non-network for the local-only
#: default. A caller targeting anything else is making an explicit remote
#: call.
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})


class TriageLabel(str, Enum):
    """The advisory verdict for a single finding."""

    CONFIRMED = "confirmed"
    NEEDS_REVIEW = "needs_review"
    LIKELY_FP = "likely_fp"
    #: Endpoint unreachable, timed out, or replied with something the
    #: parser couldn't map to one of the three labels.
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class TriageVerdict:
    """A model's advisory judgment on one finding."""

    label: TriageLabel
    rationale: str = ""


def is_local_endpoint(endpoint: str) -> bool:
    """Return True if *endpoint* points at a loopback host.

    Used by the CLI to decide whether to print a "sending findings to a
    remote endpoint" warning before any data leaves the machine.
    """
    host = (urlparse(endpoint).hostname or "").lower()
    return host in _LOCAL_HOSTS


_LABEL_ALIASES = {
    "confirmed": TriageLabel.CONFIRMED,
    "confirm": TriageLabel.CONFIRMED,
    "true_positive": TriageLabel.CONFIRMED,
    "exploitable": TriageLabel.CONFIRMED,
    "needs_review": TriageLabel.NEEDS_REVIEW,
    "review": TriageLabel.NEEDS_REVIEW,
    "unsure": TriageLabel.NEEDS_REVIEW,
    "unknown": TriageLabel.NEEDS_REVIEW,
    "likely_fp": TriageLabel.LIKELY_FP,
    "false_positive": TriageLabel.LIKELY_FP,
    "fp": TriageLabel.LIKELY_FP,
    "not_exploitable": TriageLabel.LIKELY_FP,
}

_FIRST_OBJECT_RE = re.compile(r"\{.*?\}", re.DOTALL)


def _coerce_label(raw: object) -> TriageLabel | None:
    if not isinstance(raw, str):
        return None
    key = raw.strip().lower().replace("-", "_").replace(" ", "_")
    return _LABEL_ALIASES.get(key)


def parse_model_reply(text: str) -> TriageVerdict:
    """Map a model's free-form reply to a :class:`TriageVerdict`.

    Accepts a bare JSON object, a JSON object embedded in prose, or (as a
    last resort) a reply that merely *mentions* one of the labels. Anything
    that yields no recognizable label becomes ``UNAVAILABLE`` so a confused
    model is never silently read as a real verdict.
    """
    candidates: list[str] = []
    stripped = text.strip()
    if stripped:
        candidates.append(stripped)
    m = _FIRST_OBJECT_RE.search(text)
    if m:
        candidates.append(m.group(0))
    for candidate in candidates:
        try:
            data = json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        label = _coerce_label(data.get("label") or data.get("verdict"))
        if label is not None:
            rationale = data.get("rationale") or data.get("reason") or ""
            return TriageVerdict(label, str(rationale).strip())
    # No JSON we could use: fall back to a plain mention of a label.
    low = text.lower()
    for key, label in _LABEL_ALIASES.items():
        if key in low:
            return TriageVerdict(label, "")
    return TriageVerdict(
        TriageLabel.UNAVAILABLE,
        "model reply did not contain a recognizable label",
    )


def triage_finding(
    finding: Finding,
    snippet: str,
    *,
    endpoint: str = DEFAULT_ENDPOINT,
    model: str = DEFAULT_MODEL,
    timeout: float = _TIMEOUT,
) -> TriageVerdict:
    """Ask the LLM at *endpoint* to triage *finding* given its *snippet*.

    Returns ``UNAVAILABLE`` (never raises) on any transport, decode, or
    parse failure.
    """
    payload = json.dumps({
        "model": model,
        "prompt": build_prompt(finding, snippet),
        "stream": False,
        # Ask Ollama to constrain output to JSON when the backend supports
        # it; the parser tolerates plain text either way.
        "format": "json",
    }).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
        data = json.loads(body)
    except (urllib.error.URLError, TimeoutError, OSError,
            json.JSONDecodeError, ValueError) as exc:
        return TriageVerdict(
            TriageLabel.UNAVAILABLE,
            f"triage endpoint unavailable: {type(exc).__name__}",
        )
    # Ollama wraps the model text in ``{"response": "..."}``; tolerate a
    # backend that returns the object directly.
    reply = data.get("response") if isinstance(data, dict) else None
    if not isinstance(reply, str):
        reply = body.decode("utf-8", "replace")
    return parse_model_reply(reply)


def extract_snippet(
    finding: Finding, *, context: int = _SNIPPET_CONTEXT,
) -> str:
    """Return a few source lines around *finding*'s first location.

    Reads the located file and returns ``context`` lines on each side of
    the finding's ``start_line`` (1-indexed, with a ``>`` marker on the
    offending line). Returns ``""`` when the finding has no usable
    location or the file can't be read, in which case the prompt notes the
    absence rather than failing.
    """
    start: int | None = None
    end = 0
    path = ""
    for loc in finding.locations:
        if loc.path and loc.start_line:
            start = loc.start_line
            end = loc.end_line or start
            path = loc.path
            break
    if start is None:
        return ""
    try:
        lines = Path(path).read_text(
            encoding="utf-8", errors="replace",
        ).splitlines()
    except OSError:
        return ""
    lo = max(1, start - context)
    hi = min(len(lines), end + context)
    out: list[str] = []
    for n in range(lo, hi + 1):
        marker = ">" if start <= n <= end else " "
        out.append(f"{marker} {n:>4} | {lines[n - 1]}")
    return "\n".join(out)


def triage_findings(
    findings: list[Finding],
    *,
    endpoint: str = DEFAULT_ENDPOINT,
    model: str = DEFAULT_MODEL,
    timeout: float = _TIMEOUT,
) -> list[tuple[Finding, TriageVerdict]]:
    """Triage each finding in turn, pairing it with its verdict.

    Snippets are extracted from disk per finding. Sequential by design:
    local models are single-GPU bound, so parallel requests would just
    contend. Order is preserved.
    """
    results: list[tuple[Finding, TriageVerdict]] = []
    for finding in findings:
        snippet = extract_snippet(finding)
        verdict = triage_finding(
            finding, snippet,
            endpoint=endpoint, model=model, timeout=timeout,
        )
        results.append((finding, verdict))
    return results
