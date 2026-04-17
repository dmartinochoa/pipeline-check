"""GCB-005 — Build ``timeout:`` must be set to a reasonable bound.

Cloud Build's default build timeout is 10 minutes; the maximum is
24 hours. A build without an explicit ``timeout:`` inherits the
default, which is often *too short* for container builds (leading
to silent retries) *and* provides no ceiling when a step hangs. An
excessive timeout (``7200s`` / 2 h and up) keeps hijacked builds
alive far longer than needed for a legitimate build, amplifying
the cost / dwell-time of a compromise.

Values accepted:
- ``timeout: 1800s`` (seconds, Cloud Build native format)
- ``timeout: 30m`` (convenience suffix — accepted by gcloud but not
  by the API; treated here as unresolvable and a fail)

This rule fails on:
1. ``timeout:`` absent entirely.
2. ``timeout:`` set to a value > 1800 seconds (30 minutes).

30 minutes is the threshold picked to match the cross-provider
convention in GHA-015 / GL-015 / CC-015.
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="GCB-005",
    title="Build timeout unset or excessive",
    severity=Severity.LOW,
    owasp=("CICD-SEC-7",),
    esf=("ESF-C-RESOURCE-LIMITS",),
    cwe=("CWE-400",),
    recommendation=(
        "Declare an explicit ``timeout:`` at the top of "
        "``cloudbuild.yaml`` bounded to the build's realistic worst "
        "case (e.g. ``1800s`` for most container builds). Explicit "
        "bounds shorten the window a compromised build can spend "
        "on a shared worker and flag regressions when a legitimate "
        "step slows down."
    ),
    docs_note=(
        "Cloud Build's default 10-minute timeout applies silently when "
        "``timeout:`` is absent. Accepted format is ``<N>s`` (seconds); "
        "``<N>m``/``<N>h`` forms are a gcloud convenience and are "
        "treated as malformed by the API."
    ),
)

_SECONDS_RE = re.compile(r"^\s*(\d+)\s*s\s*$")
_MAX_ACCEPTABLE_SECONDS = 1800


def _parse_timeout_seconds(value: Any) -> int | None:
    """Return timeout in seconds for a Cloud Build ``timeout:`` value.

    Cloud Build accepts ``"1800s"`` (string with ``s`` suffix); the API
    rejects bare numbers and rejects minute/hour suffixes. Anything
    unparseable returns ``None`` so the caller can treat it the same as
    an unset timeout.
    """
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return int(value)
    if isinstance(value, str):
        m = _SECONDS_RE.match(value)
        if m:
            return int(m.group(1))
    return None


def check(path: str, doc: dict[str, Any]) -> Finding:
    raw = doc.get("timeout")
    seconds = _parse_timeout_seconds(raw)
    if seconds is None:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "No ``timeout:`` declared — build inherits the 10-minute "
                "Cloud Build default."
                if raw is None else
                f"``timeout: {raw!r}`` is not a valid Cloud Build duration "
                "(expected ``<seconds>s``)."
            ),
            recommendation=RULE.recommendation, passed=False,
        )
    if seconds > _MAX_ACCEPTABLE_SECONDS:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                f"``timeout: {raw}`` ({seconds}s) exceeds the "
                f"{_MAX_ACCEPTABLE_SECONDS}s threshold. A compromised "
                "build can spend the excess time on a shared worker."
            ),
            recommendation=RULE.recommendation, passed=False,
        )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path,
        description=f"``timeout: {raw}`` ({seconds}s) is bounded.",
        recommendation=RULE.recommendation, passed=True,
    )
