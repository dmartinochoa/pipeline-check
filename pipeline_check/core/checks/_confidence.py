"""Centralised confidence defaults for every check.

Rules default to ``Confidence.HIGH`` at the Finding dataclass layer.
This registry demotes specific check IDs to ``MEDIUM`` or ``LOW``
based on their known false-positive modes, without requiring every
rule module to declare its own confidence.

The Scanner reads :func:`confidence_for` after a check runs and
applies the default ONLY when the rule hasn't set confidence
explicitly (i.e. the Finding still carries the dataclass default).
A rule that does want to override stays in control.

Adding a new demotion is a one-line entry here plus a note in the
rule's ``docs_note`` so ``explain CHECK-ID`` shows users why the
default is what it is.
"""
from __future__ import annotations

from .base import Confidence

# ── MEDIUM: heuristic rules with known FP modes ──────────────────────
_MEDIUM: frozenset[str] = frozenset({
    # GHA-004 — permissions block missing. Read-only workflows don't
    # need an explicit block; the default GITHUB_TOKEN is read-only on
    # public repos. The tightened check skips lint/test-only workflows
    # but can still over-flag some cases.
    "GHA-004",
    # Self-hosted-runner ephemeral detection — ARC / autoscaled runners
    # often use org-specific label conventions the heuristic may miss.
    "GHA-012",
    "JF-014",
    # Dep-update lockfile bypass — catches all ``pip install -U`` by
    # default; the safe subset (pip/setuptools/wheel/virtualenv) is
    # exempted but other tooling-upgrade idioms exist.
    "GHA-022",
    "GL-022",
    "BB-022",
    "ADO-022",
    "JF-022",
    "CC-022",
    # CB-005 outdated managed image — one version behind LATEST is a
    # hygiene warning, not a production issue. Two+ versions behind
    # remains HIGH via per-rule confidence assignment.
    "CB-005",
})

# ── LOW: blob-search heuristics; meaningful FP rate expected ─────────
_LOW: frozenset[str] = frozenset({
    # Curl-pipe detection — vendor installers over HTTPS are an idiom,
    # not automatically malicious. The tightened rule allowlists known
    # installers; everything else stays LOW so CI gates default-filter
    # them out unless the team explicitly opts into HIGH-only mode.
    "GHA-016", "GL-016", "BB-012", "ADO-016", "JF-016", "CC-016",
    # CP-003 source polling — ``PollForSourceChanges=true`` is the CFN
    # default for CodeCommit sources. The rule is advisory ("upgrade
    # to CodeStarSourceConnection") more than a real risk.
    "CP-003",
    # Malicious-activity rules — blob matches against a token registry.
    # Documentation repos, security training fixtures, CTF challenges
    # legitimately mention reverse shells / exfil domains.
    "GHA-027", "GL-025", "BB-025", "ADO-026", "CC-026", "JF-029",
    "CB-011",
    # Credential-shaped literals in pipeline body — AKIA/JWT patterns
    # appear in fixtures/docs even when `example` labelling isn't
    # matched by the context helper.
    "GHA-008", "GL-008", "BB-008", "ADO-008", "JF-008", "CC-008",
})


def confidence_for(check_id: str) -> Confidence:
    """Return the default confidence for *check_id*.

    HIGH is the fallback — the vast majority of checks assert on
    structural properties (an IAM policy grants ``Action: "*"``; a
    CloudTrail trail has ``LogFileValidationEnabled: false``) and their
    findings are unambiguous. Only the IDs listed above demote.
    """
    if check_id in _LOW:
        return Confidence.LOW
    if check_id in _MEDIUM:
        return Confidence.MEDIUM
    return Confidence.HIGH


def demotion_map() -> dict[str, Confidence]:
    """Full demotion table for documentation / introspection."""
    return {
        **{cid: Confidence.MEDIUM for cid in _MEDIUM},
        **{cid: Confidence.LOW for cid in _LOW},
    }
