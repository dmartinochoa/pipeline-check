"""Centralized confidence defaults for every check.

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

from ._best_practice import BEST_PRACTICE_IDS, is_best_practice
from .base import Confidence

# ── MEDIUM: heuristic rules with known FP modes ──────────────────────
_MEDIUM: frozenset[str] = frozenset({
    # GHA-004, permissions block missing. Read-only workflows don't
    # need an explicit block; the default GITHUB_TOKEN is read-only on
    # public repos. The tightened check skips lint/test-only workflows
    # but can still over-flag some cases.
    "GHA-004",
    # Self-hosted-runner ephemeral detection. ARC / autoscaled runners
    # often use org-specific label conventions the heuristic may miss.
    "GHA-012",
    # Self-hosted runner reachable from a PR trigger. Can't tell a
    # public repo (fork PRs run untrusted code) from a private one
    # with only trusted internal contributors, so it over-flags the
    # latter.
    "GHA-105",
    # Agentic AI CLI with a write-scoped token. Some agent jobs
    # legitimately need contents:write (auto-formatters behind
    # required reviews); the least-privilege fix is still to scope
    # the write away from the agent, but it's a judgment call.
    "GHA-106",
    # Agentic AI CLI co-located in one job with an unattended IaC
    # apply. The rule asserts co-location (shared workspace + cloud
    # credentials), not a proven dataflow from the agent's edits to
    # the applied plan, so an unrelated read-only agent next to an
    # apply over-flags.
    "GHA-111",
    # Self-hosted deploy without an environment gate. Deploy detection
    # is a job-name / command heuristic, and a non-prod (staging /
    # preview) self-hosted deploy may intentionally skip the gate.
    "GHA-112",
    # OIDC trusted-publishing job with no environment gate. The rule
    # infers the OIDC path from the co-occurrence of ``id-token: write``
    # and a publish step, but a job that mints the token for signing /
    # cloud credentials and publishes on a long-lived token (or a
    # first-publish bootstrap before the trusted-publisher record
    # exists) over-flags, so the assertion is co-occurrence, not a
    # proven OIDC exchange.
    "GHA-113",
    # Publish workflow on an unrestricted push trigger. An internal CD
    # pipeline may intentionally publish a snapshot to a private registry
    # on every branch push, so an unrestricted-trigger publish is not
    # always a public-release exposure.
    "GHA-114",
    # id-token: write granted workflow-wide while only a subset of jobs
    # consume it. The over-broad call depends on recognizing every job's
    # OIDC consumer; a consumer reached through an unrecognized action
    # can make a consuming job look non-consuming and over-flag it.
    "GHA-115",
    "JF-014",
    # Dep-update lockfile bypass, catches all ``pip install -U`` by
    # default; the safe subset (pip/setuptools/wheel/virtualenv) is
    # exempted but other tooling-upgrade idioms exist.
    "GHA-022",
    "GL-022",
    "BB-022",
    "ADO-022",
    "JF-022",
    "CC-022",
    # CB-005 outdated managed image, one version behind LATEST is a
    # hygiene warning, not a production issue. Two+ versions behind
    # remains HIGH via per-rule confidence assignment.
    "CB-005",
    # NPM-017 provenance built from a non-release ref. The trusted-
    # default heuristic is main/master only, so a project whose default
    # branch is named otherwise (develop, trunk) over-flags.
    "NPM-017",
    # PYPI-021, the PyPI / PEP 740 analog of NPM-017. Same trusted-
    # default heuristic (main/master only), so a project whose default
    # branch is named otherwise over-flags.
    "PYPI-021",
    # NPM-018, latest release published by an account new to the package.
    # The per-version publisher is the only static signal, so a
    # legitimate maintainer hand-off / new co-maintainer's first publish
    # trips it the same as a takeover.
    "NPM-018",
})

# ── LOW: blob-search heuristics; meaningful FP rate expected ─────────
_LOW: frozenset[str] = frozenset({
    # Curl-pipe detection, vendor installers over HTTPS are an idiom,
    # not automatically malicious. The tightened rule allowlists known
    # installers; everything else stays LOW so CI gates default-filter
    # them out unless the team explicitly opts into HIGH-only mode.
    "GHA-016", "GL-016", "BB-012", "ADO-016", "JF-016", "CC-016",
    # CP-003 source polling, ``PollForSourceChanges=true`` is the CFN
    # default for CodeCommit sources. The rule is advisory ("upgrade
    # to CodeStarSourceConnection") more than a real risk.
    "CP-003",
    # Malicious-activity rules, blob matches against a token registry.
    # Documentation repos, security training fixtures, CTF challenges
    # legitimately mention reverse shells / exfil domains.
    "GHA-027", "GL-025", "BB-025", "ADO-026", "CC-026", "JF-029",
    "CB-011",
    # Credential-shaped literals in pipeline body. AKIA/JWT patterns
    # appear in fixtures/docs even when `example` labeling isn't
    # matched by the context helper.
    "GHA-008", "GL-008", "BB-008", "ADO-008", "JF-008", "CC-008",
})


def confidence_for(check_id: str) -> Confidence:
    """Return the default confidence for *check_id*.

    HIGH is the fallback, the vast majority of checks assert on
    structural properties (an IAM policy grants ``Action: "*"``; a
    CloudTrail trail has ``LogFileValidationEnabled: false``) and their
    findings are unambiguous. Only the IDs listed above demote, plus
    the best-practice / missing-control family below.
    """
    if check_id in _LOW:
        return Confidence.LOW
    if check_id in _MEDIUM:
        return Confidence.MEDIUM
    # Best-practice / "missing-control" rules (no timeout, no SBOM, no
    # signing, no vuln scan) demote to LOW so the high-signal
    # ``--min-confidence MEDIUM`` view focuses on active risk rather than
    # hygiene gaps. The detection itself is certain (the control really is
    # absent); LOW here means "low-priority", not "likely a false
    # positive". On a real repo this family is the bulk of the firings, so
    # surfacing it at the default LOW threshold while letting CI gates
    # filter it out is the signal-to-noise win. An explicit ``_LOW`` /
    # ``_MEDIUM`` entry above still wins (specific over category).
    if is_best_practice(check_id):
        return Confidence.LOW
    return Confidence.HIGH


def demotion_map() -> dict[str, Confidence]:
    """Full demotion table for documentation / introspection.

    Best-practice IDs come first so an explicit ``_MEDIUM`` / ``_LOW``
    entry (later in the merge) wins, mirroring :func:`confidence_for`'s
    specific-over-category precedence.
    """
    return {
        **dict.fromkeys(BEST_PRACTICE_IDS, Confidence.LOW),
        **dict.fromkeys(_MEDIUM, Confidence.MEDIUM),
        **dict.fromkeys(_LOW, Confidence.LOW),
    }
