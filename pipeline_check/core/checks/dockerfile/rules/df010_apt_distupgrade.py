"""DF-010 — ``apt-get dist-upgrade`` / ``upgrade`` in RUN."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Dockerfile, run_bodies

RULE = Rule(
    id="DF-010",
    title="apt-get dist-upgrade / upgrade pulls unknown package versions",
    severity=Severity.LOW,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS",),
    cwe=("CWE-829",),
    recommendation=(
        "Drop the upgrade step. Build on a recent base image instead "
        "(rebuild your image when the base image gets a security "
        "patch — pin the base by digest per DF-001 so the rebuild is "
        "deterministic). ``apt-get install pkg=<version>`` for "
        "specific packages stays reproducible; ``upgrade`` / "
        "``dist-upgrade`` does not."
    ),
    docs_note=(
        "Running ``apt-get upgrade`` (or ``dist-upgrade``) inside a "
        "Dockerfile is the classic pet-vs-cattle anti-pattern. Two "
        "back-to-back builds with the same Dockerfile can produce "
        "different images because the upstream archive moved between "
        "the two ``RUN`` invocations. ``dist-upgrade`` additionally "
        "relaxes dependency resolution — it can install / remove "
        "arbitrary packages to satisfy upgrades, so the resulting "
        "image's package set isn't even bounded by what the "
        "Dockerfile declares."
    ),
)

_UPGRADE_RE = re.compile(
    r"\bapt(?:-get)?\s+(?:[-\w\s=]*\s+)?(?:dist-upgrade|upgrade)\b",
)


def check(df: Dockerfile) -> Finding:
    offenders: list[str] = []
    for line_no, body in run_bodies(df):
        if _UPGRADE_RE.search(body):
            offenders.append(f"L{line_no}")
    passed = not offenders
    desc = (
        "No ``RUN`` body invokes ``apt-get upgrade`` / ``dist-upgrade``."
        if passed else
        f"{len(offenders)} ``RUN`` body / bodies pull unknown package "
        f"versions via ``apt-get upgrade`` / ``dist-upgrade``: "
        f"{', '.join(offenders)}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
