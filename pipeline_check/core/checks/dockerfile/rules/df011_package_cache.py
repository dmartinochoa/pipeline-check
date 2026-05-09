"""DF-011, package install in RUN without companion cache cleanup."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Dockerfile, run_bodies

RULE = Rule(
    id="DF-011",
    title="Package manager install without cache cleanup in same layer",
    severity=Severity.LOW,
    owasp=(),
    cwe=("CWE-1116",),
    recommendation=(
        "Combine the install and cleanup into the same ``RUN`` so the "
        "cache lands in a single layer that gets discarded together. "
        "Idiomatic pattern: ``RUN apt-get update && apt-get install -y "
        "<pkgs> && rm -rf /var/lib/apt/lists/*``. Equivalent forms: "
        "``apk add --no-cache <pkgs>``, ``dnf install -y … && dnf clean "
        "all``, ``yum install -y … && yum clean all``, ``zypper -n in "
        "… && zypper clean -a``."
    ),
    docs_note=(
        "Each Dockerfile ``RUN`` produces a layer. Installing packages "
        "in one layer and cleaning the cache in a later layer leaves "
        "the cache files in the lower layer forever, final image "
        "size is unchanged and the residual files broaden the attack "
        "surface (e.g. apt's signed-by keys, package metadata). The "
        "fix is layout, not behavior: do install + cleanup in the "
        "same ``RUN``."
    ),
)

# Detect: package manager *install* invocation in a RUN body.
_INSTALL_RES = {
    "apt":      re.compile(r"\bapt(?:-get)?\s+install\b"),
    "apk":      re.compile(r"\bapk\s+add\b"),
    "dnf":      re.compile(r"\b(?:micro)?dnf\s+install\b"),
    "yum":      re.compile(r"\byum\s+install\b"),
    "zypper":   re.compile(r"\bzypper\s+(?:-n\s+)?(?:install|in)\b"),
}

# A clean-up signal in the same RUN body that pairs with each manager.
# Either the dedicated ``--no-cache`` / ``clean all`` invocation, or an
# explicit ``rm -rf`` of the canonical cache dir.
_CLEANUP_RES = {
    "apt": re.compile(
        r"\brm\s+-rf\s+(?:[^&|;\n]*\s+)?/var/lib/apt/lists/?\*?"
        r"|\bapt-get\s+clean\b",
    ),
    "apk": re.compile(
        r"\bapk\s+add\s+(?:[^&|;\n]*\s+)?--no-cache\b"
        r"|\brm\s+-rf\s+(?:[^&|;\n]*\s+)?/var/cache/apk(?:/?\*)?",
    ),
    "dnf": re.compile(
        r"\b(?:micro)?dnf\s+clean\s+all\b"
        r"|\brm\s+-rf\s+(?:[^&|;\n]*\s+)?/var/cache/dnf(?:/?\*)?",
    ),
    "yum": re.compile(
        r"\byum\s+clean\s+all\b"
        r"|\brm\s+-rf\s+(?:[^&|;\n]*\s+)?/var/cache/yum(?:/?\*)?",
    ),
    "zypper": re.compile(
        r"\bzypper\s+clean\b"
        r"|\brm\s+-rf\s+(?:[^&|;\n]*\s+)?/var/cache/zypp(?:/?\*)?",
    ),
}


def check(df: Dockerfile) -> Finding:
    offenders: list[str] = []
    for line_no, body in run_bodies(df):
        for manager, install_re in _INSTALL_RES.items():
            if not install_re.search(body):
                continue
            cleanup_re = _CLEANUP_RES[manager]
            if cleanup_re.search(body):
                continue
            offenders.append(f"L{line_no}: {manager}")
    passed = not offenders
    desc = (
        "Every package install ``RUN`` discards its cache in the same layer."
        if passed else
        f"{len(offenders)} ``RUN`` body / bodies install packages "
        f"without same-layer cleanup: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
