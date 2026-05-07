"""BK-001 — Plugins must be pinned to an exact tag/SHA, not a branch."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    iter_command_steps,
    iter_plugins,
    plugin_location,
    step_label,
)

RULE = Rule(
    id="BK-001",
    title="Buildkite plugin not pinned to an exact version",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-VERIFY-DEPS"),
    cwe=("CWE-829",),
    recommendation=(
        "Pin every plugin reference to an exact tag (``docker-compose#"
        "v4.13.0``) or a 40-char commit SHA. Bare references "
        "(``docker-compose``), branch refs (``#main`` / ``#master``), "
        "and major-only floats (``#v4``) resolve to whatever is "
        "current at agent start time, which lets a compromised plugin "
        "release execute inside the pipeline."
    ),
    docs_note=(
        "Buildkite resolves plugin refs at agent boot. ``foo#v1.2.3`` "
        "locks the version; ``foo#main`` / ``foo`` does not. Detection "
        "fires on bare names, branch keywords, and partial-semver pins "
        "(``v4``, ``v4.13``)."
    ),
)

# A pinned ref ends in either an exact-semver suffix or a 40-char SHA.
_EXACT_SEMVER_RE = re.compile(r"#v?\d+\.\d+\.\d+(?:[-+][\w.]+)?$")
_SHA_RE = re.compile(r"#[0-9a-f]{40}$")
# Branch-style refs that float — explicit denylist so an unusual but
# legitimate semver tag doesn't get caught by the partial-pin fallback.
_BRANCH_REFS: set[str] = {"main", "master", "develop", "trunk", "head"}


def _is_pinned(ref: str) -> bool:
    if "#" not in ref:
        return False
    suffix = ref.rsplit("#", 1)[1]
    if not suffix:
        return False
    if suffix.lower() in _BRANCH_REFS:
        return False
    if _EXACT_SEMVER_RE.search(ref):
        return True
    if _SHA_RE.search(ref):
        return True
    return False


def check(path: str, doc: dict[str, Any]) -> Finding:
    from ...base import Location
    unpinned: list[str] = []
    locations: list[Location] = []
    for idx, step in iter_command_steps(doc):
        for plugin_idx, (ref, _cfg) in enumerate(iter_plugins(step)):
            if not _is_pinned(ref):
                unpinned.append(f"{step_label(step, idx)}: {ref}")
                locations.append(plugin_location(path, step, plugin_idx))
    passed = not unpinned
    desc = (
        "Every plugin reference is pinned to an exact tag or SHA."
        if passed else
        f"{len(unpinned)} plugin reference(s) are not pinned: "
        f"{', '.join(unpinned[:5])}"
        f"{'…' if len(unpinned) > 5 else ''}. Floating refs let a "
        f"compromised plugin release execute in the pipeline."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
