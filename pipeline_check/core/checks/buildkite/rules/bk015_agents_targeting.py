"""BK-015. ``agents:`` map interpolates an attacker-controllable Buildkite variable."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_command_steps, step_label

RULE = Rule(
    id="BK-015",
    title="agents map interpolates attacker-controllable Buildkite variable",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7", "CICD-SEC-1"),
    esf=("ESF-D-CODE-INTEGRITY", "ESF-S-RUNNER-ISOLATION"),
    cwe=("CWE-78", "CWE-1357"),
    recommendation=(
        "Pin every ``agents:`` map entry to a static literal that "
        "matches your runner targeting policy. ``queue: linux-amd64`` "
        "or ``os: linux`` is fine; ``queue: $BUILDKITE_BRANCH`` is "
        "not, because the pusher can route their build to whichever "
        "agent pool they want, including a privileged pool reserved "
        "for the deploy step. Production runner pools should also "
        "carry a tag the agent itself enforces (e.g. "
        "``buildkite-agent start --tags 'queue=production'`` plus a "
        "queue-allow-list on the API token), so the rule is one "
        "layer of a defense-in-depth posture."
    ),
    docs_note=(
        "Buildkite uses an ``agents:`` map to route a step to a "
        "specific runner pool. Both the top-level ``agents:`` and "
        "the per-step override are scanned. Detection mirrors "
        "BK-003's tainted-variable list (``$BUILDKITE_BRANCH``, "
        "``$BUILDKITE_TAG``, ``$BUILDKITE_MESSAGE``, "
        "``$BUILDKITE_PULL_REQUEST_*``, ``$BUILDKITE_BUILD_AUTHOR*``, "
        "``$BUILDKITE_COMMIT``). The pattern matches what GHA-036, "
        "GL-032, JF-032, ADO-030, and CC-031 already enforce on the "
        "other CI providers; closes parity for Buildkite.\n\n"
        "Quote-state aware in the same way BK-003 is. ``\"$BUILDKITE_"
        "BRANCH\"`` doesn't fire (Buildkite doesn't shell-eval the "
        "agents map anyway, but the value still substitutes), only "
        "the unquoted single-token interpolation does."
    ),
    known_fp=(
        "Some teams use a static prefix plus a CI-controlled tail "
        "(``queue: build-$BUILDKITE_PIPELINE_SLUG``) to share an "
        "agent pool across pipelines. ``BUILDKITE_PIPELINE_SLUG`` "
        "is not pusher-controllable so it isn't on the tainted "
        "list, but if your team has its own conventions for "
        "trusted Buildkite vars, suppress on the specific step.",
    ),
)


# Same tainted set BK-003 uses; intentionally duplicated here so the
# two rules can evolve independently if a Buildkite release adds new
# pusher-controllable variables.
_TAINTED_VARS = (
    "BUILDKITE_BRANCH",
    "BUILDKITE_TAG",
    "BUILDKITE_MESSAGE",
    "BUILDKITE_BUILD_MESSAGE",
    "BUILDKITE_PULL_REQUEST",
    "BUILDKITE_PULL_REQUEST_BASE_BRANCH",
    "BUILDKITE_PULL_REQUEST_DEFAULT_BRANCH",
    "BUILDKITE_PULL_REQUEST_REPO",
    "BUILDKITE_BUILD_AUTHOR",
    "BUILDKITE_BUILD_AUTHOR_EMAIL",
    "BUILDKITE_COMMIT",
)

_INTERP_RE = re.compile(
    r"(?<!\\)\$\{?(" + "|".join(_TAINTED_VARS) + r")\}?(?![A-Za-z0-9_])"
)


def _scan_value(value: Any) -> list[str]:
    """Return tainted variable names interpolated unsafely in *value*.

    The Buildkite ``agents:`` map is a flat ``key: scalar`` shape,
    occasionally a list of ``"key=value"`` strings; both forms get
    flattened to a string before scanning.
    """
    hits: list[str] = []
    if isinstance(value, str):
        hits.extend(m.group(1) for m in _INTERP_RE.finditer(value))
    elif isinstance(value, dict):
        for v in value.values():
            hits.extend(_scan_value(v))
    elif isinstance(value, list):
        for item in value:
            hits.extend(_scan_value(item))
    return hits


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    top = doc.get("agents")
    if top is not None:
        for var in sorted(set(_scan_value(top))):
            offenders.append(f"pipeline.agents: {var}")
    for idx, step in iter_command_steps(doc):
        agents = step.get("agents")
        if agents is None:
            continue
        hits = sorted(set(_scan_value(agents)))
        if hits:
            offenders.append(
                f"{step_label(step, idx)}.agents: {', '.join(hits[:3])}"
            )
    passed = not offenders
    desc = (
        "No ``agents:`` map entry interpolates a tainted Buildkite "
        "variable."
        if passed else
        f"{len(offenders)} ``agents:`` map(s) interpolate "
        f"attacker-controllable Buildkite variables: "
        f"{'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The pusher controls "
        f"which runner pool the build lands on."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
