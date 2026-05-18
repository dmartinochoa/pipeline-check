"""BK-003. Attacker-controllable env vars interpolated into commands."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_command_steps, step_commands, step_label

RULE = Rule(
    id="BK-003",
    title="Untrusted Buildkite variable interpolated in command",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-CODE-INTEGRITY",),
    cwe=("CWE-78",),
    recommendation=(
        "Don't interpolate ``$BUILDKITE_BRANCH``, ``$BUILDKITE_TAG``, "
        "``$BUILDKITE_MESSAGE``, ``$BUILDKITE_PULL_REQUEST_*``, or "
        "``$BUILDKITE_BUILD_AUTHOR*`` directly into shell commands. "
        "These come from the pull request / branch and are "
        "attacker-controllable. Quote them and assign to a local "
        "variable first (``branch=\"$BUILDKITE_BRANCH\"; ./script "
        "--branch \"$branch\"``), or pass them as arguments to a "
        "script you own."
    ),
    docs_note=(
        "Buildkite passes branch / tag / message metadata as "
        "environment variables. Putting them inside ``$(...)`` or "
        "shelling out with the value unquoted is a classic command-"
        "injection vector. The detection fires on the unquoted "
        "interpolation form and on use inside ``eval`` / ``$(...)``."
    ),
    known_fp=(
        "The single-token double-quoted form "
        "(``\"$BUILDKITE_BRANCH\"``) is already excluded; "
        "multi-token shell snippets that *look* unquoted but are "
        "consumed safely by the downstream tool (e.g. a "
        "``./script.sh $BUILDKITE_BRANCH`` where the script "
        "treats argv as data and never re-evaluates) still flag. "
        "The rule has no AST-level understanding of the called "
        "script, suppress per-step via ``--ignore-file`` once "
        "you've verified the script handles untrusted argv "
        "safely (or quote the use, which is the better fix).",
    ),
)

# Buildkite-managed variables that are attacker-controllable through a
# pull request, branch name, commit message, or author identity.
_TAINTED_VARS = (
    "BUILDKITE_BRANCH",
    "BUILDKITE_TAG",
    "BUILDKITE_MESSAGE",
    "BUILDKITE_PULL_REQUEST",
    "BUILDKITE_PULL_REQUEST_BASE_BRANCH",
    "BUILDKITE_PULL_REQUEST_DEFAULT_BRANCH",
    "BUILDKITE_PULL_REQUEST_REPO",
    "BUILDKITE_BUILD_AUTHOR",
    "BUILDKITE_BUILD_AUTHOR_EMAIL",
    "BUILDKITE_COMMIT",
)

# Match ``$VAR`` or ``${VAR}`` (but not ``\$VAR`` or ``"$VAR"`` when
# already quoted. Buildkite pipeline.yml is parsed before the shell,
# so the YAML value is what gets handed to the agent). The trailing
# negative lookahead prevents matching tainted names that are merely
# a prefix of a longer identifier (e.g. ``$BUILDKITE_BRANCH_FOO``).
_INTERP_RE = re.compile(
    r"(?<!\\)\$\{?(" + "|".join(_TAINTED_VARS) + r")\}?(?![A-Za-z0-9_])"
)


def _command_unsafe(cmd: str) -> list[str]:
    """Return tainted variable names interpolated unsafely in *cmd*."""
    hits: list[str] = []
    for m in _INTERP_RE.finditer(cmd):
        var = m.group(1)
        # Quoted single-token use ("$VAR" or '$VAR') with matching
        # quotes around the interpolation is the safe form.
        start = m.start()
        end = m.end()
        before = cmd[max(0, start - 1):start]
        after = cmd[end:end + 1]
        if before in ('"', "'") and after.startswith(before):
            continue
        hits.append(var)
    return hits


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    # Preserve insertion order without duplicates so the reachability-
    # aware AC-026 chain sees every step containing an injection sink.
    anchor_steps: dict[str, None] = {}
    for idx, step in iter_command_steps(doc):
        for cmd in step_commands(step):
            hits = _command_unsafe(cmd)
            if hits:
                # Deduplicate per-step so a 50-line script that uses
                # $BUILDKITE_BRANCH 8 times reads as one offender.
                uniq = sorted(set(hits))
                label = step_label(step, idx)
                offenders.append(f"{label}: {', '.join(uniq[:3])}")
                anchor_steps[label] = None
                break
    passed = not offenders
    desc = (
        "No tainted Buildkite variables interpolated unsafely."
        if passed else
        f"{len(offenders)} step(s) interpolate attacker-controllable "
        f"Buildkite variables in commands: {'; '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Branch / tag / message "
        f"come from the PR; use them only inside double-quoted "
        f"single-token expansions or pass them as script arguments."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        # Buildkite pipelines are a flat list of steps rather than
        # named jobs; we anchor on step labels (``key`` > ``label`` >
        # ``steps[N]``). The reachability-aware AC-026 chain
        # intersects these with BK-007's ungated-deploy step set.
        job_anchors=tuple(anchor_steps),
    )
