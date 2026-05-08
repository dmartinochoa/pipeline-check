"""GCB-026 — Step's ``waitFor:`` references a step ``id:`` that doesn't exist."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_steps, step_location, step_name

RULE = Rule(
    id="GCB-026",
    title="Step waitFor: references an unknown step id",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-BUILD-ENV",),
    cwe=("CWE-684",),
    recommendation=(
        "Verify every ID listed in a step's ``waitFor:`` array matches "
        "an ``id:`` declared on a sibling step in the same build. The "
        "special token ``-`` (start at the beginning of the build, "
        "no dependencies) is the only non-id value Cloud Build "
        "accepts. A typo in ``waitFor:`` doesn't fail the build — "
        "Cloud Build silently skips the wait, so a step that was "
        "supposed to run *after* a setup step ends up running in "
        "parallel with it."
    ),
    docs_note=(
        "Cloud Build's step dependency graph is built from each "
        "step's ``waitFor:`` array. A step with no ``waitFor:`` "
        "runs after all previous steps; a step with "
        "``waitFor: ['-']`` runs at the start of the build; a "
        "step with ``waitFor: ['<id>']`` waits for the specific "
        "step. There's no validation that the referenced id "
        "exists — typo'd ids are silently treated like ``-`` "
        "(no-wait), so the dependency disappears without warning. "
        "This rule catches the silent-skip by walking every "
        "``waitFor:`` value and cross-referencing it against the "
        "set of declared step ids."
    ),
)


def _step_ids(doc: dict[str, Any]) -> set[str]:
    """Return every ``id:`` declared on a step, across all steps."""
    out: set[str] = set()
    for _, step in iter_steps(doc):
        sid = step.get("id")
        if isinstance(sid, str) and sid.strip():
            out.add(sid)
    return out


def check(path: str, doc: dict[str, Any]) -> Finding:
    ids = _step_ids(doc)
    offenders: list[str] = []
    locations: list[Location] = []
    for idx, step in iter_steps(doc):
        wait_for = step.get("waitFor")
        if not isinstance(wait_for, list):
            continue
        for ref in wait_for:
            if not isinstance(ref, str):
                continue
            ref = ref.strip()
            if ref == "-" or not ref:
                # Cloud Build's ``-`` sentinel = "no dependencies",
                # the start-of-build marker. Empty entries are
                # tolerated (Cloud Build ignores them).
                continue
            if ref not in ids:
                offenders.append(
                    f"step[{idx}] {step_name(step, idx)}: "
                    f"waitFor references unknown id ``{ref}``"
                )
                locations.append(step_location(path, step))
                # One Location per step is enough — multiple bad
                # ids in one step's waitFor list still cluster on
                # the step's source line.
                break
    passed = not offenders
    desc = (
        "Every ``waitFor:`` reference resolves to a declared step id."
        if passed else
        f"{len(offenders)} step(s) with dangling ``waitFor:`` "
        f"reference(s): {', '.join(offenders[:3])}"
        f"{'…' if len(offenders) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path,
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
