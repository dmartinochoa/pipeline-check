"""BB-005 — every step must declare a bounded `max-time`."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_steps

RULE = Rule(
    id="BB-005",
    title="Step has no `max-time` — unbounded build",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-BUILD-TIMEOUT",),
    recommendation=(
        "Add `max-time: <minutes>` to each step, sized to the 95th "
        "percentile of historical runtime plus margin. Bounded runs "
        "limit the blast radius of a compromised build and prevent "
        "runaway minute consumption."
    ),
    docs_note=(
        "Without `max-time`, the step runs until Bitbucket's 120-"
        "minute global default kills it. Explicit per-step timeouts "
        "cap blast radius and cost."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    unbounded = [loc for loc, step in iter_steps(doc) if "max-time" not in step]
    passed = not unbounded
    desc = (
        "Every step declares a `max-time`."
        if passed else
        f"{len(unbounded)} step(s) have no `max-time` and will run "
        f"until Bitbucket's 120-minute default kills them: "
        f"{', '.join(unbounded[:5])}{'…' if len(unbounded) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
