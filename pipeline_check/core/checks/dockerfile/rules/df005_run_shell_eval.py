"""DF-005 — ``RUN`` body uses dangerous shell-eval idioms."""
from __future__ import annotations

from ..._primitives import shell_eval
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import Dockerfile, run_bodies

RULE = Rule(
    id="DF-005",
    title="RUN uses shell-eval (eval / sh -c on a variable / backticks)",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-78",),
    recommendation=(
        "Replace ``eval \"$X\"`` and ``sh -c \"$X\"`` with explicit "
        "argv invocations. If the build genuinely needs a templated "
        "command, render it through a sealed config file or use "
        "``RUN --mount=type=secret`` with explicit input. ``$( … )`` / "
        "backticks should never wrap interpolated user-controlled vars "
        "inside a Dockerfile."
    ),
    docs_note=(
        "Reuses ``_primitives/shell_eval.scan`` — same primitive used "
        "by GHA-028 / GL-026 / BB-026 / ADO-027 / CC-027 / JF-030 so "
        "the safe / unsafe vocabulary matches across the tool."
    ),
)


def check(df: Dockerfile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for line_no, body in run_bodies(df):
        line_offenders = 0
        for hit in shell_eval.scan(body):
            offenders.append(f"L{line_no}: {hit.kind}")
            line_offenders += 1
        if line_offenders:
            locations.append(Location(
                path=df.path, start_line=line_no, end_line=line_no,
            ))
    passed = not offenders
    desc = (
        "No ``RUN`` body uses dangerous shell-eval idioms."
        if passed else
        f"{len(offenders)} ``RUN`` body / bodies use eval / sh -c on a "
        f"variable / unquoted backtick / cmdsub-with-var: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
