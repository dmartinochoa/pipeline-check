"""GL-030 — ``trigger: include:`` pulls child pipelines from unpinned sources.

GL-005 audits top-level ``include:``; GL-030 extends the same
pin/no-remote semantics to the ``trigger: include:`` form nested
inside a job. Parent-child and multi-project pipelines triggered this
way execute attacker-controllable YAML inside the same GitLab project
context, so unpinned refs to other projects are just as dangerous as
unpinned top-level includes.
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs

RULE = Rule(
    id="GL-030",
    title="trigger: include: pulls child pipeline without pinned ref",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-3",),
    esf=("ESF-S-PIN-DEPS", "ESF-S-TRUSTED-REG"),
    cwe=("CWE-829",),
    recommendation=(
        "Pin ``trigger: include: project:`` entries with ``ref:`` set "
        "to a tag or commit SHA. Avoid ``trigger: include: remote:`` "
        "for untrusted URLs; mirror the content into a trusted "
        "project and pin it there."
    ),
    docs_note=(
        "GL-005 only audits top-level ``include:``. Parent-child and "
        "multi-project pipelines that load YAML via the job-level "
        "``trigger: include:`` slot slip through. Branch refs "
        "(``main``/``master``/``develop``/``head``) count as unpinned."
    ),
)

_FLOATING_REFS = {"main", "master", "develop", "head"}


def _inspect_include(includes: Any, where: str, offenders: list[str]) -> None:
    """Apply the GL-005 pin rules to a ``trigger: include:`` value."""
    if includes is None:
        return
    items = includes if isinstance(includes, list) else [includes]
    for entry in items:
        if isinstance(entry, str):
            # String form is always treated as a project-local include —
            # a remote URL under that key is written as a dict with
            # ``remote:``. A bare string that's actually an HTTP URL is
            # malformed GitLab and we flag it for good measure.
            if entry.startswith(("http://", "https://")):
                offenders.append(f"{where}: remote {entry}")
            continue
        if not isinstance(entry, dict):
            continue
        if "project" in entry:
            ref = entry.get("ref")
            if not ref:
                offenders.append(f"{where}: project {entry.get('project')} (no ref)")
            elif isinstance(ref, str) and ref.lower() in _FLOATING_REFS:
                offenders.append(f"{where}: project {entry.get('project')} @{ref}")
        if "remote" in entry:
            offenders.append(f"{where}: remote {entry.get('remote')}")


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    saw_trigger_include = False
    for name, job in iter_jobs(doc):
        trigger = job.get("trigger")
        if not isinstance(trigger, dict):
            continue
        includes = trigger.get("include")
        if includes is None:
            continue
        saw_trigger_include = True
        _inspect_include(includes, name, offenders)
    if not saw_trigger_include:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="No job declares ``trigger: include:``.",
            recommendation="No action required.", passed=True,
        )
    passed = not offenders
    desc = (
        "Every ``trigger: include:`` references a pinned source."
        if passed else
        f"{len(offenders)} child-pipeline include(s) pull from an "
        f"upstream project or remote URL without a pinned ref: "
        f"{', '.join(offenders[:5])}{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
