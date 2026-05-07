"""GHA-036 — job ``runs-on:`` interpolates an attacker-controllable expression."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs
from ._helpers import UNTRUSTED_CONTEXT_RE

RULE = Rule(
    id="GHA-036",
    title="runs-on interpolates untrusted context",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"),
    cwe=("CWE-345",),
    recommendation=(
        "Hard-code ``runs-on:`` to a specific runner label or list of "
        "labels. If the choice has to be parameterised across callers, "
        "validate the input against an allowlist of known-good labels "
        "before the job runs (a small ``if:`` guard at job level), "
        "and never accept ``${{ inputs.* }}`` or any ``${{ github.event.* "
        "}}`` field as the ``runs-on`` value directly."
    ),
    docs_note=(
        "GHA-012 catches self-hosted runners that aren't ephemeral; "
        "this rule catches the upstream targeting choice. When "
        "``runs-on`` is computed from an untrusted expression, the "
        "caller picks where the workflow runs — including any "
        "self-hosted label the org owns. A reusable workflow that "
        "declares ``runs-on: ${{ inputs.runner }}`` lets a downstream "
        "caller route the job onto the production-deploy fleet (or "
        "any other privileged label) and execute arbitrary code with "
        "the privileges that fleet inherits. The same surface exists "
        "via ``workflow_dispatch`` inputs and any ``${{ github.event.* "
        "}}`` field that an attacker can populate. The rule walks "
        "all three ``runs-on`` shapes — string scalar, list of labels, "
        "and the long-form ``{ group, labels }`` dict — and matches "
        "the same untrusted-context regex GHA-003 / GHA-035 use."
    ),
    known_fp=(
        "Workflows that intentionally select runners by environment "
        "via a vetted matrix (``runs-on: ${{ matrix.os }}`` where "
        "``matrix.os`` is a hard-coded list inside the workflow) are "
        "out of scope — the matrix values are author-controlled, not "
        "caller-controlled. The rule only matches the catalog of "
        "untrusted contexts (``inputs.*``, ``github.event.*``, "
        "``github.head_ref``, …); ``matrix.*`` and ``env.*`` "
        "references are intentionally not flagged.",
    ),
)


def _runs_on_strings(runs_on: Any) -> list[str]:
    """Return every string value contributing to *runs_on*.

    Handles the three shapes GitHub Actions accepts:

    * scalar — ``runs-on: ubuntu-latest``
    * list — ``runs-on: [self-hosted, linux, x64]``
    * mapping — ``runs-on: { group: prod, labels: [a, b] }``

    Non-string entries (a malformed workflow with an int label) are
    skipped silently — the YAML loader already accepted them, so the
    surface for injection is what matters here, not the schema.
    """
    out: list[str] = []
    if isinstance(runs_on, str):
        out.append(runs_on)
    elif isinstance(runs_on, list):
        for item in runs_on:
            if isinstance(item, str):
                out.append(item)
    elif isinstance(runs_on, dict):
        group = runs_on.get("group")
        if isinstance(group, str):
            out.append(group)
        labels = runs_on.get("labels")
        if isinstance(labels, str):
            out.append(labels)
        elif isinstance(labels, list):
            for item in labels:
                if isinstance(item, str):
                    out.append(item)
    return out


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        for value in _runs_on_strings(job.get("runs-on")):
            if UNTRUSTED_CONTEXT_RE.search(value):
                offenders.append(job_id)
                break
    passed = not offenders
    desc = (
        "No job's ``runs-on:`` interpolates untrusted context."
        if passed else
        f"{len(offenders)} job(s) compute ``runs-on:`` from "
        f"attacker-controllable context: "
        f"{', '.join(sorted(set(offenders))[:5])}"
        f"{'…' if len(set(offenders)) > 5 else ''}. "
        f"A caller (or PR sender, depending on trigger) can route "
        f"the workflow onto any runner label the org exposes — "
        f"including privileged self-hosted fleets."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
