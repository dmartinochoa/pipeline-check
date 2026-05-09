"""TAINT-003. Untrusted input forwarded into reusable workflow inputs.

The third TAINT rule. Reusable workflows are GitHub Actions'
canonical "function call" mechanism: a caller workflow declares
``jobs.<id>.uses: ./path/to/callee.yml`` (or a remote ref) and
forward ``with:`` parameters into the callee. The callee
consumes them via ``${{ inputs.<name> }}`` references in its
own ``run:`` / ``with:`` bodies.

The injection shape:

  caller.yml
    jobs:
      call:
        uses: ./.github/workflows/callee.yml
        with:
          title: ${{ github.event.issue.title }}   <- taint enters

  callee.yml
    on:
      workflow_call:
        inputs:
          title:
            type: string
    jobs:
      build:
        steps:
          - run: echo "${{ inputs.title }}"        <- taint exits

GHA-003 doesn't catch the caller side because the tainted
expression is in a ``with:`` block, not a ``run:`` body. The
callee's ``run:`` interpolation is technically GHA-003's
territory, but only when the callee is in the same scan as the
caller — and even then the caller-side surface (the
*forwarding* itself) is the more actionable triage point
because the operator who controls the caller is usually not
the operator who controls the callee.

TAINT-003 fires caller-side: any ``with:`` value forwarded
into a ``uses:`` reusable workflow that interpolates a
``${{ github.event.* }}`` source directly, OR forward a
tainted step output / cross-job ``needs.*`` value. The
description names the callee so the operator can audit the
matching ``inputs.<name>`` consumer in the callee body.

v1 limitations: caller-side detection only. Confirming the
callee actually consumes the input in a sink is the next
extension (requires loading the callee body, which the
``--resolve-remote`` resolver already does for remote
references but doesn't yet feed into the taint engine).
"""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from .._taint_graph import analyze_workflow

RULE = Rule(
    id="TAINT-003",
    title="Untrusted input forwarded into reusable workflow ``with:``",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4", "CICD-SEC-1"),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-78", "CWE-829"),
    recommendation=(
        "Sanitise the value at the caller before forwarding it "
        "across the reusable-workflow boundary. The canonical "
        "safe pattern is to copy the untrusted source into a "
        "step's ``env:`` block, run a sanitiser (``tr -dc "
        "'a-zA-Z0-9 '`` is enough for a freeform title), surface "
        "the sanitised result via ``echo \"name=$VAR\" >> "
        "$GITHUB_OUTPUT``, then forward "
        "``${{ steps.<id>.outputs.<name> }}`` as the ``with:`` "
        "input. The callee then sees a string-typed value with "
        "no expression-evaluation pass left to exploit. If the "
        "callee is under your control, also handle the input "
        "via env in the callee's ``run:`` body (not direct "
        "``${{ inputs.<name> }}`` interpolation)."
    ),
    docs_note=(
        "Detection is caller-side: walk every "
        "``jobs.<id>.uses: <callee>`` reference, find every "
        "``with:`` value that interpolates an attacker-"
        "controllable source (direct ``${{ github.event.* }}``, "
        "a tainted step output via ``${{ steps.<id>.outputs."
        "<name> }}``, or a cross-job ``${{ needs.<job>.outputs."
        "<name> }}``), and flag the forward.\n\n"
        "v1 doesn't load the callee body, so the rule can't "
        "tell whether the callee actually uses the input in a "
        "sink. Confirming end-to-end injection is the next "
        "engine extension; for now the caller-side surface is "
        "where the operator who controls the caller can fix "
        "the issue without coordinating with the callee's "
        "owner."
    ),
    known_fp=(
        "Callees that wrap the input safely (immediately copy "
        "into env, sanitise before use) make the caller-side "
        "forward harmless. The rule has no way to read the "
        "callee body for v1; suppress via ignore-file scoped "
        "to the caller workflow when the callee's handling is "
        "audited and sound.",
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    # TAINT-003 paths are emitted by pass-4 of the engine. The
    # discriminator is the hop format: ``jobs.<id>.with.<name>``
    # (with-prefix). Same-job step-output paths (TAINT-001) and
    # cross-job paths (TAINT-002) use different hop shapes.
    forward_paths = [
        p for p in analyze_workflow(doc)
        if any(h.startswith("jobs.") and ".with." in h for h in p.hops)
    ]
    if not forward_paths:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "No tainted ``with:`` forward into a reusable "
                "workflow detected."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    rendered = [p.render() for p in forward_paths]
    desc = (
        f"{len(forward_paths)} reusable-workflow forward(s) carry "
        f"untrusted data into a callee's ``inputs:``: "
        f"{'; '.join(rendered[:3])}"
        f"{'...' if len(rendered) > 3 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=False,
    )
