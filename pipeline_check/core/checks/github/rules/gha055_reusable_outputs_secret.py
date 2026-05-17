"""GHA-055. Reusable-workflow ``outputs:`` derives from a secret."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="GHA-055",
    title="Reusable workflow outputs derive a secret or caller-input value",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-200", "CWE-532"),
    recommendation=(
        "Remove every ``${{ secrets.* }}`` and "
        "``${{ inputs.* }}`` reference from the "
        "``on.workflow_call.outputs.<name>.value:`` field. A "
        "reusable workflow's outputs are visible to the caller "
        "as ordinary job outputs (``needs.<job>.outputs.*``), "
        "which means: the secret value gets written into the "
        "caller's build log when the caller references the "
        "output, it gets persisted to the workflow run's "
        "summary, and any cross-job ``needs`` chain in the "
        "caller propagates it further. GitHub's secret-"
        "masking layer only redacts the value in the "
        "*defining* workflow's logs; once the value crosses "
        "the workflow boundary via ``outputs:``, the masking "
        "doesn't follow. The ``inputs.*`` route is the "
        "indirect form: a caller wires ``with: x: "
        "${{ secrets.X }}`` into one of the reusable "
        "workflow's inputs, and re-emitting that input as an "
        "output crosses the same boundary with the same "
        "loss-of-masking outcome.\n\n"
        "If the caller genuinely needs information derived "
        "from a secret (e.g., a build artifact name "
        "incorporating a tenant id), derive the non-secret "
        "transform on the callee side first (``echo \"name=$"
        "(echo \\$SECRET | sha256sum | cut -d' ' -f1)\" >> "
        "$GITHUB_OUTPUT``) and emit only the transformed value. "
        "The reusable workflow's outputs should never contain "
        "raw secret bytes or caller-controlled input bytes."
    ),
    docs_note=(
        "Scans ``on.workflow_call.outputs.<name>.value:`` for "
        "``${{ secrets.* }}`` references (and also the "
        "``${{ inputs.* }}`` shape when the caller can pass "
        "secrets through). Skips workflows that don't declare "
        "``on.workflow_call`` — only reusable workflows have "
        "outputs that propagate across the workflow boundary.\n\n"
        "Complements GHA-019 (token-to-file persistence) and "
        "GHA-033 (secret echoed in ``run:``) — both catch a "
        "secret leaking via the *log* surface. GHA-055 closes "
        "the third surface: the workflow boundary itself, "
        "where a reusable workflow's outputs cross into the "
        "caller's context without masking."
    ),
    known_fp=(
        "A reusable workflow that emits a *hash* of a secret "
        "(``sha256(secret)``) as an output is not the same "
        "risk shape — the original secret is not recoverable. "
        "The rule errs on the side of flagging any direct "
        "``${{ secrets.* }}`` / ``${{ inputs.* }}`` substring "
        "in the output value; suppress when the value is "
        "provably a one-way transform.",
    ),
)


def _extract_refs(value: str, prefix: str) -> list[str]:
    """Pull ``<prefix><name>`` tokens (e.g. ``secrets.X``,
    ``inputs.Y``) out of an expression string. Returns each unique
    reference in source order."""
    out: list[str] = []
    idx = 0
    while idx < len(value):
        mark = value.find(prefix, idx)
        if mark < 0:
            break
        end = mark + len(prefix)
        while end < len(value) and (
            value[end].isalnum() or value[end] in "_-"
        ):
            end += 1
        ref = value[mark:end]
        if ref not in out and end > mark + len(prefix):
            out.append(ref)
        idx = end
    return out


def _scan_output_value(value: Any) -> list[str]:
    """Return the list of attacker-controllable / secret-carrying
    expression tokens in *value*. Covers two leak shapes:

    * ``${{ secrets.<name> }}`` — direct secret reference.
    * ``${{ inputs.<name> }}`` — caller-supplied input. GitHub's
      reusable-workflow docs explicitly warn against passing secret
      values through ``with:``, but the API permits it, and a
      caller that does so will see the value re-emitted via
      ``outputs.<name>.value`` without secret masking applied.
    """
    if not isinstance(value, str):
        return []
    if "${{" not in value:
        return []
    hits: list[str] = []
    if "secrets." in value:
        hits.extend(_extract_refs(value, "secrets."))
    if "inputs." in value:
        hits.extend(_extract_refs(value, "inputs."))
    return hits


def _get_on_block(doc: dict[str, Any]) -> Any:
    """Return the ``on:`` block, handling YAML 1.1's ``on`` → ``True``
    quirk: PyYAML's safe_load parses ``on: ...`` with ``True`` as the
    key. The rule looks under both shapes so workflow files load
    correctly regardless of how the loader normalized the key."""
    if "on" in doc:
        return doc["on"]
    # YAML 1.1 maps the bare ``on`` keyword to the boolean ``True``;
    # PyYAML's safe_load preserves that. The dict signature here is
    # ``str -> Any`` but the loader's untyped result can carry the
    # literal ``True`` key. Cast via ``Any`` so the lookup is
    # type-safe regardless of which shape the loader chose.
    untyped: Any = doc
    return untyped.get(True)


def check(path: str, doc: dict[str, Any]) -> Finding:
    on = _get_on_block(doc)
    if not isinstance(on, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "Workflow does not declare ``on.workflow_call``; "
                "no reusable-workflow outputs to evaluate."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    workflow_call = on.get("workflow_call")
    if not isinstance(workflow_call, dict):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "Workflow is not a reusable workflow; no "
                "``workflow_call`` outputs to evaluate."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    outputs = workflow_call.get("outputs")
    if not isinstance(outputs, dict) or not outputs:
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description=(
                "Reusable workflow declares no outputs; nothing "
                "crosses the workflow boundary."
            ),
            recommendation=RULE.recommendation, passed=True,
        )
    offenders: list[str] = []
    for out_name, out_body in outputs.items():
        if not isinstance(out_body, dict):
            continue
        value = out_body.get("value")
        hits = _scan_output_value(value)
        if not hits:
            continue
        offenders.append(f"outputs.{out_name}: {', '.join(hits[:3])}")
    passed = not offenders
    desc = (
        "No reusable-workflow output references a secret or "
        "caller-supplied input."
        if passed else
        f"{len(offenders)} reusable-workflow output(s) re-emit "
        f"a secret / input across the workflow boundary: "
        f"{', '.join(offenders[:3])}"
        f"{'…' if len(offenders) > 3 else ''}. The caller sees "
        f"the value as an ordinary ``needs.<job>.outputs.*`` "
        f"entry which appears in the caller's build log when "
        f"referenced. ``secrets.*`` references are direct leaks; "
        f"``inputs.*`` references leak whatever the caller passes "
        f"through ``with:`` (including secrets the caller wired "
        f"in against GitHub's guidance)."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
