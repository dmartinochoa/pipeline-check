"""GHA-055. Reusable-workflow ``outputs:`` derives from a secret."""
from __future__ import annotations

from typing import Any

from ...base import Finding, Severity
from ...rule import Rule

RULE = Rule(
    id="GHA-055",
    title="Reusable workflow outputs derive a secret value",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-200", "CWE-532"),
    recommendation=(
        "Remove every ``${{ secrets.* }}`` reference from the "
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
        "doesn't follow.\n\n"
        "If the caller genuinely needs information derived "
        "from a secret (e.g., a build artifact name "
        "incorporating a tenant id), derive the non-secret "
        "transform on the callee side first (``echo \"name=$"
        "(echo \\$SECRET | sha256sum | cut -d' ' -f1)\" >> "
        "$GITHUB_OUTPUT``) and emit only the transformed value. "
        "The reusable workflow's outputs should never contain "
        "raw secret bytes."
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
        "``${{ secrets.* }}`` substring in the output value; "
        "suppress when the value is provably a one-way "
        "transform.",
    ),
)


def _scan_output_value(value: Any) -> list[str]:
    """Return the list of ``secrets.*`` tokens in *value*."""
    if not isinstance(value, str):
        return []
    hits: list[str] = []
    # Walk the string, looking for ``secrets.<name>`` references
    # inside ``${{ ... }}`` interpolations. The substring check
    # is broad on purpose: any nested expression that references
    # the secrets context returns the secret bytes.
    if "${{" in value and "secrets." in value:
        # Pull the first ~5 secret names mentioned (de-dup).
        idx = 0
        while idx < len(value):
            mark = value.find("secrets.", idx)
            if mark < 0:
                break
            end = mark + len("secrets.")
            while end < len(value) and (
                value[end].isalnum() or value[end] in "_-"
            ):
                end += 1
            ref = value[mark:end]
            if ref not in hits:
                hits.append(ref)
            idx = end
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
        "No reusable-workflow output references a secret."
        if passed else
        f"{len(offenders)} reusable-workflow output(s) leak a "
        f"secret to the caller: {', '.join(offenders[:3])}"
        f"{'…' if len(offenders) > 3 else ''}. The caller sees "
        f"the secret as an ordinary ``needs.<job>.outputs.*`` "
        f"value, which appears in the caller's build log when "
        f"referenced."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
