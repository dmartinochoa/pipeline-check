"""HARNESS-004. Literal credential in a pipeline / stage variable."""
from __future__ import annotations

from ..._secrets import find_secret_values
from ...base import Finding, Severity
from ...rule import Rule
from ..base import HarnessPipeline, iter_steps, iter_variables, step_spec

RULE = Rule(
    id="HARNESS-004",
    title="Literal credential in a pipeline / stage variable",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-6", "CICD-SEC-7"),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-798", "CWE-321"),
    recommendation=(
        "Move the credential into a Harness secret and reference it as an "
        "expression instead of a literal: declare the variable with "
        "``type: Secret`` and a value of "
        "``<+secrets.getValue(\"my_secret\")>`` (or store it in the "
        "built-in / a connected secret manager). Harness masks "
        "secret-expression values in logs but does not mask a literal "
        "pasted into a ``type: String`` variable, so the token ends up in "
        "the pipeline definition and the run logs indefinitely. Rotate any "
        "credential already committed this way."
    ),
    docs_note=(
        "Fires on a pipeline-level or stage-level ``variables:`` entry, or a "
        "step's ``spec.envVariables`` mapping value, that is a credential-"
        "shaped literal (matched by the shared secret-shape catalog, "
        "``find_secret_values``) rather than a ``<+secrets.getValue(...)>`` "
        "expression. ``type: Secret`` variables and any ``<+...>`` expression "
        "value are skipped (those are managed references, not literals); "
        "empty values are ignored. The value is redacted in the finding. "
        "Same value-shape model as the literal-secret rules across the other "
        "providers (DR-004 / BK-002 / TKN-005)."
    ),
    exploit_example=(
        "# Vulnerable: a real token pasted into a String variable. It lands\n"
        "# in the committed pipeline YAML and is not masked in run logs.\n"
        "pipeline:\n"
        "  identifier: build\n"
        "  variables:\n"
        "    - name: GH_TOKEN\n"
        "      type: String\n"
        "      value: ghp_0123456789abcdefghijklmnopqrstuvwxyz\n"
        "\n"
        "# Safe: a Secret-typed variable resolved from the secret manager.\n"
        "    - name: GH_TOKEN\n"
        "      type: Secret\n"
        "      value: <+secrets.getValue(\"gh_token\")>"
    ),
)


def _is_literal_secret(value: object) -> bool:
    """True when *value* is a credential-shaped literal, not an expression."""
    if not isinstance(value, str):
        return False
    v = value.strip()
    # ``<+...>`` is a Harness expression (a secret reference or other
    # managed value), never a pasted literal.
    if not v or v.startswith("<+"):
        return False
    return bool(find_secret_values([v]))


def check(pipeline: HarnessPipeline) -> Finding:
    offenders: list[str] = []
    for scope, var in iter_variables(pipeline):
        if str(var.get("type", "")).strip().lower() == "secret":
            continue
        if _is_literal_secret(var.get("value")):
            name = var.get("name")
            label = name.strip() if isinstance(name, str) and name.strip() else "?"
            offenders.append(f"{scope}.{label}")
    # Step-level ``spec.envVariables`` is the most common place a token
    # literal gets pasted; it's a mapping of ``{NAME: value}`` and was
    # not scanned by any harness rule.
    for stage_id, step in iter_steps(pipeline):
        env = step_spec(step).get("envVariables")
        if not isinstance(env, dict):
            continue
        step_ident = step.get("identifier")
        step_label = (
            step_ident.strip()
            if isinstance(step_ident, str) and step_ident.strip() else "step"
        )
        for name, value in env.items():
            if _is_literal_secret(value):
                offenders.append(f"{stage_id}.{step_label}.env.{name}")
    passed = not offenders
    desc = (
        "No pipeline / stage variable or step env value holds a literal "
        "credential."
        if passed else
        f"{len(offenders)} variable(s) hold a credential-shaped literal "
        f"instead of a secret reference: {'; '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}. Rotate and move to "
        f"<+secrets.getValue(...)>."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=pipeline.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
