"""GCB-004 — ``dynamicSubstitutions: true`` with user-controllable substitution.

Cloud Build substitutes ``$PROJECT_ID`` / ``$COMMIT_SHA`` /
``$_USER_VAR`` tokens in step ``args`` at build time. When
``options.dynamicSubstitutions`` is ``true``, Cloud Build re-evaluates
``bash``-style substitutions inside string values *after* variable
expansion, enabling sequences like ``$${FOO/bar/$_USER_VAR}``. If a
user-supplied substitution (``_*`` prefix, overridable from a build
trigger's settings or from ``gcloud builds submit --substitutions=``)
is interpolated into a step's ``args`` or ``entrypoint``, an attacker
controlling the trigger configuration can inject shell syntax or
command arguments — the Cloud Build analogue of GHA's
``${{ github.event.* }}`` script-injection pattern.

Rule fires when:

1. ``options.dynamicSubstitutions: true`` is set **and**
2. Any step ``args`` / ``entrypoint`` contains a ``$_USER_VAR``-style
   substitution token (leading underscore is the Cloud Build naming
   convention for user-provided substitutions).
"""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_steps, step_name, step_strings

RULE = Rule(
    id="GCB-004",
    title="dynamicSubstitutions on with user substitutions in step args",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-S-INPUT-VAL",),
    cwe=("CWE-78", "CWE-77"),
    recommendation=(
        "Either disable ``options.dynamicSubstitutions`` (it defaults "
        "to false) or move user substitutions (``$_FOO``) out of "
        "step ``args`` — pass them through ``env:`` and reference "
        "them inside a shell script the builder runs. Dynamic "
        "substitution re-evaluates bash syntax after variable "
        "expansion, giving trigger-config editors a script-"
        "injection channel."
    ),
    docs_note=(
        "The ``_``-prefix is Cloud Build's naming convention for "
        "user substitutions; they are editable via build trigger "
        "UI, ``gcloud builds submit --substitutions``, and the REST "
        "API. Built-in substitutions (``$PROJECT_ID``, "
        "``$COMMIT_SHA``, ``$BUILD_ID``) are derived from the "
        "trigger event and are *not* treated as user-controlled by "
        "this rule."
    ),
)

# ``$_FOO`` or ``${_FOO}`` — the leading underscore distinguishes user
# substitutions from Cloud Build built-ins (``$PROJECT_ID``, etc.).
_USER_SUB_RE = re.compile(r"\$\{?_[A-Z][A-Z0-9_]*\}?")


def _dynamic_subs_enabled(doc: dict[str, Any]) -> bool:
    options = doc.get("options")
    if not isinstance(options, dict):
        return False
    return options.get("dynamicSubstitutions") is True


def _steps_using_user_subs(doc: dict[str, Any]) -> list[str]:
    offenders: list[str] = []
    for idx, step in iter_steps(doc):
        for blob in step_strings(step):
            m = _USER_SUB_RE.search(blob)
            if m:
                offenders.append(f"{step_name(step, idx)}: {m.group(0)}")
                break
    return offenders


def check(path: str, doc: dict[str, Any]) -> Finding:
    if not _dynamic_subs_enabled(doc):
        return Finding(
            check_id=RULE.id, title=RULE.title, severity=RULE.severity,
            resource=path,
            description="options.dynamicSubstitutions is unset or false.",
            recommendation=RULE.recommendation, passed=True,
        )
    offenders = _steps_using_user_subs(doc)
    passed = not offenders
    desc = (
        "dynamicSubstitutions is on, but no step args contain a "
        "user-substitution (``$_`` prefix) token."
        if passed else
        f"dynamicSubstitutions is on and {len(offenders)} step(s) "
        f"interpolate a user substitution into args/entrypoint: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A trigger editor can "
        f"inject bash syntax through those tokens."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
