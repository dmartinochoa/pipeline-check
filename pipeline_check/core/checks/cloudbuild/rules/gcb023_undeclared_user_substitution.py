"""GCB-023. Step references a ``$_USER_VAR`` not declared in ``substitutions:``."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import iter_steps, step_location, step_name, step_strings

RULE = Rule(
    id="GCB-023",
    title="Step references a user substitution not declared in substitutions:",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-4",),
    esf=("ESF-S-INPUT-VAL",),
    cwe=("CWE-1188",),
    recommendation=(
        "Add an entry for every ``$_USER_VAR`` referenced anywhere "
        "in the build to the top-level ``substitutions:`` block, "
        "either with a sensible default or with an empty string if "
        "the trigger always supplies the value. Cloud Build's "
        "default ``options.substitutionOption: MUST_MATCH`` then "
        "fails the build at parse time on undeclared references "
        "(catching typos at the gate). With the looser "
        "``ALLOW_LOOSE`` opt-in (GCB-022) undeclared references "
        "silently expand to the empty string, which masks the bug "
        "and quietly broadens any shell command that interpolates "
        "the value."
    ),
    docs_note=(
        "Walks every step's ``args:`` / ``entrypoint:`` / ``env:`` "
        "/ ``dir:`` / ``id:`` / ``waitFor:`` for ``$_NAME`` tokens "
        "(Cloud Build's user-substitution syntax is leading "
        "underscore + uppercase / digits / underscore) and "
        "cross-references against the top-level ``substitutions:`` "
        "mapping. Built-in substitutions (``$PROJECT_ID``, "
        "``$REPO_NAME``, ``$BRANCH_NAME``, ``$TAG_NAME``, ``$COMMIT_SHA``, "
        "``$SHORT_SHA``, ``$REVISION_ID``, ``$BUILD_ID``, "
        "``$LOCATION``, ``$TRIGGER_NAME``, ``$_HEAD_*``, ``$_BASE_*``, "
        "``$_PR_NUMBER`` and the ``$_HEAD_REPO_URL`` family) are "
        "Cloud Build server-set and don't appear in ``substitutions:``; "
        "the rule allow-lists them so they don't false-positive."
    ),
    known_fp=(
        "Cloud Build deployments triggered exclusively via "
        "``gcloud builds submit --substitutions=_FOO=bar`` "
        "(without a build trigger) may legitimately reference "
        "``$_FOO`` without declaring it under ``substitutions:`` "
        "because the value is always supplied from the CLI. The "
        "scanner can't observe trigger / CLI configuration, only "
        "the YAML. Declaring the variable with an empty-string "
        "default is the canonical fix; ``--ignore-file`` is the "
        "escape hatch when that's not practical.",
    ),
)

#: Cloud Build user substitution shape: ``$_FOO`` or ``${_FOO}``.
#: User subs are leading underscore; built-in subs (``$PROJECT_ID``)
#: don't have the leading underscore, the rule scopes itself to
#: user-named subs only.
_USER_SUB_RE = re.compile(r"\$\{?(?P<name>_[A-Z0-9_]+)\}?")

#: Server-set built-ins that look user-shaped (leading underscore).
#: Cloud Build sets these from the trigger / source context; they
#: never appear in ``substitutions:`` because they're not
#: user-defined. Without this allowlist, every PR-triggered build
#: would false-positive on ``$_HEAD_BRANCH`` etc.
_BUILTIN_USER_SHAPED: frozenset[str] = frozenset({
    "_HEAD_REPO_URL", "_HEAD_BRANCH", "_HEAD_REPO_TYPE",
    "_HEAD_COMMIT_SHA", "_HEAD_SHORT_SHA",
    "_BASE_REPO_URL", "_BASE_BRANCH", "_BASE_REPO_TYPE",
    "_PR_NUMBER",
})


def _declared_user_subs(doc: dict[str, Any]) -> set[str]:
    subs = doc.get("substitutions")
    if not isinstance(subs, dict):
        return set()
    return {k for k in subs if isinstance(k, str) and k.startswith("_")}


def _referenced_user_subs(text: str) -> set[str]:
    return {m.group("name") for m in _USER_SUB_RE.finditer(text)}


def check(path: str, doc: dict[str, Any]) -> Finding:
    declared = _declared_user_subs(doc) | _BUILTIN_USER_SHAPED
    offenders: list[str] = []
    locations: list[Location] = []
    seen_per_step: set[tuple[str, str]] = set()
    for idx, step in iter_steps(doc):
        name = step_name(step, idx)
        for blob in step_strings(step):
            for ref in _referenced_user_subs(blob):
                if ref in declared:
                    continue
                key = (name, ref)
                if key in seen_per_step:
                    continue
                seen_per_step.add(key)
                offenders.append(f"step[{idx}] {name}: ${ref}")
                locations.append(step_location(path, step))
    passed = not offenders
    desc = (
        "Every user substitution referenced by a step is declared "
        "in ``substitutions:``."
        if passed else
        f"{len(offenders)} undeclared user substitution(s) "
        f"referenced: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path,
        description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
