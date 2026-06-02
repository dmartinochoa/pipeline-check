"""GCB-019. Shell entrypoint inlines a user substitution into args."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_steps, step_name

RULE = Rule(
    id="GCB-019",
    title="Shell entrypoint inlines a user substitution into args",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4",),
    esf=("ESF-S-INPUT-VAL", "ESF-D-INJECTION"),
    cwe=("CWE-78", "CWE-77"),
    recommendation=(
        "Pass user substitutions through ``env:`` (or ``secretEnv:`` "
        "for sensitive values) and reference them inside a checked-in "
        "shell script rather than splicing them directly into ``args``. "
        "If the step truly needs to invoke shell logic inline, switch "
        "the entrypoint to the underlying tool (``docker``, ``gcloud``, "
        "``gsutil``) and let the tool see the substitution as an "
        "argument, not as shell text."
    ),
    docs_note=(
        "Distinct from GCB-004, which fires only when "
        "``options.dynamicSubstitutions: true`` re-evaluates bash "
        "syntax after expansion. GCB-019 fires whenever a step uses "
        "a shell as its entrypoint AND a ``$_USER_VAR`` token lands "
        "inside ``args``: Cloud Build expands the substitution before "
        "the step runs, and the shell then interprets any metacharacters "
        "the substitution carried, straight command injection through "
        "trigger configuration."
    ),
    known_fp=(
        "Substitutions whose values are *server-controlled* in "
        "practice (e.g. the trigger always supplies a SHA from "
        "``$_HEAD_COMMIT_SHA`` aliased into a ``$_BUILD_TAG`` by "
        "the trigger config) still match the user-sub regex "
        "because Cloud Build can't distinguish locked from "
        "editable trigger fields. Suppress per-step via "
        "``--ignore-file`` once you've verified your trigger "
        "policy prevents arbitrary substitution overrides, "
        "ideally combined with ``options.substitutionOption: "
        "MUST_MATCH`` (GCB-022) to make the lock explicit.",
    ),
    exploit_example=(
        "# Vulnerable: ``entrypoint: bash`` plus a user substitution\n"
        "# inside ``args:`` means the substitution's content is\n"
        "# parsed by bash. A trigger substitution carrying shell\n"
        "# metacharacters (``v1.0\";rm -rf /;\"``) executes as\n"
        "# separate commands.\n"
        "steps:\n"
        "  - name: gcr.io/cloud-builders/bash@sha256:abc123...\n"
        "    entrypoint: bash\n"
        "    args:\n"
        "      - -c\n"
        "      - echo \"building ${_TAG}\" && ./build.sh --tag ${_TAG}\n"
        "\n"
        "# Safe: pass the substitution through an env var so the\n"
        "# shell sees one argument. Quote on every use. The shell\n"
        "# treats injected metacharacters as literal characters\n"
        "# in the env value.\n"
        "steps:\n"
        "  - name: gcr.io/cloud-builders/bash@sha256:abc123...\n"
        "    entrypoint: bash\n"
        "    env: ['TAG=${_TAG}']\n"
        "    args:\n"
        "      - -c\n"
        "      - echo \"building $TAG\" && ./build.sh --tag \"$TAG\""
    ),
)

_SHELL_ENTRYPOINTS = frozenset({
    "bash", "sh", "zsh", "ash", "dash", "ksh",
    "/bin/bash", "/bin/sh", "/bin/zsh", "/bin/ash", "/bin/dash",
    "/usr/bin/bash", "/usr/bin/sh", "/usr/bin/env",
})

_USER_SUB_RE = re.compile(r"\$\{?_[A-Z][A-Z0-9_]*\}?")


def _is_shell_entrypoint(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    return value.strip().lower() in _SHELL_ENTRYPOINTS


def _args_have_user_sub(step: dict[str, Any]) -> str | None:
    args = step.get("args")
    if not isinstance(args, list):
        return None
    for entry in args:
        if not isinstance(entry, str):
            continue
        m = _USER_SUB_RE.search(entry)
        if m:
            return m.group(0)
    return None


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for idx, step in iter_steps(doc):
        if not _is_shell_entrypoint(step.get("entrypoint")):
            continue
        token = _args_have_user_sub(step)
        if token is not None:
            offenders.append(f"{step_name(step, idx)}: {token}")
    passed = not offenders
    desc = (
        "No step combines a shell entrypoint with a user substitution in args."
        if passed else
        f"{len(offenders)} step(s) inline a user substitution into "
        f"shell-entrypoint args: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. A trigger editor can "
        f"inject command-line syntax through those tokens."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
