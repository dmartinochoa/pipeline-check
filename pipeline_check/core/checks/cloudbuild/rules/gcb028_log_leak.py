"""GCB-028. Secret-named variable echoed to the build log."""
from __future__ import annotations

from typing import Any

from ..._primitives.log_leak import scan_script_for_leaked_secrets
from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_steps

RULE = Rule(
    id="GCB-028",
    title="Secret-named variable echoed / printed in a build step",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-532", "CWE-200"),
    recommendation=(
        "Don't print secret values in build steps. A value pulled from "
        "Secret Manager into ``secretEnv`` is plaintext in the step's "
        "environment, and ``echo`` / ``set -x`` / ``env`` / ``printenv`` "
        "write it straight to the Cloud Build log, which anyone with "
        "``cloudbuild.builds.get`` (or read on the log bucket) can see. "
        "Log a boolean instead (``[ -n \"$$TOKEN\" ] && echo set || echo "
        "unset``), and avoid ``set -x`` while a credential variable is in "
        "scope."
    ),
    docs_note=(
        "Scans every step's ``entrypoint`` + ``args`` for a secret-named "
        "variable handed to ``echo`` / ``printf`` / ``cat`` / ``tee``, for "
        "an ``env`` / ``printenv`` dump, and for ``set -x`` with a "
        "secret-named variable in scope (the shared ``log_leak`` detector, "
        "with GHA-033 / GL-036 / BB-032 / ADO-031 / CC-032 / JF-042 / "
        "HARNESS-013 / BK-017 / DR-018). Variable names matching common "
        "secret patterns (PASSWORD / TOKEN / SECRET / API_KEY / CREDENTIAL) "
        "trigger the rule (the ``$$VAR`` Cloud Build escaping is matched "
        "alongside ``$VAR``). The Cloud Build analog of GL-036 / CC-032."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for idx, step in iter_steps(doc):
        # Scan each string part on its own: the shell script is a single
        # ``args`` element (``bash -c '<script>'``), so joining the parts
        # would push it off the line start where the detector anchors.
        parts: list[str] = []
        entrypoint = step.get("entrypoint")
        if isinstance(entrypoint, str):
            parts.append(entrypoint)
        args = step.get("args")
        if isinstance(args, list):
            parts += [a for a in args if isinstance(a, str)]
        elif isinstance(args, str):
            parts.append(args)
        script = step.get("script")
        if isinstance(script, str):
            parts.append(script)
        for part in parts:
            # Cloud Build escapes a literal ``$`` as ``$$``; normalize so
            # the shared shell-var detector sees ``$VAR``.
            for h in scan_script_for_leaked_secrets(part.replace("$$", "$")):
                offenders.append(f"step[{idx}]: {h}")
    passed = not offenders
    desc = (
        "No build step prints a secret-named variable to the log."
        if passed else
        f"{len(offenders)} build-step log leak(s) detected: "
        f"{'; '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
