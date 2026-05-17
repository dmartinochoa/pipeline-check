"""JF-034, ``password`` build parameter declared in ``parameters { ... }``."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import Jenkinsfile, _skip_string

RULE = Rule(
    id="JF-034",
    title="Pipeline declares a password() build parameter",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-256",),
    recommendation=(
        "Replace ``password(name: 'X')`` with a credential binding. "
        "Store the secret in Jenkins' Credentials Provider and pull "
        "it in with ``withCredentials([string(credentialsId: 'X', "
        "variable: 'X')])``. The bound variable integrates with "
        "Jenkins' log-masking, the credential definition is decoupled "
        "from build invocation (so operators don't retype the value "
        "on every trigger), and Job/Configure on the build no longer "
        "exposes the value through ``build.xml``."
    ),
    docs_note=(
        "Jenkins' ``password()`` parameter persists the supplied "
        "value into ``builds/<n>/build.xml`` as an encrypted "
        "``Secret``, the same encryption the Credentials Provider "
        "uses. The encryption is keyed off the controller's master "
        "key at ``$JENKINS_HOME/secrets/master.key``, so anyone who "
        "captures both the build XML and the master key (a "
        "filesystem backup, an admin running ``thinBackup``, a "
        "compromised agent that can read controller state) recovers "
        "every password every operator has ever submitted. The build's "
        "parameters page renders the value as ``********`` for "
        "Job/Read users, but Job/Configure (or higher) can recover "
        "the encrypted string from ``config.xml`` and decrypt it. "
        "The substantive operational gap vs ``withCredentials`` is "
        "log-masking: a ``sh \"deploy ${params.API_TOKEN}\"`` step "
        "leaks the value to the build log because the Credentials "
        "Binding plugin's masker is what intercepts that flow, and "
        "the masker only fires for ``withCredentials`` bindings, not "
        "for ``params.*`` references. ``password()`` should be "
        "treated as a deprecated anti-pattern."
    ),
    known_fp=(
        "A pipeline that intentionally uses ``password()`` for a "
        "non-secret value (e.g. a one-off prompt for a confirmation "
        "token) is still flagged, the parameter type itself is the "
        "anti-pattern. Suppress via ``.pipelinecheckignore`` with a "
        "rationale rather than disabling the rule.",
    ),
)


_PARAMETERS_HEAD_RE = re.compile(r"\bparameters\s*\{")
_PASSWORD_PARAM_RE = re.compile(
    r"\bpassword\s*\(\s*name\s*:\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]"
)


def _parameters_blocks(text: str) -> list[tuple[int, str]]:
    """Return ``(absolute_start_of_body, body)`` for every
    ``parameters { ... }`` block, with depth-aware string skipping."""
    out: list[tuple[int, str]] = []
    for head in _PARAMETERS_HEAD_RE.finditer(text):
        i = head.end()
        depth = 1
        start = i
        while i < len(text) and depth > 0:
            ch = text[i]
            if ch in ('"', "'"):
                i = _skip_string(text, i) + 1
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            i += 1
        body = text[start:i - 1] if depth == 0 else text[start:]
        out.append((start, body))
    return out


def check(jf: Jenkinsfile) -> Finding:
    text = jf.text_no_comments or jf.text
    offenders: list[str] = []
    locations: list[Location] = []
    for start, body in _parameters_blocks(text):
        for m in _PASSWORD_PARAM_RE.finditer(body):
            name = m.group(1)
            abs_line = text[: start + m.start()].count("\n") + 1
            offenders.append(f"L{abs_line}: password({name})")
            locations.append(Location(
                path=jf.path, start_line=abs_line, end_line=abs_line,
            ))
    passed = not offenders
    desc = (
        "No pipeline parameter is declared as password() type."
        if passed else
        f"{len(offenders)} password() build parameter(s) declared: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. ``params.<name>`` "
        f"references don't go through the credentials-binding "
        f"masker, so any sh step that interpolates the parameter "
        f"leaks it to the build log; use a Credentials Provider "
        f"binding instead."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
