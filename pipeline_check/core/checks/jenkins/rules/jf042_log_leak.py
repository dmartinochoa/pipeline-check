"""JF-042. Secret-named / bound variable echoed to the build log."""
from __future__ import annotations

import re

from ..._primitives.log_leak import scan_script_for_leaked_secrets
from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import Jenkinsfile
from ._helpers import SHELL_STEP_RE

RULE = Rule(
    id="JF-042",
    title="Secret-named variable echoed / printed in a build step",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-532", "CWE-200"),
    recommendation=(
        "Don't print secret values in build steps. Jenkins masks "
        "credentials bound with ``withCredentials`` in the console, but "
        "only the exact bound string. Encoded, truncated, or derived forms "
        "bypass the mask, and ``set -x`` / ``env`` / ``printenv`` dump the "
        "raw value before masking can catch it. Log a boolean instead "
        "(``[ -n \"$TOKEN\" ] && echo set || echo unset``), and avoid "
        "``set -x`` while a credential variable is in scope."
    ),
    docs_note=(
        "Scans every ``sh`` / ``bat`` / ``powershell`` step body for a "
        "credential variable handed to ``echo`` / ``printf`` / ``cat`` / "
        "``tee``, for an ``env`` / ``printenv`` dump, and for ``set -x`` "
        "with a secret-named variable in scope (the shared ``log_leak`` "
        "detector, with GHA-033 / GL-036 / BB-032 / ADO-031 / CC-032). The "
        "credential set is the union of name-pattern matches (PASSWORD / "
        "TOKEN / SECRET / API_KEY / CREDENTIAL) and the variable names "
        "bound by ``withCredentials([... variable: 'X'])`` anywhere in the "
        "Jenkinsfile, so a non-obviously-named bound credential "
        "(``variable: 'GH'``) is still caught when it is echoed. The "
        "Jenkins analog of GL-036 / CC-032."
    ),
    exploit_example=(
        "// Vulnerable: the bound credential is echoed to the console.\n"
        "withCredentials([string(credentialsId: 'prod', variable: 'TOKEN')]) {\n"
        "  sh 'echo \"deploying with $TOKEN\"'\n"
        "}\n"
        "\n"
        "// Safe: log only whether it is set.\n"
        "withCredentials([string(credentialsId: 'prod', variable: 'TOKEN')]) {\n"
        "  sh '[ -n \"$TOKEN\" ] && echo token-set || echo token-missing'\n"
        "}\n"
    ),
)

# ``withCredentials([... variable: 'NAME' ...])`` binds NAME to a secret;
# such names are treated as known credentials even when the name itself
# does not match the secret-name heuristic.
_BOUND_VAR_RE = re.compile(r"variable\s*:\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]")


def check(jf: Jenkinsfile) -> Finding:
    text = jf.text_no_comments
    bound = frozenset(_BOUND_VAR_RE.findall(text))
    offenders: list[str] = []
    locations: list[Location] = []
    for m in SHELL_STEP_RE.finditer(text):
        body = (
            m.group("triple_d") or m.group("triple_s")
            or m.group("dq") or m.group("sq") or ""
        )
        hits = scan_script_for_leaked_secrets(body, known_secret_names=bound)
        if hits:
            line_no = text[: m.start()].count("\n") + 1
            for h in hits:
                offenders.append(f"line {line_no}: {h}")
            locations.append(Location(
                path=jf.path, start_line=line_no, end_line=line_no,
            ))
    passed = not offenders
    desc = (
        "No build step prints a secret-named or bound credential variable "
        "to the log."
        if passed else
        f"{len(offenders)} build-step log leak(s) detected: "
        f"{'; '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
