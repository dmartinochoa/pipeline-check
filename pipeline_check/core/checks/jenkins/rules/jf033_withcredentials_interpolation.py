"""JF-033, ``withCredentials`` binding interpolated into a ``sh`` body via Groovy ``${VAR}``."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import Jenkinsfile, _skip_string

RULE = Rule(
    id="JF-033",
    title="withCredentials secret leaked via Groovy ${...} interpolation in sh step",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-6",),
    esf=("ESF-D-SECRETS",),
    cwe=("CWE-532",),
    recommendation=(
        "Inside a ``withCredentials([...])`` block, reference each "
        "bound variable through the shell (single-quoted Groovy "
        "string), not through Groovy interpolation. Write "
        "``sh 'curl -H \"Authorization: Bearer $TOKEN\" ...'`` instead "
        "of ``sh \"curl -H 'Authorization: Bearer ${TOKEN}' ...\"``. "
        "The single-quoted form keeps Jenkins' secret-masking layer in "
        "the loop, the double-quoted Groovy form bakes the literal "
        "value into the command string before the masker ever sees it, "
        "so ``set -x`` (Jenkins' default for ``sh``) prints the "
        "credential to the build log."
    ),
    docs_note=(
        "``withCredentials([string(credentialsId: 'X', variable: "
        "'TOKEN')])`` exposes the secret as a shell environment "
        "variable for the duration of the block. The rule fires when a "
        "``sh`` / ``bat`` / ``powershell`` step inside that block uses "
        "a Groovy interpolation (``${TOKEN}`` or ``$TOKEN`` in a "
        "double-quoted / triple-double-quoted string) to reference the "
        "binding. Groovy substitutes the literal value before handing "
        "the resulting string to the shell, so Jenkins' secret-masking "
        "wrapper, which only sees the shell-level ``$TOKEN`` token, "
        "cannot redact the value in trace output. Single-quoted bodies "
        "(``sh '... $TOKEN'``) leave the variable for the shell to "
        "resolve at run time, which is the safe pattern."
    ),
    known_fp=(
        "Bindings whose variable name doesn't look credential-ish "
        "(e.g. ``variable: 'COUNT'``) are still flagged: any value "
        "bound through ``withCredentials`` is a credential by "
        "definition.",
    ),
)


_WITH_CREDS_HEAD_RE = re.compile(r"\bwithCredentials\s*\(")
_VARIABLE_FIELD_RE = re.compile(r"\bvariable\s*:\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]")
# Both passwordVariable / usernameVariable for usernamePassword bindings.
_PASSWORD_VAR_RE = re.compile(
    r"\b(?:passwordVariable|usernameVariable)\s*:\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]"
)
_SH_HEAD_RE = re.compile(
    r"\b(?:sh|bat|powershell|pwsh)\s*\(?\s*"
    r"(?:script\s*:\s*)?"
    r"(?P<quote>\"\"\"|\"|''')"
)


def _withcreds_blocks(text: str) -> list[tuple[int, str]]:
    """Return ``(absolute_start, body)`` for every ``withCredentials(...)`` arg list.

    Walks Groovy parens/braces depth-aware so the argument span ends
    at the matching closer of the ``withCredentials(`` head — the body
    we want is the *outer* call's trailing closure, captured here as
    the slice from the opening ``(`` through to the matching ``})``.
    String literals are skipped via ``_skip_string`` so braces inside
    quoted text don't desync the depth count.
    """
    out: list[tuple[int, str]] = []
    for head in _WITH_CREDS_HEAD_RE.finditer(text):
        i = head.end()
        paren_depth = 1
        brace_depth = 0
        start = i
        while i < len(text) and paren_depth > 0:
            ch = text[i]
            if ch in ('"', "'"):
                i = _skip_string(text, i) + 1
                continue
            if ch == "(":
                paren_depth += 1
            elif ch == ")":
                paren_depth -= 1
                if paren_depth == 0:
                    # ``withCredentials([...]) { ... }`` — after the ``)``
                    # there's a closure block we still need to capture.
                    j = i + 1
                    while j < len(text) and text[j] in " \t\r\n":
                        j += 1
                    if j < len(text) and text[j] == "{":
                        brace_depth = 1
                        i = j + 1
                        while i < len(text) and brace_depth > 0:
                            ch2 = text[i]
                            if ch2 in ('"', "'"):
                                i = _skip_string(text, i) + 1
                                continue
                            if ch2 == "{":
                                brace_depth += 1
                            elif ch2 == "}":
                                brace_depth -= 1
                            i += 1
                    break
            elif ch == "{":
                brace_depth += 1
            elif ch == "}":
                brace_depth -= 1
            i += 1
        out.append((start, text[start:i]))
    return out


def _interpolates_var(body: str, var_name: str) -> bool:
    """True if *body* (a Groovy double-quoted string body) references
    ``${var_name}`` or ``$var_name`` as an interpolation."""
    pat = re.compile(
        r"\$\{?\s*" + re.escape(var_name) + r"\b\s*\}?"
    )
    return bool(pat.search(body))


def check(jf: Jenkinsfile) -> Finding:
    text = jf.text_no_comments or jf.text
    offenders: list[str] = []
    locations: list[Location] = []
    for start, body in _withcreds_blocks(text):
        bound: set[str] = set()
        bound.update(_VARIABLE_FIELD_RE.findall(body))
        bound.update(_PASSWORD_VAR_RE.findall(body))
        if not bound:
            continue
        for sh in _SH_HEAD_RE.finditer(body):
            quote = sh.group("quote")
            # Single-quoted bodies are safe (Groovy doesn't interpolate
            # them). Triple-single-quoted bodies are likewise safe.
            if quote in ("'", "'''"):
                continue
            close = body.find(quote, sh.end())
            if close == -1:
                continue
            arg_body = body[sh.end():close]
            for var in bound:
                if _interpolates_var(arg_body, var):
                    abs_line = text[: start + sh.start()].count("\n") + 1
                    offenders.append(f"L{abs_line}: ${var}")
                    locations.append(Location(
                        path=jf.path, start_line=abs_line, end_line=abs_line,
                    ))
                    break
    passed = not offenders
    desc = (
        "No withCredentials binding is interpolated into a shell step "
        "via Groovy ${...}."
        if passed else
        f"{len(offenders)} shell step(s) interpolate a credential "
        f"binding through Groovy ${{...}}: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. The literal value "
        f"reaches the command string before Jenkins' masker, so "
        f"``set -x`` prints the secret to the build log."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
