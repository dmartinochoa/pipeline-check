"""Shared detection for secrets leaked to CI build logs.

Reused by per-provider rules (GL-036, BB-032, ADO-031, CC-032) that
detect ``echo $SECRET_VAR``, ``printenv``, and ``set -x`` patterns.

GitHub Actions has its own implementation (GHA-033) because the
``${{ secrets.X }}`` syntax allows precise detection. Other CI
systems store secrets in the UI, so this module uses a name-based
heuristic: variable names matching common secret-name patterns
(PASSWORD, TOKEN, API_KEY, SECRET, CREDENTIAL, etc.) are treated
as likely secrets.
"""
from __future__ import annotations

import re

SECRET_VAR_NAME_RE = re.compile(
    r"(?:PASSWORD|PASSWD|PWD|SECRET|TOKEN|API[_\-]?KEY|ACCESS[_\-]?KEY|"
    r"SECRET[_\-]?KEY|PRIVATE[_\-]?KEY|CREDENTIAL|AUTH[_\-]?TOKEN)",
    re.IGNORECASE,
)

_PRINT_CMD_RE = re.compile(
    r"^(?:echo|printf|cat|tee|print)\b",
)

_ENV_DUMP_RE = re.compile(
    # ``printenv`` always dumps. Bare ``env`` (optionally with flags)
    # dumps only when it isn't running a command: ``env`` / ``env | grep``
    # / ``env > f`` are dumps, but ``env -i ./cmd`` and ``env VAR=x cmd``
    # run a program in a modified environment and dump nothing.
    r"(?:^|;|&&|\|\|)\s*"
    r"(?:printenv|/usr/bin/printenv|env\b(?:\s+-\S+)*\s*(?=$|[;&|<>]))",
    re.MULTILINE,
)

# ``set -x`` (and bundled forms like ``set -euxo``) ENABLE xtrace, which
# echoes every expanded command, secrets included, to the log. ``set +x``
# DISABLES it and is the standard idiom for muting trace right before a
# secret-handling line, so the leading sign must be ``-`` only. The
# long-form alternative already gets this right (``set +o xtrace`` does
# not match, only ``set -o xtrace`` does).
_SHELL_TRACE_RE = re.compile(
    r"(?:^|;|&&|\|\|)\s*set\s+"
    r"(?:-[a-zA-Z]*x[a-zA-Z]*\b|-o\s+xtrace\b)",
    re.MULTILINE,
)

_SHELL_VAR_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")

_ADO_VAR_RE = re.compile(r"\$\(([A-Za-z_][A-Za-z0-9_.]*)\)")


def _extract_printed_var_names(
    script: str,
    *,
    var_pattern: re.Pattern[str] = _SHELL_VAR_RE,
) -> list[str]:
    """Return variable names that appear as arguments to print commands."""
    hits: list[str] = []
    for raw_line in script.splitlines():
        for segment in re.split(r"(?:&&|\|\||;)", raw_line):
            seg = segment.strip()
            if not seg:
                continue
            if not _PRINT_CMD_RE.match(seg):
                continue
            for m in var_pattern.finditer(seg):
                # ``${VAR:+word}`` / ``${VAR:?word}`` print the alternate
                # word (or an error) and never the variable's value, so a
                # set-check of a secret is not a leak. ``:-`` / ``:=`` DO
                # print the value when set, so those still count. (Only
                # the POSIX brace form; the ADO ``$(VAR)`` regex never
                # starts with ``${``.)
                if (
                    seg[m.start():m.start() + 2] == "${"
                    and seg[m.end():m.end() + 2] in (":+", ":?")
                ):
                    continue
                hits.append(m.group(1))
    return hits


def scan_script_for_leaked_secrets(
    script: str,
    *,
    known_secret_names: frozenset[str] = frozenset(),
    ado_mode: bool = False,
) -> list[str]:
    """Return a list of short labels describing detected log-leak shapes.

    *known_secret_names* is a set of variable names known to hold
    secrets (e.g. from ``isSecret: true`` in Azure YAML, or
    ``protected: true`` in GitLab). When provided, these are checked
    in addition to the name-based heuristic.

    *ado_mode* switches variable reference parsing from ``$VAR`` /
    ``${VAR}`` (POSIX shell) to ``$(VAR)`` (Azure template syntax).
    """
    offenders: list[str] = []
    var_re = _ADO_VAR_RE if ado_mode else _SHELL_VAR_RE

    printed_names = _extract_printed_var_names(script, var_pattern=var_re)
    for name in printed_names:
        if name in known_secret_names:
            offenders.append(f"echo ${name} (known secret)")
        elif SECRET_VAR_NAME_RE.search(name):
            offenders.append(f"echo ${name}")

    if _ENV_DUMP_RE.search(script):
        offenders.append("env/printenv dumps all variables including secrets")

    if _SHELL_TRACE_RE.search(script):
        all_var_names = {m.group(1) for m in var_re.finditer(script)}
        leaked = {
            n for n in all_var_names
            if n in known_secret_names or SECRET_VAR_NAME_RE.search(n)
        }
        if leaked:
            sample = sorted(leaked)[:3]
            offenders.append(
                f"set -x with secret-named var(s): {', '.join(sample)}"
            )

    return offenders
