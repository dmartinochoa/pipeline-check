"""Detect inherently dangerous shell idioms.

Complementary to the provider-specific script-injection rules
(GHA-003, GL-002, BB-002, ADO-002, CC-002, JF-002) which track
taint from known-attacker-controllable sources into ``run:`` /
``script:`` blocks. This primitive fires on idioms that are unsafe
regardless of where the variable's value comes from — if an
``eval`` or ``sh -c`` receives a variable expansion, the content of
that variable determines whether the shell invocation escapes the
current process. That decision belongs at the data boundary (input
validation) rather than deep inside the CI pipeline, so CI scanners
should flag the pattern category itself.

Idioms detected:

1. ``eval "$VAR"`` / ``eval $VAR`` / ``eval "${VAR}"`` — evaluates the
   *value* of ``$VAR`` as shell. CWE-95.
2. ``sh -c "$VAR"`` / ``bash -c "$VAR"`` — re-invokes the shell on a
   variable. Effectively the same risk as ``eval``.
3. Backtick exec referencing a variable: `` `$VAR` `` or
   `` `...$VAR...` ``. Command substitution over untrusted content.
4. ``$( $VAR ... )`` — command substitution where the *command* is a
   variable. Same shape as the backtick form but POSIX-preferred.

Known non-issues not flagged (false-positive management):

- ``eval "$(ssh-agent -s)"`` — the ``$(...)`` wraps a *command*
  whose output is then eval'd. The command itself is a literal
  ``ssh-agent``; the pattern is idiomatic for tooling-output
  bootstrapping. Detected separately with a stricter sub-rule that
  requires the outer command to be literal.
- ``"$@"`` / ``"$#"`` — positional parameter expansion. Safe.
- ``sh -c 'literal command'`` single-quoted literal — no variable
  interpolation, not a taint path.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# ── Pattern catalogue ────────────────────────────────────────────

# ``eval`` followed by any variable expansion (``$X``, ``${X}``,
# ``"$X"``, ``"${X}"``). Matches the variable form even if wrapped
# in double quotes — double quotes do not suppress expansion.
# Intentionally does NOT match ``eval "$(...)"`` with a literal
# command inside, which is a common-and-usually-safe idiom.
_EVAL_VAR_RE = re.compile(
    r"\beval\s+"
    r"(?:\"[^\"]*\$(?!\()[^\"]*\""           # "…$X…"  (excludes "$(")
    r"|'[^']*\$(?!\()[^']*'"                 # '…$X…' — even single-quoted, shell expands $ in eval
    r"|\$(?!\()\w+"                          # bare $X
    r"|\$\{\w+\})"                           # ${X}
)

# Bare ``eval "$(...)"`` where the substituted command itself
# contains a variable expansion — this is the risky form. A literal
# command like ``$(ssh-agent -s)`` is safe.
_EVAL_CMDSUB_VAR_RE = re.compile(
    r"\beval\s+\"\$\([^)]*\$(?!\()[^)]*\)\""
)

# ``sh -c "$X"`` / ``bash -c "$X"`` / ``sh -c $X`` — re-invoke shell
# on a variable. Same risk category as eval.
_SHELL_DASH_C_VAR_RE = re.compile(
    r"\b(?:ba)?sh\s+-c\s+"
    r"(?:\"[^\"]*\$(?!\()[^\"]*\""           # sh -c "…$X…"
    r"|\$(?!\()\w+"                          # sh -c $X
    r"|\$\{\w+\})"                           # sh -c ${X}
)

# Backtick command substitution containing a variable expansion.
# Backticks are deprecated but still appear in legacy scripts.
_BACKTICK_VAR_RE = re.compile(
    r"`[^`]*\$(?!\()\w+[^`]*`"
    r"|`[^`]*\$\{\w+\}[^`]*`"
)

# ``$( $VAR … )`` — command substitution where the *command itself*
# is a variable expansion. Distinct from ``$(command $ARG)`` where
# the command is literal; we match only when ``$`` immediately
# follows the opening paren (after optional whitespace).
_CMDSUB_BARE_VAR_RE = re.compile(
    r"\$\(\s*\$(?!\()\w+"
    r"|\$\(\s*\$\{\w+\}"
)


@dataclass(frozen=True)
class ShellEvalFinding:
    """A single risky-idiom hit with enough context to show in a finding."""

    kind: str    # "eval", "sh-c", "backtick", "cmdsub"
    snippet: str  # the matched shell fragment, trimmed


def scan(text: str) -> list[ShellEvalFinding]:
    """Return one entry per dangerous-idiom occurrence in *text*.

    *text* is the raw command blob — typically a ``run:`` body, a
    CircleCI ``command:`` value, or a Jenkinsfile's stripped
    ``sh '…'`` block. Callers concatenate multiple shell fragments
    before passing in; duplicate matches across fragments are
    preserved so that rule callers can cite counts meaningfully.
    """
    hits: list[ShellEvalFinding] = []
    # Track spans already reported so the two eval regexes don't
    # double-count the same occurrence (``eval "$(curl $URL)"``
    # matches both the cmdsub-var variant and the var-in-quotes
    # variant).
    seen_spans: set[tuple[int, int]] = set()

    for rex in (_EVAL_CMDSUB_VAR_RE, _EVAL_VAR_RE):
        for m in rex.finditer(text):
            if m.span() in seen_spans:
                continue
            # Suppress the generic eval-var match when it fully
            # overlaps a more specific cmdsub-var match.
            if any(s[0] <= m.start() and m.end() <= s[1] for s in seen_spans):
                continue
            seen_spans.add(m.span())
            hits.append(ShellEvalFinding("eval", _trim(m.group(0))))
    for m in _SHELL_DASH_C_VAR_RE.finditer(text):
        hits.append(ShellEvalFinding("sh-c", _trim(m.group(0))))
    for m in _BACKTICK_VAR_RE.finditer(text):
        hits.append(ShellEvalFinding("backtick", _trim(m.group(0))))
    for m in _CMDSUB_BARE_VAR_RE.finditer(text):
        hits.append(ShellEvalFinding("cmdsub", _trim(m.group(0))))
    return hits


def _trim(s: str, limit: int = 60) -> str:
    s = " ".join(s.split())
    return s if len(s) <= limit else s[: limit - 1] + "…"
