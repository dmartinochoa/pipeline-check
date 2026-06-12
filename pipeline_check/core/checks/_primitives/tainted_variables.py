"""Cross-provider taint-tracking for the script-injection rules.

Every CI provider ships an `*-002` / `*-003` rule that says "do not let
attacker-controlled SCM metadata reach a shell body unquoted." The
provider differences are entirely in the *vocabulary*:

- which env-var / variable shapes are SCM-controlled
  (``CI_COMMIT_MESSAGE`` for GitLab, ``Build.SourceBranch`` for ADO,
  ``${{ github.event.* }}`` for GitHub, ``BITBUCKET_BRANCH`` for
  Bitbucket),
- which reference syntaxes the rule needs to recognize (``$VAR``,
  ``${VAR}``, ADO ``$(VAR)``, PowerShell ``$env:VAR``,
  GitHub ``${{ env.VAR }}``).

The *algorithm*, "scan script lines, treat double-quoted segments as
neutralized, treat ``VAR="...$X..."`` assignments as safe, otherwise
flag", is identical. This module owns that algorithm so every
provider rule collapses to a thin adapter passing in the right regex.

Why not also collapse the source-side taint extraction (variables /
env / variables-list / shell-export forms)? Each provider's variables
schema is genuinely different (GitLab's dict-wrapped values, ADO's
list-of-dict alternative, Bitbucket extracting taint from inline
``export`` statements). Forcing them into one signature loses
precision. Source extraction stays in the per-provider rule;
*reference detection* lives here.
"""
from __future__ import annotations

import functools
import re
from collections.abc import Callable, Iterable

from ..base import is_quoted_assignment

#: Strip every quoted segment from a line before re-checking for a
#: variable reference. Bash double-quotes prevent re-evaluation, so
#: ``cmd "$X"`` is safe even if ``$X`` carries shell metacharacters,
#: the value is treated as a single literal argument. Single-quotes are
#: stronger still, they suppress expansion entirely, so ``echo '$X'``
#: is a literal and never references ``$X`` at all. Both must be removed
#: before a surviving (unquoted) reference can be called unsafe;
#: stripping only double-quotes flagged the recommended single-quote
#: idiom as an injection. The double-quote alternative is tried first
#: so a literal ``'`` inside a double-quoted span (``"it's $X"``) is
#: consumed as part of that span, not treated as a single-quote opener.
_QUOTED_SEGMENT_RE = re.compile(r"\"[^\"]*\"|'[^']*'")


#: Compile-cache for per-name reference patterns. ``has_unsafe_reference``
#: is called per-step / per-job across 4-6 different injection-detection
#: rules in a single scan; without caching, each invocation
#: recompiles the same regex strings. The cache size is bounded so a
#: pathological scan with thousands of distinct variable names doesn't
#: balloon memory; the LRU eviction is fine because the inner-loop
#: hits are concentrated on the few names that actually carry taint.
@functools.lru_cache(maxsize=512)
def _compile_cached(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def has_direct_taint(
    lines: Iterable[str],
    untrusted_re: re.Pattern[str],
    *,
    paren_is_macro: bool = False,
) -> bool:
    """Return True if any *line* directly interpolates an untrusted-
    context expression and is not a defensively-quoted assignment.

    ``untrusted_re`` is the provider-specific catalog of attacker-
    controllable shapes. ``is_quoted_assignment`` is the cross-provider
    safe-idiom recogniser owned by ``checks.base``. ``paren_is_macro``
    is forwarded to it (set by Azure, where ``$(Name)`` is a pre-shell
    macro substitution, not a runtime command substitution).
    """
    for line in lines:
        if untrusted_re.search(line) and not is_quoted_assignment(
            line, paren_is_macro=paren_is_macro
        ):
            return True
    return False


def has_unsafe_reference(
    lines: Iterable[str],
    names: set[str],
    *,
    ref_pattern: Callable[[str], str],
    paren_is_macro: bool = False,
) -> bool:
    """Return True if any *line* references one of *names* unquoted.

    *ref_pattern* receives a tainted variable name and returns a regex
    string matching every reference syntax the provider's shell layer
    recognizes. The primitive owns the safety filter:

    1. Skip lines that match :func:`is_quoted_assignment` outright,
       a ``VAR="...$X..."`` capture is a safe idiom (the inner ``$X``
       is interpolated once into a string-typed variable, never
       re-executed).
    2. Strip every double-quoted segment from the remaining lines and
       re-run the reference regex. A surviving match is an *unquoted*
       reference and is unsafe.
    """
    for name in names:
        rx = _compile_cached(ref_pattern(name))
        for line in lines:
            if not rx.search(line):
                continue
            if is_quoted_assignment(line, paren_is_macro=paren_is_macro):
                continue
            stripped = _QUOTED_SEGMENT_RE.sub("", line)
            if rx.search(stripped):
                return True
    return False
