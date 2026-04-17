"""JF-024 — ``input`` approval steps must restrict who can approve."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Jenkinsfile
from ._helpers import DEPLOY_RE, INPUT_STEP_RE, SUBMITTER_FIELD_RE

RULE = Rule(
    id="JF-024",
    title="`input` approval step missing submitter restriction",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-1",),
    esf=("ESF-C-APPROVAL",),
    cwe=("CWE-284",),
    recommendation=(
        "Add a ``submitter: 'releasers,sre'`` (or a single role) argument "
        "to every ``input`` step in a deploy-like stage. Without it, any "
        "user with the Jenkins job ``Build`` permission can approve a "
        "production promotion — the approval gate becomes advisory."
    ),
    docs_note=(
        "JF-005 already flags deploy stages with no ``input`` step. This "
        "rule catches the subtler case: the gate exists, but it doesn't "
        "actually restrict approvers. ``submitter`` accepts a "
        "comma-separated list of Jenkins usernames and group names; "
        "scope it to the smallest release-eligible pool."
    ),
)

# Identifies a ``;`` or newline *at the outer Groovy expression depth*
# — i.e. not inside a balanced ``()``/``{}`` block or a string. Used to
# terminate the region of a short-form ``input`` call like
# ``input message: 'foo', submitter: 'releasers'``.
_EXPR_TERMINATORS = {";", "\n"}


def _input_regions(body: str) -> list[str]:
    """Extract every ``input`` call's argument region from *body*.

    ``input`` supports four surface forms in Jenkinsfiles:
        input 'Proceed?'                              # positional string
        input message: 'foo', submitter: 'releasers'  # map-style, no parens
        input(message: 'foo', submitter: 'releasers') # parenthesized map
        input { message 'foo'; submitter 'releasers' }  # block form

    For each ``input`` keyword we scan forward:
      - if the first non-whitespace char after ``input`` is ``(`` or
        ``{``, capture until the matching closer (depth-aware);
      - otherwise (map-style no parens, or quoted short form), capture
        until a depth-0 newline or ``;``.
    Strings are skipped so punctuation inside them doesn't terminate
    the region early.
    """
    regions: list[str] = []
    for m in INPUT_STEP_RE.finditer(body):
        # Skip past whitespace after ``input``.
        i = m.end()
        while i < len(body) and body[i] in " \t":
            i += 1
        if i >= len(body):
            continue
        start = i
        first = body[i]
        if first in ("(", "{"):
            close = ")" if first == "(" else "}"
            depth = 1
            i += 1
            while i < len(body) and depth > 0:
                ch = body[i]
                if ch in ('"', "'"):
                    i = _skip_string(body, i) + 1
                    continue
                if ch == first:
                    depth += 1
                elif ch == close:
                    depth -= 1
                i += 1
            regions.append(body[start:i])
        else:
            # Map-style or positional form — ends at a depth-0 newline
            # or semicolon. Track paren depth for args like
            # ``input message: someCall(x)``.
            depth = 0
            while i < len(body):
                ch = body[i]
                if ch in ('"', "'"):
                    i = _skip_string(body, i) + 1
                    continue
                if ch in "({":
                    depth += 1
                elif ch in ")}":
                    if depth == 0:
                        break
                    depth -= 1
                elif depth == 0 and ch in _EXPR_TERMINATORS:
                    break
                i += 1
            regions.append(body[start:i])
    return regions


def _skip_string(text: str, pos: int) -> int:
    """Return index of the closing quote for a Groovy string at *pos*.

    Duplicates the small helper in ``jenkins/base.py`` to avoid a
    cross-module import cycle (base.py already imports from this
    package).
    """
    for triple in ('"""', "'''"):
        if text[pos:pos + 3] == triple:
            end = text.find(triple, pos + 3)
            return end + 2 if end != -1 else len(text) - 1
    quote = text[pos]
    j = pos + 1
    while j < len(text):
        if text[j] == "\\":
            j += 2
            continue
        if text[j] == quote:
            return j
        j += 1
    return len(text) - 1


def check(jf: Jenkinsfile) -> Finding:
    offenders: list[str] = []
    # Only consider deploy-like stages; an ``input`` in a dev-build
    # stage isn't a production gate and doesn't need a submitter.
    for name, body in jf.stages:
        if not DEPLOY_RE.search(name):
            continue
        regions = _input_regions(body)
        if not regions:
            # JF-005 already flags "no input at all" — don't double-fire.
            continue
        if not any(SUBMITTER_FIELD_RE.search(r) for r in regions):
            offenders.append(name)
    passed = not offenders
    desc = (
        "Every ``input`` step in a deploy-like stage pins a submitter."
        if passed else
        f"{len(offenders)} deploy-like stage(s) use ``input`` without a "
        f"submitter restriction: {', '.join(offenders)}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=jf.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
