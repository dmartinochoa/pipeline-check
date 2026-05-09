"""DF-009, ``ADD <local-path>`` should be ``COPY``."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Dockerfile, iter_instructions

RULE = Rule(
    id="DF-009",
    title="ADD used where COPY would suffice",
    severity=Severity.LOW,
    owasp=(),
    cwe=("CWE-1357",),
    recommendation=(
        "Replace ``ADD ./local`` with ``COPY ./local``. ``ADD`` has "
        "two implicit behaviors that make it the wrong default. It "
        "fetches HTTP(S) URLs and it auto-extracts ``.tar`` / "
        "``.tar.gz`` archives. Both are easy to invoke accidentally "
        "and neither is reproducible. Reserve ``ADD`` for a deliberate "
        "URL-pull (covered by DF-003) or an explicit tarball extract."
    ),
    docs_note=(
        "Pure-local ``ADD <path> <dest>`` is functionally identical to "
        "``COPY``, but ships extra-feature surface (URL fetch, tarball "
        "auto-extract) that adds nothing and turns a benign-looking "
        "filename change into a behavior change. The Docker docs have "
        "recommended ``COPY`` for non-URL inputs since 2014."
    ),
)

_URL_RE = re.compile(r"\bhttps?://", re.IGNORECASE)
# Tarball auto-extract is the second ``ADD`` superpower; using ``ADD``
# *deliberately* to extract one is legitimate and we don't want to
# flag it. Match by extension on the source token.
_TARBALL_RE = re.compile(
    r"\.(?:tar|tgz|tbz2?|txz|tar\.(?:gz|bz2?|xz|zst))(?:\s|$)",
    re.IGNORECASE,
)


def _has_url_or_tarball(args: str) -> bool:
    if _URL_RE.search(args):
        return True
    # Skip any ``--checksum=`` flag tokens before checking for tarball
    # extension, the flag value itself can contain dots that would
    # confuse the suffix match.
    cleaned = re.sub(r"--\w+=\S+", "", args)
    return bool(_TARBALL_RE.search(cleaned))


def check(df: Dockerfile) -> Finding:
    offenders: list[str] = []
    for ins in iter_instructions(df, directive="ADD"):
        if _has_url_or_tarball(ins.args):
            continue
        offenders.append(f"L{ins.line_no}: ADD {ins.args[:50]}")
    passed = not offenders
    desc = (
        "No ``ADD`` directives that should be ``COPY``."
        if passed else
        f"{len(offenders)} ``ADD`` directive(s) reference local paths "
        f"and should be ``COPY``: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
