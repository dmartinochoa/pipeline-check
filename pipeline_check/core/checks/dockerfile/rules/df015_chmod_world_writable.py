"""DF-015 — ``RUN`` grants world-writable / world-executable permissions."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Dockerfile, run_bodies

RULE = Rule(
    id="DF-015",
    title="RUN grants world-writable permissions (chmod 777 / a+w)",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-732",),
    recommendation=(
        "Replace ``chmod 777 <path>`` with the narrowest permissions "
        "the workload actually needs. ``chmod 755`` is enough for "
        "executables under a read-only root filesystem; ``640`` "
        "or ``600`` for files the runtime user reads. ``a+w`` is "
        "almost always copy-pasted from a SO answer and almost "
        "never the correct fix."
    ),
    docs_note=(
        "World-writable directories under ``/`` are an established "
        "container-escape vector: any compromised process running as "
        "non-root can drop a payload that root-owned daemons later "
        "execute. The rule fires on the literal ``777``, ``a+w``, "
        "and ``a+rwx`` modes; the more conservative ``775`` and "
        "``ugo+x`` are not flagged."
    ),
    known_fp=(
        "Test fixtures or scratch builds that intentionally share a "
        "directory across multiple non-root users may legitimately "
        "use ``777``. Suppress with an ignore-file entry rather than "
        "weakening the rule.",
    ),
)


# Match ``chmod`` followed by a world-writable mode. Octal forms:
# 777, 0777. Symbolic: ``a+w``, ``a+rwx``, ``+w`` (which is shorthand
# for ``a+w``). Anchored to a word boundary so the false-positive of
# ``--chmod=755`` in ``COPY`` (different directive entirely) doesn't
# matter — ``run_bodies`` only feeds RUN args to the regex.
_CHMOD_WORLDWRITE_RE = re.compile(
    r"\bchmod\b[^\n]*?"
    r"(?:"
    r"\s0?777\b"               # octal 777 / 0777
    r"|\sa\+(?:w|rwx)\b"       # symbolic all+write
    r"|\s\+w(?:rx)?\b"         # bare +w (shorthand for a+w)
    r"|\sugo\+w\b"             # alternate spelling for a+w
    r")",
)


def check(df: Dockerfile) -> Finding:
    offenders: list[str] = []
    for line_no, body in run_bodies(df):
        m = _CHMOD_WORLDWRITE_RE.search(body)
        if m:
            offenders.append(f"L{line_no}: {m.group(0).strip()}")
    passed = not offenders
    desc = (
        "No ``RUN`` body grants world-writable permissions."
        if passed else
        f"{len(offenders)} ``RUN`` directive(s) grant world-writable "
        f"permissions: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
