"""DF-018. RUN ``chown -R`` rewrites ownership of a system path."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Dockerfile, run_bodies

RULE = Rule(
    id="DF-018",
    title="RUN chown rewrites ownership of a system path",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-732",),
    recommendation=(
        "Don't ``chown`` system directories at build time. If the "
        "runtime user needs to own a workload-specific subtree, "
        "``COPY --chown=<user>:<group>`` it into the image at the "
        "subtree root, or place the workload under a dedicated "
        "directory (e.g. ``/app``, ``/srv/app``) and ``chown`` only "
        "that path. Granting the runtime user write access to "
        "``/etc``, ``/usr``, ``/sbin``, or ``/lib`` lets a process "
        "exploit later steps to stage a binary the system trusts."
    ),
    docs_note=(
        "Recognizes ``chown`` and ``chgrp`` invocations whose first "
        "non-flag path argument resolves under a system directory. "
        "The non-recursive case is also flagged because a single "
        "``chown user /etc`` is just as harmful, the recursive "
        "flag matters for the size of the blast radius, not for "
        "whether it's wrong. Application paths under ``/opt``, "
        "``/srv``, ``/var/lib/<app>``, and ``/app`` are not flagged."
    ),
)

_SYSTEM_PREFIXES: tuple[str, ...] = (
    "/etc",
    "/usr",
    "/sbin",
    "/bin",
    "/lib",
    "/lib64",
    "/boot",
    "/root",
)

# Match ``chown`` or ``chgrp`` followed by optional flags, an
# owner-spec, and the first path argument. Owner-spec is a short
# token without spaces (``user``, ``user:group``, numeric ``1001``,
# ``1001:1001``). The path is captured as everything up to the next
# whitespace or end-of-line.
_CHOWN_RE = re.compile(
    r"\bch(?:own|grp)\b"
    r"(?:\s+-[A-Za-z]+)*"            # one or more short flag groups
    r"\s+(?P<owner>[^\s/][^\s]*)"    # owner spec (must not start with /)
    r"\s+(?P<path>/[^\s;&|]+)",      # absolute path
)


def _path_under_system(path: str) -> bool:
    for prefix in _SYSTEM_PREFIXES:
        if path == prefix or path.startswith(prefix + "/"):
            return True
    return False


def check(df: Dockerfile) -> Finding:
    offenders: list[str] = []
    for line_no, body in run_bodies(df):
        for m in _CHOWN_RE.finditer(body):
            path = m.group("path")
            if _path_under_system(path):
                offenders.append(f"L{line_no}: chown ... {path}")
    passed = not offenders
    desc = (
        "No ``RUN`` body chowns a system directory."
        if passed else
        f"{len(offenders)} ``RUN`` body / bodies rewrite ownership "
        f"of a system path: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
