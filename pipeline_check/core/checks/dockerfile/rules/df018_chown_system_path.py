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
        "``/srv``, ``/var/lib/<app>``, and ``/app`` are not flagged, "
        "nor are the application source/data subtrees ``/usr/src`` "
        "(the ``node`` image's ``/usr/src/app`` WORKDIR) and "
        "``/usr/share`` (web/data roots); those hold no trusted "
        "binaries on ``PATH``."
    ),
    exploit_example=(
        "# Vulnerable: the build hands the runtime user ownership\n"
        "# of a system directory to clear a write error.\n"
        "RUN useradd app && chown -R app:app /usr/local\n"
        "\n"
        "# Attack: `app` now owns everything under /usr/local,\n"
        "# including /usr/local/bin. A process compromised as\n"
        "# `app` at runtime overwrites a trusted binary there\n"
        "# (the same `node` / `python` the entrypoint execs), so\n"
        "# the next launch runs attacker code, and any step that\n"
        "# runs as root executes it with full privilege.\n"
        "USER app\n"
        "\n"
        "# Safe: chown only the workload's own subtree and leave\n"
        "# system paths owned by root. COPY --chown lands files\n"
        "# already owned correctly without a recursive chown.\n"
        "RUN useradd app && mkdir /app && chown app:app /app\n"
        "COPY --chown=app:app . /app"
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

# Subtrees that live *under* a system prefix but hold application
# source / data rather than trusted binaries on ``PATH``. The canonical
# case is ``/usr/src/app`` (the WORKDIR the official ``node`` image
# documents) and ``/usr/share/<app>`` web/data roots; ``chown``-ing
# those to the runtime user is the normal, safe pattern. They are
# checked before ``_SYSTEM_PREFIXES`` so the executable/library dirs
# (``/usr/bin``, ``/usr/local/bin``, ``/usr/lib`` ...) still fire.
_APP_SUBTREE_PREFIXES: tuple[str, ...] = (
    "/usr/src",
    "/usr/share",
    "/usr/local/src",
    "/usr/local/share",
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


def _path_under(path: str, prefixes: tuple[str, ...]) -> bool:
    for prefix in prefixes:
        if path == prefix or path.startswith(prefix + "/"):
            return True
    return False


def _path_under_system(path: str) -> bool:
    if _path_under(path, _APP_SUBTREE_PREFIXES):
        # An application source/data subtree that merely sits under a
        # system prefix (``/usr/src/app``, ``/usr/share/nginx/html``).
        return False
    return _path_under(path, _SYSTEM_PREFIXES)


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
