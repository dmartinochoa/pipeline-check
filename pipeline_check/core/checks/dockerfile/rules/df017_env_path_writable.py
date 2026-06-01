"""DF-017. ENV PATH prepends a world-writable directory."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Dockerfile, env_pairs

RULE = Rule(
    id="DF-017",
    title="ENV PATH prepends a world-writable directory",
    severity=Severity.MEDIUM,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-PRIV-BUILD",),
    cwe=("CWE-426",),
    recommendation=(
        "Don't put ``/tmp``, ``/var/tmp``, ``/dev/shm``, or any other "
        "world-writable path in ``PATH`` ahead of the system binary "
        "directories. Drop those entries entirely, or place them at "
        "the tail (``ENV PATH=/usr/bin:$PATH:/tmp``) so legitimate "
        "binaries always shadow anything dropped into the writable "
        "dir at runtime."
    ),
    docs_note=(
        "A writable PATH entry that comes before the system bins lets "
        "any process inside the container shadow ``ls``, ``ps``, "
        "``apt-get``, ``cat``, etc. by dropping a binary of the same "
        "name into the writable dir. On a multi-tenant image, or "
        "any image where an exploit can reach the filesystem, "
        "this is a free privilege-escalation vector."
    ),
    exploit_example=(
        "# Vulnerable: a world-writable directory sits ahead of\n"
        "# the system binaries on PATH.\n"
        "ENV PATH=\"/tmp/bin:${PATH}\"\n"
        "\n"
        "# Attack: /tmp is writable by every user in the image\n"
        "# and now resolves before /usr/bin, so a dropped file\n"
        "# shadows the real tool. A runtime RCE writes\n"
        "# /tmp/bin/apt-get (or psql, node, aws); the next bare\n"
        "# `apt-get` call, a later build step, the entrypoint, an\n"
        "# operator shelling in, runs the attacker's binary\n"
        "# instead of the system one.\n"
        "\n"
        "# Safe: keep writable dirs off PATH, or pin them after\n"
        "# the system bins so a real binary always shadows a\n"
        "# dropped one.\n"
        "ENV PATH=\"${PATH}:/tmp/bin\""
    ),
)

_WRITABLE_PREFIXES: tuple[str, ...] = (
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/run/lock",
)


def _path_offends(value: str) -> str | None:
    """Return the offending PATH entry if it precedes ``$PATH`` / ``${PATH}``.

    Only entries that come *before* the literal ``$PATH`` reference
    matter, appending writable dirs at the end of PATH is harmless
    because system bins still shadow them. We split on ``:`` and walk
    until we see the existing-PATH marker; entries seen so far that
    sit under a writable prefix are reported.
    """
    parts = value.split(":")
    for entry in parts:
        token = entry.strip()
        if token in ("$PATH", "${PATH}"):
            return None
        for prefix in _WRITABLE_PREFIXES:
            if token == prefix or token.startswith(prefix + "/"):
                return token
    # PATH set without referencing the prior PATH, same risk if the
    # writable prefix appears anywhere because the new value is
    # authoritative for every later directive.
    for entry in parts:
        token = entry.strip()
        for prefix in _WRITABLE_PREFIXES:
            if token == prefix or token.startswith(prefix + "/"):
                return token
    return None


def check(df: Dockerfile) -> Finding:
    offenders: list[str] = []
    for line_no, key, value in env_pairs(df):
        if key != "PATH":
            continue
        bad = _path_offends(value)
        if bad is not None:
            offenders.append(f"L{line_no}: PATH includes {bad}")
    passed = not offenders
    desc = (
        "No ``ENV PATH`` directive prepends a world-writable directory."
        if passed else
        f"{len(offenders)} ``ENV PATH`` directive(s) include a "
        f"world-writable entry: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
