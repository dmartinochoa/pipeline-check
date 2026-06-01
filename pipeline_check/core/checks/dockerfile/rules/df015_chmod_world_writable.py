"""DF-015, ``RUN`` grants world-writable / world-executable permissions."""
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
        "execute. The rule fires on octal ``777`` / ``0777`` and on "
        "any ``chmod`` ``+`` operator whose who-set is empty or "
        "contains ``a`` / ``o`` and whose mode flags include ``w`` "
        "(so ``a+w``, ``a+wx``, ``a+rwx``, ``o+w``, ``ugo+w``, "
        "``go+rw``, ``+w``, ``+rwx`` all flag). ``u+w`` and ``g+w`` "
        "are not flagged, neither grants the world-writable bit."
    ),
    known_fp=(
        "Test fixtures or scratch builds that intentionally share a "
        "directory across multiple non-root users may legitimately "
        "use ``777``. Suppress with an ignore-file entry rather than "
        "weakening the rule.",
    ),
    exploit_example=(
        "# Vulnerable: a build makes an executables directory\n"
        "# world-writable, usually copy-pasted to clear a\n"
        "# permission-denied error.\n"
        "RUN chmod -R 777 /usr/local/bin\n"
        "\n"
        "# Attack: 777 sets the world-writable bit, so any\n"
        "# process in the container, including one dropped to a\n"
        "# non-root user, can overwrite files under\n"
        "# /usr/local/bin. A runtime RCE replaces a trusted\n"
        "# binary there (the `node` / `python` / healthcheck the\n"
        "# image already runs); the next root-owned entrypoint or\n"
        "# cron step executes it and the attacker has root in the\n"
        "# container.\n"
        "USER node\n"
        "\n"
        "# Safe: grant the narrowest mode the workload needs. 755\n"
        "# keeps the directory traversable and the binaries\n"
        "# executable without making them writable by non-owners.\n"
        "RUN chmod -R 755 /usr/local/bin"
    ),
)


# Match ``chmod`` followed by a world-writable mode. Octal forms:
# 777, 0777. Symbolic: any ``+`` operator whose ``who`` set is empty
# (bare ``+w`` shorthand) or includes ``a`` (all) / ``o`` (others), and
# whose mode flags include ``w``. So ``a+w``, ``a+rwx``, ``a+wx``,
# ``o+w``, ``ugo+w``, ``go+rw``, ``+w``, ``+rwx`` all match; ``u+w``
# and ``g+w`` (which don't grant the world-writable bit) do not.
# Anchored to a word boundary so the false-positive of
# ``--chmod=755`` in ``COPY`` (different directive entirely) doesn't
# matter, ``run_bodies`` only feeds RUN args to the regex.
_CHMOD_WORLDWRITE_RE = re.compile(
    r"\bchmod\b[^\n]*?"
    r"(?:"
    r"\s0?777\b"                                             # octal 777
    r"|\s(?:[ug]*[ao][ugoa]*)?\+[rwxXst]*w[rwxXst]*\b"       # symbolic +w
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
