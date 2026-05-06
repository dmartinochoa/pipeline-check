"""DF-014 — ``WORKDIR`` set to a kernel- or system-critical path."""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Dockerfile, iter_instructions

RULE = Rule(
    id="DF-014",
    title="WORKDIR set to a system / kernel filesystem path",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-732",),
    recommendation=(
        "Move ``WORKDIR`` to a dedicated app directory (``/app``, "
        "``/srv/app``, ``/opt/<service>``). System paths like "
        "``/sys``, ``/proc``, ``/dev``, ``/etc``, ``/`` and the "
        "``root`` home are not application directories — pointing "
        "the working dir at one means subsequent ``COPY`` / ``RUN`` "
        "writes target kernel-exposed namespaces or admin-only "
        "configuration."
    ),
    docs_note=(
        "Subsequent directives in the Dockerfile (``COPY src dest``, "
        "``RUN`` writes, ``ADD …``) resolve relative paths against "
        "the active ``WORKDIR``. A ``WORKDIR /sys`` followed by "
        "``COPY conf.txt config.txt`` writes into the kernel's "
        "sysfs surface — at best a build-time error, at worst a "
        "container-escape primitive that lets a compromised step "
        "manipulate cgroups, devices, or kernel config."
    ),
)

#: Path prefixes that should never be the active ``WORKDIR``. The
#: filesystem root itself is included separately because any "starts-
#: with-/" rule would over-match. Ending slash is normalised away.
_DANGEROUS_PREFIXES: tuple[str, ...] = (
    "/sys",
    "/proc",
    "/dev",
    "/etc",
    "/boot",
    "/root",
    "/var/lib/docker",
    "/var/run/docker",
)


def _is_dangerous(path: str) -> str | None:
    """Return the matched prefix if *path* is system-rooted, else None."""
    p = path.strip().rstrip("/")
    if not p:
        return None
    if p == "/":
        return "/"
    # Match by full-component prefix to avoid catching ``/etc-overrides``.
    for prefix in _DANGEROUS_PREFIXES:
        if p == prefix or p.startswith(prefix + "/"):
            return prefix
    return None


def check(df: Dockerfile) -> Finding:
    offenders: list[str] = []
    for ins in iter_instructions(df, directive="WORKDIR"):
        prefix = _is_dangerous(ins.args)
        if prefix is not None:
            offenders.append(f"L{ins.line_no}: WORKDIR {ins.args} (under {prefix})")
    passed = not offenders
    desc = (
        "No ``WORKDIR`` points at a system or kernel path."
        if passed else
        f"{len(offenders)} ``WORKDIR`` directive(s) point at system "
        f"paths: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Subsequent ``COPY`` / "
        f"``RUN`` writes will resolve against these paths."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
