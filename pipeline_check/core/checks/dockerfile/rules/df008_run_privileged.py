"""DF-008, ``RUN`` invokes a privileged docker / capability-add idiom."""
from __future__ import annotations

import re

from ...base import Finding, Location, Severity
from ...rule import Rule
from ..base import Dockerfile, run_bodies

RULE = Rule(
    id="DF-008",
    title="RUN invokes docker --privileged or escalates capabilities",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-250",),
    recommendation=(
        "A Dockerfile build step almost never legitimately needs "
        "``--privileged`` or ``--cap-add SYS_ADMIN`` / ``ALL``. If "
        "the build genuinely requires elevated capabilities (e.g. "
        "compiling a kernel module), do it in a sealed builder image "
        "and ``COPY`` the artifact out, don't carry the privileged "
        "execution into the runtime image."
    ),
    docs_note=(
        "Mirrors GHA-017 / GL-017 / BB-013 / ADO-017 / CC-017 / "
        "JF-017 (``docker run --privileged`` in CI scripts) but at "
        "Dockerfile build time. The risk is subtler: a privileged "
        "RUN step doesn't directly elevate the resulting image, but "
        "it gives the build host's docker daemon a chance to escape, "
        "and any tampered base image can exploit the elevated build."
    ),
)

_PRIV_RE = re.compile(
    r"\bdocker\s+(?:run|exec)\b[^\n|]*--privileged\b"
    r"|--cap-add[\s=]\s*(?:ALL|SYS_ADMIN|SYS_PTRACE|NET_ADMIN|SYS_MODULE)\b"
    r"|--security-opt[\s=]\s*seccomp\s*=\s*unconfined\b"
    r"|--security-opt[\s=]\s*apparmor\s*=\s*unconfined\b"
    r"|--security-opt[\s=]\s*label\s*=\s*disable\b",
    re.IGNORECASE,
)


def check(df: Dockerfile) -> Finding:
    offenders: list[str] = []
    locations: list[Location] = []
    for line_no, body in run_bodies(df):
        line_offenders = 0
        for m in _PRIV_RE.finditer(body):
            snippet = m.group(0)[:60]
            offenders.append(f"L{line_no}: {snippet}")
            line_offenders += 1
        if line_offenders:
            # One Location per offending RUN line, keeps reporters'
            # click-to-jump tidy when a single RUN chains two
            # privileged invocations.
            locations.append(Location(
                path=df.path, start_line=line_no, end_line=line_no,
            ))
    passed = not offenders
    desc = (
        "No ``RUN`` body invokes ``--privileged`` / dangerous "
        "``--cap-add`` / unconfined security profiles."
        if passed else
        f"{len(offenders)} ``RUN`` body / bodies escalate privileges: "
        f"{', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
        locations=locations,
    )
