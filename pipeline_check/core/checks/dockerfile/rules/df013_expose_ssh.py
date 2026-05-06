"""DF-013 — ``EXPOSE`` declares a sensitive remote-access port (SSH, etc.)."""
from __future__ import annotations

import re

from ...base import Finding, Severity
from ...rule import Rule
from ..base import Dockerfile, iter_instructions

RULE = Rule(
    id="DF-013",
    title="EXPOSE declares sensitive remote-access port",
    severity=Severity.CRITICAL,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-LEAST-PRIV",),
    cwe=("CWE-693",),
    recommendation=(
        "Remove the ``EXPOSE`` line for the remote-access port. If the "
        "operator legitimately needs to reach the container, exec into "
        "it (``docker exec`` / ``kubectl exec``) — that path uses the "
        "orchestrator's auth and audit, doesn't open a network port, "
        "and doesn't ship an extra daemon inside the image. Containers "
        "should not run sshd / telnetd / ftpd / rsh-d / vncd / RDP "
        "alongside the application."
    ),
    docs_note=(
        "``EXPOSE`` is documentation, not a firewall — it doesn't "
        "actually open the port. But ``EXPOSE 22`` is a strong signal "
        "the image runs sshd, and any remote-access daemon inside the "
        "container blows up the threat model: now you have an extra "
        "auth surface, an extra service to keep patched, and a way "
        "for a compromised app to phone home from the outside. The "
        "container runtime / orchestrator's exec path covers every "
        "operational use case sshd traditionally served."
    ),
)

#: Ports that signal a remote-access daemon. Comments record the
#: typical service so reviewers can pattern-match without remembering
#: every TCP assignment.
_DANGEROUS_PORTS: dict[int, str] = {
    21:    "ftp",
    22:    "ssh / sftp",
    23:    "telnet",
    513:   "rsh / rlogin",
    514:   "rsh",
    873:   "rsync",
    2049:  "nfs",
    3389:  "rdp",
    5900:  "vnc",
    5901:  "vnc",
}

_PORT_RE = re.compile(r"\b(\d{1,5})\b(?:/(?:tcp|udp))?")


def check(df: Dockerfile) -> Finding:
    offenders: list[str] = []
    for ins in iter_instructions(df, directive="EXPOSE"):
        for m in _PORT_RE.finditer(ins.args):
            try:
                port = int(m.group(1))
            except ValueError:
                continue
            label = _DANGEROUS_PORTS.get(port)
            if label:
                offenders.append(f"L{ins.line_no}: {port}/{label}")
    passed = not offenders
    desc = (
        "No ``EXPOSE`` directive references a remote-access port."
        if passed else
        f"{len(offenders)} ``EXPOSE`` directive(s) reference remote-"
        f"access ports: {', '.join(offenders[:5])}"
        f"{'…' if len(offenders) > 5 else ''}. Containers should not "
        f"ship an embedded remote-access daemon."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=df.path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
