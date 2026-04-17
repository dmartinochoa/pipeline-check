"""GHA-026 — container-job ``options:`` must not disable isolation."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs

RULE = Rule(
    id="GHA-026",
    title="Container job disables isolation via `options:`",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-BUILD-ENV", "ESF-D-PRIV-BUILD"),
    cwe=("CWE-250", "CWE-276"),
    recommendation=(
        "Remove ``--network host``, ``--privileged``, ``--cap-add``, "
        "``--user 0``/``--user root``, ``--pid host``, ``--ipc host``, "
        "and host ``-v`` bind-mounts from ``container.options`` and "
        "``services.*.options``. If a build genuinely needs one of "
        "these, move it to a dedicated self-hosted pool with branch "
        "protection so the flag doesn't reach PR runs."
    ),
    docs_note=(
        "GitHub-hosted runners execute ``container:`` jobs inside a "
        "Docker container the runner itself manages — normally a "
        "hardened, network-namespaced sandbox. ``options:`` is a "
        "free-text passthrough to ``docker run``; a flag that breaks "
        "the sandbox (shares host network/PID, runs privileged, "
        "maps the Docker socket) turns the job into an RCE on the "
        "runner VM."
    ),
)

_BAD_OPTION_RE = re.compile(
    r"(?ix)"
    r"(?:^|\s)--privileged\b"
    r"|(?:^|\s)--cap-add\b"
    r"|(?:^|\s)--network(?:\s|=)host\b"
    r"|(?:^|\s)--pid(?:\s|=)host\b"
    r"|(?:^|\s)--ipc(?:\s|=)host\b"
    r"|(?:^|\s)--userns(?:\s|=)host\b"
    r"|(?:^|\s)--user(?:\s|=)0\b"
    r"|(?:^|\s)--user(?:\s|=)root\b"
    r"|(?:^|\s)-v\s+/var/run/docker\.sock"
    r"|(?:^|\s)-v\s+/:/"
)


def _scan_options(container_spec: Any) -> list[str]:
    if not isinstance(container_spec, dict):
        return []
    options = container_spec.get("options")
    if not isinstance(options, str):
        return []
    return sorted({m.group(0).strip() for m in _BAD_OPTION_RE.finditer(options)})


def check(path: str, doc: dict[str, Any]) -> Finding:
    offenders: list[str] = []
    for job_id, job in iter_jobs(doc):
        for flag in _scan_options(job.get("container")):
            offenders.append(f"{job_id}.container: {flag}")
        services = job.get("services") or {}
        if isinstance(services, dict):
            for svc_name, svc_spec in services.items():
                for flag in _scan_options(svc_spec):
                    offenders.append(f"{job_id}.services.{svc_name}: {flag}")
    passed = not offenders
    desc = (
        "No container job disables isolation via `options:`."
        if passed else
        f"Container ``options:`` bypass isolation in: "
        f"{', '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
