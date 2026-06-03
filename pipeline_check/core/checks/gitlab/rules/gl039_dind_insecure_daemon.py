"""GL-039. Docker-in-Docker service with TLS disabled / daemon exposed."""
from __future__ import annotations

import re
from typing import Any

from ...base import Finding, Severity
from ...rule import Rule
from ..base import iter_jobs

# A ``docker:<ver>-dind`` service image (the Docker-in-Docker daemon).
_DIND_RE = re.compile(r"\bdocker:[\w.\-]*dind\b", re.IGNORECASE)
# The plaintext daemon socket. Port 2375 is the unauthenticated TCP port;
# 2376 is the TLS port. Exposing 2375 (or pointing DOCKER_HOST at it)
# means any job on the same runner can drive the daemon with no auth.
_PLAINTEXT_DAEMON_RE = re.compile(r"tcp://[^\s\"']*:2375\b")


def _var_scalar(raw: Any) -> Any:
    if isinstance(raw, dict):  # GitLab typed ``{value:, description:}`` form
        return raw.get("value")
    return raw


def _variables(scope: dict[str, Any]) -> dict[str, Any]:
    v = scope.get("variables")
    return v if isinstance(v, dict) else {}


def _services(scope: dict[str, Any]) -> list[tuple[str, str]]:
    """Return ``(image, command_text)`` for each service in *scope*."""
    out: list[tuple[str, str]] = []
    svcs = scope.get("services")
    if not isinstance(svcs, list):
        return out
    for s in svcs:
        if isinstance(s, str):
            out.append((s, ""))
        elif isinstance(s, dict):
            name = str(s.get("name") or "")
            cmd = s.get("command") or s.get("entrypoint") or []
            cmd_text = " ".join(map(str, cmd)) if isinstance(cmd, list) else str(cmd)
            out.append((name, cmd_text))
    return out


def _tls_disabled(variables: dict[str, Any], services: list[tuple[str, str]]) -> bool:
    # Modern dind defaults to TLS on (DOCKER_TLS_CERTDIR=/certs). Setting it
    # to the empty string reverts to the plaintext 2375 socket.
    if _var_scalar(variables.get("DOCKER_TLS_CERTDIR")) == "":
        return True
    host = str(_var_scalar(variables.get("DOCKER_HOST")) or "")
    if _PLAINTEXT_DAEMON_RE.search(host):
        return True
    return any(_PLAINTEXT_DAEMON_RE.search(cmd) for _, cmd in services)


RULE = Rule(
    id="GL-039",
    title="Docker-in-Docker service exposes an unauthenticated daemon",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-7",),
    esf=("ESF-D-BUILD-ENV",),
    cwe=("CWE-306", "CWE-319"),
    recommendation=(
        "Keep TLS on the dind daemon: drop ``DOCKER_TLS_CERTDIR: \"\"`` "
        "(let it default to ``/certs``) and talk to the daemon over the "
        "TLS port 2376, not the plaintext 2375. Never expose the daemon "
        "with ``--host=tcp://0.0.0.0:2375``. On a shared / untagged "
        "runner an unauthenticated daemon socket is reachable by every "
        "other tenant's job, which means container escape and "
        "cross-tenant compromise; pin the job to a dedicated, ephemeral "
        "runner via ``tags:`` as well."
    ),
    docs_note=(
        "Fires when a job (or the global config) runs a "
        "``docker:*-dind`` service AND disables daemon authentication, "
        "either via ``DOCKER_TLS_CERTDIR: \"\"`` (reverts to the "
        "plaintext 2375 socket) or by exposing / pointing at "
        "``tcp://...:2375`` in the service ``command:`` or "
        "``DOCKER_HOST``. Global ``services:`` / ``variables:`` are "
        "merged into each job before the check. The unauthenticated "
        "daemon is the container-escape vector behind the untagged "
        "shared-runner + privileged-dind anti-pattern."
    ),
    exploit_example=(
        "# Vulnerable: dind with TLS off, no tags (any shared runner).\n"
        "build-image:\n"
        "  services:\n"
        "    - name: docker:27-dind\n"
        "      command: [\"--host=tcp://0.0.0.0:2375\"]\n"
        "  variables:\n"
        "    DOCKER_TLS_CERTDIR: \"\"\n"
        "    DOCKER_HOST: tcp://docker:2375\n"
        "  script:\n"
        "    - docker build -t app .\n"
        "\n"
        "# Attack: the daemon listens on an unauthenticated TCP socket.\n"
        "# Another tenant's job on the same shared runner connects to it,\n"
        "# mounts the host filesystem into a privileged container, and\n"
        "# escapes to the runner host.\n"
        "\n"
        "# Safe: keep TLS on (default), talk over 2376, pin a runner.\n"
        "build-image:\n"
        "  tags: [dedicated-ephemeral]\n"
        "  services:\n"
        "    - docker:27-dind\n"
        "  variables:\n"
        "    DOCKER_TLS_CERTDIR: \"/certs\"\n"
        "  script:\n"
        "    - docker build -t app ."
    ),
)


def check(path: str, doc: dict[str, Any]) -> Finding:
    global_vars = _variables(doc)
    global_services = _services(doc)
    offenders: list[str] = []
    for name, job in iter_jobs(doc):
        eff_vars = {**global_vars, **_variables(job)}
        eff_services = global_services + _services(job)
        dind = [img for img, _ in eff_services if _DIND_RE.search(img)]
        if not dind:
            continue
        if _tls_disabled(eff_vars, eff_services):
            offenders.append(f"{name}: dind service ({dind[0]})")
    passed = not offenders
    desc = (
        "No Docker-in-Docker service exposes an unauthenticated daemon."
        if passed else
        f"{len(offenders)} job(s) run a dind service with TLS disabled / "
        f"the daemon exposed on the plaintext 2375 socket: "
        f"{', '.join(offenders[:5])}"
        f"{'...' if len(offenders) > 5 else ''}."
    )
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path, description=desc,
        recommendation=RULE.recommendation, passed=passed,
    )
