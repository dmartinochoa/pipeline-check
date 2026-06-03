"""DEV-005, devcontainer initializeCommand runs on the host.

Unlike the other devcontainer lifecycle hooks, ``initializeCommand``
runs on the **host** machine, before the container is built, so it is
not sandboxed by the container at all. Opening a poisoned repo in
VS Code Dev Containers or GitHub Codespaces executes it directly on the
developer's workstation (or the Codespaces VM) with their local
privileges and credentials.

HIGH: a confirmed open-the-repo trigger that runs outside the container
isolation the rest of the devcontainer model relies on. The
remote-fetch-and-execute case is further escalated to CRITICAL by
DEV-004.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    KIND_DEVCONTAINER,
    WorkspaceFile,
    devcontainer_initialize_commands,
    location_for,
)

RULE = Rule(
    id="DEV-005",
    title="Devcontainer initializeCommand runs unsandboxed on the host",
    severity=Severity.HIGH,
    owasp=("CICD-SEC-4", "CICD-SEC-7"),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-829",),
    recommendation=(
        "Move host-side setup into ``onCreateCommand`` / "
        "``postCreateCommand`` so it runs inside the container, where "
        "the blast radius is the disposable devcontainer rather than the "
        "developer's workstation. Reserve ``initializeCommand`` for "
        "genuinely host-only, trusted, vendored steps, and never let it "
        "fetch and run remote code (DEV-004)."
    ),
    docs_note=(
        "Fires whenever ``devcontainer.json`` declares an "
        "``initializeCommand``. That hook runs on the host before the "
        "container is created, so unlike the in-container lifecycle "
        "hooks (DEV-002) it has no container isolation. Common on "
        "legitimate setups too, hence HIGH rather than CRITICAL unless "
        "it also fetches remote code."
    ),
    exploit_example=(
        "# .devcontainer/devcontainer.json\n"
        "{\n"
        '  "image": "mcr.microsoft.com/devcontainers/base:ubuntu",\n'
        '  "initializeCommand": "./.devcontainer/host-setup.sh"\n'
        "}\n"
        "\n"
        "# initializeCommand runs on the HOST before the container is\n"
        "# built. A poisoned host-setup.sh executes on the developer's\n"
        "# workstation (or the Codespaces VM) the moment they reopen the\n"
        "# repo in a devcontainer, outside any container sandbox."
    ),
)


def check(path: str, wf: WorkspaceFile) -> Finding:
    if wf.kind != KIND_DEVCONTAINER:
        return _pass(path)
    cmds = devcontainer_initialize_commands(wf.data)
    if not cmds:
        return _pass(path)
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path,
        description=(
            f"initializeCommand runs on the host before the container is "
            f"built: {cmds[0]!r}"
            + (f" (+{len(cmds) - 1} more)" if len(cmds) > 1 else "")
            + ". It executes outside container isolation."
        ),
        recommendation=RULE.recommendation, passed=False,
        locations=location_for(path, wf.raw, cmds[0]),
    )


def _pass(path: str) -> Finding:
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path,
        description="No host-side devcontainer initializeCommand.",
        recommendation=RULE.recommendation, passed=True,
    )
