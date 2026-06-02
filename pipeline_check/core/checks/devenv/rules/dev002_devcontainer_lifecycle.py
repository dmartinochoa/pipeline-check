"""DEV-002, devcontainer lifecycle command runs automatically.

``devcontainer.json`` lifecycle hooks (``onCreateCommand``,
``updateContentCommand``, ``postCreateCommand``, ``postStartCommand``,
``postAttachCommand``) run whenever a Codespace or a local devcontainer
is created or attached, with no separate confirmation. A poisoned repo
that someone opens in Codespaces runs these in a cloud environment that
typically holds a ``GITHUB_TOKEN`` and the user's forwarded
credentials.

LOW on its own: lifecycle commands are the normal, expected way to set
a devcontainer up (``pip install``, ``npm ci``). The
remote-fetch-and-execute case is escalated to CRITICAL by DEV-004, and
the host-side ``initializeCommand`` has its own rule (DEV-005).
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import (
    KIND_DEVCONTAINER,
    WorkspaceFile,
    devcontainer_lifecycle_commands,
    location_for,
)

RULE = Rule(
    id="DEV-002",
    title="Devcontainer lifecycle command runs automatically",
    severity=Severity.LOW,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-829",),
    recommendation=(
        "Treat the lifecycle commands as code that runs on every "
        "Codespace / devcontainer create. Keep them vendored in the "
        "repo, free of network fetches (DEV-004), and review changes to "
        "them the way you would any executable in the build path. There "
        "is no way to disable lifecycle execution short of removing the "
        "keys; this finding is informational so a reviewer notices what "
        "runs on open."
    ),
    docs_note=(
        "Fires when ``devcontainer.json`` declares any of "
        "``onCreateCommand`` / ``updateContentCommand`` / "
        "``postCreateCommand`` / ``postStartCommand`` / "
        "``postAttachCommand``. The host-side ``initializeCommand`` is "
        "handled separately by DEV-005 (it runs unsandboxed on the host)."
    ),
)


def check(path: str, wf: WorkspaceFile) -> Finding:
    if wf.kind != KIND_DEVCONTAINER:
        return _pass(path)
    hooks = devcontainer_lifecycle_commands(wf.data)
    if not hooks:
        return _pass(path)
    keys = ", ".join(sorted({k for k, _ in hooks}))
    first_cmd = next((c for _, c in hooks if c), "")
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path,
        description=(
            f"Devcontainer runs lifecycle command(s) on create/attach: "
            f"{keys}. These execute automatically in any Codespace or "
            "local devcontainer."
        ),
        recommendation=RULE.recommendation, passed=False,
        locations=location_for(path, wf.raw, first_cmd),
    )


def _pass(path: str) -> Finding:
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path,
        description="No devcontainer lifecycle commands.",
        recommendation=RULE.recommendation, passed=True,
    )
