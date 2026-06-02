"""DEV-001, VS Code task runs automatically on folder open.

A ``.vscode/tasks.json`` task with ``runOptions.runOn: folderOpen``
executes the moment the repository is opened in VS Code (once the
folder is trusted), before any build, test, or review. A poisoned
fork or a malicious contribution can use it to run code on a
reviewer's machine just by getting them to open the checkout.

LOW on its own: a folder-open task is frequently a benign
watch / build task. The remote-fetch-and-execute case is escalated to
CRITICAL by DEV-004.
"""
from __future__ import annotations

from ...base import Finding, Severity
from ...rule import Rule
from ..base import KIND_VSCODE_TASKS, WorkspaceFile, location_for, vscode_folderopen_tasks

RULE = Rule(
    id="DEV-001",
    title="VS Code task runs automatically on folder open",
    severity=Severity.LOW,
    owasp=("CICD-SEC-4",),
    esf=("ESF-D-INJECTION",),
    cwe=("CWE-829",),
    recommendation=(
        "Remove ``runOptions.runOn: folderOpen`` so the task runs only "
        "when invoked explicitly, or move the logic into a documented "
        "setup script a developer chooses to run. If an auto-task is "
        "genuinely required, keep its command vendored in the repo and "
        "free of any network fetch (see DEV-004)."
    ),
    docs_note=(
        "Fires on any task in ``.vscode/tasks.json`` whose "
        "``runOptions.runOn`` is ``folderOpen``. VS Code Workspace Trust "
        "gates the first run, but reviewers routinely trust repos they "
        "open, so this is a real reachable-on-open surface rather than a "
        "purely theoretical one."
    ),
)


def check(path: str, wf: WorkspaceFile) -> Finding:
    if wf.kind != KIND_VSCODE_TASKS:
        return _pass(path)
    auto = vscode_folderopen_tasks(wf.data)
    if not auto:
        return _pass(path)
    labels = ", ".join(sorted({label for label, _ in auto})[:3])
    extra = "…" if len({label for label, _ in auto}) > 3 else ""
    first_cmd = next((c for _, c in auto if c), "")
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path,
        description=(
            f"{len(auto)} VS Code task(s) run on folder open: {labels}{extra}. "
            "Opening this repo in VS Code (once trusted) runs them."
        ),
        recommendation=RULE.recommendation, passed=False,
        locations=location_for(path, wf.raw, first_cmd or "folderOpen"),
    )


def _pass(path: str) -> Finding:
    return Finding(
        check_id=RULE.id, title=RULE.title, severity=RULE.severity,
        resource=path,
        description="No folder-open VS Code tasks.",
        recommendation=RULE.recommendation, passed=True,
    )
