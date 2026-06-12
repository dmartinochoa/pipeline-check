"""GitHub Actions workflow-command (annotation) output.

Emits one ``::error`` / ``::warning`` / ``::notice`` workflow command per
failing finding location. When ``pipeline_check`` runs inside a GitHub
Actions job and prints these to stdout, GitHub renders them as inline
annotations on the changed lines (in the run log and on the PR), with no
SARIF upload step and no code-scanning / Advanced Security requirement,
so any repo gets inline feedback. Only failing findings are emitted,
mirroring the SARIF / Code Quality reporters.

Workflow-command reference:
https://docs.github.com/actions/reference/workflow-commands-for-github-actions
"""
from __future__ import annotations

import os

from .checks.base import Finding, Severity, inline_exploit
from .report_view import ReportView

#: CRITICAL / HIGH fail the build loudly; MEDIUM is a warning; LOW / INFO
#: are informational notices so they don't drown the actionable rows.
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "notice",
    Severity.INFO: "notice",
}


def _esc_data(s: str) -> str:
    """Percent-encode a workflow-command *message* body."""
    return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _esc_prop(s: str) -> str:
    """Percent-encode a workflow-command *property* value (also ``:`` / ``,``)."""
    return _esc_data(s).replace(":", "%3A").replace(",", "%2C")


def _norm_path(path: str) -> str:
    """Repo-relative, forward-slash path so GitHub can map the annotation.

    GitHub matches the ``file`` property against repo-relative paths
    (``GITHUB_WORKSPACE`` is the run's cwd). Make an absolute path relative
    to cwd and normalize separators; leave it untouched if it already looks
    relative or can't be relativized (e.g. a different drive on Windows).
    """
    if os.path.isabs(path):
        try:
            path = os.path.relpath(path)
        except ValueError:
            pass
    return path.replace("\\", "/")


def report_github_annotations(
    findings: list[Finding], inline_explain: bool = False,
) -> str:
    """Render failing *findings* as GitHub Actions workflow commands.

    One annotation per finding location (``file`` / ``line`` / ``endLine``
    set when known), keyed by ``title=<check_id>: <title>``. A finding with
    no resolved location emits a general annotation (no ``file``). With
    *inline_explain*, the exploit example is appended to the message.
    """
    lines: list[str] = []
    for f in ReportView(findings).failed:
        level = _LEVEL.get(f.severity, "error")
        msg = (f.description or f.title).strip()
        exploit = inline_exploit(f, inline_explain)
        if exploit:
            msg = f"{msg}\n\nProof of exploit:\n{exploit}"
        title = f"{f.check_id}: {f.title}"
        for loc in (f.locations or [None]):
            props: list[str] = []
            if loc is not None and loc.path:
                props.append(f"file={_esc_prop(_norm_path(loc.path))}")
                if loc.start_line is not None:
                    props.append(f"line={loc.start_line}")
                    if loc.end_line:
                        props.append(f"endLine={loc.end_line}")
            props.append(f"title={_esc_prop(title)}")
            lines.append(f"::{level} {','.join(props)}::{_esc_data(msg)}")
    return "\n".join(lines) + ("\n" if lines else "")
