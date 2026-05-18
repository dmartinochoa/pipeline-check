"""Translate pipeline_check :class:`Finding` objects to LSP diagnostics.

The mapping is intentionally narrow:

  - Severity goes through a static table (CRITICAL/HIGH → Error,
    MEDIUM → Warning, LOW → Information, INFO → Hint).
  - ``Finding.locations[0]`` (1-based line / column) becomes the LSP
    range (0-based by LSP convention).
  - ``Finding.check_id`` lands in ``Diagnostic.code`` so the client
    can surface it next to the rule title.
  - ``Diagnostic.source`` is always ``"pipeline-check"`` so the
    editor's Problems panel groups our findings together.

Findings whose ``passed`` is ``True`` are dropped; only failing
findings produce diagnostics. Findings without any ``locations`` get
a zero-zero range so the diagnostic still surfaces in the Problems
panel (it just isn't gutter-highlighted on a specific line).
"""
from __future__ import annotations

from lsprotocol import types as lsp

from pipeline_check.core.checks.base import Finding, Severity

# Static severity map. Critical and High both surface as LSP "Error"
# because most editors only render Error / Warning in the gutter and a
# CRITICAL finding has no business reading any quieter than a HIGH one.
_SEVERITY_MAP: dict[Severity, lsp.DiagnosticSeverity] = {
    Severity.CRITICAL: lsp.DiagnosticSeverity.Error,
    Severity.HIGH: lsp.DiagnosticSeverity.Error,
    Severity.MEDIUM: lsp.DiagnosticSeverity.Warning,
    Severity.LOW: lsp.DiagnosticSeverity.Information,
    Severity.INFO: lsp.DiagnosticSeverity.Hint,
}


def _range_from_finding(finding: Finding) -> lsp.Range:
    if not finding.locations:
        return lsp.Range(
            start=lsp.Position(line=0, character=0),
            end=lsp.Position(line=0, character=0),
        )
    loc = finding.locations[0]
    start_line = max(0, (loc.start_line or 1) - 1)
    end_line = max(start_line, (loc.end_line or loc.start_line or 1) - 1)
    start_col = max(0, (loc.start_column or 1) - 1)
    end_col = (
        max(start_col, (loc.end_column or loc.start_column or 1) - 1)
        if loc.end_column is not None or loc.start_column is not None
        else start_col
    )
    return lsp.Range(
        start=lsp.Position(line=start_line, character=start_col),
        end=lsp.Position(line=end_line, character=end_col),
    )


def finding_to_diagnostic(finding: Finding) -> lsp.Diagnostic:
    """Convert one failing :class:`Finding` to an LSP ``Diagnostic``."""
    return lsp.Diagnostic(
        range=_range_from_finding(finding),
        severity=_SEVERITY_MAP.get(finding.severity, lsp.DiagnosticSeverity.Warning),
        code=finding.check_id,
        source="pipeline-check",
        message=f"{finding.title}\n\n{finding.description}",
    )


def findings_to_diagnostics(
    findings: list[Finding], path: str,
) -> list[lsp.Diagnostic]:
    """Translate every failing finding pinned to *path* into a diagnostic.

    Findings without any locations are accepted (they get a zero range
    so the editor's Problems panel still surfaces them). Findings whose
    first location's ``path`` doesn't match *path* are dropped — the
    LSP publishes diagnostics per-URI and a finding pinned elsewhere
    belongs to a different publish.
    """
    out: list[lsp.Diagnostic] = []
    for f in findings:
        if f.passed:
            continue
        if f.locations:
            # The orchestrators record absolute paths; compare suffix-
            # match so trailing-slash / drive-letter casing on Windows
            # doesn't false-negative.
            if not f.locations[0].path or not _paths_match(
                f.locations[0].path, path,
            ):
                continue
        out.append(finding_to_diagnostic(f))
    return out


def _paths_match(a: str, b: str) -> bool:
    """Case-insensitive suffix-match for cross-platform path equality."""
    return (
        a.replace("\\", "/").lower().rstrip("/")
        == b.replace("\\", "/").lower().rstrip("/")
    )
