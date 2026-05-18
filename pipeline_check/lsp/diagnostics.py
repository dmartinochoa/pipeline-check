"""Translate pipeline_check :class:`Finding` objects to LSP diagnostics.

The mapping is intentionally narrow:

  - Severity goes through a static table (CRITICAL/HIGH → Error,
    MEDIUM → Warning, LOW → Information, INFO → Hint).
  - ``Finding.locations[0]`` (1-based line / column) becomes the LSP
    range (0-based by LSP convention).
  - ``Finding.check_id`` lands in ``Diagnostic.code`` so the client
    can surface it next to the rule title.
  - ``Diagnostic.codeDescription.href`` points at the rule's anchor
    in the published provider doc, so the editor renders the
    ``check_id`` as a hyperlink ("Open documentation" in VS Code).
  - ``Diagnostic.source`` is always ``"pipeline-check"`` so the
    editor's Problems panel groups our findings together.
  - ``Diagnostic.message`` carries the title, the per-finding
    description, and the fix recommendation, so the editor hover is
    self-contained.

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

# Base URL of the published reference docs. Per-rule anchors are
# ``providers/<provider>/#<check-id-lower>`` (the per-rule headings in
# ``scripts/gen_provider_docs.py`` emit attr-list IDs like ``{ #gha-001 }``).
_DOCS_BASE_URL = "https://dmartinochoa.github.io/pipeline-check"


def _docs_href(provider: str, check_id: str) -> str:
    return f"{_DOCS_BASE_URL}/providers/{provider}/#{check_id.lower()}"


def _compose_message(finding: Finding) -> str:
    parts: list[str] = [finding.title]
    if finding.description.strip():
        parts.append(finding.description.strip())
    if finding.recommendation.strip():
        parts.append(f"Fix: {finding.recommendation.strip()}")
    return "\n\n".join(parts)


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


def finding_to_diagnostic(
    finding: Finding, provider: str | None = None,
) -> lsp.Diagnostic:
    """Convert one failing :class:`Finding` to an LSP ``Diagnostic``.

    When *provider* is supplied the diagnostic gets a
    ``codeDescription.href`` that links the ``check_id`` to the
    rule's anchor in the published provider doc. Callers that don't
    know which provider produced the finding (e.g. ad-hoc tests) can
    omit it; the diagnostic still functions, but the ``check_id``
    renders as inert text rather than a hyperlink.
    """
    return lsp.Diagnostic(
        range=_range_from_finding(finding),
        severity=_SEVERITY_MAP.get(finding.severity, lsp.DiagnosticSeverity.Warning),
        code=finding.check_id,
        code_description=(
            lsp.CodeDescription(href=_docs_href(provider, finding.check_id))
            if provider
            else None
        ),
        source="pipeline-check",
        message=_compose_message(finding),
    )


def findings_to_diagnostics(
    findings: list[Finding], path: str, provider: str | None = None,
) -> list[lsp.Diagnostic]:
    """Translate every failing finding pinned to *path* into a diagnostic.

    Findings without any locations are accepted (they get a zero range
    so the editor's Problems panel still surfaces them). Findings whose
    first location's ``path`` doesn't match *path* are dropped — the
    LSP publishes diagnostics per-URI and a finding pinned elsewhere
    belongs to a different publish. *provider* is the dispatched
    provider name and threads through to ``finding_to_diagnostic`` so
    the docs link can be constructed from the rule's check_id.
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
        out.append(finding_to_diagnostic(f, provider))
    return out


def _paths_match(a: str, b: str) -> bool:
    """Case-insensitive suffix-match for cross-platform path equality."""
    return (
        a.replace("\\", "/").lower().rstrip("/")
        == b.replace("\\", "/").lower().rstrip("/")
    )
