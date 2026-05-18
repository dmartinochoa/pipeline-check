"""Finding → LSP Diagnostic conversion."""
from __future__ import annotations

import pytest

pytest.importorskip(
    "lsprotocol",
    reason="LSP server is an optional install: `pip install pipeline-check[lsp]`",
)

from lsprotocol import types as lsp  # noqa: E402

from pipeline_check.core.checks.base import (  # noqa: E402
    Finding,
    Location,
    Severity,
)
from pipeline_check.lsp.diagnostics import (  # noqa: E402
    finding_to_diagnostic,
    findings_to_diagnostics,
)


def _make_finding(
    severity: Severity = Severity.HIGH,
    passed: bool = False,
    locations: list[Location] | None = None,
) -> Finding:
    return Finding(
        check_id="GHA-001",
        title="Action not pinned to commit SHA",
        severity=severity,
        resource=".github/workflows/release.yml",
        description="actions/checkout@v4 is a tag ref; pin to a digest.",
        recommendation="Pin every uses: line to a 40-char SHA.",
        passed=passed,
        locations=locations or [],
    )


def test_severity_map_critical_and_high_both_error() -> None:
    crit = finding_to_diagnostic(_make_finding(severity=Severity.CRITICAL))
    high = finding_to_diagnostic(_make_finding(severity=Severity.HIGH))
    assert crit.severity == lsp.DiagnosticSeverity.Error
    assert high.severity == lsp.DiagnosticSeverity.Error


def test_severity_map_medium_to_warning() -> None:
    d = finding_to_diagnostic(_make_finding(severity=Severity.MEDIUM))
    assert d.severity == lsp.DiagnosticSeverity.Warning


def test_severity_map_low_to_information() -> None:
    d = finding_to_diagnostic(_make_finding(severity=Severity.LOW))
    assert d.severity == lsp.DiagnosticSeverity.Information


def test_severity_map_info_to_hint() -> None:
    d = finding_to_diagnostic(_make_finding(severity=Severity.INFO))
    assert d.severity == lsp.DiagnosticSeverity.Hint


def test_check_id_lands_in_code_field() -> None:
    d = finding_to_diagnostic(_make_finding())
    assert d.code == "GHA-001"
    assert d.source == "pipeline-check"


def test_message_includes_title_description_and_recommendation() -> None:
    d = finding_to_diagnostic(_make_finding())
    assert "Action not pinned" in d.message
    assert "actions/checkout@v4" in d.message
    # The recommendation is the actionable bit; the editor hover is
    # the user's first chance to see the fix without leaving the file.
    assert "Pin every uses:" in d.message
    assert "Fix:" in d.message


def test_code_description_links_to_provider_docs_when_provider_given() -> None:
    d = finding_to_diagnostic(_make_finding(), provider="github")
    assert d.code_description is not None
    assert d.code_description.href == (
        "https://dmartinochoa.github.io/pipeline-check"
        "/providers/github/#gha-001"
    )


def test_code_description_omitted_when_provider_unknown() -> None:
    # Callers (tests, future surfaces) that don't know which provider
    # produced the finding should still get a usable diagnostic; the
    # check_id just renders as inert text without a hyperlink.
    d = finding_to_diagnostic(_make_finding())
    assert d.code_description is None


def test_range_from_location_one_based_to_zero_based() -> None:
    finding = _make_finding(
        locations=[Location(
            path=".github/workflows/release.yml",
            start_line=14, end_line=14,
            start_column=9, end_column=27,
        )],
    )
    d = finding_to_diagnostic(finding)
    assert d.range.start.line == 13   # 14 - 1
    assert d.range.end.line == 13
    assert d.range.start.character == 8   # 9 - 1
    assert d.range.end.character == 26    # 27 - 1


def test_range_defaults_when_no_locations() -> None:
    d = finding_to_diagnostic(_make_finding())
    assert d.range.start.line == 0
    assert d.range.start.character == 0
    assert d.range.end.line == 0
    assert d.range.end.character == 0


def test_findings_to_diagnostics_drops_passing() -> None:
    failing = _make_finding(passed=False)
    passing = _make_finding(passed=True)
    out = findings_to_diagnostics(
        [failing, passing], ".github/workflows/release.yml",
    )
    assert len(out) == 1


def test_findings_to_diagnostics_filters_other_paths() -> None:
    here = _make_finding(
        locations=[Location(
            path=".github/workflows/release.yml", start_line=1,
        )],
    )
    elsewhere = _make_finding(
        locations=[Location(
            path=".github/workflows/build.yml", start_line=1,
        )],
    )
    out = findings_to_diagnostics(
        [here, elsewhere], ".github/workflows/release.yml",
    )
    assert len(out) == 1
    assert out[0].code == "GHA-001"


def test_findings_to_diagnostics_keeps_no_location_findings() -> None:
    no_loc = _make_finding(locations=[])
    out = findings_to_diagnostics(
        [no_loc], ".github/workflows/release.yml",
    )
    assert len(out) == 1


def test_findings_to_diagnostics_threads_provider_to_code_description() -> None:
    f = _make_finding()
    out = findings_to_diagnostics(
        [f], ".github/workflows/release.yml", provider="github",
    )
    assert len(out) == 1
    assert out[0].code_description is not None
    assert out[0].code_description.href.endswith("/providers/github/#gha-001")
