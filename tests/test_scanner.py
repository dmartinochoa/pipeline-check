"""Unit tests for the Scanner / MultiScanner orchestrator.

The orchestrator was previously exercised only end-to-end through the
provider suites. These cover its dispatch and finding-enrichment logic in
isolation: a Scanner built via ``__new__`` (``run()`` guards every
optional attribute behind ``getattr`` for exactly this) driving fake
check classes, so the orchestration is tested without standing up a real
provider context. MultiScanner is driven the same way with fake
sub-scanners.
"""
from __future__ import annotations

import pytest

from pipeline_check.core import pipeline_graph_builders as pgb
from pipeline_check.core import scanner as _scanner_mod
from pipeline_check.core.checks._primitives.secret_verifiers import (
    VerifyOutcome,
    VerifyResult,
)
from pipeline_check.core.checks.base import Confidence, Finding, Severity
from pipeline_check.core.scanner import MultiScanner, ScanMetadata, Scanner


def _finding(
    check_id: str = "FAKE-001",
    severity: Severity = Severity.HIGH,
    confidence: Confidence = Confidence.HIGH,
    *,
    locked: bool = False,
    resource: str = "r",
) -> Finding:
    return Finding(
        check_id=check_id, title="t", severity=severity, resource=resource,
        description="d", recommendation="rec", passed=False,
        confidence=confidence, confidence_locked=locked,
    )


def _check(findings: list[Finding]):
    """A fake check class. Constructed with ``(context, target=...)`` like
    the real ones; its ``run()`` returns the given findings."""
    class _FakeCheck:
        def __init__(self, context, target=None):
            self.context = context

        def run(self) -> list[Finding]:
            return list(findings)

    return _FakeCheck


def _scanner(check_classes, *, chains_enabled=False, overrides=None):
    """A Scanner built via ``__new__`` with only the attributes ``run()``
    reads (everything else is ``getattr``-guarded)."""
    s = Scanner.__new__(Scanner)
    s._check_classes = list(check_classes)
    s._context = object()
    s._chains_enabled = chains_enabled
    if overrides is not None:
        s._overrides = overrides
    return s


class _FakeSub:
    """A fake sub-Scanner for MultiScanner tests: ``run()`` returns fixed
    findings and it carries the ``pipeline_graphs`` MultiScanner reads."""

    def __init__(self, findings, graphs=()):
        self._findings = findings
        self.pipeline_graphs = list(graphs)

    def run(self, checks=None, target=None, standards=None):
        return list(self._findings)


class TestScannerDispatch:
    def test_runs_every_check_class_and_unions_findings(self):
        s = _scanner([_check([_finding("FAKE-001")]),
                      _check([_finding("FAKE-002")])])
        assert {f.check_id for f in s.run()} == {"FAKE-001", "FAKE-002"}

    def test_empty_check_classes_yield_no_findings(self):
        assert _scanner([]).run() == []

    def test_metadata_elapsed_recorded(self):
        s = _scanner([_check([_finding()])])
        s.run()
        assert s.metadata.elapsed_seconds >= 0


class TestScannerCheckFilter:
    def test_exact_id_allowlist(self):
        s = _scanner([_check([_finding("FAKE-001"), _finding("OTHER-002")])])
        assert {f.check_id for f in s.run(checks=["FAKE-001"])} == {"FAKE-001"}

    def test_glob_allowlist(self):
        s = _scanner([_check([
            _finding("FAKE-001"), _finding("FAKE-002"), _finding("OTHER-003"),
        ])])
        assert {f.check_id for f in s.run(checks=["FAKE-*"])} == {
            "FAKE-001", "FAKE-002",
        }

    def test_filter_is_case_insensitive(self):
        s = _scanner([_check([_finding("FAKE-001")])])
        assert len(s.run(checks=["fake-001"])) == 1


class TestScannerEnrichment:
    def test_confidence_default_applied(self):
        # GHA-004 is in the centralized MEDIUM demotion set.
        s = _scanner([_check([_finding("GHA-004", confidence=Confidence.HIGH)])])
        assert s.run()[0].confidence is Confidence.MEDIUM

    def test_confidence_locked_preserved(self):
        s = _scanner([_check([
            _finding("GHA-004", confidence=Confidence.HIGH, locked=True),
        ])])
        assert s.run()[0].confidence is Confidence.HIGH

    def test_override_mutates_severity(self):
        s = _scanner(
            [_check([_finding("FAKE-001", severity=Severity.LOW)])],
            overrides={"FAKE-001": {"severity": "critical"}},
        )
        assert s.run()[0].severity is Severity.CRITICAL

    def test_override_unknown_check_ignored(self):
        s = _scanner(
            [_check([_finding("FAKE-001", severity=Severity.LOW)])],
            overrides={"NOPE-999": {"severity": "critical"}},
        )
        assert s.run()[0].severity is Severity.LOW

    def test_override_bad_severity_value_ignored(self):
        s = _scanner(
            [_check([_finding("FAKE-001", severity=Severity.LOW)])],
            overrides={"FAKE-001": {"severity": "not-a-severity"}},
        )
        assert s.run()[0].severity is Severity.LOW


class TestScannerChainsToggle:
    def test_chains_disabled_is_empty(self):
        s = _scanner([_check([_finding()])], chains_enabled=False)
        s.run()
        assert s.chains == []

    def test_chains_enabled_returns_list(self):
        s = _scanner([_check([_finding()])], chains_enabled=True)
        s.run()
        assert isinstance(s.chains, list)


class TestScannerConstruction:
    def test_unknown_provider_raises(self):
        with pytest.raises(ValueError, match="Unknown provider"):
            Scanner(pipeline="definitely-not-a-provider")


class TestGraphBuilderResilience:
    """Graph-building is an additive visual signal that must never abort a
    scan, so ``build_graphs_for`` swallows every failure."""

    def test_unknown_provider_yields_empty(self):
        assert pgb.build_graphs_for("not-a-provider", None) == []

    def test_builder_exception_is_swallowed(self):
        def _boom(ctx):
            raise RuntimeError("kaboom")

        pgb.register_builder("faketestprovider", _boom)
        try:
            assert pgb.build_graphs_for("faketestprovider", object()) == []
        finally:
            pgb._BUILDERS.pop("faketestprovider", None)


class TestVerifyAndEnrichFindings:
    """Live secret verification mutates a finding in place: a confirmed-
    active credential escalates to CRITICAL (and locks confidence so the
    centralized default can't walk it back), an all-revoked one
    de-escalates to LOW."""

    def _patch_probe(self, monkeypatch, outcome):
        monkeypatch.setattr(
            _scanner_mod, "_build_doc_map", lambda ctx: {"r": object()},
        )
        monkeypatch.setattr(
            _scanner_mod._secret_registry, "classify_tokens_raw",
            lambda doc: [("aws", "AKIATESTTOKEN")],
        )
        monkeypatch.setattr(_scanner_mod, "has_verifier", lambda detector: True)
        monkeypatch.setattr(
            _scanner_mod, "verify_token",
            lambda detector, raw: VerifyResult(outcome=outcome, identity="acct-1"),
        )

    def test_verified_active_escalates_to_critical(self, monkeypatch):
        self._patch_probe(monkeypatch, VerifyOutcome.VERIFIED)
        f = _finding("GHA-008", severity=Severity.MEDIUM)
        _scanner_mod._verify_and_enrich_findings([f], object())
        assert f.severity is Severity.CRITICAL
        assert f.confidence is Confidence.HIGH and f.confidence_locked
        assert "VERIFIED ACTIVE" in f.description

    def test_all_unverified_deescalates_to_low(self, monkeypatch):
        self._patch_probe(monkeypatch, VerifyOutcome.UNVERIFIED)
        f = _finding("GHA-008", severity=Severity.HIGH)
        _scanner_mod._verify_and_enrich_findings([f], object())
        assert f.severity is Severity.LOW
        assert f.confidence is Confidence.LOW and f.confidence_locked

    def test_non_secret_finding_untouched(self, monkeypatch):
        self._patch_probe(monkeypatch, VerifyOutcome.VERIFIED)
        f = _finding("FAKE-001", severity=Severity.MEDIUM)
        _scanner_mod._verify_and_enrich_findings([f], object())
        assert f.severity is Severity.MEDIUM


class TestMultiScanner:
    def test_empty_pipelines_raises(self):
        with pytest.raises(ValueError, match="at least one pipeline"):
            MultiScanner([])

    def _multi(self, subs, *, chains_enabled=False, pipelines=None, meta_by=None):
        ms = MultiScanner.__new__(MultiScanner)
        ms._scanners = list(subs)
        ms._chains_enabled = chains_enabled
        ms.pipeline_graphs = []
        if pipelines is not None:
            ms.pipelines = pipelines
        if meta_by is not None:
            ms.metadata_by_provider = meta_by
        return ms

    def test_run_concatenates_in_pipeline_order(self):
        ms = self._multi([_FakeSub([_finding("A-1")]), _FakeSub([_finding("B-1")])])
        assert [f.check_id for f in ms.run()] == ["A-1", "B-1"]

    def test_run_aggregates_pipeline_graphs(self):
        ms = self._multi([_FakeSub([], graphs=["g1"]), _FakeSub([], graphs=["g2"])])
        ms.run()
        assert ms.pipeline_graphs == ["g1", "g2"]

    def test_chains_disabled_is_empty(self):
        ms = self._multi([_FakeSub([_finding()])], chains_enabled=False)
        ms.run()
        assert ms.chains == []

    def test_metadata_aggregates_across_providers(self):
        m1 = ScanMetadata(provider="github", files_scanned=2, warnings=["w1"])
        m2 = ScanMetadata(provider="gitlab", files_scanned=3, warnings=["w2"])
        ms = self._multi(
            [], pipelines=["github", "gitlab"],
            meta_by={"github": m1, "gitlab": m2},
        )
        agg = ms.metadata
        assert agg.files_scanned == 5
        assert agg.warnings == ["w1", "w2"]
        assert agg.provider == "github,gitlab"
