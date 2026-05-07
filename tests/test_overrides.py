"""Tests for the per-rule severity overrides surface.

The ``overrides:`` block in ``.pipeline-check.yml`` lets users demote
or promote a rule's severity without disabling it (the common SecOps
ask: "don't drop the rule, just downgrade it to LOW so the gate
passes"). The override flows through:

    config file -> core.config._parse_overrides
                -> core.config._LAST_OVERRIDES
                -> core.config.last_overrides()
                -> Scanner(overrides=...)
                -> applied to each Finding after confidence resolution

This module covers the parser, the Scanner application, and the
CLI integration.
"""
from __future__ import annotations

import json
import os
import pathlib
import tempfile

from click.testing import CliRunner

from pipeline_check.cli import scan
from pipeline_check.core.checks.base import Severity
from pipeline_check.core.config import (
    _parse_overrides,
    last_overrides,
    load_config,
)
from pipeline_check.core.scanner import Scanner


def _clear_env(monkeypatch):
    for name in list(os.environ):
        if name.startswith("PIPELINE_CHECK_"):
            monkeypatch.delenv(name, raising=False)


# ── _parse_overrides — config-loader normalization ───────────────────


class TestParseOverrides:
    def test_normalizes_check_id_and_severity_casing(self):
        result = _parse_overrides({
            "gha-001": {"severity": "low"},
            "K8S-024": {"severity": "Critical"},
        })
        assert result == {
            "GHA-001": {"severity": "LOW"},
            "K8S-024": {"severity": "CRITICAL"},
        }

    def test_drops_non_dict_root(self, capsys):
        assert _parse_overrides("not a mapping") == {}
        err = capsys.readouterr().err
        assert "must be a mapping" in err

    def test_drops_invalid_severity(self, capsys):
        result = _parse_overrides({"GHA-001": {"severity": "DOOM"}})
        assert result == {}
        err = capsys.readouterr().err
        assert "DOOM" in err

    def test_drops_unknown_subkey(self, capsys):
        result = _parse_overrides({
            "GHA-001": {"severity": "low", "weight": 7},
        })
        assert result == {"GHA-001": {"severity": "LOW"}}
        err = capsys.readouterr().err
        assert "weight" in err

    def test_drops_non_dict_body(self, capsys):
        result = _parse_overrides({"GHA-001": "low"})
        assert result == {}
        err = capsys.readouterr().err
        assert "must be a mapping" in err

    def test_drops_empty_check_id(self, capsys):
        result = _parse_overrides({"": {"severity": "low"}})
        assert result == {}


# ── load_config — overrides land in last_overrides() not default_map ─


class TestLoadConfigSurface:
    def test_overrides_pulled_out_of_default_map(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        (tmp_path / ".pipeline-check.yml").write_text(
            "pipeline: github\n"
            "overrides:\n"
            "  GHA-001:\n"
            "    severity: low\n"
            "  K8S-024:\n"
            "    severity: critical\n"
        )
        cfg = load_config(cwd=tmp_path)
        # ``overrides`` MUST NOT appear in the click default_map — click
        # would otherwise warn about an unknown ``--overrides`` option.
        assert "overrides" not in cfg
        # …but it's available via last_overrides().
        assert last_overrides() == {
            "GHA-001": {"severity": "LOW"},
            "K8S-024": {"severity": "CRITICAL"},
        }

    def test_overrides_cleared_between_loads(self, tmp_path, monkeypatch):
        _clear_env(monkeypatch)
        (tmp_path / ".pipeline-check.yml").write_text(
            "pipeline: github\n"
            "overrides:\n"
            "  GHA-001:\n"
            "    severity: low\n"
        )
        load_config(cwd=tmp_path)
        assert last_overrides() == {"GHA-001": {"severity": "LOW"}}
        # Second load with no overrides should clear the prior set.
        (tmp_path / ".pipeline-check.yml").write_text("pipeline: github\n")
        load_config(cwd=tmp_path)
        assert last_overrides() == {}


# ── Scanner — overrides applied after confidence resolution ──────────


def _make_unpinned_workflow(td: pathlib.Path) -> None:
    wf = td / "wf.yml"
    wf.write_text(
        "name: t\n"
        "on: push\n"
        "permissions: { contents: read }\n"
        "jobs:\n"
        "  b:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )


class TestScannerOverrides:
    def test_default_severity_when_no_overrides(self):
        with tempfile.TemporaryDirectory() as td:
            _make_unpinned_workflow(pathlib.Path(td))
            findings = Scanner(pipeline="github", gha_path=td).run()
            f = next(f for f in findings if f.check_id == "GHA-001" and not f.passed)
            assert f.severity is Severity.HIGH

    def test_override_demotes_severity(self):
        with tempfile.TemporaryDirectory() as td:
            _make_unpinned_workflow(pathlib.Path(td))
            findings = Scanner(
                pipeline="github",
                gha_path=td,
                overrides={"GHA-001": {"severity": "LOW"}},
            ).run()
            f = next(f for f in findings if f.check_id == "GHA-001" and not f.passed)
            assert f.severity is Severity.LOW

    def test_override_promotes_severity(self):
        with tempfile.TemporaryDirectory() as td:
            _make_unpinned_workflow(pathlib.Path(td))
            findings = Scanner(
                pipeline="github",
                gha_path=td,
                overrides={"GHA-001": {"severity": "CRITICAL"}},
            ).run()
            f = next(f for f in findings if f.check_id == "GHA-001" and not f.passed)
            assert f.severity is Severity.CRITICAL

    def test_override_normalizes_check_id_casing(self):
        with tempfile.TemporaryDirectory() as td:
            _make_unpinned_workflow(pathlib.Path(td))
            findings = Scanner(
                pipeline="github",
                gha_path=td,
                overrides={"gha-001": {"severity": "low"}},
            ).run()
            f = next(f for f in findings if f.check_id == "GHA-001" and not f.passed)
            assert f.severity is Severity.LOW

    def test_override_for_unknown_id_is_silently_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            _make_unpinned_workflow(pathlib.Path(td))
            findings = Scanner(
                pipeline="github",
                gha_path=td,
                overrides={"GHA-999": {"severity": "LOW"}},
            ).run()
            # GHA-001 keeps its default — the GHA-999 entry simply
            # never matched anything.
            f = next(f for f in findings if f.check_id == "GHA-001" and not f.passed)
            assert f.severity is Severity.HIGH

    def test_invalid_severity_string_falls_back_silently(self):
        # Programmatic callers can pass anything; the loader normally
        # filters bad values. The Scanner's defensive try/except keeps
        # a stray bad value from crashing the run.
        with tempfile.TemporaryDirectory() as td:
            _make_unpinned_workflow(pathlib.Path(td))
            findings = Scanner(
                pipeline="github",
                gha_path=td,
                overrides={"GHA-001": {"severity": "DOOM"}},
            ).run()
            f = next(f for f in findings if f.check_id == "GHA-001" and not f.passed)
            assert f.severity is Severity.HIGH


# ── CLI integration — config file overrides reach the JSON report ────


class TestCliOverridesIntegration:
    def test_config_override_demotes_finding_in_json_report(
        self, tmp_path, monkeypatch
    ):
        _clear_env(monkeypatch)
        monkeypatch.chdir(tmp_path)
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "c.yml").write_text(
            "on: push\n"
            "jobs:\n"
            "  b:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
        )
        (tmp_path / ".pipeline-check.yml").write_text(
            "pipeline: github\n"
            "overrides:\n"
            "  GHA-001:\n"
            "    severity: low\n"
        )
        result = CliRunner().invoke(scan, ["--output", "json"])
        assert result.exit_code in (0, 1), result.output
        payload = json.loads(result.stdout)
        gha001 = next(
            f for f in payload["findings"]
            if f["check_id"] == "GHA-001" and not f["passed"]
        )
        assert gha001["severity"] == "LOW"
