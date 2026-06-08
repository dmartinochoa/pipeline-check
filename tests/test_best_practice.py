"""Best-practice classification registry + ``--no-best-practice`` filter."""
from __future__ import annotations

import json
import pathlib

from click.testing import CliRunner

from pipeline_check.cli import scan
from pipeline_check.core.checks._best_practice import (
    BEST_PRACTICE_IDS,
    is_best_practice,
)
from pipeline_check.core.checks.rule import discover_rules

_CHECKS = pathlib.Path(__file__).resolve().parent.parent / "pipeline_check" / "core" / "checks"


def _all_rule_ids() -> set[str]:
    ids: set[str] = set()
    for pkg in _CHECKS.glob("*/rules"):
        fqn = f"pipeline_check.core.checks.{pkg.parent.name}.rules"
        for rule, _ in discover_rules(fqn):
            ids.add(rule.id)
    return ids


def test_every_best_practice_id_exists():
    """Guard the curated registry against typos / stale IDs."""
    unknown = sorted(i for i in BEST_PRACTICE_IDS if i not in _all_rule_ids())
    assert not unknown, f"BEST_PRACTICE_IDS references unknown rule(s): {unknown}"


def test_is_best_practice_discriminates():
    assert is_best_practice("GHA-015")          # no timeout-minutes (hygiene)
    assert is_best_practice("GHA-007")          # SBOM not produced
    assert not is_best_practice("GHA-003")      # script injection (real)
    assert not is_best_practice("GHA-001")      # unpinned action (real)


class TestNoBestPracticeFlag:
    def _scan(self, tmp_path, monkeypatch, extra_args):
        monkeypatch.chdir(tmp_path)
        wf = tmp_path / ".github" / "workflows"
        wf.mkdir(parents=True)
        # Minimal workflow with no timeout / SBOM / scan step, so the
        # best-practice family fires (GHA-015 etc.).
        (wf / "ci.yml").write_text(
            "on: push\njobs: {b: {runs-on: x, steps: [{run: echo}]}}\n"
        )
        result = CliRunner().invoke(
            scan,
            ["--pipeline", "github", "--output", "json", "--show-passed",
             *extra_args],
        )
        assert result.exit_code in (0, 1), result.output
        return {f["check_id"] for f in json.loads(result.stdout)["findings"]}

    def test_baseline_includes_best_practice(self, tmp_path, monkeypatch):
        ids = self._scan(tmp_path, monkeypatch, [])
        assert "GHA-015" in ids

    def test_flag_drops_best_practice_keeps_rest(self, tmp_path, monkeypatch):
        ids = self._scan(tmp_path, monkeypatch, ["--no-best-practice"])
        # every best-practice finding is gone
        assert not (ids & BEST_PRACTICE_IDS), sorted(ids & BEST_PRACTICE_IDS)
        # non-best-practice findings still emitted
        assert ids
        assert "GHA-003" in ids
