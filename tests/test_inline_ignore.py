"""Tests for inline source-line ignore comments."""
from __future__ import annotations

from pipeline_check.core.checks.base import Finding, Location, Severity
from pipeline_check.core.inline_ignore import (
    InlineIgnoreIndex,
    build_inline_index,
    extract_inline_ignores,
)


# ── Extraction ──────────────────────────────────────────────────────────


class TestExtractInlineIgnores:
    def test_ignore_same_line(self):
        text = "- run: curl | bash  # pipeline-check: ignore[GHA-007]\n"
        rules = extract_inline_ignores("wf.yml", text)
        assert len(rules) == 1
        assert rules[0].check_id == "GHA-007"
        assert rules[0].path == "wf.yml"
        assert rules[0].line == 1

    def test_ignore_next_line(self):
        text = (
            "# pipeline-check: ignore-next-line[GHA-001]\n"
            "- uses: actions/checkout@main\n"
        )
        rules = extract_inline_ignores("wf.yml", text)
        assert len(rules) == 1
        assert rules[0].check_id == "GHA-001"
        assert rules[0].line == 2

    def test_ignore_file(self):
        text = "# pipeline-check: ignore-file[CB-002]\nresource {}\n"
        rules = extract_inline_ignores("main.tf", text)
        assert len(rules) == 1
        assert rules[0].check_id == "CB-002"
        assert rules[0].line is None

    def test_multiple_ids_comma_separated(self):
        text = "run: x  # pipeline-check: ignore[GHA-001, GHA-003]\n"
        rules = extract_inline_ignores("wf.yml", text)
        assert len(rules) == 2
        assert {r.check_id for r in rules} == {"GHA-001", "GHA-003"}

    def test_reason_captured(self):
        text = "- run: x  # pipeline-check: ignore[GHA-003] reason=reviewed-safe\n"
        rules = extract_inline_ignores("wf.yml", text)
        assert rules[0].reason == "reviewed-safe"

    def test_double_slash_comment(self):
        text = '// pipeline-check: ignore[JF-001]\nnode { }\n'
        rules = extract_inline_ignores("Jenkinsfile", text)
        assert len(rules) == 1
        assert rules[0].check_id == "JF-001"

    def test_case_insensitive_directive(self):
        text = "# Pipeline-Check: Ignore[GHA-001]\n"
        rules = extract_inline_ignores("wf.yml", text)
        assert len(rules) == 1
        assert rules[0].check_id == "GHA-001"

    def test_case_insensitive_rule_id(self):
        text = "# pipeline-check: ignore[gha-001]\n"
        rules = extract_inline_ignores("wf.yml", text)
        assert rules[0].check_id == "GHA-001"

    def test_no_false_positive_on_plain_comment(self):
        text = "# this is a normal comment\n"
        rules = extract_inline_ignores("wf.yml", text)
        assert rules == []

    def test_no_false_positive_on_partial_match(self):
        text = "# pipeline-check: something-else\n"
        rules = extract_inline_ignores("wf.yml", text)
        assert rules == []

    def test_empty_file(self):
        rules = extract_inline_ignores("wf.yml", "")
        assert rules == []

    def test_multiple_lines_mixed(self):
        text = (
            "on: push\n"
            "# pipeline-check: ignore-file[GHA-004]\n"
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - run: curl | bash  # pipeline-check: ignore[GHA-007]\n"
        )
        rules = extract_inline_ignores("wf.yml", text)
        assert len(rules) == 2
        file_rules = [r for r in rules if r.line is None]
        line_rules = [r for r in rules if r.line is not None]
        assert len(file_rules) == 1
        assert file_rules[0].check_id == "GHA-004"
        assert len(line_rules) == 1
        assert line_rules[0].check_id == "GHA-007"
        assert line_rules[0].line == 6


# ── Index matching ──────────────────────────────────────────────────────


def _loc(path: str, line: int) -> Location:
    return Location(path=path, start_line=line)


def _finding(
    check_id: str, resource: str, locations: list[Location] | None = None,
) -> Finding:
    return Finding(
        check_id=check_id,
        title="test",
        severity=Severity.HIGH,
        resource=resource,
        description="test",
        recommendation="test",
        passed=False,
        locations=locations or [],
    )


class TestInlineIgnoreIndex:
    def test_line_level_match(self):
        rules = extract_inline_ignores(
            "wf.yml", "- run: x  # pipeline-check: ignore[GHA-007]\n",
        )
        index = build_inline_index(rules)
        f = _finding("GHA-007", "wf.yml", [_loc("wf.yml", 1)])
        assert index.matches(f.check_id, f.resource, f.locations)

    def test_line_level_miss(self):
        rules = extract_inline_ignores(
            "wf.yml", "- run: x  # pipeline-check: ignore[GHA-007]\n",
        )
        index = build_inline_index(rules)
        f = _finding("GHA-007", "wf.yml", [_loc("wf.yml", 5)])
        assert not index.matches(f.check_id, f.resource, f.locations)

    def test_wrong_check_id_miss(self):
        rules = extract_inline_ignores(
            "wf.yml", "- run: x  # pipeline-check: ignore[GHA-007]\n",
        )
        index = build_inline_index(rules)
        f = _finding("GHA-001", "wf.yml", [_loc("wf.yml", 1)])
        assert not index.matches(f.check_id, f.resource, f.locations)

    def test_file_level_match(self):
        rules = extract_inline_ignores(
            "wf.yml", "# pipeline-check: ignore-file[GHA-004]\n",
        )
        index = build_inline_index(rules)
        f = _finding("GHA-004", "wf.yml", [_loc("wf.yml", 50)])
        assert index.matches(f.check_id, f.resource, f.locations)

    def test_file_level_matches_by_resource(self):
        rules = extract_inline_ignores(
            "wf.yml", "# pipeline-check: ignore-file[GHA-004]\n",
        )
        index = build_inline_index(rules)
        f = _finding("GHA-004", "wf.yml", [])
        assert index.matches(f.check_id, f.resource, f.locations)

    def test_empty_index_is_falsy(self):
        index = build_inline_index([])
        assert not index

    def test_nonempty_index_is_truthy(self):
        rules = extract_inline_ignores(
            "wf.yml", "# pipeline-check: ignore-file[GHA-004]\n",
        )
        index = build_inline_index(rules)
        assert index

    def test_backslash_normalized(self):
        rules = extract_inline_ignores(
            ".github\\workflows\\ci.yml",
            "- run: x  # pipeline-check: ignore[GHA-007]\n",
        )
        index = build_inline_index(rules)
        f = _finding(
            "GHA-007",
            ".github/workflows/ci.yml",
            [_loc(".github/workflows/ci.yml", 1)],
        )
        assert index.matches(f.check_id, f.resource, f.locations)


# ── Gate integration ────────────────────────────────────────────────────


class TestGateIntegration:
    def test_inline_suppresses_finding(self):
        from pipeline_check.core.gate import GateConfig, evaluate_gate
        from pipeline_check.core.scorer import ScoreResult

        rules = extract_inline_ignores(
            "wf.yml", "- run: x  # pipeline-check: ignore[GHA-007]\n",
        )
        index = build_inline_index(rules)
        f = _finding("GHA-007", "wf.yml", [_loc("wf.yml", 1)])
        score = ScoreResult(
            grade="D", score=0.0, findings_by_severity={},
            category_scores={},
        )
        config = GateConfig(inline_ignores=index)
        result = evaluate_gate([f], score, config)
        assert f in result.suppressed
        assert f not in result.effective

    def test_inline_does_not_suppress_different_line(self):
        from pipeline_check.core.gate import GateConfig, evaluate_gate
        from pipeline_check.core.scorer import ScoreResult

        rules = extract_inline_ignores(
            "wf.yml", "- run: x  # pipeline-check: ignore[GHA-007]\n",
        )
        index = build_inline_index(rules)
        f = _finding("GHA-007", "wf.yml", [_loc("wf.yml", 10)])
        score = ScoreResult(
            grade="C", score=50.0, findings_by_severity={},
            category_scores={},
        )
        config = GateConfig(inline_ignores=index)
        result = evaluate_gate([f], score, config)
        assert f in result.effective
        assert f not in result.suppressed

    def test_file_wide_suppresses_all_lines(self):
        from pipeline_check.core.gate import GateConfig, evaluate_gate
        from pipeline_check.core.scorer import ScoreResult

        rules = extract_inline_ignores(
            "wf.yml", "# pipeline-check: ignore-file[GHA-004]\n",
        )
        index = build_inline_index(rules)
        f1 = _finding("GHA-004", "wf.yml", [_loc("wf.yml", 1)])
        f2 = _finding("GHA-004", "wf.yml", [_loc("wf.yml", 50)])
        score = ScoreResult(
            grade="D", score=0.0, findings_by_severity={},
            category_scores={},
        )
        config = GateConfig(inline_ignores=index)
        result = evaluate_gate([f1, f2], score, config)
        assert f1 in result.suppressed
        assert f2 in result.suppressed
        assert result.effective == []
