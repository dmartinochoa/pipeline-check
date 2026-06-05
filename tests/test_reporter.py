"""Unit tests for reporter.py."""

import json

from rich.console import Console

from pipeline_check.core.checks.base import Finding, Severity
from pipeline_check.core.reporter import report_json, report_terminal
from pipeline_check.core.scorer import score
from pipeline_check.core.standards.base import ControlRef


def _f(check_id, severity, passed, resource="proj"):
    return Finding(
        check_id=check_id,
        title=f"Title {check_id}",
        severity=severity,
        resource=resource,
        description="desc",
        recommendation="rec",
        passed=passed,
        controls=[ControlRef(
            standard="owasp_cicd_top_10",
            standard_title="OWASP Top 10 CI/CD Security Risks",
            control_id="CICD-SEC-1",
            control_title="Insufficient Flow Control Mechanisms",
        )],
    )


FINDINGS = [
    _f("CB-001", Severity.CRITICAL, False),
    _f("CB-002", Severity.HIGH, True),
    _f("CB-003", Severity.MEDIUM, False),
    _f("CB-004", Severity.LOW, True),
    _f("CB-005", Severity.INFO, True),
]


class TestReportJson:
    def test_structure(self):
        result = score(FINDINGS)
        output = report_json(FINDINGS, result)
        data = json.loads(output)
        assert "score" in data
        assert "findings" in data
        assert len(data["findings"]) == len(FINDINGS)

    def test_finding_fields(self):
        result = score(FINDINGS)
        output = report_json(FINDINGS, result)
        data = json.loads(output)
        f = data["findings"][0]
        for key in ("check_id", "title", "severity", "resource",
                    "description", "recommendation", "controls", "passed"):
            assert key in f, f"Missing field: {key}"

    def test_severity_serialised_as_string(self):
        result = score(FINDINGS)
        output = report_json(FINDINGS, result)
        data = json.loads(output)
        severities = {f["severity"] for f in data["findings"]}
        assert all(isinstance(s, str) for s in severities)

    def test_score_keys(self):
        result = score(FINDINGS)
        output = report_json(FINDINGS, result)
        data = json.loads(output)
        assert "grade" in data["score"]
        assert "score" in data["score"]
        assert "summary" in data["score"]


class TestReportTerminal:
    """Smoke-tests for terminal reporter — verifies no exceptions are raised."""

    def _run(self, findings, threshold=Severity.INFO):
        console = Console(file=open("nul", "w") if False else __import__("io").StringIO(),
                          highlight=False)
        result = score(findings)
        report_terminal(findings, result, severity_threshold=threshold, console=console)

    def test_renders_without_error(self):
        self._run(FINDINGS)

    def test_renders_empty_findings(self):
        self._run([])

    def test_complete_scan_has_no_incomplete_banner(self):
        import io
        buf = io.StringIO()
        console = Console(file=buf, highlight=False, width=120)
        findings = [_f("CB-005", Severity.INFO, True)]
        report_terminal(findings, score(findings), console=console)
        output = buf.getvalue()
        assert "incomplete" not in output.lower()
        assert "Grade A" in output

    def test_incomplete_reason_flags_the_grade(self):
        # A degraded scan must not read as a confident pass. The grade
        # gets an "(incomplete)" tag and a status line carries the reason.
        import io
        buf = io.StringIO()
        console = Console(file=buf, highlight=False, width=120)
        findings = [_f("CB-005", Severity.INFO, True)]
        report_terminal(
            findings, score(findings), console=console,
            incomplete_reason="1 file(s) could not be parsed. "
            "The grade reflects only what was scanned.",
        )
        output = buf.getvalue()
        assert "(incomplete)" in output
        assert "incomplete scan:" in output
        assert "could not be parsed" in output

    def test_severity_threshold_filters(self):
        import io
        buf = io.StringIO()
        console = Console(file=buf, highlight=False, width=120)
        findings = [_f("CB-001", Severity.LOW, False)]
        result = score(findings)
        # Threshold = HIGH: LOW finding should not appear
        report_terminal(findings, result, severity_threshold=Severity.HIGH, console=console)
        output = buf.getvalue()
        assert "CB-001" not in output

    def test_severity_threshold_shows_matching(self):
        import io
        buf = io.StringIO()
        console = Console(file=buf, highlight=False, width=120)
        findings = [_f("CB-001", Severity.CRITICAL, False)]
        result = score(findings)
        report_terminal(findings, result, severity_threshold=Severity.HIGH, console=console)
        output = buf.getvalue()
        assert "CB-001" in output

    def test_passed_findings_hidden_by_default(self):
        # Default UX: the table shows only failures. Passed checks
        # would drown a 50-rule scan on a 10-workflow repo in green
        # rows. The headline still reports the pass count.
        import io
        buf = io.StringIO()
        console = Console(file=buf, highlight=False, width=200)
        findings = [
            _f("CB-001", Severity.CRITICAL, False),
            _f("CB-002", Severity.HIGH, True),   # passed
            _f("CB-003", Severity.HIGH, True),   # passed
        ]
        report_terminal(findings, score(findings), console=console)
        output = buf.getvalue()
        assert "CB-001" in output
        # CB-002 / CB-003 passed — must not appear as table rows.
        assert "CB-002" not in output
        assert "CB-003" not in output

    def test_show_passed_brings_back_passes(self):
        import io
        buf = io.StringIO()
        console = Console(file=buf, highlight=False, width=200)
        findings = [
            _f("CB-001", Severity.CRITICAL, False),
            _f("CB-002", Severity.HIGH, True),
        ]
        report_terminal(
            findings, score(findings), console=console, show_passed=True,
        )
        output = buf.getvalue()
        assert "CB-001" in output
        assert "CB-002" in output

    def test_controls_hidden_by_default(self):
        # Compliance metadata always lands in JSON/SARIF; the terminal
        # default drops it to keep the per-finding panel scannable.
        import io
        buf = io.StringIO()
        console = Console(file=buf, highlight=False, width=200)
        findings = [_f("CB-001", Severity.CRITICAL, False)]
        report_terminal(findings, score(findings), console=console)
        output = buf.getvalue()
        # The OWASP control we attached must not surface in the panel.
        assert "Insufficient Flow Control" not in output

    def test_show_controls_renders_controls(self):
        import io
        buf = io.StringIO()
        console = Console(file=buf, highlight=False, width=200)
        findings = [_f("CB-001", Severity.CRITICAL, False)]
        report_terminal(
            findings, score(findings), console=console, show_controls=True,
        )
        output = buf.getvalue()
        assert "Insufficient Flow Control" in output

    def test_no_failures_hint_message(self):
        # When the threshold filters out every failure, surface a clear
        # hint instead of an empty table.
        import io
        buf = io.StringIO()
        console = Console(file=buf, highlight=False, width=200)
        findings = [_f("CB-001", Severity.LOW, False)]
        report_terminal(
            findings, score(findings),
            severity_threshold=Severity.HIGH, console=console,
        )
        output = buf.getvalue()
        assert "No failures at or above" in output


class TestGroupSimilar:
    """Findings sharing ``(check_id, resource)`` collapse to one row
    plus a single follower-summary line, unless ``group_similar=False``."""

    def _dupes(self, n: int) -> list[Finding]:
        from pipeline_check.core.checks.base import Location
        return [
            Finding(
                check_id="GHA-001",
                title="Unpinned action",
                severity=Severity.HIGH,
                resource=".github/workflows/ci.yml",
                description="d",
                recommendation="rec",
                passed=False,
                locations=[Location(path=".github/workflows/ci.yml",
                                    start_line=10 + i)],
            )
            for i in range(n)
        ]

    def _render(self, findings, *, group_similar: bool) -> str:
        import io
        buf = io.StringIO()
        console = Console(file=buf, highlight=False, width=240)
        report_terminal(
            findings, score(findings), console=console,
            group_similar=group_similar,
        )
        return buf.getvalue()

    def test_groups_collapse_repeated_rows(self):
        out = self._render(self._dupes(3), group_similar=True)
        # The follower-summary cell mentions the extra line numbers.
        assert "+ 2 more on lines 11, 12" in out
        # Only one occurrence of GHA-001 as a visible table row's check
        # column: the representative. The follower row leaves the
        # Check column blank.
        # Robustly: the panel still names the rule, so we can't just
        # count "GHA-001". Instead assert the "+N more" hint is present
        # exactly once.
        assert out.count("+ 2 more on lines") == 1

    def test_no_group_renders_every_row(self):
        out = self._render(self._dupes(3), group_similar=False)
        assert "more on lines" not in out

    def test_follower_lines_cap_after_threshold(self):
        # 13 grouped findings (1 representative + 12 followers); the
        # inline line list caps at 10 numbers + "(and N more)" so the
        # title column stays one line on rules that fire many times
        # on one resource.
        out = self._render(self._dupes(13), group_similar=True)
        # Lines start at 10, so followers carry 11..22.
        assert "+ 12 more on lines 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 (and 2 more)" in out

    def test_grouping_skipped_for_different_resources(self):
        from pipeline_check.core.checks.base import Location
        findings = [
            Finding(
                check_id="GHA-001",
                title="Unpinned action",
                severity=Severity.HIGH,
                resource=path,
                description="d",
                recommendation="rec",
                passed=False,
                locations=[Location(path=path, start_line=10)],
            )
            for path in (
                ".github/workflows/a.yml",
                ".github/workflows/b.yml",
            )
        ]
        out = self._render(findings, group_similar=True)
        # Two distinct resources → two separate rows, no follower line.
        assert "more on lines" not in out


class TestInlineExplain:
    """``--inline-explain`` injects the rule's ``exploit_example`` under
    each failing finding's panel, no round-trip to ``--explain CHECK_ID``."""

    def _render(self, findings, *, inline_explain: bool) -> str:
        import io
        buf = io.StringIO()
        console = Console(file=buf, highlight=False, width=200)
        report_terminal(
            findings, score(findings), console=console,
            inline_explain=inline_explain,
        )
        return buf.getvalue()

    def _finding(self, exploit: str | None) -> Finding:
        return Finding(
            check_id="GHA-001",
            title="Unpinned action",
            severity=Severity.HIGH,
            resource=".github/workflows/ci.yml",
            description="desc",
            recommendation="pin to a SHA",
            passed=False,
            exploit_example=exploit,
        )

    def test_off_by_default_hides_exploit(self):
        f = self._finding("attacker pushes a tag move and gets RCE")
        out = self._render([f], inline_explain=False)
        assert "Proof of exploit:" not in out
        assert "attacker pushes a tag move" not in out

    def test_on_inlines_exploit_example(self):
        f = self._finding("attacker pushes a tag move and gets RCE")
        out = self._render([f], inline_explain=True)
        assert "Proof of exploit:" in out
        assert "attacker pushes a tag move" in out

    def test_on_no_exploit_skips_block(self):
        f = self._finding(None)
        out = self._render([f], inline_explain=True)
        assert "Proof of exploit:" not in out

    def test_passing_findings_get_no_panel(self):
        # Passing findings render no per-finding panel at all, so
        # exploit injection is a no-op for them regardless of the flag.
        f = self._finding("would never run")
        f.passed = True
        out = self._render([f], inline_explain=True)
        assert "Proof of exploit:" not in out
        assert "would never run" not in out

    def test_recommendation_still_renders_with_exploit(self):
        # The injection appends to the panel; the existing recommendation
        # must not disappear.
        f = self._finding("attacker pushes a tag")
        out = self._render([f], inline_explain=True)
        assert "pin to a SHA" in out
        assert "Proof of exploit:" in out

    def test_bracketed_exploit_tokens_survive_panel_render(self):
        # Real exploit_example bodies routinely contain literal ``[...]``
        # tokens (YAML lists, Terraform list refs, K8s capabilities). The
        # Rich Panel markup parser would interpret those as style tags and
        # silently strip the bracketed segments unless the exploit text is
        # routed through ``rich.markup.escape`` first.
        f = self._finding(
            "capabilities: { drop: [ALL] }\n"
            "runAfter: [extract]\n"
            "subnets = [aws_subnet.build.id]"
        )
        out = self._render([f], inline_explain=True)
        assert "[ALL]" in out
        assert "[extract]" in out
        assert "[aws_subnet.build.id]" in out
