"""Unit tests for reporter.py."""

import json

from rich.console import Console

from pipeline_check.core.checks.base import Finding, Severity
from pipeline_check.core.reporter import (
    report_chains_terminal,
    report_json,
    report_terminal,
)
from pipeline_check.core.scorer import score
from pipeline_check.core.standards.base import ControlRef

from ._chain_helpers import make_reach_chain


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
        # JSON defaults to failures-only (matches terminal + SARIF).
        n_failed = sum(1 for f in FINDINGS if not f.passed)
        assert len(data["findings"]) == n_failed
        assert all(not f["passed"] for f in data["findings"])

    def test_show_passed_includes_every_check(self):
        # ``--show-passed`` restores the full audit record.
        result = score(FINDINGS)
        data = json.loads(report_json(FINDINGS, result, show_passed=True))
        assert len(data["findings"]) == len(FINDINGS)

    def test_score_summary_carries_counts_even_when_failures_only(self):
        # The grade/counts survive the default filter via score.summary.
        result = score(FINDINGS)
        data = json.loads(report_json(FINDINGS, result))
        n_passed = sum(1 for f in FINDINGS if f.passed)
        summary = data["score"]["summary"]
        assert sum(b["passed"] for b in summary.values()) == n_passed

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


class TestHeadlineReconciler:
    """A strong grade (A/B) on top of real failures must say so in the
    headline, so "Grade A" can't be read as a clean bill of health."""

    def _render(self, findings, score_result) -> str:
        import io
        buf = io.StringIO()
        console = Console(file=buf, highlight=False, width=120)
        report_terminal(findings, score_result, console=console)
        return buf.getvalue()

    def test_grade_a_with_failures_explains_the_gap(self):
        out = self._render(
            [_f("CB-001", Severity.LOW, False)],
            {"grade": "A", "score": 99, "summary": {}},
        )
        assert "severity-weighted posture" in out
        assert "1 check(s) still failed" in out

    def test_grade_a_clean_has_no_reconciler(self):
        out = self._render(
            [_f("CB-001", Severity.LOW, True)],
            {"grade": "A", "score": 100, "summary": {}},
        )
        assert "severity-weighted posture" not in out

    def test_grade_d_omits_reconciler(self):
        # A failing grade already signals trouble; the note would be noise.
        out = self._render(
            [_f("CB-001", Severity.CRITICAL, False)],
            {"grade": "D", "score": 10, "summary": {}},
        )
        assert "severity-weighted posture" not in out

    def test_incomplete_scan_skips_reconciler(self):
        # The incomplete banner owns the headline's second line; the
        # grade-vs-failures note must not stack on top of it.
        out = self._render_incomplete()
        assert "severity-weighted posture" not in out

    def _render_incomplete(self) -> str:
        import io
        buf = io.StringIO()
        console = Console(file=buf, highlight=False, width=120)
        report_terminal(
            [_f("CB-001", Severity.LOW, False)],
            {"grade": "A", "score": 99, "summary": {}},
            console=console,
            incomplete_reason="1 file(s) could not be parsed.",
        )
        return buf.getvalue()


class TestPanelRollup:
    """Detail panels that differ only by resource collapse into a single
    panel; panels carrying per-file prose stay separate."""

    def _finding(self, resource, description="generic finding"):
        return Finding(
            check_id="GHA-006",
            title="Artifacts not signed",
            severity=Severity.MEDIUM,
            resource=resource,
            description=description,
            recommendation="sign the artifact",
            passed=False,
        )

    def _render(self, findings) -> str:
        import io
        buf = io.StringIO()
        console = Console(file=buf, highlight=False, width=120)
        report_terminal(findings, score(findings), console=console)
        return buf.getvalue()

    def test_identical_prose_across_files_collapses_to_one_panel(self):
        findings = [
            self._finding(".github/workflows/a.yml"),
            self._finding(".github/workflows/b.yml"),
            self._finding(".github/workflows/c.yml"),
        ]
        out = self._render(findings)
        assert "Affected resources (3):" in out
        # The shared description renders once, not three times.
        assert out.count("generic finding") == 1
        for name in ("a.yml", "b.yml", "c.yml"):
            assert name in out

    def test_differing_prose_keeps_separate_panels(self):
        findings = [
            self._finding(".github/workflows/a.yml", description="a-only detail"),
            self._finding(".github/workflows/b.yml", description="b-only detail"),
        ]
        out = self._render(findings)
        assert "Affected resources" not in out
        assert "a-only detail" in out
        assert "b-only detail" in out

    def test_single_resource_is_not_a_merge(self):
        # One resource group renders the long-standing single-panel
        # layout (resource in the title), never the merged variant.
        out = self._render([self._finding(".github/workflows/a.yml")])
        assert "Affected resources" not in out
        assert "generic finding" in out


class TestSeverityStyleFor:
    """The listing commands color the SEV column through this shared
    helper, so it must mirror the report's severity scale."""

    def test_known_severities_map_to_design_styles(self):
        from pipeline_check.core.reporter import (
            _SEVERITY_STYLE,
            severity_style_for,
        )
        for sev in Severity:
            assert severity_style_for(sev.value) == _SEVERITY_STYLE[sev]

    def test_unknown_severity_defaults_to_white(self):
        from pipeline_check.core.reporter import severity_style_for
        assert severity_style_for("NOPE") == "white"


class TestResourceColumnWidth:
    """The Resource column scales to the console width so the filename
    and line survive on one cell instead of folding mid-path."""

    def _render(self, width: int) -> str:
        import io

        from pipeline_check.core.checks.base import Location
        finding = Finding(
            check_id="GHA-025",
            title="Reusable workflow not pinned",
            severity=Severity.HIGH,
            resource=".github/workflows/release.yml",
            description="d",
            recommendation="rec",
            passed=False,
            locations=[Location(path=".github/workflows/release.yml",
                                start_line=172)],
        )
        buf = io.StringIO()
        console = Console(file=buf, highlight=False, width=width)
        report_terminal([finding], score([finding]), console=console)
        return buf.getvalue()

    def test_narrow_keeps_filename_and_line_intact(self):
        out = self._render(80)
        # The filename:line stays contiguous (no mid-token fold) at the
        # cost of a head-truncation marker on the directory prefix.
        assert "…workflows/release.yml:172" in out

    def test_wide_shows_full_path_untruncated(self):
        out = self._render(200)
        assert ".github/workflows/release.yml:172" in out
        assert "…workflows/release.yml" not in out


class TestReportJsonScanStatus:
    """JSON output carries scan_status so CI consumers can detect a scan
    that parsed only part of what it was given."""

    def test_included_when_provided(self):
        status = {
            "complete": False, "files_scanned": 2,
            "files_unparsed": 1, "degraded_modules": 0, "reason": "x",
        }
        out = json.loads(report_json(FINDINGS, score(FINDINGS), scan_status=status))
        assert out["scan_status"] == status

    def test_omitted_when_none(self):
        out = json.loads(report_json(FINDINGS, score(FINDINGS)))
        assert "scan_status" not in out


class TestReachabilityBadge:
    """The weak shared-job co-location tier must not borrow the proven
    dataflow tier's confident "confirmed" badge."""

    def _render(self, chain):
        import io
        buf = io.StringIO()
        console = Console(file=buf, highlight=False, width=200)
        report_chains_terminal([chain], console=console)
        return buf.getvalue()

    def test_dataflow_tier_confirmed(self):
        out = self._render(make_reach_chain(via_dataflow=True))
        assert "Reachability confirmed (dataflow)" in out
        assert "Co-located (unverified)" not in out

    def test_structural_tier_confirmed(self):
        out = self._render(
            make_reach_chain(via_dataflow=False, via_structural=True)
        )
        assert "Reachability confirmed (structural)" in out
        assert "Co-located (unverified)" not in out

    def test_shared_job_tier_colocated_not_confirmed(self):
        out = self._render(make_reach_chain(via_dataflow=False))
        assert "Co-located (unverified)" in out
        assert "Reachability confirmed" not in out


class TestNextStepsTipAutofix:
    """The autofix nudge must point at the tier that will actually apply
    the fix: bare ``--fix`` runs safe fixers only, so an unsafe-only
    finding needs ``--fix unsafe --apply``."""

    def test_unsafe_only_finding_suggests_unsafe_tier(self):
        from pipeline_check.core import autofix
        from pipeline_check.core.reporter import next_steps_tip
        assert autofix.fixer_safety("GHA-003") == "unsafe"  # precondition
        tip = next_steps_tip([_f("GHA-003", Severity.HIGH, False)])
        assert "--fix unsafe --apply" in tip

    def test_safe_fixer_suggests_bare_fix(self):
        from pipeline_check.core import autofix
        from pipeline_check.core.reporter import next_steps_tip
        assert autofix.fixer_safety("GHA-001") == "safe"  # precondition
        tip = next_steps_tip([_f("GHA-001", Severity.HIGH, False)])
        assert "--fix --apply" in tip
        assert "--fix unsafe --apply" not in tip

    def test_mixed_counts_safe_and_notes_unsafe_remainder(self):
        from pipeline_check.core.reporter import next_steps_tip
        tip = next_steps_tip([
            _f("GHA-001", Severity.HIGH, False),
            _f("GHA-003", Severity.HIGH, False),
        ])
        assert "1 of 2" in tip  # only the safe one is counted for bare --fix
        assert "--fix --apply" in tip
        assert "via --fix unsafe" in tip
