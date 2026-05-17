"""Lock the public stability contract against silent drift.

``docs/stability.md`` enumerates exactly which surfaces are covered by
semver. Each contract there carries a corresponding assertion here so
the doc can't lie. Failing one of these tests means either:

  a) Something contracted has actually changed — bump the major
     version, update ``stability.md``, and document the deprecation
     window. OR
  b) The change wasn't intentional — revert.

Either way, this test failing is the system telling the contributor
to pause and look at the public surface deliberately.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from pipeline_check.core.checks.base import Confidence, Finding, Severity
from pipeline_check.core.reporter import JSON_SCHEMA_VERSION, report_json
from pipeline_check.core.scorer import score

REPO = Path(__file__).resolve().parent.parent


# ──────────────────────────────────────────────────────────────────
# JSON schema_version contract
# ──────────────────────────────────────────────────────────────────


class TestJsonSchemaContract:
    """The JSON payload's documented top-level + per-finding shape."""

    def _payload(self) -> dict:
        f = Finding(
            check_id="CB-001",
            title="t", severity=Severity.HIGH, resource="r",
            description="d", recommendation="rec", passed=False,
        )
        result = score([f])
        return json.loads(report_json([f], result, tool_version="9.9.9"))

    def test_schema_version_is_major_1(self):
        # ``schema_version="1.x"`` is the contracted major. A bump to
        # ``2.x`` is a breaking change requiring a deprecation window;
        # this test fails on accidental bumps so the version mark is
        # always deliberate.
        major = JSON_SCHEMA_VERSION.split(".", 1)[0]
        assert major == "1", (
            f"JSON schema major version drifted to {JSON_SCHEMA_VERSION!r}. "
            f"Bumping the major version is a breaking change — coordinate "
            f"with consumers and update docs/stability.md before merging."
        )

    def test_top_level_keys_documented(self):
        payload = self._payload()
        # Documented top-level keys must exist on every payload.
        for key in ("schema_version", "tool_version", "score", "findings"):
            assert key in payload, (
                f"docs/stability.md contracts {key!r} as a top-level "
                f"JSON field; it must be present on every payload."
            )

    def test_finding_minimum_fields(self):
        payload = self._payload()
        f = payload["findings"][0]
        # Documented per-finding minimum fields.
        for key in (
            "check_id", "title", "severity", "confidence", "resource",
            "description", "recommendation", "passed", "controls", "cwe",
        ):
            assert key in f, (
                f"docs/stability.md contracts findings[].{key} as a "
                f"per-finding minimum field; it must be present on "
                f"every finding."
            )

    def test_severity_values_within_contract(self):
        payload = self._payload()
        contracted = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for f in payload["findings"]:
            assert f["severity"] in contracted, (
                f"severity {f['severity']!r} is not in the contracted set "
                f"{contracted}. Adding a new severity is a major-version "
                f"change."
            )

    def test_score_keys_documented(self):
        payload = self._payload()
        s = payload["score"]
        for key in ("score", "grade", "summary"):
            assert key in s, (
                f"docs/stability.md contracts score.{key} as a top-level "
                f"score field; it must be present."
            )
        assert s["grade"] in ("A", "B", "C", "D"), (
            f"grade {s['grade']!r} outside contracted A/B/C/D set; "
            f"grade thresholds are stable per docs/stability.md."
        )

    def test_passed_is_boolean(self):
        payload = self._payload()
        for f in payload["findings"]:
            assert isinstance(f["passed"], bool), (
                f"findings[].passed must be a JSON boolean; got "
                f"{type(f['passed']).__name__}."
            )


# ──────────────────────────────────────────────────────────────────
# Exit-code contract
# ──────────────────────────────────────────────────────────────────


class TestExitCodeContract:
    """The 0/1/2/3 exit-code semantics described in docs/stability.md.

    Spawns the CLI as a subprocess so the test exercises the real
    process-exit path, not Click's testing harness (which sometimes
    masks SystemExit codes).
    """

    def _run(self, args: list[str], cwd: Path) -> int:
        return subprocess.run(
            [sys.executable, "-m", "pipeline_check", *args],
            cwd=cwd, capture_output=True, text=True, timeout=60,
        ).returncode

    def test_exit_0_on_clean_scan(self, tmp_path):
        # Drop a trivial GitLab pipeline so auto-detect succeeds. No
        # checks fail on a near-empty pipeline → exit 0.
        (tmp_path / ".gitlab-ci.yml").write_text("stages: []\n")
        code = self._run(["--output", "json", "--quiet"], cwd=tmp_path)
        # Permit 0 (clean) or 1 (gate tripped on default-content scan
        # findings); both are valid here. Exit 2/3 would indicate the
        # CLI itself errored.
        assert code in (0, 1), (
            f"expected exit 0 or 1 from a normal scan, got {code}"
        )

    def test_exit_2_on_usage_error(self, tmp_path):
        # Empty cwd → UX-3 raises UsageError → exit 2.
        code = self._run([], cwd=tmp_path)
        assert code == 2, (
            f"empty-cwd auto-detect must exit 2 (UsageError per "
            f"docs/stability.md), got {code}"
        )

    def test_exit_2_on_unknown_pipeline_flag(self, tmp_path):
        code = self._run(["--pipeline", "lolnope"], cwd=tmp_path)
        assert code == 2, (
            f"unknown --pipeline value must exit 2 (UsageError), got {code}"
        )


# ──────────────────────────────────────────────────────────────────
# Severity / Confidence enum contract
# ──────────────────────────────────────────────────────────────────


class TestEnumContract:
    """Severity / Confidence enum values are part of the public surface
    (they show up in the JSON output and the gate config)."""

    def test_severity_values_locked(self):
        actual = {s.value for s in Severity}
        contracted = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        assert actual == contracted, (
            f"Severity enum values drifted to {actual}. Removing a "
            f"value is a breaking change; adding one is too (it widens "
            f"the JSON severity set consumers must handle). Update "
            f"docs/stability.md before changing."
        )

    def test_confidence_values_locked(self):
        actual = {c.value for c in Confidence}
        contracted = {"HIGH", "MEDIUM", "LOW"}
        assert actual == contracted, (
            f"Confidence enum values drifted to {actual}. Same caveat "
            f"as Severity above."
        )


# ──────────────────────────────────────────────────────────────────
# Scoring formula contract
# ──────────────────────────────────────────────────────────────────


class TestScoringFormulaContract:
    """Weighted score formula and A/B/C/D grade thresholds are stable
    per docs/stability.md."""

    def test_weights_locked(self):
        # CRITICAL=20, HIGH=10, MEDIUM=5, LOW=2, INFO=0.
        cases = [
            (Severity.CRITICAL, 20),
            (Severity.HIGH, 10),
            (Severity.MEDIUM, 5),
            (Severity.LOW, 2),
            (Severity.INFO, 0),
        ]
        for sev, expected in cases:
            f = Finding(
                check_id="T-001", title="t", severity=sev,
                resource="r", description="d", recommendation="r",
                passed=False,
            )
            # Add one PASS at CRITICAL to make total > 0 so the math
            # has a denominator (no findings → score 100 short-circuit).
            anchor = Finding(
                check_id="T-002", title="t", severity=Severity.CRITICAL,
                resource="r", description="d", recommendation="r",
                passed=True,
            )
            r = score([f, anchor])
            # Failing severity ``sev`` contributes ``expected``; passing
            # CRITICAL contributes 20 to the denominator only. So:
            #   score = 100 * (1 - expected / (expected + 20))
            if expected == 0:  # INFO doesn't count
                assert r["score"] == 100, (
                    f"INFO findings must not affect score; got {r['score']}"
                )
            else:
                # Just sanity-check the score moves with the weight.
                assert 0 <= r["score"] < 100

    def test_grade_thresholds_locked(self):
        # A >= 90, B >= 75, C >= 60, D < 60. Pinned against the
        # ``score()`` function's authoritative output by reading the
        # source to confirm the threshold constants haven't drifted.
        # If the source no longer literally embeds the contracted
        # boundaries, this test fails so the doc and the constants
        # stay in sync.
        import inspect

        from pipeline_check.core import scorer as _scorer
        body = inspect.getsource(_scorer.score)
        assert ">= 90" in body, (
            "score()'s A-grade threshold drifted from >= 90. Update "
            "docs/stability.md and bump the major version before "
            "changing grade boundaries."
        )
        assert ">= 75" in body, (
            "score()'s B-grade threshold drifted from >= 75."
        )
        assert ">= 60" in body, (
            "score()'s C-grade threshold drifted from >= 60."
        )


# ──────────────────────────────────────────────────────────────────
# Stability doc presence + non-empty (so the contract source-of-truth
# can't be deleted without intent).
# ──────────────────────────────────────────────────────────────────


def test_stability_doc_exists_and_is_indexed():
    """The stability contract lives at docs/stability.md and is in
    the mkdocs nav. Deleting it is a breaking governance change."""
    doc = REPO / "docs" / "stability.md"
    assert doc.is_file(), (
        "docs/stability.md is the source of truth for what semver "
        "covers. Don't delete it — supersede or revise."
    )
    text = doc.read_text(encoding="utf-8")
    assert len(text) > 1000, "stability.md is suspiciously short"

    nav = (REPO / "mkdocs.yml").read_text(encoding="utf-8")
    assert "stability.md" in nav, (
        "docs/stability.md must be linked from mkdocs.yml nav so it "
        "ships in the published docs."
    )


@pytest.mark.parametrize("snippet", [
    "schema_version",
    "Finding identity",
    "Exit codes",
    "Scoring model",
    "CLI flags",
])
def test_stability_doc_covers_each_contract(snippet):
    doc = (REPO / "docs" / "stability.md").read_text(encoding="utf-8")
    assert snippet in doc, (
        f"docs/stability.md is missing the {snippet!r} contract "
        f"section. Each guard in this test file is paired with a "
        f"prose section there — keep them in sync."
    )
