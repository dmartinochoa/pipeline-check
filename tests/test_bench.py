"""Regression gate for the vulnerable-by-design benchmark.

Runs ``bench/run.py`` in-process against every case under
``bench/cases/`` and asserts 100% recall — i.e., every check_id
listed in a case's ``expected.txt`` actually fires when
pipeline-check scans the case fixtures.

Catches drift two ways:

  * A rule that silently stops firing on a case (regression on
    the rule, the orchestrator, or the parser the case exercises).
  * A new ``expected.txt`` line that doesn't correspond to a real
    rule firing on its case (asserts the benchmark stays
    self-consistent as new cases are added).

Per-case failures surface the missing IDs in the assertion
message so the diff in CI is actionable rather than
"recall < 100%."
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make ``bench/`` importable so we can call ``run`` directly. Same
# sys.path arithmetic the script does when executed as a module.
_REPO = Path(__file__).resolve().parent.parent
_BENCH = _REPO / "bench"
if str(_BENCH) not in sys.path:
    sys.path.insert(0, str(_BENCH))

import run as bench_run  # noqa: E402

CASES_DIR = _REPO / "bench" / "cases"


def _case_dirs() -> list[Path]:
    return sorted(d for d in CASES_DIR.iterdir() if d.is_dir())


@pytest.mark.parametrize(
    "case_dir",
    _case_dirs(),
    ids=[d.name for d in _case_dirs()],
)
def test_case_recall_is_100_percent(case_dir: Path):
    """Every check_id in the case's ``expected.txt`` must fire."""
    result = bench_run._evaluate_case(case_dir)
    assert result.expected, (
        f"{case_dir.name}: expected.txt is empty — every case "
        f"must declare at least one check_id."
    )
    assert not result.missing, (
        f"{case_dir.name}: {len(result.missing)} expected check_id(s) "
        f"did not fire: {result.missing}. Either the rule regressed "
        f"or the case fixtures no longer trigger it."
    )


def test_runner_exits_zero_when_all_cases_pass():
    """Smoke test: the runner's main() returns 0 when every
    case hits 100% recall. Locks the CI-gate exit-code contract."""
    rc = bench_run.main(["--json"])
    assert rc == 0, (
        f"bench/run.py exited {rc}; recall regression on at least "
        f"one case. Run it directly for the per-case detail."
    )


def test_every_case_has_a_notes_md():
    """Hygiene: every case explains itself. Missing notes makes
    new cases harder to review and harder to defend in the
    ``--explain`` chain narrative."""
    missing = [
        d.name for d in _case_dirs()
        if not (d / "notes.md").is_file()
    ]
    assert not missing, (
        f"cases without notes.md: {missing}. Add a notes.md "
        f"explaining the vulnerability + a real-world incident."
    )
