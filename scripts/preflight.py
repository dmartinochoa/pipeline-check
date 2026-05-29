#!/usr/bin/env python3
"""Run the gates CI enforces, in one command, before you open a PR.

This mirrors the three jobs in ``.github/workflows/python-app.yml``
(ruff lint over ``pipeline_check`` + ``tests``, ``mypy pipeline_check``,
pytest) and adds the three doc-staleness checks, so drift surfaces
locally instead of in CI. Every step runs through ``sys.executable -m``
or a project script, so it works the same on Windows and POSIX.

    python scripts/preflight.py            # lint, docs, types, full suite
    python scripts/preflight.py --quick    # swap the full suite for the fast
                                           # drift/framework subset

The full run takes about two minutes; ``--quick`` is a few seconds and
is the right inner-loop gate while iterating on a rule.

Formatting is intentionally not checked here: CI does not gate
``ruff format``, and the project's pre-commit hook already runs it on
changed files. Install the hooks once with ``pre-commit install``.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent

# The fast "code is the source of truth, docs follow" suites plus the
# rule-framework and fixture guards. Cheap enough for the inner loop.
_DRIFT_TESTS = [
    "tests/test_cli_docs_drift.py",
    "tests/test_doc_claims.py",
    "tests/test_english_variant.py",
    "tests/test_rule_framework.py",
    "tests/test_rule_test_coverage.py",
    "tests/test_standards.py",
    "tests/test_workflow_fixtures.py",
]

_PY = sys.executable


def _gen(script: str) -> list[str]:
    return [_PY, str(_REPO_ROOT / "scripts" / script), "--check"]


def _steps(quick: bool) -> list[tuple[str, list[str]]]:
    """Ordered ``(label, argv)`` steps. Cheap and high-signal first.

    Lint scope matches the CI ``lint`` job (``pipeline_check`` + ``tests``,
    not ``scripts``). The doc-freshness checks are faster, clearer-erroring
    duplicates of what the drift tests enforce inside pytest.
    """
    steps: list[tuple[str, list[str]]] = [
        ("ruff lint", [_PY, "-m", "ruff", "check", "pipeline_check", "tests"]),
        ("provider docs fresh", _gen("gen_provider_docs.py")),
        ("standards docs fresh", _gen("gen_standards_docs.py")),
        ("attack-chains doc fresh", _gen("gen_attack_chains_doc.py")),
        ("mypy (strict)", [_PY, "-m", "mypy", "pipeline_check"]),
    ]
    if quick:
        steps.append(("drift + framework tests", [_PY, "-m", "pytest", *_DRIFT_TESTS, "-q", "--no-header"]))
    else:
        steps.append(("full test suite", [_PY, "-m", "pytest", "tests", "-q", "--no-header"]))
    return steps


def _run(label: str, argv: list[str]) -> tuple[bool, float]:
    bar = "=" * 70
    print(f"\n{bar}\n  {label}\n{bar}", flush=True)
    start = time.monotonic()
    rc = subprocess.run(argv, cwd=_REPO_ROOT, check=False).returncode
    return rc == 0, time.monotonic() - start


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run the fast drift/framework subset instead of the full suite.",
    )
    args = parser.parse_args(argv)

    results: list[tuple[str, bool, float]] = []
    for label, cmd in _steps(args.quick):
        ok, elapsed = _run(label, cmd)
        results.append((label, ok, elapsed))

    print("\n" + "=" * 70)
    print("  preflight summary")
    print("=" * 70)
    for label, ok, elapsed in results:
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {label:<28} {elapsed:6.1f}s")
    failed = [label for label, ok, _ in results if not ok]
    if failed:
        print(f"\n{len(failed)} step(s) failed: {', '.join(failed)}")
        return 1
    print("\nAll gates passed. Ready to open a PR.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
