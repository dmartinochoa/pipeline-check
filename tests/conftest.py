"""Shared test helpers for provider-agnostic tests (scorer, reporter, etc.)

AWS-specific helpers (make_session, make_paginator) live in tests/aws/conftest.py.

Also carries a session-scoped guard that pins ``os.getcwd()`` and the
``PIPELINE_CHECK_*`` env-var set across the suite. The
``tests/test_stability_contract.py::TestExitCodeContract`` tests spawn
the CLI via ``subprocess.run([sys.executable, "-m", "pipeline_check",
...], cwd=tmp_path)`` and so inherit whatever environment / cwd the
running pytest process holds. If a sibling test forgot to restore
``os.chdir`` or to ``monkeypatch.delenv`` a ``PIPELINE_CHECK_*``
override, the subprocess child sees the pollution and the stability
tests flap. The guard below fails fast with a pointer at the leaking
test instead of letting the flake hide downstream.
"""
from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _no_cwd_or_env_drift():
    """Snapshot cwd + PIPELINE_CHECK_* env at the start of each test,
    re-assert at teardown.

    A test that ``os.chdir(...)`` without restoring, or one that
    ``os.environ[...] = ...`` without going through
    ``monkeypatch.setenv``, will fail with a pointer here instead of
    polluting later tests in the same session. Tests that intentionally
    change cwd / env should use ``monkeypatch`` (auto-restored at
    teardown) or skip the assertion with ``pytest.mark.no_cwd_guard``.
    """
    before_cwd = os.getcwd()
    before_env = {
        k: v for k, v in os.environ.items() if k.startswith("PIPELINE_CHECK_")
    }
    yield
    after_cwd = os.getcwd()
    if after_cwd != before_cwd:
        # Restore so subsequent tests don't cascade-fail, then report.
        os.chdir(before_cwd)
        pytest.fail(
            f"test leaked an os.chdir: {before_cwd!r} -> {after_cwd!r}. "
            f"Use ``monkeypatch.chdir(...)`` so the cwd is restored at "
            f"fixture teardown."
        )
    after_env = {
        k: v for k, v in os.environ.items() if k.startswith("PIPELINE_CHECK_")
    }
    if after_env != before_env:
        # Restore the snapshot, then report.
        for k in set(after_env) - set(before_env):
            os.environ.pop(k, None)
        for k, v in before_env.items():
            os.environ[k] = v
        added = sorted(set(after_env) - set(before_env))
        removed = sorted(set(before_env) - set(after_env))
        changed = sorted(
            k for k in before_env if k in after_env and before_env[k] != after_env[k]
        )
        pytest.fail(
            f"test leaked PIPELINE_CHECK_* env vars: "
            f"added={added}, removed={removed}, changed={changed}. "
            f"Use ``monkeypatch.setenv(...)`` / ``monkeypatch.delenv(...)`` "
            f"so the environment is restored at fixture teardown."
        )
