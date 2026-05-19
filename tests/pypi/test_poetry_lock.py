"""poetry.lock parser + rule reuse tests.

Exercises both layers:

1. ``_parse_poetry_lock`` unit tests: lock-version 1.x (files in
   ``[metadata.files]``) and 2.x (files inside each ``[[package]]``
   table), git sources (PEP 508 direct URL synthesis), missing
   files / version (defensive paths).
2. End-to-end via ``PypiContext.from_path``: a real ``poetry.lock``
   on disk produces a :class:`RequirementsFile` that
   :class:`PypiChecks` fans out across PYPI-001 / PYPI-002 /
   PYPI-004 / PYPI-006 without per-rule changes.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

from pipeline_check.core.checks.pypi.base import (
    PypiContext,
    _parse_poetry_lock,
)
from pipeline_check.core.checks.pypi.pipelines import PypiChecks

# ── _parse_poetry_lock ──────────────────────────────────────────────


class TestParsePoetryLock:
    def test_lock_v2_inline_files(self) -> None:
        # Lock-version 2.x carries ``files`` as a per-package field.
        text = textwrap.dedent(
            """\
            [[package]]
            name = "requests"
            version = "2.31.0"
            description = ""
            optional = false
            python-versions = ">=3.7"
            files = [
                {file = "requests-2.31.0.tar.gz", hash = "sha256:aaa"},
                {file = "requests-2.31.0-py3-none-any.whl", hash = "sha256:bbb"},
            ]

            [metadata]
            lock-version = "2.0"
            """
        )
        lines, options = _parse_poetry_lock(text)
        assert len(lines) == 1
        line = lines[0]
        assert line.body == "requests==2.31.0"
        assert "--hash=sha256:aaa" in line.flags
        assert "--hash=sha256:bbb" in line.flags
        assert "--require-hashes" in options

    def test_lock_v1_metadata_files(self) -> None:
        # Lock-version 1.x stores files at the bottom in
        # ``[metadata.files]`` keyed by package name.
        text = textwrap.dedent(
            """\
            [[package]]
            name = "requests"
            version = "2.28.0"
            description = ""
            optional = false
            python-versions = ">=3.7"

            [metadata]
            lock-version = "1.1"

            [metadata.files]
            requests = [
                {file = "requests-2.28.0.tar.gz", hash = "sha256:ccc"},
            ]
            """
        )
        lines, options = _parse_poetry_lock(text)
        assert len(lines) == 1
        assert lines[0].body == "requests==2.28.0"
        assert lines[0].flags == ("--hash=sha256:ccc",)
        assert "--require-hashes" in options

    def test_git_source_emits_direct_url(self) -> None:
        text = textwrap.dedent(
            """\
            [[package]]
            name = "forked"
            version = "1.0.0"

            [package.source]
            type = "git"
            url = "https://github.com/owner/forked.git"
            reference = "main"
            resolved_reference = "abcdef1234567890abcdef1234567890abcdef12"

            [metadata]
            lock-version = "2.0"
            """
        )
        lines, _ = _parse_poetry_lock(text)
        assert len(lines) == 1
        # PEP 508 direct URL form, with resolved_reference appended
        # so PYPI-004 sees a 40-char SHA-pinned VCS dep.
        assert lines[0].body == (
            "forked @ git+https://github.com/owner/forked.git@"
            "abcdef1234567890abcdef1234567890abcdef12"
        )

    def test_git_source_with_only_branch_reference(self) -> None:
        # No resolved_reference (rare; usually only when Poetry has
        # not run an install): fall back to reference verbatim.
        text = textwrap.dedent(
            """\
            [[package]]
            name = "forked"
            version = "0.1.0"

            [package.source]
            type = "git"
            url = "https://github.com/owner/forked.git"
            reference = "main"

            [metadata]
            lock-version = "2.0"
            """
        )
        lines, _ = _parse_poetry_lock(text)
        assert lines[0].body == (
            "forked @ git+https://github.com/owner/forked.git@main"
        )

    def test_package_without_files_still_emitted(self) -> None:
        # Packages missing files (e.g., the project's own root
        # package) still produce a RequirementLine — PYPI-006 needs
        # the (name, version) tuple regardless of whether hashes
        # are present.
        text = textwrap.dedent(
            """\
            [[package]]
            name = "ctx"
            version = "0.2.2"

            [metadata]
            lock-version = "2.0"
            """
        )
        lines, _ = _parse_poetry_lock(text)
        assert len(lines) == 1
        assert lines[0].body == "ctx==0.2.2"
        assert lines[0].flags == ()

    def test_empty_lockfile_emits_no_lines(self) -> None:
        text = textwrap.dedent(
            """\
            [metadata]
            lock-version = "2.0"
            """
        )
        lines, options = _parse_poetry_lock(text)
        assert lines == ()
        # --require-hashes is still set so PYPI-002 reports the
        # contract even on an empty lock (defensive; reaching here
        # means the file existed and Poetry resolved to nothing,
        # which is fine).
        assert options == ("--require-hashes",)


# ── Integration: end-to-end via PypiContext.from_path ─────────────


_POETRY_LOCK_BODY = textwrap.dedent(
    """\
    # This file is automatically @generated by Poetry and should not
    # be changed by hand.

    [[package]]
    name = "requests"
    version = "2.31.0"
    description = "Python HTTP for Humans."
    optional = false
    python-versions = ">=3.7"
    files = [
        {file = "requests-2.31.0.tar.gz", hash = "sha256:aaa"},
        {file = "requests-2.31.0-py3-none-any.whl", hash = "sha256:bbb"},
    ]

    [[package]]
    name = "ctx"
    version = "0.2.2"
    description = "Python Context (compromised)"
    optional = false
    python-versions = "*"
    files = [
        {file = "ctx-0.2.2.tar.gz", hash = "sha256:malicious"},
    ]

    [metadata]
    lock-version = "2.0"
    python-versions = "^3.8"
    content-hash = "deadbeef"
    """
)


def _write_poetry_lock(tmp_path: Path) -> Path:
    target = tmp_path / "poetry.lock"
    target.write_text(_POETRY_LOCK_BODY, encoding="utf-8")
    return target


def test_poetry_lock_picked_up_by_loader(tmp_path: Path) -> None:
    _write_poetry_lock(tmp_path)
    ctx = PypiContext.from_path(tmp_path)
    assert len(ctx.files) == 1
    rf = ctx.files[0]
    bodies = {line.body for line in rf.lines}
    assert "requests==2.31.0" in bodies
    assert "ctx==0.2.2" in bodies


def test_poetry_lock_pypi001_passes_on_exact_pins(tmp_path: Path) -> None:
    _write_poetry_lock(tmp_path)
    ctx = PypiContext.from_path(tmp_path)
    findings = list(PypiChecks(ctx).run())
    p001 = [f for f in findings if f.check_id == "PYPI-001"]
    assert p001 and all(f.passed for f in p001)


def test_poetry_lock_pypi002_passes_with_hashes(tmp_path: Path) -> None:
    _write_poetry_lock(tmp_path)
    ctx = PypiContext.from_path(tmp_path)
    findings = list(PypiChecks(ctx).run())
    p002 = [f for f in findings if f.check_id == "PYPI-002"]
    assert p002 and all(f.passed for f in p002), (
        "poetry.lock with per-package hashes + synthesized "
        "--require-hashes must pass PYPI-002"
    )


def test_poetry_lock_pypi004_fires_on_mutable_git_ref(tmp_path: Path) -> None:
    body = textwrap.dedent(
        """\
        [[package]]
        name = "forked"
        version = "1.0.0"

        [package.source]
        type = "git"
        url = "https://github.com/owner/forked.git"
        reference = "main"

        [metadata]
        lock-version = "2.0"
        """
    )
    (tmp_path / "poetry.lock").write_text(body, encoding="utf-8")
    ctx = PypiContext.from_path(tmp_path)
    findings = list(PypiChecks(ctx).run())
    p004 = [f for f in findings if f.check_id == "PYPI-004"]
    assert p004 and not p004[0].passed


def test_poetry_lock_pypi004_passes_on_resolved_sha(tmp_path: Path) -> None:
    body = textwrap.dedent(
        """\
        [[package]]
        name = "forked"
        version = "1.0.0"

        [package.source]
        type = "git"
        url = "https://github.com/owner/forked.git"
        reference = "main"
        resolved_reference = "abcdef1234567890abcdef1234567890abcdef12"

        [metadata]
        lock-version = "2.0"
        """
    )
    (tmp_path / "poetry.lock").write_text(body, encoding="utf-8")
    ctx = PypiContext.from_path(tmp_path)
    findings = list(PypiChecks(ctx).run())
    p004 = [f for f in findings if f.check_id == "PYPI-004"]
    # resolved_reference is a 40-char SHA -> PYPI-004 passes even
    # though source.reference says "main".
    assert p004 and all(f.passed for f in p004)


def test_poetry_lock_pypi006_flags_compromised_version(tmp_path: Path) -> None:
    _write_poetry_lock(tmp_path)  # body pins ctx==0.2.2
    ctx = PypiContext.from_path(tmp_path)
    findings = list(PypiChecks(ctx).run())
    p006 = [f for f in findings if f.check_id == "PYPI-006"]
    assert p006 and not p006[0].passed
    assert "ctx" in p006[0].description
