"""Pipfile.lock parser + rule reuse tests.

Exercises both layers:

1. ``_parse_pipfile_lock`` unit tests: default + develop buckets,
   ``version: "==1.2.3"`` normalization, git source with / without
   ``ref``, malformed entries skipped.
2. End-to-end via ``PypiContext.from_path``: a real
   ``Pipfile.lock`` on disk produces a :class:`RequirementsFile`
   that :class:`PypiChecks` fans out across PYPI-001 / PYPI-002 /
   PYPI-004 / PYPI-006 without per-rule changes.
"""
from __future__ import annotations

import json
from pathlib import Path

from pipeline_check.core.checks.pypi.base import (
    PypiContext,
    _parse_pipfile_lock,
)
from pipeline_check.core.checks.pypi.pipelines import PypiChecks

# ── _parse_pipfile_lock ──────────────────────────────────────────


class TestParsePipfileLock:
    def test_default_bucket_registry_entry(self) -> None:
        text = json.dumps({
            "_meta": {"pipfile-spec": 6},
            "default": {
                "requests": {
                    "version": "==2.31.0",
                    "hashes": ["sha256:aaa", "sha256:bbb"],
                    "index": "pypi",
                },
            },
            "develop": {},
        })
        lines, options = _parse_pipfile_lock(text)
        assert len(lines) == 1
        assert lines[0].body == "requests==2.31.0"
        assert "--hash=sha256:aaa" in lines[0].flags
        assert "--hash=sha256:bbb" in lines[0].flags
        assert "--require-hashes" in options

    def test_develop_bucket_also_walked(self) -> None:
        text = json.dumps({
            "default": {
                "requests": {"version": "==2.31.0", "hashes": ["sha256:a"]},
            },
            "develop": {
                "pytest": {"version": "==7.4.0", "hashes": ["sha256:b"]},
            },
        })
        lines, _ = _parse_pipfile_lock(text)
        assert len(lines) == 2
        bodies = {line.body for line in lines}
        assert bodies == {"requests==2.31.0", "pytest==7.4.0"}

    def test_git_source_with_ref(self) -> None:
        text = json.dumps({
            "default": {
                "forked": {
                    "git": "https://github.com/owner/repo.git",
                    "ref": "abcdef1234567890abcdef1234567890abcdef12",
                },
            },
        })
        lines, _ = _parse_pipfile_lock(text)
        assert lines[0].body == (
            "forked @ git+https://github.com/owner/repo.git@"
            "abcdef1234567890abcdef1234567890abcdef12"
        )

    def test_git_source_without_ref(self) -> None:
        text = json.dumps({
            "default": {
                "forked": {
                    "git": "https://github.com/owner/repo.git",
                },
            },
        })
        lines, _ = _parse_pipfile_lock(text)
        assert lines[0].body == (
            "forked @ git+https://github.com/owner/repo.git"
        )

    def test_version_with_leading_operator_normalized(self) -> None:
        # Pipfile.lock writes ``"==1.2.3"`` with the operator
        # included; synthesizer strips before reattaching ``==``.
        text = json.dumps({
            "default": {
                "foo": {"version": "==1.2.3", "hashes": ["sha256:x"]},
            },
        })
        lines, _ = _parse_pipfile_lock(text)
        assert lines[0].body == "foo==1.2.3"

    def test_entry_without_version_or_git_dropped(self) -> None:
        # Defensive: an entry with only a ``file:`` source and no
        # ``version`` has no recoverable identity for PYPI-001 /
        # PYPI-006; drop it rather than emit a half-formed body.
        text = json.dumps({
            "default": {
                "local": {"file": "./local-pkg.tar.gz"},
            },
        })
        lines, _ = _parse_pipfile_lock(text)
        assert lines == ()

    def test_malformed_top_level_returns_empty(self) -> None:
        # Defensive: JSON whose top level isn't a dict (rare; would
        # only happen for a truncated file) returns empty lines so
        # downstream rule iteration doesn't choke.
        lines, options = _parse_pipfile_lock("[]")
        assert lines == ()
        assert options == ("--require-hashes",)


# ── Integration: end-to-end via PypiContext.from_path ─────────────


_PIPFILE_LOCK_BODY = json.dumps({
    "_meta": {
        "hash": {"sha256": "deadbeef"},
        "pipfile-spec": 6,
        "requires": {"python_version": "3.10"},
        "sources": [
            {
                "name": "pypi",
                "url": "https://pypi.org/simple",
                "verify_ssl": True,
            },
        ],
    },
    "default": {
        "requests": {
            "version": "==2.31.0",
            "hashes": ["sha256:aaa", "sha256:bbb"],
            "index": "pypi",
        },
        "ctx": {
            "version": "==0.2.2",
            "hashes": ["sha256:malicious"],
            "index": "pypi",
        },
    },
    "develop": {},
})


def _write_pipfile_lock(tmp_path: Path) -> Path:
    target = tmp_path / "Pipfile.lock"
    target.write_text(_PIPFILE_LOCK_BODY, encoding="utf-8")
    return target


def test_pipfile_lock_picked_up_by_loader(tmp_path: Path) -> None:
    _write_pipfile_lock(tmp_path)
    ctx = PypiContext.from_path(tmp_path)
    assert len(ctx.files) == 1
    rf = ctx.files[0]
    bodies = {line.body for line in rf.lines}
    assert "requests==2.31.0" in bodies
    assert "ctx==0.2.2" in bodies


def test_pipfile_lock_pypi001_passes_on_exact_pins(tmp_path: Path) -> None:
    _write_pipfile_lock(tmp_path)
    ctx = PypiContext.from_path(tmp_path)
    findings = list(PypiChecks(ctx).run())
    p001 = [f for f in findings if f.check_id == "PYPI-001"]
    assert p001 and all(f.passed for f in p001)


def test_pipfile_lock_pypi002_passes_with_hashes(tmp_path: Path) -> None:
    _write_pipfile_lock(tmp_path)
    ctx = PypiContext.from_path(tmp_path)
    findings = list(PypiChecks(ctx).run())
    p002 = [f for f in findings if f.check_id == "PYPI-002"]
    assert p002 and all(f.passed for f in p002)


def test_pipfile_lock_pypi004_fires_on_mutable_git_ref(tmp_path: Path) -> None:
    body = json.dumps({
        "default": {
            "forked": {
                "git": "https://github.com/owner/forked.git",
                "ref": "main",
            },
        },
    })
    (tmp_path / "Pipfile.lock").write_text(body, encoding="utf-8")
    ctx = PypiContext.from_path(tmp_path)
    findings = list(PypiChecks(ctx).run())
    p004 = [f for f in findings if f.check_id == "PYPI-004"]
    assert p004 and not p004[0].passed


def test_pipfile_lock_pypi004_passes_on_resolved_sha(tmp_path: Path) -> None:
    body = json.dumps({
        "default": {
            "forked": {
                "git": "https://github.com/owner/forked.git",
                "ref": "abcdef1234567890abcdef1234567890abcdef12",
            },
        },
    })
    (tmp_path / "Pipfile.lock").write_text(body, encoding="utf-8")
    ctx = PypiContext.from_path(tmp_path)
    findings = list(PypiChecks(ctx).run())
    p004 = [f for f in findings if f.check_id == "PYPI-004"]
    assert p004 and all(f.passed for f in p004)


def test_pipfile_lock_pypi006_flags_compromised_version(
    tmp_path: Path,
) -> None:
    _write_pipfile_lock(tmp_path)  # body pins ctx==0.2.2
    ctx = PypiContext.from_path(tmp_path)
    findings = list(PypiChecks(ctx).run())
    p006 = [f for f in findings if f.check_id == "PYPI-006"]
    assert p006 and not p006[0].passed
    assert "ctx" in p006[0].description
