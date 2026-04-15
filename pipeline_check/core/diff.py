"""Resolve the set of files changed since a base git ref.

Used by ``--diff-base`` to scope a scan to just the workflows touched
on a feature branch. Two-step filter:

1. ``git diff --name-only <base>...HEAD`` returns every file that has
   diverged from the merge base with ``<base>``.
2. Workflow providers filter their loaded documents against this set
   so checks run only against the files a PR actually changes.

The intent is scoping, not correctness — if git is unavailable or the
base ref can't be resolved we return ``None`` (meaning "do not filter")
rather than raising. The caller decides whether that's acceptable.
"""
from __future__ import annotations

import subprocess
from pathlib import Path


def changed_files(base_ref: str, cwd: str | Path = ".") -> set[str] | None:
    """Return absolute + relative path strings of files changed vs ``base_ref``.

    Returns ``None`` on any git failure so the caller can fall back to
    scanning everything. Returns an empty set when the branch is in
    sync with the base ref (intentional — means "scan nothing").
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", f"{base_ref}...HEAD"],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    root = Path(cwd).resolve()
    out: set[str] = set()
    for raw in result.stdout.splitlines():
        rel = raw.strip()
        if not rel:
            continue
        out.add(rel)
        out.add(str(root / rel))
        # Also add the forward-slash-normalised absolute form so the
        # filter matches on Windows where Path strings use backslashes.
        out.add((root / rel).as_posix())
    return out


def filter_paths(paths: list[str], allowed: set[str] | None) -> list[str]:
    """Intersect *paths* with *allowed*. ``None`` disables filtering."""
    if allowed is None:
        return paths
    allowed_norm = {_norm(p) for p in allowed}
    return [p for p in paths if _norm(p) in allowed_norm]


def _norm(p: str) -> str:
    return Path(p).as_posix().lower()


def git_show(ref: str, path: str, cwd: str | Path = ".") -> str | None:
    """Return the content of ``path`` at ``ref`` via ``git show``, or None.

    Used by ``--baseline-from-git`` to resolve a prior scan's JSON
    report without requiring the caller to restore the artifact by
    hand. ``None`` on any git failure — callers should degrade to a
    full scan rather than refusing to run.
    """
    try:
        result = subprocess.run(
            ["git", "show", f"{ref}:{path}"],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout
