"""Resolve the set of files changed since a base git ref.

Used by ``--diff-base`` to scope a scan to just the workflows touched
on a feature branch. Two-step filter:

1. ``git diff --name-only <base>...HEAD`` returns every file that has
   diverged from the merge base with ``<base>``.
2. Workflow providers filter their loaded documents against this set
   so checks run only against the files a PR actually changes.

The intent is scoping, not correctness, if git is unavailable or the
base ref can't be resolved we return ``None`` (meaning "do not filter")
rather than raising. The caller decides whether that's acceptable.

Security
--------
``base_ref`` (and the ``ref`` / ``path`` of :func:`git_show`) flow
into git as positional arguments composed via f-string. If those
values start with ``-`` git parses them as options instead of refs,
which lets a caller pass arbitrary git flags. Notable abuses:
``--output=PATH`` on ``git diff`` writes diff output to a chosen
file (CWE-88, argument injection). We reject leading-dash values
before invoking git, and pass ``--end-of-options`` (git 2.24+) so
even an internal regression can't reintroduce the issue.
"""
from __future__ import annotations

import subprocess
from pathlib import Path


def _reject_dash_prefix(name: str, value: str) -> None:
    """Reject a value that would smuggle a flag into git.

    git parses any argv element starting with ``-`` as an option, even
    when it appears in a positional slot. ``base_ref="--output=p"`` on
    ``git diff`` writes the diff to ``p``; ``ref="--exec=cmd"`` on
    ``git show`` is similarly dangerous on older builds. Reject these
    at the helper boundary so a misuse from any caller (CLI, library,
    config-file driven) is blocked uniformly.
    """
    if value.startswith("-"):
        raise ValueError(
            f"{name} cannot start with '-' "
            f"(would smuggle a git flag into a positional argument); "
            f"got {value!r}"
        )


def changed_files(base_ref: str, cwd: str | Path = ".") -> set[str] | None:
    """Return absolute + relative path strings of files changed vs ``base_ref``.

    Returns ``None`` on any git failure so the caller can fall back to
    scanning everything. Returns an empty set when the branch is in
    sync with the base ref (intentional, means "scan nothing").
    """
    _reject_dash_prefix("--diff-base", base_ref)
    try:
        result = subprocess.run(
            [
                "git", "diff", "--name-only",
                # Defense in depth: ``--end-of-options`` (git 2.24+)
                # forces every remaining argv element to be treated as
                # a positional, even if it starts with ``-``. Older
                # git versions reject the flag and the helper falls
                # back via the ``returncode != 0`` path below.
                "--end-of-options",
                f"{base_ref}...HEAD",
            ],
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
        # Also add the forward-slash-normalized absolute form so the
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


def git_top(cwd: str | Path = ".") -> Path | None:
    """Return the absolute path of the git repo top, or ``None`` on failure.

    ``git show <ref>:<path>`` interprets ``<path>`` as repo-top-relative
    regardless of the cwd it's invoked from. Callers that need to fetch
    a tracked file at a base ref must first resolve the repo top so the
    path they hand to :func:`git_show` is correct even when the scan
    root is a subdirectory of the repo.
    """
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
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
    top = result.stdout.strip()
    if not top:
        return None
    return Path(top)


def git_show(ref: str, path: str, cwd: str | Path = ".") -> str | None:
    """Return the content of ``path`` at ``ref`` via ``git show``, or None.

    Used by ``--baseline-from-git`` to resolve a prior scan's JSON
    report without requiring the caller to restore the artifact by
    hand. ``None`` on any git failure, callers should degrade to a
    full scan rather than refusing to run.
    """
    _reject_dash_prefix("--baseline-from-git ref", ref)
    _reject_dash_prefix("--baseline-from-git path", path)
    try:
        result = subprocess.run(
            ["git", "show", "--end-of-options", f"{ref}:{path}"],
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
